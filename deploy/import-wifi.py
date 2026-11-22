#!/usr/bin/env python3
"""Import Wi-Fi profiles from Linux NetworkManager, Android Wi-Fi QR, or Android WifiConfigStore.xml
and push them securely (via SSH stdin, never argv) to GL-MT3000's /etc/van-wan-guard/known_networks.json."""

from __future__ import annotations

import argparse
import configparser
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def _unescape_qr(val: str) -> str:
    out: list[str] = []
    i = 0
    n = len(val)
    while i < n:
        if val[i] == "\\" and i + 1 < n:
            out.append(val[i + 1])
            i += 2
        else:
            out.append(val[i])
            i += 1
    return "".join(out)


def parse_wifi_qr(qr: str) -> dict:
    raw = qr.strip()
    if not raw.upper().startswith("WIFI:"):
        raise ValueError("QR string must start with 'WIFI:'")
    body = raw[5:]

    fields: dict[str, str] = {}
    buf: list[str] = []
    escaped = False
    for ch in body:
        if escaped:
            buf.append("\\" + ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == ";":
            token = "".join(buf)
            buf = []
            if ":" in token:
                k, v = token.split(":", 1)
                fields[k.upper()] = _unescape_qr(v)
            continue
        buf.append(ch)
    if buf:
        token = "".join(buf)
        if ":" in token:
            k, v = token.split(":", 1)
            fields[k.upper()] = _unescape_qr(v)

    ssid = fields.get("S", "")
    if not ssid:
        raise ValueError("QR string missing SSID (S:...)")
    t = fields.get("T", "nopass").upper()
    psk = fields.get("P", "")
    if t in ("WPA", "WPA2", "WPA3", "SAE") or psk:
        security = "wpa2"
    else:
        security = "open"
        psk = ""
    return {"ssid": ssid, "security": security, "psk": psk}


def parse_nmconnection_text(text: str) -> dict | None:
    cp = configparser.ConfigParser(interpolation=None)
    cp.read_string(text)
    if cp.get("connection", "type", fallback="").strip().lower() != "wifi":
        return None
    ssid = cp.get("wifi", "ssid", fallback="").rstrip("\r\n")
    if not ssid or not ssid.strip():
        return None
    key_mgmt = cp.get("wifi-security", "key-mgmt", fallback="").strip().lower()
    if key_mgmt in ("wpa-eap", "ieee8021x", "wpa-eap-suite-b-192"):
        return None
    psk = cp.get("wifi-security", "psk", fallback="")
    if key_mgmt in ("wpa-psk", "sae") or psk:
        if not psk:
            return None
        return {"ssid": ssid, "security": "wpa2", "psk": psk}
    return {"ssid": ssid, "security": "open", "psk": ""}


def _strip_android_quotes(val: str | None) -> str:
    if not val:
        return ""
    s = val.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s


def parse_android_wifi_xml(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    results: list[dict] = []
    seen: set[str] = set()
    # Iterate parent <Network> blocks when present so we can skip Enterprise / Passpoint networks
    networks = list(root.iter("Network"))
    if networks:
        for net in networks:
            if net.find("WifiEnterpriseConfiguration") is not None or net.find("PasspointConfiguration") is not None:
                continue
            cfg = net.find("WifiConfiguration")
            if cfg is None:
                continue
            ssid = ""
            psk = ""
            for elem in cfg.findall("string"):
                name = elem.attrib.get("name", "")
                if name == "SSID":
                    ssid = _strip_android_quotes(elem.text)
                elif name == "PreSharedKey":
                    psk = _strip_android_quotes(elem.text)
            if not ssid or ssid in seen:
                continue
            seen.add(ssid)
            if psk:
                results.append({"ssid": ssid, "security": "wpa2", "psk": psk})
            else:
                results.append({"ssid": ssid, "security": "open", "psk": ""})
        return results

    for cfg in root.iter("WifiConfiguration"):
        ssid = ""
        psk = ""
        for elem in cfg.findall("string"):
            name = elem.attrib.get("name", "")
            if name == "SSID":
                ssid = _strip_android_quotes(elem.text)
            elif name == "PreSharedKey":
                psk = _strip_android_quotes(elem.text)
        if not ssid or ssid in seen:
            continue
        seen.add(ssid)
        if psk:
            results.append({"ssid": ssid, "security": "wpa2", "psk": psk})
        else:
            results.append({"ssid": ssid, "security": "open", "psk": ""})
    return results


def load_nm_profiles(nm_dir: Path = Path("/etc/NetworkManager/system-connections")) -> list[dict]:
    out: list[dict] = []
    if not nm_dir.exists():
        return out
    for p in sorted(nm_dir.glob("*.nmconnection")):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except PermissionError:
            continue
        parsed = parse_nmconnection_text(text)
        if parsed:
            out.append(parsed)
    return out


def push_network_to_router(
    host: str,
    entry: dict,
    trusted: bool = False,
    priority: int | None = None,
    runner=subprocess.run,
) -> dict:
    payload = {
        "ssid": entry["ssid"],
        "security": entry["security"],
        "psk": entry.get("psk", ""),
        "trusted": bool(trusted and entry["security"] != "open" and entry.get("psk")),
    }
    if priority is not None:
        payload["priority"] = int(priority)
    if host.startswith("-"):
        raise ValueError(f"Invalid SSH host (must not start with '-'): {host!r}")
    proc = runner(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6", "-o", "IPQoS=none", host, "/usr/bin/van-wan networks upsert"],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or f"SSH exit {proc.returncode}").strip())
    return json.loads((proc.stdout or "{}").strip() or "{}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Import Wi-Fi profiles to OpenWrt/GL.iNet van-wan-guard allowlist")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--from-qr", help="Android/Samsung Share Wi-Fi QR string (WIFI:T:WPA;S:...;P:...;;)")
    src.add_argument("--from-nm", action="store_true", help="Read Linux NetworkManager profiles (may require sudo)")
    src.add_argument("--from-android-xml", type=Path, help="Path to Android WifiConfigStore.xml")
    ap.add_argument("--nm-dir", type=Path, default=Path("/etc/NetworkManager/system-connections"))
    ap.add_argument("--ssid", action="append", default=[], help="Filter to specific SSID(s) (repeatable)")
    ap.add_argument("--list", action="store_true", help="Dry-run: list parsed SSIDs (PSKs redacted) without uploading")
    ap.add_argument("--trusted", action="store_true", help="Mark imported WPA2/WPA3 SSID(s) as trusted (skip VPN)")
    ap.add_argument("--priority", type=int, default=None, help="Priority rank (lower = higher priority)")
    ap.add_argument("--host", default="gl-mt3000", help="OpenWrt/GL.iNet SSH target (e.g. root@192.168.8.1 or gl-mt3000)")
    args = ap.parse_args()

    profiles: list[dict] = []
    if args.from_qr:
        if args.from_qr == "-":
            qr_raw = sys.stdin.read().strip()
        else:
            print("Note: pass '--from-qr -' via stdin to avoid exposing Wi-Fi PSKs in shell history/argv.", file=sys.stderr)
            qr_raw = args.from_qr
        profiles = [parse_wifi_qr(qr_raw)]
    elif args.from_nm:
        profiles = load_nm_profiles(args.nm_dir)
    elif args.from_android_xml:
        profiles = parse_android_wifi_xml(args.from_android_xml.read_text(encoding="utf-8"))

    if args.ssid:
        want = set(args.ssid)
        profiles = [p for p in profiles if p["ssid"] in want]

    if args.list or (args.from_nm and not args.ssid):
        print(f"Found {len(profiles)} Wi-Fi profile(s) (PSKs hidden):")
        for p in profiles:
            print(f"  - {p['ssid']} ({p['security']}, has_psk={bool(p.get('psk'))})")
        if args.from_nm and not args.ssid and not args.list:
            print("\nSafety guard: pass --ssid '<SSID>' (repeatable) to select which Linux NetworkManager networks to upload.")
        return 0

    if not profiles:
        print("No matching Wi-Fi profiles found.", file=sys.stderr)
        return 1

    for p in profiles:
        if args.trusted and (p["security"] == "open" or not p.get("psk")):
            print(f"Skipping --trusted on open/empty-PSK SSID {p['ssid']!r} (evil-twin protection)", file=sys.stderr)
        res = push_network_to_router(args.host, p, trusted=args.trusted, priority=args.priority)
        print(f"Uploaded {p['ssid']!r}: {json.dumps(res)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
