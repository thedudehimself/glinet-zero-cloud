#!/usr/bin/env python3
"""Harden a GL.iNet Comet KVM (RM1/RM1PE/RM10) against USB/HDMI fingerprinting.

1. Writes /etc/kvmd/override.yaml to disable virtual USB drives (msd) and spoof
   USB OTG descriptors (e.g., Logitech USB Receiver or Dell KB216 Keyboard).
2. Patches /etc/kvmd/edid.json with a standard monitor PNP ID (DEL) and name,
   recomputing the 128-byte EDID base-block checksum.
3. Flashes the patched EDID onto the HDMI receiver EEPROM via POST /api/upgrade/edid
   (multipart/form-data field 'edid', required on V1.10.2/V1.10.3).
4. Ensures /etc/glinet/gl-cloud.conf ends with a trailing newline so SSH probes
   never concatenate section markers onto the JSON line.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import ssl
import subprocess
import urllib.request
import uuid
from typing import Any

USB_PRESETS: dict[str, dict[str, Any]] = {
    "logitech-receiver": {
        "vendor_id": "0x046d",
        "product_id": "0xc52b",
        "manufacturer": "Logitech",
        "product": "USB Receiver",
        "serial": "L19F402B",
        "config": "Logitech HID",
    },
    "dell-kb216": {
        "vendor_id": "0x413c",
        "product_id": "0x2113",
        "manufacturer": "Dell",
        "product": "Dell KB216 Wired Keyboard",
        "serial": "D48E710C",
        "config": "Dell USB Keyboard",
    },
}


def patch_edid_hex(hex_str: str, monitor_name: str, pnp_hi: int = 0x10, pnp_lo: int = 0xAC) -> str:
    """Replace PNP ID + monitor name descriptor and recompute byte-127 EDID checksum."""
    b = bytearray.fromhex(hex_str.strip())
    if len(b) < 128:
        raise ValueError(f"EDID block too short ({len(b)} bytes; expected >= 128)")
    b[8] = pnp_hi
    b[9] = pnp_lo
    tag = bytes.fromhex("000000fc00")
    idx = b.find(tag, 54, 126)
    if idx != -1:
        name_bytes = (monitor_name[:12] + "\n").ljust(13, " ").encode("ascii")
        b[idx + 5 : idx + 18] = name_bytes[:13]
    b[127] = (256 - (sum(b[:127]) % 256)) % 256
    return b.hex()


def render_override_yaml(preset: dict[str, Any], serial: str | None = None) -> str:
    """Render /etc/kvmd/override.yaml disabling MSD and setting USB OTG descriptors."""
    ser = serial or preset["serial"]
    return (
        "kvmd:\n"
        "    msd:\n"
        "        type: disabled\n\n"
        "otg:\n"
        f"    vendor_id: {preset['vendor_id']}\n"
        f"    product_id: {preset['product_id']}\n"
        f"    manufacturer: \"{preset['manufacturer']}\"\n"
        f"    product: \"{preset['product']}\"\n"
        f"    serial: \"{ser}\"\n"
        f"    config: \"{preset['config']}\"\n"
        "    devices:\n"
        "        msd:\n"
        "            enabled: false\n"
        "        drive:\n"
        "            enabled: false\n"
    )


def _ssh(host: str, cmd: str, stdin_bytes: bytes | None = None) -> str:
    proc = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", host, cmd],
        input=stdin_bytes,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"SSH failed ({proc.returncode}): {proc.stderr.decode(errors='replace')}")
    return proc.stdout.decode(errors="replace")


def _flash_edid_http(base_url: str, username: str, password: str, edid_hex: str) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = base_url.rstrip("/")

    # Login via application/x-www-form-urlencoded
    login_body = f"user={username}&passwd={password}".encode("utf-8")
    req = urllib.request.Request(
        f"{base}/api/auth/login",
        data=login_body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        cookies = resp.headers.get_all("Set-Cookie") or []
    cookie_hdr = "; ".join(c.split(";", 1)[0] for c in cookies)

    boundary = f"----glkvm{uuid.uuid4().hex}"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="edid"\r\n\r\n'
        f"{edid_hex}\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    edid_req = urllib.request.Request(
        f"{base}/api/upgrade/edid",
        data=body,
        headers={
            "Cookie": cookie_hdr,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        method="POST",
    )
    with urllib.request.urlopen(edid_req, context=ctx, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Harden GL.iNet KVM USB/HDMI descriptors")
    parser.add_argument("--ssh-host", required=True, help="e.g. root@10.10.20.15")
    parser.add_argument("--url", required=True, help="e.g. https://10.10.20.15")
    parser.add_argument("--preset", choices=sorted(USB_PRESETS), default="logitech-receiver")
    parser.add_argument("--monitor-name", default="DELL U2723QE", help="1-12 ASCII chars")
    parser.add_argument("--edid-key", default="E2560x1440", help="Profile key in /etc/kvmd/edid.json")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password-env", default="GLKVM_PASSWORD")
    args = parser.parse_args()

    password = os.environ.get(args.password_env) or getpass.getpass("KVM Web UI password: ")
    preset = USB_PRESETS[args.preset]
    override_yaml = render_override_yaml(preset)

    print(f"[1/4] Writing /etc/kvmd/override.yaml ({args.preset}, msd disabled)...")
    _ssh(args.ssh_host, "cat > /etc/kvmd/override.yaml && kvmd -m --dump-config >/dev/null", override_yaml.encode("utf-8"))

    print(f"[2/4] Patching /etc/kvmd/edid.json ({args.monitor_name})...")
    raw_edid = _ssh(args.ssh_host, "cp -n /etc/kvmd/edid.json /etc/kvmd/edid.json.bak 2>/dev/null || true; cat /etc/kvmd/edid.json")
    entries = json.loads(raw_edid)
    selected_hex = None
    for entry in entries:
        entry["label"] = entry["label"].replace("GLKVM", args.monitor_name)
        entry["content"] = patch_edid_hex(entry["content"], args.monitor_name)
        if entry.get("key") == args.edid_key:
            selected_hex = entry["content"]
    if selected_hex is None and entries:
        selected_hex = entries[0]["content"]
    _ssh(args.ssh_host, "cat > /etc/kvmd/edid.json", json.dumps(entries, indent=4).encode("utf-8"))

    print("[3/4] Ensuring /etc/glinet/gl-cloud.conf trailing newline & restarting kvmd-otg...")
    _ssh(
        args.ssh_host,
        "python3 -c \"p='/etc/glinet/gl-cloud.conf'; import os; "
        "os.path.exists(p) and open(p,'w').write(open(p).read().rstrip()+'\\n')\"; "
        "/etc/init.d/S98kvmd stop; /etc/init.d/S50kvmd-otg restart; /etc/init.d/S98kvmd start",
    )

    if selected_hex:
        print(f"[4/4] Flashing EDID ({args.edid_key}) to HDMI receiver EEPROM...")
        res = _flash_edid_http(args.url, args.username, password, selected_hex)
        print("EDID flash result:", json.dumps(res))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
