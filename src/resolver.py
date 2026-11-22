"""MAC-to-IP resolver reading WireGuard dumps, Linux neighbor tables, and dnsmasq leases."""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

LIVE_NEIGH_RANK = {
    "REACHABLE": 3,
    "PERMANENT": 3,
    "DELAY": 2,
    "PROBE": 2,
    "STALE": 1,
}


def load_config(path: str | Path) -> dict:
    with Path(path).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def infer_vlan_from_ip(ip: str, default_vlan: str = "br0") -> str:
    parts = ip.split(".")
    if len(parts) == 4 and parts[0] == "192" and parts[1] == "168":
        if parts[2] == "1":
            return "br0"
        if parts[2].isdigit():
            return f"br{parts[2]}"
    return default_vlan


def parse_dnsmasq_leases(text: str) -> dict[str, list[dict]]:
    leases: dict[str, list[dict]] = {}
    for raw_line in text.splitlines():
        parts = raw_line.split()
        if len(parts) < 4:
            continue
        expiry_str, mac, ip, hostname = parts[0], parts[1].lower(), parts[2], parts[3]
        try:
            expiry = int(expiry_str)
        except ValueError:
            expiry = 0
        leases.setdefault(mac, []).append({"ip": ip, "hostname": hostname, "expiry": expiry})
    return leases


def parse_ip_neigh(text: str) -> dict[str, list[dict]]:
    neighbors: dict[str, list[dict]] = {}
    for raw_line in text.splitlines():
        parts = raw_line.split()
        if len(parts) < 4 or "lladdr" not in parts or "dev" not in parts:
            continue
        ip = parts[0]
        try:
            dev = parts[parts.index("dev") + 1]
            mac = parts[parts.index("lladdr") + 1].lower()
        except (ValueError, IndexError):
            continue
        state = parts[-1].upper()
        neighbors.setdefault(mac, []).append({"ip": ip, "dev": dev, "state": state})
    return neighbors


def parse_wg_dump(text: str, now: int | None = None, max_age_sec: int = 180) -> set[str]:
    """Parse `wg show <iface> dump` output and return active peer IPs with fresh handshakes."""
    ts_now = int(time.time()) if now is None else int(now)
    active: set[str] = set()
    lines = text.splitlines()
    for line in lines[1:]:
        cols = line.split("\t")
        if len(cols) < 5:
            continue
        allowed_raw, handshake_raw = cols[3], cols[4]
        try:
            handshake = int(handshake_raw)
        except ValueError:
            continue
        if handshake <= 0 or (ts_now - handshake) > max_age_sec:
            continue
        for cidr in allowed_raw.split(","):
            cidr = cidr.strip()
            if cidr.endswith("/32"):
                active.add(cidr[:-3])
    return active


def read_wg_active_ips(iface: str = "wg0", max_age_sec: int = 180) -> set[str]:
    try:
        proc = subprocess.run(
            ["wg", "show", iface, "dump"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0:
            return parse_wg_dump(proc.stdout, max_age_sec=max_age_sec)
    except (OSError, subprocess.SubprocessError):
        pass
    return set()


def resolve_device_ip(
    device: dict,
    leases: dict[str, list[dict]],
    neighbors: dict[str, list[dict]],
    wg_active_ips: set[str] | None = None,
) -> dict:
    wg_ip = device.get("wg_ip")
    if wg_ip and wg_active_ips and wg_ip in wg_active_ips:
        return {
            "ip": wg_ip,
            "vlan": device.get("wg_iface", "wg0"),
            "source": "wireguard",
            "neigh_state": "WG_ACTIVE",
        }

    mac = device["mac"].lower()
    preferred_vlan = device.get("preferred_vlan", "br0")

    live_neighbors = [
        n for n in neighbors.get(mac, []) if n.get("state", "").upper() in LIVE_NEIGH_RANK
    ]
    if live_neighbors:
        live_neighbors.sort(
            key=lambda n: (
                1 if n["dev"] == preferred_vlan else 0,
                LIVE_NEIGH_RANK.get(n["state"].upper(), 0),
            ),
            reverse=True,
        )
        best = live_neighbors[0]
        return {
            "ip": best["ip"],
            "vlan": best["dev"],
            "source": "neigh",
            "neigh_state": best["state"].upper(),
        }

    mac_leases = leases.get(mac, [])
    if mac_leases:
        ranked = sorted(
            mac_leases,
            key=lambda l: (
                1 if infer_vlan_from_ip(l["ip"]) == preferred_vlan else 0,
                l.get("expiry", 0),
            ),
            reverse=True,
        )
        best_lease = ranked[0]
        return {
            "ip": best_lease["ip"],
            "vlan": infer_vlan_from_ip(best_lease["ip"], preferred_vlan),
            "source": "lease",
            "neigh_state": None,
        }

    return {
        "ip": device["fallback_ip"],
        "vlan": infer_vlan_from_ip(device["fallback_ip"], preferred_vlan),
        "source": "fallback",
        "neigh_state": None,
    }


def read_system_tables(lease_path: str | Path | None = None) -> tuple[dict, dict]:
    leases: dict[str, list[dict]] = {}
    neighbors: dict[str, list[dict]] = {}
    candidates = [Path(lease_path)] if lease_path else [Path("/run/dnsmasq.lease"), Path("/var/lib/misc/dnsmasq.leases")]
    for p in candidates:
        if p.exists():
            try:
                leases = parse_dnsmasq_leases(p.read_text(encoding="utf-8", errors="replace"))
                break
            except OSError:
                leases = {}
    try:
        proc = subprocess.run(
            ["ip", "-4", "neigh", "show"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0:
            neighbors = parse_ip_neigh(proc.stdout)
    except (OSError, subprocess.SubprocessError):
        neighbors = {}
    return leases, neighbors
