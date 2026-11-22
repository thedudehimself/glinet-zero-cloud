"""Linux gateway /proc/net/nf_conntrack egress guardrail for GoodCloud/C2 and KVM WAN traffic."""

from __future__ import annotations

import ipaddress
from pathlib import Path

CRITICAL_PORTS = {18883, 28883, 3900, 5912, 5913, 8899}
CRITICAL_NETS = [
    ipaddress.ip_network("66.245.219.252/32"),
    ipaddress.ip_network("65.20.71.131/32"),
    ipaddress.ip_network("170.39.226.0/24"),
]
ALLOWED_KVM_WAN_PORTS = {123, 19302}


def _parse_original_tuple(line: str) -> tuple[str, str, str, int] | None:
    parts = line.split()
    if len(parts) < 8 or parts[0] not in ("ipv4", "ipv6"):
        return None
    proto = parts[2].lower()
    src = dst = None
    dport = None
    for tok in parts[4:]:
        if tok.startswith("src=") and src is None:
            src = tok[4:]
        elif tok.startswith("dst=") and dst is None:
            dst = tok[4:]
        elif tok.startswith("dport=") and dport is None:
            try:
                dport = int(tok[6:])
            except ValueError:
                return None
        if src is not None and dst is not None and dport is not None:
            return proto, src, dst, dport
    return None


def _is_global_wan(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return ip_obj.is_global and not ip_obj.is_multicast


def is_conntrack_gateway_available(path: str = "/proc/net/nf_conntrack") -> bool:
    p = Path(path)
    if not p.exists():
        return False
    fwd = Path("/proc/sys/net/ipv4/ip_forward")
    try:
        return fwd.read_text(encoding="utf-8").strip() == "1"
    except OSError:
        return False


def scan_conntrack_text(text: str, device_ips: dict[str, dict]) -> list[dict]:
    alerts: list[dict] = []
    seen: set[tuple[str, str, str, str, int]] = set()

    for line in text.splitlines():
        parsed = _parse_original_tuple(line)
        if not parsed:
            continue
        proto, src, dst, dport = parsed
        dev = device_ips.get(src)
        if not dev:
            continue

        try:
            dst_ip = ipaddress.ip_address(dst)
        except ValueError:
            continue

        severity = None
        reason = ""
        if dport in CRITICAL_PORTS:
            severity = "CRITICAL"
            reason = f"GoodCloud/C2 port {dport}"
        elif isinstance(dst_ip, ipaddress.IPv4Address) and any(dst_ip in net for net in CRITICAL_NETS):
            severity = "CRITICAL"
            reason = f"CSA-2026-01 attacker IP {dst}"
        elif dev.get("role") == "kvm" and _is_global_wan(dst_ip) and dport not in ALLOWED_KVM_WAN_PORTS:
            severity = "WARN"
            reason = f"Unexpected KVM WAN egress to {dst}:{dport}"

        if severity:
            key = (dev["id"], src, dst, proto, dport)
            if key not in seen:
                seen.add(key)
                alerts.append(
                    {
                        "severity": severity,
                        "device_id": dev["id"],
                        "src": src,
                        "dst": dst,
                        "proto": proto,
                        "dport": dport,
                        "reason": reason,
                    }
                )

    return alerts


def scan_system_conntrack(device_ips: dict[str, dict], path: str = "/proc/net/nf_conntrack") -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return scan_conntrack_text(text, device_ips)
