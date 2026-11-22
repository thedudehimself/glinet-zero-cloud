from pathlib import Path
from resolver import load_config, parse_dnsmasq_leases, parse_ip_neigh, parse_wg_dump, resolve_device_ip

LEASES = """\
1795443860 02:00:5e:00:53:02 10.10.10.22 glkvm 01:02:00:5e:00:53:02
1795449999 02:00:5e:00:53:01 10.10.10.21 * 01:02:00:5e:00:53:01
1795450000 02:00:5e:00:53:01 10.10.20.15 glkvm-rm1pe 01:02:00:5e:00:53:01
"""

NEIGH = """\
192.168.1.23 dev br0 FAILED
10.10.10.21 dev br0 lladdr 02:00:5e:00:53:01 STALE
10.10.20.15 dev vlan20 lladdr 02:00:5e:00:53:01 REACHABLE
10.10.20.12 dev vlan20 lladdr 02:00:5e:00:53:02 FAILED
10.10.10.22 dev br0 lladdr 02:00:5e:00:53:02 DELAY
"""


def test_prefers_live_preferred_vlan_over_stale_br0():
    dev = {"id": "rm1pe", "mac": "02:00:5E:00:53:01", "fallback_ip": "10.10.10.21", "preferred_vlan": "vlan20"}
    res = resolve_device_ip(dev, parse_dnsmasq_leases(LEASES), parse_ip_neigh(NEIGH))
    assert res == {"ip": "10.10.20.15", "vlan": "vlan20", "source": "neigh", "neigh_state": "REACHABLE"}


def test_ignores_failed_preferred_vlan_and_uses_live_other_vlan():
    dev = {"id": "rm10", "mac": "02:00:5e:00:53:02", "fallback_ip": "10.10.20.12", "preferred_vlan": "vlan20"}
    res = resolve_device_ip(dev, parse_dnsmasq_leases(LEASES), parse_ip_neigh(NEIGH))
    assert res == {"ip": "10.10.10.22", "vlan": "br0", "source": "neigh", "neigh_state": "DELAY"}


def test_falls_back_to_lease_then_fallback_ip():
    dev = {"id": "rm10", "mac": "02:00:5e:00:53:02", "fallback_ip": "10.10.20.12", "preferred_vlan": "vlan20"}
    res = resolve_device_ip(dev, parse_dnsmasq_leases(LEASES), {})
    assert res["ip"] == "10.10.10.22" and res["source"] == "lease" and res["vlan"] == "vlan20"
    res2 = resolve_device_ip(dev, {}, {})
    assert res2 == {"ip": "10.10.20.12", "vlan": "vlan20", "source": "fallback", "neigh_state": None}


def test_fallback_infers_vlan_from_fallback_ip():
    dev = {"id": "rm1pe", "mac": "02:00:5e:00:53:01", "fallback_ip": "10.10.10.21", "preferred_vlan": "vlan20"}
    res = resolve_device_ip(dev, {}, {})
    assert res == {"ip": "10.10.10.21", "vlan": "vlan20", "source": "fallback", "neigh_state": None}


def test_prefers_preferred_vlan_lease_when_no_neighbors():
    dev = {"id": "rm1pe", "mac": "02:00:5e:00:53:01", "fallback_ip": "10.10.10.21", "preferred_vlan": "vlan20"}
    res = resolve_device_ip(dev, parse_dnsmasq_leases(LEASES), {})
    assert res["ip"] == "10.10.20.15" and res["vlan"] == "vlan20" and res["source"] == "lease"


def test_load_config_reads_devices():
    cfg = load_config(Path(__file__).resolve().parent.parent / "config" / "devices.example.json")
    assert cfg["tailscale_host"] == "gateway.tailnet-example.ts.net"
    assert [d["id"] for d in cfg["devices"]] == ["rm1pe", "rm10", "mt3000"]


def test_parse_wg_dump_filters_stale_handshakes():
    now = 1795500000
    dump = (
        "privkey\tpubkey\t51820\toff\n"
        f"peer1\t(none)\t1.2.3.4:51820\t192.168.2.5/32\t{now - 40}\t1000\t2000\t25\n"
        f"peer2\t(none)\t5.6.7.8:51820\t192.168.2.9/32\t{now - 400}\t1000\t2000\t25\n"
        "peer3\t(none)\t(none)\t192.168.2.10/32\t0\t0\t0\toff\n"
    )
    active = parse_wg_dump(dump, now=now, max_age_sec=180)
    assert active == {"192.168.2.5"}


def test_prefers_active_wireguard_ip_and_falls_back_when_stale():
    dev = {
        "id": "mt3000",
        "mac": "02:00:5e:00:53:03",
        "fallback_ip": "10.10.10.50",
        "preferred_vlan": "br0",
        "wg_ip": "192.168.2.5",
        "wg_iface": "wg0",
    }
    neigh = parse_ip_neigh("10.10.10.50 dev br0 lladdr 02:00:5e:00:53:03 REACHABLE\n")
    res_wg = resolve_device_ip(dev, {}, neigh, wg_active_ips={"192.168.2.5"})
    assert res_wg == {"ip": "192.168.2.5", "vlan": "wg0", "source": "wireguard", "neigh_state": "WG_ACTIVE"}

    res_lan = resolve_device_ip(dev, {}, neigh, wg_active_ips=set())
    assert res_lan == {"ip": "10.10.10.50", "vlan": "br0", "source": "neigh", "neigh_state": "REACHABLE"}

