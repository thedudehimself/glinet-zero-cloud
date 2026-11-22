from conntrack import scan_conntrack_text

DEVICES = {
    "10.10.20.12": {"id": "rm10", "role": "kvm"},
    "10.10.10.22": {"id": "rm10_br0", "role": "kvm"},
    "10.10.10.50": {"id": "mt3000", "role": "router"},
}

CONNTRACK = """\
ipv4 2 tcp 6 120 ESTABLISHED src=10.10.20.12 dst=47.88.1.5 sport=51234 dport=28883 src=47.88.1.5 dst=10.10.20.12 sport=28883 dport=51234
ipv4 2 tcp 6 120 ESTABLISHED src=10.10.10.50 dst=170.39.226.42 sport=44111 dport=443 src=170.39.226.42 dst=10.10.10.50 sport=443 dport=44111
ipv4 2 udp 17 30 src=10.10.20.12 dst=142.250.82.127 sport=40000 dport=19302 src=142.250.82.127 dst=10.10.20.12 sport=19302 dport=40000
ipv4 2 udp 17 30 src=10.10.20.12 dst=129.6.15.28 sport=40002 dport=123 src=129.6.15.28 dst=10.10.20.12 sport=123 dport=40002
ipv4 2 udp 17 30 src=10.10.20.12 dst=1.1.1.1 sport=40001 dport=443 src=1.1.1.1 dst=10.10.20.12 sport=443 dport=40001
ipv4 2 tcp 6 120 ESTABLISHED src=10.10.10.21 dst=8.8.8.8 sport=55555 dport=28883 src=8.8.8.8 dst=10.10.10.21 sport=28883 dport=55555
ipv4 2 tcp 6 120 ESTABLISHED src=100.64.0.10 dst=10.10.20.12 sport=28883 dport=443 src=10.10.20.12 dst=100.64.0.10 sport=443 dport=28883
ipv4 2 udp 17 30 src=10.10.20.12 dst=224.0.0.251 sport=5353 dport=5353 src=224.0.0.251 dst=10.10.20.12 sport=5353 dport=5353
ipv4 2 tcp 6 120 ESTABLISHED src=10.10.10.50 dst=1.1.1.1 sport=44112 dport=443 src=1.1.1.1 dst=10.10.10.50 sport=443 dport=44112
"""


def test_classifies_critical_warn_and_ignores_allowed_prefix_and_reply():
    alerts = scan_conntrack_text(CONNTRACK, DEVICES)
    assert len(alerts) == 3
    by_key = {(a["device_id"], a["dst"], a["dport"]): a["severity"] for a in alerts}
    assert by_key == {
        ("rm10", "47.88.1.5", 28883): "CRITICAL",
        ("mt3000", "170.39.226.42", 443): "CRITICAL",
        ("rm10", "1.1.1.1", 443): "WARN",
    }


def test_deduplicates_identical_flows():
    dup = (
        "ipv4 2 tcp 6 120 ESTABLISHED src=10.10.20.12 dst=66.245.219.252 sport=50000 dport=8000 "
        "src=66.245.219.252 dst=10.10.20.12 sport=8000 dport=50000\n"
    ) * 2
    alerts = scan_conntrack_text(dup, DEVICES)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "CRITICAL"
    assert alerts[0]["dst"] == "66.245.219.252"


def test_ignores_tailscale_cgnat_100_64_range():
    line = (
        "ipv4 2 udp 17 30 src=10.10.20.12 dst=100.64.1.20 sport=41641 dport=41641 "
        "src=100.64.1.20 dst=10.10.20.12 sport=41641 dport=41641\n"
    )
    assert scan_conntrack_text(line, DEVICES) == []

