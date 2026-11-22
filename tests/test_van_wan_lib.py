import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIB_SH = ROOT / "router" / "usr" / "libexec" / "van-wan-guard" / "lib.sh"
VAN_WAN_CLI = ROOT / "router" / "usr" / "bin" / "van-wan"
DEFAULT_CFG = ROOT / "router" / "etc" / "van-wan-guard" / "config.json"


def _sh(snippet: str, stdin_text: str = "", env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    script = f'. "{LIB_SH}"\n{snippet}\n'
    return subprocess.run(
        ["/bin/sh", "-c", script],
        input=stdin_text,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def test_parse_ping_stats_healthy_degraded_and_100pct_loss():
    healthy = """\
PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: seq=0 ttl=57 time=18.432 ms
--- 1.1.1.1 ping statistics ---
5 packets transmitted, 5 packets received, 0% packet loss
round-trip min/avg/max = 16.100/18.432/21.500 ms
"""
    r = _sh("parse_ping_stats", stdin_text=healthy)
    assert r.returncode == 0
    assert r.stdout.strip() == "0 18"

    degraded = """\
--- 1.1.1.1 ping statistics ---
5 packets transmitted, 3 packets received, 40% packet loss
round-trip min/avg/max = 310.0/420.6/510.2 ms
"""
    r2 = _sh("parse_ping_stats", stdin_text=degraded)
    assert r2.returncode == 0
    assert r2.stdout.strip() == "40 421"

    total_loss = """\
PING 1.1.1.1 (1.1.1.1): 56 data bytes
--- 1.1.1.1 ping statistics ---
5 packets transmitted, 0 packets received, 100% packet loss
"""
    r3 = _sh("parse_ping_stats", stdin_text=total_loss)
    assert r3.returncode == 0
    assert r3.stdout.strip() == "100 9999"


def test_classify_cpe_health_matrix():
    cases = [
        ("1 0 42 204 20 300", "healthy"),
        ("1 20 299 204 20 300", "healthy"),
        ("1 0 25 302 20 300", "captive"),
        ("1 0 25 200 20 300", "captive"),
        ("1 0 25 307 20 300", "captive"),
        ("1 40 50 204 20 300", "degraded"),
        ("1 0 350 204 20 300", "degraded"),
        ("1 0 50 000 20 300", "down"),
        ("0 0 0 204 20 300", "down"),
    ]
    for args, expected in cases:
        r = _sh(f"classify_cpe_health {args}")
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == expected, f"args={args} got={r.stdout!r}"


def test_decide_next_state_hysteresis_and_modes():
    # auto on cpe: 1st strike stays cpe, 2nd strike flips to starlink
    r1 = _sh("decide_next_state auto 0 1000 cpe degraded 1 0 0 2 3")
    assert r1.stdout.strip() == "auto cpe 1 0"
    r2 = _sh("decide_next_state auto 0 1015 cpe degraded 1 1 0 2 3")
    assert r2.stdout.strip() == "auto starlink 2 0"

    # auto on starlink: needs 3 consecutive healthy probes to fail back to cpe
    r3 = _sh("decide_next_state auto 0 1030 starlink healthy 1 2 0 2 3")
    assert r3.stdout.strip() == "auto starlink 0 1"
    r4 = _sh("decide_next_state auto 0 1045 starlink healthy 1 0 1 2 3")
    assert r4.stdout.strip() == "auto starlink 0 2"
    r5 = _sh("decide_next_state auto 0 1060 starlink healthy 1 0 2 2 3")
    assert r5.stdout.strip() == "auto cpe 0 3"

    # captive_login pins cpe while captive and unexpired
    r6 = _sh("decide_next_state captive_login 1600 1100 starlink captive 1 2 0 2 3")
    assert r6.stdout.strip() == "captive_login cpe 0 0"
    # captive_login auto-exits early to auto once HTTP 204 becomes healthy
    r7 = _sh("decide_next_state captive_login 1600 1150 cpe healthy 1 0 0 2 3")
    assert r7.stdout.strip() == "auto cpe 0 0"
    # captive_login auto-expires after deadline back to auto
    r8 = _sh("decide_next_state captive_login 1600 1600 cpe captive 1 0 0 2 3")
    assert r8.stdout.strip() == "auto cpe 1 0"

    # force_cpe never touches starlink even if cpe down; force_starlink locks starlink
    r9 = _sh("decide_next_state force_cpe 0 1000 starlink down 1 2 0 2 3")
    assert r9.stdout.strip() == "force_cpe cpe 0 0"
    r10 = _sh("decide_next_state force_starlink 0 1000 cpe healthy 1 0 3 2 3")
    assert r10.stdout.strip() == "force_starlink starlink 0 0"


def test_update_usage_bytes_increment_reboot_rollover_and_cycle_reset():
    # Normal increment: 100 -> 350 (+250) on stored_total 1000 -> 1250
    r1 = _sh("update_usage_bytes 2026-11 2026-11 100 1000 350")
    assert r1.stdout.strip() == "2026-11 350 1250"

    # Reboot rollover: counter dropped from 500 to 12 -> add 12 to 1000 -> 1012
    r2 = _sh("update_usage_bytes 2026-11 2026-11 500 1000 12")
    assert r2.stdout.strip() == "2026-11 12 1012"

    # Billing cycle rollover: 2026-11 -> 2026-12 resets total to 0, tracks new baseline
    r3 = _sh("update_usage_bytes 2026-12 2026-11 500 999999 650")
    assert r3.stdout.strip() == "2026-12 650 0"

    # Pre-NTP backward clock (1970-01 < 2026-11) MUST NOT wipe stored_total!
    r4 = _sh("update_usage_bytes 1970-01 2026-11 500 999999 600")
    assert r4.stdout.strip() == "2026-11 600 1000099"

    # Numeric comparison check: 1000 > 500 (not lexicographical "1000" < "500")
    r5 = _sh("update_usage_bytes 2026-11 2026-11 500 1000 1000")
    assert r5.stdout.strip() == "2026-11 1000 1500"


def test_parse_groove_monitor_extracts_fields():
    sample = """\
                 status: connected-to-ess
                channel: 5180/20-Ceee/ac(20dBm)
      wireless-protocol: 802.11
                tx-rate: 173.3Mbps-40MHz/2S/SGI
                rx-rate: 144.4Mbps-20MHz/2S/SGI
                   ssid: Campground Free WiFi
                  bssid: AA:BB:CC:DD:EE:FF
        signal-strength: -64dBm
"""
    r = _sh("parse_groove_monitor", stdin_text=sample)
    assert r.returncode == 0
    fields = r.stdout.rstrip("\n").split("|")
    assert fields == [
        "connected-to-ess",
        "Campground Free WiFi",
        "AA:BB:CC:DD:EE:FF",
        "-64",
        "5180/20-Ceee/ac(20dBm)",
        "173.3Mbps-40MHz/2S/SGI",
    ]

    # Empty SSID must NOT shift subsequent columns left
    hidden = "status: connected-to-ess\nssid: \nbssid: 11:22:33:44:55:66\nsignal-strength: -70dBm\n"
    r2 = _sh("parse_groove_monitor", stdin_text=hidden)
    assert r2.stdout.rstrip("\n").split("|")[:4] == ["connected-to-ess", "", "11:22:33:44:55:66", "-70"]


def test_van_wan_cli_mode_validation_and_default_config(tmp_path: Path):
    cfg = json.loads(DEFAULT_CFG.read_text(encoding="utf-8"))
    assert cfg["starlink_cap_gb"] == 50.0
    assert cfg["failover_strikes"] == 2
    assert cfg["failback_strikes"] == 3
    assert cfg["captive_override_sec"] == 600

    env = os.environ.copy()
    env["VAN_STATE_DIR"] = str(tmp_path / "run")
    env["VAN_CONF_DIR"] = str(tmp_path / "etc")
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "config.json").write_text(DEFAULT_CFG.read_text(encoding="utf-8"))

    bad = subprocess.run([str(VAN_WAN_CLI), "mode", "evil;id"], capture_output=True, text=True, env=env)
    assert bad.returncode != 0

    ok = subprocess.run([str(VAN_WAN_CLI), "mode", "captive_login"], capture_output=True, text=True, env=env)
    assert ok.returncode == 0, ok.stderr
    ov = json.loads((tmp_path / "run" / "override.json").read_text(encoding="utf-8"))
    assert ov["mode"] == "captive_login" and ov["expires_at"] > 0

    ok2 = subprocess.run([str(VAN_WAN_CLI), "mode", "force_cpe"], capture_output=True, text=True, env=env)
    assert ok2.returncode == 0, ok2.stderr
    mode_data = json.loads((tmp_path / "etc" / "mode.json").read_text(encoding="utf-8"))
    assert mode_data["mode"] == "force_cpe"
    assert not (tmp_path / "run" / "override.json").exists()


def test_cgi_enforces_csrf_origin_and_mode_whitelist(tmp_path: Path):
    cgi = ROOT / "router" / "www" / "cgi-bin" / "van-wan"
    state_dir = tmp_path / "run"
    conf_dir = tmp_path / "etc"
    state_dir.mkdir()
    conf_dir.mkdir()
    (conf_dir / "config.json").write_text(DEFAULT_CFG.read_text(encoding="utf-8"))
    (state_dir / "status.json").write_text('{"active_wan":"cpe","mode":"auto"}\n')

    def run_cgi(method: str, headers: dict, body: str = "") -> tuple[int, str]:
        env = os.environ.copy()
        env.update(
            {
                "REQUEST_METHOD": method,
                "CONTENT_LENGTH": str(len(body.encode("utf-8"))),
                "VAN_STATE_DIR": str(state_dir),
                "VAN_CONF_DIR": str(conf_dir),
                "VAN_CLI": str(VAN_WAN_CLI),
                "VAN_LIB_PATH": str(LIB_SH),
            }
        )
        env.update(headers)
        res = subprocess.run([str(cgi)], input=body, capture_output=True, text=True, env=env, check=False)
        status = 200
        for line in res.stdout.splitlines():
            if line.lower().startswith("status:"):
                status = int(line.split()[1])
        parts = res.stdout.split("\n\n", 1)
        if len(parts) == 1:
            parts = res.stdout.split("\r\n\r\n", 1)
        return status, parts[1] if len(parts) > 1 else ""

    code, body = run_cgi("GET", {})
    assert code == 200 and json.loads(body)["active_wan"] == "cpe"

    # Missing X-Van-Action header -> 403
    code, _ = run_cgi("POST", {"HTTP_ORIGIN": "http://192.168.8.1:8080"}, '{"mode":"captive_login"}')
    assert code == 403

    # Bad Origin -> 403
    code, _ = run_cgi(
        "POST",
        {"HTTP_X_VAN_ACTION": "1", "HTTP_ORIGIN": "https://evil.example"},
        '{"mode":"captive_login"}',
    )
    assert code == 403

    # Shell injection in mode -> 400
    code, _ = run_cgi(
        "POST",
        {"HTTP_X_VAN_ACTION": "1", "HTTP_ORIGIN": "http://192.168.8.1:8080"},
        '{"mode":"auto;id"}',
    )
    assert code == 400

    # Valid POST sets captive_login override
    code, body = run_cgi(
        "POST",
        {"HTTP_X_VAN_ACTION": "1", "HTTP_ORIGIN": "http://192.168.8.1:8080"},
        '{"mode":"captive_login"}',
    )
    assert code == 200 and json.loads(body)["mode"] == "captive_login"
    assert (state_dir / "override.json").exists()


def test_daemon_once_writes_valid_status_json_with_stubbed_probes(tmp_path: Path):
    daemon = ROOT / "router" / "usr" / "libexec" / "van-wan-guard" / "daemon.sh"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()

    (fake_bin / "ip").write_text(
        """#!/bin/sh
if [ "$1" = "-4" ] && [ "$2" = "addr" ]; then
  if [ "$5" = "eth0" ]; then echo "    inet 192.168.88.20/24 brd 192.168.88.255 scope global eth0"; fi
  if [ "$5" = "eth1" ]; then echo "    inet 100.64.10.2/10 scope global eth1"; fi
  exit 0
fi
if [ "$1" = "route" ] && [ "$2" = "show" ] && [ "$3" = "table" ]; then
  if [ "$4" = "101" ]; then echo "default via 192.168.88.1 dev eth0"; fi
  if [ "$4" = "102" ]; then echo "default via 100.64.0.1 dev eth1"; fi
  exit 0
fi
exit 0
"""
    )
    (fake_bin / "ping").write_text(
        """#!/bin/sh
echo "5 packets transmitted, 5 packets received, 0% packet loss"
echo "round-trip min/avg/max = 12.1/19.4/24.0 ms"
"""
    )
    (fake_bin / "curl").write_text("#!/bin/sh\nprintf '204'\n")
    for p in fake_bin.iterdir():
        p.chmod(0o755)

    state_dir = tmp_path / "run"
    conf_dir = tmp_path / "etc"
    sys_net = tmp_path / "sysnet"
    (sys_net / "eth0").mkdir(parents=True)
    (sys_net / "eth1" / "statistics").mkdir(parents=True)
    (sys_net / "eth0" / "carrier").write_text("1\n")
    (sys_net / "eth1" / "carrier").write_text("1\n")
    (sys_net / "eth1" / "statistics" / "rx_bytes").write_text("104857600\n")
    (sys_net / "eth1" / "statistics" / "tx_bytes").write_text("52428800\n")
    conf_dir.mkdir()
    (conf_dir / "config.json").write_text(DEFAULT_CFG.read_text(encoding="utf-8"))

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["VAN_STATE_DIR"] = str(state_dir)
    env["VAN_CONF_DIR"] = str(conf_dir)
    env["VAN_SYS_NET"] = str(sys_net)
    env["VAN_DRY_RUN"] = "1"
    env["VAN_SKIP_GROOVE"] = "1"
    env["VAN_REQUIRE_VPN"] = "0"

    res = subprocess.run([str(daemon), "--once"], capture_output=True, text=True, env=env, check=False)
    assert res.returncode == 0, res.stderr
    status = json.loads((state_dir / "status.json").read_text(encoding="utf-8"))
    assert status["active_wan"] == "cpe"
    assert status["mode"] == "auto"
    assert status["cpe"]["health"] == "healthy"
    assert status["cpe"]["http_code"] == 204
    assert status["cpe"]["rtt_ms"] == 19
    assert status["starlink"]["cap_gb"] == 50.0
    assert status["starlink"]["link_up"] is True


def test_captive_login_clears_previous_force_starlink_and_reset_creates_pending_flag(tmp_path: Path):
    env = os.environ.copy()
    env["VAN_STATE_DIR"] = str(tmp_path / "run")
    env["VAN_CONF_DIR"] = str(tmp_path / "etc")
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "config.json").write_text(DEFAULT_CFG.read_text(encoding="utf-8"))

    subprocess.run([str(VAN_WAN_CLI), "mode", "force_starlink"], check=True, env=env)
    subprocess.run([str(VAN_WAN_CLI), "mode", "captive_login"], check=True, env=env)
    # mode.json must be reset to auto so captive_login expiry never snaps back to force_starlink
    assert json.loads((tmp_path / "etc" / "mode.json").read_text())["mode"] == "auto"

    subprocess.run([str(VAN_WAN_CLI), "reset-usage"], check=True, env=env)
    assert (tmp_path / "etc" / "usage_reset.pending").exists()


def test_daemon_curl_timeout_returns_clean_3digit_code_and_force_cpe_deletes_starlink_route(tmp_path: Path):
    daemon = ROOT / "router" / "usr" / "libexec" / "van-wan-guard" / "daemon.sh"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    ip_log = tmp_path / "ip.log"

    (fake_bin / "ip").write_text(
        f"""#!/bin/sh
echo "$@" >> "{ip_log}"
if [ "$1" = "-4" ] && [ "$2" = "addr" ]; then
  if [ "$5" = "eth0" ]; then echo "    inet 192.168.88.20/24 scope global eth0"; fi
  if [ "$5" = "eth1" ]; then echo "    inet 100.64.10.2/10 scope global eth1"; fi
  exit 0
fi
if [ "$1" = "route" ] && [ "$2" = "show" ] && [ "$3" = "table" ]; then
  if [ "$4" = "101" ]; then echo "default via 192.168.88.1 dev eth0"; fi
  if [ "$4" = "102" ]; then echo "default via 100.64.0.1 dev eth1"; fi
  exit 0
fi
exit 0
"""
    )
    (fake_bin / "ping").write_text("#!/bin/sh\necho '5 packets transmitted, 5 packets received, 0% packet loss'\necho 'round-trip min/avg/max = 10/15/20 ms'\n")
    # Simulate curl printing 302 then exiting non-zero (transfer timeout after headers)
    (fake_bin / "curl").write_text("#!/bin/sh\nprintf '302'\nexit 28\n")
    (fake_bin / "killall").write_text("#!/bin/sh\nexit 0\n")
    for p in fake_bin.iterdir():
        p.chmod(0o755)

    state_dir = tmp_path / "run"
    conf_dir = tmp_path / "etc"
    sys_net = tmp_path / "sysnet"
    (sys_net / "eth0").mkdir(parents=True)
    (sys_net / "eth1" / "statistics").mkdir(parents=True)
    (sys_net / "eth0" / "carrier").write_text("1\n")
    (sys_net / "eth1" / "carrier").write_text("1\n")
    (sys_net / "eth1" / "statistics" / "rx_bytes").write_text("0\n")
    (sys_net / "eth1" / "statistics" / "tx_bytes").write_text("0\n")
    conf_dir.mkdir()
    (conf_dir / "config.json").write_text(DEFAULT_CFG.read_text(encoding="utf-8"))
    (conf_dir / "mode.json").write_text('{"mode":"force_cpe"}\n')

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["VAN_STATE_DIR"] = str(state_dir)
    env["VAN_CONF_DIR"] = str(conf_dir)
    env["VAN_SYS_NET"] = str(sys_net)
    env["VAN_RESOLV_FILE"] = str(tmp_path / "resolv.auto")
    env["VAN_DRY_RUN"] = "0"
    env["VAN_SKIP_GROOVE"] = "1"

    res = subprocess.run([str(daemon), "--once"], capture_output=True, text=True, env=env, check=False)
    assert res.returncode == 0, res.stderr
    status = json.loads((state_dir / "status.json").read_text(encoding="utf-8"))
    # Must be 302 (captive), NOT 302000 (down)!
    assert status["cpe"]["http_code"] == 302
    assert status["cpe"]["health"] == "captive"
    log_text = ip_log.read_text()
    # Must use onlink when setting default route in main with ip4table isolation
    assert "route replace default via 192.168.88.1 dev eth0 onlink metric 5" in log_text
    # force_cpe MUST delete Starlink default route and NOT install Starlink metric 50 fallback
    assert "route del default dev eth1" in log_text
    assert "via 100.64.0.1 dev eth1" not in log_text
    # Active DNS resolv.auto must be written for CPE
    assert (tmp_path / "resolv.auto").exists()


