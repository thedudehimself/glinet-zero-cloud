import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIB_SH = ROOT / "router" / "usr" / "libexec" / "van-wan-guard" / "lib.sh"
VPN_GATE_SH = ROOT / "router" / "usr" / "libexec" / "van-wan-guard" / "vpn-gate.sh"
DAEMON_SH = ROOT / "router" / "usr" / "libexec" / "van-wan-guard" / "daemon.sh"
DEFAULT_CFG = ROOT / "router" / "etc" / "van-wan-guard" / "config.json"


def _sh(snippet: str, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    script = f'. "{LIB_SH}"\n. "{VPN_GATE_SH}"\n{snippet}\n'
    return subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, env=env, check=False)


def test_classify_cpe_with_vpn_gates():
    cases = [
        ("healthy 0 0", "vpn_blocked"),
        ("healthy 0 1", "healthy_vpn"),
        ("healthy 1 0", "healthy_trusted"),
        ("healthy 1 1", "healthy_trusted"),
        ("captive 0 0", "captive"),
        ("degraded 0 1", "degraded"),
        ("down 1 1", "down"),
    ]
    for args, expected in cases:
        r = _sh(f"classify_cpe_with_vpn {args}")
        assert r.returncode == 0, r.stderr
        assert r.stdout.strip() == expected, f"args={args} got={r.stdout!r}"


def test_apply_vpn_gate_enforces_locked_vpn_active_captive_and_trusted(tmp_path: Path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    ipt_log = tmp_path / "ipt.log"
    ip_log = tmp_path / "ip.log"

    (fake_bin / "iptables").write_text(f'#!/bin/sh\necho "$@" >> "{ipt_log}"\ncase " $* " in *" -C "*) exit 1 ;; esac\nexit 0\n')
    (fake_bin / "ip6tables").write_text(f'#!/bin/sh\necho "V6 $@" >> "{ipt_log}"\ncase " $* " in *" -C "*) exit 1 ;; esac\nexit 0\n')
    (fake_bin / "ip").write_text(f'#!/bin/sh\necho "$@" >> "{ip_log}"\nexit 0\n')
    for p in fake_bin.iterdir():
        p.chmod(0o755)

    env = {"PATH": f"{fake_bin}:{os.environ['PATH']}", "VAN_STATE_DIR": str(tmp_path / "run")}

    # 1. locked state: unconditional FORWARD 1 -o eth0, atomic REJECT, DNS REJECT, fwmark 0x101 unreachable + !eth0 DROP, wg_van src unreachable
    r = _sh("apply_vpn_gate locked eth0 wg_van 192.168.2.6 wg_mgmt 192.168.2.5", env_extra=env)
    assert r.returncode == 0, r.stderr
    ipt = ipt_log.read_text()
    ipl = ip_log.read_text()
    assert "-I FORWARD 1 -o eth0 -j VAN_CPE_GATE" in ipt
    assert "-I VAN_CPE_GATE 1 -j REJECT" in ipt
    assert "-I VAN_CPE_DNS_OUT 1 -p udp --dport 53 -j REJECT" in ipt
    assert "-m mark --mark 0x101 ! -o eth0 -j DROP" in ipt
    assert "V6 -w -I FORWARD 1 -o eth0 -j REJECT" in ipt
    assert "rule add fwmark 0x101 table 101 prio 85" in ipl
    assert "rule add fwmark 0x101 unreachable prio 86" in ipl
    assert "rule add from 192.168.2.5/32 table 104 prio 88" in ipl
    assert "rule add from 192.168.2.6/32 table 103 prio 89" in ipl
    assert "rule add from 192.168.2.6/32 unreachable prio 90" in ipl
    assert "rule del prio 95" in ipl

    # 2. vpn_active: keeps VAN_CPE_GATE REJECT locked AND installs table 103 + prio 93/94/95/96 + terminal 97/98 unreachable
    ipt_log.write_text("")
    ip_log.write_text("")
    r2 = _sh("apply_vpn_gate vpn_active eth0 wg_van 192.168.2.6 wg_mgmt 192.168.2.5", env_extra=env)
    assert r2.returncode == 0, r2.stderr
    ipt2 = ipt_log.read_text()
    ipl2 = ip_log.read_text()
    assert "-I VAN_CPE_GATE 1 -j REJECT" in ipt2
    assert "-I VAN_CPE_DNS_OUT 1 -p udp --dport 53 -j REJECT" in ipt2
    assert "route replace default dev wg_van table 103" in ipl2
    assert "rule add to 192.168.2.1/32 table 103 prio 93" in ipl2
    assert "rule add to 192.168.8.0/24 table main prio 94" in ipl2
    assert "rule add iif br-lan table 103 prio 95" in ipl2
    assert "rule add iif br-guest table 103 prio 96" in ipl2
    assert "rule add iif br-lan unreachable prio 97" in ipl2
    assert "rule add iif br-guest unreachable prio 98" in ipl2

    # 3. captive_temp: allows ONLY 80,443 TCP and 53 UDP/TCP on eth0, removes table 103 client rules
    ipt_log.write_text("")
    ip_log.write_text("")
    r3 = _sh("apply_vpn_gate captive_temp eth0 wg_van 192.168.2.6 wg_mgmt 192.168.2.5", env_extra=env)
    assert r3.returncode == 0, r3.stderr
    ipt3 = ipt_log.read_text()
    assert "--dport 80 -j ACCEPT" in ipt3
    assert "--dport 443 -j ACCEPT" in ipt3
    assert "--dport 53 -j ACCEPT" in ipt3
    assert "-I VAN_CPE_GATE 1 -j REJECT" in ipt3

    # 4. trusted_direct: allows eth0 directly and removes table 103 client rules
    ipt_log.write_text("")
    ip_log.write_text("")
    r4 = _sh("apply_vpn_gate trusted_direct eth0 wg_van 192.168.2.6 wg_mgmt 192.168.2.5", env_extra=env)
    assert r4.returncode == 0, r4.stderr
    assert "-A VAN_CPE_GATE -j ACCEPT" in ipt_log.read_text()


def _run_daemon_vpn_scenario(tmp_path: Path, wg_van_ok: bool) -> tuple[dict, str]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(parents=True, exist_ok=True)
    now = int(subprocess.check_output(["date", "+%s"]).decode().strip())

    (fake_bin / "ip").write_text(
        """#!/bin/sh
if [ "$1" = "-4" ] && [ "$2" = "addr" ]; then
  if [ "$5" = "eth0" ]; then echo "    inet 192.168.88.20/24 scope global eth0"; fi
  if [ "$5" = "eth1" ]; then echo "    inet 100.64.10.2/10 scope global eth1"; fi
  if [ "$5" = "wg_van" ]; then echo "    inet 192.168.2.6/32 scope global wg_van"; fi
  if [ "$5" = "wg_mgmt" ]; then echo "    inet 192.168.2.5/32 scope global wg_mgmt"; fi
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
    ping_wg = "exit 0" if wg_van_ok else "exit 1"
    (fake_bin / "ping").write_text(
        f"""#!/bin/sh
case "$*" in
  *"192.168.2.6"*) {ping_wg} ;;
esac
echo "5 packets transmitted, 5 packets received, 0% packet loss"
echo "round-trip min/avg/max = 12.0/18.0/22.0 ms"
"""
    )
    hs_ts = now - 20 if wg_van_ok else 0
    (fake_bin / "wg").write_text(f"#!/bin/sh\necho 'peerpub\t{hs_ts}'\n")
    (fake_bin / "curl").write_text(
        """#!/bin/sh
case "$*" in
  *"dns-query"*) printf '{"Answer":[{"data":"142.250.80.14"}]}' ;;
  *) printf '204' ;;
esac
"""
    )
    (fake_bin / "iptables").write_text("#!/bin/sh\nexit 0\n")
    (fake_bin / "ip6tables").write_text("#!/bin/sh\nexit 0\n")
    (fake_bin / "killall").write_text("#!/bin/sh\nexit 0\n")
    for p in fake_bin.iterdir():
        p.chmod(0o755)

    state_dir = tmp_path / "run"
    conf_dir = tmp_path / "etc"
    sys_net = tmp_path / "sysnet"
    (sys_net / "eth0").mkdir(parents=True, exist_ok=True)
    (sys_net / "eth1" / "statistics").mkdir(parents=True, exist_ok=True)
    (sys_net / "eth0" / "carrier").write_text("1\n")
    (sys_net / "eth1" / "carrier").write_text("1\n")
    (sys_net / "eth1" / "statistics" / "rx_bytes").write_text("0\n")
    (sys_net / "eth1" / "statistics" / "tx_bytes").write_text("0\n")
    conf_dir.mkdir(exist_ok=True)
    (conf_dir / "config.json").write_text(DEFAULT_CFG.read_text(encoding="utf-8"))
    resolv = tmp_path / "resolv.auto"
    resolv.write_text("")

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["VAN_STATE_DIR"] = str(state_dir)
    env["VAN_CONF_DIR"] = str(conf_dir)
    env["VAN_SYS_NET"] = str(sys_net)
    env["VAN_RESOLV_FILE"] = str(resolv)
    env["VAN_DRY_RUN"] = "0"
    env["VAN_SKIP_GROOVE"] = "1"
    env["VAN_REQUIRE_VPN"] = "1"

    res = subprocess.run([str(DAEMON_SH), "--once"], capture_output=True, text=True, env=env, check=False)
    assert res.returncode == 0, res.stderr
    return json.loads((state_dir / "status.json").read_text()), resolv.read_text()


def test_daemon_blocks_untrusted_cpe_when_wg_van_down_and_encrypts_when_up(tmp_path: Path):
    st_down, resolv_down = _run_daemon_vpn_scenario(tmp_path / "down", wg_van_ok=False)
    assert st_down["cpe"]["health"] == "vpn_blocked"
    assert st_down["vpn"]["state"] == "killswitch_locked"
    assert "192.168.88.1" not in resolv_down

    st_up, resolv_up = _run_daemon_vpn_scenario(tmp_path / "up", wg_van_ok=True)
    assert st_up["cpe"]["health"] == "healthy_vpn"
    assert st_up["vpn"]["state"] == "encrypted"
    assert resolv_up.strip() == "nameserver 192.168.2.1"


def test_captive_login_exits_immediately_on_vpn_blocked():
    # Critical #2 regression: once HTTP 204 clears on a VPN-blocking AP, captive_login MUST exit to auto
    r = _sh("decide_next_state captive_login 9999999999 1000 cpe vpn_blocked 1 0 0 2 3")
    assert r.returncode == 0, r.stderr
    parts = r.stdout.strip().split()
    assert parts[0] == "auto", f"expected captive_login to exit to auto on vpn_blocked, got {parts}"


def test_daemon_ignores_stale_or_searching_groove_ssid_and_hunter_lock_for_trust(tmp_path: Path):
    # Critical #1 regression: stale/searching groove.json or live hunter.lock MUST NOT open trusted_direct
    base = tmp_path / "trust_race"
    fake_bin = base / "bin"
    fake_bin.mkdir(parents=True)
    now = int(subprocess.check_output(["date", "+%s"]).decode().strip())
    (fake_bin / "ip").write_text(
        """#!/bin/sh
if [ "$1" = "-4" ] && [ "$2" = "addr" ]; then
  if [ "$5" = "eth0" ]; then echo "    inet 192.168.88.20/24 scope global eth0"; fi
  if [ "$5" = "wg_van" ]; then echo "    inet 192.168.2.6/32 scope global wg_van"; fi
  exit 0
fi
if [ "$1" = "route" ] && [ "$2" = "show" ] && [ "$3" = "table" ] && [ "$4" = "101" ]; then
  echo "default via 192.168.88.1 dev eth0"
fi
exit 0
"""
    )
    (fake_bin / "ping").write_text(
        """#!/bin/sh
case "$*" in *"192.168.2.6"*) exit 1 ;; esac
echo "5 packets transmitted, 5 packets received, 0% packet loss"
echo "round-trip min/avg/max = 12.0/18.0/22.0 ms"
"""
    )
    (fake_bin / "wg").write_text("#!/bin/sh\necho 'peerpub\t0'\n")
    (fake_bin / "curl").write_text(
        """#!/bin/sh
case "$*" in
  *"dns-query"*) printf '{"Answer":[{"data":"142.250.80.14"}]}' ;;
  *) printf '204' ;;
esac
"""
    )
    (fake_bin / "iptables").write_text("#!/bin/sh\nexit 0\n")
    (fake_bin / "ip6tables").write_text("#!/bin/sh\nexit 0\n")
    (fake_bin / "killall").write_text("#!/bin/sh\nexit 0\n")
    # Fake lua reports HomeWiFi as trusted if asked
    (fake_bin / "lua").write_text('#!/bin/sh\n[ "$2" = "is-trusted" ] && [ "$4" = "HomeWiFi" ] && exit 0\nexit 1\n')
    for p in fake_bin.iterdir():
        p.chmod(0o755)

    state_dir = base / "run"
    conf_dir = base / "etc"
    sys_net = base / "sysnet"
    (sys_net / "eth0").mkdir(parents=True)
    (sys_net / "eth1" / "statistics").mkdir(parents=True)
    (sys_net / "eth0" / "carrier").write_text("1\n")
    (sys_net / "eth1" / "carrier").write_text("0\n")
    (sys_net / "eth1" / "statistics" / "rx_bytes").write_text("0\n")
    (sys_net / "eth1" / "statistics" / "tx_bytes").write_text("0\n")
    state_dir.mkdir(parents=True)
    conf_dir.mkdir(parents=True)
    (conf_dir / "config.json").write_text(DEFAULT_CFG.read_text(encoding="utf-8"))
    (conf_dir / "known_networks.json").write_text('{"networks":[{"ssid":"HomeWiFi","security":"wpa2","psk":"pw","trusted":true}]}')
    resolv = base / "resolv.auto"
    resolv.write_text("")

    # Case A: groove.json says status=searching-for-network (not connected-to-ess!)
    (state_dir / "groove.json").write_text('{"reachable":true,"status":"searching-for-network","ssid":"HomeWiFi"}')
    env = os.environ.copy()
    env.update({
        "PATH": f"{fake_bin}:{env['PATH']}",
        "VAN_STATE_DIR": str(state_dir),
        "VAN_CONF_DIR": str(conf_dir),
        "VAN_SYS_NET": str(sys_net),
        "VAN_RESOLV_FILE": str(resolv),
        "VAN_DRY_RUN": "0",
        "VAN_SKIP_GROOVE": "1",
        "VAN_REQUIRE_VPN": "1",
    })
    r = subprocess.run([str(DAEMON_SH), "--once"], capture_output=True, text=True, env=env, check=False)
    assert r.returncode == 0, r.stderr
    st = json.loads((state_dir / "status.json").read_text())
    assert st["vpn"]["trusted_ssid"] is False
    assert st["vpn"]["state"] == "killswitch_locked"

    # Case B: groove.json says connected-to-ess BUT hunter.lock is live (switching APs)
    (state_dir / "groove.json").write_text('{"reachable":true,"status":"connected-to-ess","ssid":"HomeWiFi"}')
    (state_dir / "hunter.lock").mkdir()
    (state_dir / "hunter.lock" / "pid").write_text(str(os.getpid()))
    r2 = subprocess.run([str(DAEMON_SH), "--once"], capture_output=True, text=True, env=env, check=False)
    assert r2.returncode == 0, r2.stderr
    st2 = json.loads((state_dir / "status.json").read_text())
    assert st2["vpn"]["trusted_ssid"] is False
    assert st2["vpn"]["state"] == "killswitch_locked"


def test_daemon_parses_multiline_pretty_printed_ping_targets(tmp_path: Path):
    base = tmp_path / "ml"
    fake_bin = base / "bin"
    fake_bin.mkdir(parents=True)
    ping_log = base / "ping_targets.log"

    (fake_bin / "ip").write_text(
        """#!/bin/sh
if [ "$1" = "-4" ] && [ "$2" = "addr" ]; then
  if [ "$5" = "eth0" ]; then echo "    inet 192.168.88.20/24 scope global eth0"; fi
  exit 0
fi
if [ "$1" = "route" ] && [ "$2" = "show" ] && [ "$3" = "table" ] && [ "$4" = "101" ]; then
  echo "default via 192.168.88.1 dev eth0"
fi
exit 0
"""
    )
    (fake_bin / "ping").write_text(
        f"""#!/bin/sh
echo "PING $*" >> "{ping_log}"
echo "5 packets transmitted, 5 packets received, 0% packet loss"
echo "round-trip min/avg/max = 10.0/12.0/15.0 ms"
"""
    )
    (fake_bin / "wg").write_text("#!/bin/sh\necho 'peerpub\t0'\n")
    (fake_bin / "curl").write_text("#!/bin/sh\nprintf '204'\n")
    (fake_bin / "iptables").write_text("#!/bin/sh\nexit 0\n")
    (fake_bin / "ip6tables").write_text("#!/bin/sh\nexit 0\n")
    (fake_bin / "killall").write_text("#!/bin/sh\nexit 0\n")
    for p in fake_bin.iterdir():
        p.chmod(0o755)

    state_dir = base / "run"
    conf_dir = base / "etc"
    sys_net = base / "sysnet"
    (sys_net / "eth0").mkdir(parents=True)
    (sys_net / "eth1" / "statistics").mkdir(parents=True)
    (sys_net / "eth0" / "carrier").write_text("1\n")
    (sys_net / "eth1" / "carrier").write_text("0\n")
    (sys_net / "eth1" / "statistics" / "rx_bytes").write_text("0\n")
    (sys_net / "eth1" / "statistics" / "tx_bytes").write_text("0\n")
    state_dir.mkdir(parents=True)
    conf_dir.mkdir(parents=True)

    cfg = json.loads(DEFAULT_CFG.read_text(encoding="utf-8"))
    cfg["ping_targets"] = ["9.9.9.9", "149.112.112.112"]
    # Pretty-printed multi-line JSON identical to deploy/setup-mt3000.sh
    (conf_dir / "config.json").write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    resolv = base / "resolv.auto"
    resolv.write_text("")

    env = os.environ.copy()
    env.update({
        "PATH": f"{fake_bin}:{env['PATH']}",
        "VAN_STATE_DIR": str(state_dir),
        "VAN_CONF_DIR": str(conf_dir),
        "VAN_SYS_NET": str(sys_net),
        "VAN_RESOLV_FILE": str(resolv),
        "VAN_DRY_RUN": "0",
        "VAN_SKIP_GROOVE": "1",
        "VAN_REQUIRE_VPN": "1",
    })
    r = subprocess.run([str(DAEMON_SH), "--once"], capture_output=True, text=True, env=env, check=False)
    assert r.returncode == 0, r.stderr
    logged = ping_log.read_text(encoding="utf-8")
    assert "9.9.9.9" in logged, f"Custom pretty-printed ping_targets ignored! Got: {logged}"
    assert "1.1.1.1" not in logged

