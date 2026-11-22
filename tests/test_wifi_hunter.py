import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HUNTER_SH = ROOT / "router" / "usr" / "libexec" / "van-wan-guard" / "wifi-hunter.sh"
VAN_WAN_CLI = ROOT / "router" / "usr" / "bin" / "van-wan"
DEFAULT_CFG = ROOT / "router" / "etc" / "van-wan-guard" / "config.json"
DEFAULT_KNOWN = ROOT / "router" / "etc" / "van-wan-guard" / "known_networks.json"


def _make_fake_env(tmp_path: Path, wg_van_ok: bool = False, lua_rank_json: str = "[]"):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(parents=True, exist_ok=True)
    log_file = tmp_path / "calls.log"
    now = int(subprocess.check_output(["date", "+%s"]).decode().strip())

    # Minimal fake lua stub that mimics networks.lua subcommands for local pytest runs
    (fake_bin / "lua").write_text(
        f"""#!/bin/sh
echo "LUA $@" >> "{log_file}"
shift
cmd="$1"
shift
case "$cmd" in
  get-config)
    key="$2"
    def="${{3:-}}"
    case "$key" in
      auto_hunt) echo "true" ;;
      cooldown_sec) echo "7200" ;;
      *) echo "$def" ;;
    esac
    ;;
  rank-scan)
    cat >/dev/null
    printf '%s\\n' '{lua_rank_json}'
    ;;
  ros-connect-cmd)
    echo '/interface wireless set [find default-name=wlan1] security-profile="van-open" ssid="'"$2"'" bssid="'"${{3:-}}"'"'
    ;;
  is-trusted)
    exit 1
    ;;
  cooldown)
    echo "COOLDOWN $2 $3 $4" >> "{log_file}"
    printf '{{"ok":true}}\\n'
    ;;
  update-state)
    cat >/dev/null
    printf '{{"ok":true}}\\n'
    ;;
  list)
    printf '{{"auto_hunt":true,"networks":[]}}\\n'
    ;;
  upsert|delete|block|set-config)
    cat >/dev/null
    printf '{{"ok":true,"cmd":"%s"}}\\n' "$cmd"
    ;;
  *)
    exit 1
    ;;
esac
"""
    )
    (fake_bin / "dbclient").write_text(
        f"""#!/bin/sh
echo "DBCLIENT $@" >> "{log_file}"
echo "AB EE:EE:EE:EE:EE:01 Free Cafe WiFi 2462/20 -62 -100 38 none"
"""
    )
    (fake_bin / "timeout").write_text('#!/bin/sh\nshift\nexec "$@"\n')
    (fake_bin / "ip").write_text(
        """#!/bin/sh
if [ "$1" = "-4" ] && [ "$2" = "addr" ]; then
  if [ "$5" = "eth0" ]; then echo "    inet 192.168.88.20/24 scope global eth0"; fi
  if [ "$5" = "wg_van" ]; then echo "    inet 192.168.2.6/32 scope global wg_van"; fi
  exit 0
fi
if [ "$1" = "route" ] && [ "$2" = "show" ] && [ "$3" = "table" ] && [ "$4" = "101" ]; then
  echo "default via 192.168.88.1 dev eth0"
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
echo "round-trip min/avg/max = 10.0/15.0/20.0 ms"
"""
    )
    hs_ts = now - 15 if wg_van_ok else 0
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
    (fake_bin / "udhcpc").write_text("#!/bin/sh\nexit 0\n")
    for p in fake_bin.iterdir():
        p.chmod(0o755)

    conf_dir = tmp_path / "etc"
    state_dir = tmp_path / "run"
    conf_dir.mkdir(exist_ok=True)
    state_dir.mkdir(exist_ok=True)
    (conf_dir / "config.json").write_text(DEFAULT_CFG.read_text(encoding="utf-8"))
    (conf_dir / "groove_dropbear.key").write_text("dummykey")
    if DEFAULT_KNOWN.exists():
        (conf_dir / "known_networks.json").write_text(DEFAULT_KNOWN.read_text(encoding="utf-8"))
    else:
        (conf_dir / "known_networks.json").write_text('{"auto_hunt":true,"networks":[],"blocklist":[]}')

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["VAN_CONF_DIR"] = str(conf_dir)
    env["VAN_STATE_DIR"] = str(state_dir)
    env["VAN_HUNTER_WAIT_DHCP_SEC"] = "1"
    env["VAN_HUNTER_WAIT_VPN_SEC"] = "1"
    return env, log_file, state_dir, conf_dir


def test_wifi_hunter_lock_exclusion_returns_busy(tmp_path: Path):
    env, _, state_dir, _ = _make_fake_env(tmp_path)
    lock_dir = state_dir / "hunter.lock"
    lock_dir.mkdir(parents=True)
    # Write current process PID so lock appears live
    (lock_dir / "pid").write_text(str(os.getpid()))

    r = subprocess.run([str(HUNTER_SH), "scan"], capture_output=True, text=True, env=env, check=False)
    assert r.returncode == 3, f"expected rc=3 busy, got rc={r.returncode} out={r.stdout} err={r.stderr}"
    data = json.loads(r.stdout)
    assert data["ok"] is False
    assert data["error"] == "busy"


def test_wifi_hunter_records_vpn_blocked_cooldown_when_gate3_fails(tmp_path: Path):
    rank_json = json.dumps([
        {
            "ssid": "Free Cafe WiFi",
            "bssid": "EE:EE:EE:EE:EE:01",
            "rssi_dbm": -62,
            "security": "open",
            "tier": 4,
            "trusted": False,
            "vpn_required": True,
            "profile": "van-open",
        }
    ])
    env, log_file, _, _ = _make_fake_env(tmp_path, wg_van_ok=False, lua_rank_json=rank_json)

    r = subprocess.run([str(HUNTER_SH), "auto"], capture_output=True, text=True, env=env, check=False)
    assert r.returncode == 0, r.stderr
    logs = log_file.read_text()
    assert "COOLDOWN EE:EE:EE:EE:EE:01 vpn_blocked" in logs
    out = json.loads(r.stdout)
    assert out["connected"] is False


def test_wifi_hunter_connect_succeeds_when_gate3_passes(tmp_path: Path):
    env, _, _, _ = _make_fake_env(tmp_path, wg_van_ok=True)
    r = subprocess.run(
        [str(HUNTER_SH), "connect", "Free Cafe WiFi", "EE:EE:EE:EE:EE:01"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["ok"] is True
    assert out["vpn_verified"] is True


def test_van_wan_cli_hunter_and_networks_subcommands(tmp_path: Path):
    env, log_file, _, _ = _make_fake_env(tmp_path, wg_van_ok=True)
    r_list = subprocess.run([str(VAN_WAN_CLI), "networks", "list"], capture_output=True, text=True, env=env, check=False)
    assert r_list.returncode == 0, r_list.stderr
    assert json.loads(r_list.stdout)["auto_hunt"] is True

    r_tog = subprocess.run([str(VAN_WAN_CLI), "hunt-toggle", "off"], capture_output=True, text=True, env=env, check=False)
    assert r_tog.returncode == 0, r_tog.stderr
    assert json.loads(r_tog.stdout)["ok"] is True

    r_scan = subprocess.run([str(VAN_WAN_CLI), "hunt-scan"], capture_output=True, text=True, env=env, check=False)
    assert r_scan.returncode == 0, r_scan.stderr
    assert json.loads(r_scan.stdout)["ok"] is True


def test_cgi_supports_networks_get_and_csrf_guarded_hunter_actions(tmp_path: Path):
    cgi = ROOT / "router" / "www" / "cgi-bin" / "van-wan"
    lib_sh = ROOT / "router" / "usr" / "libexec" / "van-wan-guard" / "lib.sh"
    env, _, _, _ = _make_fake_env(tmp_path, wg_van_ok=True)
    env["VAN_CLI"] = str(VAN_WAN_CLI)
    env["VAN_LIB_PATH"] = str(lib_sh)

    # 1. GET ?resource=networks returns redacted allowlist JSON
    get_env = dict(env, REQUEST_METHOD="GET", QUERY_STRING="resource=networks")
    r_get = subprocess.run([str(cgi)], capture_output=True, text=True, env=get_env, check=False)
    assert r_get.returncode == 0, r_get.stderr
    assert "Status: 200 OK" in r_get.stdout
    body_get = json.loads(r_get.stdout.split("\n\n", 1)[1])
    assert body_get["auto_hunt"] is True

    # 2. POST hunt-scan without X-Van-Action is rejected (403)
    payload = json.dumps({"action": "hunt-scan"})
    bad_env = dict(
        env,
        REQUEST_METHOD="POST",
        HTTP_ORIGIN="http://192.168.8.1:8080",
        CONTENT_LENGTH=str(len(payload)),
    )
    r_403 = subprocess.run([str(cgi)], input=payload, capture_output=True, text=True, env=bad_env, check=False)
    assert "Status: 403 Forbidden" in r_403.stdout

    # 3. POST hunt-scan, hunt-connect, hunt-config, networks-upsert with valid CSRF succeed (200)
    for act_payload in [
        {"action": "hunt-scan"},
        {"action": "hunt-connect", "ssid": "Free Cafe WiFi", "bssid": "EE:EE:EE:EE:EE:01"},
        {"action": "hunt-config", "auto_hunt": False},
        {"action": "networks-upsert", "ssid": "TestNet", "security": "wpa2", "psk": "secret123", "trusted": False},
    ]:
        raw = json.dumps(act_payload)
        ok_env = dict(
            env,
            REQUEST_METHOD="POST",
            HTTP_X_VAN_ACTION="1",
            HTTP_ORIGIN="http://192.168.8.1:8080",
            CONTENT_LENGTH=str(len(raw)),
        )
        r_ok = subprocess.run([str(cgi)], input=raw, capture_output=True, text=True, env=ok_env, check=False)
        assert r_ok.returncode == 0, r_ok.stderr
        assert "Status: 200 OK" in r_ok.stdout, f"payload={act_payload} out={r_ok.stdout}"

    # 4. POST invalid action returns 400
    raw_bad = json.dumps({"action": "rm-rf"})
    inv_env = dict(
        env,
        REQUEST_METHOD="POST",
        HTTP_X_VAN_ACTION="1",
        HTTP_ORIGIN="http://192.168.8.1:8080",
        CONTENT_LENGTH=str(len(raw_bad)),
    )
    r_400 = subprocess.run([str(cgi)], input=raw_bad, capture_output=True, text=True, env=inv_env, check=False)
    assert "Status: 400 Bad Request" in r_400.stdout

    # 5. Regex metacharacters in HTTP_HOST must NOT bypass Origin check
    evil_env = dict(
        env,
        REQUEST_METHOD="POST",
        HTTP_X_VAN_ACTION="1",
        HTTP_HOST=".*:8080",
        HTTP_ORIGIN="http://evil.example.com:8080",
        CONTENT_LENGTH=str(len(payload)),
    )
    r_evil = subprocess.run([str(cgi)], input=payload, capture_output=True, text=True, env=evil_env, check=False)
    assert "Status: 403 Forbidden" in r_evil.stdout

    # 6. Optional ui_token enforces 401 when missing/wrong and allows 200 when matching
    conf_dir = Path(env["VAN_CONF_DIR"])
    (conf_dir / "ui_token").write_text("s3cr3t-lan-token\n", encoding="utf-8")
    r_unauth = subprocess.run([str(cgi)], capture_output=True, text=True, env=get_env, check=False)
    assert "Status: 401 Unauthorized" in r_unauth.stdout
    auth_get_env = dict(get_env, HTTP_X_VAN_TOKEN="s3cr3t-lan-token")
    r_auth = subprocess.run([str(cgi)], capture_output=True, text=True, env=auth_get_env, check=False)
    assert "Status: 200 OK" in r_auth.stdout


def test_wifi_hunter_refuses_psk_argv_fallback_without_scp(tmp_path: Path):
    env, log_file, _, _ = _make_fake_env(tmp_path, wg_van_ok=True)
    # Override fake lua to emit a PSK connect command; remove scp from PATH
    fake_bin = tmp_path / "bin"
    lua_path = fake_bin / "lua"
    lua_txt = lua_path.read_text(encoding="utf-8").replace(
        'echo \'/interface wireless set [find default-name=wlan1] security-profile="van-open" ssid="\'\"$2\"\'\" bssid="\'\"${3:-}\"\'\"\'',
        'echo \'/interface wireless security-profiles set [find name="van-dyn"] wpa2-pre-shared-key="SuperSecretPSK"\'',
    )
    lua_path.write_text(lua_txt, encoding="utf-8")
    # Restrict PATH to fake_bin + minimal dir without scp (or override scp with failing stub not executable)
    no_scp_dir = tmp_path / "minbin"
    no_scp_dir.mkdir()
    for tool in ("sh", "awk", "sed", "grep", "tr", "cat", "rm", "mkdir", "mv", "date", "sleep", "head", "dd", "mktemp", "chmod"):
        for base in ("/usr/bin", "/bin"):
            src = Path(base) / tool
            if src.exists():
                (no_scp_dir / tool).symlink_to(src)
                break
    env["PATH"] = f"{fake_bin}:{no_scp_dir}"
    r = subprocess.run(
        [str(HUNTER_SH), "connect", "PrivateNet", "AA:BB:CC:DD:EE:01"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert r.returncode != 0
    logs = log_file.read_text(encoding="utf-8") if log_file.exists() else ""
    assert "SuperSecretPSK" not in logs


def test_wifi_hunter_sigterm_during_scp_cleans_up_psk_rsc(tmp_path: Path):
    import signal
    import time

    env, _, state_dir, _ = _make_fake_env(tmp_path, wg_van_ok=True)
    fake_bin = tmp_path / "bin"
    lua_path = fake_bin / "lua"
    lua_txt = lua_path.read_text(encoding="utf-8").replace(
        'echo \'/interface wireless set [find default-name=wlan1] security-profile="van-open" ssid="\'\"$2\"\'\" bssid="\'\"${3:-}\"\'\"\'',
        'echo \'/interface wireless security-profiles set [find name="van-dyn"] wpa2-pre-shared-key="SuperSecretPSK"\'',
    )
    lua_path.write_text(lua_txt, encoding="utf-8")

    marker = tmp_path / "scp_started"
    fake_scp = fake_bin / "scp"
    fake_scp.write_text(
        f"""#!/bin/sh
touch "{marker}"
sleep 10
""",
        encoding="utf-8",
    )
    fake_scp.chmod(0o755)

    proc = subprocess.Popen(
        [str(HUNTER_SH), "connect", "PrivateNet", "AA:BB:CC:DD:EE:01"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        start_new_session=True,
    )
    deadline = time.time() + 5.0
    while not marker.exists() and time.time() < deadline:
        time.sleep(0.05)
    assert marker.exists(), "fake scp never started"

    # Verify .rsc existed mid-scp, then SIGTERM process group and confirm cleanup removes it
    rsc_before = list(state_dir.glob("van_hunter.*.rsc"))
    assert len(rsc_before) == 1
    os.killpg(proc.pid, signal.SIGTERM)
    proc.wait(timeout=5)

    rsc_after = list(state_dir.glob("van_hunter.*.rsc"))
    assert rsc_after == [], f"Orphaned PSK .rsc survived SIGTERM: {rsc_after}"
