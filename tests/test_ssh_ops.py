import subprocess
from pathlib import Path
from ssh_ops import (
    disable_kvm_cloud,
    disable_van_cloud,
    parse_kvm_probe_output,
    parse_triage_output,
    parse_van_router_probe_output,
    probe_kvm,
    run_triage_sweep,
    set_van_wan_mode,
)

SAMPLE_PROBE = """\
---VERSION---
RK_MODEL=RM1PE
RK_VERSION=V1.10.0 release1
---UPTIME---
 09:30:01 up 12:14,  0 users,  load average: 0.12, 0.08, 0.05
---CLOUDCONF---
{"enable": false}
---PROCS---
"""


def test_parse_kvm_probe_clean():
    parsed = parse_kvm_probe_output(SAMPLE_PROBE)
    assert parsed["model"] == "RM1PE"
    assert parsed["fw"] == "V1.10.0 release1"
    assert parsed["uptime"] == "up 12:14"
    assert parsed["cloud_config_enabled"] is False
    assert parsed["cloud_procs"] == []
    assert parsed["cloud_off"] is True


def test_parse_kvm_probe_detects_running_cloud_proc():
    dirty = SAMPLE_PROBE + "  412 root /usr/sbin/gl-cloud\n"
    parsed = parse_kvm_probe_output(dirty)
    assert parsed["cloud_procs"] == ["412 root /usr/sbin/gl-cloud"]
    assert parsed["cloud_off"] is False


def test_parse_triage_exit_codes_and_summary():
    out = "Header\nSummary: IOC=0 PERSIST=0 REVIEW=1 INFO=0\nVerdict: REVIEW (no IOCs)\n"
    res0 = parse_triage_output(0, out, "")
    assert res0["status"] == "clean" and res0["summary"] == {"IOC": 0, "PERSIST": 0, "REVIEW": 1, "INFO": 0}
    assert res0["verdict"] == "REVIEW (no IOCs)"
    res1 = parse_triage_output(1, "Summary: IOC=2 PERSIST=1 REVIEW=0 INFO=0\nVerdict: COMPROMISED\n", "")
    assert res1["status"] == "ioc" and res1["summary"]["IOC"] == 2
    res4 = parse_triage_output(4, "", "script error")
    assert res4["status"] == "error"
    res255 = parse_triage_output(255, "", "Connection timed out")
    assert res255["status"] == "error" and "Connection timed out" in res255["output"]


def test_run_triage_sweep_handles_timeout(tmp_path: Path):
    script = tmp_path / "triage.sh"
    script.write_text("#!/bin/sh\necho ok\n")

    def fake_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="ssh", timeout=45)

    res = run_triage_sweep("10.10.20.12", "root", tmp_path / "id_ed25519", script, runner=fake_timeout)
    assert res["status"] == "error" and "timed out" in res["verdict"].lower()

    missing = run_triage_sweep("10.10.20.12", "root", tmp_path / "id_ed25519", tmp_path / "missing.sh", runner=fake_timeout)
    assert missing["status"] == "error" and "not installed" in missing["verdict"].lower()


def test_probe_kvm_and_disable_cloud_handle_errors(tmp_path: Path):
    def fake_fail(*args, **kwargs):
        return subprocess.CompletedProcess(args=args[0], returncode=255, stdout="", stderr="No route to host")

    res = probe_kvm("10.10.20.12", "root", tmp_path / "id_ed25519", runner=fake_fail)
    assert res["ok"] is False and "No route to host" in res["error"]

    res_dis = disable_kvm_cloud("10.10.20.12", "root", tmp_path / "id_ed25519", runner=fake_fail)
    assert res_dis["ok"] is False


def test_parse_van_router_probe_extracts_fw_cloud_and_van_wan_json():
    raw = """\
---GLVERSION---
4.8.1
---UPTIME---
 12:00:01 up 3 days,  4:12,  load average: 0.10, 0.05, 0.01
---CLOUDUCI---
0
---PROCS---
---VANWAN---
{"active_wan":"cpe","mode":"auto","cpe":{"health":"healthy","rtt_ms":21,"loss_pct":0},"starlink":{"monthly_gb":4.25,"cap_gb":50.0,"pct_used":8.5},"groove":{"reachable":true,"ssid":"CampWiFi","rssi_dbm":-62}}
"""
    parsed = parse_van_router_probe_output(raw)
    assert parsed["fw"] == "4.8.1"
    assert parsed["cloud_config_enabled"] is False
    assert parsed["cloud_off"] is True
    assert parsed["van_wan"]["active_wan"] == "cpe"
    assert parsed["van_wan"]["starlink"]["monthly_gb"] == 4.25
    assert parsed["van_wan"]["groove"]["ssid"] == "CampWiFi"


def test_set_van_wan_mode_validates_allowed_modes_and_disable_van_cloud(tmp_path: Path):
    calls = []

    def fake_ok(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout='{"ok":true,"mode":"captive_login"}\n', stderr="")

    bad = set_van_wan_mode("192.168.2.5", "root", tmp_path / "k", "evil;reboot", runner=fake_ok)
    assert bad["ok"] is False and calls == []

    ok = set_van_wan_mode("192.168.2.5", "root", tmp_path / "k", "captive_login", runner=fake_ok)
    assert ok["ok"] is True and len(calls) == 1
    assert "van-wan mode captive_login" in calls[0][-1]

    dis = disable_van_cloud("192.168.2.5", "root", tmp_path / "k", runner=fake_ok)
    assert dis["ok"] is True and "uci set gl-cloud.@cloud[0].enable='0'" in calls[-1][-1]


def test_van_hunter_and_networks_ssh_ops_use_45s_timeout_and_stdin_json(tmp_path: Path):
    from ssh_ops import (
        list_van_networks,
        mutate_van_networks,
        run_van_hunt_connect,
        run_van_hunt_scan,
        set_van_hunt_config,
    )

    seen = []

    def fake_run(cmd, **kwargs):
        seen.append((cmd, kwargs))
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout='{"ok":true,"candidates":[]}\n', stderr="")

    # 1. Scan uses 45s timeout and disables IPQoS (prevents GL.iNet 4.11+ Wi-Fi DSCP drops)
    res_scan = run_van_hunt_scan("192.168.2.5", "root", tmp_path / "k", runner=fake_run)
    assert res_scan["ok"] is True
    assert seen[-1][1]["timeout"] == 45
    assert "IPQoS=none" in seen[-1][0]
    assert seen[-1][0][-1] == "/usr/bin/van-wan hunt-scan"

    # 2. Connect rejects control chars and passes SSID/BSSID strictly on stdin (zero shell interpolation!)
    bad = run_van_hunt_connect("192.168.2.5", "root", tmp_path / "k", "bad\nssid", runner=fake_run)
    assert bad["ok"] is False

    res_conn = run_van_hunt_connect("192.168.2.5", "root", tmp_path / "k", 'Cafe "WiFi" $1', "AA:BB:CC:DD:EE:FF", runner=fake_run)
    assert res_conn["ok"] is True
    assert seen[-1][1]["timeout"] == 45
    assert seen[-1][0][-1] == "/usr/bin/van-wan hunt-connect --stdin"
    assert "Cafe" not in seen[-1][0][-1]
    assert '"ssid": "Cafe \\"WiFi\\" $1"' in seen[-1][1]["input"]

    # 3. Mutate networks passes PSK strictly on stdin (never in remote argv!)
    res_mut = mutate_van_networks(
        "192.168.2.5",
        "root",
        tmp_path / "k",
        {"action": "upsert", "ssid": "HomeNet", "security": "wpa2", "psk": "SuperSecret!123", "trusted": True},
        runner=fake_run,
    )
    assert res_mut["ok"] is True
    assert "SuperSecret" not in " ".join(seen[-1][0])
    assert seen[-1][0][-1] == "/usr/bin/van-wan networks upsert"
    assert "SuperSecret!123" in seen[-1][1]["input"]

    # 4. List & config
    assert list_van_networks("192.168.2.5", "root", tmp_path / "k", runner=fake_run)["ok"] is True
    assert set_van_hunt_config("192.168.2.5", "root", tmp_path / "k", {"auto_hunt": False}, runner=fake_run)["ok"] is True


