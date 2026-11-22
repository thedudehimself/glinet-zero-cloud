"""SSH operations for GLKVM devices (probe, streaming CSA-2026-01 triage, disable-cloud, reboot)."""

from __future__ import annotations

import json
import re
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SUMMARY_RE = re.compile(r"Summary:\s*IOC=(\d+)\s+PERSIST=(\d+)\s+REVIEW=(\d+)\s+INFO=(\d+)")
VERDICT_RE = re.compile(r"Verdict:\s*(.+)")
UPTIME_RE = re.compile(r"\b(up\s+[^,]+(?:,\s*\d+:\d+)?)")

PROBE_REMOTE_CMD = (
    "echo '---VERSION---'; cat /etc/version 2>/dev/null || true; "
    "echo '---UPTIME---'; uptime 2>/dev/null || true; "
    "echo '---CLOUDCONF---'; cat /etc/glinet/gl-cloud.conf 2>/dev/null || true; "
    "echo '---PROCS---'; ps w 2>/dev/null | grep -E '[g]l-cloud|[r]tty' || true"
)

DISABLE_CLOUD_REMOTE_CMD = (
    "printf '{\"enable\": false}\\n' > /etc/glinet/gl-cloud.conf && "
    "(/etc/init.d/S99gl-cloud stop 2>/dev/null || true) && "
    "(/etc/init.d/S99rtty stop 2>/dev/null || true) && "
    "(killall gl-cloud gl_cloud rtty 2>/dev/null || true)"
)

REBOOT_REMOTE_CMD = "(sleep 1; reboot) >/dev/null 2>&1 &"

VALID_VAN_MODES = {"auto", "captive_login", "force_cpe", "force_starlink"}

VAN_PROBE_REMOTE_CMD = (
    "echo '---GLVERSION---'; cat /etc/glversion 2>/dev/null || true; "
    "echo '---UPTIME---'; uptime 2>/dev/null || true; "
    "echo '---CLOUDUCI---'; uci -q get gl-cloud.@cloud[0].enable 2>/dev/null || echo 0; "
    "echo '---PROCS---'; ps w 2>/dev/null | grep -E '[g]l-cloud|[g]l_cloud|[r]tty' || true; "
    "echo '---VANWAN---'; /usr/bin/van-wan status 2>/dev/null || true"
)

DISABLE_VAN_CLOUD_REMOTE_CMD = (
    "uci set gl-cloud.@cloud[0].enable='0' 2>/dev/null || true; "
    "uci commit gl-cloud 2>/dev/null || true; "
    "(/etc/init.d/gl_cloud stop 2>/dev/null || true); "
    "(/etc/init.d/gl-cloud stop 2>/dev/null || true); "
    "(/etc/init.d/rtty stop 2>/dev/null || true); "
    "(killall gl-cloud gl_cloud rtty 2>/dev/null || true)"
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ssh_base_cmd(ip: str, user: str, key_path: Path) -> list[str]:
    known_hosts = Path(key_path).parent / "known_hosts"
    return [
        "ssh",
        "-i",
        str(key_path),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=4",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=2",
        "-o",
        "IPQoS=none",
        f"{user}@{ip}",
    ]


def check_tcp_reachable(ip: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def parse_kvm_probe_output(stdout: str) -> dict:
    sections: dict[str, list[str]] = {}
    current = None
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("---") and stripped.endswith("---") and len(stripped) > 6:
            current = stripped.strip("-")
            sections[current] = []
        elif current is not None:
            sections[current].append(line)

    model = None
    fw = None
    for line in sections.get("VERSION", []):
        if line.startswith("RK_MODEL="):
            model = line.split("=", 1)[1].strip()
        elif line.startswith("RK_VERSION="):
            fw = line.split("=", 1)[1].strip()

    uptime_raw = " ".join(sections.get("UPTIME", [])).strip()
    uptime = None
    if uptime_raw:
        m = UPTIME_RE.search(uptime_raw)
        uptime = m.group(1).strip() if m else uptime_raw

    cloud_config_enabled = None
    cloud_text = "\n".join(sections.get("CLOUDCONF", [])).strip()
    if cloud_text:
        try:
            data = json.loads(cloud_text)
            if isinstance(data, dict) and "enable" in data:
                cloud_config_enabled = bool(data["enable"])
        except json.JSONDecodeError:
            cloud_config_enabled = None

    cloud_procs = [ln.strip() for ln in sections.get("PROCS", []) if ln.strip()]
    cloud_off = (cloud_config_enabled is False) and (len(cloud_procs) == 0)

    return {
        "model": model,
        "fw": fw,
        "uptime": uptime,
        "cloud_config_enabled": cloud_config_enabled,
        "cloud_procs": cloud_procs,
        "cloud_off": cloud_off,
    }


def parse_triage_output(exit_code: int, stdout: str, stderr: str) -> dict:
    combined = stdout
    if stderr.strip():
        combined = f"{stdout}\n[stderr]\n{stderr}".strip() if stdout.strip() else stderr.strip()

    summary: dict[str, int] = {}
    m_sum = SUMMARY_RE.search(stdout)
    if m_sum:
        summary = {
            "IOC": int(m_sum.group(1)),
            "PERSIST": int(m_sum.group(2)),
            "REVIEW": int(m_sum.group(3)),
            "INFO": int(m_sum.group(4)),
        }

    m_ver = VERDICT_RE.search(stdout)
    verdict = m_ver.group(1).strip() if m_ver else ""

    if exit_code == 0:
        status = "clean"
        verdict = verdict or "CLEAN"
    elif exit_code == 1:
        status = "ioc"
        verdict = verdict or "IOC DETECTED"
    else:
        status = "error"
        if not verdict:
            err_line = next((ln.strip() for ln in stderr.splitlines() if ln.strip()), "")
            verdict = err_line or f"SSH/script error (exit {exit_code})"

    return {
        "timestamp": _utc_now(),
        "exit_code": exit_code,
        "status": status,
        "verdict": verdict,
        "summary": summary,
        "output": combined,
    }


def probe_kvm(ip: str, user: str, key_path: Path, runner=subprocess.run, timeout: int = 12) -> dict:
    cmd = _ssh_base_cmd(ip, user, key_path) + [PROBE_REMOTE_CMD]
    try:
        proc = runner(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"SSH probe timed out after {timeout}s"}
    except OSError as exc:
        return {"ok": False, "error": str(exc) or type(exc).__name__}

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or f"SSH exited {proc.returncode}").strip()
        return {"ok": False, "error": err}

    parsed = parse_kvm_probe_output(proc.stdout)
    parsed["ok"] = True
    parsed["error"] = None
    return parsed


def run_triage_sweep(
    ip: str,
    user: str,
    key_path: Path,
    script_path: Path,
    runner=subprocess.run,
    timeout: int = 45,
) -> dict:
    p = Path(script_path)
    if not p.is_file():
        msg = f"Triage script not found at {p}. Fetch upstream admonstrator/glinet-csa-2026-01 to enable sweeps."
        return {
            "timestamp": _utc_now(),
            "exit_code": -1,
            "status": "error",
            "verdict": "Triage script not installed",
            "summary": {},
            "output": msg,
        }
    script_text = p.read_text(encoding="utf-8")
    cmd = _ssh_base_cmd(ip, user, key_path) + ["sh -s -- --check --no-report --no-color"]
    try:
        proc = runner(
            cmd,
            input=script_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "timestamp": _utc_now(),
            "exit_code": -1,
            "status": "error",
            "verdict": f"Triage sweep timed out after {timeout}s",
            "summary": {},
            "output": f"SSH triage sweep timed out after {timeout}s",
        }
    except OSError as exc:
        msg = str(exc) or type(exc).__name__
        return {
            "timestamp": _utc_now(),
            "exit_code": -1,
            "status": "error",
            "verdict": msg,
            "summary": {},
            "output": msg,
        }
    return parse_triage_output(proc.returncode, proc.stdout or "", proc.stderr or "")


def disable_kvm_cloud(ip: str, user: str, key_path: Path, runner=subprocess.run, timeout: int = 15) -> dict:
    cmd = _ssh_base_cmd(ip, user, key_path) + [DISABLE_CLOUD_REMOTE_CMD]
    try:
        proc = runner(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"ok": False, "error": str(exc) or type(exc).__name__}
    if proc.returncode != 0:
        return {"ok": False, "error": (proc.stderr or proc.stdout or f"SSH exited {proc.returncode}").strip()}
    return {"ok": True, "error": None}


def reboot_kvm(ip: str, user: str, key_path: Path, runner=subprocess.run, timeout: int = 10) -> dict:
    cmd = _ssh_base_cmd(ip, user, key_path) + [REBOOT_REMOTE_CMD]
    try:
        proc = runner(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"ok": False, "error": str(exc) or type(exc).__name__}
    if proc.returncode != 0:
        return {"ok": False, "error": (proc.stderr or proc.stdout or f"SSH exited {proc.returncode}").strip()}
    return {"ok": True, "error": None}


def parse_van_router_probe_output(stdout: str) -> dict:
    sections: dict[str, list[str]] = {}
    current = None
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("---") and stripped.endswith("---") and len(stripped) > 6:
            current = stripped.strip("-")
            sections[current] = []
        elif current is not None:
            sections[current].append(line)

    fw = "\n".join(sections.get("GLVERSION", [])).strip() or None

    uptime_raw = " ".join(sections.get("UPTIME", [])).strip()
    uptime = None
    if uptime_raw:
        m = UPTIME_RE.search(uptime_raw)
        uptime = m.group(1).strip() if m else uptime_raw

    uci_val = "\n".join(sections.get("CLOUDUCI", [])).strip()
    cloud_config_enabled: bool | None = None
    if uci_val in ("0", "false", "off"):
        cloud_config_enabled = False
    elif uci_val in ("1", "true", "on"):
        cloud_config_enabled = True

    cloud_procs = [ln.strip() for ln in sections.get("PROCS", []) if ln.strip()]
    cloud_off = (cloud_config_enabled is False) and (len(cloud_procs) == 0)

    van_wan = None
    van_raw = "\n".join(sections.get("VANWAN", [])).strip()
    if van_raw:
        try:
            parsed_json = json.loads(van_raw)
            if isinstance(parsed_json, dict) and "active_wan" in parsed_json:
                van_wan = parsed_json
        except json.JSONDecodeError:
            van_wan = None

    return {
        "fw": fw,
        "uptime": uptime,
        "cloud_config_enabled": cloud_config_enabled,
        "cloud_procs": cloud_procs,
        "cloud_off": cloud_off,
        "van_wan": van_wan,
    }


def probe_van_router(ip: str, user: str, key_path: Path, runner=subprocess.run, timeout: int = 12) -> dict:
    cmd = _ssh_base_cmd(ip, user, key_path) + [VAN_PROBE_REMOTE_CMD]
    try:
        proc = runner(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"SSH probe timed out after {timeout}s"}
    except OSError as exc:
        return {"ok": False, "error": str(exc) or type(exc).__name__}

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or f"SSH exited {proc.returncode}").strip()
        return {"ok": False, "error": err}

    parsed = parse_van_router_probe_output(proc.stdout)
    parsed["ok"] = True
    parsed["error"] = None
    return parsed


def disable_van_cloud(ip: str, user: str, key_path: Path, runner=subprocess.run, timeout: int = 15) -> dict:
    cmd = _ssh_base_cmd(ip, user, key_path) + [DISABLE_VAN_CLOUD_REMOTE_CMD]
    try:
        proc = runner(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"ok": False, "error": str(exc) or type(exc).__name__}
    if proc.returncode != 0:
        return {"ok": False, "error": (proc.stderr or proc.stdout or f"SSH exited {proc.returncode}").strip()}
    return {"ok": True, "error": None}


def set_van_wan_mode(ip: str, user: str, key_path: Path, mode: str, runner=subprocess.run, timeout: int = 12) -> dict:
    if mode not in VALID_VAN_MODES:
        return {"ok": False, "error": f"Invalid mode: {mode!r}"}
    cmd = _ssh_base_cmd(ip, user, key_path) + [f"/usr/bin/van-wan mode {mode}"]
    try:
        proc = runner(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"ok": False, "error": str(exc) or type(exc).__name__}
    if proc.returncode != 0:
        return {"ok": False, "error": (proc.stderr or proc.stdout or f"SSH exited {proc.returncode}").strip()}
    try:
        data = json.loads((proc.stdout or "").strip() or "{}")
    except json.JSONDecodeError:
        data = {}
    return {"ok": True, "mode": mode, "result": data, "error": None}


VALID_NETWORK_ACTIONS = {"upsert", "delete", "block", "unblock"}
_BSSID_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


def _has_control_chars(val: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in val)


def _run_van_json_cmd(
    ip: str,
    user: str,
    key_path: Path,
    remote_cmd: str,
    payload: dict | None = None,
    runner=subprocess.run,
    timeout: int = 15,
) -> dict:
    cmd = _ssh_base_cmd(ip, user, key_path) + [remote_cmd]
    kwargs = {"capture_output": True, "text": True, "timeout": timeout, "check": False}
    if payload is not None:
        kwargs["input"] = json.dumps(payload)
    try:
        proc = runner(cmd, **kwargs)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"SSH command timed out after {timeout}s"}
    except OSError as exc:
        return {"ok": False, "error": str(exc) or type(exc).__name__}

    raw_out = (proc.stdout or "").strip()
    parsed = None
    if raw_out:
        try:
            parsed = json.loads(raw_out)
        except json.JSONDecodeError:
            parsed = None

    if proc.returncode != 0:
        if isinstance(parsed, dict) and parsed.get("error"):
            err = str(parsed["error"])
        else:
            err = (proc.stderr or raw_out or f"SSH exited {proc.returncode}").strip()
        out = {"ok": False, "error": err, "exit_code": proc.returncode}
        if isinstance(parsed, dict):
            out["result"] = parsed
        return out

    if isinstance(parsed, dict):
        parsed.setdefault("ok", True)
        return parsed
    return {"ok": True, "raw": raw_out}


def run_van_hunt_scan(ip: str, user: str, key_path: Path, runner=subprocess.run, timeout: int = 45) -> dict:
    return _run_van_json_cmd(ip, user, key_path, "/usr/bin/van-wan hunt-scan", runner=runner, timeout=timeout)


def run_van_hunt_connect(
    ip: str,
    user: str,
    key_path: Path,
    ssid: str,
    bssid: str = "",
    runner=subprocess.run,
    timeout: int = 45,
) -> dict:
    if not isinstance(ssid, str) or not (1 <= len(ssid) <= 32) or _has_control_chars(ssid):
        return {"ok": False, "error": "Invalid SSID (1-32 printable characters required)", "exit_code": 2}
    if bssid and (not isinstance(bssid, str) or not _BSSID_RE.match(bssid)):
        return {"ok": False, "error": "Invalid BSSID format", "exit_code": 2}
    return _run_van_json_cmd(
        ip,
        user,
        key_path,
        "/usr/bin/van-wan hunt-connect --stdin",
        payload={"ssid": ssid, "bssid": bssid.upper() if bssid else ""},
        runner=runner,
        timeout=timeout,
    )


def set_van_hunt_config(
    ip: str,
    user: str,
    key_path: Path,
    cfg: dict,
    runner=subprocess.run,
    timeout: int = 15,
) -> dict:
    if not isinstance(cfg, dict):
        return {"ok": False, "error": "Config payload must be a JSON object", "exit_code": 2}
    allowed_keys = {"auto_hunt", "allow_xfinity", "allow_open_wifi", "min_rssi_dbm", "cooldown_sec"}
    clean = {k: v for k, v in cfg.items() if k in allowed_keys}
    if not clean:
        return {"ok": False, "error": "No valid hunt config fields provided", "exit_code": 2}
    return _run_van_json_cmd(
        ip,
        user,
        key_path,
        "/usr/bin/van-wan hunt-config",
        payload=clean,
        runner=runner,
        timeout=timeout,
    )


def list_van_networks(ip: str, user: str, key_path: Path, runner=subprocess.run, timeout: int = 15) -> dict:
    return _run_van_json_cmd(ip, user, key_path, "/usr/bin/van-wan networks list", runner=runner, timeout=timeout)


def get_van_status(ip: str, user: str, key_path: Path, runner=subprocess.run, timeout: int = 12) -> dict:
    return _run_van_json_cmd(ip, user, key_path, "/usr/bin/van-wan status", runner=runner, timeout=timeout)


def reset_van_usage(ip: str, user: str, key_path: Path, runner=subprocess.run, timeout: int = 12) -> dict:
    return _run_van_json_cmd(ip, user, key_path, "/usr/bin/van-wan reset-usage", runner=runner, timeout=timeout)


def mutate_van_networks(
    ip: str,
    user: str,
    key_path: Path,
    payload: dict,
    runner=subprocess.run,
    timeout: int = 15,
) -> dict:
    if not isinstance(payload, dict):
        return {"ok": False, "error": "Payload must be a JSON object"}
    action = payload.get("action")
    if action not in VALID_NETWORK_ACTIONS:
        return {"ok": False, "error": f"Invalid network action: {action!r}"}

    if action == "upsert":
        remote_cmd = "/usr/bin/van-wan networks upsert"
        clean = {
            k: payload[k]
            for k in ("ssid", "security", "psk", "trusted", "priority")
            if k in payload
        }
    elif action == "delete":
        remote_cmd = "/usr/bin/van-wan networks delete --stdin"
        clean = {"ssid": payload.get("ssid", "")}
    elif action == "block":
        remote_cmd = "/usr/bin/van-wan networks block --stdin"
        clean = {"pattern": payload.get("pattern", "")}
    else:
        remote_cmd = "/usr/bin/van-wan networks unblock --stdin"
        clean = {"pattern": payload.get("pattern", "")}

    return _run_van_json_cmd(ip, user, key_path, remote_cmd, payload=clean, runner=runner, timeout=timeout)

