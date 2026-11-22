"""GL.iNet private management portal HTTP server & background poller (127.0.0.1:8450)."""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from conntrack import is_conntrack_gateway_available, scan_system_conntrack
from nginx_sync import sync_nginx_upstreams
from resolver import load_config, read_system_tables, read_wg_active_ips, resolve_device_ip
from ssh_ops import (
    VALID_NETWORK_ACTIONS,
    VALID_VAN_MODES,
    check_tcp_reachable,
    disable_kvm_cloud,
    disable_van_cloud,
    get_van_status,
    list_van_networks,
    mutate_van_networks,
    probe_kvm,
    probe_van_router,
    reboot_kvm,
    reset_van_usage,
    run_triage_sweep,
    run_van_hunt_connect,
    run_van_hunt_scan,
    set_van_hunt_config,
    set_van_wan_mode,
)
from store import StateStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
LOG = logging.getLogger("glinet-portal")

STATIC_DIR = Path(__file__).resolve().parent / "static"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hdr_get_all(headers, name: str) -> list[str]:
    if hasattr(headers, "get_all"):
        vals = headers.get_all(name)
        if vals is not None:
            return [str(v).strip() for v in vals]
    lower = name.lower()
    return [str(v).strip() for k, v in headers.items() if k.lower() == lower]


def _normalize_ip(val: str) -> str:
    try:
        return str(ipaddress.ip_address(val.strip())).lower()
    except ValueError:
        return ""


def _hdr_get(headers, name: str) -> str:
    vals = _hdr_get_all(headers, name)
    return vals[-1] if vals else ""


class PortalApp:
    def __init__(
        self,
        config: dict,
        store: StateStore,
        triage_script: Path | None = None,
        ssh_key: Path | None = None,
        nginx_conf: Path | None = None,
        upstreams_path: Path | None = None,
        nginx_pid: Path | None = None,
        enable_system_io: bool = True,
        sweep_fn: Callable | None = None,
        probe_fn: Callable | None = None,
        van_probe_fn: Callable | None = None,
        disable_cloud_fn: Callable | None = None,
        disable_van_cloud_fn: Callable | None = None,
        reboot_fn: Callable | None = None,
        wan_mode_fn: Callable | None = None,
        hunt_scan_fn: Callable | None = None,
        hunt_connect_fn: Callable | None = None,
        hunt_config_fn: Callable | None = None,
        list_networks_fn: Callable | None = None,
        mutate_networks_fn: Callable | None = None,
        van_status_fn: Callable | None = None,
        van_reset_usage_fn: Callable | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.tailscale_host = str(config.get("tailscale_host", "")).lower()
        self.allowed_users = {u.lower() for u in config.get("allowed_tailscale_users", [])}
        self.allowed_ips = {
            norm for ip in config.get("allowed_tailscale_ips", []) if (norm := _normalize_ip(ip))
        }
        self.devices: list[dict] = list(config.get("devices", []))
        self.devices_by_id: dict[str, dict] = {d["id"]: d for d in self.devices}
        self.triage_script = Path(triage_script) if triage_script else Path("/opt/glinet-portal/gl-helper-triage.sh")
        self.ssh_key = Path(ssh_key) if ssh_key else Path("/opt/glinet-portal/id_ed25519")
        self.nginx_conf = Path(nginx_conf) if nginx_conf else Path("/opt/glinet-portal/nginx.conf")
        self.upstreams_path = Path(upstreams_path) if upstreams_path else Path("/run/glinet-portal/upstreams.conf")
        self.nginx_pid = Path(nginx_pid) if nginx_pid else Path("/run/glinet-portal/nginx.pid")
        self.enable_system_io = enable_system_io

        self._sweep_fn = sweep_fn or run_triage_sweep
        self._probe_fn = probe_fn or probe_kvm
        self._van_probe_fn = van_probe_fn or probe_van_router
        self._disable_cloud_fn = disable_cloud_fn or disable_kvm_cloud
        self._disable_van_cloud_fn = disable_van_cloud_fn or disable_van_cloud
        self._reboot_fn = reboot_fn or reboot_kvm
        self._wan_mode_fn = wan_mode_fn or set_van_wan_mode
        self._hunt_scan_fn = hunt_scan_fn or run_van_hunt_scan
        self._hunt_connect_fn = hunt_connect_fn or run_van_hunt_connect
        self._hunt_config_fn = hunt_config_fn or set_van_hunt_config
        self._list_networks_fn = list_networks_fn or list_van_networks
        self._mutate_networks_fn = mutate_networks_fn or mutate_van_networks
        self._van_status_fn = van_status_fn or get_van_status
        self._van_reset_usage_fn = van_reset_usage_fn or reset_van_usage

        self._state_lock = threading.Lock()
        self._fast_lock = threading.Lock()
        self._ssh_lock = threading.Lock()
        self._sweep_locks: dict[str, threading.Lock] = {d["id"]: threading.Lock() for d in self.devices}
        self._hunt_locks: dict[str, threading.Lock] = {d["id"]: threading.Lock() for d in self.devices}
        self._stop_event = threading.Event()
        self._nginx_sync_status: dict = {"changed": False, "reloaded": False, "error": None}

        # Hydrate cached state from SQLite on startup
        self._device_state: dict[str, dict] = self.store.get_all_device_statuses()
        for dev in self.devices:
            self._device_state.setdefault(
                dev["id"],
                {
                    "ip": dev["fallback_ip"],
                    "vlan": dev.get("preferred_vlan", "br0"),
                    "source": "fallback",
                    "neigh_state": None,
                    "online": False,
                    "fw": None,
                    "uptime": None,
                    "cloud_config_enabled": None,
                    "cloud_procs": [],
                    "cloud_off": None,
                    "ssh_error": None,
                    "last_probe_at": None,
                },
            )
        self._latest_sweeps: dict[str, dict] = self.store.get_latest_sweeps()
        self._conntrack: dict = self.store.get_conntrack_snapshot()

    def is_authorized(self, headers, method: str, path: str) -> tuple[bool, int, str]:
        ts_user = _hdr_get(headers, "Tailscale-User-Login").lower()
        xff_vals = _hdr_get_all(headers, "X-Forwarded-For")
        xff_raw = ",".join(xff_vals).strip()
        xff_parts = [p.strip() for p in xff_raw.split(",") if p.strip()] if xff_raw else []
        xff_ip = _normalize_ip(xff_parts[-1]) if xff_parts else ""
        clean_path = path.split("?", 1)[0]

        if ts_user:
            if ts_user not in self.allowed_users:
                return False, 403, f"Tailscale user {ts_user!r} is not allowlisted"
        elif xff_ip and xff_ip in self.allowed_ips:
            pass
        else:
            if method in ("GET", "HEAD") and clean_path == "/healthz" and not xff_raw:
                return True, 200, "ok"
            return False, 403, "Tailscale authentication required"

        if method == "POST":
            if clean_path == "/cgi-bin/van-wan":
                if _hdr_get(headers, "X-Van-Action") != "1" and _hdr_get(headers, "X-Portal-Action") != "1":
                    return False, 403, "Missing X-Van-Action header"
            elif _hdr_get(headers, "X-Portal-Action") != "1":
                return False, 403, "Missing X-Portal-Action header"
            origin = _hdr_get(headers, "Origin")
            if not origin:
                return False, 403, "Missing Origin header"
            if not self.tailscale_host:
                return False, 403, "Portal tailscale_host is not configured"
            parsed_origin = urlparse(origin)
            origin_scheme = (parsed_origin.scheme or "").lower()
            origin_host = (parsed_origin.hostname or "").lower()
            if origin_scheme != "https" or origin_host != self.tailscale_host:
                return False, 403, f"Origin {origin!r} must use https://{self.tailscale_host}"

        return True, 200, "ok"

    def refresh_fast(self) -> dict:
        if not self.enable_system_io:
            return self.build_devices_payload()

        with self._fast_lock:
            leases, neighbors = read_system_tables()
            wg_ifaces = {d.get("wg_iface", "wg0") for d in self.devices if d.get("wg_ip")}
            wg_active_by_iface = {iface: read_wg_active_ips(iface) for iface in wg_ifaces}
            resolved_ips: dict[str, str] = {}
            conntrack_map: dict[str, dict] = {}

            for dev in self.devices:
                dev_id = dev["id"]
                wg_active = wg_active_by_iface.get(dev.get("wg_iface", "wg0")) if dev.get("wg_ip") else None
                res = resolve_device_ip(dev, leases, neighbors, wg_active_ips=wg_active)
                ip = res["ip"]
                online = check_tcp_reachable(ip, dev["upstream_port"], timeout=1.5)
                if not online and res["source"] == "wireguard":
                    if not check_tcp_reachable(ip, 22, timeout=1.5):
                        lan_res = resolve_device_ip(dev, leases, neighbors, wg_active_ips=None)
                        if lan_res["ip"] != ip and (
                            check_tcp_reachable(lan_res["ip"], dev["upstream_port"], timeout=1.5)
                            or check_tcp_reachable(lan_res["ip"], 22, timeout=1.5)
                        ):
                            res = lan_res
                            ip = res["ip"]
                            online = check_tcp_reachable(ip, dev["upstream_port"], timeout=1.5)
                resolved_ips[dev_id] = ip
                conntrack_map[ip] = {"id": dev_id, "role": dev["role"]}
                with self._state_lock:
                    st = dict(self._device_state.get(dev_id, {}))
                    st.update(
                        {
                            "ip": ip,
                            "vlan": res["vlan"],
                            "source": res["source"],
                            "neigh_state": res["neigh_state"],
                            "online": online,
                            "checked_at": _utc_now(),
                        }
                    )
                    self._device_state[dev_id] = st
                    self.store.upsert_device_status(dev_id, st)

            sync_res = sync_nginx_upstreams(
                self.devices,
                resolved_ips,
                self.upstreams_path,
                self.nginx_conf,
                self.nginx_pid,
            )
            self._nginx_sync_status = sync_res
            if sync_res.get("changed"):
                LOG.info("Synced nginx upstreams: %s", sync_res)
            elif sync_res.get("error"):
                LOG.warning("Nginx upstream sync error: %s", sync_res["error"])

            ct_available = is_conntrack_gateway_available()
            alerts = scan_system_conntrack(conntrack_map) if ct_available else []
            checked_at = _utc_now()
            with self._state_lock:
                self._conntrack = {"checked_at": checked_at, "available": ct_available, "alerts": alerts}
                self.store.save_conntrack_alerts(alerts, checked_at)
        return self.build_devices_payload()

    def refresh_ssh(self, device_id: str | None = None) -> None:
        with self._ssh_lock:
            targets = [self.devices_by_id[device_id]] if device_id and device_id in self.devices_by_id else self.devices
            for dev in targets:
                if not dev.get("ssh_enabled"):
                    continue
                dev_id = dev["id"]
                with self._state_lock:
                    cur = self._device_state.get(dev_id, {})
                    ip = cur.get("ip") or dev["fallback_ip"]
                    online = bool(cur.get("online", False))
                if not online and self.enable_system_io:
                    if not check_tcp_reachable(ip, 22, timeout=1.5):
                        with self._state_lock:
                            st = dict(self._device_state.get(dev_id, {}))
                            st["ssh_error"] = "Device offline"
                            st["last_probe_at"] = _utc_now()
                            self._device_state[dev_id] = st
                            self.store.upsert_device_status(dev_id, st)
                        continue
                probe_fn = self._van_probe_fn if dev.get("role") == "van_router" else self._probe_fn
                probe = probe_fn(ip, dev.get("ssh_user", "root"), self.ssh_key)
                with self._state_lock:
                    st = dict(self._device_state.get(dev_id, {}))
                    st["last_probe_at"] = _utc_now()
                    if probe.get("ok"):
                        st["fw"] = probe.get("fw") or st.get("fw")
                        st["uptime"] = probe.get("uptime")
                        st["cloud_config_enabled"] = probe.get("cloud_config_enabled")
                        st["cloud_procs"] = probe.get("cloud_procs", [])
                        st["cloud_off"] = probe.get("cloud_off")
                        if "van_wan" in probe:
                            st["van_wan"] = probe.get("van_wan")
                        st["ssh_error"] = None
                    else:
                        st["ssh_error"] = probe.get("error") or "SSH probe failed"
                    self._device_state[dev_id] = st
                    self.store.upsert_device_status(dev_id, st)

    def trigger_sweep(self, device_id: str) -> tuple[int, dict]:
        dev = self.devices_by_id.get(device_id)
        if not dev:
            return 404, {"error": f"Unknown device: {device_id}"}
        if not dev.get("ssh_enabled"):
            return 400, {"error": f"SSH triage is not enabled for {device_id}"}

        lock = self._sweep_locks[device_id]
        if not lock.acquire(blocking=False):
            return 409, {"error": f"Triage sweep already in progress for {device_id}"}

        try:
            with self._state_lock:
                ip = self._device_state.get(device_id, {}).get("ip") or dev["fallback_ip"]
            result = self._sweep_fn(ip, dev.get("ssh_user", "root"), self.ssh_key, self.triage_script)
            result.setdefault("timestamp", _utc_now())
            self.store.record_sweep(device_id, result)
            with self._state_lock:
                self._latest_sweeps[device_id] = result
            return 200, {"device_id": device_id, "sweep": result}
        finally:
            lock.release()

    def trigger_disable_cloud(self, device_id: str) -> tuple[int, dict]:
        dev = self.devices_by_id.get(device_id)
        if not dev:
            return 404, {"error": f"Unknown device: {device_id}"}
        if not dev.get("ssh_enabled"):
            return 400, {"error": f"SSH actions not enabled for {device_id}"}
        with self._state_lock:
            ip = self._device_state.get(device_id, {}).get("ip") or dev["fallback_ip"]
        dis_fn = self._disable_van_cloud_fn if dev.get("role") == "van_router" else self._disable_cloud_fn
        res = dis_fn(ip, dev.get("ssh_user", "root"), self.ssh_key)
        if res.get("ok"):
            self.refresh_ssh(device_id)
            return 200, {"device_id": device_id, "ok": True}
        return 502, {"device_id": device_id, "ok": False, "error": res.get("error")}

    def trigger_wan_mode(self, device_id: str, mode: str) -> tuple[int, dict]:
        dev = self.devices_by_id.get(device_id)
        if not dev:
            return 404, {"error": f"Unknown device: {device_id}"}
        if dev.get("role") != "van_router":
            return 400, {"error": f"WAN mode control only supported for van_router devices (not {device_id})"}
        if mode not in VALID_VAN_MODES:
            return 400, {"error": f"Invalid mode {mode!r}; allowed: {sorted(VALID_VAN_MODES)}"}
        with self._state_lock:
            ip = self._device_state.get(device_id, {}).get("ip") or dev["fallback_ip"]
        res = self._wan_mode_fn(ip, dev.get("ssh_user", "root"), self.ssh_key, mode)
        if res.get("ok"):
            with self._state_lock:
                st = dict(self._device_state.get(device_id, {}))
                if isinstance(st.get("van_wan"), dict):
                    vw = dict(st["van_wan"])
                    vw["mode"] = mode
                    st["van_wan"] = vw
                    self._device_state[device_id] = st
                    self.store.upsert_device_status(device_id, st)
            if self.enable_system_io:
                def _delayed_refresh() -> None:
                    time.sleep(4)
                    try:
                        self.refresh_ssh(device_id)
                    except Exception:
                        pass
                threading.Thread(target=_delayed_refresh, daemon=True).start()
            return 200, {"device_id": device_id, "ok": True, "mode": mode, "result": res.get("result")}
        return 502, {"device_id": device_id, "ok": False, "error": res.get("error")}

    def trigger_reboot(self, device_id: str) -> tuple[int, dict]:
        dev = self.devices_by_id.get(device_id)
        if not dev:
            return 404, {"error": f"Unknown device: {device_id}"}
        if not dev.get("ssh_enabled"):
            return 400, {"error": f"SSH actions not enabled for {device_id}"}
        with self._state_lock:
            ip = self._device_state.get(device_id, {}).get("ip") or dev["fallback_ip"]
        res = self._reboot_fn(ip, dev.get("ssh_user", "root"), self.ssh_key)
        if res.get("ok"):
            return 200, {"device_id": device_id, "ok": True}
        return 502, {"device_id": device_id, "ok": False, "error": res.get("error")}

    def _require_van_router(self, device_id: str) -> tuple[dict | None, int, dict | None]:
        dev = self.devices_by_id.get(device_id)
        if not dev:
            return None, 404, {"error": f"Unknown device: {device_id}"}
        if dev.get("role") != "van_router" or not dev.get("ssh_enabled"):
            return None, 400, {"error": f"Action only supported for SSH-enabled van_router devices (not {device_id})"}
        return dev, 200, None

    def _device_ip(self, device_id: str, dev: dict) -> str:
        with self._state_lock:
            return self._device_state.get(device_id, {}).get("ip") or dev["fallback_ip"]

    def trigger_hunt_scan(self, device_id: str) -> tuple[int, dict]:
        dev, code, err = self._require_van_router(device_id)
        if not dev:
            return code, err or {"error": "invalid device"}
        lock = self._hunt_locks[device_id]
        if not lock.acquire(blocking=False):
            return 409, {"error": f"Wi-Fi hunt/scan already in progress for {device_id}"}
        try:
            ip = self._device_ip(device_id, dev)
            res = self._hunt_scan_fn(ip, dev.get("ssh_user", "root"), self.ssh_key)
            if res.get("ok"):
                return 200, res
            if res.get("exit_code") == 3 or res.get("error") == "busy":
                return 409, {"error": "Router Wi-Fi hunter is busy", "ok": False}
            return 502, {"ok": False, "error": res.get("error") or "Scan failed"}
        finally:
            lock.release()

    def trigger_hunt_connect(self, device_id: str, ssid: str, bssid: str = "") -> tuple[int, dict]:
        dev, code, err = self._require_van_router(device_id)
        if not dev:
            return code, err or {"error": "invalid device"}
        if not isinstance(ssid, str) or not ssid.strip():
            return 400, {"error": "Missing non-empty string field 'ssid'"}
        lock = self._hunt_locks[device_id]
        if not lock.acquire(blocking=False):
            return 409, {"error": f"Wi-Fi hunt/connect already in progress for {device_id}"}
        try:
            ip = self._device_ip(device_id, dev)
            res = self._hunt_connect_fn(ip, dev.get("ssh_user", "root"), self.ssh_key, ssid, bssid)
            if res.get("ok"):
                if self.enable_system_io:
                    def _delayed_refresh() -> None:
                        time.sleep(3)
                        try:
                            self.refresh_ssh(device_id)
                        except Exception:
                            pass
                    threading.Thread(target=_delayed_refresh, daemon=True).start()
                return 200, res
            if res.get("exit_code") == 3 or res.get("error") == "busy":
                return 409, {"error": "Router Wi-Fi hunter is busy", "ok": False}
            if res.get("exit_code") == 2:
                return 400, {"ok": False, "error": res.get("error") or "Invalid SSID/BSSID"}
            return 502, {"ok": False, "error": res.get("error") or "Connect failed", "result": res.get("result")}
        finally:
            lock.release()

    def trigger_hunt_config(self, device_id: str, cfg_payload: dict) -> tuple[int, dict]:
        dev, code, err = self._require_van_router(device_id)
        if not dev:
            return code, err or {"error": "invalid device"}
        ip = self._device_ip(device_id, dev)
        res = self._hunt_config_fn(ip, dev.get("ssh_user", "root"), self.ssh_key, cfg_payload)
        if res.get("ok"):
            return 200, res
        return (400 if res.get("exit_code") == 2 else 502), {"ok": False, "error": res.get("error") or "Config update failed"}

    def get_van_networks(self, device_id: str) -> tuple[int, dict]:
        dev, code, err = self._require_van_router(device_id)
        if not dev:
            return code, err or {"error": "invalid device"}
        ip = self._device_ip(device_id, dev)
        res = self._list_networks_fn(ip, dev.get("ssh_user", "root"), self.ssh_key)
        if res.get("ok"):
            # Belt-and-suspenders: strip any 'psk' field if ever returned
            if isinstance(res.get("networks"), list):
                for n in res["networks"]:
                    if isinstance(n, dict):
                        n.pop("psk", None)
            return 200, res
        return 502, {"ok": False, "error": res.get("error") or "Failed to load known networks"}

    def trigger_van_networks(self, device_id: str, payload: dict) -> tuple[int, dict]:
        dev, code, err = self._require_van_router(device_id)
        if not dev:
            return code, err or {"error": "invalid device"}
        if not isinstance(payload, dict) or payload.get("action") not in VALID_NETWORK_ACTIONS:
            return 400, {"error": f"Invalid action; allowed: {sorted(VALID_NETWORK_ACTIONS)}"}
        ip = self._device_ip(device_id, dev)
        res = self._mutate_networks_fn(ip, dev.get("ssh_user", "root"), self.ssh_key, payload)
        if res.get("ok"):
            return 200, res
        return (400 if res.get("exit_code") == 2 else 502), {"ok": False, "error": res.get("error") or "Network update failed"}

    def default_van_device_id(self) -> str | None:
        for dev in self.devices:
            if dev.get("role") == "van_router":
                return dev["id"]
        return None

    def get_van_status_live(self, device_id: str) -> tuple[int, dict]:
        dev = self.devices_by_id.get(device_id)
        if not dev or dev.get("role") != "van_router":
            return 404, {"error": "Van router not configured"}
        ip = self._device_ip(device_id, dev)
        res = self._van_status_fn(ip, dev.get("ssh_user", "root"), self.ssh_key)
        if res.get("ok"):
            return 200, res
        return 502, {"ok": False, "error": res.get("error") or "Failed to fetch van-wan status"}

    def trigger_van_reset_usage(self, device_id: str) -> tuple[int, dict]:
        dev = self.devices_by_id.get(device_id)
        if not dev or dev.get("role") != "van_router":
            return 404, {"error": "Van router not configured"}
        ip = self._device_ip(device_id, dev)
        res = self._van_reset_usage_fn(ip, dev.get("ssh_user", "root"), self.ssh_key)
        if res.get("ok"):
            return 200, res
        return 502, {"ok": False, "error": res.get("error") or "Failed to reset usage"}

    def handle_van_cgi_post(self, device_id: str, body_json: dict) -> tuple[int, dict]:
        action = body_json.get("action")
        if isinstance(action, str) and action:
            if action == "reset-usage":
                return self.trigger_van_reset_usage(device_id)
            if action == "hunt-scan":
                return self.trigger_hunt_scan(device_id)
            if action == "hunt-connect":
                ssid = body_json.get("ssid")
                bssid = body_json.get("bssid", "")
                if not isinstance(ssid, str) or (bssid is not None and not isinstance(bssid, str)):
                    return 400, {"error": "Invalid ssid/bssid fields"}
                return self.trigger_hunt_connect(device_id, ssid, bssid or "")
            if action == "hunt-config":
                return self.trigger_hunt_config(device_id, body_json)
            if action in ("networks-upsert", "networks-delete", "networks-block", "networks-unblock"):
                sub = dict(body_json)
                sub["action"] = action.split("-", 1)[1]
                return self.trigger_van_networks(device_id, sub)
            return 400, {"error": f"Unknown action: {action!r}"}
        mode = body_json.get("mode")
        if isinstance(mode, str) and mode:
            return self.trigger_wan_mode(device_id, mode)
        return 400, {"error": "Missing action or mode"}

    def build_devices_payload(self) -> dict:
        with self._state_lock:
            items = []
            for dev in self.devices:
                dev_id = dev["id"]
                st = dict(self._device_state.get(dev_id, {}))
                sweep = self._latest_sweeps.get(dev_id)
                launch_url = (
                    f"https://{self.tailscale_host}:{dev['tailscale_port']}/"
                    if dev["role"] in ("kvm", "van_router") and dev.get("tailscale_port")
                    else None
                )
                items.append(
                    {
                        "id": dev_id,
                        "name": dev["name"],
                        "role": dev["role"],
                        "model": dev["model"],
                        "mac": dev["mac"],
                        "preferred_vlan": dev.get("preferred_vlan", "br0"),
                        "ssh_enabled": bool(dev.get("ssh_enabled", False)),
                        "launch_url": launch_url,
                        "status": st,
                        "last_sweep": sweep,
                        "sweep_running": self._sweep_locks[dev_id].locked(),
                        "hunt_running": self._hunt_locks[dev_id].locked(),
                    }
                )
            conntrack_snap = dict(self._conntrack)

        return {
            "tailscale_host": self.tailscale_host,
            "generated_at": _utc_now(),
            "nginx_sync": self._nginx_sync_status,
            "conntrack": conntrack_snap,
            "devices": items,
        }

    def start_pollers(self, fast_interval: int = 30, ssh_interval: int = 300) -> None:
        def _fast_loop() -> None:
            while not self._stop_event.is_set():
                try:
                    self.refresh_fast()
                except Exception as exc:
                    LOG.exception("Fast poller error: %s", str(exc) or type(exc).__name__)
                self._stop_event.wait(fast_interval)

        def _ssh_loop() -> None:
            # Small initial delay so fast poller resolves IPs first
            self._stop_event.wait(2)
            while not self._stop_event.is_set():
                try:
                    self.refresh_ssh()
                except Exception as exc:
                    LOG.exception("SSH poller error: %s", str(exc) or type(exc).__name__)
                self._stop_event.wait(ssh_interval)

        threading.Thread(target=_fast_loop, name="fast-poller", daemon=True).start()
        threading.Thread(target=_ssh_loop, name="ssh-poller", daemon=True).start()

    def stop(self) -> None:
        self._stop_event.set()


def create_server(app: PortalApp, host: str = "127.0.0.1", port: int = 8450) -> ThreadingHTTPServer:
    index_path = STATIC_DIR / "index.html"
    van_index_candidates = (
        STATIC_DIR / "van.html",
        Path(__file__).resolve().parent.parent / "router" / "www" / "van" / "index.html",
    )

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(30)

        def log_message(self, fmt: str, *args) -> None:
            LOG.info("%s - %s", self.address_string(), fmt % args)

        def _send_json(self, code: int, payload: dict, head_only: bool = False) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if not head_only:
                self.wfile.write(body)

        def _send_html(self, html_bytes: bytes, head_only: bool = False) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Content-Length", str(len(html_bytes)))
            self.end_headers()
            if not head_only:
                self.wfile.write(html_bytes)

        def _check_auth(self, method: str) -> bool:
            ok, code, msg = app.is_authorized(self.headers, method, self.path)
            if not ok:
                if method == "POST":
                    self.close_connection = True
                self._send_json(code, {"error": msg}, head_only=(method == "HEAD"))
            return ok

        def _serve_get(self, head_only: bool) -> None:
            method = "HEAD" if head_only else "GET"
            if not self._check_auth(method):
                return
            path = self.path.split("?", 1)[0]
            if path == "/healthz":
                self._send_json(200, {"ok": True}, head_only=head_only)
                return
            if path in ("/", "/index.html"):
                if not index_path.exists():
                    self._send_json(500, {"error": "index.html missing"}, head_only=head_only)
                    return
                self._send_html(index_path.read_bytes(), head_only=head_only)
                return
            if path == "/van":
                self.send_response(302)
                self.send_header("Location", "/van/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path in ("/van/", "/van/index.html"):
                van_path = next((p for p in van_index_candidates if p.exists()), None)
                if not van_path:
                    self._send_json(500, {"error": "van.html missing"}, head_only=head_only)
                    return
                self._send_html(van_path.read_bytes(), head_only=head_only)
                return
            if path == "/cgi-bin/van-wan":
                van_id = app.default_van_device_id()
                if not van_id:
                    self._send_json(404, {"error": "No van_router configured"}, head_only=head_only)
                    return
                qs = self.path.split("?", 1)[1] if "?" in self.path else ""
                if "resource=networks" in qs:
                    code, data = app.get_van_networks(van_id)
                else:
                    code, data = app.get_van_status_live(van_id)
                self._send_json(code, data, head_only=head_only)
                return
            if path == "/api/devices":
                self._send_json(200, app.build_devices_payload(), head_only=head_only)
                return
            parts = [p for p in path.rstrip("/").split("/") if p]
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "devices" and parts[3] == "networks":
                code, data = app.get_van_networks(parts[2])
                self._send_json(code, data, head_only=head_only)
                return
            self._send_json(404, {"error": "Not found"}, head_only=head_only)

        def do_GET(self) -> None:
            self._serve_get(head_only=False)

        def do_HEAD(self) -> None:
            self._serve_get(head_only=True)

        def do_POST(self) -> None:
            if not self._check_auth("POST"):
                return
            if (self.headers.get("Transfer-Encoding") or "").strip():
                self.close_connection = True
                self._send_json(411, {"error": "Chunked Transfer-Encoding not supported"})
                return
            raw_len = (self.headers.get("Content-Length") or "0").strip()
            try:
                length = int(raw_len)
            except ValueError:
                self.close_connection = True
                self._send_json(400, {"error": "Invalid Content-Length"})
                return
            if length < 0:
                self.close_connection = True
                self._send_json(400, {"error": "Invalid Content-Length"})
                return
            if length > 65536:
                self.close_connection = True
                self._send_json(413, {"error": "Payload too large"})
                return
            raw_body = self.rfile.read(length) if length > 0 else b""

            path = self.path.split("?", 1)[0].rstrip("/")
            if path == "/api/refresh":
                app.refresh_fast()
                app.refresh_ssh()
                self._send_json(200, app.build_devices_payload())
                return

            if path == "/cgi-bin/van-wan":
                van_id = app.default_van_device_id()
                if not van_id:
                    self._send_json(404, {"error": "No van_router configured"})
                    return
                try:
                    body_json = json.loads(raw_body.decode("utf-8") or "{}")
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self._send_json(400, {"error": "Invalid JSON body"})
                    return
                if not isinstance(body_json, dict):
                    self._send_json(400, {"error": "JSON object required"})
                    return
                code, data = app.handle_van_cgi_post(van_id, body_json)
                self._send_json(code, data)
                return

            parts = [p for p in path.split("/") if p]
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "devices":
                dev_id, action = parts[2], parts[3]
                if action == "sweep":
                    code, data = app.trigger_sweep(dev_id)
                    self._send_json(code, data)
                    return
                if action == "disable-cloud":
                    code, data = app.trigger_disable_cloud(dev_id)
                    self._send_json(code, data)
                    return
                if action == "reboot":
                    code, data = app.trigger_reboot(dev_id)
                    self._send_json(code, data)
                    return
                if action == "wan-mode":
                    try:
                        body_json = json.loads(raw_body.decode("utf-8") or "{}")
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        self._send_json(400, {"error": "Invalid JSON body"})
                        return
                    if not isinstance(body_json, dict) or not isinstance(body_json.get("mode"), str):
                        self._send_json(400, {"error": "Missing string field 'mode'"})
                        return
                    code, data = app.trigger_wan_mode(dev_id, body_json["mode"])
                    self._send_json(code, data)
                    return
                if action == "hunt-scan":
                    code, data = app.trigger_hunt_scan(dev_id)
                    self._send_json(code, data)
                    return
                if action in ("hunt-connect", "hunt-config", "networks"):
                    try:
                        body_json = json.loads(raw_body.decode("utf-8") or "{}")
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        self._send_json(400, {"error": "Invalid JSON body"})
                        return
                    if not isinstance(body_json, dict):
                        self._send_json(400, {"error": "JSON object required"})
                        return
                    if action == "hunt-connect":
                        ssid = body_json.get("ssid")
                        bssid = body_json.get("bssid", "")
                        if not isinstance(ssid, str) or (bssid is not None and not isinstance(bssid, str)):
                            self._send_json(400, {"error": "Invalid ssid/bssid fields"})
                            return
                        code, data = app.trigger_hunt_connect(dev_id, ssid, bssid or "")
                    elif action == "hunt-config":
                        code, data = app.trigger_hunt_config(dev_id, body_json)
                    else:
                        code, data = app.trigger_van_networks(dev_id, body_json)
                    self._send_json(code, data)
                    return

            self._send_json(404, {"error": "Not found"})

    ThreadingHTTPServer.allow_reuse_address = True
    return ThreadingHTTPServer((host, port), Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description="GL.iNet Private Management Portal")
    parser.add_argument("--config", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument("--triage", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--nginx-conf", required=True)
    parser.add_argument("--upstreams", required=True)
    parser.add_argument("--nginx-pid", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8450)
    args = parser.parse_args()

    cfg = load_config(args.config)
    store = StateStore(args.db)
    app = PortalApp(
        config=cfg,
        store=store,
        triage_script=Path(args.triage),
        ssh_key=Path(args.key),
        nginx_conf=Path(args.nginx_conf),
        upstreams_path=Path(args.upstreams),
        nginx_pid=Path(args.nginx_pid),
        enable_system_io=True,
    )
    app.start_pollers()
    server = create_server(app, args.host, args.port)

    def _shutdown(_sig, _frame):
        LOG.info("Shutting down glinet-portal...")
        app.stop()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    LOG.info("Listening on http://%s:%d", args.host, args.port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        store.close()


if __name__ == "__main__":
    main()
