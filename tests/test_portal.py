import json
import threading
import time
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path

from portal import PortalApp, create_server
from store import StateStore

CFG = {
    "tailscale_host": "gateway.tailnet-example.ts.net",
    "allowed_tailscale_users": ["alice@example.com"],
    "allowed_tailscale_ips": ["100.64.0.10"],
    "devices": [
        {
            "id": "rm1pe",
            "name": "GLKVM RM1PE",
            "role": "kvm",
            "model": "RM1PE",
            "mac": "02:00:5e:00:53:01",
            "fallback_ip": "10.10.10.21",
            "preferred_vlan": "vlan20",
            "scheme": "https",
            "upstream_port": 443,
            "proxy_local_port": 8451,
            "tailscale_port": 8441,
            "ssh_enabled": True,
            "ssh_user": "root",
        }
    ],
}


def test_auth_and_csrf_rules(tmp_path: Path):
    app = PortalApp(CFG, StateStore(tmp_path / "s.db"), enable_system_io=False)
    assert app.is_authorized({"Tailscale-User-Login": "ALICE@example.com"}, "GET", "/")[0] is True
    assert app.is_authorized({"Tailscale-User-Login": "bob@example.com"}, "GET", "/")[0] is False
    assert app.is_authorized({}, "GET", "/healthz")[0] is True
    assert app.is_authorized({}, "GET", "/api/devices")[0] is False
    assert app.is_authorized({}, "GET", "/")[0] is False
    assert app.is_authorized({}, "POST", "/api/devices/rm1pe/reboot")[0] is False
    assert app.is_authorized({"Tailscale-User-Login": "alice@example.com"}, "POST", "/api/devices/rm1pe/reboot")[0] is False
    assert (
        app.is_authorized(
            {
                "Tailscale-User-Login": "alice@example.com",
                "X-Portal-Action": "1",
                "Origin": "http://gateway.tailnet-example.ts.net:8440",
            },
            "POST",
            "/api/devices/rm1pe/reboot",
        )[0]
        is False
    )
    assert (
        app.is_authorized(
            {
                "Tailscale-User-Login": "alice@example.com",
                "X-Portal-Action": "1",
                "Origin": "https://evil.example",
            },
            "POST",
            "/api/devices/rm1pe/reboot",
        )[0]
        is False
    )
    assert (
        app.is_authorized(
            {
                "Tailscale-User-Login": "alice@example.com",
                "X-Portal-Action": "1",
                "Origin": "https://gateway.tailnet-example.ts.net:8440",
            },
            "POST",
            "/api/devices/rm1pe/reboot",
        )[0]
        is True
    )
    # Tagged Linux node (no Tailscale-User-Login, allowlisted X-Forwarded-For)
    assert app.is_authorized({"X-Forwarded-For": "100.64.0.10"}, "GET", "/")[0] is True
    assert (
        app.is_authorized(
            {
                "X-Forwarded-For": "100.64.0.10",
                "X-Portal-Action": "1",
                "Origin": "https://gateway.tailnet-example.ts.net:8440",
            },
            "POST",
            "/api/devices/rm1pe/sweep",
        )[0]
        is True
    )
    # Unlisted IP with no Tailscale-User-Login must be rejected
    assert app.is_authorized({"X-Forwarded-For": "100.64.0.99"}, "GET", "/")[0] is False
    # Even if X-Forwarded-For matched, a non-allowlisted Tailscale-User-Login is rejected
    assert (
        app.is_authorized(
            {"Tailscale-User-Login": "bob@example.com", "X-Forwarded-For": "100.64.0.10"},
            "GET",
            "/",
        )[0]
        is False
    )


def test_head_request_returns_200_no_store(tmp_path: Path):
    app = PortalApp(CFG, StateStore(tmp_path / "s.db"), enable_system_io=False)
    srv = create_server(app, "127.0.0.1", 0)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/",
            method="HEAD",
            headers={"X-Forwarded-For": "100.64.0.10"},
        )
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            assert "no-store" in resp.headers.get("Cache-Control", "")
    finally:
        srv.shutdown()
        srv.server_close()


def test_concurrent_sweep_returns_409_and_html_sets_no_store(tmp_path: Path):
    gate = threading.Event()

    def slow_sweep(*args, **kwargs):
        gate.wait(2)
        return {"exit_code": 0, "status": "clean", "verdict": "CLEAN", "summary": {"IOC": 0}, "output": "ok"}

    app = PortalApp(CFG, StateStore(tmp_path / "s.db"), enable_system_io=False, sweep_fn=slow_sweep)
    srv = create_server(app, "127.0.0.1", 0)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/",
            headers={"Tailscale-User-Login": "alice@example.com"},
        )
        with urllib.request.urlopen(req) as resp:
            assert "no-store" in resp.headers.get("Cache-Control", "")
            assert resp.status == 200

        # Minimal /healthz works without Tailscale header; /api/devices requires auth
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz") as resp:
            assert resp.status == 200
            assert json.loads(resp.read().decode("utf-8")) == {"ok": True}

        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/devices")
            assert False, "Expected 403 for unauthenticated /api/devices"
        except urllib.error.HTTPError as e:
            assert e.code == 403

        # Authenticated GET /api/devices works
        auth_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/devices",
            headers={"Tailscale-User-Login": "alice@example.com"},
        )
        with urllib.request.urlopen(auth_req) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            assert payload["devices"][0]["id"] == "rm1pe"

        # Unauthorized Tailscale user gets 403
        bad_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/devices",
            headers={"Tailscale-User-Login": "bob@example.com"},
        )
        try:
            urllib.request.urlopen(bad_req)
            assert False, "Expected 403"
        except urllib.error.HTTPError as e:
            assert e.code == 403

        post_hdrs = {
            "Tailscale-User-Login": "alice@example.com",
            "X-Portal-Action": "1",
            "Origin": "https://gateway.tailnet-example.ts.net:8440",
        }
        first_done = []

        def do_first():
            r = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/devices/rm1pe/sweep",
                method="POST",
                headers=post_hdrs,
            )
            with urllib.request.urlopen(r) as resp:
                first_done.append(resp.status)

        t1 = threading.Thread(target=do_first)
        t1.start()
        time.sleep(0.1)
        try:
            r2 = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/devices/rm1pe/sweep",
                method="POST",
                headers=post_hdrs,
            )
            urllib.request.urlopen(r2)
            assert False, "Expected 409"
        except urllib.error.HTTPError as e:
            assert e.code == 409
        finally:
            gate.set()
            t1.join(timeout=3)
        assert first_done == [200]
    finally:
        srv.shutdown()
        srv.server_close()


def test_xff_uses_rightmost_ip_and_blocks_spoofed_leftmost_or_blank_prefix(tmp_path: Path):
    app = PortalApp(CFG, StateStore(tmp_path / "s.db"), enable_system_io=False)
    # Spoofed leftmost allowlisted IP followed by untrusted peer IP must be rejected
    assert app.is_authorized({"X-Forwarded-For": "100.64.0.10, 100.64.0.99"}, "GET", "/")[0] is False
    # Leading comma must NOT bypass loopback check on GET /api/devices
    assert app.is_authorized({"X-Forwarded-For": ", 100.64.0.99"}, "GET", "/api/devices")[0] is False
    # Rightmost entry matching Linux is allowed
    assert app.is_authorized({"X-Forwarded-For": "10.0.0.1, 100.64.0.10"}, "GET", "/")[0] is True
    # Multiple X-Forwarded-For header lines: second header's peer IP wins and blocks
    msg = Message()
    msg.add_header("X-Forwarded-For", "100.64.0.10")
    msg.add_header("X-Forwarded-For", "100.64.0.99")
    assert app.is_authorized(msg, "GET", "/")[0] is False


def test_refresh_fast_excludes_dormant_fallback_ip_from_conntrack(tmp_path: Path, monkeypatch):
    import portal as portal_mod

    seen_maps = []
    monkeypatch.setattr(
        portal_mod,
        "read_system_tables",
        lambda: (
            {},
            {"02:00:5e:00:53:01": [{"ip": "10.10.20.15", "dev": "vlan20", "state": "REACHABLE"}]},
        ),
    )
    monkeypatch.setattr(portal_mod, "check_tcp_reachable", lambda ip, port, timeout=1.5: True)
    monkeypatch.setattr(
        portal_mod,
        "sync_nginx_upstreams",
        lambda *a, **kw: {"changed": False, "reloaded": False, "error": None},
    )
    monkeypatch.setattr(portal_mod, "is_conntrack_gateway_available", lambda: True)
    monkeypatch.setattr(portal_mod, "scan_system_conntrack", lambda m: (seen_maps.append(dict(m)) or []))

    app = PortalApp(CFG, StateStore(tmp_path / "s.db"), enable_system_io=True)
    app.refresh_fast()
    assert len(seen_maps) == 1
    assert "10.10.20.15" in seen_maps[0]
    assert "10.10.10.21" not in seen_maps[0]
    assert app.build_devices_payload()["conntrack"]["available"] is True


def test_conntrack_marks_unavailable_on_non_gateway_host(tmp_path: Path, monkeypatch):
    import portal as portal_mod

    monkeypatch.setattr(portal_mod, "read_system_tables", lambda: ({}, {}))
    monkeypatch.setattr(portal_mod, "check_tcp_reachable", lambda ip, port, timeout=1.5: False)
    monkeypatch.setattr(
        portal_mod,
        "sync_nginx_upstreams",
        lambda *a, **kw: {"changed": False, "reloaded": False, "error": None},
    )
    monkeypatch.setattr(portal_mod, "is_conntrack_gateway_available", lambda: False)

    app = PortalApp(CFG, StateStore(tmp_path / "s.db"), enable_system_io=True)
    app.refresh_fast()
    assert app.build_devices_payload()["conntrack"]["available"] is False


def test_index_html_checks_response_ok_and_uses_delegated_actions():
    html = (Path(__file__).resolve().parent.parent / "src" / "static" / "index.html").read_text(encoding="utf-8")
    assert "if (!r.ok)" in html
    assert 'onclick="runSweep(' not in html
    assert "data-action=" in html


def test_wan_mode_endpoint_validates_role_mode_json_and_body_size(tmp_path: Path):
    cfg = json.loads(json.dumps(CFG))
    cfg["devices"].append(
        {
            "id": "mt3000",
            "name": "GL-MT3000 (Mobile Router)",
            "role": "van_router",
            "model": "GL-MT3000",
            "mac": "02:00:5e:00:53:03",
            "fallback_ip": "10.10.10.50",
            "wg_ip": "192.168.2.5",
            "wg_iface": "wg0",
            "preferred_vlan": "br0",
            "scheme": "http",
            "upstream_port": 80,
            "proxy_local_port": 8455,
            "tailscale_port": 8445,
            "ssh_enabled": True,
            "ssh_user": "root",
        }
    )
    called = []

    def fake_wan_mode(ip, user, key, mode):
        called.append((ip, mode))
        return {"ok": True, "mode": mode, "result": {"ok": True}, "error": None}

    app = PortalApp(cfg, StateStore(tmp_path / "s.db"), enable_system_io=False, wan_mode_fn=fake_wan_mode)
    payload = app.build_devices_payload()
    mt = [d for d in payload["devices"] if d["id"] == "mt3000"][0]
    assert mt["launch_url"] == "https://gateway.tailnet-example.ts.net:8445/"

    srv = create_server(app, "127.0.0.1", 0)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    hdrs = {
        "Tailscale-User-Login": "alice@example.com",
        "X-Portal-Action": "1",
        "Origin": "https://gateway.tailnet-example.ts.net:8440",
        "Content-Type": "application/json",
    }
    try:
        # Valid mode on van_router -> 200
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/devices/mt3000/wan-mode",
            method="POST",
            headers=hdrs,
            data=json.dumps({"mode": "captive_login"}).encode("utf-8"),
        )
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
        assert called == [("10.10.10.50", "captive_login")]

        # Invalid mode -> 400
        for url, data, expected in [
            (f"http://127.0.0.1:{port}/api/devices/mt3000/wan-mode", b'{"mode":"bogus"}', 400),
            (f"http://127.0.0.1:{port}/api/devices/mt3000/wan-mode", b"{not-json", 400),
            (f"http://127.0.0.1:{port}/api/devices/rm1pe/wan-mode", b'{"mode":"auto"}', 400),
            (f"http://127.0.0.1:{port}/api/devices/mt3000/wan-mode", b"x" * 70000, 413),
        ]:
            r = urllib.request.Request(url, method="POST", headers=hdrs, data=data)
            try:
                urllib.request.urlopen(r)
                assert False, f"Expected {expected}"
            except urllib.error.HTTPError as e:
                assert e.code == expected
    finally:
        srv.shutdown()
        srv.server_close()

    html = (Path(__file__).resolve().parent.parent / "src" / "static" / "index.html").read_text(encoding="utf-8")
    assert 'data-action="wan-mode"' in html
    assert "starlink" in html.lower()


def test_refresh_fast_falls_back_to_lan_when_wg_ip_unreachable(tmp_path: Path, monkeypatch):
    import portal as portal_mod

    cfg = json.loads(json.dumps(CFG))
    cfg["devices"] = [
        {
            "id": "mt3000",
            "name": "GL-MT3000 (Mobile Router)",
            "role": "van_router",
            "model": "GL-MT3000",
            "mac": "02:00:5e:00:53:03",
            "fallback_ip": "10.10.10.50",
            "wg_ip": "192.168.2.5",
            "wg_iface": "wg0",
            "preferred_vlan": "br0",
            "scheme": "http",
            "upstream_port": 80,
            "proxy_local_port": 8455,
            "tailscale_port": 8445,
            "ssh_enabled": True,
            "ssh_user": "root",
        }
    ]
    monkeypatch.setattr(
        portal_mod,
        "read_system_tables",
        lambda: ({}, {"02:00:5e:00:53:03": [{"ip": "10.10.10.50", "dev": "br0", "state": "REACHABLE"}]}),
    )
    monkeypatch.setattr(portal_mod, "read_wg_active_ips", lambda iface="wg0": {"192.168.2.5"})
    # 192.168.2.5 fails TCP, 10.10.10.50 succeeds TCP
    monkeypatch.setattr(portal_mod, "check_tcp_reachable", lambda ip, port, timeout=1.5: ip == "10.10.10.50")
    monkeypatch.setattr(
        portal_mod,
        "sync_nginx_upstreams",
        lambda *a, **kw: {"changed": False, "reloaded": False, "error": None},
    )
    monkeypatch.setattr(portal_mod, "scan_system_conntrack", lambda m: [])

    app = PortalApp(cfg, StateStore(tmp_path / "s.db"), enable_system_io=True)
    payload = app.refresh_fast()
    assert payload["devices"][0]["status"]["ip"] == "10.10.10.50"
    assert payload["devices"][0]["status"]["source"] == "neigh"


def test_van_hunter_and_networks_endpoints_enforce_409_lock_role_and_redaction(tmp_path: Path):
    cfg = json.loads(json.dumps(CFG))
    cfg["devices"].append(
        {
            "id": "mt3000",
            "name": "GL-MT3000 (Mobile Router)",
            "role": "van_router",
            "model": "GL-MT3000",
            "mac": "02:00:5e:00:53:03",
            "fallback_ip": "10.10.10.50",
            "wg_ip": "192.168.2.5",
            "wg_iface": "wg0",
            "preferred_vlan": "br0",
            "scheme": "http",
            "upstream_port": 80,
            "proxy_local_port": 8455,
            "tailscale_port": 8445,
            "ssh_enabled": True,
            "ssh_user": "root",
        }
    )

    started = threading.Event()
    release = threading.Event()

    def slow_scan(ip, user, key):
        started.set()
        release.wait(timeout=3)
        return {"ok": True, "candidates": [{"ssid": "xfinitywifi", "rssi_dbm": -65, "tier": 3}]}

    def fake_connect(ip, user, key, ssid, bssid=""):
        return {"ok": True, "ssid": ssid, "bssid": bssid, "vpn_verified": True}

    def fake_list_nets(ip, user, key):
        return {"ok": True, "auto_hunt": True, "networks": [{"ssid": "Home", "trusted": True, "has_psk": True}]}

    def fake_mutate_nets(ip, user, key, payload):
        return {"ok": True, "action": payload.get("action")}

    def fake_hunt_cfg(ip, user, key, payload):
        return {"ok": True, "config": payload}

    app = PortalApp(
        cfg,
        StateStore(tmp_path / "s.db"),
        enable_system_io=False,
        hunt_scan_fn=slow_scan,
        hunt_connect_fn=fake_connect,
        hunt_config_fn=fake_hunt_cfg,
        list_networks_fn=fake_list_nets,
        mutate_networks_fn=fake_mutate_nets,
    )

    srv = create_server(app, "127.0.0.1", 0)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    hdrs = {
        "Tailscale-User-Login": "alice@example.com",
        "X-Portal-Action": "1",
        "Origin": "https://gateway.tailnet-example.ts.net:8440",
        "Content-Type": "application/json",
    }
    try:
        # 1. GET /api/devices/mt3000/networks returns redacted list
        req_get = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/devices/mt3000/networks",
            headers={"Tailscale-User-Login": "alice@example.com"},
        )
        with urllib.request.urlopen(req_get) as resp:
            assert resp.status == 200
            nets_data = json.loads(resp.read().decode())
            assert nets_data["networks"][0]["has_psk"] is True
            assert "psk" not in nets_data["networks"][0]

        # 2. Non-van_router (rm1pe) returns 400
        req_bad_role = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/devices/rm1pe/hunt-scan",
            method="POST",
            headers=hdrs,
            data=b"{}",
        )
        try:
            urllib.request.urlopen(req_bad_role)
            assert False, "expected 400 on non-van_router"
        except urllib.error.HTTPError as e:
            assert e.code == 400

        # 3. Concurrent hunt-scan + hunt-connect returns 409 Conflict
        res_t1 = {}
        def _bg_scan():
            r = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/devices/mt3000/hunt-scan",
                method="POST",
                headers=hdrs,
                data=b"{}",
            )
            with urllib.request.urlopen(r) as resp:
                res_t1["code"] = resp.status

        bg = threading.Thread(target=_bg_scan)
        bg.start()
        assert started.wait(timeout=2)

        req_409 = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/devices/mt3000/hunt-connect",
            method="POST",
            headers=hdrs,
            data=json.dumps({"ssid": "xfinitywifi"}).encode(),
        )
        try:
            urllib.request.urlopen(req_409)
            assert False, "expected 409 when hunt already in progress"
        except urllib.error.HTTPError as e:
            assert e.code == 409
        finally:
            release.set()
            bg.join(timeout=3)
        assert res_t1.get("code") == 200

        # 4. POST /networks and /hunt-config succeed (200)
        req_net = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/devices/mt3000/networks",
            method="POST",
            headers=hdrs,
            data=json.dumps({"action": "upsert", "ssid": "Camp", "security": "wpa2", "psk": "pw123"}).encode(),
        )
        with urllib.request.urlopen(req_net) as resp:
            assert resp.status == 200

        req_cfg = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/devices/mt3000/hunt-config",
            method="POST",
            headers=hdrs,
            data=json.dumps({"auto_hunt": False}).encode(),
        )
        with urllib.request.urlopen(req_cfg) as resp:
            assert resp.status == 200
    finally:
        srv.shutdown()
        srv.server_close()

    html = (Path(__file__).resolve().parent.parent / "src" / "static" / "index.html").read_text(encoding="utf-8")
    assert 'data-action="hunt-scan"' in html
    assert 'data-action="open-networks"' in html
    assert "VPN ENCRYPTED" in html
    assert 'href="/van/"' in html


def test_van_ui_and_cgi_bridge_routes_require_tailscale_auth_and_csrf(tmp_path: Path):
    cfg = json.loads(json.dumps(CFG))
    cfg["devices"].append(
        {
            "id": "mt3000",
            "name": "GL-MT3000 (Mobile Router)",
            "role": "van_router",
            "model": "GL-MT3000",
            "mac": "02:00:5e:00:53:03",
            "fallback_ip": "10.10.20.50",
            "wg_ip": "192.168.2.5",
            "wg_iface": "wg0",
            "preferred_vlan": "vlan20",
            "scheme": "http",
            "upstream_port": 80,
            "proxy_local_port": 8455,
            "tailscale_port": 8445,
            "ssh_enabled": True,
            "ssh_user": "root",
        }
    )

    app = PortalApp(
        cfg,
        StateStore(tmp_path / "s.db"),
        enable_system_io=False,
        van_status_fn=lambda *a: {"ok": True, "mode": "auto", "active_wan": "cpe", "vpn": {"state": "killswitch_locked"}},
        list_networks_fn=lambda *a: {"ok": True, "auto_hunt": True, "networks": [], "blocklist": []},
        wan_mode_fn=lambda ip, user, key, mode: {"ok": True, "mode": mode, "result": {"ok": True}, "error": None},
        van_reset_usage_fn=lambda *a: {"ok": True, "reset": True},
    )
    srv = create_server(app, "127.0.0.1", 0)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        for p in ("/van/", "/cgi-bin/van-wan"):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}{p}")
                assert False, f"Expected 403 for unauthenticated {p}"
            except urllib.error.HTTPError as e:
                assert e.code == 403

        auth_hdrs = {"Tailscale-User-Login": "alice@example.com"}
        with urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/van/", headers=auth_hdrs)) as resp:
            assert resp.status == 200
            assert "no-store" in resp.headers.get("Cache-Control", "")
            assert b"cgi-bin/van-wan" in resp.read()

        with urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/cgi-bin/van-wan", headers=auth_hdrs)) as resp:
            assert resp.status == 200
            assert json.loads(resp.read().decode())["mode"] == "auto"

        with urllib.request.urlopen(
            urllib.request.Request(f"http://127.0.0.1:{port}/cgi-bin/van-wan?resource=networks", headers=auth_hdrs)
        ) as resp:
            assert resp.status == 200
            assert json.loads(resp.read().decode())["auto_hunt"] is True

        bad_post = urllib.request.Request(
            f"http://127.0.0.1:{port}/cgi-bin/van-wan",
            method="POST",
            headers={
                "Tailscale-User-Login": "alice@example.com",
                "Origin": "https://gateway.tailnet-example.ts.net:8440",
                "Content-Type": "application/json",
            },
            data=json.dumps({"mode": "auto"}).encode(),
        )
        try:
            urllib.request.urlopen(bad_post)
            assert False, "Expected 403 without X-Van-Action"
        except urllib.error.HTTPError as e:
            assert e.code == 403

        ok_hdrs = {
            "Tailscale-User-Login": "alice@example.com",
            "X-Van-Action": "1",
            "Origin": "https://gateway.tailnet-example.ts.net:8440",
            "Content-Type": "application/json",
        }
        ok_post = urllib.request.Request(
            f"http://127.0.0.1:{port}/cgi-bin/van-wan",
            method="POST",
            headers=ok_hdrs,
            data=json.dumps({"action": "reset-usage"}).encode(),
        )
        with urllib.request.urlopen(ok_post) as resp:
            assert resp.status == 200
            assert json.loads(resp.read().decode())["reset"] is True
    finally:
        srv.shutdown()
        srv.server_close()


def test_van_status_returns_cached_snapshot_during_hunt_scan(tmp_path):
    cfg = {
        "tailscale_host": "gateway.tailnet-example.ts.net",
        "portal_port": 8440,
        "allowed_tailscale_users": ["alice@example.com"],
        "devices": [
            {
                "id": "mt3000",
                "name": "GL-MT3000",
                "role": "van_router",
                "model": "GL-MT3000",
                "mac": "94:83:c4:00:00:03",
                "preferred_vlan": "br10",
                "fallback_ip": "192.168.2.5",
                "ssh_enabled": True,
            }
        ],
    }
    calls = {"n": 0}

    def fake_status(*_args):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"ok": True, "mode": "auto", "active_wan": "cpe", "hunter": {"hunting": False}}
        return {"ok": False, "error": "SSH timed out during band switch"}

    app = PortalApp(cfg, StateStore(tmp_path / "s.db"), enable_system_io=False, van_status_fn=fake_status)
    code1, data1 = app.get_van_status_live("mt3000")
    assert code1 == 200 and data1["mode"] == "auto"

    # Simulate an active dual-band Groove scan holding the hunt lock
    assert app._hunt_locks["mt3000"].acquire(blocking=False)
    try:
        code2, data2 = app.get_van_status_live("mt3000")
        assert code2 == 200
        assert data2["stale"] is True
        assert data2["hunter"]["hunting"] is True
        assert calls["n"] == 1  # Served from cache without burning a doomed SSH timeout
    finally:
        app._hunt_locks["mt3000"].release()


def test_trigger_hunt_best_returns_benchmark_winner(tmp_path):
    cfg = {
        "tailscale_host": "gateway.tailnet-example.ts.net",
        "portal_port": 8440,
        "allowed_tailscale_users": ["alice@example.com"],
        "devices": [
            {
                "id": "mt3000",
                "name": "GL-MT3000",
                "role": "van_router",
                "model": "GL-MT3000",
                "mac": "94:83:c4:00:00:03",
                "preferred_vlan": "br10",
                "fallback_ip": "192.168.2.5",
                "ssh_enabled": True,
            }
        ],
    }
    app = PortalApp(
        cfg,
        StateStore(tmp_path / "s.db"),
        enable_system_io=False,
        hunt_best_fn=lambda *a: {
            "ok": True,
            "connected": True,
            "ssid": "Camp5G",
            "band": "5g",
            "mbps": 42.5,
            "rtt_ms": 21,
            "loss_pct": 0,
            "tried": 2,
        },
    )
    code, data = app.handle_van_cgi_post("mt3000", {"action": "hunt-best"})
    assert code == 200
    assert data["ssid"] == "Camp5G"
    assert data["mbps"] == 42.5






