import json
import threading
from pathlib import Path
import pytest
from nginx_sync import _atomic_write, render_upstreams_conf, seed_upstreams_from_config, sync_nginx_upstreams

DEVICES = [
    {"id": "rm1pe", "role": "kvm", "fallback_ip": "10.10.10.21", "upstream_port": 443, "proxy_local_port": 8451},
    {"id": "rm10", "role": "kvm", "fallback_ip": "10.10.20.12", "upstream_port": 443, "proxy_local_port": 8452},
    {"id": "mt3000", "role": "router", "fallback_ip": "10.10.10.50", "upstream_port": 80, "proxy_local_port": 8455},
]


def test_render_upstreams_conf_contains_named_upstreams():
    conf = render_upstreams_conf(DEVICES, {"rm1pe": "10.10.20.15", "rm10": "10.10.20.12"})
    assert "upstream glinet_rm1pe {" in conf and "server 10.10.20.15:443;" in conf
    assert "upstream glinet_rm10 {" in conf and "server 10.10.20.12:443;" in conf
    assert "upstream glinet_mt3000 {" in conf and "server 10.10.10.50:80;" in conf


def test_render_upstreams_rejects_invalid_ip():
    with pytest.raises(ValueError):
        render_upstreams_conf(DEVICES, {"rm1pe": "192.168.1.1; evil"})


def test_sync_skips_reload_when_unchanged_and_rolls_back_on_validation_error(tmp_path: Path):
    out = tmp_path / "upstreams.conf"
    pid = tmp_path / "nginx.pid"
    pid.write_text("4242\n")
    reloads = []

    res1 = sync_nginx_upstreams(
        DEVICES,
        {"rm1pe": "10.10.10.21"},
        out,
        tmp_path / "n.conf",
        pid,
        validate_cmd=["true"],
        reload_fn=reloads.append,
    )
    assert res1 == {"changed": True, "reloaded": True, "error": None}
    assert reloads == [4242]

    res2 = sync_nginx_upstreams(
        DEVICES,
        {"rm1pe": "10.10.10.21"},
        out,
        tmp_path / "n.conf",
        pid,
        validate_cmd=["true"],
        reload_fn=reloads.append,
    )
    assert res2 == {"changed": False, "reloaded": False, "error": None}

    res3 = sync_nginx_upstreams(
        DEVICES,
        {"rm1pe": "10.10.20.99"},
        out,
        tmp_path / "n.conf",
        pid,
        validate_cmd=["false"],
        reload_fn=reloads.append,
    )
    assert res3["reloaded"] is False and res3["error"] is not None
    assert "10.10.10.21:443" in out.read_text()
    assert reloads == [4242]


def test_seed_upstreams_from_config_writes_fallback_file(tmp_path: Path):
    cfg = tmp_path / "devices.example.json"
    cfg.write_text(json.dumps({"devices": DEVICES}))
    out = tmp_path / "run" / "upstreams.conf"
    seed_upstreams_from_config(cfg, out)
    text = out.read_text()
    assert "server 10.10.10.21:443;" in text
    assert "server 10.10.20.12:443;" in text


def test_concurrent_atomic_writes_do_not_collide(tmp_path: Path):
    target = tmp_path / "upstreams.conf"
    errors = []

    def worker(idx: int):
        try:
            for j in range(25):
                _atomic_write(target, f"worker={idx} iter={j}\n")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
    assert errors == []


def test_deploy_templates_enforce_request_buffering_off_and_rightmost_xff():
    root = Path(__file__).resolve().parent.parent
    tmpl = (root / "deploy" / "nginx.conf.tmpl").read_text(encoding="utf-8")
    deploy_sh = (root / "deploy" / "deploy.sh").read_text(encoding="utf-8")
    assert "__SERVER_BLOCKS__" in tmpl
    assert "proxy_request_buffering off;" in deploy_sh
    assert "tailscale serve --bg --https=" in deploy_sh
    assert r"(^|,\s*)" in deploy_sh


