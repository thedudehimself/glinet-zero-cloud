#!/usr/bin/env bash
# Config-driven deployer for GL.iNet Private Management Portal on any Linux systemd edge gateway.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATEWAY_HOST="${GATEWAY_HOST:-}"
REMOTE_DIR="${REMOTE_DIR:-/opt/glinet-portal}"
CONFIG_PATH="${CONFIG_PATH:-${ROOT_DIR}/config/devices.json}"
TRIAGE_SCRIPT="${TRIAGE_SCRIPT:-${ROOT_DIR}/vendor/gl-helper-triage.sh}"
PORTAL_TS_PORT="${PORTAL_TS_PORT:-8440}"

if [ -z "${GATEWAY_HOST}" ]; then
    echo "Usage: GATEWAY_HOST=root@<gateway-ip> [REMOTE_DIR=/opt/glinet-portal] $0" >&2
    exit 2
fi
if [ ! -f "${CONFIG_PATH}" ]; then
    echo "ERROR: Missing ${CONFIG_PATH}. Copy config/devices.example.json to config/devices.json and fill in your devices." >&2
    exit 2
fi

echo "[1/5] Running local unit test suite..."
(cd "${ROOT_DIR}" && PYTHONPATH=src:deploy pytest -v)

echo "[2/5] Rendering nginx.conf and systemd units from ${CONFIG_PATH}..."
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

python3 - "${CONFIG_PATH}" "${ROOT_DIR}/deploy" "${TMP_DIR}" "${REMOTE_DIR}" "${PORTAL_TS_PORT}" << 'PYEOF'
import json, re, sys
from pathlib import Path

cfg = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
deploy_dir = Path(sys.argv[2])
out_dir = Path(sys.argv[3])
remote_dir = sys.argv[4]
portal_ts_port = int(sys.argv[5])

users = cfg.get("allowed_tailscale_users", [])
ips = cfg.get("allowed_tailscale_ips", [])
if not users:
    raise SystemExit("allowed_tailscale_users must not be empty")

user_rules = "\n".join(f"        ~*^{re.escape(u)}$ allow;" for u in users)
ip_rules = "\n".join(rf"        ~*(^|,\s*){re.escape(ip)}$ 1;" for ip in ips)

server_blocks = []
serve_cmds = [f"tailscale serve --bg --https={portal_ts_port} http://127.0.0.1:8450"]

for dev in cfg.get("devices", []):
    if not dev.get("proxy_local_port") or not dev.get("tailscale_port"):
        continue
    dev_id = dev["id"]
    if not re.fullmatch(r"[a-z0-9_]+", dev_id):
        raise SystemExit(f"Invalid device id for nginx upstream (lowercase alnum/underscore only): {dev_id!r}")
    scheme = dev.get("scheme", "http")
    if scheme not in ("http", "https"):
        raise SystemExit(f"Invalid scheme for {dev_id}: {scheme!r}")
    local_port = int(dev["proxy_local_port"])
    ts_port = int(dev["tailscale_port"])
    is_https = scheme == "https"
    # GL.iNet 4.11.1+ oui-access.lua rejects external *.ts.net Host headers with 403; use router LAN Host for van_router
    host_hdr = dev.get("upstream_host_header", "192.168.8.1" if dev.get("role") == "van_router" else "$http_host")
    if not re.fullmatch(r"[A-Za-z0-9.:$_-]+", host_hdr):
        raise SystemExit(f"Invalid upstream_host_header for {dev_id}: {host_hdr!r}")
    ssl_lines = "            proxy_ssl_verify off;\n            proxy_ssl_server_name off;\n" if is_https else ""
    timeout_s = "3600s" if dev.get("role") == "kvm" else "300s"
    max_body = "0" if dev.get("role") == "kvm" else "64m"
    server_blocks.append(
        f"""    server {{
        listen 127.0.0.1:{local_port};
        server_name _;

        if ($ts_allowed = 0) {{
            return 403;
        }}

        location / {{
            proxy_pass {scheme}://glinet_{dev_id};
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header Host {host_hdr};
            proxy_set_header X-Forwarded-Proto https;
{ssl_lines}            proxy_buffering off;
            proxy_request_buffering off;
            proxy_redirect off;
            proxy_read_timeout {timeout_s};
            proxy_send_timeout {timeout_s};
            client_max_body_size {max_body};
        }}
    }}"""
    )
    serve_cmds.append(f"tailscale serve --bg --https={ts_port} http://127.0.0.1:{local_port}")

nginx_tmpl = (deploy_dir / "nginx.conf.tmpl").read_text(encoding="utf-8")
nginx_rendered = (
    nginx_tmpl.replace("__TS_USER_RULES__", user_rules)
    .replace("__TS_IP_RULES__", ip_rules)
    .replace("__SERVER_BLOCKS__", "\n\n".join(server_blocks))
)
(out_dir / "nginx.conf").write_text(nginx_rendered, encoding="utf-8")

for unit in ("glinet-portal.service", "glinet-portal-nginx.service"):
    tmpl = (deploy_dir / f"{unit}.tmpl").read_text(encoding="utf-8")
    (out_dir / unit).write_text(tmpl.replace("__REMOTE_DIR__", remote_dir), encoding="utf-8")

(out_dir / "tailscale-serve.sh").write_text("#!/bin/sh\nset -e\n" + "\n".join(serve_cmds) + "\n", encoding="utf-8")
PYEOF

echo "[3/5] Syncing files to ${GATEWAY_HOST}:${REMOTE_DIR}..."
ssh "${GATEWAY_HOST}" "mkdir -p '${REMOTE_DIR}/src/static' /run/glinet-portal/tmp"
scp -q "${ROOT_DIR}"/src/*.py "${GATEWAY_HOST}:${REMOTE_DIR}/src/"
scp -q "${ROOT_DIR}/src/static/index.html" "${GATEWAY_HOST}:${REMOTE_DIR}/src/static/"
scp -q "${ROOT_DIR}/router/www/van/index.html" "${GATEWAY_HOST}:${REMOTE_DIR}/src/static/van.html"
scp -q "${CONFIG_PATH}" "${GATEWAY_HOST}:${REMOTE_DIR}/devices.json"
scp -q "${TMP_DIR}/nginx.conf" "${GATEWAY_HOST}:${REMOTE_DIR}/nginx.conf"
scp -q "${TMP_DIR}/glinet-portal.service" "${TMP_DIR}/glinet-portal-nginx.service" "${GATEWAY_HOST}:/etc/systemd/system/"
scp -q "${TMP_DIR}/tailscale-serve.sh" "${GATEWAY_HOST}:${REMOTE_DIR}/tailscale-serve.sh"
if [ -f "${TRIAGE_SCRIPT}" ]; then
    scp -q "${TRIAGE_SCRIPT}" "${GATEWAY_HOST}:${REMOTE_DIR}/gl-helper-triage.sh"
    ssh "${GATEWAY_HOST}" "chmod +x '${REMOTE_DIR}/gl-helper-triage.sh'"
else
    echo "  NOTE: Optional triage script not found at ${TRIAGE_SCRIPT}; see README to fetch upstream admonstrator/glinet-csa-2026-01."
fi
ssh "${GATEWAY_HOST}" "chmod 600 '${REMOTE_DIR}/devices.json' && ([ ! -f '${REMOTE_DIR}/state.db' ] || chmod 600 '${REMOTE_DIR}/state.db') && chmod +x '${REMOTE_DIR}/tailscale-serve.sh'"

echo "[4/5] Ensuring dedicated portal SSH keypair on ${GATEWAY_HOST}..."
PUB_KEY="$(ssh "${GATEWAY_HOST}" "if [ ! -f '${REMOTE_DIR}/id_ed25519' ]; then ssh-keygen -t ed25519 -N '' -C 'glinet-portal' -f '${REMOTE_DIR}/id_ed25519' >/dev/null; chmod 600 '${REMOTE_DIR}/id_ed25519'; fi; cat '${REMOTE_DIR}/id_ed25519.pub'")"
echo "  Portal SSH public key: ${PUB_KEY}"
echo "  (Enroll this key in /root/.ssh/authorized_keys on KVMs or /etc/dropbear/authorized_keys on OpenWrt routers.)"

echo "[5/5] Reloading systemd, starting services, and applying tailscale serve..."
ssh "${GATEWAY_HOST}" "systemctl daemon-reload && systemctl enable glinet-portal-nginx.service glinet-portal.service && systemctl restart glinet-portal-nginx.service glinet-portal.service && sh '${REMOTE_DIR}/tailscale-serve.sh'"
echo "Deploy complete."
