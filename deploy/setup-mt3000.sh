#!/usr/bin/env bash
# Safe, idempotent GL.iNet 4.x / OpenWrt 21.02 (fw3/iptables) Multi-WAN + Fail-Closed VPN Gate + Wi-Fi Hunter installer.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MT_HOST="gl-mt3000"
PORTAL_HOST="${PORTAL_HOST:-}"
PORTAL_DIR="${PORTAL_DIR:-/opt/glinet-portal}"
WG_CONF=""
WG_VAN_CONF=""
GROOVE_IP="192.168.88.1"
GROOVE_KEY_TYPE="ed25519"
RESET_DAY="1"
CAP_GB="50.0"
SKIP_WAN_RECONFIG="0"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --host) MT_HOST="$2"; shift 2 ;;
        --wg-conf) WG_CONF="$2"; shift 2 ;;
        --wg-van-conf) WG_VAN_CONF="$2"; shift 2 ;;
        --groove-ip) GROOVE_IP="$2"; shift 2 ;;
        --groove-key-type) GROOVE_KEY_TYPE="$2"; shift 2 ;;
        --reset-day) RESET_DAY="$2"; shift 2 ;;
        --cap-gb) CAP_GB="$2"; shift 2 ;;
        --skip-wan-reconfig) SKIP_WAN_RECONFIG="1"; shift ;;
        -h|--help)
            echo "Usage: $0 [--host gl-mt3000] [--wg-conf wg-mgmt.conf] [--wg-van-conf wg-van-full.conf] [--groove-ip 192.168.88.1] [--groove-key-type ed25519|rsa] [--reset-day 1] [--cap-gb 50.0] [--skip-wan-reconfig]"
            exit 0
            ;;
        *) echo "Unknown arg: $1" >&2; exit 2 ;;
    esac
done

case "${GROOVE_KEY_TYPE}" in
    ed25519|rsa) ;;
    *) echo "ERROR: --groove-key-type must be ed25519 or rsa" >&2; exit 2 ;;
esac

echo "[1/6] Verifying SSH connectivity, fw3/iptables, and required tools on ${MT_HOST}..."
ssh -o BatchMode=yes -o ConnectTimeout=5 -o IPQoS=none "${MT_HOST}" '
if [ -x /sbin/fw4 ] && [ ! -x /sbin/fw3 ]; then
    echo "ERROR: OpenWrt fw4/nftables detected. van-wan-guard currently requires fw3/iptables (GL.iNet 4.x / OpenWrt 21.02)." >&2
    exit 1
fi
(cat /etc/glversion 2>/dev/null || cat /etc/openwrt_release) && uname -a
for b in curl ip ping dropbearkey dbclient scp wg ubus lua iptables ip6tables uhttpd; do
    command -v "$b" >/dev/null || { echo "MISSING tool: $b" >&2; exit 1; }
done
lua -e "require(\"luci.jsonc\")"
'

echo "[2/6] Backing up /etc/config on ${MT_HOST}..."
ssh -o IPQoS=none "${MT_HOST}" 'TS=$(date +%Y%m%d-%H%M%S); tar -czf "/root/uci-backup-${TS}.tar.gz" /etc/config && ls -lh "/root/uci-backup-${TS}.tar.gz"'

echo "[3/6] Installing van-wan-guard, VPN killswitch, Lua allowlist engine, wifi-hunter & offline UI (scp -O)..."
ssh -o IPQoS=none "${MT_HOST}" "mkdir -p /etc/van-wan-guard /var/run/van-wan-guard /usr/libexec/van-wan-guard /www/van /www/cgi-bin /etc/sysctl.d /etc/hotplug.d/firewall"
scp -O -o IPQoS=none -q "${ROOT_DIR}/router/usr/libexec/van-wan-guard/lib.sh" \
          "${ROOT_DIR}/router/usr/libexec/van-wan-guard/vpn-gate.sh" \
          "${ROOT_DIR}/router/usr/libexec/van-wan-guard/daemon.sh" \
          "${ROOT_DIR}/router/usr/libexec/van-wan-guard/groove-poll.sh" \
          "${ROOT_DIR}/router/usr/libexec/van-wan-guard/groove-ssh.sh" \
          "${ROOT_DIR}/router/usr/libexec/van-wan-guard/networks.lua" \
          "${ROOT_DIR}/router/usr/libexec/van-wan-guard/wifi-hunter.sh" \
          "${MT_HOST}:/usr/libexec/van-wan-guard/"
scp -O -o IPQoS=none -q "${ROOT_DIR}/router/usr/bin/van-wan" "${MT_HOST}:/usr/bin/van-wan"
scp -O -o IPQoS=none -q "${ROOT_DIR}/router/etc/init.d/van-wan-guard" "${MT_HOST}:/etc/init.d/van-wan-guard"
scp -O -o IPQoS=none -q "${ROOT_DIR}/router/etc/firewall.user" "${MT_HOST}:/etc/firewall.user"
scp -O -o IPQoS=none -q "${ROOT_DIR}/router/etc/sysctl.d/99-van-no-ipv6.conf" "${MT_HOST}:/etc/sysctl.d/99-van-no-ipv6.conf"
scp -O -o IPQoS=none -q "${ROOT_DIR}/router/etc/hotplug.d/firewall/90-van-wan-guard" "${MT_HOST}:/etc/hotplug.d/firewall/90-van-wan-guard"
scp -O -o IPQoS=none -q "${ROOT_DIR}/router/www/van/index.html" "${MT_HOST}:/www/van/index.html"
scp -O -o IPQoS=none -q "${ROOT_DIR}/router/www/cgi-bin/van-wan" "${MT_HOST}:/www/cgi-bin/van-wan"
ssh -o IPQoS=none "${MT_HOST}" "chmod +x /usr/libexec/van-wan-guard/*.sh /usr/libexec/van-wan-guard/networks.lua /usr/bin/van-wan /etc/init.d/van-wan-guard /etc/hotplug.d/firewall/90-van-wan-guard /www/cgi-bin/van-wan"

# Preserve existing known_networks.json if present; install template only on first deploy
if ! ssh -o IPQoS=none "${MT_HOST}" "[ -s /etc/van-wan-guard/known_networks.json ]"; then
    scp -O -o IPQoS=none -q "${ROOT_DIR}/router/etc/van-wan-guard/known_networks.json" "${MT_HOST}:/etc/van-wan-guard/known_networks.json"
fi
ssh -o IPQoS=none "${MT_HOST}" "chmod 600 /etc/van-wan-guard/known_networks.json && (grep -qxF '/etc/van-wan-guard' /etc/sysupgrade.conf 2>/dev/null || printf '/etc/van-wan-guard\n' >> /etc/sysupgrade.conf)"

TMP_CFG="$(mktemp)"
EXISTING_CFG="$(mktemp)"
trap 'rm -f "${TMP_CFG}" "${EXISTING_CFG}"' EXIT
ssh -o IPQoS=none "${MT_HOST}" "cat /etc/van-wan-guard/config.json 2>/dev/null || true" > "${EXISTING_CFG}" || true
python3 - "${ROOT_DIR}/router/etc/van-wan-guard/config.json" "${TMP_CFG}" "${GROOVE_IP}" "${RESET_DAY}" "${CAP_GB}" "${WG_CONF}" "${WG_VAN_CONF}" "${EXISTING_CFG}" << 'PYEOF'
import json, re, sys
from pathlib import Path

cfg = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
ex_path = Path(sys.argv[8])
if ex_path.exists() and ex_path.stat().st_size > 0:
    try:
        ex = json.loads(ex_path.read_text(encoding="utf-8"))
        if ex.get("wg_endpoint_host"):
            cfg["wg_endpoint_host"] = ex["wg_endpoint_host"]
        if ex.get("wg_endpoint_port"):
            cfg["wg_endpoint_port"] = int(ex["wg_endpoint_port"])
    except json.JSONDecodeError:
        pass
cfg["groove_ip"] = sys.argv[3]
cfg["billing_reset_day"] = int(sys.argv[4])
cfg["starlink_cap_gb"] = float(sys.argv[5])
for wg_path in (sys.argv[7], sys.argv[6]):
    if wg_path and Path(wg_path).exists():
        text = Path(wg_path).read_text(encoding="utf-8")
        m = re.search(r"^\s*Endpoint\s*=\s*([^:\s#]+):(\d+)", text, re.M)
        if m:
            cfg["wg_endpoint_host"] = m.group(1)
            cfg["wg_endpoint_port"] = int(m.group(2))
            break
Path(sys.argv[2]).write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
PYEOF
scp -O -o IPQoS=none -q "${TMP_CFG}" "${MT_HOST}:/etc/van-wan-guard/config.json"

echo "[4/6] Checking Dropbear CPE keypair (${GROOVE_KEY_TYPE}) & optionally enrolling portal SSH key..."
GROOVE_PUB="$(ssh -o IPQoS=none "${MT_HOST}" "if [ ! -f /etc/van-wan-guard/groove_dropbear.key ]; then dropbearkey -t '${GROOVE_KEY_TYPE}' -f /etc/van-wan-guard/groove_dropbear.key >/dev/null; chmod 600 /etc/van-wan-guard/groove_dropbear.key; fi; dropbearkey -y -f /etc/van-wan-guard/groove_dropbear.key | grep '^ssh-'")"
echo "  CPE Dropbear pubkey: ${GROOVE_PUB}"

if [ -n "${PORTAL_HOST}" ]; then
    PORTAL_PUB="$(ssh -o BatchMode=yes -o ConnectTimeout=3 -o IPQoS=none "${PORTAL_HOST}" "cat '${PORTAL_DIR}/id_ed25519.pub'" 2>/dev/null || true)"
    if [ -n "${PORTAL_PUB}" ]; then
        printf '%s\n' "${PORTAL_PUB}" | ssh -o IPQoS=none "${MT_HOST}" '
            set -eu
            IFS= read -r key
            mkdir -p /etc/dropbear
            touch /etc/dropbear/authorized_keys
            chmod 600 /etc/dropbear/authorized_keys
            grep -qxF "$key" /etc/dropbear/authorized_keys || printf "%s\n" "$key" >> /etc/dropbear/authorized_keys
        '
        echo "  Enrolled portal SSH pubkey in /etc/dropbear/authorized_keys."
    else
        echo "  WARNING: Could not fetch portal pubkey from ${PORTAL_HOST}; enroll manually if using the portal." >&2
    fi
fi

if [ "${SKIP_WAN_RECONFIG}" = "0" ]; then
    echo "[5/6] Configuring dual-WAN, IPv6 leak blocks, LAN-only :8080 UI, firewall.user reload=1, & killswitch hygiene..."
    ssh -o IPQoS=none "${MT_HOST}" 'sh -s' << 'REMOTE_UCI'
set -eu

if ! ubus call network.wireless status 2>/dev/null | grep -q '"up": true'; then
    echo "ERROR: No live Wi-Fi AP is UP in ubus network.wireless; aborting eth1 detach for safety." >&2
    exit 1
fi

SSH_PEER="${SSH_CLIENT:-}"
SSH_PEER="${SSH_PEER%% *}"
if [ -n "${SSH_PEER:-}" ] && ip -4 neigh show dev eth1 2>/dev/null | grep -q "^${SSH_PEER} "; then
    echo "ERROR: Current SSH session (${SSH_PEER}) is on eth1; reconnect via router Wi-Fi AP before detaching eth1." >&2
    exit 1
fi

for devsec in $(uci show network | awk -F. '/=device$/ {print $2}'); do
    if [ "$(uci -q get network.${devsec}.name || true)" = "br-lan" ]; then
        uci -q del_list "network.${devsec}.ports=eth1" || true
        uci set "network.${devsec}.bridge_empty=1"
    fi
done

uci set network.wan.device='eth0'
uci set network.wan.proto='dhcp'
uci set network.wan.defaultroute='0'
uci set network.wan.peerdns='0'
uci set network.wan.ipv6='0'
uci set network.wan.ip4table='101'
uci -q delete network.wan.disabled || true
uci -q delete network.wan.metric || true

uci set network.wan2=interface
uci set network.wan2.device='eth1'
uci set network.wan2.proto='dhcp'
uci set network.wan2.defaultroute='0'
uci set network.wan2.peerdns='0'
uci set network.wan2.ipv6='0'
uci set network.wan2.ip4table='102'
uci -q delete network.wan2.disabled || true
uci -q delete network.wan2.metric || true

uci -q set network.wan6.disabled='1' || true

uci set network.starlink_dish=route
uci set network.starlink_dish.interface='wan2'
uci set network.starlink_dish.target='192.168.100.1/32'
uci set network.starlink_dish.scope='link'
uci set network.starlink_dish.table='254'
uci -q delete network.starlink_dish.onlink || true

for z in $(uci show firewall | awk -F. '/=zone$/ {print $2}'); do
    if [ "$(uci -q get firewall.${z}.name || true)" = "wan" ]; then
        uci -q del_list "firewall.${z}.network=wan2" || true
        uci add_list "firewall.${z}.network=wan2"
    fi
done

# Bind uhttpd strictly to LAN_IP (never 0.0.0.0) and block guest -> :8080/:8443
LAN_IP="$(uci -q get network.lan.ipaddr || echo 192.168.8.1)"
if uci -q get uhttpd.main >/dev/null 2>&1; then
    uci -q del uhttpd.main.listen_http || true
    uci add_list "uhttpd.main.listen_http=${LAN_IP}:8080"
    if uci -q get uhttpd.main.listen_https >/dev/null 2>&1; then
        uci -q del uhttpd.main.listen_https || true
        uci add_list "uhttpd.main.listen_https=${LAN_IP}:8443"
    fi
    uci set uhttpd.main.rfc1918_filter='1'
    uci -q delete uhttpd.van_ui || true
else
    uci set uhttpd.van_ui=uhttpd
    uci -q del uhttpd.van_ui.listen_http || true
    uci add_list "uhttpd.van_ui.listen_http=${LAN_IP}:8080"
    uci set uhttpd.van_ui.home='/www'
    uci set uhttpd.van_ui.cgi_prefix='/cgi-bin'
    uci set uhttpd.van_ui.rfc1918_filter='1'
fi
uci commit uhttpd

uci set firewall.block_guest_van_ui=rule
uci set firewall.block_guest_van_ui.name='Block-Guest-Van-UI-8080'
uci set firewall.block_guest_van_ui.src='guest'
uci set firewall.block_guest_van_ui.proto='tcp'
uci set firewall.block_guest_van_ui.dest_port='8080 8443'
uci set firewall.block_guest_van_ui.target='REJECT'

_has_inc=0
for inc in $(uci show firewall | awk -F. '/=include$/ {print $2}'); do
    if [ "$(uci -q get firewall.${inc}.path || true)" = "/etc/firewall.user" ]; then
        uci set "firewall.${inc}.reload=1"
        uci set "firewall.${inc}.enabled=1"
        _has_inc=1
    fi
done
if [ "$_has_inc" = "0" ]; then
    uci set firewall.van_user=include
    uci set firewall.van_user.type='script'
    uci set firewall.van_user.path='/etc/firewall.user'
    uci set firewall.van_user.reload='1'
    uci set firewall.van_user.enabled='1'
fi

uci -q set network.wgclient.disabled='1' || true
uci -q set network.wgclient1.disabled='1' || true
for rsec in $(uci show network | awk -F. '/\.gl_vpn_rules=/ {print $2}'); do
    uci -q set "network.${rsec}.disabled=1" || true
done

for sec in $(uci show network | awk -F. '/=wireguard_wg_mgmt$/ {print $2}'); do
    uci set "network.${sec}.route_allowed_ips=0"
done

sysctl -p /etc/sysctl.d/99-van-no-ipv6.conf >/dev/null 2>&1 || true

uci -q set gl-cloud.@cloud[0].enable='0' || true
uci -q commit gl-cloud || true
/etc/init.d/kmwan stop 2>/dev/null || true
/etc/init.d/kmwan disable 2>/dev/null || true

uci commit network
uci commit firewall
/etc/init.d/uhttpd enable 2>/dev/null || true
/etc/init.d/uhttpd restart 2>/dev/null || true
/etc/init.d/network reload
/etc/init.d/firewall reload
while ip rule del prio 9920 2>/dev/null; do :; done
REMOTE_UCI
else
    echo "[5/6] Skipping UCI dual-WAN reconfig (--skip-wan-reconfig)."
    ssh -o IPQoS=none "${MT_HOST}" "sysctl -p /etc/sysctl.d/99-van-no-ipv6.conf >/dev/null 2>&1 || true; sh /etc/firewall.user"
fi

_render_wg_uci() {
    python3 - "$1" "$2" << 'PYEOF'
import configparser, shlex, sys
from pathlib import Path

mode = sys.argv[1]
raw = Path(sys.argv[2]).read_text(encoding="utf-8")
# Strip full-line and inline WireGuard '#' comments safely
clean_lines = []
for line in raw.splitlines():
    s = line.split("#", 1)[0].strip()
    if s:
        clean_lines.append(s)
cp = configparser.ConfigParser(interpolation=None)
cp.read_string("\n".join(clean_lines))

priv = cp.get("Interface", "PrivateKey", fallback="").strip()
addr = cp.get("Interface", "Address", fallback="").split(",")[0].strip()
pub = cp.get("Peer", "PublicKey", fallback="").strip()
psk = cp.get("Peer", "PresharedKey", fallback="").strip()
ep = cp.get("Peer", "Endpoint", fallback="").strip()
allowed = cp.get("Peer", "AllowedIPs", fallback="192.168.2.1/32").split(",")[0].strip()

if not (priv and addr and pub and ep) or ":" not in ep:
    raise SystemExit("WireGuard conf missing required PrivateKey/Address/PublicKey/Endpoint")
host, port = ep.rsplit(":", 1)
if not port.isdigit():
    raise SystemExit(f"Invalid WireGuard endpoint port: {port!r}")

def q(v: str) -> str:
    return shlex.quote(v)

if mode == "mgmt":
    peer_src = allowed if allowed.endswith("/32") else "192.168.2.1/32"
    cmds = [
        "uci set network.wg_mgmt=interface",
        "uci set network.wg_mgmt.proto='wireguard'",
        f"uci set network.wg_mgmt.private_key={q(priv)}",
        "uci -q del network.wg_mgmt.addresses || true",
        f"uci add_list network.wg_mgmt.addresses={q(addr)}",
        "uci set network.wg_mgmt_peer=wireguard_wg_mgmt",
        f"uci set network.wg_mgmt_peer.public_key={q(pub)}",
        f"uci set network.wg_mgmt_peer.endpoint_host={q(host)}",
        f"uci set network.wg_mgmt_peer.endpoint_port={q(port)}",
        "uci set network.wg_mgmt_peer.persistent_keepalive='25'",
        "uci set network.wg_mgmt_peer.route_allowed_ips='0'",
        "uci -q del network.wg_mgmt_peer.allowed_ips || true",
        f"uci add_list network.wg_mgmt_peer.allowed_ips={q(peer_src)}",
        "uci set firewall.wg_mgmt_zone=zone",
        "uci set firewall.wg_mgmt_zone.name='wg_mgmt'",
        "uci set firewall.wg_mgmt_zone.input='REJECT'",
        "uci set firewall.wg_mgmt_zone.output='ACCEPT'",
        "uci set firewall.wg_mgmt_zone.forward='REJECT'",
        "uci -q del firewall.wg_mgmt_zone.network || true",
        "uci add_list firewall.wg_mgmt_zone.network='wg_mgmt'",
        "uci set firewall.wg_mgmt_allow=rule",
        "uci set firewall.wg_mgmt_allow.name='Allow-Gateway-Portal-SSH-HTTP'",
        "uci set firewall.wg_mgmt_allow.src='wg_mgmt'",
        f"uci set firewall.wg_mgmt_allow.src_ip={q(peer_src)}",
        "uci set firewall.wg_mgmt_allow.dest_port='22 80'",
        "uci set firewall.wg_mgmt_allow.proto='tcp'",
        "uci set firewall.wg_mgmt_allow.target='ACCEPT'",
    ]
    if psk:
        cmds.insert(7, f"uci set network.wg_mgmt_peer.preshared_key={q(psk)}")
else:
    cmds = [
        "uci set network.wg_van=interface",
        "uci set network.wg_van.proto='wireguard'",
        f"uci set network.wg_van.private_key={q(priv)}",
        "uci set network.wg_van.fwmark='0x101'",
        "uci -q del network.wg_van.addresses || true",
        f"uci add_list network.wg_van.addresses={q(addr)}",
        "uci set network.wg_van_peer=wireguard_wg_van",
        f"uci set network.wg_van_peer.public_key={q(pub)}",
        f"uci set network.wg_van_peer.endpoint_host={q(host)}",
        f"uci set network.wg_van_peer.endpoint_port={q(port)}",
        "uci set network.wg_van_peer.persistent_keepalive='25'",
        "uci set network.wg_van_peer.route_allowed_ips='0'",
        "uci -q del network.wg_van_peer.allowed_ips || true",
        "uci add_list network.wg_van_peer.allowed_ips='0.0.0.0/0'",
        "uci set firewall.wg_van_zone=zone",
        "uci set firewall.wg_van_zone.name='wg_van'",
        "uci set firewall.wg_van_zone.input='REJECT'",
        "uci set firewall.wg_van_zone.output='ACCEPT'",
        "uci set firewall.wg_van_zone.forward='REJECT'",
        "uci set firewall.wg_van_zone.masq='1'",
        "uci set firewall.wg_van_zone.mtu_fix='1'",
        "uci -q del firewall.wg_van_zone.network || true",
        "uci add_list firewall.wg_van_zone.network='wg_van'",
        "uci set firewall.lan_to_wg_van=forwarding",
        "uci set firewall.lan_to_wg_van.src='lan'",
        "uci set firewall.lan_to_wg_van.dest='wg_van'",
        "uci set firewall.guest_to_wg_van=forwarding",
        "uci set firewall.guest_to_wg_van.src='guest'",
        "uci set firewall.guest_to_wg_van.dest='wg_van'",
    ]
    if psk:
        cmds.insert(8, f"uci set network.wg_van_peer.preshared_key={q(psk)}")

cmds.append("uci commit network && uci commit firewall && /etc/init.d/network reload && /etc/init.d/firewall reload")
print("\n".join(cmds))
PYEOF
}

if [ -n "${WG_CONF}" ]; then
    echo "[5b] Configuring split-tunnel management WireGuard (wg_mgmt, route_allowed_ips=0)..."
    _render_wg_uci mgmt "${WG_CONF}" | ssh -o IPQoS=none "${MT_HOST}" "sh -eu"
fi

if [ -n "${WG_VAN_CONF}" ]; then
    echo "[5c] Configuring full-tunnel CPE WireGuard (wg_van, fwmark=0x101 pinned strictly to eth0)..."
    _render_wg_uci van "${WG_VAN_CONF}" | ssh -o IPQoS=none "${MT_HOST}" "sh -eu"
fi

echo "[6/6] Enabling & starting van-wan-guard and verifying fail-closed VPN killswitch + offline LAN UI..."
ssh -o IPQoS=none "${MT_HOST}" '
LAN_IP="$(uci -q get network.lan.ipaddr || echo 192.168.8.1)"
/etc/init.d/van-wan-guard enable && /etc/init.d/van-wan-guard restart && sleep 3
/usr/bin/van-wan status
echo "--- zero-leak firewall check ---"
iptables -S FORWARD | head -n 4
iptables -S VAN_CPE_GATE
iptables -S VAN_CPE_DNS_OUT
echo "--- offline UI check (${LAN_IP}:8080) ---"
curl -sS -o /dev/null -w "van_ui_http=%{http_code}\n" "http://${LAN_IP}:8080/van/index.html"
curl -sS -o /dev/null -w "van_cgi_get=%{http_code}\n" "http://${LAN_IP}:8080/cgi-bin/van-wan"
curl -sS -o /dev/null -w "van_cgi_nets=%{http_code}\n" "http://${LAN_IP}:8080/cgi-bin/van-wan?resource=networks"
curl -sS -o /dev/null -w "van_cgi_csrf=%{http_code}\n" -X POST "http://${LAN_IP}:8080/cgi-bin/van-wan"
'
echo "Router setup complete."
