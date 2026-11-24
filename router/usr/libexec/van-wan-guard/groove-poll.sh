#!/bin/sh
# Non-blocking MikroTik CPE RouterOS telemetry poller (OpenSSH or Dropbear).
set -eu

CONF_DIR="${VAN_CONF_DIR:-/etc/van-wan-guard}"
STATE_DIR="${VAN_STATE_DIR:-/var/run/van-wan-guard}"
SCRIPT_DIR="$(dirname "$0")"
# shellcheck source=lib.sh
. "${SCRIPT_DIR}/lib.sh"

CFG="${CONF_DIR}/config.json"
GROOVE_IP="$(json_get_val "$CFG" "groove_ip" "192.168.88.1")"
GROOVE_USER="$(json_get_val "$CFG" "groove_user" "hunter")"
GROOVE_KEY="$(json_get_val "$CFG" "groove_key" "/etc/van-wan-guard/groove_dropbear.key")"

ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [ ! -f "$GROOVE_KEY" ]; then
    atomic_write_file "${STATE_DIR}/groove.json" \
        "{\"reachable\":false,\"error\":\"key_not_enrolled\",\"checked_at\":\"${ts}\"}"
    exit 0
fi

export HOME="${HOME:-/root}"

run_ros_cmd() {
    if [ -x /usr/libexec/ssh-openssh ] && [ -x "${SCRIPT_DIR}/groove-ssh.sh" ]; then
        if command -v timeout >/dev/null 2>&1; then
            timeout 5 "${SCRIPT_DIR}/groove-ssh.sh" -i "$GROOVE_KEY" "${GROOVE_USER}@${GROOVE_IP}" "$1" </dev/null 2>/dev/null || true
        else
            "${SCRIPT_DIR}/groove-ssh.sh" -i "$GROOVE_KEY" "${GROOVE_USER}@${GROOVE_IP}" "$1" </dev/null 2>/dev/null || true
        fi
    else
        SSH_BIN="dbclient"
        command -v dbclient >/dev/null 2>&1 || SSH_BIN="ssh"
        if command -v timeout >/dev/null 2>&1; then
            timeout 3 "$SSH_BIN" -y -i "$GROOVE_KEY" "${GROOVE_USER}@${GROOVE_IP}" "$1" </dev/null 2>/dev/null || true
        else
            "$SSH_BIN" -y -i "$GROOVE_KEY" "${GROOVE_USER}@${GROOVE_IP}" "$1" </dev/null 2>/dev/null || true
        fi
    fi
}

raw="$(run_ros_cmd "/interface wireless monitor wlan1 once")"
if ! printf '%s\n' "$raw" | grep -qE '^[[:space:]]*(status|state):'; then
    raw="$(run_ros_cmd "/interface wifi monitor 0 once")"
fi

if ! printf '%s\n' "$raw" | grep -qE '^[[:space:]]*(status|state):'; then
    atomic_write_file "${STATE_DIR}/groove.json" \
        "{\"reachable\":false,\"error\":\"unreachable\",\"checked_at\":\"${ts}\"}"
    exit 0
fi

parsed="$(printf '%s\n' "$raw" | parse_groove_monitor)"
IFS='|' read -r g_status g_ssid g_bssid g_rssi g_chan g_tx <<EOF
$parsed
EOF

g_rssi_json="null"
case "$g_rssi" in
    -[0-9]*|[0-9]*) g_rssi_json="$g_rssi" ;;
esac

json="$(printf '{"reachable":true,"status":"%s","ssid":"%s","bssid":"%s","rssi_dbm":%s,"channel":"%s","tx_rate":"%s","checked_at":"%s"}' \
    "$(json_escape "$g_status")" \
    "$(json_escape "$g_ssid")" \
    "$(json_escape "$g_bssid")" \
    "$g_rssi_json" \
    "$(json_escape "$g_chan")" \
    "$(json_escape "$g_tx")" \
    "$ts")"
atomic_write_file "${STATE_DIR}/groove.json" "$json"
