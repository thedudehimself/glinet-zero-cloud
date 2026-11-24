#!/bin/sh
# Autonomous quality-gated dual-WAN failover daemon for GL-MT3000 (GrooveA-52 CPE primary, Starlink failover).
set -eu

CONF_DIR="${VAN_CONF_DIR:-/etc/van-wan-guard}"
STATE_DIR="${VAN_STATE_DIR:-/var/run/van-wan-guard}"
SYS_NET="${VAN_SYS_NET:-/sys/class/net}"
RESOLV_FILE="${VAN_RESOLV_FILE:-/tmp/resolv.conf.d/resolv.conf.auto}"
DRY_RUN="${VAN_DRY_RUN:-0}"
SKIP_GROOVE="${VAN_SKIP_GROOVE:-0}"
SCRIPT_DIR="$(dirname "$0")"
# shellcheck source=lib.sh
. "${SCRIPT_DIR}/lib.sh"
# shellcheck source=vpn-gate.sh
. "${SCRIPT_DIR}/vpn-gate.sh"

mkdir -p "$CONF_DIR" "$STATE_DIR"
CFG="${CONF_DIR}/config.json"

CPE_IFACE="$(json_get_val "$CFG" "cpe_iface" "eth0")"
SL_IFACE="$(json_get_val "$CFG" "starlink_iface" "eth1")"
CPE_TABLE="$(json_get_val "$CFG" "cpe_table" "101")"
SL_TABLE="$(json_get_val "$CFG" "starlink_table" "102")"
PING_COUNT="$(json_get_val "$CFG" "ping_count" "5")"
MAX_LOSS="$(json_get_val "$CFG" "max_loss_pct" "20")"
MAX_RTT="$(json_get_val "$CFG" "max_rtt_ms" "300")"
CAPTIVE_URL="$(json_get_val "$CFG" "captive_url" "http://connectivitycheck.gstatic.com/generate_204")"
INTERVAL="$(json_get_val "$CFG" "probe_interval_sec" "15")"
MAX_FAIL="$(json_get_val "$CFG" "failover_strikes" "2")"
MAX_OK="$(json_get_val "$CFG" "failback_strikes" "3")"
CAP_GB="$(json_get_val "$CFG" "starlink_cap_gb" "50.0")"
RESET_DAY="$(json_get_val "$CFG" "billing_reset_day" "1")"
GROOVE_IP="$(json_get_val "$CFG" "groove_ip" "192.168.88.1")"
WG_IFACE="$(json_get_val "$CFG" "wg_iface" "wg_mgmt")"
WG_MGMT_IP="$(json_get_val "$CFG" "wg_mgmt_ip" "192.168.2.5")"
WG_VAN_IFACE="$(json_get_val "$CFG" "wg_van_iface" "wg_van")"
WG_VAN_IP="$(json_get_val "$CFG" "wg_van_ip" "192.168.2.6")"
WG_PEER_IP="$(json_get_val "$CFG" "wg_peer_ip" "192.168.2.1")"
WG_EP_HOST="$(json_get_val "$CFG" "wg_endpoint_host" "")"
WG_EP_PORT="$(json_get_val "$CFG" "wg_endpoint_port" "51820")"
_req_vpn_cfg="$(json_get_val "$CFG" "require_vpn_untrusted" "true")"
REQUIRE_VPN="${VAN_REQUIRE_VPN:-}"
if [ -z "$REQUIRE_VPN" ]; then
    [ "$_req_vpn_cfg" = "false" ] && REQUIRE_VPN="0" || REQUIRE_VPN="1"
fi

CUR_WAN="cpe"
FAIL_STRIKES=0
OK_STRIKES=0
CPE_UNHEALTHY_STRIKES=0
LAST_GROOVE_POLL=0
LAST_HUNT_ATTEMPT=0
LAST_USAGE_FLUSH=0
LAST_FLUSHED_TOTAL=0
LAST_ROUTE_SIG=""
LAST_GATE_SIG=""
STOP_REQ=0
WAKE_REQ=0

# Load persisted Starlink usage
USAGE_FILE="${CONF_DIR}/starlink_usage.json"
RESET_FLAG="${CONF_DIR}/usage_reset.pending"
STORED_CYCLE="$(json_get_val "$USAGE_FILE" "cycle_key" "")"
LAST_IF_BYTES="$(json_get_val "$USAGE_FILE" "last_iface_bytes" "0")"
TOTAL_BYTES="$(json_get_val "$USAGE_FILE" "total_bytes" "0")"
LAST_FLUSHED_TOTAL="$TOTAL_BYTES"

consume_pending_reset() {
    if [ -f "$RESET_FLAG" ]; then
        _line="$(cat "$RESET_FLAG" 2>/dev/null || true)"
        rm -f "$RESET_FLAG"
        set -- $_line
        if [ -n "${1:-}" ] && [ -n "${2:-}" ]; then
            STORED_CYCLE="$1"
            LAST_IF_BYTES="$2"
            TOTAL_BYTES=0
            LAST_FLUSHED_TOTAL=0
        fi
    fi
}

flush_usage_to_flash() {
    consume_pending_reset
    _ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    atomic_write_file "$USAGE_FILE" \
        "{\"cycle_key\":\"${STORED_CYCLE}\",\"last_iface_bytes\":${LAST_IF_BYTES},\"total_bytes\":${TOTAL_BYTES},\"updated_at\":\"${_ts}\"}"
    LAST_USAGE_FLUSH="$(date +%s)"
    LAST_FLUSHED_TOTAL="$TOTAL_BYTES"
}

trap 'WAKE_REQ=1' USR1
trap 'STOP_REQ=1' TERM INT

get_iface_carrier() {
    _c="$(cat "${SYS_NET}/$1/carrier" 2>/dev/null || echo 0)"
    [ "$_c" = "1" ] && echo 1 || echo 0
}

get_iface_ip() {
    ip -4 addr show dev "$1" 2>/dev/null | awk '/inet / { sub(/\/.*/, "", $2); print $2; exit }'
}

get_table_gw() {
    ip route show table "$1" 2>/dev/null | awk '/^default / { for (i=1;i<=NF;i++) if ($i=="via") { print $(i+1); exit } }'
}

ensure_policy_rule() {
    _ip="$1"
    _tbl="$2"
    [ "$DRY_RUN" = "1" ] && return 0
    [ -z "$_ip" ] && return 0
    if ! ip rule show 2>/dev/null | grep -q "^${_tbl}:.*from ${_ip} lookup ${_tbl}"; then
        ip rule del prio "$_tbl" 2>/dev/null || true
        ip rule add from "${_ip}/32" table "$_tbl" prio "$_tbl" 2>/dev/null || true
    fi
}

ensure_mgmt_dest_rules() {
    [ "$DRY_RUN" = "1" ] && return 0
    if [ -n "$GROOVE_IP" ] && ! ip rule show 2>/dev/null | grep -q "to ${GROOVE_IP} lookup ${CPE_TABLE}"; then
        ip rule del prio 91 2>/dev/null || true
        ip rule add to "${GROOVE_IP}/32" table "$CPE_TABLE" prio 91 2>/dev/null || true
    fi
    if ! ip rule show 2>/dev/null | grep -q "to 192.168.100.1 lookup ${SL_TABLE}"; then
        ip rule del prio 92 2>/dev/null || true
        ip rule add to 192.168.100.1/32 table "$SL_TABLE" prio 92 2>/dev/null || true
    fi
}

get_ubus_dns() {
    _uci_iface="$1"
    if command -v ubus >/dev/null 2>&1; then
        ubus call "network.interface.${_uci_iface}" status 2>/dev/null | awk '
            /"dns-server"/ { in_dns=1; next }
            in_dns && /\]/ { in_dns=0 }
            in_dns {
                gsub(/[",[:space:]]/, "", $0)
                if ($0 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print "nameserver " $0
            }
        '
    fi
}

sync_active_dns() {
    _want="$1"
    _cpe_gw="$2"
    _gate_state="$3"
    [ "$DRY_RUN" = "1" ] && return 0
    _dns=""
    if [ "$_want" = "starlink" ]; then
        _dns="$(get_ubus_dns wan2)"
        [ -z "$_dns" ] && _dns="$(printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8')"
    elif [ "$_gate_state" = "vpn_active" ]; then
        # Zero DNS leak: forward exclusively to home WireGuard gateway resolver inside wg_van
        _dns="nameserver ${WG_PEER_IP}"
    elif [ "$_gate_state" = "trusted_direct" ] || [ "$_gate_state" = "captive_temp" ]; then
        _dns="$(get_ubus_dns wan)"
        if [ -z "$_dns" ]; then
            if [ -n "$_cpe_gw" ]; then
                _dns="nameserver ${_cpe_gw}"
            else
                _dns="nameserver 1.1.1.1"
            fi
        fi
    else
        # Untrusted CPE locked: NEVER write _cpe_gw or public cleartext DNS for eth0
        _dns="nameserver ${WG_PEER_IP}"
    fi
    atomic_write_file "$RESOLV_FILE" "$_dns"
    killall -HUP dnsmasq 2>/dev/null || true
}

apply_active_route() {
    _mode="$1"
    _want="$2"
    _cpe_gw="$3"
    _sl_gw="$4"
    _gate_state="$5"
    [ "$DRY_RUN" = "1" ] && return 0

    if [ "$_mode" = "force_cpe" ]; then
        # Strict 0-byte Starlink guarantee: never leave any Starlink default route in main
        ip route del default dev "$SL_IFACE" 2>/dev/null || true
        if [ -n "$_cpe_gw" ]; then
            ip route replace default via "$_cpe_gw" dev "$CPE_IFACE" onlink metric 5 2>/dev/null || true
        else
            ip route del default dev "$CPE_IFACE" 2>/dev/null || true
        fi
    elif [ "$_mode" = "force_starlink" ]; then
        ip route del default dev "$CPE_IFACE" 2>/dev/null || true
        if [ -n "$_sl_gw" ]; then
            ip route replace default via "$_sl_gw" dev "$SL_IFACE" onlink metric 5 2>/dev/null || true
        else
            ip route del default dev "$SL_IFACE" 2>/dev/null || true
        fi
    elif [ "$_want" = "starlink" ]; then
        if [ -n "$_sl_gw" ]; then
            ip route replace default via "$_sl_gw" dev "$SL_IFACE" onlink metric 5 2>/dev/null || true
        else
            ip route del default dev "$SL_IFACE" 2>/dev/null || true
        fi
        if [ -n "$_cpe_gw" ]; then
            ip route replace default via "$_cpe_gw" dev "$CPE_IFACE" onlink metric 50 2>/dev/null || true
        else
            ip route del default dev "$CPE_IFACE" 2>/dev/null || true
        fi
    else
        if [ -n "$_cpe_gw" ]; then
            ip route replace default via "$_cpe_gw" dev "$CPE_IFACE" onlink metric 5 2>/dev/null || true
        else
            ip route del default dev "$CPE_IFACE" 2>/dev/null || true
        fi
        if [ "$_mode" = "captive_login" ]; then
            ip route del default dev "$SL_IFACE" 2>/dev/null || true
        elif [ -n "$_sl_gw" ]; then
            ip route replace default via "$_sl_gw" dev "$SL_IFACE" onlink metric 50 2>/dev/null || true
        else
            ip route del default dev "$SL_IFACE" 2>/dev/null || true
        fi
    fi

    sync_active_dns "$_want" "$_cpe_gw" "$_gate_state"
}

check_trusted_ssid() {
    _ssid="$1"
    [ -z "$_ssid" ] && return 1
    [ -f "${CONF_DIR}/known_networks.json" ] || return 1
    [ -f "${SCRIPT_DIR}/networks.lua" ] || return 1
    command -v lua >/dev/null 2>&1 || return 1
    lua "${SCRIPT_DIR}/networks.lua" is-trusted "${CONF_DIR}/known_networks.json" "$_ssid" >/dev/null 2>&1
}

poke_wg_iface() {
    _wgif="$1"
    _src_ip="$2"
    [ "$DRY_RUN" = "1" ] && return 0
    command -v wg >/dev/null 2>&1 || return 0
    ip link show "$_wgif" >/dev/null 2>&1 || return 0
    if [ -n "$WG_EP_HOST" ]; then
        _peer_pub="$(wg show "$_wgif" peers 2>/dev/null | head -n 1 || true)"
        _ep_ip=""
        if [ -n "$_src_ip" ]; then
            _ep_ip="$(resolve_doh_ipv4 "$WG_EP_HOST" "$_src_ip" || true)"
        fi
        if [ -z "$_ep_ip" ]; then
            _ep_ip="$(nslookup "$WG_EP_HOST" 2>/dev/null | awk '
                /^Name:/ { ok=1; next }
                ok && /^Address/ {
                    for (i=2; i<=NF; i++) {
                        if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { print $i; exit }
                    }
                }
            ' || true)"
        fi
        if [ -n "$_peer_pub" ] && [ -n "$_ep_ip" ]; then
            wg set "$_wgif" peer "$_peer_pub" endpoint "${_ep_ip}:${WG_EP_PORT}" 2>/dev/null || true
        fi
    fi
}

wg_handshake_stale() {
    command -v wg >/dev/null 2>&1 || return 1
    ip link show "$WG_IFACE" >/dev/null 2>&1 || return 1
    _hs="$(wg show "$WG_IFACE" latest-handshakes 2>/dev/null | awk 'NR==1 { print $2 }')"
    [ -z "$_hs" ] && return 0
    _now="$(date +%s)"
    _age=$((_now - _hs))
    [ "$_hs" -eq 0 ] || [ "$_age" -gt 150 ]
}

poke_wireguard() {
    _mgmt_ip="${1:-$WG_MGMT_IP}"
    _cpe_src="${2:-}"
    [ "$DRY_RUN" = "1" ] && return 0
    command -v wg >/dev/null 2>&1 || return 0
    ip link show "$WG_IFACE" >/dev/null 2>&1 || return 0
    if [ -n "$WG_EP_HOST" ]; then
        _peer_pub="$(wg show "$WG_IFACE" peers 2>/dev/null | head -n 1 || true)"
        _ep_ip=""
        if [ -n "$_cpe_src" ] && [ "$CUR_WAN" = "cpe" ]; then
            _ep_ip="$(resolve_doh_ipv4 "$WG_EP_HOST" "$_cpe_src" || true)"
        fi
        if [ -z "$_ep_ip" ]; then
            _ep_ip="$(nslookup "$WG_EP_HOST" 2>/dev/null | awk '
                /^Name:/ { ok=1; next }
                ok && /^Address/ {
                    for (i=2; i<=NF; i++) {
                        if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { print $i; exit }
                    }
                }
            ' || true)"
        fi
        if [ -n "$_peer_pub" ] && [ -n "$_ep_ip" ]; then
            wg set "$WG_IFACE" peer "$_peer_pub" endpoint "${_ep_ip}:${WG_EP_PORT}" 2>/dev/null || true
        fi
    fi
    if [ -n "$_mgmt_ip" ]; then
        ping -I "$_mgmt_ip" -c 1 -W 2 "$WG_PEER_IP" >/dev/null 2>&1 || true
    else
        ping -c 1 -W 2 "$WG_PEER_IP" >/dev/null 2>&1 || true
    fi
}

probe_cpe_http() {
    probe_cpe_http_eth0 "$1" "$CAPTIVE_URL"
}

hunter_is_running() {
    if [ -f "${STATE_DIR}/hunter.lock/pid" ]; then
        _hpid="$(cat "${STATE_DIR}/hunter.lock/pid" 2>/dev/null || true)"
        if [ -n "$_hpid" ] && kill -0 "$_hpid" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

evaluate_groove_trust() {
    # Fail-closed: NEVER trust cached SSID while wifi-hunter is switching APs
    if hunter_is_running; then
        return 1
    fi
    _g_reach="$(json_get_val "${STATE_DIR}/groove.json" "reachable" "false")"
    _g_stat="$(json_get_val "${STATE_DIR}/groove.json" "status" "")"
    _g_ssid="$(json_get_val "${STATE_DIR}/groove.json" "ssid" "")"
    [ "$_g_reach" = "true" ] || return 1
    case "$_g_stat" in
        connected-to-ess|connected) ;;
        *) return 1 ;;
    esac
    check_trusted_ssid "$_g_ssid"
}

run_tick() {
    _force_gate="${1:-0}"
    now="$(date +%s)"
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    consume_pending_reset

    # Read current mode (ephemeral captive_login override takes precedence over persisted mode.json)
    mode="$(json_get_val "${CONF_DIR}/mode.json" "mode" "auto")"
    mode_exp=0
    if [ -f "${STATE_DIR}/override.json" ]; then
        _ov_mode="$(json_get_val "${STATE_DIR}/override.json" "mode" "")"
        _ov_exp="$(json_get_val "${STATE_DIR}/override.json" "expires_at" "0")"
        if [ "$_ov_mode" = "captive_login" ]; then
            mode="captive_login"
            mode_exp="$_ov_exp"
        fi
    fi

    cpe_carrier="$(get_iface_carrier "$CPE_IFACE")"
    sl_carrier="$(get_iface_carrier "$SL_IFACE")"
    cpe_ip="$(get_iface_ip "$CPE_IFACE")"
    sl_ip="$(get_iface_ip "$SL_IFACE")"
    cpe_gw="$(get_table_gw "$CPE_TABLE")"
    sl_gw="$(get_table_gw "$SL_TABLE")"

    cpe_link=0
    [ "$cpe_carrier" = "1" ] && [ -n "$cpe_ip" ] && [ -n "$cpe_gw" ] && cpe_link=1
    sl_link=0
    [ "$sl_carrier" = "1" ] && [ -n "$sl_ip" ] && [ -n "$sl_gw" ] && sl_link=1

    ensure_policy_rule "$cpe_ip" "$CPE_TABLE"
    ensure_policy_rule "$sl_ip" "$SL_TABLE"
    ensure_mgmt_dest_rules

    # Probe CPE strictly via eth0 source IP (table 101) using configured ping_targets
    cpe_loss=100
    cpe_rtt=9999
    cpe_http=000
    if [ "$cpe_link" = "1" ]; then
        _ptargets="$(awk '
            BEGIN { in_pt = 0; buf = "" }
            /"ping_targets"[[:space:]]*:/ {
                in_pt = 1
                line = $0
                sub(/^.*"ping_targets"[[:space:]]*:[[:space:]]*\[?/, "", line)
                if (index(line, "]") > 0) {
                    sub(/\].*$/, "", line)
                    buf = buf " " line
                    in_pt = 0
                    exit
                }
                buf = buf " " line
                next
            }
            in_pt {
                line = $0
                if (index(line, "]") > 0) {
                    sub(/\].*$/, "", line)
                    buf = buf " " line
                    in_pt = 0
                    exit
                }
                buf = buf " " line
            }
            END {
                gsub(/"|\[|\]|,/, " ", buf)
                gsub(/[[:space:]]+/, " ", buf)
                sub(/^ /, "", buf)
                sub(/ $/, "", buf)
                print buf
            }
        ' "$CFG" 2>/dev/null || true)"
        [ -z "$_ptargets" ] && _ptargets="1.1.1.1 8.8.8.8"
        for _pt in $_ptargets; do
            _ping_out="$(ping -I "$cpe_ip" -c "$PING_COUNT" -W 2 "$_pt" 2>/dev/null || true)"
            _stats="$(printf '%s\n' "$_ping_out" | parse_ping_stats)"
            cpe_loss="${_stats%% *}"
            cpe_rtt="${_stats#* }"
            if [ "$cpe_loss" -lt 100 ]; then
                break
            fi
        done
        cpe_http="$(probe_cpe_http "$cpe_ip")"
    fi

    cpe_base_health="$(classify_cpe_health "$cpe_link" "$cpe_loss" "$cpe_rtt" "$cpe_http" "$MAX_LOSS" "$MAX_RTT")"
    captive_flag="false"
    [ "$cpe_base_health" = "captive" ] && captive_flag="true"

    # Determine Groove SSID trust status & run Gate 3 (wg_van over eth0) before routing untrusted CPE
    groove_json='{"reachable":false}'
    if [ -s "${STATE_DIR}/groove.json" ]; then
        groove_json="$(cat "${STATE_DIR}/groove.json")"
    fi
    is_trusted=0
    if evaluate_groove_trust; then
        # Always confirm fresh CPE association before entering OR keeping trusted_direct (prevents stale cache trust)
        if [ "$SKIP_GROOVE" != "1" ] && [ "$DRY_RUN" != "1" ] && [ -x "${SCRIPT_DIR}/groove-poll.sh" ]; then
            if [ $((now - LAST_GROOVE_POLL)) -ge 15 ] || [ "${LAST_GATE_SIG%%|*}" != "trusted_direct" ]; then
                LAST_GROOVE_POLL="$now"
                "${SCRIPT_DIR}/groove-poll.sh" >/dev/null 2>&1 || true
                [ -s "${STATE_DIR}/groove.json" ] && groove_json="$(cat "${STATE_DIR}/groove.json")"
            fi
        fi
        if evaluate_groove_trust; then
            is_trusted=1
        fi
    fi

    wg_van_live_ip="$(get_iface_ip "$WG_VAN_IFACE")"
    [ -z "$wg_van_live_ip" ] && wg_van_live_ip="$WG_VAN_IP"
    wg_mgmt_live_ip="$(get_iface_ip "$WG_IFACE")"
    [ -z "$wg_mgmt_live_ip" ] && wg_mgmt_live_ip="$WG_MGMT_IP"

    # Heal table 104 (wg_mgmt) and table 103 (wg_van) routes on every tick after netifd bounces
    if [ "$DRY_RUN" != "1" ]; then
        ensure_wg_routes "$WG_VAN_IFACE" "$wg_van_live_ip" "$WG_IFACE" "$wg_mgmt_live_ip"
    fi

    wg_van_ok=0
    if [ "$REQUIRE_VPN" = "1" ] && [ "$is_trusted" = "0" ] && [ "$cpe_base_health" = "healthy" ]; then
        # Ensure base fwmark 0x101 + source rules exist BEFORE probing wg_van
        if [ "$DRY_RUN" != "1" ]; then
            _ensure_base_vpn_hooks "$CPE_IFACE" "$WG_VAN_IFACE" "$wg_van_live_ip" "$WG_IFACE" "$wg_mgmt_live_ip"
            poke_wg_iface "$WG_VAN_IFACE" "$cpe_ip"
        fi
        if probe_wg_van "$WG_VAN_IFACE" "$wg_van_live_ip" "$WG_PEER_IP" 150; then
            wg_van_ok=1
        fi
    fi

    if [ "$REQUIRE_VPN" = "1" ]; then
        cpe_health="$(classify_cpe_with_vpn "$cpe_base_health" "$is_trusted" "$wg_van_ok")"
    else
        cpe_health="$cpe_base_health"
    fi

    _next="$(decide_next_state "$mode" "$mode_exp" "$now" "$CUR_WAN" "$cpe_health" "$sl_link" "$FAIL_STRIKES" "$OK_STRIKES" "$MAX_FAIL" "$MAX_OK")"
    set -- $_next
    new_mode="$1"
    new_wan="$2"
    FAIL_STRIKES="$3"
    OK_STRIKES="$4"

    if [ "$mode" = "captive_login" ] && [ "$new_mode" = "auto" ]; then
        rm -f "${STATE_DIR}/override.json"
        atomic_write_file "${CONF_DIR}/mode.json" '{"mode":"auto"}'
        mode_exp=0
    fi
    mode="$new_mode"

    wan_changed=0
    if [ "$new_wan" != "$CUR_WAN" ]; then
        CUR_WAN="$new_wan"
        wan_changed=1
    fi

    # Choose fail-closed VPN gate state
    gate_state="locked"
    vpn_state_label="killswitch_locked"
    if [ "$mode" = "captive_login" ]; then
        gate_state="captive_temp"
        vpn_state_label="captive_temp"
    elif [ "$CUR_WAN" = "cpe" ]; then
        if [ "$is_trusted" = "1" ] && [ "$cpe_health" = "healthy_trusted" ]; then
            gate_state="trusted_direct"
            vpn_state_label="trusted_direct"
        elif [ "$REQUIRE_VPN" = "0" ] && [ "$cpe_health" = "healthy" ]; then
            gate_state="trusted_direct"
            vpn_state_label="trusted_direct"
        elif [ "$cpe_health" = "healthy_vpn" ] && [ "$wg_van_ok" = "1" ]; then
            gate_state="vpn_active"
            vpn_state_label="encrypted"
        else
            gate_state="locked"
            vpn_state_label="killswitch_locked"
        fi
    fi

    if [ "$DRY_RUN" != "1" ]; then
        gate_sig="${gate_state}|${wg_van_live_ip}|${wg_mgmt_live_ip}"
        if [ "$gate_sig" != "$LAST_GATE_SIG" ] || [ "$_force_gate" = "1" ]; then
            apply_vpn_gate "$gate_state" "$CPE_IFACE" "$WG_VAN_IFACE" "$wg_van_live_ip" "$WG_IFACE" "$wg_mgmt_live_ip"
            LAST_GATE_SIG="$gate_sig"
        fi
    fi

    route_sig="${mode}|${CUR_WAN}|${cpe_gw}|${sl_gw}|${gate_state}"
    if [ "$route_sig" != "$LAST_ROUTE_SIG" ]; then
        apply_active_route "$mode" "$CUR_WAN" "$cpe_gw" "$sl_gw" "$gate_state"
        LAST_ROUTE_SIG="$route_sig"
    fi

    if [ "$wan_changed" = "1" ] || wg_handshake_stale; then
        poke_wireguard "$wg_mgmt_live_ip" "$cpe_ip"
    fi

    # Update Starlink monthly usage counter
    consume_pending_reset
    cycle_key="$(compute_cycle_key "$(date +%Y)" "$(date +%m)" "$(date +%d)" "$RESET_DAY")"
    rx_b="$(cat "${SYS_NET}/${SL_IFACE}/statistics/rx_bytes" 2>/dev/null || echo 0)"
    tx_b="$(cat "${SYS_NET}/${SL_IFACE}/statistics/tx_bytes" 2>/dev/null || echo 0)"
    curr_if_bytes="$(awk -v r="$rx_b" -v t="$tx_b" 'BEGIN { r+=0; t+=0; printf "%.0f\n", r + t }')"
    if [ -z "$STORED_CYCLE" ]; then
        STORED_CYCLE="$cycle_key"
        LAST_IF_BYTES="$curr_if_bytes"
        TOTAL_BYTES=0
        flush_usage_to_flash
    else
        _u="$(update_usage_bytes "$cycle_key" "$STORED_CYCLE" "$LAST_IF_BYTES" "$TOTAL_BYTES" "$curr_if_bytes")"
        set -- $_u
        STORED_CYCLE="$1"
        LAST_IF_BYTES="$2"
        TOTAL_BYTES="$3"
        _delta_flush="$(awk -v a="$TOTAL_BYTES" -v b="$LAST_FLUSHED_TOTAL" 'BEGIN { a+=0; b+=0; d=a-b; if (d<0) d=-d; printf "%.0f\n", d }')"
        if [ "$_delta_flush" != "0" ]; then
            if [ $((now - LAST_USAGE_FLUSH)) -ge 300 ] || [ "$(awk -v d="$_delta_flush" 'BEGIN { d+=0; print (d >= 26214400) ? 1 : 0 }')" = "1" ]; then
                flush_usage_to_flash
            fi
        fi
    fi

    monthly_gb="$(awk -v b="$TOTAL_BYTES" 'BEGIN { b+=0; printf "%.2f\n", b / 1073741824.0 }')"
    pct_used="$(awk -v g="$monthly_gb" -v cap="$CAP_GB" 'BEGIN { g+=0; cap+=0; if (cap<=0) print "0.0"; else printf "%.1f\n", (g / cap) * 100.0 }')"

    # Spawn non-blocking Groove telemetry poll every 30s
    if [ "$SKIP_GROOVE" != "1" ] && [ $((now - LAST_GROOVE_POLL)) -ge 30 ]; then
        LAST_GROOVE_POLL="$now"
        "${SCRIPT_DIR}/groove-poll.sh" >/dev/null 2>&1 &
    fi
    if [ -s "${STATE_DIR}/groove.json" ]; then
        groove_json="$(cat "${STATE_DIR}/groove.json")"
    fi

    # Track CPE unhealthy strikes independently of mode so auto-hunt works in BOTH auto and force_cpe
    case "$cpe_health" in
        healthy|healthy_vpn|healthy_trusted)
            CPE_UNHEALTHY_STRIKES=0
            ;;
        *)
            CPE_UNHEALTHY_STRIKES=$((CPE_UNHEALTHY_STRIKES + 1))
            ;;
    esac

    # Optional autonomous Wi-Fi hunter trigger when CPE unhealthy/vpn_blocked for >= 2 strikes (rate-limited 90s)
    if [ "$SKIP_GROOVE" != "1" ] && [ "$DRY_RUN" != "1" ] && [ -x "${SCRIPT_DIR}/wifi-hunter.sh" ]; then
        if [ "$mode" = "auto" ] || [ "$mode" = "force_cpe" ]; then
            case "$cpe_health" in
                down|vpn_blocked|degraded)
                    if [ "$CPE_UNHEALTHY_STRIKES" -ge 2 ] && [ $((now - LAST_HUNT_ATTEMPT)) -ge 90 ]; then
                        LAST_HUNT_ATTEMPT="$now"
                        "${SCRIPT_DIR}/wifi-hunter.sh" auto >/dev/null 2>&1 &
                    fi
                    ;;
            esac
        fi
    fi

    hunter_json='{"hunting":false}'
    if [ -s "${STATE_DIR}/hunter_state.json" ]; then
        hunter_json="$(cat "${STATE_DIR}/hunter_state.json")"
    fi

    cpe_link_json="false"; [ "$cpe_link" = "1" ] && cpe_link_json="true"
    sl_link_json="false"; [ "$sl_link" = "1" ] && sl_link_json="true"
    wg_van_up_json="false"; [ "$wg_van_ok" = "1" ] && wg_van_up_json="true"
    trusted_json="false"; [ "$is_trusted" = "1" ] && trusted_json="true"

    status_json="$(printf '{
  "updated_at": "%s",
  "mode": "%s",
  "mode_expires_at": %d,
  "active_wan": "%s",
  "fail_strikes": %d,
  "ok_strikes": %d,
  "vpn": {
    "state": "%s",
    "wg_van_up": %s,
    "wg_van_ip": "%s",
    "trusted_ssid": %s,
    "require_vpn_untrusted": %s
  },
  "cpe": {
    "iface": "%s",
    "link_up": %s,
    "ip": "%s",
    "gw": "%s",
    "loss_pct": %d,
    "rtt_ms": %d,
    "http_code": %d,
    "captive_detected": %s,
    "health": "%s"
  },
  "starlink": {
    "iface": "%s",
    "link_up": %s,
    "ip": "%s",
    "gw": "%s",
    "cycle_key": "%s",
    "monthly_bytes": %s,
    "monthly_gb": %s,
    "cap_gb": %s,
    "pct_used": %s
  },
  "groove": %s,
  "hunter": %s
}' \
        "$ts" "$mode" "$mode_exp" "$CUR_WAN" "$FAIL_STRIKES" "$OK_STRIKES" \
        "$vpn_state_label" "$wg_van_up_json" "$(json_escape "$wg_van_live_ip")" "$trusted_json" "$([ "$REQUIRE_VPN" = "1" ] && echo true || echo false)" \
        "$CPE_IFACE" "$cpe_link_json" "$(json_escape "$cpe_ip")" "$(json_escape "$cpe_gw")" \
        "$cpe_loss" "$cpe_rtt" "$cpe_http" "$captive_flag" "$cpe_health" \
        "$SL_IFACE" "$sl_link_json" "$(json_escape "$sl_ip")" "$(json_escape "$sl_gw")" \
        "$STORED_CYCLE" "$TOTAL_BYTES" "$monthly_gb" "$CAP_GB" "$pct_used" \
        "$groove_json" "$hunter_json")"

    atomic_write_file "${STATE_DIR}/status.json" "$status_json"
}

if [ "${1:-}" = "--once" ]; then
    run_tick
    exit 0
fi

printf '%d\n' "$$" > "${STATE_DIR}/daemon.pid"
while [ "$STOP_REQ" = "0" ]; do
    _woken="$WAKE_REQ"
    WAKE_REQ=0
    run_tick "$_woken" || true
    _slept=0
    while [ "$_slept" -lt "$INTERVAL" ] && [ "$STOP_REQ" = "0" ] && [ "$WAKE_REQ" = "0" ]; do
        sleep 1
        _slept=$((_slept + 1))
    done
done

flush_usage_to_flash
rm -f "${STATE_DIR}/daemon.pid"
