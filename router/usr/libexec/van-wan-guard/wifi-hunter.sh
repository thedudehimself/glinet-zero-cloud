#!/bin/sh
# Autonomous & manual MikroTik GrooveA-52 Wi-Fi hunter with fail-closed Gate 3 (wg_van) verification.
set -eu

export HOME="${HOME:-/root}"
CONF_DIR="${VAN_CONF_DIR:-/etc/van-wan-guard}"
STATE_DIR="${VAN_STATE_DIR:-/var/run/van-wan-guard}"
SCRIPT_DIR="$(dirname "$0")"
# shellcheck source=lib.sh
. "${SCRIPT_DIR}/lib.sh"
# shellcheck source=vpn-gate.sh
. "${SCRIPT_DIR}/vpn-gate.sh"

mkdir -p "$CONF_DIR" "$STATE_DIR"
CFG="${CONF_DIR}/config.json"
KNOWN_FILE="${CONF_DIR}/known_networks.json"
HUNTER_STATE="${STATE_DIR}/hunter_state.json"
NET_LUA="${SCRIPT_DIR}/networks.lua"
LOCK_DIR="${STATE_DIR}/hunter.lock"

GROOVE_IP="$(json_get_val "$CFG" "groove_ip" "192.168.88.1")"
GROOVE_USER="$(json_get_val "$CFG" "groove_user" "hunter")"
GROOVE_KEY="$(json_get_val "$CFG" "groove_key" "${CONF_DIR}/groove_dropbear.key")"
if [ ! -f "$GROOVE_KEY" ] && [ -f "${CONF_DIR}/groove_dropbear.key" ]; then
    GROOVE_KEY="${CONF_DIR}/groove_dropbear.key"
fi
CPE_IFACE="$(json_get_val "$CFG" "cpe_iface" "eth0")"
CPE_TABLE="$(json_get_val "$CFG" "cpe_table" "101")"
CAPTIVE_URL="$(json_get_val "$CFG" "captive_url" "http://connectivitycheck.gstatic.com/generate_204")"
WG_VAN_IFACE="$(json_get_val "$CFG" "wg_van_iface" "wg_van")"
WG_VAN_IP="$(json_get_val "$CFG" "wg_van_ip" "192.168.2.6")"
WG_MGMT_IFACE="$(json_get_val "$CFG" "wg_iface" "wg_mgmt")"
WG_MGMT_IP="$(json_get_val "$CFG" "wg_mgmt_ip" "192.168.2.5")"
WG_PEER_IP="$(json_get_val "$CFG" "wg_peer_ip" "192.168.2.1")"
WG_EP_HOST="$(json_get_val "$CFG" "wg_endpoint_host" "")"
WG_EP_PORT="$(json_get_val "$CFG" "wg_endpoint_port" "51820")"
WAIT_DHCP_SEC="${VAN_HUNTER_WAIT_DHCP_SEC:-15}"
WAIT_VPN_SEC="${VAN_HUNTER_WAIT_VPN_SEC:-12}"

acquire_lock() {
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        printf '%d\n' "$$" > "${LOCK_DIR}/pid"
        return 0
    fi
    _old_pid="$(cat "${LOCK_DIR}/pid" 2>/dev/null || true)"
    if [ -n "$_old_pid" ] && kill -0 "$_old_pid" 2>/dev/null; then
        return 1
    fi
    rm -rf "$LOCK_DIR" 2>/dev/null || true
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        printf '%d\n' "$$" > "${LOCK_DIR}/pid"
        return 0
    fi
    return 1
}

ACTIVE_RSC="${STATE_DIR}/van_hunter.$$.rsc"

cleanup() {
    # Always remove parent-scoped temp .rsc even when associate_and_verify ran inside $(...) subshell
    rm -f "${STATE_DIR}/van_hunter.$$.rsc" 2>/dev/null || true
    if [ -n "$ACTIVE_RSC" ]; then
        rm -f "$ACTIVE_RSC" 2>/dev/null || true
    fi
    rm -rf "$LOCK_DIR" 2>/dev/null || true
}

release_lock() {
    cleanup
}

signal_daemon() {
    if [ -f "${STATE_DIR}/daemon.pid" ]; then
        _pid="$(cat "${STATE_DIR}/daemon.pid" 2>/dev/null || true)"
        if [ -n "$_pid" ] && kill -0 "$_pid" 2>/dev/null; then
            kill -USR1 "$_pid" 2>/dev/null || true
        fi
    fi
}

update_hunter_state() {
    _patch="$1"
    printf '%s\n' "$_patch" | lua "$NET_LUA" update-state "$HUNTER_STATE" >/dev/null 2>&1 || true
}

run_groove_ssh() {
    _rcmd="$1"
    _tmo="${2:-12}"
    [ -f "$GROOVE_KEY" ] || return 1
    if [ -x /usr/libexec/ssh-openssh ] && [ -x "${SCRIPT_DIR}/groove-ssh.sh" ]; then
        timeout "$_tmo" "${SCRIPT_DIR}/groove-ssh.sh" -i "$GROOVE_KEY" "${GROOVE_USER}@${GROOVE_IP}" "$_rcmd" </dev/null 2>/dev/null
    else
        timeout "$_tmo" dbclient -y -i "$GROOVE_KEY" "${GROOVE_USER}@${GROOVE_IP}" "$_rcmd" </dev/null 2>/dev/null
    fi
}

# Upload PSK connect command via 0600 temp .rsc + scp so plaintext PSK NEVER appears in dbclient argv.
# SECURITY: Never fall back to dbclient argv when a PSK is present!
run_groove_connect_cmd() {
    _rcmd="$1"
    case "$_rcmd" in
        *wpa2-pre-shared-key*|*passphrase*)
            if ! command -v scp >/dev/null 2>&1 || [ ! -x "${SCRIPT_DIR}/groove-ssh.sh" ]; then
                return 1
            fi
            ACTIVE_RSC="${STATE_DIR}/van_hunter.$$.rsc"
            trap 'rm -f "${STATE_DIR}/van_hunter.$$.rsc" "$ACTIVE_RSC" 2>/dev/null || true' EXIT
            trap 'rm -f "${STATE_DIR}/van_hunter.$$.rsc" "$ACTIVE_RSC" 2>/dev/null || true; exit 143' INT TERM
            (umask 077 && printf '%s\n' "$_rcmd" > "$ACTIVE_RSC")
            _ok=0
            if timeout 10 scp -S "${SCRIPT_DIR}/groove-ssh.sh" -i "$GROOVE_KEY" "$ACTIVE_RSC" "${GROOVE_USER}@${GROOVE_IP}:van_hunter.rsc" >/dev/null 2>&1; then
                if run_groove_ssh '/import file-name=van_hunter.rsc; /file remove [find name="van_hunter.rsc"]' 12 >/dev/null; then
                    _ok=1
                else
                    run_groove_ssh '/file remove [find name="van_hunter.rsc"]' 6 >/dev/null || true
                fi
            fi
            rm -f "$ACTIVE_RSC"
            [ "$_ok" = "1" ] && return 0
            return 1
            ;;
    esac
    run_groove_ssh "$_rcmd" 10 >/dev/null
}

scan_groove_raw() {
    # Dual-band RouterOS v6 sweep in 2 batched SSH sessions (avoids saturating 600 MHz MIPS CPE):
    # 1) Read active band + non-disruptive background scan on current band.
    # 2) Switch to opposite band (2.4 GHz <-> 5 GHz), scan, and restore original band cleanly.
    _out1="$(run_groove_ssh ':local ob [/interface wireless get [find default-name=wlan1] band]; :put ("ORIGBAND=" . $ob); /interface wireless scan wlan1 duration=4 background=yes save-file=van_scan1.txt; :put [/file get van_scan1.txt contents]; /file remove [find name="van_scan1.txt"]' 18 || true)"
    _orig_band="$(printf '%s\n' "$_out1" | awk -F= '/^ORIGBAND=/ { gsub(/\r/, "", $2); print $2; exit }')"
    _out2=""
    case "$_orig_band" in
        2ghz*)
            _out2="$(run_groove_ssh ":if ([/interface wireless get [find default-name=wlan1] interface-type] ~ \"AR9300\") do={ /interface wireless set [find default-name=wlan1] band=5ghz-a/n channel-width=20/40mhz-XX } else={ :do { /interface wireless set [find default-name=wlan1] band=5ghz-a/n/ac channel-width=20/40/80mhz-XXXX } on-error={ /interface wireless set [find default-name=wlan1] band=5ghz-a/n channel-width=20/40mhz-XX } }; /interface wireless scan wlan1 duration=6 background=no save-file=van_scan2.txt; :put [/file get van_scan2.txt contents]; /file remove [find name=\"van_scan2.txt\"]; /interface wireless set [find default-name=wlan1] band=${_orig_band} channel-width=20/40mhz-XX" 22 || true)"
            ;;
        5ghz*)
            _out2="$(run_groove_ssh "/interface wireless set [find default-name=wlan1] band=2ghz-b/g/n channel-width=20/40mhz-XX; /interface wireless scan wlan1 duration=5 background=no save-file=van_scan2.txt; :put [/file get van_scan2.txt contents]; /file remove [find name=\"van_scan2.txt\"]; :do { /interface wireless set [find default-name=wlan1] band=${_orig_band} } on-error={ /interface wireless set [find default-name=wlan1] band=5ghz-a/n }" 22 || true)"
            ;;
    esac
    _out="${_out1}
${_out2}"
    if ! printf '%s\n' "$_out" | grep -qE '[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}'; then
        _out="$(run_groove_ssh '/interface wireless scan wlan1 duration=5 background=no' 14 || true)"
    fi
    if ! printf '%s\n' "$_out" | grep -qE '[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}'; then
        _out="$(run_groove_ssh '/interface wifi scan wifi1 duration=5' 14 || true)"
    fi
    printf '%s\n' "$_out"
}

get_iface_ip() {
    ip -4 addr show dev "$1" 2>/dev/null | awk '/inet / { sub(/\/.*/, "", $2); print $2; exit }'
}

get_table_gw() {
    ip route show table "$1" 2>/dev/null | awk '/^default / { for (i=1;i<=NF;i++) if ($i=="via") { print $(i+1); exit } }'
}

ensure_cpe_policy_rule() {
    _ip="$1"
    [ -z "$_ip" ] && return 0
    if ! ip rule show 2>/dev/null | grep -q "^${CPE_TABLE}:.*from ${_ip} lookup ${CPE_TABLE}"; then
        ip rule del prio "$CPE_TABLE" 2>/dev/null || true
        ip rule add from "${_ip}/32" table "$CPE_TABLE" prio "$CPE_TABLE" 2>/dev/null || true
    fi
}

probe_http_code() {
    probe_cpe_http_eth0 "$1" "$CAPTIVE_URL"
}

extract_candidates_tsv() {
    _json="$1"
    _tsv="$(printf '%s\n' "$_json" | lua "$NET_LUA" candidates-tsv 2>/dev/null || true)"
    if [ -n "$_tsv" ]; then
        printf '%s\n' "$_tsv"
        return 0
    fi
    printf '%s\n' "$_json" | awk '
        BEGIN { RS="}" }
        {
            b=""; s=""; t="0"
            if (match($0, /"bssid"[[:space:]]*:[[:space:]]*"[^"]*"/)) {
                b = substr($0, RSTART, RLENGTH)
                sub(/^"bssid"[[:space:]]*:[[:space:]]*"/, "", b); sub(/"$/, "", b)
            }
            if (match($0, /"ssid"[[:space:]]*:[[:space:]]*"[^"]*"/)) {
                s = substr($0, RSTART, RLENGTH)
                sub(/^"ssid"[[:space:]]*:[[:space:]]*"/, "", s); sub(/"$/, "", s)
            }
            if ($0 ~ /"trusted"[[:space:]]*:[[:space:]]*true/) t="1"
            if (b != "" && s != "") printf "%s\t%s\t%s\n", b, t, s
        }
    '
}

associate_and_verify() {
    _ssid="$1"
    _bssid="${2:-}"
    _band="${3:-}"
    if [ -z "$_band" ] && [ -f "$HUNTER_STATE" ]; then
        _band="$(lua "$NET_LUA" lookup-band "$HUNTER_STATE" "$_ssid" "$_bssid" 2>/dev/null | tr -d '\r\n' || true)"
    fi

    # Critical fail-closed: clear any active captive_login override, lock VAN_CPE_GATE,
    # invalidate cached groove.json, and wake daemon.sh BEFORE switching APs
    rm -f "${STATE_DIR}/override.json"
    apply_vpn_gate "locked" "$CPE_IFACE" "$WG_VAN_IFACE" "$WG_VAN_IP" "$WG_MGMT_IFACE" "$WG_MGMT_IP"
    atomic_write_file "${STATE_DIR}/groove.json" '{"reachable":false,"status":"associating","ssid":""}'
    signal_daemon

    _ros_cmd="$(lua "$NET_LUA" ros-connect-cmd "$KNOWN_FILE" "$_ssid" "$_bssid" "$_band" 2>/dev/null || true)"
    if [ -z "$_ros_cmd" ]; then
        printf 'invalid_target\n'
        return 1
    fi
    if ! run_groove_connect_cmd "$_ros_cmd"; then
        printf 'groove_ssh_failed\n'
        return 1
    fi

    # Wait up to WAIT_DHCP_SEC (wall-clock) for eth0 IP + gateway AND non-000 HTTP response
    # (handles Groove NAT mode where eth0 already has an IP before wlan1 finishes associating)
    _deadline=$(( $(date +%s) + WAIT_DHCP_SEC ))
    _cpe_ip=""
    _cpe_gw=""
    _http="000"
    while [ "$(date +%s)" -lt "$_deadline" ]; do
        _cpe_ip="$(get_iface_ip "$CPE_IFACE")"
        _cpe_gw="$(get_table_gw "$CPE_TABLE")"
        if [ -n "$_cpe_ip" ] && [ -n "$_cpe_gw" ]; then
            ensure_cpe_policy_rule "$_cpe_ip"
            _http="$(probe_http_code "$_cpe_ip")"
            if [ "$_http" != "000" ]; then
                break
            fi
        fi
        sleep 1
    done

    if [ -z "$_cpe_ip" ] || [ -z "$_cpe_gw" ]; then
        printf 'dhcp_timeout\n'
        return 1
    fi
    if [ "$_http" = "000" ]; then
        printf 'no_internet\n'
        return 1
    fi

    # Refresh groove.json synchronously so daemon.sh sees true connected SSID/status immediately
    if [ -x "${SCRIPT_DIR}/groove-poll.sh" ]; then
        "${SCRIPT_DIR}/groove-poll.sh" >/dev/null 2>&1 || true
    fi

    if [ "$_http" != "204" ]; then
        printf 'captive_portal\n'
        return 2
    fi

    # Trusted WPA2/WPA3 bypass check
    if lua "$NET_LUA" is-trusted "$KNOWN_FILE" "$_ssid" >/dev/null 2>&1; then
        printf 'trusted_ok\n'
        return 0
    fi

    # Untrusted / open AP: MUST pass Gate 3 (wg_van over eth0) BEFORE signaling success
    if [ -n "$WG_EP_HOST" ] && command -v wg >/dev/null 2>&1; then
        _peer_pub="$(wg show "$WG_VAN_IFACE" peers 2>/dev/null | head -n 1 || true)"
        _ep_ip="$(resolve_doh_ipv4 "$WG_EP_HOST" "$_cpe_ip" || true)"
        if [ -n "$_peer_pub" ] && [ -n "$_ep_ip" ]; then
            wg set "$WG_VAN_IFACE" peer "$_peer_pub" endpoint "${_ep_ip}:${WG_EP_PORT}" 2>/dev/null || true
        fi
    fi

    _vpn_deadline=$(( $(date +%s) + WAIT_VPN_SEC ))
    while [ "$(date +%s)" -lt "$_vpn_deadline" ]; do
        if probe_wg_van "$WG_VAN_IFACE" "$WG_VAN_IP" "$WG_PEER_IP" 150; then
            printf 'vpn_ok\n'
            return 0
        fi
        sleep 2
    done

    printf 'vpn_blocked\n'
    return 3
}

# Quick 4-second stability + throughput probe over the verified link:
# For trusted_ok, probes via eth0 source IP; for vpn_ok, probes strictly via wg_van (zero cleartext leak).
# Outputs: "<loss_pct> <rtt_ms> <mbps>"
benchmark_active_link() {
    _res="$1"
    if [ "$_res" = "vpn_ok" ]; then
        _src="$WG_VAN_IFACE"
        _ping_dst="$WG_PEER_IP"
    else
        _src="$(get_iface_ip "$CPE_IFACE")"
        _ping_dst="1.1.1.1"
    fi
    if [ -z "$_src" ]; then
        printf '100 9999 0.0\n'
        return 0
    fi
    _pout="$(ping -I "$_src" -c 4 -W 1 "$_ping_dst" 2>/dev/null || true)"
    _pstats="$(printf '%s\n' "$_pout" | parse_ping_stats)"
    _loss="${_pstats%% *}"
    _rtt="${_pstats#* }"
    _cf_ip="$(resolve_doh_ipv4 "speed.cloudflare.com" "$_src" 2>/dev/null || true)"
    if [ -n "$_cf_ip" ]; then
        _bps="$(curl -4 --interface "$_src" --connect-timeout 2 --max-time 4 -sS \
            --resolve "speed.cloudflare.com:443:${_cf_ip}" \
            -o /dev/null -w '%{speed_download}' \
            "https://speed.cloudflare.com/__down?bytes=1500000" 2>/dev/null || echo 0)"
    else
        _bps="$(curl -4 --interface "$_src" --connect-timeout 2 --max-time 4 -sS \
            -o /dev/null -w '%{speed_download}' \
            "https://speed.cloudflare.com/__down?bytes=1500000" 2>/dev/null || echo 0)"
    fi
    _mbps="$(awk -v b="${_bps:-0}" 'BEGIN { b += 0; if (b < 0) b = 0; printf "%.1f", (b * 8) / 1000000 }')"
    printf '%d %d %s\n' "$_loss" "$_rtt" "$_mbps"
}

score_benchmark() {
    _tier="$1"
    _loss="$2"
    _rtt="$3"
    _mbps="$4"
    _rssi="$5"
    awk -v t="$_tier" -v l="$_loss" -v r="$_rtt" -v m="$_mbps" -v s="$_rssi" 'BEGIN {
        bonus = (t == 1) ? 1000 : ((t == 2) ? 500 : 0);
        sc = bonus + (m * 10) - (l * 8) - (r / 4) + ((s + 100) / 5);
        printf "%d", sc;
    }'
}

cmd="${1:-scan}"

if ! acquire_lock; then
    printf '{"ok":false,"error":"busy"}\n'
    exit 3
fi
trap 'release_lock' EXIT
trap 'release_lock; exit 130' INT
trap 'release_lock; exit 143' TERM

if [ ! -f "$GROOVE_KEY" ]; then
    printf '{"ok":false,"error":"groove ssh key not enrolled"}\n'
    exit 1
fi

case "$cmd" in
    scan)
        now="$(date +%s)"
        update_hunter_state "{\"hunting\":true,\"last_action\":\"scanning\"}"
        raw="$(scan_groove_raw)"
        ranked="$(printf '%s\n' "$raw" | lua "$NET_LUA" rank-scan "$KNOWN_FILE" "$HUNTER_STATE" "$now" --include-cooled 2>/dev/null || echo '[]')"
        [ -z "$ranked" ] && ranked='[]'
        update_hunter_state "{\"hunting\":false,\"last_scan_at\":${now},\"last_action\":\"scan_complete\",\"last_candidates\":${ranked}}"
        printf '{"ok":true,"scanned_at":%d,"candidates":%s}\n' "$now" "$ranked"
        ;;
    connect)
        ssid="${2:-}"
        bssid="${3:-}"
        band="${4:-}"
        if [ -z "$ssid" ]; then
            printf '{"ok":false,"error":"missing ssid"}\n'
            exit 2
        fi
        update_hunter_state "{\"hunting\":true,\"last_action\":\"connecting\"}"
        res_code=0
        reason="$(associate_and_verify "$ssid" "$bssid" "$band")" || res_code=$?
        now="$(date +%s)"
        cd_sec="$(lua "$NET_LUA" get-config "$KNOWN_FILE" cooldown_sec 7200 2>/dev/null || echo 7200)"
        if [ "$res_code" -eq 0 ]; then
            vpn_ver="false"
            [ "$reason" = "vpn_ok" ] && vpn_ver="true"
            update_hunter_state "{\"hunting\":false,\"last_action\":\"connected:${reason}\"}"
            signal_daemon
            printf '{"ok":true,"ssid":"%s","bssid":"%s","result":"%s","vpn_verified":%s}\n' \
                "$(json_escape "$ssid")" "$(json_escape "$bssid")" "$reason" "$vpn_ver"
        elif [ "$res_code" -eq 2 ]; then
            update_hunter_state "{\"hunting\":false,\"last_action\":\"captive_available\",\"captive_available\":\"$(json_escape "$ssid")\"}"
            signal_daemon
            printf '{"ok":true,"ssid":"%s","bssid":"%s","result":"captive_portal","vpn_verified":false,"captive_required":true}\n' \
                "$(json_escape "$ssid")" "$(json_escape "$bssid")"
        else
            if [ -n "$bssid" ]; then
                lua "$NET_LUA" cooldown "$HUNTER_STATE" "$bssid" "$reason" "$((now + cd_sec))" >/dev/null 2>&1 || true
            fi
            update_hunter_state "{\"hunting\":false,\"last_action\":\"failed:${reason}\"}"
            printf '{"ok":false,"error":"%s","ssid":"%s","bssid":"%s","result":"%s","vpn_verified":false}\n' \
                "$reason" "$(json_escape "$ssid")" "$(json_escape "$bssid")" "$reason"
            exit 1
        fi
        ;;
    auto)
        auto_en="$(lua "$NET_LUA" get-config "$KNOWN_FILE" auto_hunt true 2>/dev/null || echo true)"
        if [ "$auto_en" != "true" ]; then
            printf '{"ok":true,"connected":false,"reason":"auto_hunt_disabled"}\n'
            exit 0
        fi
        now="$(date +%s)"
        cd_sec="$(lua "$NET_LUA" get-config "$KNOWN_FILE" cooldown_sec 7200 2>/dev/null || echo 7200)"
        update_hunter_state "{\"hunting\":true,\"last_action\":\"auto_scanning\"}"
        raw="$(scan_groove_raw)"
        ranked="$(printf '%s\n' "$raw" | lua "$NET_LUA" rank-scan "$KNOWN_FILE" "$HUNTER_STATE" "$now" 2>/dev/null || echo '[]')"
        [ -z "$ranked" ] && ranked='[]'
        update_hunter_state "{\"hunting\":true,\"last_scan_at\":${now},\"last_candidates\":${ranked}}"

        tried=0
        connected_ssid=""
        connected_res=""
        captive_ssid=""
        tsv="$(extract_candidates_tsv "$ranked")"
        _tab="$(printf '\t')"
        while IFS="$_tab" read -r cand_bssid cand_trusted cand_ssid; do
            [ -z "$cand_ssid" ] && continue
            tried=$((tried + 1))
            [ "$tried" -gt 3 ] && break
            res_code=0
            reason="$(associate_and_verify "$cand_ssid" "$cand_bssid")" || res_code=$?
            if [ "$res_code" -eq 0 ]; then
                connected_ssid="$cand_ssid"
                connected_res="$reason"
                break
            elif [ "$res_code" -eq 2 ]; then
                [ -z "$captive_ssid" ] && captive_ssid="$cand_ssid"
                lua "$NET_LUA" cooldown "$HUNTER_STATE" "$cand_bssid" "captive_stuck" "$((now + cd_sec))" >/dev/null 2>&1 || true
            else
                lua "$NET_LUA" cooldown "$HUNTER_STATE" "$cand_bssid" "$reason" "$((now + cd_sec))" >/dev/null 2>&1 || true
            fi
        done <<EOF
$tsv
EOF

        if [ -n "$connected_ssid" ]; then
            update_hunter_state "{\"hunting\":false,\"last_action\":\"connected:${connected_res}\"}"
            signal_daemon
            printf '{"ok":true,"connected":true,"ssid":"%s","result":"%s","tried":%d}\n' \
                "$(json_escape "$connected_ssid")" "$connected_res" "$tried"
        else
            update_hunter_state "{\"hunting\":false,\"last_action\":\"no_vpn_capable_ap\",\"captive_available\":\"$(json_escape "$captive_ssid")\"}"
            printf '{"ok":true,"connected":false,"tried":%d,"captive_available":"%s"}\n' \
                "$tried" "$(json_escape "$captive_ssid")"
        fi
        ;;
    best)
        # 1-button quality & speed shootout (~30-60s): dual-band scan + benchmark top 3 diverse APs,
        # then lock onto the highest-scoring stable/fast winner. Survives transient SSH HUP during AP switches.
        trap '' HUP
        now="$(date +%s)"
        budget_sec="${VAN_HUNTER_BEST_BUDGET_SEC:-50}"
        deadline=$((now + budget_sec))
        cd_sec="$(lua "$NET_LUA" get-config "$KNOWN_FILE" cooldown_sec 7200 2>/dev/null || echo 7200)"
        update_hunter_state "{\"hunting\":true,\"last_action\":\"best_scanning\"}"

        raw="$(scan_groove_raw)"
        # Manual 1-button request re-evaluates cooled APs too (van may have moved or firewall changed)
        ranked="$(printf '%s\n' "$raw" | lua "$NET_LUA" rank-scan "$KNOWN_FILE" "$HUNTER_STATE" "$now" --include-cooled 2>/dev/null || echo '[]')"
        [ -z "$ranked" ] && ranked='[]'
        update_hunter_state "{\"hunting\":true,\"last_scan_at\":${now},\"last_action\":\"best_benchmarking\",\"last_candidates\":${ranked}}"

        tsv="$(printf '%s\n' "$ranked" | lua "$NET_LUA" best-candidates-tsv 3 2>/dev/null || true)"
        _tab="$(printf '\t')"

        tried=0
        best_score="-999999"
        best_ssid=""
        best_bssid=""
        best_band=""
        best_res=""
        best_mbps="0.0"
        best_rtt="9999"
        best_loss="100"
        best_tier="99"
        last_bssid=""
        captive_ssid=""
        captive_bssid=""
        captive_band=""
        tested_json=""

        while IFS="$_tab" read -r cand_bssid cand_tier cand_band cand_rssi cand_ssid; do
            [ -z "$cand_ssid" ] && continue
            # If a Tier 1 trusted AP already passed cleanly (loss <= 10%), never downgrade to untrusted Tiers 2-4
            if [ "$best_tier" = "1" ] && [ "$cand_tier" -gt 1 ]; then
                break
            fi
            if [ "$tried" -ge 1 ] && [ "$(date +%s)" -ge "$deadline" ]; then
                break
            fi
            tried=$((tried + 1))
            update_hunter_state "{\"hunting\":true,\"last_action\":\"testing:${tried}:$(json_escape "$cand_ssid")\"}"
            res_code=0
            reason="$(associate_and_verify "$cand_ssid" "$cand_bssid" "$cand_band")" || res_code=$?
            last_bssid="$cand_bssid"

            if [ "$res_code" -eq 0 ]; then
                bstats="$(benchmark_active_link "$reason")"
                _bloss="${bstats%% *}"
                _brest="${bstats#* }"
                _brtt="${_brest%% *}"
                _bmbps="${_brest#* }"
                _bscore="$(score_benchmark "$cand_tier" "$_bloss" "$_brtt" "$_bmbps" "$cand_rssi")"
                entry="$(printf '{"ssid":"%s","bssid":"%s","band":"%s","tier":%d,"rssi_dbm":%d,"result":"%s","mbps":%s,"rtt_ms":%d,"loss_pct":%d,"score":%d}' \
                    "$(json_escape "$cand_ssid")" "$(json_escape "$cand_bssid")" "$(json_escape "$cand_band")" \
                    "$cand_tier" "$cand_rssi" "$reason" "$_bmbps" "$_brtt" "$_bloss" "$_bscore")"
                tested_json="${tested_json:+${tested_json},}${entry}"
                if [ "$_bscore" -gt "$best_score" ]; then
                    best_score="$_bscore"
                    best_ssid="$cand_ssid"
                    best_bssid="$cand_bssid"
                    best_band="$cand_band"
                    best_res="$reason"
                    best_mbps="$_bmbps"
                    best_rtt="$_brtt"
                    best_loss="$_bloss"
                    best_tier="$cand_tier"
                fi
            elif [ "$res_code" -eq 2 ]; then
                if [ -z "$captive_ssid" ]; then
                    captive_ssid="$cand_ssid"
                    captive_bssid="$cand_bssid"
                    captive_band="$cand_band"
                fi
                entry="$(printf '{"ssid":"%s","bssid":"%s","band":"%s","tier":%d,"rssi_dbm":%d,"result":"captive_portal"}' \
                    "$(json_escape "$cand_ssid")" "$(json_escape "$cand_bssid")" "$(json_escape "$cand_band")" \
                    "$cand_tier" "$cand_rssi")"
                tested_json="${tested_json:+${tested_json},}${entry}"
            else
                lua "$NET_LUA" cooldown "$HUNTER_STATE" "$cand_bssid" "$reason" "$((now + cd_sec))" >/dev/null 2>&1 || true
                entry="$(printf '{"ssid":"%s","bssid":"%s","band":"%s","tier":%d,"rssi_dbm":%d,"result":"%s"}' \
                    "$(json_escape "$cand_ssid")" "$(json_escape "$cand_bssid")" "$(json_escape "$cand_band")" \
                    "$cand_tier" "$cand_rssi" "$reason")"
                tested_json="${tested_json:+${tested_json},}${entry}"
            fi
        done <<EOF
$tsv
EOF

        if [ -n "$best_ssid" ]; then
            if [ "$last_bssid" != "$best_bssid" ]; then
                update_hunter_state "{\"hunting\":true,\"last_action\":\"locking:$(json_escape "$best_ssid")\"}"
                associate_and_verify "$best_ssid" "$best_bssid" "$best_band" >/dev/null 2>&1 || true
            fi
            vpn_ver="false"
            [ "$best_res" = "vpn_ok" ] && vpn_ver="true"
            summary="best:${best_ssid} (${best_mbps} Mbps, ${best_rtt}ms)"
            update_hunter_state "{\"hunting\":false,\"last_action\":\"$(json_escape "$summary")\"}"
            signal_daemon
            printf '{"ok":true,"connected":true,"ssid":"%s","bssid":"%s","band":"%s","result":"%s","vpn_verified":%s,"mbps":%s,"rtt_ms":%d,"loss_pct":%d,"score":%d,"tried":%d,"tested":[%s]}\n' \
                "$(json_escape "$best_ssid")" "$(json_escape "$best_bssid")" "$(json_escape "$best_band")" \
                "$best_res" "$vpn_ver" "$best_mbps" "$best_rtt" "$best_loss" "$best_score" "$tried" "$tested_json"
        elif [ -n "$captive_ssid" ]; then
            if [ "$last_bssid" != "$captive_bssid" ]; then
                associate_and_verify "$captive_ssid" "$captive_bssid" "$captive_band" >/dev/null 2>&1 || true
            fi
            update_hunter_state "{\"hunting\":false,\"last_action\":\"captive_available\",\"captive_available\":\"$(json_escape "$captive_ssid")\"}"
            signal_daemon
            printf '{"ok":true,"connected":false,"ssid":"%s","bssid":"%s","band":"%s","result":"captive_portal","vpn_verified":false,"captive_required":true,"tried":%d,"tested":[%s]}\n' \
                "$(json_escape "$captive_ssid")" "$(json_escape "$captive_bssid")" "$(json_escape "$captive_band")" "$tried" "$tested_json"
        else
            update_hunter_state "{\"hunting\":false,\"last_action\":\"no_vpn_capable_ap\"}"
            printf '{"ok":true,"connected":false,"tried":%d,"tested":[%s]}\n' "$tried" "$tested_json"
        fi
        ;;
    *)
        printf '{"ok":false,"error":"usage: wifi-hunter.sh {scan|connect <ssid> [bssid] [band]|auto|best}"}\n' >&2
        exit 2
        ;;
esac
