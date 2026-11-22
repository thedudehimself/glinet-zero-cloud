#!/bin/sh
# Fail-closed IPv4/IPv6 VPN gate, wg_van policy routing, Gate 2 DoH-backed captive probe, and Gate 3 probe.

_vpn_gate_lock() {
    _ldir="${VAN_STATE_DIR:-/var/run/van-wan-guard}/vpn_gate.lock"
    mkdir -p "$(dirname "$_ldir")" 2>/dev/null || true
    _tries=0
    while [ "$_tries" -lt 20 ]; do
        if mkdir "$_ldir" 2>/dev/null; then
            printf '%d\n' "$$" > "${_ldir}/pid" 2>/dev/null || true
            return 0
        fi
        _opid="$(cat "${_ldir}/pid" 2>/dev/null || true)"
        if [ -n "$_opid" ] && ! kill -0 "$_opid" 2>/dev/null; then
            rm -rf "$_ldir" 2>/dev/null || true
            continue
        fi
        _tries=$((_tries + 1))
        sleep 1 2>/dev/null || true
    done
    rm -rf "$_ldir" 2>/dev/null || true
    mkdir "$_ldir" 2>/dev/null || true
    printf '%d\n' "$$" > "${_ldir}/pid" 2>/dev/null || true
}

_vpn_gate_unlock() {
    rm -rf "${VAN_STATE_DIR:-/var/run/van-wan-guard}/vpn_gate.lock" 2>/dev/null || true
}

# Atomically set VAN_CPE_GATE to fail-closed REJECT without any empty-chain window.
_set_gate_chain_reject() {
    iptables -w -I VAN_CPE_GATE 1 -j REJECT --reject-with icmp-admin-prohibited 2>/dev/null || true
    _cnt="$(iptables -w -S VAN_CPE_GATE 2>/dev/null | grep -c '^-A ' || true)"
    _cnt="${_cnt:-0}"
    while [ "$_cnt" -gt 1 ]; do
        iptables -w -D VAN_CPE_GATE 2 2>/dev/null || break
        _cnt=$((_cnt - 1))
    done
}

# Atomically set VAN_CPE_DNS_OUT to fail-closed REJECT (:53/:853) without any empty-chain window.
_set_dns_chain_reject() {
    iptables -w -I VAN_CPE_DNS_OUT 1 -p udp --dport 53 -j REJECT 2>/dev/null || true
    iptables -w -I VAN_CPE_DNS_OUT 2 -p tcp --dport 53 -j REJECT 2>/dev/null || true
    iptables -w -I VAN_CPE_DNS_OUT 3 -p tcp --dport 853 -j REJECT 2>/dev/null || true
    _cnt="$(iptables -w -S VAN_CPE_DNS_OUT 2>/dev/null | grep -c '^-A ' || true)"
    _cnt="${_cnt:-0}"
    while [ "$_cnt" -gt 3 ]; do
        iptables -w -D VAN_CPE_DNS_OUT 4 2>/dev/null || break
        _cnt=$((_cnt - 1))
    done
}

# Ensure base boot-time hooks and policy rules exist (idempotent).
_ensure_base_vpn_hooks() {
    _cpe_if="$1"
    _wg_van_if="$2"
    _wg_van_ip="$3"
    _wg_mgmt_if="$4"
    _wg_mgmt_ip="$5"

    # Unconditional IPv4 FORWARD killswitch chain at index 1 on eth0 (above RELATED,ESTABLISHED; covers ALL VLANs/bridges)
    iptables -w -N VAN_CPE_GATE 2>/dev/null || true
    iptables -w -C FORWARD -o "$_cpe_if" -j VAN_CPE_GATE 2>/dev/null || \
        iptables -w -I FORWARD 1 -o "$_cpe_if" -j VAN_CPE_GATE 2>/dev/null || true

    # IPv4 OUTPUT DNS killswitch on eth0
    iptables -w -N VAN_CPE_DNS_OUT 2>/dev/null || true
    iptables -w -C OUTPUT -o "$_cpe_if" -j VAN_CPE_DNS_OUT 2>/dev/null || \
        iptables -w -I OUTPUT 1 -o "$_cpe_if" -j VAN_CPE_DNS_OUT 2>/dev/null || true

    # Hard fwmark 0x101 transport lock: wg_van packets may NEVER exit Starlink
    iptables -w -C OUTPUT -m mark --mark 0x101 ! -o "$_cpe_if" -j DROP 2>/dev/null || \
        iptables -w -I OUTPUT 1 -m mark --mark 0x101 ! -o "$_cpe_if" -j DROP 2>/dev/null || true

    # IPv6 fail-closed DROP/REJECT on eth0
    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -w -C FORWARD -o "$_cpe_if" -j REJECT 2>/dev/null || \
            ip6tables -w -I FORWARD 1 -o "$_cpe_if" -j REJECT 2>/dev/null || true
        ip6tables -w -C OUTPUT -o "$_cpe_if" -j REJECT 2>/dev/null || \
            ip6tables -w -I OUTPUT 1 -o "$_cpe_if" -j REJECT 2>/dev/null || true
    fi

    # Policy rules: fwmark 0x101 strictly eth0 (table 101) with terminal unreachable at prio 86
    ip rule del prio 85 2>/dev/null || true
    ip rule add fwmark 0x101 table 101 prio 85 2>/dev/null || true
    ip rule del prio 86 2>/dev/null || true
    ip rule add fwmark 0x101 unreachable prio 86 2>/dev/null || true

    # Source-aware wg_mgmt (table 104) vs wg_van (table 103) separation for 192.168.2.1
    if [ -n "$_wg_mgmt_ip" ]; then
        ip route replace 192.168.2.1/32 dev "$_wg_mgmt_if" table 104 2>/dev/null || true
        ip rule del prio 88 2>/dev/null || true
        ip rule add from "${_wg_mgmt_ip}/32" table 104 prio 88 2>/dev/null || true
    fi
    if [ -n "$_wg_van_ip" ]; then
        ip route replace 192.168.2.1/32 dev "$_wg_van_if" table 103 2>/dev/null || true
        ip route replace default dev "$_wg_van_if" table 103 2>/dev/null || true
        ip rule del prio 89 2>/dev/null || true
        ip rule add from "${_wg_van_ip}/32" table 103 prio 89 2>/dev/null || true
        # Terminal unreachable for wg_van source IP so Gate 3 probes can NEVER fall through to Starlink/main
        ip rule del prio 90 2>/dev/null || true
        ip rule add from "${_wg_van_ip}/32" unreachable prio 90 2>/dev/null || true
    fi
}

# Lightweight per-tick route healer: restores table 104 (wg_mgmt) and table 103 (wg_van) after netifd bounces.
ensure_wg_routes() {
    _wg_van_if="${1:-wg_van}"
    _wg_van_ip="${2:-192.168.2.6}"
    _wg_mgmt_if="${3:-wg_mgmt}"
    _wg_mgmt_ip="${4:-192.168.2.5}"

    if [ -n "$_wg_mgmt_ip" ] && ip link show "$_wg_mgmt_if" >/dev/null 2>&1; then
        if ! ip route show table 104 2>/dev/null | grep -q "192.168.2.1"; then
            ip route replace 192.168.2.1/32 dev "$_wg_mgmt_if" table 104 2>/dev/null || true
        fi
    fi
    if [ -n "$_wg_van_ip" ] && ip link show "$_wg_van_if" >/dev/null 2>&1; then
        if ! ip route show table 103 2>/dev/null | grep -q "default"; then
            ip route replace 192.168.2.1/32 dev "$_wg_van_if" table 103 2>/dev/null || true
            ip route replace default dev "$_wg_van_if" table 103 2>/dev/null || true
        fi
    fi
}

# Discover local LAN/guest subnets dynamically (falls back to GL.iNet defaults 192.168.8.0/24 & 192.168.9.0/24).
_list_local_lan_cidrs() {
    _cidrs="$(ip -4 route show proto kernel scope link 2>/dev/null | awk '$3 ~ /^br-/ && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/ { print $1 }')"
    if [ -n "$_cidrs" ]; then
        printf '%s\n' "$_cidrs"
    else
        printf '192.168.8.0/24\n192.168.9.0/24\n'
    fi
}

# Apply gate state: locked | vpn_active | captive_temp | trusted_direct
# Args: <gate_state> <cpe_iface> <wg_van_iface> <wg_van_ip> <wg_mgmt_iface> <wg_mgmt_ip>
apply_vpn_gate() {
    _state="$1"
    _cpe_if="${2:-eth0}"
    _wg_van_if="${3:-wg_van}"
    _wg_van_ip="${4:-192.168.2.6}"
    _wg_mgmt_if="${5:-wg_mgmt}"
    _wg_mgmt_ip="${6:-192.168.2.5}"

    _vpn_gate_lock

    _ensure_base_vpn_hooks "$_cpe_if" "$_wg_van_if" "$_wg_van_ip" "$_wg_mgmt_if" "$_wg_mgmt_ip"

    # Reset client VPN rules (93..98) before setting target state (bounded to avoid infinite loops)
    for _p in 93 94 95 96 97 98; do
        _tries=0
        while [ "$_tries" -lt 16 ] && ip rule del prio "$_p" 2>/dev/null; do
            _tries=$((_tries + 1))
        done
    done

    case "$_state" in
        vpn_active)
            # Atomically keep raw eth0 BLOCKED for both clients & router DNS; steer clients + 192.168.2.1 DNS into table 103
            _set_gate_chain_reject
            _set_dns_chain_reject

            ip route replace 192.168.2.1/32 dev "$_wg_van_if" table 103 2>/dev/null || true
            ip route replace default dev "$_wg_van_if" table 103 2>/dev/null || true
            # prio 93 sits AFTER prio 88 (from wg_mgmt_ip -> wg_mgmt) so management never collides
            ip rule add to 192.168.2.1/32 table 103 prio 93 2>/dev/null || true
            for _cidr in $(_list_local_lan_cidrs); do
                ip rule add to "$_cidr" table main prio 94 2>/dev/null || true
            done
            ip rule add iif br-lan table 103 prio 95 2>/dev/null || true
            ip rule add iif br-guest table 103 prio 96 2>/dev/null || true
            # Terminal unreachable rules guarantee zero fallback to Starlink/main if wg_van flaps between ticks
            ip rule add iif br-lan unreachable prio 97 2>/dev/null || true
            ip rule add iif br-guest unreachable prio 98 2>/dev/null || true
            ;;
        captive_temp)
            # Explicit user-triggered 10m splash login: permit ONLY HTTP/HTTPS/DNS out eth0
            _set_gate_chain_reject
            iptables -w -I VAN_CPE_GATE 1 -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
            iptables -w -I VAN_CPE_GATE 2 -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
            iptables -w -I VAN_CPE_GATE 3 -p udp --dport 53 -j ACCEPT 2>/dev/null || true
            iptables -w -I VAN_CPE_GATE 4 -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
            _set_dns_chain_reject
            iptables -w -I VAN_CPE_DNS_OUT 1 -p udp --dport 53 -j ACCEPT 2>/dev/null || true
            iptables -w -I VAN_CPE_DNS_OUT 2 -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
            ;;
        trusted_direct)
            iptables -w -F VAN_CPE_GATE 2>/dev/null || true
            iptables -w -A VAN_CPE_GATE -j ACCEPT 2>/dev/null || true
            iptables -w -F VAN_CPE_DNS_OUT 2>/dev/null || true
            iptables -w -A VAN_CPE_DNS_OUT -j ACCEPT 2>/dev/null || true
            ;;
        *)
            # locked (default fail-closed, zero empty-chain window)
            _set_gate_chain_reject
            _set_dns_chain_reject
            ;;
    esac

    _vpn_gate_unlock
}

# Gate 3: Verify wg_van route binding, handshake freshness, AND live in-tunnel ping from wg_van_ip to 192.168.2.1.
# Args: <wg_van_iface> <wg_van_ip> <wg_peer_ip> <max_hs_age>
probe_wg_van() {
    _iface="${1:-wg_van}"
    _src_ip="${2:-192.168.2.6}"
    _peer_ip="${3:-192.168.2.1}"
    _max_age="${4:-150}"

    [ -z "$_src_ip" ] && return 1
    command -v wg >/dev/null 2>&1 || return 1

    # Verify kernel route for peer from src_ip actually exits via wg_van (prevents false pass over Starlink)
    _rget="$(ip route get "$_peer_ip" from "$_src_ip" 2>/dev/null || true)"
    if [ -n "$_rget" ] && ! printf '%s\n' "$_rget" | grep -q "dev ${_iface}"; then
        return 1
    fi

    # Always attempt in-tunnel ping first (triggers handshake if peer is reachable over eth0)
    if ! ping -I "$_src_ip" -c 2 -W 2 "$_peer_ip" >/dev/null 2>&1; then
        return 1
    fi

    _hs="$(wg show "$_iface" latest-handshakes 2>/dev/null | awk 'NR==1 { print $2 }')"
    [ -z "$_hs" ] && return 1
    _now="$(date +%s)"
    _age=$((_now - _hs))
    [ "$_hs" -gt 0 ] && [ "$_age" -le "$_max_age" ]
}

# Resolve hostname over encrypted DoH bound strictly to eth0 source IP (zero dnsmasq deadlock, zero cleartext DNS).
resolve_doh_ipv4() {
    _host="$1"
    _src_ip="$2"
    [ -z "$_host" ] && return 1
    case "$_host" in
        [0-9]*.[0-9]*.[0-9]*.[0-9]*) printf '%s\n' "$_host"; return 0 ;;
    esac
    command -v curl >/dev/null 2>&1 || return 1
    _json="$(curl --interface "$_src_ip" --connect-timeout 3 --max-time 4 -sS \
        -H 'accept: application/dns-json' \
        "https://1.1.1.1/dns-query?name=${_host}&type=A" 2>/dev/null || true)"
    printf '%s\n' "$_json" | awk '
        {
            while (match($0, /"data"[[:space:]]*:[[:space:]]*"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"/)) {
                s = substr($0, RSTART, RLENGTH)
                sub(/^"data"[[:space:]]*:[[:space:]]*"/, "", s)
                sub(/"$/, "", s)
                print s
                exit
            }
        }
    '
}

# Gate 2: Captive-portal HTTP 204 probe strictly over eth0 without relying on dnsmasq (avoids DNS deadlock when Starlink is off).
# Args: <src_ip> <captive_url>
probe_cpe_http_eth0() {
    _src_ip="$1"
    _url="${2:-http://connectivitycheck.gstatic.com/generate_204}"
    command -v curl >/dev/null 2>&1 || { printf '000\n'; return 0; }

    _host="$(printf '%s' "$_url" | sed -n 's|^https\?://\([^/:]*\).*|\1|p')"
    _raw=""
    if [ -n "$_host" ]; then
        _ip="$(resolve_doh_ipv4 "$_host" "$_src_ip" || true)"
        if [ -n "$_ip" ]; then
            _raw="$(curl --interface "$_src_ip" --resolve "${_host}:80:${_ip}" --resolve "${_host}:443:${_ip}" \
                --connect-timeout 3 --max-time 4 -sS -o /dev/null -w '%{http_code}' "$_url" 2>/dev/null || true)"
        fi
    fi

    # If DoH was blocked/intercepted (common on captive portals), probe IPv4 directly with Host header (no dnsmasq needed)
    case "$_raw" in
        [0-9][0-9][0-9])
            if [ "$_raw" != "000" ]; then
                printf '%s\n' "$_raw"
                return 0
            fi
            ;;
    esac

    _raw="$(curl --interface "$_src_ip" --connect-timeout 3 --max-time 4 -sS -o /dev/null -w '%{http_code}' \
        -H "Host: ${_host:-connectivitycheck.gstatic.com}" "http://1.1.1.1/" 2>/dev/null || true)"
    case "$_raw" in
        301|302|303|307|308|200)
            # Check if 1.1.1.1 redirected to Cloudflare HTTPS (normal internet) vs a captive portal
            _loc="$(curl --interface "$_src_ip" --connect-timeout 3 --max-time 4 -sSI \
                "http://1.1.1.1/" 2>/dev/null | awk 'tolower($1)=="location:" { print $2; exit }' | tr -d '\r')"
            case "$_loc" in
                https://1.1.1.1/*|https://one.one.one.one/*)
                    # Direct internet reached Cloudflare HTTPS cleanly (no captive interception)
                    printf '204\n'; return 0
                    ;;
                *)
                    printf '%s\n' "$_raw"; return 0
                    ;;
            esac
            ;;
        [0-9][0-9][0-9]) printf '%s\n' "$_raw" ;;
        *) printf '000\n' ;;
    esac
}
