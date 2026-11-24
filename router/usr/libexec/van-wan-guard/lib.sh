#!/bin/sh
# Pure POSIX sh + BusyBox awk core library for van-wan-guard.

# Escape a string for safe JSON emission (strips ASCII control bytes 0x00-0x1f & 0x7f).
json_escape() {
    printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037\177' | awk '
        BEGIN { ORS="" }
        {
            gsub(/\\/, "\\\\")
            gsub(/"/, "\\\"")
            gsub(/\r/, "")
            gsub(/\t/, "\\t")
            if (NR > 1) printf "\\n"
            printf "%s", $0
        }
    '
}

# Read simple top-level JSON string/number value without requiring jq/jsonfilter.
json_get_val() {
    _file="$1"
    _key="$2"
    _default="$3"
    if [ ! -f "$_file" ]; then
        printf '%s\n' "$_default"
        return 0
    fi
    _val="$(awk -v k="$_key" '
        {
            pat = "\"" k "\"[[:space:]]*:[[:space:]]*"
            if (match($0, pat)) {
                rest = substr($0, RSTART + RLENGTH)
                if (substr(rest, 1, 1) == "\"") {
                    rest = substr(rest, 2)
                    i = index(rest, "\"")
                    if (i > 0) {
                        val = substr(rest, 1, i - 1)
                        gsub(/\\\//, "/", val)
                        print val
                        exit
                    }
                } else {
                    gsub(/[,}[:space:]].*$/, "", rest)
                    print rest
                    exit
                }
            }
        }
    ' "$_file")"
    if [ -n "$_val" ]; then
        printf '%s\n' "$_val"
    else
        printf '%s\n' "$_default"
    fi
}

# Parse BusyBox or iputils ping stdout -> "<loss_pct> <avg_rtt_ms_int>"
parse_ping_stats() {
    awk '
        BEGIN { loss = 100; rtt = 9999 }
        /packet loss/ {
            if (match($0, /[0-9]+(\.[0-9]+)?%/)) {
                s = substr($0, RSTART, RLENGTH - 1)
                loss = int(s + 0.5)
            }
        }
        /(round-trip|rtt)[[:space:]]/ && /=/ {
            idx = index($0, "=")
            rest = substr($0, idx + 1)
            sub(/^[[:space:]]+/, "", rest)
            sub(/[[:space:]].*$/, "", rest)
            n = split(rest, a, "/")
            if (n >= 2 && a[2] != "") {
                rtt = int(a[2] + 0.5)
            }
        }
        END { printf "%d %d\n", loss, rtt }
    '
}

# Classify CPE health from probe signals.
# Args: <link_up> <loss_pct> <rtt_ms> <http_code> <max_loss> <max_rtt>
classify_cpe_health() {
    _link="$1"
    _loss="$2"
    _rtt="$3"
    _http="$4"
    _max_loss="$5"
    _max_rtt="$6"

    if [ "$_link" != "1" ]; then
        printf 'down\n'
        return 0
    fi
    case "$_http" in
        204)
            if [ "$_loss" -le "$_max_loss" ] && [ "$_rtt" -lt "$_max_rtt" ]; then
                printf 'healthy\n'
            else
                printf 'degraded\n'
            fi
            ;;
        200|301|302|303|307|308)
            printf 'captive\n'
            ;;
        *)
            printf 'down\n'
            ;;
    esac
}

# Gate 3: Combine base CPE health with trust & wg_van verification.
# Args: <base_health> <is_trusted:0|1> <wg_van_ok:0|1>
classify_cpe_with_vpn() {
    _base="$1"
    _trusted="$2"
    _wg_ok="$3"
    if [ "$_base" != "healthy" ]; then
        printf '%s\n' "$_base"
        return 0
    fi
    if [ "$_trusted" = "1" ]; then
        printf 'healthy_trusted\n'
    elif [ "$_wg_ok" = "1" ]; then
        printf 'healthy_vpn\n'
    else
        printf 'vpn_blocked\n'
    fi
}

_is_healthy_state() {
    case "$1" in
        healthy|healthy_vpn|healthy_trusted) return 0 ;;
        *) return 1 ;;
    esac
}

# Pure state-machine transition with hysteresis and captive_login early-exit/expiry.
# Args: <mode> <mode_expires_at> <now> <cur_wan> <cpe_health> <sl_up> <fail_strikes> <ok_strikes> <max_fail> <max_ok>
# Output: "<new_mode> <new_wan> <new_fail_strikes> <new_ok_strikes>"
decide_next_state() {
    _mode="$1"
    _exp="$2"
    _now="$3"
    _cur="$4"
    _health="$5"
    _sl_up="$6"
    _fail="$7"
    _ok="$8"
    _max_fail="$9"
    shift 9
    _max_ok="$1"

    if [ "$_mode" = "force_cpe" ]; then
        printf 'force_cpe cpe 0 0\n'
        return 0
    fi
    if [ "$_mode" = "force_starlink" ]; then
        printf 'force_starlink starlink 0 0\n'
        return 0
    fi

    if [ "$_mode" = "captive_login" ]; then
        if _is_healthy_state "$_health"; then
            printf 'auto cpe 0 0\n'
            return 0
        fi
        # Critical fail-closed invariant: once HTTP 204 clears on a VPN-blocking AP,
        # exit captive_login immediately so VAN_CPE_GATE snaps back to REJECT!
        if [ "$_health" = "vpn_blocked" ]; then
            printf 'auto %s 1 0\n' "$([ "$_sl_up" = "1" ] && echo starlink || echo cpe)"
            return 0
        fi
        if [ "$_exp" -gt 0 ] && [ "$_now" -ge "$_exp" ]; then
            _mode="auto"
        else
            printf 'captive_login cpe 0 0\n'
            return 0
        fi
    fi

    # mode == auto
    if _is_healthy_state "$_health"; then
        _fail=0
        if [ "$_cur" = "cpe" ]; then
            printf 'auto cpe 0 %d\n' "$_max_ok"
            return 0
        fi
        _ok=$((_ok + 1))
        if [ "$_ok" -ge "$_max_ok" ]; then
            printf 'auto cpe 0 %d\n' "$_ok"
        else
            printf 'auto starlink 0 %d\n' "$_ok"
        fi
        return 0
    fi

    # CPE is captive, degraded, or down
    _ok=0
    _fail=$((_fail + 1))
    if [ "$_cur" = "starlink" ]; then
        printf 'auto starlink %d 0\n' "$_fail"
        return 0
    fi

    if [ "$_fail" -ge "$_max_fail" ] && [ "$_sl_up" = "1" ]; then
        printf 'auto starlink %d 0\n' "$_fail"
    else
        printf 'auto cpe %d 0\n' "$_fail"
    fi
}

# Accumulate interface byte counter across reboots and billing-cycle rollovers (64-bit safe via awk).
# Args: <cycle_key> <stored_cycle> <last_iface_bytes> <stored_total> <curr_iface_bytes>
# Output: "<cycle_key> <curr_iface_bytes> <new_total>"
update_usage_bytes() {
    awk -v ck="$1" -v sc="$2" -v last="$3" -v tot="$4" -v curr="$5" '
        BEGIN {
            last += 0; tot += 0; curr += 0
            cy = substr(ck, 1, 4) + 0
            if (sc != "" && ck > sc && cy >= 2026) {
                printf "%s %.0f 0\n", ck, curr
                exit
            }
            out_cycle = (sc != "" && (ck < sc || cy < 2026)) ? sc : ck
            if (curr >= last) {
                delta = curr - last
            } else {
                delta = curr
            }
            printf "%s %.0f %.0f\n", out_cycle, curr, tot + delta
        }
    '
}

# Compute billing cycle key YYYY-MM based on reset day (1..28).
# Args: <year> <month> <day> <reset_day>
compute_cycle_key() {
    awk -v y="$1" -v m="$2" -v d="$3" -v r="$4" '
        BEGIN {
            y += 0; m += 0; d += 0; r += 0
            if (d < r) {
                m -= 1
                if (m < 1) { m = 12; y -= 1 }
            }
            printf "%04d-%02d\n", y, m
        }
    '
}

# Parse RouterOS /interface wireless monitor wlan1 once (or /interface wifi monitor) output.
# Output: pipe-separated "<status>|<ssid>|<bssid>|<rssi>|<channel>|<tx_rate>" (non-whitespace delimiter preserves empty SSID).
parse_groove_monitor() {
    awk '
        BEGIN { status=""; ssid=""; bssid=""; rssi=""; channel=""; tx="" }
        {
            sub(/\r$/, "")
            line = $0
            sub(/^[[:space:]]+/, "", line)
            idx = index(line, ":")
            if (idx == 0) next
            k = substr(line, 1, idx - 1)
            v = substr(line, idx + 1)
            sub(/^[[:space:]]+/, "", v)
            sub(/[[:space:]]+$/, "", v)
            gsub(/\|/, "/", v)
            if (k == "status" || k == "state") status = v
            else if (k == "ssid") ssid = v
            else if (k == "bssid" || k == "mac-address") bssid = v
            else if (k == "signal-strength" || k == "signal") {
                sub(/dBm.*$/, "", v)
                sub(/@.*$/, "", v)
                rssi = v
            }
            else if (k == "channel") channel = v
            else if (k == "tx-rate") tx = v
        }
        END {
            printf "%s|%s|%s|%s|%s|%s\n", status, ssid, bssid, rssi, channel, tx
        }
    '
}

atomic_write_file() {
    _dest="$1"
    _content="$2"
    _dir="$(dirname "$_dest")"
    mkdir -p "$_dir"
    _tmp="${_dest}.tmp.$$"
    printf '%s\n' "$_content" > "$_tmp" && mv -f "$_tmp" "$_dest"
}
