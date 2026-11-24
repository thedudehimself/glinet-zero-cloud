#!/usr/bin/env lua
-- Native OpenWrt Lua (luci.jsonc) allowlist, PSK redaction, scan ranker, and RouterOS command generator.
-- Strictly Lua 5.1 compatible (OpenWrt 21.02 on GL-MT3000).

local jsonc = require("luci.jsonc")

-- Seed RNG from /dev/urandom when available so concurrent processes never collide on temp names
do
    local seed = os.time()
    local uf = io.open("/dev/urandom", "rb")
    if uf then
        local bytes = uf:read(3)
        uf:close()
        if bytes and #bytes == 3 then
            local b1, b2, b3 = bytes:byte(1, 3)
            seed = b1 + b2 * 256 + b3 * 65536
        end
    end
    math.randomseed(seed)
end

local function fail(msg, code)
    io.stdout:write(jsonc.stringify({ ok = false, error = msg }) .. "\n")
    os.exit(code or 2)
end

local function read_file(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local data = f:read("*a")
    f:close()
    return data
end

local function sh_quote(s)
    return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

local function write_atomic(path, content, mode_600)
    local dir = path:match("^(.*)/[^/]+$")
    if dir and #dir > 0 then
        os.execute("mkdir -p " .. sh_quote(dir))
    end
    -- Serialize mutations with a brief mkdir lock (with stale-lock recovery)
    local lockdir = path .. ".lock"
    local locked = false
    for _ = 1, 20 do
        local rc = os.execute("mkdir " .. sh_quote(lockdir) .. " 2>/dev/null")
        if rc == 0 or rc == true then
            locked = true
            break
        end
        os.execute("sleep 1 2>/dev/null || true")
    end
    if not locked then
        os.execute("rm -rf " .. sh_quote(lockdir) .. " 2>/dev/null; mkdir " .. sh_quote(lockdir) .. " 2>/dev/null")
        locked = true
    end

    local tmp = path .. ".tmp." .. tostring(os.time()) .. "." .. tostring(math.random(100000, 999999))
    if mode_600 then
        -- Pre-create temp file with 0600 permissions BEFORE writing any plaintext PSKs
        local rc = os.execute("(umask 077 && : > " .. sh_quote(tmp) .. ")")
        if rc ~= 0 and rc ~= true then
            os.execute("rm -rf " .. sh_quote(lockdir) .. " 2>/dev/null")
            fail("cannot pre-create 0600 temp file", 1)
        end
    end
    local f, err = io.open(tmp, "w")
    if not f then
        os.remove(tmp)
        os.execute("rm -rf " .. sh_quote(lockdir) .. " 2>/dev/null")
        fail("cannot write temp file: " .. tostring(err), 1)
    end
    f:write(content)
    f:write("\n")
    f:close()
    if mode_600 then
        os.execute("chmod 600 " .. sh_quote(tmp))
    end
    local ok, rerr = os.rename(tmp, path)
    os.execute("rm -rf " .. sh_quote(lockdir) .. " 2>/dev/null")
    if not ok then
        os.remove(tmp)
        fail("atomic rename failed: " .. tostring(rerr), 1)
    end
end

local function default_known()
    return {
        auto_hunt = true,
        allow_xfinity = true,
        allow_open_wifi = true,
        min_rssi_dbm = -78,
        cooldown_sec = 7200,
        networks = {},
        blocklist = { "DIRECT-*", "HP-Print-*", "TravelAP*" },
    }
end

local function load_known(path)
    local raw = read_file(path)
    local data = raw and jsonc.parse(raw) or nil
    if type(data) ~= "table" then
        data = default_known()
    end
    if data.auto_hunt == nil then data.auto_hunt = true end
    if data.allow_xfinity == nil then data.allow_xfinity = true end
    if data.allow_open_wifi == nil then data.allow_open_wifi = true end
    if type(data.min_rssi_dbm) ~= "number" then data.min_rssi_dbm = -78 end
    if type(data.cooldown_sec) ~= "number" then data.cooldown_sec = 7200 end
    if type(data.networks) ~= "table" then data.networks = {} end
    if type(data.blocklist) ~= "table" then data.blocklist = { "DIRECT-*", "HP-Print-*", "TravelAP*" } end
    return data
end

local function load_state(path)
    local raw = read_file(path)
    local data = raw and jsonc.parse(raw) or nil
    if type(data) ~= "table" then
        data = {}
    end
    if type(data.cooldowns) ~= "table" then
        data.cooldowns = {}
    end
    return data
end

local function has_control_chars(s)
    if type(s) ~= "string" then return true end
    for i = 1, #s do
        local b = s:byte(i)
        if b < 32 or b == 127 then
            return true
        end
    end
    return false
end

local function has_hostile_ros_chars(s)
    if has_control_chars(s) then return true end
    if s:find("[%[%]$%\"\\`;]") then return true end
    return false
end

local function escape_ros_string(s)
    -- Escape \, ", $, [ for RouterOS double-quoted string literals
    local out = s:gsub("\\", "\\\\")
    out = out:gsub('"', '\\"')
    out = out:gsub("%$", "\\$")
    out = out:gsub("%[", "\\[")
    return out
end

local function glob_match(pattern, text)
    if type(pattern) ~= "string" or type(text) ~= "string" then return false end
    -- Escape Lua pattern magic chars except * and ?
    local esc = pattern:gsub("([%^%$%(%)%%%.%[%]%+%-])", "%%%1")
    esc = esc:gsub("%*", ".*"):gsub("%?", ".")
    return text:match("^" .. esc .. "$") ~= nil
end

local function is_blocklisted(blocklist, ssid)
    for _, pat in ipairs(blocklist or {}) do
        if glob_match(pat, ssid) then
            return true
        end
    end
    return false
end

local function find_known_network(known, ssid)
    for idx, net in ipairs(known.networks or {}) do
        if net.ssid == ssid then
            return net, idx
        end
    end
    return nil, nil
end

local function sort_networks(nets)
    table.sort(nets, function(a, b)
        local at = a.trusted and 0 or 1
        local bt = b.trusted and 0 or 1
        if at ~= bt then return at < bt end
        local ap = tonumber(a.priority) or 50
        local bp = tonumber(b.priority) or 50
        if ap ~= bp then return ap < bp end
        return tostring(a.ssid or "") < tostring(b.ssid or "")
    end)
end

local function redact_known(known)
    local out_nets = {}
    for _, n in ipairs(known.networks or {}) do
        local psk_present = (type(n.psk) == "string" and #n.psk > 0)
        table.insert(out_nets, {
            ssid = n.ssid,
            security = n.security or (psk_present and "wpa2" or "open"),
            trusted = (n.trusted == true) and psk_present and (n.security ~= "open"),
            priority = tonumber(n.priority) or 50,
            has_psk = psk_present,
        })
    end
    return {
        auto_hunt = known.auto_hunt == true,
        allow_xfinity = known.allow_xfinity == true,
        allow_open_wifi = known.allow_open_wifi == true,
        min_rssi_dbm = tonumber(known.min_rssi_dbm) or -78,
        cooldown_sec = tonumber(known.cooldown_sec) or 7200,
        networks = out_nets,
        blocklist = known.blocklist or {},
    }
end

local function parse_scan_line(line)
    -- Matches RouterOS v6 save-file CSV (MAC,'SSID',freq,rssi,proto,flags,), v6 table, and v7 (/interface wifi scan).
    -- SECURITY: Anchor split to the RIGHTMOST RouterOS frequency+RSSI boundary so a crafted
    -- 32-byte SSID can NEVER spoof SSID, RSSI, or security!
    line = line:gsub("\r", "")
    local mac_s, mac_e, mac = line:find("(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
    if not mac then return nil end
    local prefix = line:sub(1, mac_s - 1)
    local rest = line:sub(mac_e + 1)

    local function find_last_match(str, pat)
        local last_s = nil
        local pos = 1
        while true do
            local s, _ = str:find(pat, pos)
            if not s then break end
            last_s = s
            pos = s + 1
        end
        return last_s
    end

    -- Format 1: RouterOS save-file CSV: ,'<SSID>',2437/20/gn(24dBm),-60,802.11,privacy,
    if rest:sub(1, 2) == ",'" then
        local csv_body = rest:sub(3)
        local csv_split = find_last_match(csv_body, "',[2567]%d%d%d[^,]*,%-%d+,")
        if csv_split then
            local ssid = csv_body:sub(1, csv_split - 1)
            local tail = csv_body:sub(csv_split + 2)
            local freq_str = tail:match("^([2567]%d%d%d)")
            local freq_mhz = freq_str and tonumber(freq_str) or nil
            local rssi_str = tail:match(",(%-%d+),")
            local rssi = rssi_str and tonumber(rssi_str) or nil
            if not rssi or rssi > 0 or rssi < -120 then return nil end
            local low_tail = tail:lower()
            local sec = "open"
            if low_tail:find("privacy", 1, true)
                or low_tail:find("wpa", 1, true)
                or low_tail:find("rsn", 1, true)
                or low_tail:find("aes", 1, true)
                or low_tail:find("tkip", 1, true)
                or low_tail:find("sae", 1, true)
                or low_tail:find("dot1x", 1, true)
                or low_tail:find("eap", 1, true)
                or low_tail:find("wep", 1, true)
                or low_tail:find("owe", 1, true)
            then
                sec = "wpa2"
            end
            return {
                bssid = mac:upper(),
                ssid = ssid,
                rssi_dbm = rssi,
                security = sec,
                freq_mhz = freq_mhz,
                band = (freq_mhz and freq_mhz >= 4900) and "5g" or "2g",
            }
        end
    end

    -- Format 2: Space-delimited RouterOS v6/v7 scan table
    local p1 = find_last_match(rest, "%s+[2567]%d%d%d/[^%s]*%s+%-%d+")
    local p2 = find_last_match(rest, "%s+[2567]%d%d%d%s+%-%d+")
    local split_pos = nil
    if p1 and p2 then
        split_pos = (p1 > p2) and p1 or p2
    else
        split_pos = p1 or p2 or find_last_match(rest, "%s+%-%d+%s+%-%d+")
    end
    if not split_pos then return nil end

    local ssid = rest:sub(1, split_pos - 1):gsub("^%s+", ""):gsub("%s+$", "")
    local tail = rest:sub(split_pos)
    local freq_str = tail:match("%s+([2567]%d%d%d)")
    local freq_mhz = freq_str and tonumber(freq_str) or nil

    -- First negative integer in tail is signal strength (dBm), before noise floor
    local rssi_str = tail:match("%s+(%-%d+)")
    if not rssi_str then return nil end
    local rssi = tonumber(rssi_str)
    if not rssi or rssi > 0 or rssi < -120 then return nil end

    local low_tail = tail:lower()
    local sec = "open"
    if prefix:find("P", 1, true)
        or low_tail:find("wpa", 1, true)
        or low_tail:find("rsn", 1, true)
        or low_tail:find("aes", 1, true)
        or low_tail:find("tkip", 1, true)
        or low_tail:find("sae", 1, true)
        or low_tail:find("privacy", 1, true)
        or low_tail:find("dot1x", 1, true)
        or low_tail:find("eap", 1, true)
        or low_tail:find("wep", 1, true)
        or low_tail:find("owe", 1, true)
    then
        sec = "wpa2"
    end

    return {
        bssid = mac:upper(),
        ssid = ssid,
        rssi_dbm = rssi,
        security = sec,
        freq_mhz = freq_mhz,
        band = (freq_mhz and freq_mhz >= 4900) and "5g" or "2g",
    }
end

local cmd = arg[1]
if not cmd then
    fail("missing command", 2)
end

if cmd == "list" then
    local known_path = arg[2] or fail("missing known_path", 2)
    local known = load_known(known_path)
    io.stdout:write(jsonc.stringify(redact_known(known)) .. "\n")
    os.exit(0)

elseif cmd == "get-config" then
    local known_path = arg[2] or fail("missing known_path", 2)
    local key = arg[3] or fail("missing key", 2)
    local def = arg[4] or ""
    local known = load_known(known_path)
    local v = known[key]
    if v == nil then
        io.stdout:write(tostring(def) .. "\n")
    else
        io.stdout:write(tostring(v) .. "\n")
    end
    os.exit(0)

elseif cmd == "is-trusted" then
    local known_path = arg[2] or os.exit(1)
    local ssid = arg[3] or ""
    if #ssid == 0 then os.exit(1) end
    local known = load_known(known_path)
    local net = find_known_network(known, ssid)
    if net and net.trusted == true and net.security ~= "open" and type(net.psk) == "string" and #net.psk > 0 then
        os.exit(0)
    end
    os.exit(1)

elseif cmd == "upsert" then
    local known_path = arg[2] or fail("missing known_path", 2)
    local raw = io.stdin:read("*a") or ""
    local body = jsonc.parse(raw)
    if type(body) ~= "table" then
        fail("invalid JSON body", 2)
    end
    local ssid = body.ssid
    if type(ssid) ~= "string" or #ssid == 0 or #ssid > 32 or has_control_chars(ssid) then
        fail("invalid ssid (1-32 printable bytes required)", 2)
    end

    local known = load_known(known_path)
    local existing, idx = find_known_network(known, ssid)

    local psk = body.psk
    if psk == nil and existing and body.security ~= "open" then
        psk = existing.psk or ""
    end
    if psk == nil then psk = "" end
    if type(psk) ~= "string" or has_control_chars(psk) or #psk > 64 then
        fail("invalid psk", 2)
    end

    local sec = body.security
    if sec == nil or sec == "" then
        sec = (#psk > 0) and "wpa2" or "open"
    end
    if sec ~= "wpa2" and sec ~= "wpa3" and sec ~= "open" then
        fail("invalid security (allowed: wpa2|wpa3|open)", 2)
    end
    if sec == "open" then
        psk = ""
    end

    local trusted = (body.trusted == true)
    if trusted and (sec == "open" or #psk == 0) then
        fail("evil-twin protection: trusted=true requires WPA2/WPA3 security and non-empty psk", 2)
    end

    local priority = tonumber(body.priority)
    if not priority then
        priority = existing and tonumber(existing.priority) or (trusted and 10 or 50)
    end
    if priority < 1 then priority = 1 end
    if priority > 999 then priority = 999 end

    local entry = {
        ssid = ssid,
        security = sec,
        psk = psk,
        trusted = trusted,
        priority = math.floor(priority),
    }
    if idx then
        known.networks[idx] = entry
    else
        table.insert(known.networks, entry)
    end
    sort_networks(known.networks)
    write_atomic(known_path, jsonc.stringify(known), true)
    io.stdout:write(jsonc.stringify({
        ok = true,
        ssid = ssid,
        security = sec,
        trusted = trusted,
        priority = entry.priority,
        has_psk = (#psk > 0),
    }) .. "\n")
    os.exit(0)

elseif cmd == "delete" or cmd == "delete-stdin" then
    local known_path = arg[2] or fail("missing known_path", 2)
    local ssid = nil
    if cmd == "delete-stdin" or arg[3] == nil then
        local body = jsonc.parse(io.stdin:read("*a") or "")
        ssid = type(body) == "table" and body.ssid or nil
    else
        ssid = arg[3]
    end
    if type(ssid) ~= "string" or #ssid == 0 then
        fail("missing ssid", 2)
    end
    local known = load_known(known_path)
    local kept = {}
    local removed = false
    for _, n in ipairs(known.networks or {}) do
        if n.ssid == ssid then
            removed = true
        else
            table.insert(kept, n)
        end
    end
    known.networks = kept
    write_atomic(known_path, jsonc.stringify(known), true)
    io.stdout:write(jsonc.stringify({ ok = true, ssid = ssid, deleted = removed }) .. "\n")
    os.exit(0)

elseif cmd == "block" or cmd == "unblock" or cmd == "block-stdin" or cmd == "unblock-stdin" then
    local known_path = arg[2] or fail("missing known_path", 2)
    local is_stdin = (cmd == "block-stdin" or cmd == "unblock-stdin")
    local base_cmd = (cmd == "block" or cmd == "block-stdin") and "block" or "unblock"
    local pat = nil
    if is_stdin or arg[3] == nil then
        local body = jsonc.parse(io.stdin:read("*a") or "")
        pat = type(body) == "table" and body.pattern or nil
    else
        pat = arg[3]
    end
    if type(pat) ~= "string" or #pat == 0 or #pat > 64 or has_control_chars(pat) then
        fail("invalid blocklist pattern", 2)
    end
    local known = load_known(known_path)
    if base_cmd == "block" then
        local exists = false
        for _, p in ipairs(known.blocklist or {}) do
            if p == pat then exists = true; break end
        end
        if not exists then
            table.insert(known.blocklist, pat)
        end
    else
        local kept = {}
        for _, p in ipairs(known.blocklist or {}) do
            if p ~= pat then table.insert(kept, p) end
        end
        known.blocklist = kept
    end
    write_atomic(known_path, jsonc.stringify(known), true)
    io.stdout:write(jsonc.stringify({ ok = true, action = base_cmd, pattern = pat, blocklist = known.blocklist }) .. "\n")
    os.exit(0)

elseif cmd == "set-config" then
    local known_path = arg[2] or fail("missing known_path", 2)
    local body = jsonc.parse(io.stdin:read("*a") or "")
    if type(body) ~= "table" then
        fail("invalid JSON config body", 2)
    end
    local known = load_known(known_path)
    if type(body.auto_hunt) == "boolean" then known.auto_hunt = body.auto_hunt end
    if type(body.allow_xfinity) == "boolean" then known.allow_xfinity = body.allow_xfinity end
    if type(body.allow_open_wifi) == "boolean" then known.allow_open_wifi = body.allow_open_wifi end
    if type(body.min_rssi_dbm) == "number" then
        local r = math.floor(body.min_rssi_dbm)
        if r >= -100 and r <= -30 then known.min_rssi_dbm = r end
    end
    if type(body.cooldown_sec) == "number" then
        local c = math.floor(body.cooldown_sec)
        if c >= 60 and c <= 86400 then known.cooldown_sec = c end
    end
    write_atomic(known_path, jsonc.stringify(known), true)
    io.stdout:write(jsonc.stringify({
        ok = true,
        config = {
            auto_hunt = known.auto_hunt,
            allow_xfinity = known.allow_xfinity,
            allow_open_wifi = known.allow_open_wifi,
            min_rssi_dbm = known.min_rssi_dbm,
            cooldown_sec = known.cooldown_sec,
        },
    }) .. "\n")
    os.exit(0)

elseif cmd == "rank-scan" then
    local known_path = arg[2] or fail("missing known_path", 2)
    local state_path = arg[3] or ""
    local now = tonumber(arg[4]) or os.time()
    local include_cooled = (arg[5] == "--include-cooled")

    local known = load_known(known_path)
    local state = (#state_path > 0) and load_state(state_path) or { cooldowns = {} }
    local raw = io.stdin:read("*a") or ""

    local by_bssid = {}
    for line in raw:gmatch("[^\r\n]+") do
        local row = parse_scan_line(line)
        if row and #row.ssid > 0 then
            local prev = by_bssid[row.bssid]
            if not prev or row.rssi_dbm > prev.rssi_dbm then
                by_bssid[row.bssid] = row
            end
        end
    end

    local ranked = {}
    for _, row in pairs(by_bssid) do
        local keep = true
        if row.rssi_dbm < known.min_rssi_dbm then
            keep = false
        elseif has_control_chars(row.ssid) then
            keep = false
        elseif is_blocklisted(known.blocklist, row.ssid) then
            keep = false
        end

        local cd = state.cooldowns and state.cooldowns[row.bssid] or nil
        local cooled = (type(cd) == "table" and tonumber(cd.until_ts or cd["until"]) and (tonumber(cd.until_ts or cd["until"]) > now)) or false
        if cooled and not include_cooled then
            keep = false
        end

        if keep then
            local net = find_known_network(known, row.ssid)
            local tier = nil
            local trusted = false
            local profile = nil
            local priority = 500
            local vpn_required = true

            if net and net.security ~= "open" and type(net.psk) == "string" and #net.psk > 0 and row.security ~= "open" then
                if net.trusted == true then
                    tier = 1
                    trusted = true
                    vpn_required = false
                else
                    tier = 2
                    trusted = false
                    vpn_required = true
                end
                profile = "van-psk"
                priority = tonumber(net.priority) or 50
            elseif net and net.security ~= "open" and row.security == "open" then
                -- Evil-twin defense: NEVER promote an open AP spoofing a saved WPA2/WPA3 SSID
                tier = nil
            elseif net and net.security == "open" and row.security == "open" then
                if not has_hostile_ros_chars(row.ssid) then
                    tier = 2
                    trusted = false
                    vpn_required = true
                    profile = "van-open"
                    priority = tonumber(net.priority) or 50
                end
            elseif row.security == "open" then
                -- Reject unknown/open SSIDs with RouterOS injection metacharacters
                if not has_hostile_ros_chars(row.ssid) then
                    if known.allow_xfinity and row.ssid:lower() == "xfinitywifi" then
                        tier = 3
                        trusted = false
                        vpn_required = true
                        profile = "van-open"
                    elseif known.allow_open_wifi then
                        tier = 4
                        trusted = false
                        vpn_required = true
                        profile = "van-open"
                    end
                end
            end

            if tier then
                table.insert(ranked, {
                    ssid = row.ssid,
                    bssid = row.bssid,
                    rssi_dbm = row.rssi_dbm,
                    security = row.security,
                    freq_mhz = row.freq_mhz,
                    band = row.band,
                    tier = tier,
                    priority = priority,
                    trusted = trusted,
                    vpn_required = vpn_required,
                    profile = profile,
                    cooled_down = cooled,
                    cooldown_reason = cooled and cd.reason or nil,
                })
            end
        end
    end

    table.sort(ranked, function(a, b)
        if a.tier ~= b.tier then return a.tier < b.tier end
        if a.priority ~= b.priority then return a.priority < b.priority end
        if a.rssi_dbm ~= b.rssi_dbm then return a.rssi_dbm > b.rssi_dbm end
        return a.ssid < b.ssid
    end)

    io.stdout:write(jsonc.stringify(ranked) .. "\n")
    os.exit(0)

elseif cmd == "ros-connect-cmd" or cmd == "ros-connect-cmd-stdin" then
    local known_path = arg[2] or fail("missing known_path", 2)
    local ssid = nil
    local bssid = ""
    local band = ""
    if cmd == "ros-connect-cmd-stdin" then
        local body = jsonc.parse(io.stdin:read("*a") or "")
        if type(body) ~= "table" then fail("invalid connect json", 2) end
        ssid = body.ssid
        bssid = (type(body.bssid) == "string") and body.bssid or ""
        band = (type(body.band) == "string") and body.band or ""
    else
        ssid = arg[3]
        bssid = arg[4] or ""
        band = arg[5] or ""
    end
    if type(ssid) ~= "string" or #ssid == 0 or #ssid > 32 or has_control_chars(ssid) then
        fail("invalid ssid", 2)
    end
    if #bssid > 0 and not bssid:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") then
        fail("invalid bssid", 2)
    end

    local band_prefix = ""
    if band == "5g" then
        band_prefix = ':if ([/interface wireless get [find default-name=wlan1] interface-type] ~ "AR9300") do={ /interface wireless set [find default-name=wlan1] band=5ghz-a/n channel-width=20/40mhz-XX } else={ :do { /interface wireless set [find default-name=wlan1] band=5ghz-a/n/ac channel-width=20/40/80mhz-XXXX } on-error={ /interface wireless set [find default-name=wlan1] band=5ghz-a/n channel-width=20/40mhz-XX } }; '
    elseif band == "2g" then
        band_prefix = '/interface wireless set [find default-name=wlan1] band=2ghz-b/g/n channel-width=20/40mhz-XX; '
    end

    local known = load_known(known_path)
    local net = find_known_network(known, ssid)
    if net and net.security ~= "open" and type(net.psk) == "string" and #net.psk > 0 then
        if has_control_chars(net.psk) or #net.psk > 64 then
            fail("corrupted psk contains control characters", 2)
        end
        local esc_ssid = escape_ros_string(ssid)
        local esc_psk = escape_ros_string(net.psk)
        local auth_types = (net.security == "wpa3") and "wpa2-psk,wpa3-psk" or "wpa2-psk"
        local clist = '/interface wireless connect-list remove [find comment="van-hunter"]; '
        if #bssid > 0 then
            clist = clist .. string.format(
                '/interface wireless connect-list add comment="van-hunter" interface=wlan1 mac-address=%s ssid="%s" security-profile="van-psk" connect=yes; ',
                bssid:upper(), esc_ssid
            )
        end
        io.stdout:write(string.format(
            '%s/interface wireless security-profiles set [find name="van-psk"] mode=dynamic-keys authentication-types=%s wpa2-pre-shared-key="%s"; %s/interface wireless set [find default-name=wlan1] security-profile="van-psk" ssid="%s"\n',
            band_prefix, auth_types, esc_psk, clist, esc_ssid
        ))
        os.exit(0)
    else
        if has_hostile_ros_chars(ssid) then
            fail("rejected hostile metacharacters in open ssid", 2)
        end
        local esc_ssid = escape_ros_string(ssid)
        local clist = '/interface wireless connect-list remove [find comment="van-hunter"]; '
        if #bssid > 0 then
            clist = clist .. string.format(
                '/interface wireless connect-list add comment="van-hunter" interface=wlan1 mac-address=%s ssid="%s" security-profile="van-open" connect=yes; ',
                bssid:upper(), esc_ssid
            )
        end
        io.stdout:write(string.format(
            '%s%s/interface wireless set [find default-name=wlan1] security-profile="van-open" ssid="%s"\n',
            band_prefix, clist, esc_ssid
        ))
        os.exit(0)
    end

elseif cmd == "lookup-band" then
    local state_path = arg[2] or fail("missing state_path", 2)
    local target_ssid = arg[3] or ""
    local target_bssid = (arg[4] or ""):upper()
    local state = load_state(state_path)
    local cands = type(state.last_candidates) == "table" and state.last_candidates or {}
    local found = ""
    for _, c in ipairs(cands) do
        if type(c) == "table" and (c.band == "5g" or c.band == "2g") then
            if #target_bssid > 0 and type(c.bssid) == "string" and c.bssid:upper() == target_bssid then
                found = c.band
                break
            elseif found == "" and c.ssid == target_ssid then
                found = c.band
            end
        end
    end
    io.stdout:write(found .. "\n")
    os.exit(0)

elseif cmd == "cooldown" then
    local state_path = arg[2] or fail("missing state_path", 2)
    local bssid = (arg[3] or ""):upper()
    local reason = arg[4] or "failed"
    local until_ts = tonumber(arg[5]) or (os.time() + 7200)
    if not bssid:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") then
        fail("invalid bssid", 2)
    end
    local state = load_state(state_path)
    local now = os.time()
    -- Prune expired cooldowns
    for k, v in pairs(state.cooldowns) do
        local u = type(v) == "table" and tonumber(v["until"] or v.until_ts) or 0
        if u <= now then state.cooldowns[k] = nil end
    end
    state.cooldowns[bssid] = { ["until"] = math.floor(until_ts), reason = reason }
    write_atomic(state_path, jsonc.stringify(state), false)
    io.stdout:write(jsonc.stringify({ ok = true, bssid = bssid, reason = reason, ["until"] = math.floor(until_ts) }) .. "\n")
    os.exit(0)

elseif cmd == "update-state" then
    local state_path = arg[2] or fail("missing state_path", 2)
    local patch = jsonc.parse(io.stdin:read("*a") or "")
    if type(patch) ~= "table" then fail("invalid state patch json", 2) end
    local state = load_state(state_path)
    for k, v in pairs(patch) do
        if k ~= "cooldowns" then
            state[k] = v
        end
    end
    write_atomic(state_path, jsonc.stringify(state), false)
    io.stdout:write(jsonc.stringify({ ok = true }) .. "\n")
    os.exit(0)

elseif cmd == "candidates-tsv" then
    local arr = jsonc.parse(io.stdin:read("*a") or "")
    if type(arr) ~= "table" then os.exit(0) end
    for _, c in ipairs(arr) do
        if type(c) == "table" and type(c.ssid) == "string" and type(c.bssid) == "string" then
            io.stdout:write(string.format("%s\t%s\t%s\n", c.bssid, c.trusted and "1" or "0", c.ssid))
        end
    end
    os.exit(0)

else
    fail("unknown command: " .. tostring(cmd), 2)
end
