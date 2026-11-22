#!/usr/bin/env lua
-- Native OpenWrt Lua + luci.jsonc test suite for networks.lua.
-- Executed on GL-MT3000's real /usr/bin/lua interpreter.

local jsonc = require("luci.jsonc")

local script = arg[1] or "/tmp/networks.lua"
local tmpdir = arg[2] or "/tmp/test_networks_lua"
os.execute("rm -rf " .. tmpdir .. " && mkdir -p " .. tmpdir)

local known = tmpdir .. "/known_networks.json"
local state = tmpdir .. "/hunter_state.json"

local function run_cmd(cmd, stdin_data)
    local in_file = tmpdir .. "/stdin.tmp"
    local out_file = tmpdir .. "/stdout.tmp"
    if stdin_data then
        local f = assert(io.open(in_file, "w"))
        f:write(stdin_data)
        f:close()
        cmd = cmd .. " < " .. in_file
    end
    local rc = os.execute(cmd .. " > " .. out_file .. " 2>&1")
    local f = assert(io.open(out_file, "r"))
    local out = f:read("*a")
    f:close()
    -- Lua 5.1 returns exit code * 256; Lua 5.2+ returns boolean
    local ok = (rc == 0 or rc == true)
    return ok, out
end

local function assert_eq(actual, expected, msg)
    if actual ~= expected then
        error(string.format("ASSERT FAIL (%s): expected=%s actual=%s", msg or "", tostring(expected), tostring(actual)))
    end
end

-- 1. Reject trusted:true on open network or empty PSK
local ok1, out1 = run_cmd(
    "lua " .. script .. " upsert " .. known,
    jsonc.stringify({ ssid = "EvilOpen", security = "open", psk = "", trusted = true })
)
assert_eq(ok1, false, "trusted open network must be rejected")

local ok2, out2 = run_cmd(
    "lua " .. script .. " upsert " .. known,
    jsonc.stringify({ ssid = "EmptyPsk", security = "wpa2", psk = "", trusted = true })
)
assert_eq(ok2, false, "trusted empty-psk network must be rejected")

-- 2. Upsert trusted WPA2 + untrusted WPA2 + open, verify PSK redaction in list
local ok3, out3 = run_cmd(
    "lua " .. script .. " upsert " .. known,
    jsonc.stringify({ ssid = "HomeWiFi", security = "wpa2", psk = 'Sup3r$ecret"[\\]!', trusted = true, priority = 10 })
)
assert_eq(ok3, true, "upsert trusted wpa2: " .. out3)

local ok4, out4 = run_cmd(
    "lua " .. script .. " upsert " .. known,
    jsonc.stringify({ ssid = "Campground WPA", security = "wpa2", psk = "camp1234", trusted = false, priority = 20 })
)
assert_eq(ok4, true, "upsert untrusted wpa2: " .. out4)

local ok_list, out_list = run_cmd("lua " .. script .. " list " .. known)
assert_eq(ok_list, true, "list failed: " .. out_list)
local parsed_list = assert(jsonc.parse(out_list), "list must return valid JSON: " .. out_list)
assert_eq(#parsed_list.networks, 2, "expected 2 networks")
assert_eq(parsed_list.networks[1].ssid, "HomeWiFi", "first network should be trusted HomeWiFi")
assert_eq(parsed_list.networks[1].psk, nil, "psk MUST be redacted from list")
assert_eq(parsed_list.networks[1].has_psk, true, "has_psk must be true")
assert_eq(out_list:find("Sup3r", 1, true), nil, "raw psk substring must NEVER appear in list output")

-- 3. is-trusted checks
local ok_tr, _ = run_cmd("lua " .. script .. " is-trusted " .. known .. ' "HomeWiFi"')
assert_eq(ok_tr, true, "HomeWiFi should be trusted")
local ok_untr, _ = run_cmd("lua " .. script .. " is-trusted " .. known .. ' "Campground WPA"')
assert_eq(ok_untr, false, "Campground WPA should NOT be trusted")
local ok_unk, _ = run_cmd("lua " .. script .. " is-trusted " .. known .. ' "xfinitywifi"')
assert_eq(ok_unk, false, "xfinitywifi should NOT be trusted")

-- 4. Cooldown a BSSID and test rank-scan (RouterOS v6 + v7 + hostile SSIDs + weak RSSI + blocklist)
local now = 1700000000
local ok_cd, out_cd = run_cmd("lua " .. script .. " cooldown " .. state .. " CC:CC:CC:CC:CC:CC vpn_blocked " .. tostring(now + 7200))
assert_eq(ok_cd, true, "cooldown failed: " .. out_cd)

local scan_sample = table.concat({
    "Flags: A - active, B - bss",
    "   ADDRESS           SSID                      CHANNEL        SIG   NF   SNR  SECURITY",
    "AB AA:AA:AA:AA:AA:01 HomeWiFi              2412/20-Ce/gn  -60  -104  44  wpa2-psk",
    "AB AA:AA:AA:AA:AA:02 HomeWiFi              2437/20        -45  -104  59  none",
    "AB BB:BB:BB:BB:BB:01 Campground WPA            5180/20-Ceee   -64  -100  36  wpa2-psk",
    "AB CC:CC:CC:CC:CC:CC Cooled Open WiFi          2412/20        -50  -100  50  none",
    "AB DD:DD:DD:DD:DD:01 xfinitywifi               5220/ac        -66  -100  34  open",
    "AB EE:EE:EE:EE:EE:01 Free Cafe WiFi            2462/20        -62  -100  38  none",
    "AB FF:FF:FF:FF:FF:01 FreeWiFi[/system reboot]  2412/20        -40  -100  60  none",
    "AB FF:FF:FF:FF:FF:02 Bad$SSID                  2412/20        -41  -100  59  none",
    "AB 11:22:33:44:55:01 TravelAP 5G          5180/ax        -35  -100  65  wpa2-psk",
    "AB 11:22:33:44:55:02 Weak Open                 2412/20        -85  -100  15  none",
    "AB 11:22:33:44:55:03 Unknown Private WPA       5200/ac        -52  -100  48  wpa2-psk",
    "AB 11:22:33:44:55:04 Campground 2026           2437/20        -63  -100  37  none",
    "AB 11:22:33:44:55:05 HomeWiFi 2412/20 -30 wpa2 2462/20        -67  -100  33  none",
    "AB 11:22:33:44:55:06 HomeWiFi 2412/x -30 wpa2  5180           -68  -100  32  none",
}, "\n")

local ok_rank, out_rank = run_cmd("lua " .. script .. " rank-scan " .. known .. " " .. state .. " " .. tostring(now), scan_sample)
assert_eq(ok_rank, true, "rank-scan failed: " .. out_rank)
local ranked = assert(jsonc.parse(out_rank), "rank-scan invalid JSON: " .. out_rank)

-- Expect: 1) HomeWiFi (WPA2, Tier 1), 2) Campground WPA (Tier 2), 3) xfinitywifi (Tier 3), 4) Free Cafe WiFi & Campground 2026 (Tier 4)
assert_eq(ranked[1].ssid, "HomeWiFi", "rank 1 must be trusted WPA2 HomeWiFi")
assert_eq(ranked[1].tier, 1, "rank 1 must be tier 1")
assert_eq(ranked[1].trusted, true, "rank 1 must be trusted")
assert_eq(ranked[1].profile, "van-psk", "rank 1 must use van-psk")
assert_eq(ranked[2].ssid, "Campground WPA", "rank 2 must be Campground WPA")
assert_eq(ranked[2].tier, 2, "rank 2 must be tier 2")
assert_eq(ranked[2].trusted, false, "rank 2 must not be trusted")
assert_eq(ranked[3].ssid, "xfinitywifi", "rank 3 must be xfinitywifi")
assert_eq(ranked[3].tier, 3, "rank 3 must be tier 3")
assert_eq(ranked[3].profile, "van-open", "rank 3 must use van-open")

-- Verify hostile SSIDs, weak RSSI, blocklisted TravelAP, cooled BSSID, unknown WPA2, AND open evil twin of saved WPA2 are NOT in ranked
local saw_2026 = false
for _, c in ipairs(ranked) do
    assert(c.ssid:find("[", 1, true) == nil, "hostile bracket SSID leaked into ranked: " .. c.ssid)
    assert(c.ssid:find("$", 1, true) == nil, "hostile dollar SSID leaked into ranked: " .. c.ssid)
    assert(c.bssid ~= "CC:CC:CC:CC:CC:CC", "cooled BSSID leaked into ranked")
    assert(c.ssid ~= "TravelAP 5G", "blocklisted SSID leaked into ranked")
    assert(c.ssid ~= "Weak Open", "weak RSSI SSID leaked into ranked")
    assert(c.ssid ~= "Unknown Private WPA", "unknown WPA2 without PSK leaked into ranked")
    assert(c.bssid ~= "AA:AA:AA:AA:AA:02", "open evil twin of saved WPA2 HomeWiFi must be excluded!")
    if c.bssid == "11:22:33:44:55:05" then
        assert_eq(c.ssid, "HomeWiFi 2412/20 -30 wpa2", "crafted 32-byte SSID must not truncate to HomeWiFi")
        assert_eq(c.security, "open", "crafted SSID must not spoof wpa2 security")
        assert_eq(c.rssi_dbm, -67, "crafted SSID must not spoof RSSI -30")
        assert_eq(c.trusted, false, "crafted SSID must NEVER be trusted")
        assert_eq(c.tier, 4, "crafted open SSID must stay Tier 4")
    end
    if c.bssid == "11:22:33:44:55:06" then
        assert_eq(c.ssid, "HomeWiFi 2412/x -30 wpa2", "non-slash channel rightmost anchor must beat crafted SSID")
        assert_eq(c.security, "open", "crafted non-slash SSID must not spoof wpa2 security")
        assert_eq(c.rssi_dbm, -68, "crafted non-slash SSID must not spoof RSSI -30")
        assert_eq(c.trusted, false, "crafted non-slash SSID must NEVER be trusted")
    end
    if c.ssid == "Campground 2026" then saw_2026 = true end
end
assert_eq(saw_2026, true, "SSID with 4-digit year 'Campground 2026' must not be truncated")

-- 5. RouterOS connect command generation & escaping
local ok_cmd1, cmd1 = run_cmd("lua " .. script .. " ros-connect-cmd " .. known .. ' "HomeWiFi" "AA:AA:AA:AA:AA:01"')
assert_eq(ok_cmd1, true, "ros-connect-cmd wpa2 failed: " .. cmd1)
assert(cmd1:find('security-profile="van-psk"', 1, true) ~= nil, "must select van-psk: " .. cmd1)
assert(cmd1:find('Sup3r\\$ecret\\"\\[\\\\]', 1, true) ~= nil, "must escape $, \", [, \\ in PSK: " .. cmd1)
assert(cmd1:find('bssid="AA:AA:AA:AA:AA:01"', 1, true) ~= nil, "must set bssid: " .. cmd1)

local ok_cmd2, cmd2 = run_cmd("lua " .. script .. " ros-connect-cmd " .. known .. ' "xfinitywifi"')
assert_eq(ok_cmd2, true, "ros-connect-cmd open failed: " .. cmd2)
assert(cmd2:find('security-profile="van-open"', 1, true) ~= nil, "must select van-open: " .. cmd2)
assert(cmd2:find('bssid=""', 1, true) ~= nil, "must clear bssid when omitted: " .. cmd2)

local ok_cmd_bad, _ = run_cmd("lua " .. script .. " ros-connect-cmd " .. known .. ' "Bad[/system reboot]"')
assert_eq(ok_cmd_bad, false, "ros-connect-cmd must reject hostile open SSID")

-- 6. set-config, block, delete
local ok_cfg, out_cfg = run_cmd(
    "lua " .. script .. " set-config " .. known,
    jsonc.stringify({ auto_hunt = false, allow_open_wifi = false, min_rssi_dbm = -72 })
)
assert_eq(ok_cfg, true, "set-config failed: " .. out_cfg)
local ok_get, out_get = run_cmd("lua " .. script .. " get-config " .. known .. " auto_hunt")
assert_eq(ok_get, true, "get-config failed")
assert_eq(out_get:gsub("%s+", ""), "false", "auto_hunt should be false")

local ok_del, _ = run_cmd("lua " .. script .. " delete " .. known .. ' "Campground WPA"')
assert_eq(ok_del, true, "delete failed")
local _, out_list2 = run_cmd("lua " .. script .. " list " .. known)
local parsed2 = assert(jsonc.parse(out_list2))
assert_eq(#parsed2.networks, 1, "expected 1 network after delete")

os.execute("rm -rf " .. tmpdir)
print("LUA_NETWORKS_CHECK_OK")
