# glinet-zero-cloud

A self-hosted, zero-cloud management plane and mobile router stack for GL.iNet hardware (built in response to CSA-2026-01). No vendor cloud agents, no Docker overhead, and no cleartext leaks on untrusted Wi-Fi.

It ships as two modular components you can run together or independently:

1. **Private Management Portal (`src/`, `deploy/deploy.sh`)**: A ~20 MB RAM Python stdlib + isolated nginx control plane behind Tailscale Serve for GL.iNet KVMs (`RM1` / `RM1PE` / `RM10`) and OpenWrt routers.
2. **Fail-Closed VPN Gate, Multi-WAN Failover & Autonomous Wi-Fi Hunter (`router/`)**: A standalone OpenWrt / GL.iNet daemon (`van-wan-guard`) that prioritizes roof/external Wi-Fi over metered cellular or Starlink Roam (50 GB cap) while blocking all cleartext IPv4/IPv6/DNS traffic until WireGuard verifies inside the tunnel.

---

## Why This Exists

After the November 20, 2026 GoodCloud incident (CSA-2026-01), keeping `gl-cloud` or `rtty` enabled on routers and IP-KVMs isn't acceptable. Existing self-hosted replacements still pull in Docker stacks or relay servers, and travel routers running stock multi-WAN don't enforce a fail-closed VPN gate before routing clients onto campground or public Wi-Fi.

This repo keeps the footprint minimal:

- **Zero third-party Python dependencies**: Pure Python 3 stdlib on the gateway host, ~17 MB RSS for the portal and ~3 MB RSS for isolated nginx.
- **Targeted for GL.iNet 4.x / OpenWrt 21.02 (`fw3`/`iptables`)**: Runs on stock GL.iNet firmware (`ash`, `awk`, `fw3`/`iptables`, `ip6tables`, `wg`, `curl`, `dbclient`, `scp`, `uhttpd`, and built-in `/usr/bin/lua` + `luci.jsonc`). *(OpenWrt 22.03-24.10 `fw4`/`nftables` is not supported yet and `setup-mt3000.sh` explicitly aborts if `fw4` is detected so it can never boot fail-open.)*
- **Fail-closed from boot**: Unconditional `eth0` forwarding (`FORWARD` index 1, above `RELATED,ESTABLISHED`), router DNS (`OUTPUT` `:53`/`:853`), and IPv6 on the Wi-Fi WAN interface default to `REJECT` before the daemon even starts.

---

## Component 1: Private GL.iNet Management Portal

Runs on any Linux systemd gateway, Raspberry Pi, or homelab VM with `python3`, `nginx`, and `tailscale`.

### Features
- **Tailscale Identity Allowlist + CSRF Protection**: Verifies `Tailscale-User-Login` (or allowlisted rightmost `X-Forwarded-For` for tagged tailnet servers) at both nginx and Python layers. State-changing `POST` endpoints require `X-Portal-Action: 1` and matching `Origin`.
- **MAC-Driven IP Auto-Healing**: Resolves devices across WireGuard (`wg show dump`), Linux neighbor tables (`ip -4 neigh`), and `dnsmasq` leases, then atomically validates (`nginx -t`) and reloads upstreams with rollback on error.
- **Conntrack Egress Guardrail**: When deployed on an L3 Linux gateway (`ip_forward=1` + `/proc/net/nf_conntrack`), polls IPv4/IPv6 conntrack for GoodCloud/C2 ports (`18883`, `28883`, `3900`, `5912`, `5913`, `8899`), published CSA-2026-01 attacker IPs, and unexpected KVM WAN egress. On non-gateway hosts (like a Pi or VM), the UI displays `UNAVAILABLE (NON-GATEWAY HOST)` instead of a false-green banner.
- **On-Demand CSA-2026-01 Triage & Cloud Kill**: Streams an upstream read-only triage script (such as [admonstrator/glinet-csa-2026-01](https://github.com/admonstrator/glinet-csa-2026-01)) over SSH with per-device `409 Conflict` locking, plus one-click `gl-cloud`/`rtty` shutdown. Includes `-o IPQoS=none` to prevent post-auth DSCP drops observed on GL-MT3000 firmware `4.11.1`.

### Quickstart (Portal)

```bash
cp config/devices.example.json config/devices.json
# Edit config/devices.json with your tailscale_host, allowed_tailscale_users, and device MACs

# Optional: download the upstream CSA-2026-01 triage script and verify its checksum before deploying
# mkdir -p vendor && curl -fL -o vendor/gl-helper-triage.sh <upstream-raw-url>

GATEWAY_HOST=root@<your-gateway-ip> ./deploy/deploy.sh
```

`deploy.sh` runs the local unit tests, renders `nginx.conf` and systemd units dynamically from `config/devices.json`, provisions a dedicated Ed25519 key on the gateway, and configures `tailscale serve --bg` (never `tailscale funnel`).

---

## Component 2: `van-wan-guard` (Fail-Closed VPN Gate + Multi-WAN + Wi-Fi Hunter)

Standalone OpenWrt / GL.iNet stack tested on **GL-MT3000 (Beryl AX, firmware `4.8.1` and `4.11.1_release3`)** with a roof/external **MikroTik GrooveA-52** on `eth0` and **Starlink** (or metered LTE/5G) on `eth1`.

### Zero-Leak VPN-Before-Routing Invariant
1. **Boot-Time Lockdown**: `/etc/firewall.user` (`reload=1`) inserts `VAN_CPE_GATE` (`REJECT`) unconditionally on `eth0` at `FORWARD` rule 1 (above `RELATED,ESTABLISHED`), `VAN_CPE_DNS_OUT` (`REJECT` UDP/TCP `53` and TCP `853`) on `OUTPUT`, `OUTPUT -m mark --mark 0x101 ! -o eth0 -j DROP`, and `ip6tables` `REJECT` on `eth0` alongside `disable_ipv6=1`. State transitions are serialized with a `mkdir` lock and insert `REJECT` at index 1 before trimming old rules (zero empty-chain window).
2. **Strict Interface-Pinned WireGuard (`wg_van`)**: Uses `fwmark 0x101` routed exclusively through `eth0` (`table 101`, `prio 85`) with terminal `prio 86 unreachable` (`fwmark 0x101`), `prio 90 unreachable` (`from wg_van_ip`), and `prio 97`/`98 unreachable` (`iif br-lan`/`br-guest` in `vpn_active`) so neither tunnel transport nor client traffic can fall through to Starlink if `wg_van` flaps.
3. **3-Gate Verification Before Routing Clients**:
   - **Gate 1**: `eth0` ICMP probe using configured `ping_targets` (`loss <= 20%`, `rtt < 300 ms`).
   - **Gate 2**: `eth0` HTTP `204` captive-portal check resolved via `eth0`-bound DoH (`curl --resolve`) with direct IPv4 fallback (zero `dnsmasq` deadlock when Starlink is offline).
   - **Gate 3**: `wg_van` route check (`ip route get`), handshake age `<= 150 s`, AND in-tunnel `ping -I <wg_van_ip> <wg_peer_ip>` success.
4. **Encrypted DNS**: Once Gate 3 passes, clients route via `table 103` (`wg_van`) and `dnsmasq` forwards exclusively to `<wg_peer_ip>` inside the tunnel. WireGuard DDNS updates use `eth0`-bound DoH (`https://1.1.1.1/dns-query`) to avoid DNS deadlocks.
5. **Evil-Twin & Captive Portal Discipline**: `trusted: true` (direct routing without VPN) is strictly rejected for open or empty-PSK networks. Explicit `captive_login` mode opens only TCP `80,443` and UDP/TCP `53` for up to 10 minutes, then snaps `VAN_CPE_GATE` back to `REJECT` the instant HTTP `204` clears (even if the AP blocks WireGuard).

### Autonomous Wi-Fi Hunter & Importer
- **Least-Privilege RouterOS Access**: Drives a MikroTik CPE over Dropbear SSH using a dedicated `hunter` group (`ssh,read,write` only: no `policy`, `ftp`, `winbox`, or `reboot`).
- **Hostile SSID Defense & PSK Secrecy**: `networks.lua` rejects open/unknown SSIDs containing RouterOS metacharacters (`[ ] $ " \ \` ;` or control chars), excludes open evil twins of saved WPA2 networks, writes `known_networks.json` atomically under `umask 077`, redacts PSKs from all `GET` responses, and uploads `van-psk` commands via `0600` temp `.rsc` + `scp` so plaintext PSKs never appear in `dbclient` `argv`.
- **Priority Ranking & Cooldowns**: Tier 1 Trusted WPA2/WPA3, Tier 2 Saved WPA2/WPA3 (VPN-gated), Tier 3 `xfinitywifi` (VPN-gated), Tier 4 Open Wi-Fi (optional, VPN-gated). APs that fail Gate 3 receive a 2-hour `vpn_blocked` cooldown.
- **Offline Phone UI**: Served locally at `http://192.168.8.1:8080/van/` with CSRF checks (`X-Van-Action: 1` + `Origin`), VPN security badge, mode toggles, Starlink monthly budget bar, Scan & Connect, and Known Wi-Fi editor.
- **Wi-Fi Importer (`deploy/import-wifi.py`)**: Imports profiles from Linux NetworkManager (`--from-nm --list`, opt-in `--ssid`), Android Share Wi-Fi QR (`--from-qr -` via stdin), or Android `WifiConfigStore.xml` and pushes them over SSH stdin.

### Quickstart (Router)

```bash
# 1. Install van-wan-guard, fail-closed firewall hooks, Lua engine, and offline UI
./deploy/setup-mt3000.sh --host root@192.168.8.1 \
  --wg-conf wg-mgmt.conf \
  --wg-van-conf wg-van-full.conf

# 2. (Optional) Provision least-privilege RouterOS 'hunter' user & profiles on MikroTik CPE
./deploy/setup-groove.sh 192.168.88.1 admin

# 3. Import saved Wi-Fi networks securely via SSH stdin
sudo ./deploy/import-wifi.py --from-nm --list
sudo ./deploy/import-wifi.py --from-nm --ssid "MyHomeWiFi" --trusted --host root@192.168.8.1
```

---

## Testing

```bash
sh -n router/etc/firewall.user router/etc/hotplug.d/firewall/90-van-wan-guard router/usr/bin/van-wan router/www/cgi-bin/van-wan router/usr/libexec/van-wan-guard/*.sh
bash -n deploy/*.sh
PYTHONPATH=src:deploy pytest -v
```

To verify `networks.lua` on real OpenWrt `/usr/bin/lua` + `luci.jsonc`:

```bash
scp -O router/usr/libexec/van-wan-guard/networks.lua tests/lua_networks_check.lua root@<router>:/tmp/
ssh root@<router> 'lua /tmp/lua_networks_check.lua /tmp/networks.lua /tmp/test_lua && rm -rf /tmp/networks.lua /tmp/lua_networks_check.lua /tmp/test_lua'
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for routing tables and diagrams, and [SECURITY.md](SECURITY.md) for the threat model and limitations.

## License

MIT. See [LICENSE](LICENSE).
