# Security Model & Threat Analysis

This document states the exact security invariants enforced by `glinet-zero-cloud`, the assumptions it relies on, and its explicit non-goals.

## Security Invariants

1. **No Public Internet Exposure**: The management portal binds exclusively to `127.0.0.1:8450` (and isolated nginx upstreams on `127.0.0.1:845x`) and is published only via `tailscale serve` inside your private tailnet. Never use `tailscale funnel`.
2. **Defense-in-Depth Auth & CSRF**: Both nginx and `portal.py` validate `Tailscale-User-Login` (or allowlisted rightmost `X-Forwarded-For` IP for tagged tailnet servers where Tailscale omits the login header). Unauthenticated local requests are rejected (only `/healthz` returns `{"ok":true}`). Every mutating `POST` requires `X-Portal-Action: 1` and a matching `https://` `Origin` header, closes keep-alive connections on early `4xx`, and rejects chunked encoding.
3. **Fail-Closed Untrusted Wi-Fi Gate**: On the router, `VAN_CPE_GATE` hooks `-o eth0` unconditionally at `FORWARD` index 1 (above `RELATED,ESTABLISHED`) defaulting to `REJECT`, `VAN_CPE_DNS_OUT` blocks `:53`/`:853` on `OUTPUT`, `ip6tables` + `disable_ipv6=1` disable IPv6 on `eth0`/`eth1`, `fwmark 0x101` has terminal `prio 86 unreachable` + `OUTPUT ! -o eth0 -j DROP`, `wg_van` source probes have terminal `prio 90 unreachable`, and `vpn_active` client routing has terminal `prio 97/98 unreachable`. Gate transitions use a `mkdir` lock and insert `REJECT` before removing old rules.
4. **Evil-Twin & Spoofed-SSID Rejection**: `networks.lua` rejects `trusted: true` unless `security != "open"` and a non-empty PSK is stored, anchors RouterOS scan parsing to the rightmost channel+RSSI column (preventing crafted 32-byte SSIDs from spoofing RSSI/WPA2), and excludes any open AP broadcasting the SSID of a saved WPA2/WPA3 network.
5. **PSK & Secret Isolation**: Plaintext Wi-Fi PSKs live only on the router in `/etc/van-wan-guard/known_networks.json` (created atomically under `umask 077` / `0600`). They are stripped from all `GET` responses, never stored in the gateway SQLite database, passed strictly over SSH `stdin`, and uploaded to RouterOS via `0600` `.rsc` + `scp` (failing hard rather than falling back to `argv`, with `EXIT/INT/TERM` trap cleanup).
6. **LAN-Isolated Offline UI**: `setup-mt3000.sh` binds the offline `:8080` `uhttpd` UI strictly to the router's LAN IP (never `0.0.0.0`), blocks `guest -> :8080` in firewall rules, enforces strict `Origin` + `X-Van-Action: 1` checks, and supports an optional `0600` `/etc/van-wan-guard/ui_token` header guard (`X-Van-Token`).
7. **Least-Privilege RouterOS Automation**: The MikroTik CPE `hunter` group grants only `ssh,read,write` (explicitly denying `policy`, `ftp`, `winbox`, `reboot`, `password`, `sensitive`, `web`, and `api`). Open/unknown SSIDs containing RouterOS metacharacters (`[ ] $ " \ \` ;` or control bytes) are rejected before CLI formatting.

## Assumptions & Explicit Limitations

- **Single-Tenant Trusted Root Appliances**: Both the Linux gateway running `portal.py` (`127.0.0.1:8450`) and the OpenWrt router running `van-wan-guard` are assumed to be single-admin appliances with no untrusted local UIDs or containers sharing localhost.
- **Self-Signed Upstream TLS on Local KVMs**: Local nginx reverse proxies use `proxy_ssl_verify off` toward LAN IP-KVMs (which ship self-signed certificates on private VLANs). Isolation relies on private VLAN segmentation and MAC-to-IP resolution.
- **Explicit Captive-Portal Login Window**: Triggering `captive_login` intentionally permits direct TCP `80,443` and UDP/TCP `53` on `eth0` for up to 10 minutes so a browser can click through a splash page. The killswitch automatically snaps back to `REJECT` as soon as HTTP `204` clears or the timer expires, and `wifi-hunter.sh` clears any active `captive_login` override before switching APs.
- **fw3 / iptables Target**: `router/` targets GL.iNet `4.x` / OpenWrt 21.02 (`fw3`/`iptables`). OpenWrt 22.03-24.10 (`fw4`/`nftables`) is explicitly unsupported (`setup-mt3000.sh` aborts on `fw4`-only systems).
- **RouterOS `wireless` Package**: `networks.lua` targets the RouterOS `/interface wireless` stack used on GrooveA-52 / legacy RouterOS CPEs; RouterOS v7 `wifi-qcom`/`/interface wifi` syntax is not yet implemented for `ros-connect-cmd`.

## Reporting Vulnerabilities

If you find a security bug or bypass in the VPN killswitch, RouterOS escaping, or portal authentication, please open a GitHub Security Advisory (private vulnerability report) rather than posting an exploit publicly.
