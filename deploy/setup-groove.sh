#!/usr/bin/env bash
# Provision MikroTik CPE with least-privilege 'hunter' SSH user (ssh,read,write ONLY - NO policy)
# and dual security profiles ('van-open' + 'van-psk') for van-wan-guard autonomous Wi-Fi hunting.
set -euo pipefail

GROOVE_IP="${1:-192.168.88.1}"
GROOVE_ADMIN="${2:-admin}"
MT_HOST="${MT_HOST:-gl-mt3000}"

echo "[1/4] Inspecting GrooveA-52 (${GROOVE_ADMIN}@${GROOVE_IP})..."
ROS_VER="$(ssh -o ConnectTimeout=5 "${GROOVE_ADMIN}@${GROOVE_IP}" "/system resource print" 2>/dev/null | awk -F: '/version:/ { gsub(/^[[:space:]]+/, "", $2); print $2; exit }' || true)"
echo "  RouterOS version: ${ROS_VER:-unknown}"

echo "[2/4] Fetching GL-MT3000 Dropbear public key..."
PUB_KEY="$(ssh -o BatchMode=yes -o ConnectTimeout=5 "${MT_HOST}" 'dropbearkey -y -f /etc/van-wan-guard/groove_dropbear.key | grep "^ssh-"')"
echo "  Public key: ${PUB_KEY}"
if [[ "${ROS_VER}" == 6.* ]] && [[ "${PUB_KEY}" == ssh-ed25519* ]]; then
    echo "  NOTE: RouterOS v6 detected; if Ed25519 SSH import fails, re-run setup-mt3000.sh with --groove-key-type rsa." >&2
fi

echo "[3/4] Creating least-privilege RouterOS 'hunter' group (ssh,read,write ONLY - NO policy/ftp/winbox/reboot) & dual profiles..."
TMP_PUB="$(mktemp)"
trap 'rm -f "${TMP_PUB}"' EXIT
printf '%s\n' "${PUB_KEY}" > "${TMP_PUB}"
scp -q "${TMP_PUB}" "${GROOVE_ADMIN}@${GROOVE_IP}:hunter_van.pub"

ssh "${GROOVE_ADMIN}@${GROOVE_IP}" << 'ROS_EOF'
:if ([:len [/user group find name="hunter"]] = 0) do={
  /user group add name=hunter policy=ssh,read,write,!local,!telnet,!ftp,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!api,!romon
} else={
  /user group set [find name="hunter"] policy=ssh,read,write,!local,!telnet,!ftp,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!api,!romon
}
:if ([:len [/user find name="hunter"]] = 0) do={
  /user add name=hunter group=hunter disabled=no
} else={
  /user set [find name="hunter"] group=hunter disabled=no
}
:do { /user ssh-keys import public-key-file=hunter_van.pub user=hunter } on-error={}
/file remove [find name="hunter_van.pub"]
:if ([:len [/interface wireless security-profiles find name="van-open"]] = 0) do={
  /interface wireless security-profiles add name=van-open mode=none
} else={
  /interface wireless security-profiles set [find name="van-open"] mode=none
}
:if ([:len [/interface wireless security-profiles find name="van-psk"]] = 0) do={
  /interface wireless security-profiles add name=van-psk mode=dynamic-keys authentication-types=wpa2-psk wpa2-pre-shared-key="placeholder-set-by-hunter"
} else={
  /interface wireless security-profiles set [find name="van-psk"] mode=dynamic-keys authentication-types=wpa2-psk
}
ROS_EOF

echo "[4/4] Verifying non-blocking Groove poll & hunter SSH access from ${MT_HOST}..."
ssh "${MT_HOST}" "/usr/libexec/van-wan-guard/groove-poll.sh && cat /var/run/van-wan-guard/groove.json"
echo "GrooveA-52 provisioning complete."
