#!/bin/sh
# Non-interactive SSH wrapper for MikroTik CPE.
# Prefers OpenSSH (/usr/libexec/ssh-openssh) when installed for RouterOS v6/v7 KEX compatibility,
# and falls back to Dropbear dbclient otherwise.
if [ -x /usr/libexec/ssh-openssh ]; then
    exec /usr/libexec/ssh-openssh \
        -o BatchMode=yes \
        -o ConnectTimeout=5 \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o KexAlgorithms=+diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1 \
        -o HostKeyAlgorithms=+ssh-rsa \
        -o PubkeyAcceptedKeyTypes=+ssh-rsa \
        "$@"
fi
exec dbclient -y "$@"
