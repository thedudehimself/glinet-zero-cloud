#!/bin/sh
# Non-interactive Dropbear SSH wrapper for scp -S (avoids interactive hostkey prompt and keeps PSKs out of argv).
exec dbclient -y "$@"
