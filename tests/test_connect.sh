#!/bin/bash
# Ultra-minimal SSH connectivity test
set -x
exec 3<>/dev/tcp/cnb.space/22 && echo "CONNECTED" || echo "FAIL"
read -t 5 -u 3 line && echo "BANNER: $line" || echo "NO BANNER"
printf 'SSH-2.0-T\r\n' >&3
sleep 0.2
# Read 4 bytes for packet length
dd bs=1 count=4 <&3 2>/dev/null | xxd -p
echo "---"
exec 3>&-
