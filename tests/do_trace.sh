#!/bin/bash
# Clean trace - output to a unique file
OUTFILE="/tmp/trace_ssh_$$"
timeout 15 strace -f -e sendto -s 300 -o "$OUTFILE" \
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o UserKnownHostsFile=/dev/null \
  -p 22 root@cnb.space "echo HELLO_SUCCESS" >/dev/null 2>&1
RC=$?
echo "SSH_RC=$RC"
echo "TRACE_FILE=$OUTFILE"
if [ -f "$OUTFILE" ]; then
    echo "SIZE=$(wc -c < "$OUTFILE")"
    grep 'sendto(3,' "$OUTFILE" | head -8
else
    echo "NO TRACE FILE"
fi
