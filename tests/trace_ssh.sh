#!/bin/bash
# Run SSH under strace, capture trace to file, suppress program output
timeout 15 strace -f -e sendto -s 300 -o /tmp/ssh_trace_final.txt \
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o UserKnownHostsFile=/dev/null \
  -p 22 root@cnb.space "echo HELLO" >/dev/null 2>&1
echo "SSH_EXIT=$?"
echo "=== SSH sendto traces ==="
grep 'sendto(3,' /tmp/ssh_trace_final.txt | head -10
