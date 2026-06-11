#!/bin/bash
# Build and run the SSH baseline client
#
# Usage:
#   ./run.sh <host> <port> <user> <password> [command]
#
# Example (with Docker sshd):
#   docker run -d --name test-sshd -p 2222:22 \
#     -e USER_NAME=test -e USER_PASSWORD=test123 \
#     linuxserver/openssh-server:latest
#   ./run.sh localhost 2222 test test123 'uname -a'

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASELINE_DIR="$SCRIPT_DIR"

# Build
echo "=== Building baseline SSH client ==="
gcc -Wall -Wextra -o "$BASELINE_DIR/ssh_baseline" "$BASELINE_DIR/ssh_baseline.c" -lcrypto
echo "Build OK: $BASELINE_DIR/ssh_baseline"

if [ $# -lt 4 ]; then
    echo ""
    echo "Usage: $0 <host> <port> <user> <password> [command]"
    echo "Example: $0 localhost 2222 root test123 'uname -a'"
    exit 1
fi

HOST="$1"
PORT="$2"
USER="$3"
PASS="${4:-test123}"
CMD="${5:-uname -a}"

echo ""
echo "=== Running: $CMD on $HOST:$PORT as $USER ==="
"$BASELINE_DIR/ssh_baseline" "$HOST" "$PORT" "$USER" "$PASS" "$CMD"
echo ""
echo "=== Done (exit code: $?) ==="
