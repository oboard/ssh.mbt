#!/bin/bash

set -e

source .env
set +a

export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --exec 'uname -a' --key ${workspace}/scripts/ssh-server/id_ed25519"

# export MOONBIT_SSH_DEBUG="true"

moon clean
moon build . --target native
../../_build/native/debug/build/cmd/key-ed25519/key-ed25519.exe
