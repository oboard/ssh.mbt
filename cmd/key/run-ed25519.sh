#!/bin/bash

set -e

source .env
set +a

export MSSH_PORT="2022"
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --exec 'uname -a' --key ${workspace}/scripts/ssh-server/id_ed25519"

# export MOONBIT_SSH_DEBUG="true"

moon clean
moon run . --target native

# moon build . --target native
# ../../_build/native/debug/build/cmd/key/key.exe
