#!/bin/bash

set -e

source .env
set +a

export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --exec 'uname -a' --password $MSSH_PASSWORD"

# 是否输出 调试信息
# export MOONBIT_SSH_DEBUG="true"

moon clean

moon run . --target native

# moon build . --target native
# ../../_build/native/debug/build/cmd/password/password.exe
