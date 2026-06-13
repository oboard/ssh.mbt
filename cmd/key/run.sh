#!/bin/bash

set -e

source .env
set +a

export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --exec 'uname -a' --key ../../scripts/ssh-server/id_ed25519"

# 是否输出 调试信息
# export MOONBIT_SSH_DEBUG="true"

moon clean

# # 存在 ffi 时，直接 run 会没有任何输出，需要使用 build 后手动运行
# moon build . --target native

moon build . --target native
../../_build/native/debug/build/cmd/key/key.exe
