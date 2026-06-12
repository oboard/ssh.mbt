#!/bin/bash

set -e

source .env
set +a

# docker run -d --name ssh-server -p 1022:2222 -e SUDO_ACCESS=true -e USER_NAME=admin -e PASSWORD_ACCESS=true -e USER_PASSWORD=123456 lscr.io/linuxserver/openssh-server

export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --exec 'uname -a' --password $MSSH_PASSWORD"

# 是否输出 调试信息
# export MOONBIT_SSH_DEBUG="true"

# # 存在 ffi 时，直接 run 会没有任何输出，需要使用 build 后手动运行
# moon build cmd/main --target native

moon build cmd/main --target native
./_build/native/debug/build/cmd/main/main.exe
