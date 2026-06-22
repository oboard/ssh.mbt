#!/bin/bash

set -e

source .env
set +a

# export MOONBIT_SSH_DEBUG="true"

# 远程转发示例
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT -R 8080:localhost:1080 --password $MSSH_PASSWORD"
# 验证
#  - ssh 登录
#  ssh $MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT
#  - ssh 内执行 curl
#  curl http://127.0.0.1:8080

# # 本地转发示例
# export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT -L 1080:localhost:80 --password $MSSH_PASSWORD"

# # SOCKS5 代理示例
# export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT -D 1080 --password $MSSH_PASSWORD"


moon clean

moon run . --target native

# moon build . --target native
# ../../_build/native/debug/build/cmd/forward/forward.exe
