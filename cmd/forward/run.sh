#!/bin/bash

set -e

source .env
set +a


moon clean
moon build . --target native

# 本地转发示例
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT -L 8080:localhost:80 --password $MSSH_PASSWORD"

# # 远程转发示例
# export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT -R 9090:localhost:3000 --password $MSSH_PASSWORD"

# # SOCKS5 代理示例
# export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT -D 1080 --password $MSSH_PASSWORD"

../../_build/native/debug/build/cmd/forward/forward.exe
