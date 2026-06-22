#!/bin/bash

set -e

source .env
set +a


moon clean
moon build . --target native

# export MOONBIT_SSH_DEBUG="true"

docker rm -f nginx

# 启动一个 nginx bind 到本地的 1080 端口 
docker run --name nginx -d -p 1080:80 nginx

sleep 5

# 访问 1080 测试 nginx
curl http://127.0.0.1:1080

# 本地转发示例
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT -L 1080:localhost:80 --password $MSSH_PASSWORD"

# # 远程转发示例
# export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT -R 9090:localhost:3000 --password $MSSH_PASSWORD"

# # SOCKS5 代理示例
# export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT -D 1080 --password $MSSH_PASSWORD"

../../_build/native/debug/build/cmd/forward/forward.exe
