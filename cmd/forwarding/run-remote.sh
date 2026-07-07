#!/bin/bash

# 远程转发测试（-R）
# 本地 nginx(host:1080) → SSH 服务器注册端口 8080
#
# 流量路径：SSH服务器:8080 → SSH隧道 → 本地 nginx:1080
#
# 验证方式：
#   docker exec openssh-server_forwarding curl http://127.0.0.1:8080

set -e

[ -f .env ] || cp .env.example .env
source .env
set +a

# export MOONBIT_SSH_DEBUG="true"

export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT -R 8080:localhost:1080 --password $MSSH_PASSWORD"

moon clean
moon run . --target native
