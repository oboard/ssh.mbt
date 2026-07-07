#!/bin/bash

# SOCKS5 动态代理测试（-D）
# 本地 SOCKS5 代理:3080 → SSH 隧道 → SSH 服务器连接目标
#
# 流量路径：curl --socks5 → SOCKS5代理:3080 → SSH隧道 → SSH服务器 → 目标
#
# 验证方式（通过 SOCKS5 代理访问宿主机 nginx）：
#   curl --socks5 127.0.0.1:3080 http://<gateway_ip>:1080

set -e

[ -f .env ] || cp .env.example .env
source .env
set +a

# 获取 Docker 网关 IP
GATEWAY_IP=$(docker exec openssh-server_forwarding ip route show default | awk '{print $3}')
echo "SOCKS5 target will be: $GATEWAY_IP:1080 (host nginx via Docker gateway)"
echo "Verify with: curl --socks5 127.0.0.1:3080 http://$GATEWAY_IP:1080"

# export MOONBIT_SSH_DEBUG="true"

export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT -D 3080 --password $MSSH_PASSWORD"

moon clean
moon run . --target native
