#!/bin/bash

# 本地转发测试（-L）
# 本地监听 2080 → SSH 隧道 → SSH 服务器 → 宿主机 nginx:1080
#
# 流量路径：curl localhost:2080 → SSH隧道 → SSH服务器 → gateway:1080
#
# 验证方式：
#   curl http://127.0.0.1:2080

set -e

[ -f .env ] || cp .env.example .env
source .env
set +a

# 获取 Docker 网关 IP（SSH 服务器容器内访问宿主机用）
# 注意：某些容器内 `ip route show default` 会输出多行（含 link scope 行），
# 必须只取 default 行，否则 GATEWAY_IP 会带换行符导致 getaddrinfo 失败
# （服务端返回 SSH_OPEN_CONNECT_FAILED / "Try again"）。
GATEWAY_IP=$(docker exec openssh-server_forwarding ip route show default | awk '/^default/ {print $3; exit}')
echo "Target: $GATEWAY_IP:1080 (host nginx via Docker gateway)"

# export MOONBIT_SSH_DEBUG="true"

export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT -L 2080:$GATEWAY_IP:1080 --password $MSSH_PASSWORD"

moon clean
moon run . --target native
