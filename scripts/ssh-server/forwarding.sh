#!/bin/bash

# 端口转发测试基础设施
# 启动 SSH 服务器 + nginx 测试目标，置于同一 Docker 网络
#
# nginx 绑定宿主机 :1080，三种转发模式共用：
#   -R 远程转发：客户端直接连 localhost:1080 → 隧道 → SSH服务器:8080
#   -L 本地转发：本地:2080 → 隧道 → SSH服务器 → gateway:1080 (宿主机nginx)
#   -D SOCKS5：  curl --socks5 → 隧道 → SSH服务器 → gateway:1080 (宿主机nginx)

set -e

[ -f .env ] || cp .env.example .env
source .env
set +a

NETWORK="forward-test-net"

# 创建专用 Docker 网络
docker network rm $NETWORK 2>/dev/null || true
docker network create $NETWORK

# 启动 nginx 测试目标（绑定宿主机 1080 端口，远程转发直接用）
docker rm -f nginx-forward-test 2>/dev/null || true
docker run -d \
  --name nginx-forward-test \
  --network $NETWORK \
  -p 1080:80 \
  nginx

# 启动 SSH 服务器
docker rm -f openssh-server_forwarding 2>/dev/null || true
docker run -d \
  --name=openssh-server_forwarding \
  --hostname=openssh-server_forwarding \
  --network $NETWORK \
  -e PUID=1000 \
  -e PGID=1000 \
  -e TZ=Etc/UTC \
  -e PASSWORD_ACCESS=true \
  -e USER_PASSWORD="$password" \
  -e SUDO_ACCESS=true \
  -e USER_NAME=admin \
  -p 5022:2222 \
  lscr.io/linuxserver/openssh-server:latest

sleep 5

# 允许端口转发
docker exec openssh-server_forwarding bash -c "
sed -i 's/^#\?AllowTcpForwarding.*/AllowTcpForwarding yes/' /config/sshd/sshd_config && \
sed -i 's/^#\?GatewayPorts.*/GatewayPorts yes/' /config/sshd/sshd_config && \
sed -i 's/^#\?PermitOpen.*/PermitOpen any/' /config/sshd/sshd_config
"
docker exec openssh-server_forwarding pkill sshd

sleep 3

# 获取 Docker 网关 IP（容器访问宿主机用）
GATEWAY_IP=$(docker exec openssh-server_forwarding ip route show default | awk '{print $3}')
echo "Docker gateway IP: $GATEWAY_IP"

# 验证：宿主机 nginx
curl -sf http://127.0.0.1:1080 > /dev/null \
  && echo "Host -> nginx:1080: OK" \
  || echo "Host -> nginx:1080: FAILED"

# 验证：从 SSH 服务器容器内通过 gateway 访问宿主机 nginx
docker exec openssh-server_forwarding curl -sf http://$GATEWAY_IP:1080 > /dev/null \
  && echo "SSH server -> gateway:1080: OK" \
  || echo "SSH server -> gateway:1080: FAILED"
