#!/bin/bash

set -e

source .env
set +a

docker rm -f openssh-server_forwarding

docker run -d \
  --name=openssh-server_forwarding \
  --hostname=openssh-server_forwarding \
  -e PUID=1000 \
  -e PGID=1000 \
  -e TZ=Etc/UTC \
  -e PASSWORD_ACCESS=true \
  -e USER_PASSWORD="$password" \
  -e SUDO_ACCESS=true \
  -e USER_NAME=admin \
  -p 5022:2222 \
  lscr.io/linuxserver/openssh-server:latest

docker rm -f nginx

# 启动一个 nginx bind 到本地的 1080 端口 
docker run --name nginx -d -p 1080:80 nginx

sleep 5

# 访问 1080 测试 nginx
curl http://127.0.0.1:1080

sleep 5

docker exec -it openssh-server_forwarding bash -c "
sed -i 's/^#\?AllowTcpForwarding.*/AllowTcpForwarding yes/' /config/sshd/sshd_config && \
sed -i 's/^#\?GatewayPorts.*/GatewayPorts no/' /config/sshd/sshd_config && \
sed -i 's/^#\?PermitOpen.*/PermitOpen any/' /config/sshd/sshd_config
"

docker exec -it openssh-server_forwarding pkill sshd
docker exec -it openssh-server_forwarding cat /config/sshd/sshd_config

# # 将本地的 1080 端口转发到 ssh 的 8080 端口
# ssh -v -R 8080:127.0.0.1:1080 admin@127.0.0.1 -p 5022

# # 验证 ssh 的 8080 是否可以访问
# docker exec -it openssh-server_forwarding curl http://127.0.0.1:8080

