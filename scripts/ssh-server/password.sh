#!/bin/bash

set -e

source .env
set +a

docker rm -f openssh-server_password

docker run -d \
  --name=openssh-server_password \
  --hostname=openssh-server_password \
  -e PUID=1000 \
  -e PGID=1000 \
  -e TZ=Etc/UTC \
  -e PASSWORD_ACCESS=true \
  -e USER_PASSWORD="$password" \
  -e SUDO_ACCESS=true \
  -e USER_NAME=admin \
  -p 1022:2222 \
  lscr.io/linuxserver/openssh-server:latest
