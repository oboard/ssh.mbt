#!/bin/bash

set -e

# ssh -i id_ed25519 admin@127.0.0.1 -p 2022

rm -f id_ed25519 id_ed25519.pub

ssh-keygen -t ed25519 -N "" -f id_ed25519

publickey=$(cat id_ed25519.pub)

docker rm -f openssh-server_publickey

docker run -d \
  --name=openssh-server_publickey \
  --hostname=openssh-server_publickey \
  -e PUID=1000 \
  -e PGID=1000 \
  -e TZ=Etc/UTC \
  -e PUBLIC_KEY="$publickey" \
  -e SUDO_ACCESS=true \
  -e USER_NAME=admin \
  -p 2022:2222 \
  lscr.io/linuxserver/openssh-server:latest
