#!/bin/bash

set -e

# ssh -i id_rsa admin@127.0.0.1 -p 3022

rm -f id_rsa id_rsa.pub

ssh-keygen -t rsa -b 4096 -N "" -f id_rsa

publickey=$(cat id_rsa.pub)

docker rm -f openssh-server_key_rsa

docker run -d \
  --name=openssh-server_key_rsa \
  --hostname=openssh-server_key_rsa \
  -e PUID=1000 \
  -e PGID=1000 \
  -e TZ=Etc/UTC \
  -e PUBLIC_KEY="$publickey" \
  -e SUDO_ACCESS=true \
  -e USER_NAME=admin \
  -p 3022:2222 \
  lscr.io/linuxserver/openssh-server:latest
