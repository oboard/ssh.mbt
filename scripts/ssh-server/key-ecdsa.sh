#!/bin/bash

set -e

# ssh -i id_ecdsa admin@127.0.0.1 -p 4022

rm -f id_ecdsa id_ecdsa.pub

ssh-keygen -t ecdsa -b 256 -N "" -f id_ecdsa

publickey=$(cat id_ecdsa.pub)

docker rm -f openssh-server_key_ecdsa

docker run -d \
  --name=openssh-server_key_ecdsa \
  --hostname=openssh-server_key_ecdsa \
  -e PUID=1000 \
  -e PGID=1000 \
  -e TZ=Etc/UTC \
  -e PUBLIC_KEY="$publickey" \
  -e SUDO_ACCESS=true \
  -e USER_NAME=admin \
  -p 4022:2222 \
  lscr.io/linuxserver/openssh-server:latest
