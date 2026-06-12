#!/bin/bash

set -e

source .env
set +a

# docker run -d --name ssh-server -p 1022:2222 -e SUDO_ACCESS=true -e USER_NAME=admin -e PASSWORD_ACCESS=true -e USER_PASSWORD=123456 lscr.io/linuxserver/openssh-server

export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --exec 'CMD' --password $MSSH_PASSWORD"
moon run cmd/main --target native
