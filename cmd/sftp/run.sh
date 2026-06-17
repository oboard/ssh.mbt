#!/bin/bash
set -e
source .env

moon clean
moon build . --target native


# ls - 列出目录
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command ls /"
../../_build/native/debug/build/cmd/sftp/sftp.exe

# mkdir - 创建目录
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command mkdir /sftp_test"
../../_build/native/debug/build/cmd/sftp/sftp.exe

# ls - 列出目录
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command ls /"
../../_build/native/debug/build/cmd/sftp/sftp.exe


# put - 上传文件
echo "hello sftp" > /tmp/test_sftp.txt
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command put dummy /sftp_test/test_sftp.txt"
../../_build/native/debug/build/cmd/sftp/sftp.exe


# get - 下载文件
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command get /sftp_test/test_sftp.txt"
../../_build/native/debug/build/cmd/sftp/sftp.exe

# stat - 查看文件属性
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command stat /sftp_test/test_sftp.txt"
../../_build/native/debug/build/cmd/sftp/sftp.exe


# rm - 删除文件
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command rm /sftp_test/test_sftp.txt"
../../_build/native/debug/build/cmd/sftp/sftp.exe


# rmdir - 删除目录
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command rmdir /sftp_test"
../../_build/native/debug/build/cmd/sftp/sftp.exe


# ls - 列出目录
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command ls /"
../../_build/native/debug/build/cmd/sftp/sftp.exe
