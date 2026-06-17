#!/bin/bash
set -e
source .env

moon clean
moon build . --target native


# ls - 列出目录
echo "===> ls /"
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command ls /"
../../_build/native/debug/build/cmd/sftp/sftp.exe

# mkdir - 创建目录
echo "===> mkdir /tmp/sftp_test"
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command mkdir /tmp/sftp_test"
../../_build/native/debug/build/cmd/sftp/sftp.exe

# ls - 列出目录
echo "===> ls /tmp"
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command ls /tmp"
../../_build/native/debug/build/cmd/sftp/sftp.exe


# put - 上传文件
echo "===> put dummy /tmp/sftp_test/test_sftp.txt"
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command put dummy /tmp/sftp_test/test_sftp.txt"
../../_build/native/debug/build/cmd/sftp/sftp.exe

# ls - 列出目录
echo "===> ls /tmp/sftp_test"
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command ls /tmp/sftp_test"
../../_build/native/debug/build/cmd/sftp/sftp.exe

# get - 下载文件
echo "===> get /tmp/sftp_test/test_sftp.txt"
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command get /tmp/sftp_test/test_sftp.txt"
../../_build/native/debug/build/cmd/sftp/sftp.exe

# stat - 查看文件属性
echo "===> stat /tmp/sftp_test/test_sftp.txt"
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command stat /tmp/sftp_test/test_sftp.txt"
../../_build/native/debug/build/cmd/sftp/sftp.exe


# rm - 删除文件
echo "===> rm /tmp/sftp_test/test_sftp.txt"
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command rm /tmp/sftp_test/test_sftp.txt"
../../_build/native/debug/build/cmd/sftp/sftp.exe


# rmdir - 删除目录
echo "===> rmdir /tmp/sftp_test"
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command rmdir /tmp/sftp_test"
../../_build/native/debug/build/cmd/sftp/sftp.exe


# ls - 列出目录
echo "===> ls /tmp"
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command ls /tmp"
../../_build/native/debug/build/cmd/sftp/sftp.exe
