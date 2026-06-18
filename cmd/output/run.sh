#!/bin/bash

set -e

moon clean

# # 存在 ffi 时，直接 run 会没有任何输出，需要使用 build 后手动运行
# moon build . --target native

moon build . --target native
../../_build/native/debug/build/cmd/output/output.exe
