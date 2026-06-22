#!/bin/bash

set -e

moon clean

moon run . --target native

# moon build . --target native
# ../../_build/native/debug/build/cmd/output/output.exe
