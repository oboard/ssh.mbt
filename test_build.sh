#!/bin/bash
cd /workspace
echo "=== Compiling ==="
gcc -o tests/baseline/ssh_baseline tests/baseline/ssh_baseline.c -lcrypto 2>&1
echo "GCC RC=$?"
ls -la tests/baseline/ssh_baseline 2>&1
echo "=== Running ==="
timeout 12 tests/baseline/ssh_baseline cnb.space 22 'cnb-ato-1jqnvb31h-001.564f7334-3418-4d55-ad34-fb3552d8e514-obg' '' 'id' 2>&1 | tail -30
echo "RUN RC=$?"
