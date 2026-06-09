#!/bin/bash
# Check what algorithms the CNB server supports
exec 3<>/dev/tcp/cnb.space/22
# Read server banner
read -r line <&3
echo "Server: $line"

# Send our banner
echo -ne "SSH-2.0-MoonSSH_0.1.0\r\n" >&3
sleep 0.3

# Read KEXINIT from server
read_hex() { dd bs=1 count=$1 <&3 2>/dev/null | xxd -p | tr -d '\n'; }

len_bytes=$(read_hex 4)
len=$((16#${len_bytes}))
echo "KEXINIT packet length: $len bytes"

kexinit=$(read_hex $len)

# Parse: byte(0x14) + 16 cookie + name-lists
kexrest=${kexinit:34}  # skip msg type (2) + cookie (32 hex = 16 bytes)
# Actually just split properly
off=0
skip_hex() { off=$((off + $1 * 2)); }
read_u32() { 
  val=$((16#${kexrest:$off:8}))
  off=$((off + 8))
  echo $val
}
read_str() {
  slen=$(read_u32)
  str=$(echo -n "${kexrest:$off:$((slen*2))}" | xxd -r -p)
  off=$((off + slen*2))
  echo "$str"
}

off=2  # skip msg type (0x14 = 1 byte = 2 hex)
echo "Cookie: ${kexrest:0:32}"  # 16 bytes = 32 hex
off=34

echo "KEX algs: $(read_str)"
echo "Host key algs: $(read_str)"
echo "Enc c2s: $(read_str)"
echo "Enc s2c: $(read_str)"
echo "MAC c2s: $(read_str)"
echo "MAC s2c: $(read_str)"
echo "Comp c2s: $(read_str)"
echo "Comp s2c: $(read_str)"
