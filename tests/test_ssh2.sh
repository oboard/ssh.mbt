#!/bin/bash
exec 3<>/dev/tcp/cnb.space/22
read -r line <&3
echo "BANNER: $line"
echo -ne "SSH-2.0-MoonSSH_0.1.0\r\n" >&3
sleep 0.2

# Read server KEXINIT
len4=$(dd bs=1 count=4 <&3 2>/dev/null | xxd -p)
len=$((16#${len4}))
echo "Server KEXINIT: $len bytes"
dd bs=1 count=$len <&3 2>/dev/null > /dev/null

# Generate proper X25519 key and extract pubkey
openssl genpkey -algorithm X25519 -out /tmp/xk.pem 2>/dev/null
PUBKEY_HEX=$(openssl pkey -in /tmp/xk.pem -text -noout 2>/dev/null | grep -A1 "^pub:" | tail -1 | tr -d " :\n")
PUBKEY_HEX="${PUBKEY_HEX:0:64}"
echo "PUBKEY: $PUBKEY_HEX"

# Build ECDH INIT
ECDH_PAYLOAD="1e$(printf "%08x" 32)$PUBKEY_HEX"
ECDH_PLEN=$(( ${#ECDH_PAYLOAD} / 2 ))
ECDH_PAD=4
ECDH_BODY=$((1 + ECDH_PLEN + ECDH_PAD))
while [ $((ECDH_BODY % 8)) -ne 0 ]; do
  ECDH_PAD=$((ECDH_PAD+1))
  ECDH_BODY=$((1+ECDH_PLEN+ECDH_PAD))
done
ECDH_PKT=$(printf "%08x" $ECDH_BODY)$(printf "%02x" $ECDH_PAD)$ECDH_PAYLOAD
for i in $(seq 1 $ECDH_PAD); do ECDH_PKT+="00"; done
echo "ECDH INIT: $(( ${#ECDH_PKT} / 2 )) bytes"

# Send without KEXINIT first - just send ECDH INIT (like MoonSSH does after KEXINIT)
echo -ne "$(echo $ECDH_PKT | xxd -r -p)" >&3
sleep 0.5

res4=$(dd bs=1 count=4 <&3 2>/dev/null | xxd -p)
if [ -z "$res4" ]; then
  echo "NO RESPONSE"
else
  rlen=$((16#${res4}))
  echo "RESPONSE len=$rlen"
  dd bs=1 count=$rlen <&3 2>/dev/null | xxd | head -5
fi
