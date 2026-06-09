#!/bin/bash
# Full SSH KEX - mimic MoonSSH exactly with correct 32-byte key
exec 3<>/dev/tcp/cnb.space/22
read -r line <&3
echo "BANNER: $line"
echo -ne "SSH-2.0-MoonSSH_0.1.0\r\n" >&3
sleep 0.2

# Helper
nl() { local s="$1"; local sl=$(echo -n "$s" | wc -c); printf "%08x" $sl; echo -n "$s" | xxd -p; }

KEX=$(nl "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1")
HK=$(nl "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-256,ssh-rsa")
ENC=$(nl "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr")
MAC=$(nl "hmac-sha2-512,hmac-sha2-256,hmac-sha1")
COMP=$(nl "none")
EMPTY="00000000"
PAYLOAD="14"  # SSH_MSG_KEXINIT
PAYLOAD+="0102030405060708090a0b0c0d0e0f10"
PAYLOAD+="$KEX$HK$ENC$ENC$MAC$MAC$COMP$COMP$EMPTY$EMPTY"
PAYLOAD+="0000000000"

PLEN=$(( ${#PAYLOAD} / 2 ))
PAD=4; BODY=$((1+PLEN+PAD)); while [ $((BODY % 8)) -ne 0 ]; do PAD=$((PAD+1)); BODY=$((1+PLEN+PAD)); done
PKT=$(printf "%08x" $BODY)$(printf "%02x" $PAD)$PAYLOAD
for i in $(seq 1 $PAD); do PKT+="00"; done
echo "KEXINIT: $(( ${#PKT} / 2 )) bytes"
echo -ne "$(echo $PKT | xxd -r -p)" >&3
sleep 0.3

# Read server KEXINIT
len4=$(dd bs=1 count=4 <&3 2>/dev/null | xxd -p)
len=$((16#${len4}))
echo "Server KEXINIT: $len bytes"
dd bs=1 count=$len <&3 2>/dev/null > /dev/null

# Generate X25519 key and get raw 32-byte pub
openssl genpkey -algorithm X25519 -out /tmp/xkt.pem 2>/dev/null
# Use EVP_PKEY_get_raw_public_key via openssl pkey -pubout -raw
PUBKEY_HEX=$(openssl pkey -in /tmp/xkt.pem -pubout -outform DER 2>/dev/null | xxd -p)
echo "Full DER: $PUBKEY_HEX"
# Parse DER to extract key: SubjectPublicKeyInfo for X25519
# OID: 06 03 2b 65 6e, then BIT STRING with leading 0x00
# Extract the raw key (last 32 bytes NO leading 0)
PUBKEY_HEX=$(echo "$PUBKEY_HEX" | sed 's/^.*2b656e03//' | sed 's/^2[0-9a-f]00//' | head -c 64)
echo "Raw key: $PUBKEY_HEX"
echo "Key length: $(echo -n "$PUBKEY_HEX" | wc -c) hex chars"

if [ "$(echo -n "$PUBKEY_HEX" | wc -c)" -ne 64 ]; then
  echo "ERROR: key must be 32 bytes (64 hex chars)"
  echo "Trying alternative extraction..."
  # Alternative: get just the raw bytes  
  PUBKEY_HEX=$(openssl pkey -in /tmp/xkt.pem -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p)
  echo "Raw key (alt): $PUBKEY_HEX"
fi

# Send ECDH INIT
ECDH_PAYLOAD="1e$(printf "%08x" 32)$PUBKEY_HEX"
ECDH_PLEN=$(( ${#ECDH_PAYLOAD} / 2 ))
ECDH_PAD=4; ECDH_BODY=$((1+ECDH_PLEN+ECDH_PAD))
while [ $((ECDH_BODY % 8)) -ne 0 ]; do ECDH_PAD=$((ECDH_PAD+1)); ECDH_BODY=$((1+ECDH_PLEN+ECDH_PAD)); done
ECDH_PKT=$(printf "%08x" $ECDH_BODY)$(printf "%02x" $ECDH_PAD)$ECDH_PAYLOAD
for i in $(seq 1 $ECDH_PAD); do ECDH_PKT+="00"; done
echo "ECDH INIT: $(( ${#ECDH_PKT} / 2 )) bytes"
echo -ne "$(echo $ECDH_PKT | xxd -r -p)" >&3
sleep 0.7

res4=$(dd bs=1 count=4 <&3 2>/dev/null | xxd -p)
if [ -z "$res4" ]; then
  echo "NO RESPONSE"
else
  rlen=$((16#${res4}))
  echo "RESPONSE len=$rlen"
  dd bs=1 count=$rlen <&3 2>/dev/null | xxd | head -10
fi
echo "---DONE---"
