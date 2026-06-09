#!/bin/bash
# Full SSH KEX test: send banner, KEXINIT, then ECDH INIT
exec 3<>/dev/tcp/cnb.space/22

read -r line <&3
echo "BANNER: $line"

echo -ne "SSH-2.0-MoonSSH_Test\r\n" >&3
sleep 0.2

# Read server KEXINIT
len_hex=$(dd bs=1 count=4 <&3 2>/dev/null | xxd -p)
len=$((16#${len_hex}))
echo "Server KEXINIT length: $len"
dd bs=1 count=$len <&3 2>/dev/null >&-

# Send our KEXINIT (same format as MoonSSH)
PAYLOAD_HEX="14" # SSH_MSG_KEXINIT
# 16-byte cookie
PAYLOAD_HEX+="0102030405060708090a0b0c0d0e0f10"
# kex algs: curve25519-sha256,curve25519-sha256@libssh.org
KEX="curve25519-sha256,curve25519-sha256@libssh.org"
plen() { printf "%08x" $(echo -n "$1" | wc -c); }
PAYLOAD_HEX+=$(plen "$KEX")$(echo -n "$KEX" | xxd -p)
# host key
HK="ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-256,ssh-rsa"
PAYLOAD_HEX+=$(plen "$HK")$(echo -n "$HK" | xxd -p)
# enc (both directions same)
ENC="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
PAYLOAD_HEX+=$(plen "$ENC")$(echo -n "$ENC" | xxd -p)
PAYLOAD_HEX+=$(plen "$ENC")$(echo -n "$ENC" | xxd -p)
# mac (both directions same)
MAC="hmac-sha2-512,hmac-sha2-256,hmac-sha1"
PAYLOAD_HEX+=$(plen "$MAC")$(echo -n "$MAC" | xxd -p)
PAYLOAD_HEX+=$(plen "$MAC")$(echo -n "$MAC" | xxd -p)
# comp
COMP="none"
PAYLOAD_HEX+=$(plen "$COMP")$(echo -n "$COMP" | xxd -p)
PAYLOAD_HEX+=$(plen "$COMP")$(echo -n "$COMP" | xxd -p)
# lang
PAYLOAD_HEX+="00000000"
PAYLOAD_HEX+="00000000"
# first_kex_follows=0, reserved=0
PAYLOAD_HEX+="00"
PAYLOAD_HEX+="00000000"

PAYLOAD_LEN=$(( ${#PAYLOAD_HEX} / 2 ))
# Wrap in SSH packet
PAD=4
BODY=$((1 + PAYLOAD_LEN + PAD))
while [ $((BODY % 8)) -ne 0 ]; do PAD=$((PAD+1)); BODY=$((1+PAYLOAD_LEN+PAD)); done
PKT=$(printf "%08x" $BODY)$(printf "%02x" $PAD)$PAYLOAD_HEX
for i in $(seq 1 $PAD); do PKT+="00"; done
echo "Sending KEXINIT ($(( ${#PKT} / 2 )) bytes)..."
echo -ne "$(echo $PKT | xxd -r -p)" >&3
sleep 0.3

# Read server KEXINIT response (we already read it, so this will read OUR OWN echo)
# Actually, we already consumed it above. Now send ECDH INIT.
# Generate a random 32-byte X25519 public key
FAKE_PUB=$(openssl rand 32 2>/dev/null | xxd -p)
ECDH_PAYLOAD="1e"$(printf "%08x" 32)$FAKE_PUB
ECDH_PAD=4
ECDH_BODY=$((1 + 37 + ECDH_PAD))
while [ $((ECDH_BODY % 8)) -ne 0 ]; do ECDH_PAD=$((ECDH_PAD+1)); ECDH_BODY=$((1+37+ECDH_PAD)); done
ECDH_PKT=$(printf "%08x" $ECDH_BODY)$(printf "%02x" $ECDH_PAD)$ECDH_PAYLOAD
for i in $(seq 1 $ECDH_PAD); do ECDH_PKT+="00"; done
echo "Sending ECDH INIT ($(( ${#ECDH_PKT} / 2 )) bytes)..."
echo -ne "$(echo $ECDH_PKT | xxd -r -p)" >&3
sleep 0.5

# Try to read response
echo "Reading response..."
dd bs=1 count=4 <&3 2>/dev/null | xxd
echo "Done"
