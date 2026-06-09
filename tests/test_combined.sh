#!/bin/bash
# Send KEXINIT and ECDH INIT together in one write
exec 3<>/dev/tcp/cnb.space/22
read -r line <&3
echo "BANNER: $line"
echo -ne "SSH-2.0-MoonSSH_0.1.0\r\n" >&3
sleep 0.2

# Helper
nl() { local s="$1"; local sl=$(echo -n "$s" | wc -c); printf "%08x" $sl; echo -n "$s" | xxd -p; }

# Build KEXINIT packet  
KEX=$(nl "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1")
HK=$(nl "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-256,ssh-rsa")
ENC=$(nl "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr")
MAC=$(nl "hmac-sha2-512,hmac-sha2-256,hmac-sha1")
COMP=$(nl "none")
EMPTY="00000000"
PAYLOAD="14"
PAYLOAD+="0102030405060708090a0b0c0d0e0f10"
PAYLOAD+="$KEX$HK$ENC$ENC$MAC$MAC$COMP$COMP$EMPTY$EMPTY"
PAYLOAD+="0000000000"
PLEN=$(( ${#PAYLOAD} / 2 ))
PAD=4; BODY=$((1+PLEN+PAD)); while [ $((BODY % 8)) -ne 0 ]; do PAD=$((PAD+1)); BODY=$((1+PLEN+PAD)); done
PKT=$(printf "%08x" $BODY)$(printf "%02x" $PAD)$PAYLOAD
for i in $(seq 1 $PAD); do PKT+="00"; done

# Generate X25519 key  
openssl genpkey -algorithm X25519 -out /tmp/xkc.pem 2>/dev/null
PUBKEY_HEX=$(openssl pkey -in /tmp/xkc.pem -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p)
# Build ECDH INIT packet
ECDH_PAYLOAD="1e$(printf "%08x" 32)$PUBKEY_HEX"
ECDH_PLEN=$(( ${#ECDH_PAYLOAD} / 2 ))
ECDH_PAD=4; ECDH_BODY=$((1+ECDH_PLEN+ECDH_PAD))
while [ $((ECDH_BODY % 8)) -ne 0 ]; do ECDH_PAD=$((ECDH_PAD+1)); ECDH_BODY=$((1+ECDH_PLEN+ECDH_PAD)); done
ECDH_PKT=$(printf "%08x" $ECDH_BODY)$(printf "%02x" $ECDH_PAD)$ECDH_PAYLOAD
for i in $(seq 1 $ECDH_PAD); do ECDH_PKT+="00"; done

# Combine and send both at once (KEXINIT then ECDH INIT)
COMBINED=$(echo $PKT | xxd -r -p)$(echo $ECDH_PKT | xxd -r -p)
echo "Sending KEXINIT($(( ${#PKT} / 2 ))b) + ECDH INIT($(( ${#ECDH_PKT} / 2 ))b) = $(( $(echo -n "$COMBINED" | wc -c) )) bytes combined"
echo -ne "$COMBINED" >&3

# Read server KEXINIT 
sleep 0.5
len4=$(dd bs=1 count=4 <&3 2>/dev/null | xxd -p)
if [ -z "$len4" ]; then
  echo "NO RESPONSE to combined send"
else
  len=$((16#${len4}))
  echo "Server response: len=$len"
  dd bs=1 count=$len <&3 2>/dev/null | xxd | head -5
fi
echo "---DONE---"
