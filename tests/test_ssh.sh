#!/bin/bash
# Capture the EXACT bytes that OpenSSH sends for KEXINIT + ECDH INIT
# by using the SSH_DEBUG_KEX environment or similar

# Let's use ssh -T to connect with a non-existing user and capture
# just the KEX exchange packets using SOCAT-style approach

# Actually, let's use openssl to generate a X25519 keypair and send the
# exact ECDH INIT that a real SSH client would send

# Generate real X25519 key pair
openssl genpkey -algorithm X25519 -out /tmp/x25519_priv.pem 2>/dev/null
openssl pkey -in /tmp/x25519_priv.pem -pubout -out /tmp/x25519_pub.pem 2>/dev/null

# Extract raw 32-byte public key
PUBKEY_HEX=$(openssl pkey -in /tmp/x25519_priv.pem -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p)
echo "X25519 pub key: $PUBKEY_HEX"

# Now do the full SSH KEX
exec 3<>/dev/tcp/cnb.space/22

# Read banner
read -r line <&3
echo "BANNER: $line"

# Send banner
echo -ne "SSH-2.0-MoonSSH_0.1.0\r\n" >&3
sleep 0.2

# Read server KEXINIT
len4=$(dd bs=1 count=4 <&3 2>/dev/null | xxd -p)
len=$((16#${len4}))
echo "Server KEXINIT len: $len"
dd bs=1 count=$len <&3 2>/dev/null > /dev/null

# Now send our KEXINIT with same format as MoonSSH
# Build name-list with proper length prefix
nl() {
  local s="$1"
  local slen=$(echo -n "$s" | wc -c)
  printf "%08x" $slen
  echo -n "$s" | xxd -p
}

KEX_LIST=$(nl "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1")
HK_LIST=$(nl "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-256,ssh-rsa")
ENC_LIST=$(nl "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr")
MAC_LIST=$(nl "hmac-sha2-512,hmac-sha2-256,hmac-sha1")
COMP_LIST=$(nl "none")
EMPTY="00000000"

PAYLOAD="14"  # SSH_MSG_KEXINIT
PAYLOAD+="0102030405060708090a0b0c0d0e0f10"  # 16-byte cookie
PAYLOAD+="$KEX_LIST$HK_LIST$ENC_LIST$ENC_LIST$MAC_LIST$MAC_LIST$COMP_LIST$COMP_LIST$EMPTY$EMPTY"
PAYLOAD+="0000000000"  # first_kex_follows=0, reserved=0

PLEN=$(( ${#PAYLOAD} / 2 ))
PAD=4
BODY=$((1 + PLEN + PAD))
while [ $((BODY % 8)) -ne 0 ]; do PAD=$((PAD+1)); BODY=$((1+PLEN+PAD)); done

PKT=$(printf "%08x" $BODY)$(printf "%02x" $PAD)$PAYLOAD
for i in $(seq 1 $PAD); do PKT+="00"; done
echo "Sending KEXINIT ($(( ${#PKT} / 2 )) bytes)..."
echo -ne "$(echo $PKT | xxd -r -p)" >&3
sleep 0.3

# Now send ECDH INIT
ECDH_PAYLOAD="1e"$(printf "%08x" 32)$PUBKEY_HEX
ECDH_PLEN=$(( ${#ECDH_PAYLOAD} / 2 ))
ECDH_PAD=4
ECDH_BODY=$((1 + ECDH_PLEN + ECDH_PAD))
while [ $((ECDH_BODY % 8)) -ne 0 ]; do ECDH_PAD=$((ECDH_PAD+1)); ECDH_BODY=$((1+ECDH_PLEN+ECDH_PAD)); done
ECDH_PKT=$(printf "%08x" $ECDH_BODY)$(printf "%02x" $ECDH_PAD)$ECDH_PAYLOAD
for i in $(seq 1 $ECDH_PAD); do ECDH_PKT+="00"; done
echo "Sending ECDH INIT ($(( ${#ECDH_PKT} / 2 )) bytes)..."
echo -ne "$(echo $ECDH_PKT | xxd -r -p)" >&3
sleep 0.5

# Read response
echo "Reading response..."
res4=$(dd bs=1 count=4 <&3 2>/dev/null | xxd -p)
if [ -z "$res4" ]; then
  echo "NO RESPONSE (connection closed/timed out)"
else
  res_len=$((16#${res4}))
  echo "Response len: $res_len"
  dd bs=1 count=$res_len <&3 2>/dev/null | xxd | head -10
fi
echo "DONE"
