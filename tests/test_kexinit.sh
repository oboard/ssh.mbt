#!/bin/bash
# Test: send the exact KEXINIT that MoonSSH would generate
exec 3<>/dev/tcp/cnb.space/22

# Read server banner
read -r line <&3
echo "BANNER: $line"

# Send our banner as MoonSSH does
echo -ne "SSH-2.0-MoonSSH_0.1.0\r\n" >&3
sleep 0.2

# Build a KEXINIT similar to what MoonSSH build_kexinit_payload produces
# The payload from build_kexinit_payload:
# SSH_MSG_KEXINIT(1) + cookie(16) + name_lists + first_kex_follows(1) + reserved(4)
#
# We need to construct the payload first, then wrap it in a packet
# Using Python-like construction with echo/printf

# Step 1: construct KEXINIT payload
# 1 byte: 0x14 (SSH_MSG_KEXINIT)
# 16 bytes: random cookie (use zeros for test)
# Then name-lists as computed by the MoonBit code

# Let me use the EXACT same algorithm names MoonSSH uses
KEX_ALGS="curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1"
HK_ALGS="ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-256,ssh-rsa"
ENC_ALGS="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
MAC_ALGS="hmac-sha2-512,hmac-sha2-256,hmac-sha1"
COMP_ALGS="none"

plen() { printf "%08x" $(echo -n "$1" | wc -c); }

# Build KEXINIT payload hex
P="14" # SSH_MSG_KEXINIT
P+="000102030405060708090a0b0c0d0e0f" # 16-byte cookie

# Write name-lists: 4-byte big-endian length + data
write_nl() {
  local len=$(echo -n "$1" | wc -c)
  printf -v hex "%08x" $len
  P+="$hex"
  P+=$(echo -n "$1" | xxd -p)
}

write_nl "$KEX_ALGS"
write_nl "$HK_ALGS"
write_nl "$ENC_ALGS"
write_nl "$ENC_ALGS"
write_nl "$MAC_ALGS"
write_nl "$MAC_ALGS"
write_nl "$COMP_ALGS"
write_nl "$COMP_ALGS"
# language lists - empty
write_nl ""
write_nl ""
# first_kex_follows
P+="00"
# reserved
P+="00000000"

PAYLOAD_LEN=$(( ${#P} / 2 ))
echo "KEX payload size: $PAYLOAD_LEN bytes"

# Step 2: compute padding (block_size=8, min_pad=4)
# body = 1 (pad_len) + payload + padding
# Must be multiple of 8
PAD=4
BODY=$((1 + PAYLOAD_LEN + PAD))
REM=$((BODY % 8))
if [ $REM -ne 0 ]; then
  PAD=$((PAD + 8 - REM))
  BODY=$((1 + PAYLOAD_LEN + PAD))
fi
echo "padding: $PAD, body: $BODY"

# Step 3: build packet
PKT=$(printf "%08x" $BODY) # 4-byte length
PKT+=$(printf "%02x" $PAD) # 1-byte padding length
PKT+="$P"                  # payload
for i in $(seq 1 $PAD); do PKT+="00"; done # padding zeros

echo "Packet size: $(( ${#PKT} / 2 )) bytes"
echo -ne "$(echo $PKT | xxd -r -p)" >&3

sleep 0.5

echo "Reading response..."
dd bs=1 count=4 <&3 2>/dev/null | xxd
echo "Done"
