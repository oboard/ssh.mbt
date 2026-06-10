#!/bin/bash
# Test v8: Try adding ext-info-c and strict-kex to see if server requires them
# Also test if standard SSH still works (to rule out rate limiting)

set -x

HOST="cnb.space"
D="/tmp/ssh_$$"
mkdir -p "$D"

# First verify standard SSH works
echo "=== Test A: Standard SSH ==="
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes "$HOST" "echo SSH_OK" 2>&1 | head -3 || echo "Standard SSH FAILED"
echo ""

# Now test raw with ext-info-c and strict-kex
echo "=== Test B: Raw SSH with ext-info-c + strict-kex ==="

exec 3<>/dev/tcp/$HOST/22 || { echo "FAIL connect"; exit 1; }

read -t 5 -u 3 bl; echo "Banner: $bl"
printf 'SSH-2.0-Test\r\n' >&3
sleep 0.2

dd bs=1 count=4 <&3 >"$D/slen" 2>/dev/null
SL=$(xxd -p "$D/slen" | tr -d '\n'); SLEN=$((16#$SL))
dd bs=1 count=$SLEN <&3 >"$D/skex" 2>/dev/null
echo "Server KEX OK ($SLEN bytes)"

P="14"; P+=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | xxd -p | tr -d '\n')

anl() { local s="$1"; local n=${#s}; P+="$(printf '%02x%02x%02x%02x' $((n>>24&255)) $((n>>16&255)) $((n>>8&255)) $((n&255)))"; P+=$(printf '%s' "$s" | xxd -p | tr -d '\n'); }

# Add ext-info-c as FIRST kex algo (per RFC 8308)
# Add kex-strict-s-v00@openssh.com 
anl "ext-info-c,kex-strict-s-v00@openssh.com,curve25519-sha256@libssh.org,curve25519-sha256,ecdh-sha2-nistp256"
anl "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-rsa"
anl "chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
anl "chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
anl "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"
anl "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"
anl "none,zlib@openssh.com"; anl "none,zlib@openssh.com"
anl ""; anl ""
P+="00" "00000000"

PB=$(( ${#P} / 2 ))
R=$(( (PB + 1) % 8 )); [ "$R" -eq 0 ] && PAD=4 || PAD=$((8-R)); [ "$PAD" -lt 4 ] && PAD=4
TOT=$(( PB + PAD + 1 ))
PKT="$(printf '%08x' $TOT)${P}$(printf '%02x' $PAD)"
for ((i=0;i<PAD;i++)); do PKT+="$(printf '%02x' $((RANDOM%256)))"; done

echo -n "$PKT" | xxd -r -p >&3
echo "Sent KEXINT with ext-info-c + strict-kex ($TOT bytes)"

sleep 1
(dd bs=1 count=65536 <&3 >"$D/resp" 2>/dev/null) & PID=$!
sleep 2

if kill $PID 2>/dev/null; then
    wait $PID 2>/dev/null
    echo "*** Still no response after 2s ***"
else
    wait $PID 2>/dev/null
    RSIZE=$(stat -c%s "$D/resp" 2>/dev/null || echo "0")
    if [ "$RSIZE" -gt 0 ]; then
        echo "*** Got $RSIZE bytes response! ***"
        xxd "$D/resp" | head -10
        # Parse msg type (byte 5 = after 4-byte len + 1-byte pad_len)
        MSG=$(od -An -tu1 -N6 "$D/resp" | awk '{print $6}')
        echo "msg_type=$MSG"
    else
        echo "*** Server closed connection (0 bytes) - even with ext-info-c ***"
    fi
fi

exec 3>&-
rm -rf "$D"

# === Test C: What if we DON'T send KEXINIT at all? Just read what server sends ===
echo ""
echo "=== Test C: Don't send KEXINT, just read ==="
exec 3<>/dev/tcp/$HOST/22 || exit 1
read -t 5 -u 3 bl
printf 'SSH-2.0-T\r\n' >&3
sleep 0.2

dd bs=1 count=4 <&3 >"$D/sl2" 2>/dev/null
SL2=$((16#$(xxd -p "$D/sl2" | tr -d '\n')))
dd bs=1 count=$SL2 <&3 >"$D/sk2" 2>/dev/null
echo "Read server KEXINT ($SL2 bytes)"

# Now wait to see if server sends anything else (DISCONNECT?) without us responding
sleep 3
(dd bs=1 count=4 <&3 >"$D/r2" 2>/dev/null) & P2=$!
sleep 2

if kill $P2 2>/dev/null; then
    wait $P2 2>/dev/null
    echo "Server didn't send anything extra (waiting for our KEXINIT)"
else
    wait $P2 2>/dev/null
    RS2=$(stat -c%s "$D/r2" 2>/dev/null || echo "0")
    if [ "$RS2" -gt 0 ]; then
        RL2=$((16#$(xxd -p "$D/r2" | tr -d '\n')))
        dd bs=1 count=$RL2 <&3 >"$D/d2" 2>/dev/null
        M2=$(od -An -tu1 -N6 "$D/d2" | awk '{print $6}')
        echo "Server sent msg_type=$M2 while waiting for our KEXINIT!"
        xxd "$D/d2" | head -5
    fi
fi

exec 3>&-
rm -rf "$D"
echo "DONE"
