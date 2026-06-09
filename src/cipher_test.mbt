///| Cipher 对称加密单元测试：AES-CTR 加解密往返。

test "AES-128-CTR encrypt-decrypt roundtrip" {
  let alg = @crypto.CipherAlgorithm::aes128_ctr()
  let key = Bytes::make(16, b'\x00')
  let iv = Bytes::make(16, b'\x00')
  let plaintext = @utf8.encode("Hello, MoonSSH!")

  let (ct, _tag) = @crypto.encrypt(alg, key, iv, plaintext)
  let pt = @crypto.decrypt(alg, key, iv, ct)
  assert_eq(pt, plaintext)
}

test "AES-256-CTR encrypt-decrypt roundtrip" {
  let alg = @crypto.CipherAlgorithm::aes256_ctr()
  let key = Bytes::make(32, b'\x42')
  let iv = Bytes::make(16, b'\x00')
  let plaintext = @utf8.encode("AES-256-CTR test payload for SSH encryption")

  let (ct, _tag) = @crypto.encrypt(alg, key, iv, plaintext)
  let pt = @crypto.decrypt(alg, key, iv, ct)
  assert_eq(pt, plaintext)
}

test "AES-192-CTR roundtrip" {
  let alg = @crypto.CipherAlgorithm::aes192_ctr()
  let key = Bytes::make(24, b'\xAB')
  let iv = Bytes::make(16, b'\xCD')
  let plaintext = b"\x00\x01\x02\x03\x04\x05"

  let (ct, _tag) = @crypto.encrypt(alg, key, iv, plaintext)
  let pt = @crypto.decrypt(alg, key, iv, ct)
  assert_eq(pt, plaintext)
}

test "CipherAlgorithm key lengths" {
  assert_eq(@crypto.CipherAlgorithm::aes128_ctr().key_len(), 16)
  assert_eq(@crypto.CipherAlgorithm::aes192_ctr().key_len(), 24)
  assert_eq(@crypto.CipherAlgorithm::aes256_ctr().key_len(), 32)
  assert_eq(@crypto.CipherAlgorithm::aes128_gcm().key_len(), 16)
  assert_eq(@crypto.CipherAlgorithm::aes256_gcm().key_len(), 32)
  assert_eq(@crypto.CipherAlgorithm::chacha20_poly1305().key_len(), 32)
}

test "CipherAlgorithm IV lengths" {
  assert_eq(@crypto.CipherAlgorithm::aes128_ctr().iv_len(), 16)
  assert_eq(@crypto.CipherAlgorithm::aes128_gcm().iv_len(), 12)
  assert_eq(@crypto.CipherAlgorithm::aes256_gcm().iv_len(), 12)
  assert_eq(@crypto.CipherAlgorithm::chacha20_poly1305().iv_len(), 12)
}

test "CipherAlgorithm AEAD detection" {
  assert_true(@crypto.CipherAlgorithm::aes128_gcm().is_aead())
  assert_true(@crypto.CipherAlgorithm::aes256_gcm().is_aead())
  assert_true(@crypto.CipherAlgorithm::chacha20_poly1305().is_aead())
  assert_false(@crypto.CipherAlgorithm::aes128_ctr().is_aead())
  assert_false(@crypto.CipherAlgorithm::aes256_ctr().is_aead())
}

test "CipherAlgorithm tag lengths" {
  assert_eq(@crypto.CipherAlgorithm::aes128_gcm().tag_len(), 16)
  assert_eq(@crypto.CipherAlgorithm::aes256_gcm().tag_len(), 16)
  assert_eq(@crypto.CipherAlgorithm::chacha20_poly1305().tag_len(), 16)
  assert_eq(@crypto.CipherAlgorithm::aes128_ctr().tag_len(), 0)
}

test "AES-256-GCM encrypt-decrypt with tag" {
  let alg = @crypto.CipherAlgorithm::aes256_gcm()
  let key = Bytes::make(32, b'\x01')
  let iv = Bytes::make(12, b'\x00')
  let plaintext = @utf8.encode("AEAD encrypted message")

  let (ct, tag) = @crypto.encrypt(alg, key, iv, plaintext)
  assert_true(ct.length() > 0)
  assert_true(tag.length() == 16)

  let pt = @crypto.decrypt(alg, key, iv, ct, tag)
  assert_eq(pt, plaintext)
}

test "AES-128-GCM roundtrip" {
  let alg = @crypto.CipherAlgorithm::aes128_gcm()
  let key = Bytes::make(16, b'\xDE')
  let iv = Bytes::make(12, b'\xAD')
  let plaintext = b"\x00\x11\x22\x33\x44\x55\x66\x77"

  let (ct, tag) = @crypto.encrypt(alg, key, iv, plaintext)
  let pt = @crypto.decrypt(alg, key, iv, ct, tag)
  assert_eq(pt, plaintext)
}

test "ChaCha20-Poly1305 roundtrip" {
  let alg = @crypto.CipherAlgorithm::chacha20_poly1305()
  let key = Bytes::make(32, b'\xCC')
  let iv = Bytes::make(12, b'\xBB')
  let plaintext = @utf8.encode("ChaCha20-Poly1305 SSH cipher")

  let (ct, tag) = @crypto.encrypt(alg, key, iv, plaintext)
  let pt = @crypto.decrypt(alg, key, iv, ct, tag)
  assert_eq(pt, plaintext)
}

test "streaming Cipher update multiple times" {
  let alg = @crypto.CipherAlgorithm::aes256_ctr()
  let key = Bytes::make(32, b'\x11')
  let iv = Bytes::make(16, b'\x22')
  let enc = @crypto.Cipher::new(alg, key, iv, encrypt=true)
  let p1 = enc.update(b"part1")
  let p2 = enc.update(b"part2")
  enc.close()

  let dec = @crypto.Cipher::new(alg, key, iv, encrypt=false)
  let d1 = dec.update(p1)
  let d2 = dec.update(p2)
  dec.close()
  assert_eq(d1 + d2, b"part1part2")
}

test "CipherAlgorithm block_len" {
  assert_eq(@crypto.CipherAlgorithm::aes128_ctr().block_len(), 16)
  assert_eq(@crypto.CipherAlgorithm::aes256_ctr().block_len(), 16)
  assert_eq(@crypto.CipherAlgorithm::aes128_gcm().block_len(), 16)
  assert_eq(@crypto.CipherAlgorithm::chacha20_poly1305().block_len(), 64)
}

test "CipherAlgorithm name strings" {
  assert_eq(@crypto.CipherAlgorithm::aes128_ctr().name(), "aes128-ctr")
  assert_eq(@crypto.CipherAlgorithm::aes256_ctr().name(), "aes256-ctr")
  assert_eq(@crypto.CipherAlgorithm::aes128_gcm().name(), "aes128-gcm@openssh.com")
  assert_eq(@crypto.CipherAlgorithm::chacha20_poly1305().name(), "chacha20-poly1305@openssh.com")
}
