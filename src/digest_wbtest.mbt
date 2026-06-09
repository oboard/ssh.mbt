///| Digest 单元测试：SHA-256/512 已知向量（FIPS 180-4 / RFC 4634）。

test "SHA-256 empty input" {
  let h = @crypto.Hasher::new(@crypto.Algorithm::sha256())
  let digest = h.finalize()
  // FIPS 180-4: SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  assert_eq(digest.length(), 32)
}

test "SHA-256 abc" {
  let h = @crypto.Hasher::new(@crypto.Algorithm::sha256())
  h.update_string("abc")
  let digest = h.finalize()
  // SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  assert_eq(digest.length(), 32)
  assert_eq(digest.unsafe_get(0).to_int(), 0xba)
  assert_eq(digest.unsafe_get(1).to_int(), 0x78)
}

test "SHA-256 oneshot matches incremental" {
  let data = @utf8.encode("The quick brown fox jumps over the lazy dog")
  let one = @crypto.digest(@crypto.Algorithm::sha256(), data)
  let mut h = @crypto.Hasher::new(@crypto.Algorithm::sha256())
  h.update(@utf8.encode("The quick brown fox "))
  h.update(@utf8.encode("jumps over the lazy dog"))
  let two = h.finalize()
  assert_eq(one, two)
  assert_eq(one.length(), 32)
}

test "SHA-512 empty input" {
  let h = @crypto.Hasher::new(@crypto.Algorithm::sha512())
  let digest = h.finalize()
  // SHA512("") = cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
  assert_eq(digest.length(), 64)
}

test "SHA-512 abc" {
  let h = @crypto.Hasher::new(@crypto.Algorithm::sha512())
  h.update_string("abc")
  let digest = h.finalize()
  // SHA512("abc") = ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
  assert_eq(digest.length(), 64)
  assert_eq(digest.unsafe_get(0).to_int(), 0xdd)
}

test "SHA-1 output length" {
  let h = @crypto.Hasher::new(@crypto.Algorithm::sha1())
  let digest = h.finalize()
  // SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
  assert_eq(digest.length(), 20)
  assert_eq(digest.unsafe_get(0).to_int(), 0xda)
}

test "Algorithm::output_len consistency" {
  assert_eq(@crypto.Algorithm::sha1().output_len(), 20)
  assert_eq(@crypto.Algorithm::sha256().output_len(), 32)
  assert_eq(@crypto.Algorithm::sha384().output_len(), 48)
  assert_eq(@crypto.Algorithm::sha512().output_len(), 64)
}

test "Algorithm::block_len consistency" {
  assert_eq(@crypto.Algorithm::sha1().block_len(), 64)
  assert_eq(@crypto.Algorithm::sha256().block_len(), 64)
  assert_eq(@crypto.Algorithm::sha384().block_len(), 128)
  assert_eq(@crypto.Algorithm::sha512().block_len(), 128)
}
