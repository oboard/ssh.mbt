///|
/// MAC (HMAC) 单元测试：RFC 4231 测试向量。
test "HMAC-SHA256 RFC 4231 Test Case 2" {
  // Key = "Jefe"
  // Data = "what do ya want for nothing?"
  let key = @utf8.encode("Jefe")
  let data = @utf8.encode("what do ya want for nothing?")
  let tag = @crypto.hmac(@crypto.MacAlgorithm::hmac_sha256(), key, data)
  // Expected: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
  assert_eq(tag.length(), 32)
  assert_eq(tag.unsafe_get(0).to_int(), 0x5b)
  assert_eq(tag.unsafe_get(1).to_int(), 0xdc)
}

///|
test "HMAC-SHA256 empty data" {
  let key = Bytes::make(32, b'\x0b')
  let tag = @crypto.hmac(@crypto.MacAlgorithm::hmac_sha256(), key, b"")
  assert_eq(tag.length(), 32)
}

///|
test "HMAC-SHA512 RFC 4231 Test Case 1" {
  let key = Bytes::make(20, b'\x0b')
  let data = @utf8.encode("Hi There")
  let tag = @crypto.hmac(@crypto.MacAlgorithm::hmac_sha512(), key, data)
  // Expected: 87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cded817d69f1fcd3d28f91a64b50d2e88bc
  assert_eq(tag.length(), 64)
  assert_eq(tag.unsafe_get(0).to_int(), 0x87)
  assert_eq(tag.unsafe_get(1).to_int(), 0xaa)
}

///|
test "HMAC-SHA1 basic" {
  let key = @utf8.encode("key")
  let data = @utf8.encode("data")
  let tag = @crypto.hmac(@crypto.MacAlgorithm::hmac_sha1(), key, data)
  assert_eq(tag.length(), 20)
}

///|
test "Mac incremental matches oneshot" {
  let key = Bytes::make(16, b'\xAA')
  let data1 = @utf8.encode("Test ")
  let data2 = @utf8.encode("message")

  let oneshot_tag = @crypto.hmac(
    @crypto.MacAlgorithm::hmac_sha256(),
    key,
    data1 + data2,
  )

  let mac = @crypto.Mac::new(@crypto.MacAlgorithm::hmac_sha256(), key)
  mac.update(data1)
  mac.update(data2)
  let inc_tag = mac.finalize()

  assert_eq(oneshot_tag, inc_tag)
}

///|
test "MacAlgorithm::output_len consistency" {
  assert_eq(@crypto.MacAlgorithm::hmac_sha1().output_len(), 20)
  assert_eq(@crypto.MacAlgorithm::hmac_sha256().output_len(), 32)
  assert_eq(@crypto.MacAlgorithm::hmac_sha384().output_len(), 48)
  assert_eq(@crypto.MacAlgorithm::hmac_sha512().output_len(), 64)
}

///|
test "truncate MAC to shorter length" {
  let full = Bytes::make(32, b'\xFF')
  let short = @crypto.truncate(full, 16)
  assert_eq(short.length(), 16)
  for i in 0..<16 {
    assert_eq(short.unsafe_get(i), b'\xFF')
  }
  // Truncating to same or longer returns original
  let same = @crypto.truncate(full, 32)
  assert_eq(same.length(), 32)
  let longer = @crypto.truncate(full, 48)
  assert_eq(longer.length(), 32)
}
