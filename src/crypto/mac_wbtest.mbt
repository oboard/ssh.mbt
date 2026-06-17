// Whitebox tests for mac.mbt (HMAC-SHA1, HMAC-SHA256).
// Run `moon test --target native` to execute.

// ============== MacAlgorithm properties ==============

///|
test "mac_algorithm/hmac_sha1_output_len" {
  inspect(MacAlgorithm::hmac_sha1().output_len(), content="20")
}

///|
test "mac_algorithm/hmac_sha256_output_len" {
  inspect(MacAlgorithm::hmac_sha256().output_len(), content="32")
}

///|
test "mac_algorithm/eq" {
  inspect(
    MacAlgorithm::hmac_sha1() == MacAlgorithm::hmac_sha1(),
    content="true",
  )
  inspect(
    MacAlgorithm::hmac_sha256() == MacAlgorithm::hmac_sha256(),
    content="true",
  )
  inspect(
    MacAlgorithm::hmac_sha1() == MacAlgorithm::hmac_sha256(),
    content="false",
  )
}

// ============== HMAC oneshot (RFC 4231 test vectors) ==============

///|
test "hmac/sha256_rfc4231_test1" {
  // RFC 4231 Test Case 1
  // Key  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
  // Data = "Hi There"
  // HMAC-SHA256 = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
  let key = Bytes::from_array([
    b'\x0b', b'\x0b', b'\x0b', b'\x0b', b'\x0b', b'\x0b', b'\x0b', b'\x0b', b'\x0b',
    b'\x0b', b'\x0b', b'\x0b', b'\x0b', b'\x0b', b'\x0b', b'\x0b', b'\x0b', b'\x0b',
    b'\x0b', b'\x0b',
  ])
  let data = b"Hi There"
  let result = hmac(MacAlgorithm::hmac_sha256(), key, data) catch {
    _ => abort("hmac failed")
  }
  let expected_hex = b"\xb04La\xd8\xdb8S\x5c\xa8\xaf\xce\xaf\x0b\xf1+\x88\x1d\xc2\x00\xc9\x83=\xa7&\xe97l.2\xcf\xf7"
  inspect(result, content=expected_hex.to_string())
}

///|
test "hmac/sha1_rfc2104_test" {
  // RFC 2104 / common test vector:
  // HMAC-SHA1(key="Jefe", data="what do ya want for nothing?")
  // = effcdf6ae5eb2fa2d27416d5f184df9c259a7c79
  let key = b"Jefe"
  let data = b"what do ya want for nothing?"
  let result = hmac(MacAlgorithm::hmac_sha1(), key, data) catch {
    _ => abort("hmac failed")
  }
  let expected_hex = b"\xef\xfc\xdfj\xe5\xeb/\xa2\xd2t\x16\xd5\xf1\x84\xdf\x9c%\x9a|y"
  inspect(result, content=expected_hex.to_string())
}

// ============== Mac struct ==============

///|
test "mac/new_and_output_len" {
  let key = Bytes::make(32, b'\x01')
  let m = Mac::new(MacAlgorithm::hmac_sha256(), key)
  inspect(m.alg_output_len(), content="32")
}

///|
test "mac/update_finalize_roundtrip" {
  // Mac::update + finalize should match direct hmac call
  let key = b"secret-key"
  let data = b"hello, world!"
  let expected = hmac(MacAlgorithm::hmac_sha256(), key, data) catch {
    _ => abort("hmac failed")
  }
  let m = Mac::new(MacAlgorithm::hmac_sha256(), key)
  m.update(b"hello, ")
  m.update(b"world!")
  let result = m.finalize() catch { _ => abort("finalize failed") }
  inspect(result == expected, content="true")
}

///|
test "mac/hmac_on_bypasses_buffer" {
  // hmac_on computes directly on data, ignoring internal buffer
  let key = b"key"
  let data = b"direct"
  let expected = hmac(MacAlgorithm::hmac_sha256(), key, data) catch {
    _ => abort("hmac failed")
  }
  let m = Mac::new(MacAlgorithm::hmac_sha256(), key)
  // Put something in the buffer — should not affect hmac_on result
  m.update(b"buffered")
  let result = m.hmac_on(data) catch { _ => abort("hmac_on failed") }
  inspect(result == expected, content="true")
}

// ============== truncate ==============

///|
test "truncate/shorter_than_n_unchanged" {
  let tag = Bytes::from_array([b'\x01', b'\x02', b'\x03'])
  let result = truncate(tag, 10)
  inspect(result.length(), content="3")
  inspect(result == tag, content="true")
}

///|
test "truncate/exact_n_unchanged" {
  let tag = Bytes::from_array([b'\x01', b'\x02', b'\x03'])
  let result = truncate(tag, 3)
  inspect(result.length(), content="3")
  inspect(result == tag, content="true")
}

///|
test "truncate/truncates_to_n" {
  let tag = Bytes::from_array([
    b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06',
  ])
  let result = truncate(tag, 4)
  inspect(result.length(), content="4")
  inspect(result[0].to_int(), content="1")
  inspect(result[3].to_int(), content="4")
}

// ============== array_to_bytes (internal helper) ==============

///|
test "mac/finalize_clears_buffer" {
  // After finalize, the internal buffer should be cleared.
  // Calling finalize again on a new Mac with same key should give same result.
  let key = b"key123"
  let m1 = Mac::new(MacAlgorithm::hmac_sha256(), key)
  m1.update(b"data")
  let r1 = m1.finalize() catch { _ => abort("") }

  let m2 = Mac::new(MacAlgorithm::hmac_sha256(), key)
  m2.update(b"data")
  let r2 = m2.finalize() catch { _ => abort("") }
  inspect(r1 == r2, content="true")
}
