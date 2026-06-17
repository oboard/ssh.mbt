// Whitebox tests for pkey.mbt (PKey, base64, ECDH).
// Run `moon test --target native` to execute.

// ============== base64_decode ==============

///|
test "base64_decode/simple" {
  // "SGVsbG8=" -> "Hello"
  let result = base64_decode("SGVsbG8=") catch {
    _ => abort("base64_decode failed")
  }
  let expected = b"Hello"
  inspect(result == expected, content="true")
}

///|
test "base64_decode/empty" {
  let result = base64_decode("") catch { _ => abort("base64_decode failed") }
  inspect(result.length(), content="0")
}

// ///|
// test "base64_decode/no_padding" {
//   // "SGVsbG8" (no padding) -> "Hello"
//   let result = base64_decode("SGVsbG8") catch {
//     _ => abort("base64_decode failed")
//   }
//   let expected = b"Hello"
//   inspect(result == expected, content="true")
// }

///|
test "base64_decode/with_whitespace" {
  // Whitespace should be ignored
  let result = base64_decode("SGVs\nbG8=") catch {
    _ => abort("base64_decode failed")
  }
  let expected = b"Hello"
  inspect(result == expected, content="true")
}

///|
test "base64_decode/invalid_raises" {
  try {
    let _ = base64_decode("!!!invalid!!!")
    fail("expected CryptoError")
  } catch {
    CryptoError::OperationFailed(_, _) => ()
    _ => fail("expected OperationFailed")
  }
}

// ============== ECDH P-256 ==============

///|
test "ecdh/generate_and_derive_shared_secret" {
  // Two parties generate keys and derive the same shared secret
  let (priv_a, pub_a) = ecdh_nistp256_generate() catch {
    _ => abort("ecdh generate A failed")
  }
  let (priv_b, pub_b) = ecdh_nistp256_generate() catch {
    _ => abort("ecdh generate B failed")
  }
  let shared_a = ecdh_nistp256_derive(priv_a, pub_b) catch {
    _ => abort("ecdh derive A failed")
  }
  let shared_b = ecdh_nistp256_derive(priv_b, pub_a) catch {
    _ => abort("ecdh derive B failed")
  }
  // Both sides should derive the same 32-byte shared secret
  inspect(shared_a.length(), content="32")
  inspect(shared_a == shared_b, content="true")
  priv_a.close()
  priv_b.close()
}

///|
test "ecdh/pub_key_format" {
  // P-256 uncompressed point: 04 || x || y, total 65 bytes
  let (_, pub_key) = ecdh_nistp256_generate() catch {
    _ => abort("ecdh generate failed")
  }
  // Public key should start with 0x04 (uncompressed point)
  inspect(pub_key[0].to_int(), content="4")
  inspect(pub_key.length(), content="65")
}
