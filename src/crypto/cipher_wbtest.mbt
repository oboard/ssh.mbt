// Whitebox tests for cipher.mbt (AES-128-CTR).
// Run `moon test --target native` to execute.

// ============== CipherAlgorithm properties ==============

///|
test "cipher_algorithm/aes128_ctr_id" {
  let alg = CipherAlgorithm::aes128_ctr()
  inspect(alg.id(), content="1")
}

///|
test "cipher_algorithm/aes128_ctr_key_len" {
  let alg = CipherAlgorithm::aes128_ctr()
  inspect(alg.key_len(), content="16")
}

///|
test "cipher_algorithm/aes128_ctr_iv_len" {
  let alg = CipherAlgorithm::aes128_ctr()
  inspect(alg.iv_len(), content="16")
}

///|
test "cipher_algorithm/aes128_ctr_block_len" {
  let alg = CipherAlgorithm::aes128_ctr()
  inspect(alg.block_len(), content="16")
}

///|
test "cipher_algorithm/eq" {
  let a = CipherAlgorithm::aes128_ctr()
  let b = CipherAlgorithm::aes128_ctr()
  inspect(a == b, content="true")
}

// ============== Cipher encrypt/decrypt roundtrip ==============

///|
test "cipher/encrypt_decrypt_roundtrip" {
  let key = Bytes::from_array([
    b'\x2b', b'\x7e', b'\x15', b'\x16', b'\x28', b'\xae', b'\xd2', b'\xa6',
    b'\xab', b'\xf7', b'\x15', b'\x88', b'\x09', b'\xcf', b'\x4f', b'\x3c',
  ])
  let iv = Bytes::from_array([
    b'\xf0', b'\xf1', b'\xf2', b'\xf3', b'\xf4', b'\xf5', b'\xf6', b'\xf7',
    b'\xf8', b'\xf9', b'\xfa', b'\xfb', b'\xfc', b'\xfd', b'\xfe', b'\xff',
  ])
  let plaintext = Bytes::from_array([
    b'\x6b', b'\xc1', b'\xbe', b'\xe2', b'\x2e', b'\x40', b'\x9f', b'\x96',
    b'\xe9', b'\x3d', b'\x7e', b'\x11', b'\x73', b'\x93', b'\x17', b'\x2a',
  ])

  // Encrypt
  let enc = Cipher::new(Aes128Ctr, key, iv, encrypt=true) catch {
    _ => abort("Cipher::new encrypt failed")
  }
  let ciphertext = enc.update(plaintext) catch {
    _ => abort("Cipher::update encrypt failed")
  }
  let _ = enc.finalize() catch { _ => abort("Cipher::finalize encrypt failed") }
  enc.close()

  // Ciphertext should differ from plaintext
  inspect(ciphertext != plaintext, content="true")
  inspect(ciphertext.length(), content="16")

  // Decrypt with same key/iv
  let dec = Cipher::new(Aes128Ctr, key, iv, encrypt=false) catch {
    _ => abort("Cipher::new decrypt failed")
  }
  let decrypted = dec.update(ciphertext) catch {
    _ => abort("Cipher::update decrypt failed")
  }
  let _ = dec.finalize() catch { _ => abort("Cipher::finalize decrypt failed") }
  dec.close()

  // Should recover original plaintext
  inspect(decrypted == plaintext, content="true")
}

// ============== Cipher invalid arguments ==============

///|
test "cipher/bad_key_length_raises" {
  let short_key = Bytes::from_array([b'\x00', b'\x01', b'\x02'])
  let iv = Bytes::make(16, b'\x00')
  try {
    let _ = Cipher::new(Aes128Ctr, short_key, iv, encrypt=true)
    fail("expected CryptoError")
  } catch {
    CryptoError::InvalidArgument(_) => ()
    _ => fail("expected InvalidArgument")
  }
}

///|
test "cipher/bad_iv_length_raises" {
  let key = Bytes::make(16, b'\x00')
  let short_iv = Bytes::make(8, b'\x00')
  try {
    let _ = Cipher::new(Aes128Ctr, key, short_iv, encrypt=true)
    fail("expected CryptoError")
  } catch {
    CryptoError::InvalidArgument(_) => ()
    _ => fail("expected InvalidArgument")
  }
}

// ============== Cipher empty input ==============

///|
test "cipher/empty_update_returns_empty" {
  let key = Bytes::make(16, b'\x00')
  let iv = Bytes::make(16, b'\x00')
  let enc = Cipher::new(Aes128Ctr, key, iv, encrypt=true) catch {
    _ => abort("Cipher::new failed")
  }
  let result = enc.update(b"") catch { _ => abort("Cipher::update failed") }
  let _ = enc.finalize() catch { _ => abort("Cipher::finalize failed") }
  enc.close()
  inspect(result.length(), content="0")
}
