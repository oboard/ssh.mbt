// Whitebox tests for digest.mbt (SHA-1, SHA-256).
// Run `moon test --target native` to execute.

// ============== Algorithm properties ==============

///|
test "algorithm/sha1_output_len" {
  let alg = Algorithm::sha1()
  inspect(alg.output_len(), content="20")
}

///|
test "algorithm/sha256_output_len" {
  let alg = Algorithm::sha256()
  inspect(alg.output_len(), content="32")
}

///|
test "algorithm/eq" {
  inspect(Algorithm::sha1() == Algorithm::sha1(), content="true")
  inspect(Algorithm::sha256() == Algorithm::sha256(), content="true")
  inspect(Algorithm::sha1() == Algorithm::sha256(), content="false")
}

// ============== digest oneshot (known test vectors) ==============

///|
test "digest/sha1_abc" {
  // NIST SHA-1 test vector: SHA1("abc")
  let expected_hex = b"\xa9\x99>6G\x06\x81j\xba>%qxP\xc2l\x9c\xd0\xd8\x9d"
  let result = digest(Algorithm::sha1(), b"abc") catch {
    _ => abort("digest failed")
  }
  inspect(result, content=expected_hex.to_string())
}

///|
test "digest/sha256_abc" {
  // NIST SHA-256 test vector: SHA256("abc")
  let expected_hex = b"\xbax\x16\xbf\x8f\x01\xcf\xeaAA@\xde]\xae\x22#\xb0\x03a\xa3\x96\x17z\x9c\xb4\x10\xffa\xf2\x00\x15\xad"
  let result = digest(Algorithm::sha256(), b"abc") catch {
    _ => abort("digest failed")
  }
  inspect(result, content=expected_hex.to_string())
}

///|
test "digest/sha256_empty" {
  // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  let expected_hex = b"\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99o\xb9$'\xaeA\xe4d\x9b\x93L\xa4\x95\x99\x1bxR\xb8U"
  let result = digest(Algorithm::sha256(), b"") catch {
    _ => abort("digest failed")
  }
  inspect(result, content=expected_hex.to_string())
}

// ============== Hasher streaming ==============

///|
test "hasher/sha256_streaming_matches_oneshot" {
  let data1 = b"hello, "
  let data2 = b"world!"
  let oneshot = digest(Algorithm::sha256(), b"hello, world!") catch {
    _ => abort("digest failed")
  }

  let hasher = Hasher::new(Algorithm::sha256()) catch {
    _ => abort("Hasher::new failed")
  }
  hasher.update(data1) catch {
    _ => abort("Hasher::update failed")
  }
  hasher.update(data2) catch {
    _ => abort("Hasher::update failed")
  }
  let streaming = hasher.finalize() catch {
    _ => abort("Hasher::finalize failed")
  }

  inspect(streaming == oneshot, content="true")
}

///|
test "hasher/sha1_streaming" {
  // SHA1("abc") via streaming
  let oneshot = digest(Algorithm::sha1(), b"abc") catch {
    _ => abort("digest failed")
  }
  let hasher = Hasher::new(Algorithm::sha1()) catch {
    _ => abort("Hasher::new failed")
  }
  hasher.update(b"a") catch {
    _ => abort("update failed")
  }
  hasher.update(b"bc") catch {
    _ => abort("update failed")
  }
  let streaming = hasher.finalize() catch { _ => abort("finalize failed") }
  inspect(streaming == oneshot, content="true")
}

///|
test "hasher/sha256_update_string" {
  let oneshot = digest(Algorithm::sha256(), b"abc") catch {
    _ => abort("digest failed")
  }
  let hasher = Hasher::new(Algorithm::sha256()) catch {
    _ => abort("Hasher::new failed")
  }
  hasher.update_string("abc") catch {
    _ => abort("update_string failed")
  }
  let streaming = hasher.finalize() catch { _ => abort("finalize failed") }
  inspect(streaming == oneshot, content="true")
}
