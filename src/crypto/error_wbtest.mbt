// Whitebox tests for `error.mbt`.
// Error variants are package-private; this file lives inside the package so
// it can construct and pattern-match on them directly.

///|
test "RandomFailed carries its message" {
  let e : CryptoError = RandomFailed("entropy source down")
  // Show output must include the message for debuggability.
  let s = e.to_string()
  assert_true(s.contains("entropy"))
}

///|
test "OperationFailed carries op name and detail" {
  let e : CryptoError = OperationFailed("EVP_DigestInit_ex", "bad alg")
  let s = e.to_string()
  assert_true(s.contains("EVP_DigestInit_ex"))
  assert_true(s.contains("bad alg"))
}

///|
test "InvalidArgument carries its message" {
  let e : CryptoError = InvalidArgument("key length 8 != 16")
  let s = e.to_string()
  assert_true(s.contains("key length"))
}

///|
test "CryptoError equality is structural" {
  assert_eq(RandomFailed("a"), RandomFailed("a"))
  assert_true(RandomFailed("a") != RandomFailed("b"))
  assert_true(RandomFailed("a") != OperationFailed("a", "b"))
  assert_true(OperationFailed("x", "y") != OperationFailed("x", "z"))
  assert_true(InvalidArgument("a") != InvalidArgument("b"))
}
