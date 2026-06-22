// Whitebox tests for kex.mbt (DH Group14).
// Run `moon test --target native` to execute.

// ============== DH Group14 constants ==============

///|
test "dh_group14/prime_is_nonzero" {
  let p = dh_group14_prime()
  // The prime should be a large positive number (2048-bit)
  inspect(p > @bigint.BigInt::from_int(0), content="true")
}

///|
test "dh_group14/generator_is_2" {
  let g = dh_group14_generator()
  inspect(g.to_int(), content="2")
}

// ============== DH Group14 keygen / shared secret ==============

///|
test "dh_group14/keygen_shared_secret_agree" {
  // Two parties derive the same shared secret from their key pairs
  let x_a = @bigint.BigInt::from_int(12345)
  let x_b = @bigint.BigInt::from_int(67890)
  let (_, pub_a) = dh_group14_keygen(x_a)
  let (_, pub_b) = dh_group14_keygen(x_b)
  let shared_a = dh_group14_shared(x_a, pub_b)
  let shared_b = dh_group14_shared(x_b, pub_a)
  inspect(shared_a == shared_b, content="true")
}

///|
test "dh_group14/keygen_public_value_range" {
  // Public value g^x mod p should be in [2, p-1]
  let x = @bigint.BigInt::from_int(42)
  let p = dh_group14_prime()
  let (_, pub_val) = dh_group14_keygen(x)
  inspect(pub_val > @bigint.BigInt::from_int(1), content="true")
  inspect(pub_val < p, content="true")
}
