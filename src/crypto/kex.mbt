///|
/// SSH 密钥交换所需的密钥协商原语。
/// - DH Group14 (diffie-hellman-group14-sha256, diffie-hellman-group14-sha1)

// ==================== DH Group14 ====================

///|
pub fn dh_group14_prime() -> @bigint.BigInt {
  @bigint.BigInt::from_string(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    radix=16,
  )
}

///|
pub fn dh_group14_generator() -> @bigint.BigInt {
  @bigint.BigInt::from_int(2)
}

///|
pub fn dh_group14_keygen(
  x : @bigint.BigInt,
) -> (@bigint.BigInt, @bigint.BigInt) {
  let p = dh_group14_prime()
  let g = dh_group14_generator()
  let public_value = g.pow(x, modulus=p)
  (x, public_value)
}

///|
pub fn dh_group14_shared(
  x : @bigint.BigInt,
  peer_pub : @bigint.BigInt,
) -> @bigint.BigInt {
  let p = dh_group14_prime()
  peer_pub.pow(x, modulus=p)
}
