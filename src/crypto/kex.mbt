///|
/// SSH 密钥交换层所需的密钥协商原语。
///   - X25519 (curve25519-sha256, curve25519-sha256@libssh.org)
///   - ECDH nistp256 (ecdh-sha2-nistp256)
///   - DH group14 (diffie-hellman-group14-sha256, 仅作占位)
///   - HKDF-SHA2-256 / HKDF-SHA2-512 (RFC 5869)

///|
#borrow(peer_pub, out, out_len)
extern "C" fn pkey_derive_ffi(
  our : Pkey,
  peer_pub : Bytes,
  peer_pub_len : Int,
  out : FixedArray[Byte],
  out_len : Ref[Int],
) -> Int = "moonbitlang_ssh_pkey_derive"

///|
#borrow(salt, ikm, info, okm)
extern "C" fn hkdf_ffi(
  md_alg : Int,
  salt : Bytes,
  salt_len : Int,
  ikm : Bytes,
  ikm_len : Int,
  info : Bytes,
  info_len : Int,
  okm : FixedArray[Byte],
  okm_len : Int,
) -> Int = "moonbitlang_ssh_hkdf"

// --- X25519 ---------------------------------------------------------

///|
/// Generate a Curve25519 key pair. The 32-byte private scalar is the seed.
pub fn x25519_generate() -> (PKey, Bytes) raise CryptoError {
  let pk = PKey::generate(KeyType::X25519)
  let priv_bytes = pk.raw_private()
  (pk, priv_bytes)
}

///|
/// Re-create a private key from a 32-byte X25519 secret.
pub fn x25519_from_private(priv_bytes : Bytes) -> PKey raise CryptoError {
  PKey::from_raw(KeyType::X25519, priv_bytes)
}

///|
/// Compute the X25519 shared secret (32 bytes) from our private key and the
/// peer's 32-byte raw public key.
pub fn x25519_derive(our : PKey, peer_pub : Bytes) -> Bytes raise CryptoError {
  let out = FixedArray::make(32, b'\x00')
  let out_len = Ref(32)
  let rc = pkey_derive_ffi(
    our.raw_ptr(),
    peer_pub,
    peer_pub.length(),
    out,
    out_len,
  )
  if rc != 1 {
    raise CryptoError::OperationFailed(
      "EVP_PKEY_derive (X25519)",
      err_get_and_clear(),
    )
  }
  let view = FixedArray::makei(out_len.val, i => out.unsafe_get(i))
  Bytes::from_fixedarray(view)
}

// --- ECDH nistp256 --------------------------------------------------

///|
/// Generate a nistp256 EC private key.
pub fn nistp256_generate() -> (PKey, Bytes) raise CryptoError {
  let pk = PKey::generate(KeyType::EcP256)
  let priv_bytes = pk.raw_private()
  (pk, priv_bytes)
}

///|
/// Build a nistp256 private key from a 32-byte scalar.
pub fn nistp256_from_private(priv_bytes : Bytes) -> PKey raise CryptoError {
  PKey::from_raw(KeyType::EcP256, priv_bytes)
}

///|
/// Compute the nistp256 ECDH shared point's X coordinate (32 bytes) from
/// our private key and the peer's uncompressed SEC1 public point
/// (0x04 || X (32) || Y (32)).
pub fn nistp256_derive(
  our : PKey,
  peer_pub_sec1 : Bytes,
) -> Bytes raise CryptoError {
  let out = FixedArray::make(32, b'\x00')
  let out_len = Ref(32)
  let rc = pkey_derive_ffi(
    our.raw_ptr(),
    peer_pub_sec1,
    peer_pub_sec1.length(),
    out,
    out_len,
  )
  if rc != 1 {
    raise CryptoError::OperationFailed(
      "EVP_PKEY_derive (EC)",
      err_get_and_clear(),
    )
  }
  let view = FixedArray::makei(out_len.val, i => out.unsafe_get(i))
  Bytes::from_fixedarray(view)
}

// --- HKDF (RFC 5869) ------------------------------------------------

///|
/// HKDF-SHA-256. `salt` and `info` may be empty (pass `b""`).
pub fn hkdf_sha256(
  ikm : Bytes,
  salt : Bytes,
  info : Bytes,
  length : Int,
) -> Bytes raise CryptoError {
  ensure_openssl()
  let out = FixedArray::make(length, b'\x00')
  let rc = hkdf_ffi(
    2,
    salt,
    salt.length(),
    ikm,
    ikm.length(),
    info,
    info.length(),
    out,
    length,
  )
  if rc != 1 {
    raise CryptoError::OperationFailed("HKDF-SHA256", err_get_and_clear())
  }
  Bytes::from_fixedarray(out)
}

///|
/// HKDF-SHA-512. `salt` and `info` may be empty.
pub fn hkdf_sha512(
  ikm : Bytes,
  salt : Bytes,
  info : Bytes,
  length : Int,
) -> Bytes raise CryptoError {
  ensure_openssl()
  let out = FixedArray::make(length, b'\x00')
  let rc = hkdf_ffi(
    4,
    salt,
    salt.length(),
    ikm,
    ikm.length(),
    info,
    info.length(),
    out,
    length,
  )
  if rc != 1 {
    raise CryptoError::OperationFailed("HKDF-SHA512", err_get_and_clear())
  }
  Bytes::from_fixedarray(out)
}

// --- DH group14 -----------------------------------------------------

///|
/// Oakley Group 14 (RFC 3526 §3): 2048-bit MODP group.
/// Used by `diffie-hellman-group14-sha256` and `diffie-hellman-group14-sha1`.
pub fn dh_group14_prime() -> @bigint.BigInt {
  // RFC 3526 §3, the 2048-bit prime in hex.
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
/// Oakley Group 14 generator `g = 2`.
pub fn dh_group14_generator() -> @bigint.BigInt {
  @bigint.BigInt::from_int(2)
}

///|
/// Compute `pub = g^x mod p` where `x` is a uniform random 256-byte (2048-bit)
/// exponent, `g = 2`, `p` is the Oakley Group 14 prime. Returns the public
/// value as a 256-byte big-endian buffer.
pub fn dh_group14_keygen(
  x : @bigint.BigInt,
) -> (@bigint.BigInt, @bigint.BigInt) raise CryptoError {
  let p = dh_group14_prime()
  let g = dh_group14_generator()
  let public_value = g.pow(x, modulus=p)
  (x, public_value)
}

///|
/// Compute the shared secret `shared = peer_pub^x mod p`.
pub fn dh_group14_shared(
  x : @bigint.BigInt,
  peer_pub : @bigint.BigInt,
) -> @bigint.BigInt raise CryptoError {
  let p = dh_group14_prime()
  peer_pub.pow(x, modulus=p)
}
