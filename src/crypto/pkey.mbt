///|
/// EVP_PKEY 包装。支持 SSH 协议层需要的所有公钥操作：
///   - Ed25519: 签名 / 验签（host key）
///   - RSA: 签名 / 验签（host key）
///   - ECDSA (nistp256): 签名 / 验签（host key）
///   - X25519: ECDH 共享密钥派生（kex）
///   - ECDH (nistp256): 共享密钥派生（kex）
///
/// key_type id（C 侧使用）：
///   1 = X25519, 2 = Ed25519, 3 = RSA, 4 = EC (nistp256)

///|
pub enum KeyType {
  X25519
  Ed25519
  Rsa
  EcP256
} derive(Eq, Show)

// Factory functions for cross-package construction (enum constructors are package-private)
pub fn KeyType::x25519() -> KeyType { X25519 }
pub fn KeyType::ed25519() -> KeyType { Ed25519 }
pub fn KeyType::rsa() -> KeyType { Rsa }
pub fn KeyType::ec_p256() -> KeyType { EcP256 }

///|
pub fn KeyType::id(self : KeyType) -> Int {
  match self {
    X25519 => 1
    Ed25519 => 2
    Rsa => 3
    EcP256 => 4
  }
}

///|
pub fn KeyType::name(self : KeyType) -> String {
  match self {
    X25519 => "x25519"
    Ed25519 => "ssh-ed25519"
    Rsa => "ssh-rsa"
    EcP256 => "ecdsa-sha2-nistp256"
  }
}

// --- FFI ------------------------------------------------------------

///|
#external
priv type Pkey

///|
extern "C" fn pkey_new_ffi() -> Pkey = "moonbitlang_ssh_pkey_new"

///|
extern "C" fn pkey_free_ffi(p : Pkey) = "moonbitlang_ssh_pkey_free"

///|
#borrow(bits, out)
extern "C" fn pkey_keygen_ffi(
  key_type : Int,
  bits : Int,
  out : Ref[Pkey],
) -> Int = "moonbitlang_ssh_pkey_keygen"

///|
#borrow(raw, out)
extern "C" fn pkey_new_raw_ffi(
  key_type : Int,
  raw : Bytes,
  raw_len : Int,
  out : Ref[Pkey],
) -> Int = "moonbitlang_ssh_pkey_new_raw_private"

///|
#borrow(scalar, out)
extern "C" fn pkey_new_ec_ffi(
  scalar : Bytes,
  scalar_len : Int,
  out : Ref[Pkey],
) -> Int = "moonbitlang_ssh_pkey_new_ec"

///|
#borrow(n, e, d, out)
extern "C" fn pkey_new_rsa_ffi(
  n : Bytes,
  n_len : Int,
  e : Bytes,
  e_len : Int,
  d : Bytes,
  d_len : Int,
  out : Ref[Pkey],
) -> Int = "moonbitlang_ssh_pkey_new_rsa"

///|
#borrow(tbs, sig, sig_len)
extern "C" fn pkey_sign_ffi(
  p : Pkey,
  md_alg : Int,
  tbs : Bytes,
  tbs_len : Int,
  sig : FixedArray[Byte],
  sig_len : Ref[Int],
) -> Int = "moonbitlang_ssh_pkey_sign"

///|
#borrow(tbs, sig)
extern "C" fn pkey_verify_ffi(
  p : Pkey,
  md_alg : Int,
  tbs : Bytes,
  tbs_len : Int,
  sig : Bytes,
  sig_len : Int,
) -> Int = "moonbitlang_ssh_pkey_verify"

///|
#borrow(buf, buf_len)
extern "C" fn pkey_get_raw_pub_ffi(
  p : Pkey,
  buf : FixedArray[Byte],
  buf_len : Ref[Int],
) -> Int = "moonbitlang_ssh_pkey_get_raw_public"

///|
#borrow(buf, buf_len)
extern "C" fn pkey_get_raw_priv_ffi(
  p : Pkey,
  buf : FixedArray[Byte],
  buf_len : Ref[Int],
) -> Int = "moonbitlang_ssh_pkey_get_raw_private"

///|
extern "C" fn pkey_size_ffi(p : Pkey) -> Int = "moonbitlang_ssh_pkey_size"

///|
extern "C" fn pkey_get_id_ffi(p : Pkey) -> Int = "moonbitlang_ssh_pkey_get_id"

// --- Public wrapper -------------------------------------------------

///|
/// Opaque wrapper around an OpenSSL `EVP_PKEY *`. Holds a single reference;
/// freed on `close`.
pub struct PKey {
  priv ptr : Pkey
}

///|
pub fn PKey::generate(typ : KeyType) -> PKey raise CryptoError {
  ensure_openssl()
  let out : Ref[Pkey] = Ref::new(pkey_new_ffi())
  let bits = match typ {
    Rsa => 3072 // 3072-bit minimum per RFC 4253 §6.6
    _ => 0
  }
  let rc = pkey_keygen_ffi(typ.id(), bits, out)
  if rc != 1 {
    pkey_free_ffi(out.val)
    err_clear()
    raise CryptoError::OperationFailed("EVP_PKEY_keygen", err_get_error())
  }
  { ptr: out.val }
}

///|
/// Build a key from raw bytes (32 bytes for X25519 / Ed25519 private or
/// public, 32 bytes for nistp256 private scalar).
pub fn PKey::from_raw(typ : KeyType, raw : Bytes) -> PKey raise CryptoError {
  ensure_openssl()
  let out : Ref[Pkey] = Ref::new(pkey_new_ffi())
  let rc = match typ {
    X25519 | Ed25519 => pkey_new_raw_ffi(typ.id(), raw, raw.length(), out)
    EcP256 => pkey_new_ec_ffi(raw, raw.length(), out)
    Rsa =>
      raise CryptoError::InvalidArgument(
        "RSA keys must be built via from_rsa_components",
      )
  }
  if rc != 1 {
    pkey_free_ffi(out.val)
    err_clear()
    raise CryptoError::OperationFailed("EVP_PKEY_fromdata", err_get_error())
  }
  { ptr: out.val }
}

///|
/// Build an RSA public key from `(n, e)` components, or a private key if
/// `d_opt` is provided.
pub fn PKey::from_rsa_components(
  n : Bytes,
  e : Bytes,
  d_opt? : Bytes = b"",
) -> PKey raise CryptoError {
  ensure_openssl()
  let out : Ref[Pkey] = Ref::new(pkey_new_ffi())
  let rc = pkey_new_rsa_ffi(
    n,
    n.length(),
    e,
    e.length(),
    d_opt,
    d_opt.length(),
    out,
  )
  if rc != 1 {
    pkey_free_ffi(out.val)
    err_clear()
    raise CryptoError::OperationFailed("RSA fromdata", err_get_error())
  }
  { ptr: out.val }
}

///|
pub fn PKey::close(self : PKey) -> Unit {
  pkey_free_ffi(self.ptr)
}

///|
pub fn PKey::size(self : PKey) -> Int {
  pkey_size_ffi(self.ptr)
}

///|
pub fn PKey::id(self : PKey) -> Int {
  pkey_get_id_ffi(self.ptr)
}

///|
/// Access the raw `EVP_PKEY*` for use by other crypto modules (e.g.
/// `kex.mbt`). Internal API — callers should not free the pointer.
fn PKey::raw_ptr(self : PKey) -> Pkey {
  self.ptr
}

///|
/// Return the raw public key bytes (32 bytes for X25519/Ed25519).
pub fn PKey::raw_public(self : PKey) -> Bytes raise CryptoError {
  let arr = FixedArray::make(256, b'\x00')
  let len = Ref(0)
  let rc = pkey_get_raw_pub_ffi(self.ptr, arr, len)
  if rc != 1 {
    err_clear()
    raise CryptoError::OperationFailed(
      "EVP_PKEY_get_raw_public_key",
      err_get_error(),
    )
  }
  let view = FixedArray::makei(len.val, i => arr.unsafe_get(i))
  Bytes::from_fixedarray(view)
}

///|
/// Return the raw private key bytes (32 bytes for X25519/Ed25519).
pub fn PKey::raw_private(self : PKey) -> Bytes raise CryptoError {
  let arr = FixedArray::make(256, b'\x00')
  let len = Ref(0)
  let rc = pkey_get_raw_priv_ffi(self.ptr, arr, len)
  if rc != 1 {
    err_clear()
    raise CryptoError::OperationFailed(
      "EVP_PKEY_get_raw_private_key",
      err_get_error(),
    )
  }
  let view = FixedArray::makei(len.val, i => arr.unsafe_get(i))
  Bytes::from_fixedarray(view)
}

///|
/// Sign `data` with this key. `md_alg` is 0 for pure algorithms (Ed25519);
/// 1..4 for digest algorithms (RSA / ECDSA).
pub fn PKey::sign(
  self : PKey,
  md_alg : Int,
  data : Bytes,
) -> Bytes raise CryptoError {
  let sig_cap = 512
  let arr = FixedArray::make(sig_cap, b'\x00')
  let sig_len = Ref(sig_cap)
  let rc = pkey_sign_ffi(self.ptr, md_alg, data, data.length(), arr, sig_len)
  if rc != 1 {
    err_clear()
    raise CryptoError::OperationFailed("EVP_PKEY_sign", err_get_error())
  }
  let view = FixedArray::makei(sig_len.val, i => arr.unsafe_get(i))
  Bytes::from_fixedarray(view)
}

///|
/// Verify a signature. Returns true if valid.
pub fn PKey::verify(
  self : PKey,
  md_alg : Int,
  data : Bytes,
  sig : Bytes,
) -> Bool raise CryptoError {
  let rc = pkey_verify_ffi(
    self.ptr,
    md_alg,
    data,
    data.length(),
    sig,
    sig.length(),
  )
  if rc < 0 {
    err_clear()
    raise CryptoError::OperationFailed("EVP_PKEY_verify", err_get_error())
  }
  rc == 1
}
