///|
/// 公钥操作封装。包含：
/// - RSA 签名/验签（ssh-rsa, rsa-sha2-256）
/// - PEM 加载
/// - ECDH P-256 密钥生成和派生
#external
type Pkey

///|
extern "C" fn pkey_new_ffi() -> Pkey = "moonbitlang_ssh_pkey_new"

///|
extern "C" fn pkey_free_ffi(p : Pkey) = "moonbitlang_ssh_pkey_free"

///|
extern "C" fn pkey_size_ffi(p : Pkey) -> Int = "moonbitlang_ssh_pkey_size"

///|
#borrow(tbs, sig, sig_len)
extern "C" fn rsa_sign_ffi(
  p : Pkey,
  md_alg : Int,
  tbs : Bytes,
  tbs_len : Int,
  sig : FixedArray[Byte],
  sig_len : Ref[Int],
) -> Int = "moonbitlang_ssh_rsa_sign"

///|
#borrow(tbs, sig)
extern "C" fn rsa_verify_ffi(
  p : Pkey,
  md_alg : Int,
  tbs : Bytes,
  tbs_len : Int,
  sig : Bytes,
  sig_len : Int,
) -> Int = "moonbitlang_ssh_rsa_verify"

///|
#borrow(path, out)
extern "C" fn pem_read_private_key_ffi(
  path : Bytes,
  path_len : Int,
  out : Ref[Pkey],
) -> Int = "moonbitlang_ssh_pem_read_private_key"

///|
#borrow(path, out)
extern "C" fn pem_read_public_key_ffi(
  path : Bytes,
  path_len : Int,
  out : Ref[Pkey],
) -> Int = "moonbitlang_ssh_pem_read_public_key"

// ECDH P-256

///|
#borrow(priv_out, pub_buf, pub_len)
extern "C" fn ecdh_gen_key_ffi(
  priv_out : Ref[Pkey],
  pub_buf : FixedArray[Byte],
  pub_len : Ref[Int],
) -> Int = "moonbitlang_ssh_ecdh_gen_key"

///|
#borrow(peer_pub, out, out_len)
extern "C" fn ecdh_derive_ffi(
  our : Pkey,
  peer_pub : Bytes,
  peer_len : Int,
  out : FixedArray[Byte],
  out_len : Ref[Int],
) -> Int = "moonbitlang_ssh_ecdh_derive"

///|
#borrow(n, e, out)
extern "C" fn pkey_new_rsa_ffi(
  n : Bytes,
  n_len : Int,
  e : Bytes,
  e_len : Int,
  out : Ref[Pkey],
) -> Int = "moonbitlang_ssh_pkey_new_rsa"

///|
/// 公钥包装。
pub struct PKey {
  ptr : Pkey
}

///|
pub fn PKey::load_private_key(path : String) -> PKey raise CryptoError {
  ensure_openssl()
  let out : Ref[Pkey] = Ref(pkey_new_ffi())
  let path_bytes = @utf8.encode(path)
  let rc = pem_read_private_key_ffi(path_bytes, path_bytes.length(), out)
  if rc != 1 {
    pkey_free_ffi(out.val)
    raise CryptoError::OperationFailed(
      "PEM_read_bio_PrivateKey",
      err_get_and_clear(),
    )
  }
  { ptr: out.val }
}

///|
pub fn PKey::load_public_key(path : String) -> PKey raise CryptoError {
  ensure_openssl()
  let out : Ref[Pkey] = Ref(pkey_new_ffi())
  let path_bytes = @utf8.encode(path)
  let rc = pem_read_public_key_ffi(path_bytes, path_bytes.length(), out)
  if rc != 1 {
    pkey_free_ffi(out.val)
    raise CryptoError::OperationFailed(
      "PEM_read_bio_PUBKEY",
      err_get_and_clear(),
    )
  }
  { ptr: out.val }
}

///|
pub fn PKey::from_rsa_components(
  n : Bytes,
  e : Bytes,
) -> PKey raise CryptoError {
  ensure_openssl()
  let out : Ref[Pkey] = Ref(pkey_new_ffi())
  let rc = pkey_new_rsa_ffi(n, n.length(), e, e.length(), out)
  if rc != 1 {
    pkey_free_ffi(out.val)
    raise CryptoError::OperationFailed("RSA fromdata", err_get_and_clear())
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
/// 包内使用：获取原始指针。
fn PKey::raw_ptr(self : PKey) -> Pkey {
  self.ptr
}

///|
/// RSA 签名。md_alg: 1=SHA1, 2=SHA256。
pub fn PKey::sign(
  self : PKey,
  md_alg : Int,
  data : Bytes,
) -> Bytes raise CryptoError {
  let sig_cap = 512
  let arr = FixedArray::make(sig_cap, b'\x00')
  let sig_len = Ref(sig_cap)
  let rc = rsa_sign_ffi(self.ptr, md_alg, data, data.length(), arr, sig_len)
  if rc != 1 {
    raise CryptoError::OperationFailed("RSA_sign", err_get_and_clear())
  }
  let view = FixedArray::makei(sig_len.val, i => arr.unsafe_get(i))
  Bytes::from_array(view)
}

///|
pub fn PKey::verify(
  self : PKey,
  md_alg : Int,
  data : Bytes,
  sig : Bytes,
) -> Bool raise CryptoError {
  let rc = rsa_verify_ffi(
    self.ptr,
    md_alg,
    data,
    data.length(),
    sig,
    sig.length(),
  )
  if rc < 0 {
    raise CryptoError::OperationFailed("RSA_verify", err_get_and_clear())
  }
  rc == 1
}

// ==================== ECDH P-256 ====================

///|
pub fn ecdh_nistp256_generate() -> (PKey, Bytes) raise CryptoError {
  ensure_openssl()
  let priv_out : Ref[Pkey] = Ref(pkey_new_ffi())
  let pub_buf = FixedArray::make(256, b'\x00')
  let pub_len = Ref(256)
  let rc = ecdh_gen_key_ffi(priv_out, pub_buf, pub_len)
  if rc != 1 {
    pkey_free_ffi(priv_out.val)
    raise CryptoError::OperationFailed("ecdh_gen_key", err_get_and_clear())
  }
  let pub_arr = FixedArray::makei(pub_len.val, i => pub_buf.unsafe_get(i))
  ({ ptr: priv_out.val }, Bytes::from_array(pub_arr))
}

///|
pub fn ecdh_nistp256_derive(
  our : PKey,
  peer_pub_sec1 : Bytes,
) -> Bytes raise CryptoError {
  ensure_openssl()
  let out = FixedArray::make(32, b'\x00')
  let out_len = Ref(32)
  let rc = ecdh_derive_ffi(
    our.ptr,
    peer_pub_sec1,
    peer_pub_sec1.length(),
    out,
    out_len,
  )
  if rc != 1 {
    raise CryptoError::OperationFailed("ecdh_derive", err_get_and_clear())
  }
  let view = FixedArray::makei(out_len.val, i => out.unsafe_get(i))
  Bytes::from_array(view)
}
