///|
/// SSH 协议层需要的 hash 算法包装。算法 id:
///   1 = SHA-1   (RFC 4253 §6.4; 仅 host key 旧兼容)
///   2 = SHA-256 (RFC 6668 / RFC 4253 kex)
///   3 = SHA-384
///   4 = SHA-512 (RFC 6668 SHA-512 算法族)

///|
pub enum Algorithm {
  Sha1 = 1
  Sha256 = 2
  Sha384 = 3
  Sha512 = 4
} derive(Eq, Show)

///|
pub fn Algorithm::sha1() -> Algorithm {
  Sha1
}

///|
pub fn Algorithm::sha256() -> Algorithm {
  Sha256
}

pub fn Algorithm::sha384() -> Algorithm {
  Sha384
}

pub fn Algorithm::sha512() -> Algorithm {
  Sha512
}

///|
pub fn Algorithm::output_len(self : Algorithm) -> Int {
  match self {
    Sha1 => 20
    Sha256 => 32
    Sha384 => 48
    Sha512 => 64
  }
}

///|
pub fn Algorithm::block_len(self : Algorithm) -> Int {
  match self {
    Sha1 | Sha256 => 64
    Sha384 | Sha512 => 128
  }
}

///|
fn alg_id(a : Algorithm) -> Int {
  match a {
    Sha1 => 1
    Sha256 => 2
    Sha384 => 3
    Sha512 => 4
  }
}

// --- FFI ------------------------------------------------------------

///|
#external
priv type MdCtx

///|
extern "C" fn md_ctx_new_ffi() -> MdCtx = "moonbitlang_ssh_md_ctx_new"

///|
extern "C" fn md_ctx_free_ffi(ctx : MdCtx) = "moonbitlang_ssh_md_ctx_free"

///|
extern "C" fn md_init_ffi(ctx : MdCtx, alg : Int) -> Int = "moonbitlang_ssh_md_init"

///|
#borrow(data)
extern "C" fn md_update_ffi(ctx : MdCtx, data : Bytes, len : Int) -> Int = "moonbitlang_ssh_md_update"

///|
#borrow(out, out_len)
extern "C" fn md_final_ffi(
  ctx : MdCtx,
  out : FixedArray[Byte],
  out_len : Ref[Int],
) -> Int = "moonbitlang_ssh_md_final"

///|
#borrow(data, out, out_len)
extern "C" fn digest_oneshot_ffi(
  alg : Int,
  data : Bytes,
  len : Int,
  out : FixedArray[Byte],
  out_len : Ref[Int],
) -> Int = "moonbitlang_ssh_digest"

///|
extern "C" fn md_size_ffi(alg : Int) -> Int = "moonbitlang_ssh_md_size"

// --- Public API ----------------------------------------------------

///|
/// Incremental hasher. Use `update` repeatedly then `finalize` to get digest.
pub struct Hasher {
  priv ctx : MdCtx
  priv alg : Algorithm
}

///|
pub fn Hasher::new(alg : Algorithm) -> Hasher raise CryptoError {
  ensure_openssl()
  let ctx = md_ctx_new_ffi()
  if md_init_ffi(ctx, alg_id(alg)) != 1 {
    md_ctx_free_ffi(ctx)
    err_clear()
    raise CryptoError::OperationFailed("EVP_DigestInit_ex", err_get_error())
  }
  { ctx, alg }
}

///|
pub fn Hasher::update(self : Hasher, data : Bytes) -> Unit raise CryptoError {
  if md_update_ffi(self.ctx, data, data.length()) != 1 {
    err_clear()
    raise CryptoError::OperationFailed("EVP_DigestUpdate", err_get_error())
  }
}

///|
pub fn Hasher::update_string(
  self : Hasher,
  s : String,
) -> Unit raise CryptoError {
  self.update(@utf8.encode(s))
}

///|
/// Finalize and return the digest. The hasher is consumed.
pub fn Hasher::finalize(self : Hasher) -> Bytes raise CryptoError {
  let out_len_ref = Ref(0)
  let out = FixedArray::make(self.alg.output_len(), b'\x00')
  let rc = md_final_ffi(self.ctx, out, out_len_ref)
  md_ctx_free_ffi(self.ctx)
  if rc != 1 || out_len_ref.val != self.alg.output_len() {
    err_clear()
    raise CryptoError::OperationFailed("EVP_DigestFinal_ex", err_get_error())
  }
  Bytes::from_fixedarray(out)
}

// --- One-shot ------------------------------------------------------

///|
/// Compute digest in a single call. Convenience over `Hasher`.
pub fn digest(alg : Algorithm, data : Bytes) -> Bytes raise CryptoError {
  ensure_openssl()
  let out_len_ref = Ref(0)
  let out = FixedArray::make(alg.output_len(), b'\x00')
  let rc = digest_oneshot_ffi(
    alg_id(alg),
    data,
    data.length(),
    out,
    out_len_ref,
  )
  if rc != 1 || out_len_ref.val != alg.output_len() {
    err_clear()
    raise CryptoError::OperationFailed("EVP_Digest", err_get_error())
  }
  Bytes::from_fixedarray(out)
}

///|
pub fn digest_string(alg : Algorithm, s : String) -> Bytes raise CryptoError {
  digest(alg, @utf8.encode(s))
}
