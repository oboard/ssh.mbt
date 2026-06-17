///
/// 哈希算法包装（SSH 所需：SHA-1, SHA-256）。

///|
/// 摘要算法枚举。
pub enum Algorithm {
  Sha1 = 1
  Sha256 = 2
} derive(Eq, Debug)

///|
/// SHA-1 算法（输出 20 字节）。
pub fn Algorithm::sha1() -> Algorithm {
  Sha1
}

///|
/// SHA-256 算法（输出 32 字节）。
pub fn Algorithm::sha256() -> Algorithm {
  Sha256
}

///|
/// 返回算法的输出长度（字节数）。
pub fn Algorithm::output_len(self : Algorithm) -> Int {
  match self {
    Sha1 => 20
    Sha256 => 32
  }
}

///|
fn alg_id(a : Algorithm) -> Int {
  match a {
    Sha1 => 1
    Sha256 => 2
  }
}

///|
#external
type MdCtx

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
/// 增量哈希计算上下文（基于 OpenSSL EVP_MD_CTX）。
pub struct Hasher {
  ctx : MdCtx
  alg : Algorithm
}

///|
/// 创建指定算法的增量哈希上下文。
pub fn Hasher::new(alg : Algorithm) -> Hasher raise CryptoError {
  ensure_openssl()
  let ctx = md_ctx_new_ffi()
  if md_init_ffi(ctx, alg_id(alg)) != 1 {
    md_ctx_free_ffi(ctx)
    raise CryptoError::OperationFailed("EVP_DigestInit_ex", err_get_and_clear())
  }
  { ctx, alg }
}

///|
/// 向哈希上下文追加数据。
pub fn Hasher::update(self : Hasher, data : Bytes) -> Unit raise CryptoError {
  if md_update_ffi(self.ctx, data, data.length()) != 1 {
    raise CryptoError::OperationFailed("EVP_DigestUpdate", err_get_and_clear())
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
/// 完成哈希计算，返回摘要值并释放上下文。
pub fn Hasher::finalize(self : Hasher) -> Bytes raise CryptoError {
  let out_len_ref = Ref(0)
  let out = FixedArray::make(self.alg.output_len(), b'\x00')
  let rc = md_final_ffi(self.ctx, out, out_len_ref)
  md_ctx_free_ffi(self.ctx)
  if rc != 1 || out_len_ref.val != self.alg.output_len() {
    raise CryptoError::OperationFailed(
      "EVP_DigestFinal_ex",
      err_get_and_clear(),
    )
  }
  Bytes::from_array(out)
}

///|
/// 一次性计算摘要（等价于 new + update + finalize）。
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
    raise CryptoError::OperationFailed("EVP_Digest", err_get_and_clear())
  }
  Bytes::from_array(out)
}
