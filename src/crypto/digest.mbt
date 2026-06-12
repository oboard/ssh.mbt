///
/// 哈希算法包装（SSH 所需：SHA-1, SHA-256）。

///
pub enum Algorithm {
  Sha1 = 1
  Sha256 = 2
} derive(Eq, Debug)

pub fn Algorithm::sha1() -> Algorithm { Sha1 }
pub fn Algorithm::sha256() -> Algorithm { Sha256 }
pub fn Algorithm::output_len(self : Algorithm) -> Int { match self { Sha1 => 20; Sha256 => 32 } }

fn alg_id(a : Algorithm) -> Int { match a { Sha1 => 1; Sha256 => 2 } }

///
#external
type MdCtx

extern "C" fn md_ctx_new_ffi() -> MdCtx = "moonbitlang_ssh_md_ctx_new"
extern "C" fn md_ctx_free_ffi(ctx : MdCtx) = "moonbitlang_ssh_md_ctx_free"
extern "C" fn md_init_ffi(ctx : MdCtx, alg : Int) -> Int = "moonbitlang_ssh_md_init"

#borrow(data)
extern "C" fn md_update_ffi(ctx : MdCtx, data : Bytes, len : Int) -> Int = "moonbitlang_ssh_md_update"

#borrow(out, out_len)
extern "C" fn md_final_ffi(ctx : MdCtx, out : FixedArray[Byte], out_len : Ref[Int]) -> Int = "moonbitlang_ssh_md_final"

#borrow(data, out, out_len)
extern "C" fn digest_oneshot_ffi(alg : Int, data : Bytes, len : Int, out : FixedArray[Byte], out_len : Ref[Int]) -> Int = "moonbitlang_ssh_digest"

///
pub struct Hasher {
  ctx : MdCtx
  alg : Algorithm
}

///
pub fn Hasher::new(alg : Algorithm) -> Hasher raise CryptoError {
  ensure_openssl()
  let ctx = md_ctx_new_ffi()
  if md_init_ffi(ctx, alg_id(alg)) != 1 {
    md_ctx_free_ffi(ctx)
    raise CryptoError::OperationFailed("EVP_DigestInit_ex", err_get_and_clear())
  }
  { ctx, alg }
}

///
pub fn Hasher::update(self : Hasher, data : Bytes) -> Unit raise CryptoError {
  if md_update_ffi(self.ctx, data, data.length()) != 1 {
    raise CryptoError::OperationFailed("EVP_DigestUpdate", err_get_and_clear())
  }
}

pub fn Hasher::update_string(self : Hasher, s : String) -> Unit raise CryptoError {
  self.update(@utf8.encode(s))
}

///
pub fn Hasher::finalize(self : Hasher) -> Bytes raise CryptoError {
  let out_len_ref = Ref(0)
  let out = FixedArray::make(self.alg.output_len(), b'\x00')
  let rc = md_final_ffi(self.ctx, out, out_len_ref)
  md_ctx_free_ffi(self.ctx)
  if rc != 1 || out_len_ref.val != self.alg.output_len() {
    raise CryptoError::OperationFailed("EVP_DigestFinal_ex", err_get_and_clear())
  }
  Bytes::from_array(out)
}

///
pub fn digest(alg : Algorithm, data : Bytes) -> Bytes raise CryptoError {
  ensure_openssl()
  let out_len_ref = Ref(0)
  let out = FixedArray::make(alg.output_len(), b'\x00')
  let rc = digest_oneshot_ffi(alg_id(alg), data, data.length(), out, out_len_ref)
  if rc != 1 || out_len_ref.val != alg.output_len() {
    raise CryptoError::OperationFailed("EVP_Digest", err_get_and_clear())
  }
  Bytes::from_array(out)
}
