///
/// 对称加密原语。
/// 算法 id: 1 = aes128-ctr

///
pub enum CipherAlgorithm {
  Aes128Ctr
} derive(Eq, Debug)

pub fn CipherAlgorithm::aes128_ctr() -> CipherAlgorithm { Aes128Ctr }
pub fn CipherAlgorithm::id(self : CipherAlgorithm) -> Int { 1 }
pub fn CipherAlgorithm::key_len(self : CipherAlgorithm) -> Int { 16 }
pub fn CipherAlgorithm::iv_len(self : CipherAlgorithm) -> Int { 16 }
pub fn CipherAlgorithm::block_len(self : CipherAlgorithm) -> Int { 16 }

///
#external
type CipherCtx

extern "C" fn cipher_ctx_new_ffi() -> CipherCtx = "moonbitlang_ssh_cipher_ctx_new"
extern "C" fn cipher_ctx_free_ffi(ctx : CipherCtx) = "moonbitlang_ssh_cipher_ctx_free"

#borrow(key, iv)
extern "C" fn cipher_init_ffi(ctx : CipherCtx, alg : Int, encrypt : Int, key : Bytes, iv : Bytes) -> Int = "moonbitlang_ssh_cipher_init"

#borrow(in_, out, out_len)
extern "C" fn cipher_update_ffi(ctx : CipherCtx, encrypt : Int, in_ : Bytes, in_len : Int, out : FixedArray[Byte], out_len : Ref[Int]) -> Int = "moonbitlang_ssh_cipher_update"

#borrow(out, out_len)
extern "C" fn cipher_final_ffi(ctx : CipherCtx, encrypt : Int, out : FixedArray[Byte], out_len : Ref[Int]) -> Int = "moonbitlang_ssh_cipher_final"

///
/// 流加密上下文。
pub struct Cipher {
  ctx : CipherCtx
  alg : CipherAlgorithm
  encrypt : Bool
}

///
pub fn Cipher::new(alg : CipherAlgorithm, key : Bytes, iv : Bytes, encrypt~ : Bool) -> Cipher raise CryptoError {
  ensure_openssl()
  if key.length() != alg.key_len() {
    raise CryptoError::InvalidArgument("key length \{key.length()} != \{alg.key_len()}")
  }
  if iv.length() != alg.iv_len() {
    raise CryptoError::InvalidArgument("iv length \{iv.length()} != \{alg.iv_len()}")
  }
  let ctx = cipher_ctx_new_ffi()
  let rc = cipher_init_ffi(ctx, alg.id(), if encrypt { 1 } else { 0 }, key, iv)
  if rc != 1 {
    cipher_ctx_free_ffi(ctx)
    raise CryptoError::OperationFailed("EVP_CipherInit_ex", err_get_and_clear())
  }
  { ctx, alg, encrypt }
}

///
pub fn Cipher::update(self : Cipher, in_ : Bytes) -> Bytes raise CryptoError {
  let in_len = in_.length()
  let out_cap = in_len + self.alg.block_len()
  let out = FixedArray::make(out_cap, b'\x00')
  let out_len = Ref(0)
  let rc = cipher_update_ffi(self.ctx, if self.encrypt { 1 } else { 0 }, in_, in_len, out, out_len)
  if rc != 1 {
    raise CryptoError::OperationFailed("EVP_*Update", err_get_and_clear())
  }
  let out_arr = FixedArray::makei(out_len.val, i => out.unsafe_get(i))
  Bytes::from_array(out_arr)
}

///
pub fn Cipher::finalize(self : Cipher) -> Bytes raise CryptoError {
  let out = FixedArray::make(self.alg.block_len(), b'\x00')
  let out_len = Ref(0)
  let rc = cipher_final_ffi(self.ctx, if self.encrypt { 1 } else { 0 }, out, out_len)
  if rc != 1 {
    raise CryptoError::OperationFailed("EVP_*Final_ex", err_get_and_clear())
  }
  let out_arr = FixedArray::makei(out_len.val, i => out.unsafe_get(i))
  Bytes::from_array(out_arr)
}

///
pub fn Cipher::close(self : Cipher) -> Unit { cipher_ctx_free_ffi(self.ctx) }
