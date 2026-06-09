///|
/// 对称加密原语。
/// 算法 id:
///   1 = aes128-ctr       (RFC 4344 §4; SSH 推荐默认)
///   2 = aes192-ctr
///   3 = aes256-ctr
///   4 = aes128-gcm       (RFC 5647; AEAD)
///   5 = aes256-gcm       (RFC 5647; AEAD)
///   6 = chacha20-poly1305 (RFC 7539; AEAD)

///|
pub enum CipherAlgorithm {
  Aes128Ctr
  Aes192Ctr
  Aes256Ctr
  Aes128Gcm
  Aes256Gcm
  ChaCha20Poly1305
} derive(Eq, Show)

///|
pub fn CipherAlgorithm::aes128_ctr() -> CipherAlgorithm {
  Aes128Ctr
}

///|
pub fn CipherAlgorithm::aes192_ctr() -> CipherAlgorithm {
  Aes192Ctr
}

///|
pub fn CipherAlgorithm::aes256_ctr() -> CipherAlgorithm {
  Aes256Ctr
}

///|
pub fn CipherAlgorithm::aes128_gcm() -> CipherAlgorithm {
  Aes128Gcm
}

///|
pub fn CipherAlgorithm::aes256_gcm() -> CipherAlgorithm {
  Aes256Gcm
}

///|
pub fn CipherAlgorithm::chacha20_poly1305() -> CipherAlgorithm {
  ChaCha20Poly1305
}

///|
pub fn CipherAlgorithm::id(self : CipherAlgorithm) -> Int {
  match self {
    Aes128Ctr => 1
    Aes192Ctr => 2
    Aes256Ctr => 3
    Aes128Gcm => 4
    Aes256Gcm => 5
    ChaCha20Poly1305 => 6
  }
}

///|
pub fn CipherAlgorithm::key_len(self : CipherAlgorithm) -> Int {
  match self {
    Aes128Ctr | Aes128Gcm => 16
    Aes192Ctr => 24
    Aes256Ctr | Aes256Gcm | ChaCha20Poly1305 => 32
  }
}

///|
pub fn CipherAlgorithm::iv_len(self : CipherAlgorithm) -> Int {
  match self {
    Aes128Ctr | Aes192Ctr | Aes256Ctr => 16
    Aes128Gcm | Aes256Gcm => 12
    ChaCha20Poly1305 => 12
  }
}

///|
pub fn CipherAlgorithm::block_len(self : CipherAlgorithm) -> Int {
  match self {
    Aes128Ctr | Aes192Ctr | Aes256Ctr => 16
    Aes128Gcm | Aes256Gcm => 16
    ChaCha20Poly1305 => 64
  }
}

///|
pub fn CipherAlgorithm::tag_len(self : CipherAlgorithm) -> Int {
  match self {
    Aes128Gcm | Aes256Gcm | ChaCha20Poly1305 => 16
    _ => 0
  }
}

///|
pub fn CipherAlgorithm::is_aead(self : CipherAlgorithm) -> Bool {
  self.tag_len() > 0
}

///|
pub fn CipherAlgorithm::name(self : CipherAlgorithm) -> String {
  match self {
    Aes128Ctr => "aes128-ctr"
    Aes192Ctr => "aes192-ctr"
    Aes256Ctr => "aes256-ctr"
    Aes128Gcm => "aes128-gcm@openssh.com"
    Aes256Gcm => "aes256-gcm@openssh.com"
    ChaCha20Poly1305 => "chacha20-poly1305@openssh.com"
  }
}

// --- FFI ------------------------------------------------------------

///|
#external
priv type CipherCtx

///|
extern "C" fn cipher_ctx_new_ffi() -> CipherCtx = "moonbitlang_ssh_cipher_ctx_new"

///|
extern "C" fn cipher_ctx_free_ffi(ctx : CipherCtx) = "moonbitlang_ssh_cipher_ctx_free"

///|
#borrow(key, iv)
extern "C" fn cipher_init_ffi(
  ctx : CipherCtx,
  alg : Int,
  encrypt : Int,
  key : Bytes,
  iv : Bytes,
) -> Int = "moonbitlang_ssh_cipher_init"

///|
extern "C" fn cipher_set_iv_len_ffi(ctx : CipherCtx, iv_len : Int) -> Int = "moonbitlang_ssh_cipher_set_iv_len"

///|
#borrow(tag)
extern "C" fn cipher_set_tag_ffi(
  ctx : CipherCtx,
  tag : FixedArray[Byte],
  tag_len : Int,
) -> Int = "moonbitlang_ssh_cipher_set_tag"

///|
#borrow(tag)
extern "C" fn cipher_get_tag_ffi(
  ctx : CipherCtx,
  tag : FixedArray[Byte],
  tag_len : Int,
) -> Int = "moonbitlang_ssh_cipher_get_tag"

///|
#borrow(in_, out, out_len)
extern "C" fn cipher_update_ffi(
  ctx : CipherCtx,
  encrypt : Int,
  in_ : Bytes,
  in_len : Int,
  out : FixedArray[Byte],
  out_len : Ref[Int],
) -> Int = "moonbitlang_ssh_cipher_update"

///|
#borrow(out, out_len)
extern "C" fn cipher_final_ffi(
  ctx : CipherCtx,
  encrypt : Int,
  out : FixedArray[Byte],
  out_len : Ref[Int],
) -> Int = "moonbitlang_ssh_cipher_final"

// --- Streaming cipher wrapper --------------------------------------

///|
/// Streaming cipher context. For CTR modes, `update` consumes whole blocks
/// and never calls `final` (CTR is its own finalization). For AEAD modes
/// (GCM, ChaCha20-Poly1305), the final `tag` is read out via `final` on
/// encrypt and must be passed back in via `set_tag` on decrypt.
pub struct Cipher {
  priv ctx : CipherCtx
  priv alg : CipherAlgorithm
  priv encrypt : Bool
  priv is_aead : Bool
}

///|
pub fn Cipher::new(
  alg : CipherAlgorithm,
  key : Bytes,
  iv : Bytes,
  encrypt~ : Bool,
) -> Cipher raise CryptoError {
  ensure_openssl()
  if key.length() != alg.key_len() {
    raise CryptoError::InvalidArgument(
      "key length \{key.length()} != \{alg.key_len()}",
    )
  }
  if iv.length() != alg.iv_len() {
    raise CryptoError::InvalidArgument(
      "iv length \{iv.length()} != \{alg.iv_len()}",
    )
  }
  let ctx = cipher_ctx_new_ffi()
  let rc = cipher_init_ffi(ctx, alg.id(), if encrypt { 1 } else { 0 }, key, iv)
  if rc != 1 {
    cipher_ctx_free_ffi(ctx)
    raise CryptoError::OperationFailed(
      "EVP_EncryptInit_ex",
      err_get_and_clear(),
    )
  }
  { ctx, alg, encrypt, is_aead: alg.is_aead() }
}

///|
/// For AEAD: set the expected authentication tag (decrypt only). Call
/// before processing ciphertext.
pub fn Cipher::set_tag(self : Cipher, tag : Bytes) -> Unit raise CryptoError {
  if tag.length() != self.alg.tag_len() {
    raise CryptoError::InvalidArgument(
      "tag length \{tag.length()} != \{self.alg.tag_len()}",
    )
  }
  let arr = tag.to_fixedarray()
  let rc = cipher_set_tag_ffi(self.ctx, arr, arr.length())
  if rc != 1 {
    raise CryptoError::OperationFailed(
      "EVP_CTRL_GCM_SET_TAG",
      err_get_and_clear(),
    )
  }
}

///|
/// Get the authentication tag after the last `update` (encrypt only).
/// Returns the 16-byte tag.
pub fn Cipher::get_tag(self : Cipher) -> Bytes raise CryptoError {
  let arr = FixedArray::make(self.alg.tag_len(), b'\x00')
  let rc = cipher_get_tag_ffi(self.ctx, arr, arr.length())
  if rc != 1 {
    raise CryptoError::OperationFailed(
      "EVP_CTRL_GCM_GET_TAG",
      err_get_and_clear(),
    )
  }
  Bytes::from_fixedarray(arr)
}

///|
/// Process `in_` and return ciphertext/plaintext bytes.
pub fn Cipher::update(self : Cipher, in_ : Bytes) -> Bytes raise CryptoError {
  let in_len = in_.length()
  // For CTR/GCM: out can be at most in_len + block_len
  let out_cap = in_len + self.alg.block_len()
  let out = FixedArray::make(out_cap, b'\x00')
  let out_len = Ref(0)
  let rc = cipher_update_ffi(
    self.ctx,
    if self.encrypt {
      1
    } else {
      0
    },
    in_,
    in_len,
    out,
    out_len,
  )
  if rc != 1 {
    raise CryptoError::OperationFailed("EVP_*Update", err_get_and_clear())
  }
  // Trim
  let out_view = FixedArray::makei(out_len.val, i => out.unsafe_get(i))
  Bytes::from_fixedarray(out_view)
}

///|
/// Finalize the cipher. For CTR modes this is a no-op. For AEAD on encrypt
/// it returns the final tag (use `get_tag` after for clarity). For AEAD on
/// decrypt it validates the tag; failure raises.
pub fn Cipher::finalize(self : Cipher) -> Bytes raise CryptoError {
  let out = FixedArray::make(self.alg.block_len(), b'\x00')
  let out_len = Ref(0)
  let rc = cipher_final_ffi(
    self.ctx,
    if self.encrypt {
      1
    } else {
      0
    },
    out,
    out_len,
  )
  if rc != 1 {
    raise CryptoError::OperationFailed("EVP_*Final_ex", err_get_and_clear())
  }
  let out_view = FixedArray::makei(out_len.val, i => out.unsafe_get(i))
  Bytes::from_fixedarray(out_view)
}

///|
/// Free the underlying context. The `Cipher` value must not be used after
/// `close`.
pub fn Cipher::close(self : Cipher) -> Unit {
  cipher_ctx_free_ffi(self.ctx)
}

// --- One-shot helpers ----------------------------------------------

///|
/// Encrypt a full message in one call (no streaming). Suitable for small
/// payloads (e.g. SSH packet payloads that are <16 KB).
pub fn encrypt(
  alg : CipherAlgorithm,
  key : Bytes,
  iv : Bytes,
  plaintext : Bytes,
) -> (Bytes, Bytes) raise CryptoError {
  let c = Cipher::new(alg, key, iv, encrypt=true)
  let ciphertext = c.update(plaintext)
  let tail = c.finalize()
  let tag = if c.is_aead { c.get_tag() } else { b"" }
  c.close()
  // Concatenate tail with tag (for AEAD, get_tag is the authentication tag)
  if c.is_aead {
    (ciphertext + tail, tag)
  } else {
    (ciphertext + tail, b"")
  }
}

///|
/// Decrypt a full message in one call. For AEAD the caller must pass the
/// expected tag.
pub fn decrypt(
  alg : CipherAlgorithm,
  key : Bytes,
  iv : Bytes,
  ciphertext : Bytes,
  tag? : Bytes = b"",
) -> Bytes raise CryptoError {
  let c = Cipher::new(alg, key, iv, encrypt=false)
  if c.is_aead && tag.length() > 0 {
    c.set_tag(tag)
  }
  let plain = c.update(ciphertext)
  let tail = c.finalize()
  c.close()
  plain + tail
}
