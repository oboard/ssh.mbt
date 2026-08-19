///
/// 对称加密原语。AES-128-CTR 纯 MoonBit 实现，底层使用 cc06b/mooncry/lib。

///|
pub enum CipherAlgorithm {
  Aes128Ctr
} derive(Eq, Debug)

///|
pub fn CipherAlgorithm::aes128_ctr() -> CipherAlgorithm {
  Aes128Ctr
}

///|
pub fn CipherAlgorithm::id(_self : CipherAlgorithm) -> Int {
  1
}

///|
pub fn CipherAlgorithm::key_len(_self : CipherAlgorithm) -> Int {
  16
}

///|
pub fn CipherAlgorithm::iv_len(_self : CipherAlgorithm) -> Int {
  16
}

///|
pub fn CipherAlgorithm::block_len(_self : CipherAlgorithm) -> Int {
  16
}

///|
/// 流加密上下文（纯 MoonBit，mooncry AES-CTR）。
/// mooncry aes_ctr_encrypt/decrypt 是无状态的（每次传入完整 key+counter），
/// 所以我们累积 block_offset 来跟踪流位置。
pub struct Cipher {
  alg : CipherAlgorithm
  encrypt : Bool
  key : Bytes
  // 初始 IV 的前 12 字节作为 nonce，后 4 字节转为 big-endian counter
  nonce : Bytes
  priv mut block_offset : UInt64
}

///|
pub fn Cipher::new(
  alg : CipherAlgorithm,
  key : Bytes,
  iv : Bytes,
  encrypt~ : Bool,
) -> Cipher raise CryptoError {
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
  // For AES-CTR in SSH, the IV is the initial counter block (16 bytes).
  // We store the full 16-byte IV as nonce for use with mooncry.
  let nonce = iv
  { alg, encrypt, key, nonce, block_offset: 0UL }
}

///|
/// 对输入数据执行加密或解密（流模式）。
pub fn Cipher::update(self : Cipher, in_ : Bytes) -> Bytes raise CryptoError {
  let out = aes_ctr_process(self.key, self.nonce, self.block_offset, in_)
  // advance block_offset by number of 16-byte blocks consumed (round up)
  let n_bytes = in_.length().to_uint64()
  let blocks = (n_bytes + 15UL) / 16UL
  self.block_offset = self.block_offset + blocks
  out
}

///|
/// CTR mode is symmetric; no-op finalize.
pub fn Cipher::finalize(_self : Cipher) -> Bytes raise CryptoError {
  b""
}

///|
pub fn Cipher::close(_self : Cipher) -> Unit {
  // pure MoonBit — nothing to free
}

///|
/// Apply AES-128-CTR keystream starting from `block_offset` (0-indexed block number).
/// Uses mooncry's aes_ctr_encrypt which takes a 16-byte key and 16-byte counter block.
fn aes_ctr_process(
  key : Bytes,
  iv : Bytes,
  block_offset : UInt64,
  data : Bytes,
) -> Bytes raise CryptoError {
  // Build the counter block from iv + block_offset.
  // SSH uses the full 16-byte IV as the initial counter block (big-endian counter
  // spread across the last 8 bytes by adding block_offset).
  // We reconstruct by treating iv as a 128-bit big-endian integer and adding block_offset.
  let ctr = add_counter(iv, block_offset)
  // mooncry aes_ctr_encrypt(data, key, counter) -> Bytes
  @lib.aes_ctr(data, key, ctr)
}

///|
/// Add a 64-bit counter to a 16-byte big-endian counter block (IV).
fn add_counter(iv : Bytes, delta : UInt64) -> Bytes {
  let arr = FixedArray::makei(16, i => iv[i])
  // Add delta to the low 8 bytes (bytes 8..15) as big-endian uint64.
  let mut carry = delta
  let mut i = 15
  while i >= 8 && carry > 0UL {
    let b = arr.unsafe_get(i).to_int().reinterpret_as_uint()
    let sum = b.to_uint64() + (carry & 0xFFUL)
    arr[i] = (sum & 0xFFUL).to_int().to_byte()
    carry = (carry >> 8) + (sum >> 8)
    i = i - 1
  }
  // propagate carry into bytes 0..7 if needed
  while i >= 0 && carry > 0UL {
    let b = arr.unsafe_get(i).to_int().reinterpret_as_uint()
    let sum = b.to_uint64() + (carry & 0xFFUL)
    arr[i] = (sum & 0xFFUL).to_int().to_byte()
    carry = sum >> 8
    i = i - 1
  }
  Bytes::from_array(arr)
}
