///|
/// HMAC 包装（RFC 2104 / RFC 4231）。
/// 用于 SSH MAC 字段（hmac-sha2-256, hmac-sha2-512, hmac-sha1）。

///|
pub enum MacAlgorithm {
  HmacSha1
  HmacSha256
  HmacSha384
  HmacSha512
} derive(Eq, Show)

///|
pub fn MacAlgorithm::hmac_sha1() -> MacAlgorithm {
  HmacSha1
}

///|
pub fn MacAlgorithm::hmac_sha256() -> MacAlgorithm {
  HmacSha256
}

///|
pub fn MacAlgorithm::hmac_sha384() -> MacAlgorithm {
  HmacSha384
}

///|
pub fn MacAlgorithm::hmac_sha512() -> MacAlgorithm {
  HmacSha512
}

///|
pub fn MacAlgorithm::output_len(self : MacAlgorithm) -> Int {
  match self {
    HmacSha1 => 20
    HmacSha256 => 32
    HmacSha384 => 48
    HmacSha512 => 64
  }
}

///|
fn mac_alg_id(a : MacAlgorithm) -> Int {
  match a {
    HmacSha1 => 1
    HmacSha256 => 2
    HmacSha384 => 3
    HmacSha512 => 4
  }
}

// --- FFI ------------------------------------------------------------

///|
#borrow(key, data, out, out_len)
extern "C" fn hmac_oneshot_ffi(
  alg : Int,
  key : Bytes,
  key_len : Int,
  data : Bytes,
  data_len : Int,
  out : FixedArray[Byte],
  out_len : Ref[Int],
) -> Int = "moonbitlang_ssh_hmac"

///|
/// Compute HMAC in a single call. Returns a 20/32/48/64-byte tag.
pub fn hmac(
  alg : MacAlgorithm,
  key : Bytes,
  data : Bytes,
) -> Bytes raise CryptoError {
  ensure_openssl()
  let out_len_ref = Ref(0)
  let out = FixedArray::make(alg.output_len(), b'\x00')
  let rc = hmac_oneshot_ffi(
    mac_alg_id(alg),
    key,
    key.length(),
    data,
    data.length(),
    out,
    out_len_ref,
  )
  if rc != 1 || out_len_ref.val != alg.output_len() {
    raise CryptoError::OperationFailed("EVP_MAC HMAC", err_get_and_clear())
  }
  Bytes::from_fixedarray(out)
}

///|
/// Incremental HMAC. Call `update` zero or more times, then `finalize` to get
/// the tag.
pub struct Mac {
  priv alg : MacAlgorithm
  priv buf : Array[Byte]
  priv key : Bytes
}

///|
pub fn Mac::new(alg : MacAlgorithm, key : Bytes) -> Mac {
  { alg, buf: [], key }
}

///|
pub fn Mac::update(self : Mac, data : Bytes) -> Unit {
  for b in data {
    self.buf.push(b)
  }
}

///|
pub fn Mac::update_string(self : Mac, s : String) -> Unit {
  self.update(@utf8.encode(s))
}

///|
pub fn Mac::finalize(self : Mac) -> Bytes raise CryptoError {
  let data = Bytes::from_array(self.buf)
  hmac(self.alg, self.key, data)
}

///|
/// Truncate a MAC tag to the first `n` bytes (used for ETM modes).
pub fn truncate(tag : Bytes, n : Int) -> Bytes {
  if tag.length() <= n {
    return tag
  }
  let arr = tag.to_fixedarray()
  let sliced = FixedArray::makei(n, i => arr.unsafe_get(i))
  Bytes::from_fixedarray(sliced)
}
