///
/// HMAC 包装（RFC 2104）。用于 SSH MAC（hmac-sha2-256, hmac-sha1）。

///|
pub enum MacAlgorithm {
  HmacSha1
  HmacSha256
} derive(Eq, Debug)

///|
pub fn MacAlgorithm::hmac_sha1() -> MacAlgorithm {
  HmacSha1
}

///|
pub fn MacAlgorithm::hmac_sha256() -> MacAlgorithm {
  HmacSha256
}

///|
pub fn MacAlgorithm::output_len(self : MacAlgorithm) -> Int {
  match self {
    HmacSha1 => 20
    HmacSha256 => 32
  }
}

///|
fn mac_alg_id(a : MacAlgorithm) -> Int {
  match a {
    HmacSha1 => 1
    HmacSha256 => 2
  }
}

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
    raise CryptoError::OperationFailed("HMAC", err_get_and_clear())
  }
  Bytes::from_array(out)
}

///|
pub struct Mac {
  alg : MacAlgorithm
  buf : Array[Byte]
  key : Bytes
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
pub fn Mac::finalize(self : Mac) -> Bytes raise CryptoError {
  hmac(self.alg, self.key, Bytes::from_array(self.buf))
}

///|
pub fn Mac::alg_output_len(self : Mac) -> Int {
  self.alg.output_len()
}

///|
pub fn truncate(tag : Bytes, n : Int) -> Bytes {
  if tag.length() <= n {
    return tag
  }
  let arr = tag.to_fixedarray()
  let sliced = FixedArray::makei(n, i => arr.unsafe_get(i))
  Bytes::from_array(sliced)
}
