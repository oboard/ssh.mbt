///
/// HMAC 包装（RFC 2104）。用于 SSH MAC（hmac-sha2-256, hmac-sha1）。
/// 纯 MoonBit 实现，底层使用 cc06b/mooncry/lib。

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
/// 一次性 HMAC 计算。
pub fn hmac(
  alg : MacAlgorithm,
  key : Bytes,
  data : Bytes,
) -> Bytes raise CryptoError {
  match alg {
    HmacSha1 => @lib.hmac_sha1(key, data)
    HmacSha256 => @lib.hmac_sha256(key, data)
  }
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
  let data = array_to_bytes(self.buf)
  let result = hmac(self.alg, self.key, data)
  self.buf.clear()
  result
}

///|
pub fn Mac::hmac_on(self : Mac, data : Bytes) -> Bytes raise CryptoError {
  hmac(self.alg, self.key, data)
}

///|
pub fn Mac::alg_output_len(self : Mac) -> Int {
  self.alg.output_len()
}

///|
pub fn truncate(tag : Bytes, n : Int) -> Bytes {
  if n >= tag.length() {
    return tag
  }
  let arr = FixedArray::makei(n, i => tag[i])
  Bytes::from_array(arr)
}

///|
fn array_to_bytes(buf : Array[Byte]) -> Bytes {
  let fixed = FixedArray::makei(buf.length(), i => buf[i])
  Bytes::from_array(fixed)
}
