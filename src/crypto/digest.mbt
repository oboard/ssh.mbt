///
/// 哈希算法包装（SSH 所需：SHA-1, SHA-256）。
/// 纯 MoonBit 实现，底层使用 cc06b/mooncry/lib。

///|
/// 摘要算法枚举。
pub enum Algorithm {
  Sha1 = 1
  Sha256 = 2
} derive(Eq, Debug)

///|
pub fn Algorithm::sha1() -> Algorithm {
  Sha1
}

///|
pub fn Algorithm::sha256() -> Algorithm {
  Sha256
}

///|
pub fn Algorithm::output_len(self : Algorithm) -> Int {
  match self {
    Sha1 => 20
    Sha256 => 32
  }
}

///|
/// 增量哈希计算上下文（纯 MoonBit 实现）。
pub struct Hasher {
  alg : Algorithm
  buf : Array[Byte]
}

///|
pub fn Hasher::new(alg : Algorithm) -> Hasher raise CryptoError {
  { alg, buf: [] }
}

///|
pub fn Hasher::update(self : Hasher, data : Bytes) -> Unit raise CryptoError {
  for b in data {
    self.buf.push(b)
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
pub fn Hasher::finalize(self : Hasher) -> Bytes raise CryptoError {
  let data = array_to_bytes(self.buf)
  self.buf.clear()
  digest(self.alg, data)
}

///|
/// 一次性计算摘要。
pub fn digest(alg : Algorithm, data : Bytes) -> Bytes raise CryptoError {
  match alg {
    Sha1 => @lib.sha1(data)
    Sha256 => @lib.sha256(data)
  }
}

///|


