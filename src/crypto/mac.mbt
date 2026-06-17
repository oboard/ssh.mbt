///
/// HMAC 包装（RFC 2104）。用于 SSH MAC（hmac-sha2-256, hmac-sha1）。

///|
/// HMAC 算法枚举。
pub enum MacAlgorithm {
  HmacSha1
  HmacSha256
} derive(Eq, Debug)

///|
/// HMAC-SHA1（输出 20 字节）。
pub fn MacAlgorithm::hmac_sha1() -> MacAlgorithm {
  HmacSha1
}

///|
/// HMAC-SHA256（输出 32 字节）。
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
/// 一次性 HMAC 计算。
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
/// 增量 HMAC 计算上下文（先 update 再 finalize）。
pub struct Mac {
  alg : MacAlgorithm
  buf : Array[Byte]
  key : Bytes
}

///|
/// 创建增量 HMAC 上下文。
pub fn Mac::new(alg : MacAlgorithm, key : Bytes) -> Mac {
  { alg, buf: [], key }
}

///|
/// 向 HMAC 上下文追加数据。
pub fn Mac::update(self : Mac, data : Bytes) -> Unit {
  for b in data {
    self.buf.push(b)
  }
}

///|
/// 完成 HMAC 计算，返回标签值并清空内部缓冲区。
pub fn Mac::finalize(self : Mac) -> Bytes raise CryptoError {
  let data = array_to_bytes(self.buf)
  let result = hmac(self.alg, self.key, data)
  self.buf.clear()
  result
}

///|
/// 直接对外部数据计算 HMAC（绕过内部缓冲区）。
pub fn Mac::hmac_on(self : Mac, data : Bytes) -> Bytes raise CryptoError {
  hmac(self.alg, self.key, data)
}

///|
fn array_to_bytes(buf : Array[Byte]) -> Bytes {
  let len = buf.length()
  let fixed = FixedArray::makei(len, i => buf[i])
  Bytes::from_array(fixed)
}

///|
/// 返回当前 MAC 算法的输出长度（字节数）。
pub fn Mac::alg_output_len(self : Mac) -> Int {
  self.alg.output_len()
}

///|
/// 截断 HMAC 标签到指定长度（ETM 模式使用）。
pub fn truncate(tag : Bytes, n : Int) -> Bytes {
  if tag.length() <= n {
    return tag
  }
  let arr = tag.to_fixedarray()
  let sliced = FixedArray::makei(n, i => arr.unsafe_get(i))
  Bytes::from_array(sliced)
}
