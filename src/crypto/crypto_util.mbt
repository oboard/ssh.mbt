///
/// 密码学工具函数：随机数生成（使用 moonbitlang/async/tls rand_bytes）。
/// 注：async/tls 的 rand_bytes 内部使用 OpenSSL RAND_bytes，
/// 但本项目不再维护自己的 openssl.c，改为复用已有的系统 TLS 实现。

///|
/// 生成 `num` 字节的密码学安全随机字节。
pub fn rand_bytes(num : Int) -> Bytes raise CryptoError {
  @tls.rand_bytes(num) catch {
    e => raise CryptoError::RandomFailed(Repr(e).to_string())
  }
}

///|
/// OpenSSL 错误兼容 stubs（纯 MoonBit 实现无 OpenSSL 错误队列）。
pub fn err_get_error() -> String {
  ""
}

///|
pub fn err_peek_code() -> UInt {
  0U
}

///|
pub fn err_clear() -> Unit {
  ()
}

///|
pub fn err_get_and_clear() -> String {
  ""
}
