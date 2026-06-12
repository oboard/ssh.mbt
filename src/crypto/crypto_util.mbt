///
/// 密码学工具函数：随机数生成、OpenSSL 错误处理。

#borrow(buf)
extern "C" fn rand_bytes_ffi(buf : FixedArray[Byte], num : Int) -> Int = "moonbitlang_ssh_rand_bytes"

#borrow(buf)
extern "C" fn err_get_error_string_ffi(buf : FixedArray[Byte]) -> Int = "moonbitlang_ssh_get_error_string"

extern "C" fn err_clear_error_ffi() = "moonbitlang_ssh_clear_error"
extern "C" fn err_peek_error_code_ffi() -> UInt = "moonbitlang_ssh_peek_error_code"

///
pub fn rand_bytes(num : Int) -> Bytes raise CryptoError {
  ensure_openssl()
  let result = FixedArray::make(num, b'\x00')
  let rc = rand_bytes_ffi(result, num)
  if rc != 1 {
    err_clear()
    raise CryptoError::RandomFailed("RAND_bytes returned \{rc}")
  }
  Bytes::from_array(result)
}

///
pub fn err_get_error() -> String {
  let buf = FixedArray::make(256, Byte::default())
  let len = err_get_error_string_ffi(buf)
  if len <= 0 { return "" }
  ascii_bytes_to_string(buf, len)
}

pub fn err_peek_code() -> UInt { err_peek_error_code_ffi() }
pub fn err_clear() -> Unit { err_clear_error_ffi() }

///
pub fn err_get_and_clear() -> String {
  let s = err_get_error()
  err_clear()
  s
}

fn ascii_bytes_to_string(buf : FixedArray[Byte], len : Int) -> String {
  let mut s = ""
  for i in 0..<len { s = s + buf.unsafe_get(i).to_char().to_string() }
  s
}
