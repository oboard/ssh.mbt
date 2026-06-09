// Copyright 2025 International Digital Economy Academy
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// ---------------------------------------------------------------------------
// Derived from moonbitlang/async/src/tls/crypto_util.mbt (Apache 2.0).
// Modifications:
//   - removed `#internal` annotations (this module is the public crypto API
//     of the SSH library, not internal to a wrapping package)
//   - removed the Windows code path (ssh/crypto does not yet target Windows)
//   - retained RAND_bytes
// ---------------------------------------------------------------------------

///|
#borrow(buf)
extern "C" fn rand_bytes_ffi(buf : FixedArray[Byte], num : Int) -> Int = "moonbitlang_ssh_rand_bytes"

///|
/// Generate cryptographically secure random bytes using OpenSSL's `RAND_bytes`.
/// Returns the requested number of bytes on success, raises `CryptoError` on
/// failure.
pub fn rand_bytes(num : Int) -> Bytes raise CryptoError {
  ensure_openssl()
  let result = FixedArray::make(num, b'\x00')
  let rc = rand_bytes_ffi(result, num)
  if rc != 1 {
    err_clear()
    raise CryptoError::RandomFailed("RAND_bytes returned \{rc}")
  }
  Bytes::from_fixedarray(result)
}

///|
/// Fills the provided buffer with random bytes in place.
pub fn rand_bytes_into(buf : Bytes) -> Unit raise CryptoError {
  ensure_openssl()
  let arr = buf.to_fixedarray()
  let rc = rand_bytes_ffi(arr, arr.length())
  if rc != 1 {
    err_clear()
    raise CryptoError::RandomFailed("RAND_bytes returned \{rc}")
  }
}

///|
#borrow(buf)
extern "C" fn err_get_error_string_ffi(buf : FixedArray[Byte]) -> Int = "moonbitlang_ssh_get_error_string"

///|
extern "C" fn err_clear_error_ffi() = "moonbitlang_ssh_clear_error"

///|
extern "C" fn err_peek_error_code_ffi() -> UInt = "moonbitlang_ssh_peek_error_code"

///|
/// Retrieve and clear the latest OpenSSL error from the thread-local queue.
/// Returns an empty string if no error is pending.
pub fn err_get_error() -> String {
  let buf = FixedArray::make(256, Byte::default())
  let len = err_get_error_string_ffi(buf)
  if len <= 0 {
    return ""
  }
  ascii_bytes_to_string(buf, len)
}

///|
/// Peek the latest OpenSSL error code without removing it from the queue.
pub fn err_peek_code() -> UInt {
  err_peek_error_code_ffi()
}

///|
/// Clear all OpenSSL errors on the current thread.
pub fn err_clear() -> Unit {
  err_clear_error_ffi()
}

///|
/// Retrieve the error string AND clear the OpenSSL error queue.
/// This is the safe alternative to calling `err_clear()` before
/// `err_get_error()` (which would discard the error).
pub fn err_get_and_clear() -> String {
  let s = err_get_error()
  err_clear()
  s
}

///|
/// Convert a fixed array of ASCII bytes (no null terminator) to a MoonBit
/// `String`. The bytes are interpreted as 7-bit ASCII.
fn ascii_bytes_to_string(buf : FixedArray[Byte], len : Int) -> String {
  let mut s = ""
  for i in 0..<len {
    let b = buf.unsafe_get(i)
    s = s + b.to_char().to_string()
  }
  s
}
