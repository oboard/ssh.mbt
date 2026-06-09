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
// Derived from moonbitlang/async/src/tls/openssl_loader.mbt (Apache 2.0).
// Modifications: removed BIO/SSL initialization; the SSH transport reads
// from @async/socket directly so no BIO method is required.
// ---------------------------------------------------------------------------

// --- Non-Windows path: dynamic dlopen of libcrypto --------------------

///|
#cfg(not(platform="windows"))
#borrow(major, minor, fix)
extern "C" fn load_openssl_ffi(
  major : Ref[Int],
  minor : Ref[Int],
  fix : Ref[Int],
) -> Int = "moonbitlang_ssh_load_openssl"

///|
#cfg(not(platform="windows"))
let openssl_loaded : Ref[Bool] = Ref(false)

///|
#cfg(not(platform="windows"))
fn load_openssl() -> Unit {
  if openssl_loaded.val {
    return
  }
  openssl_loaded.val = true
  let major = Ref(0)
  let minor = Ref(0)
  let fix = Ref(0)
  match load_openssl_ffi(major, minor, fix) {
    0 => ()
    1 => abort("failed to load OpenSSL (libcrypto)")
    2 => abort("failed to get OpenSSL version")
    3 =>
      abort("unsupported OpenSSL version \{major.val}.\{minor.val}.\{fix.val}")
    4 => abort("failed to load some OpenSSL function")
    _ => panic()
  }
}

// --- Windows path: also use dynamic loading --------------------

///|
#cfg(platform="windows")
#borrow(major, minor, fix)
extern "C" fn load_openssl_ffi(
  major : Ref[Int],
  minor : Ref[Int],
  fix : Ref[Int],
) -> Int = "moonbitlang_ssh_load_openssl"

///|
#cfg(platform="windows")
let openssl_loaded : Ref[Bool] = Ref(false)

///|
#cfg(platform="windows")
fn load_openssl() -> Unit {
  if openssl_loaded.val {
    return
  }
  openssl_loaded.val = true
  let major = Ref(0)
  let minor = Ref(0)
  let fix = Ref(0)
  match load_openssl_ffi(major, minor, fix) {
    0 => ()
    1 => abort("failed to load OpenSSL (libcrypto-3-x64.dll or libcrypto.dll)")
    2 => abort("failed to get OpenSSL version")
    3 =>
      abort("unsupported OpenSSL version \{major.val}.\{minor.val}.\{fix.val}")
    4 => abort("failed to load some OpenSSL function")
    _ => panic()
  }
}

///|
/// Trigger OpenSSL symbol loading. Must be called before any other function
/// in this module that touches OpenSSL through FFI.
///
/// On Windows this aborts (see `load_openssl`).
pub fn ensure_openssl() -> Unit {
  load_openssl()
}
