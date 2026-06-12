///|
/// 动态加载 OpenSSL libcrypto。
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
    1 => abort("failed to load OpenSSL (libcrypto-3-x64.dll)")
    2 => abort("failed to get OpenSSL version")
    3 =>
      abort("unsupported OpenSSL version \{major.val}.\{minor.val}.\{fix.val}")
    4 => abort("failed to load some OpenSSL function")
    _ => panic()
  }
}

///|
pub fn ensure_openssl() -> Unit {
  load_openssl()
}
