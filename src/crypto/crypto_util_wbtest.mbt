// Whitebox tests for crypto_util.mbt (rand_bytes, error handling).
// Run `moon test --target native` to execute.

// ============== rand_bytes ==============

///|
test "rand_bytes/returns_correct_length" {
  let buf = rand_bytes(32) catch { _ => abort("rand_bytes failed") }
  inspect(buf.length(), content="32")
}

///|
test "rand_bytes/zero_length" {
  let buf = rand_bytes(0) catch { _ => abort("rand_bytes failed") }
  inspect(buf.length(), content="0")
}

///|
test "rand_bytes/two_calls_differ" {
  // Two random buffers of 16 bytes should (almost certainly) differ
  let a = rand_bytes(16) catch { _ => abort("rand_bytes failed") }
  let b = rand_bytes(16) catch { _ => abort("rand_bytes failed") }
  // Extremely unlikely to be equal; verify at least one byte differs
  let mut differs = false
  for i in 0..<16 {
    if a[i] != b[i] {
      differs = true
      break
    }
  }
  inspect(differs, content="true")
}

// ============== Error handling helpers ==============

///|
test "err_clear/no_error" {
  // After clearing, err_get_error should return empty
  err_clear()
  let msg = err_get_error()
  inspect(msg == "", content="true")
}

///|
test "err_get_and_clear/returns_string" {
  // Should return a string (possibly empty when no error pending)
  let s = err_get_and_clear()
  // Just verify it's a String type, not crash
  ignore(s)
}

// ///|
// test "err_peek_code/no_error_returns_zero" {
//   // With no pending error, peek code should return 0
//   err_clear()
//   let code = err_peek_code()
//   inspect(code == 0.to_uint(), content="true")
// }
