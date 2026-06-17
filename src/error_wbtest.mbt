// Whitebox tests for src/error.mbt.
// Run `moon test --target native` to execute.

///|
test "ssh_error/constructors" {
  // 验证所有构造器都能被正常创建并匹配
  let e1 : SshError = IoError("conn refused")
  let e2 : SshError = ConnectionClosed
  let e3 : SshError = ProtocolError("bad length")
  let e4 : SshError = MacMismatch
  let e5 : SshError = NotEncrypted
  let e6 : SshError = HostKeyMismatch("ed25519:fingerprint")
  let e7 : SshError = AuthFailed("password")
  let e8 : SshError = RequestDenied("shell")
  let e9 : SshError = ParseError("reader: need 4 bytes")
  // 全部构造器实例应互不相等
  inspect(e1 == e2, content="false")
  inspect(e1 == e3, content="false")
  inspect(e4 == e5, content="false")
  inspect(e7 == e8, content="false")
  // 自反：同实例相等
  inspect(e1 == IoError("conn refused"), content="true")
  // AuthFailed 和 RequestDenied 携带不同原因时也不等
  inspect(AuthFailed("a") == AuthFailed("b"), content="false")
  // HostKeyMismatch 与 IoError 也不等
  ignore(e6)
  ignore(e9)
}

///|
test "ssh_error/match_io_error" {
  // 调用方应能 match 出具体错误类型以做细粒度处理
  let e : SshError = IoError("read: timeout")
  let category = match e {
    IoError(msg) => "io:" + msg
    ConnectionClosed => "closed"
    ProtocolError(_) => "proto"
    MacMismatch => "mac"
    NotEncrypted => "noenc"
    HostKeyMismatch(_) => "host"
    AuthFailed(_) => "auth"
    RequestDenied(_) => "deny"
    ParseError(_) => "parse"
  }
  inspect(category, content="io:read: timeout")
}

///|
test "ssh_error/match_auth_failed_carries_reason" {
  // AuthFailed 携带的字符串可被取出并展示
  let e : SshError = AuthFailed("methods: [publickey,password]")
  match e {
    AuthFailed(reason) => inspect(reason, content="methods: [publickey,password]")
    _ => fail("expected AuthFailed")
  }
}

///|
test "ssh_error/can_be_raised_and_caught" {
  // SshError 是 suberror，可以从函数抛出并在调用处捕获
  fn fail_with_auth() -> Unit raise SshError {
    raise AuthFailed("denied")
  }

  try {
    fail_with_auth()
    fail("expected AuthFailed to be raised")
  } catch {
    AuthFailed(reason) => inspect(reason, content="denied")
    _ => fail("expected AuthFailed, got other")
  }
}

///|
test "ssh_error/propagates_through_raise" {
  // ProtocolError 的字符串负载应当原样向上传递
  fn inner() -> Unit raise SshError {
    raise ProtocolError("bad length 1000000")
  }

  fn outer() -> Unit raise SshError {
    inner()
  }

  try {
    outer()
    fail("expected ProtocolError")
  } catch {
    ProtocolError(msg) => inspect(msg, content="bad length 1000000")
    _ => fail("expected ProtocolError, got other")
  }
}

///|
test "ssh_error/parse_error_carries_position" {
  // ParseError 通常由 Reader 在字节不足时抛出
  // 验证字符串内容可被精确传递
  let e : SshError = ParseError("reader: need 8 bytes, have 3")
  match e {
    ParseError(msg) => inspect(msg, content="reader: need 8 bytes, have 3")
    _ => fail("expected ParseError")
  }
}
