///|
/// Auth 认证协议单元测试（RFC 4252）。
test "build_service_request userauth" {
  let req = build_service_request("ssh-userauth")
  assert_eq(req.unsafe_get(0).to_int(), 5) // SSH_MSG_SERVICE_REQUEST
  let r = Reader::new(req)
  let msg = r.read_byte()
  assert_eq(msg.to_int(), 5)
  let svc = r.read_string_as_str()
  assert_eq(svc, "ssh-userauth")
}

///|
test "build_userauth_request none method" {
  let req = build_userauth_request("alice", "ssh-connection", method_none())
  assert_eq(req.unsafe_get(0).to_int(), 50) // SSH_MSG_USERAUTH_REQUEST
  let r = Reader::new(req)
  assert_eq(r.read_byte().to_int(), 50)
  assert_eq(r.read_string_as_str(), "alice")
  assert_eq(r.read_string_as_str(), "ssh-connection")
  assert_eq(r.read_string_as_str(), "none")
}

///|
test "build_userauth_request password method" {
  let req = build_userauth_request(
    "bob",
    "ssh-connection",
    method_password(),
    password="secret",
  )
  let r = Reader::new(req)
  assert_eq(r.read_byte().to_int(), 50)
  assert_eq(r.read_string_as_str(), "bob")
  assert_eq(r.read_string_as_str(), "ssh-connection")
  assert_eq(r.read_string_as_str(), "password")
  assert_eq(r.read_byte().to_int(), 0) // FALSE = no password change
  assert_eq(r.read_string_as_str(), "secret")
}

///|
test "parse_auth_reply success" {
  let reply = b"\x32" // SSH_MSG_USERAUTH_SUCCESS = 52
  let parsed = parse_auth_reply(reply)
  match parsed {
    Success => ()
    _ => fail("expected Success")
  }
}

///|
test "parse_auth_reply failure" {
  let w = Writer::new()
  w.write_byte(0x33) // SSH_MSG_USERAUTH_FAILURE = 51
  w.write_name_list(["password", "publickey"])
  w.write_byte(1) // partial success
  let reply = w.to_bytes()
  let parsed = parse_auth_reply(reply)
  match parsed {
    Failure(methods, partial) => {
      assert_eq(methods.length(), 2)
      assert_true(partial)
    }
    _ => fail("expected Failure")
  }
}

///|
test "parse_auth_reply service_accept" {
  let w = Writer::new()
  w.write_byte(6) // SSH_MSG_SERVICE_ACCEPT
  w.write_string_from_str("ssh-userauth")
  let reply = w.to_bytes()
  let parsed = parse_auth_reply(reply)
  match parsed {
    ServiceAccept => ()
    _ => fail("expected ServiceAccept")
  }
}

///|
test "AuthContext initial state is Idle" {
  let ctx = AuthContext::new("testuser")
  assert_false(ctx.is_authenticated())
}

///|
test "AuthContext::build_initial sends none" {
  let ctx = AuthContext::new("alice")
  let req = ctx.build_initial()
  let r = Reader::new(req)
  assert_eq(r.read_byte().to_int(), 50)
  assert_eq(r.read_string_as_str(), "alice")
  assert_eq(r.read_string_as_str(), "ssh-connection")
  assert_eq(r.read_string_as_str(), "none")
}

///|
test "AuthContext::build_password generates valid request" {
  let ctx = AuthContext::new("bob")
  let req = ctx.build_password("mypass")
  // Verify the request starts with SSH_MSG_USERAUTH_REQUEST (50)
  assert_eq(req.unsafe_get(0).to_int(), 50)
  // Verify total length is reasonable (> 0)
  assert_true(req.length() > 10)
}

///|
test "method constants" {
  assert_eq(method_none(), "none")
  assert_eq(method_password(), "password")
  assert_eq(method_publickey(), "publickey")
  assert_eq(SERVICE_USERAUTH, "ssh-userauth")
}
