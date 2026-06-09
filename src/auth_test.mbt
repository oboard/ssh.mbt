///| Auth 认证协议单元测试（RFC 4252）。

test "build_service_request userauth" {
  let req = build_service_request("ssh-userauth")
  assert_eq(req.unsafe_get(0).to_int(), 5) // SSH_MSG_SERVICE_REQUEST
  let r = Reader::new(req)
  let msg = r.read_byte()
  assert_eq(msg.to_int(), 5)
  let svc = r.read_string_as_str()
  assert_eq(svc, "ssh-userauth")
}

test "build_userauth_request none method" {
  let req = build_userauth_request("alice", "ssh-connection", method_none())
  assert_eq(req.unsafe_get(0).to_int(), 50) // SSH_MSG_USERAUTH_REQUEST
  let r = Reader::new(req)
  assert_eq(r.read_byte().to_int(), 50)
  assert_eq(r.read_string_as_str(), "alice")
  assert_eq(r.read_string_as_str(), "ssh-connection")
  assert_eq(r.read_string_as_str(), "none")
}

test "build_userauth_request password method" {
  let req = build_userauth_request(
    "bob",
    "ssh-connection",
    method_password(),
    password~="secret",
  )
  let r = Reader::new(req)
  assert_eq(r.read_byte().to_int(), 50)
  assert_eq(r.read_string_as_str(), "bob")
  assert_eq(r.read_string_as_str(), "ssh-connection")
  assert_eq(r.read_string_as_str(), "password")
  assert_eq(r.read_byte().to_int(), 0) // FALSE = no password change
  assert_eq(r.read_string_as_str(), "secret")
}

test "parse_auth_reply success" {
  let reply = b"\x32" // SSH_MSG_USERAUTH_SUCCESS = 52
  let parsed = parse_auth_reply(reply)
  match parsed {
    Success => ()
    _ => fail("expected Success")
  }
}

test "parse_auth_reply failure" {
  // Build a FAILURE message manually
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

test "parse_auth_reply publickey_ok" {
  let w = Writer::new()
  w.write_byte(60) // SSH_MSG_USERAUTH_PK_OK = 60
  w.write_string_from_str("ssh-ed25519")
  w.write_string(Bytes::make(32, b'\xAA'))
  let reply = w.to_bytes()
  let parsed = parse_auth_reply(reply)
  match parsed {
    PublicKeyOk(alg, blob) => {
      assert_eq(alg, "ssh-ed25519")
      assert_eq(blob.length(), 32)
    }
    _ => fail("expected PublicKeyOk")
  }
}

test "AuthContext initial state is Idle" {
  let ctx = AuthContext::new("testuser")
  assert_false(ctx.is_authenticated())
}

test "AuthContext::build_initial sends none" {
  let ctx = AuthContext::new("alice")
  let req = ctx.build_initial()
  let r = Reader::new(req)
  assert_eq(r.read_byte().to_int(), 50)
  assert_eq(r.read_string_as_str(), "alice")
  assert_eq(r.read_string_as_str(), "ssh-connection")
  assert_eq(r.read_string_as_str(), "none")
}

test "AuthContext::build_password generates valid request" {
  let ctx = AuthContext::new("bob")
  let req = ctx.build_password("mypass")
  let r = Reader::new(req)
  assert_eq(r.read_string_as_str(), "bob")
  assert_eq(r.read_string_as_str(), "password")
  assert_eq(r.read_string_as_str(), "mypass")
}

test "AuthContext apply_reply transitions to Authenticated on Success" {
  let ctx = AuthContext::new("alice")
  ctx.apply_reply(Success)
  assert_true(ctx.is_authenticated())
}

test "AuthContext apply_reply transitions to Rejected on Failure" {
  let ctx = AuthContext::new("alice")
  ctx.apply_reply(Failure(["password"], false))
  assert_false(ctx.is_authenticated())
  match ctx.state {
    Rejected(methods) => assert_eq(methods[0], "password")
    _ => fail("expected Rejected state")
  }
}

test "build_publickkey_signature_input structure" {
  let sid = b"\x00\x01\x02\x03"
  let sig_input = build_publickkey_signature_input(
    sid,
    "user",
    "ssh-connection",
    "ssh-ed25519",
    b"pubkey-blob",
  )
  let r = Reader::new(sig_input)
  assert_eq(r.read_string(), sid)
  assert_eq(r.read_byte().to_int(), 50) // USERAUTH_REQUEST
  assert_eq(r.read_string_as_str(), "user")
  assert_eq(r.read_string_as_str(), "ssh-connection")
  assert_eq(r.read_string_as_str(), "publickey")
  assert_eq(r.read_byte().to_int(), 1) // TRUE
  assert_eq(r.read_string_as_str(), "ssh-ed25519")
  assert_eq(r.read_string(), b"pubkey-blob")
}

test "method constants" {
  assert_eq(method_none(), "none")
  assert_eq(method_password(), "password")
  assert_eq(method_publickey(), "publickey")
  assert_eq(SERVICE_USERAUTH, "ssh-userauth")
}

test "build_publickey_query no signature" {
  let ctx = AuthContext::new("user")
  let alg = "ssh-ed25519"
  let blob = b"pubkey-data"
  let req = ctx.build_publickey_query(alg, blob)
  let r = Reader::new(req)
  assert_eq(r.read_string_as_str(), "publickey")
  assert_eq(r.read_byte().to_int(), 0) // FALSE = query, no signature
  assert_eq(r.read_string_as_str(), alg)
  assert_eq(r.read_string(), blob)
}
