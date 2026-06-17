// Whitebox tests for src/auth.mbt.
// Run `moon test --target native` to execute.

///|
test "service_name/userauth" {
  // RFC 4252 规定的 userauth 服务名
  inspect(SERVICE_USERAUTH, content="ssh-userauth")
}

///|
test "method_names/wire_strings" {
  // 认证方法名应与 RFC 4252 / 4256 中规定的字面量完全一致
  inspect(method_none(), content="none")
  inspect(method_password(), content="password")
  inspect(method_publickey(), content="publickey")
  inspect(method_keyboard_interactive(), content="keyboard-interactive")
}

///|
/// 解析已构建的 userauth 请求：消息号 + user + service + method + 剩余字节。
/// 内部用 Reader 解码，与 parse_auth_reply 共用同一编解码器，
/// 因此既可作为 "请求格式正确" 的回归测试，也可作为编解码器自身的环回测试。
fn parse_userauth_request(
  buf : Bytes,
) -> (String, String, String, Bytes) raise SshError {
  let r = Reader::new(buf)
  let _msg_type = r.read_byte()
  let user = r.read_string_as_str()
  let service = r.read_string_as_str()
  let m = r.read_string_as_str()
  (user, service, m, r.rest())
}

// ============== build_service_request ==============

///|
test "build_service_request/frame" {
  // SSH_MSG_SERVICE_REQUEST = 5；随后是 SSH "string"（4 字节长度 + UTF-8 名称）
  let buf = build_service_request(SERVICE_USERAUTH)
  let r = Reader::new(buf)
  let msg_type = r.read_byte()
  inspect(msg_type.to_int(), content="5")
  let svc = r.read_string_as_str()
  inspect(svc, content="ssh-userauth")
  // 消息体正好用完
  inspect(r.remaining(), content="0")
}

// ============== build_userauth_request ==============

///|
test "build_userauth_request/none" {
  // "none" 方法不应追加任何额外字段
  let buf = build_userauth_request("alice", "ssh-connection", "none")
  let (user, svc, m, rest) = parse_userauth_request(buf) catch {
    _ => ("", "", "", b"")
  }
  inspect(user, content="alice")
  inspect(svc, content="ssh-connection")
  inspect(m, content="none")
  inspect(rest.length(), content="0")
}

///|
test "build_userauth_request/password" {
  // password 字段顺序：FALSE (0x00) + password string
  let buf = build_userauth_request(
    "bob",
    "ssh-connection",
    "password",
    password="s3cret",
  )
  let (user, svc, m, rest) = parse_userauth_request(buf) catch {
    _ => ("", "", "", b"")
  }
  inspect(user, content="bob")
  inspect(svc, content="ssh-connection")
  inspect(m, content="password")
  // 剩余字段应为 [FALSE, len(password), 's','3','c','r','e','t']
  let r = Reader::new(rest)
  let false_byte = r.read_byte()
  inspect(false_byte.to_int(), content="0")
  let pw = r.read_string_as_str()
  inspect(pw, content="s3cret")
  inspect(r.remaining(), content="0")
}

///|
test "build_userauth_request/password_missing" {
  // 缺省 password 应编码为空字符串
  let buf = build_userauth_request("bob", "ssh-connection", "password")
  let (_, _, m, rest) = parse_userauth_request(buf) catch {
    _ => ("", "", "", b"")
  }
  inspect(m, content="password")
  let r = Reader::new(rest)
  ignore(r.read_byte()) // FALSE
  let pw = r.read_string_as_str()
  inspect(pw, content="")
  inspect(r.remaining(), content="0")
}

///|
test "build_userauth_request/publickey_query" {
  // 第一阶段：无签名 → FALSE + alg + 公钥 blob
  let blob = Bytes::from_array([b'\x01', b'\x02', b'\x03'])
  let buf = build_userauth_request(
    "carol",
    "ssh-connection",
    "publickey",
    has_signature=false,
    pubkey_alg="ssh-ed25519",
    pubkey_blob=blob,
  )
  let (user, svc, m, rest) = parse_userauth_request(buf) catch {
    _ => ("", "", "", b"")
  }
  inspect(user, content="carol")
  inspect(svc, content="ssh-connection")
  inspect(m, content="publickey")
  let r = Reader::new(rest)
  let has_sig = r.read_byte()
  inspect(has_sig.to_int(), content="0")
  let alg = r.read_string_as_str()
  let out_blob = r.read_string()
  inspect(alg, content="ssh-ed25519")
  inspect(out_blob.length(), content="3")
  // 无签名 → query 后没有签名 string
  inspect(r.remaining(), content="0")
}

///|
test "build_userauth_request/publickey_sign" {
  // 第二阶段：带签名 → TRUE + alg + 公钥 blob + 签名
  let blob = Bytes::from_array([b'\x07', b'\x08'])
  let sig = Bytes::from_array([b'\xaa', b'\xbb', b'\xcc', b'\xdd'])
  let buf = build_userauth_request(
    "carol",
    "ssh-connection",
    "publickey",
    has_signature=true,
    pubkey_alg="ssh-ed25519",
    pubkey_blob=blob,
    signature=sig,
  )
  let (user, svc, m, rest) = parse_userauth_request(buf) catch {
    _ => ("", "", "", b"")
  }
  inspect(user, content="carol")
  inspect(svc, content="ssh-connection")
  inspect(m, content="publickey")
  let r = Reader::new(rest)
  let has_sig = r.read_byte()
  inspect(has_sig.to_int(), content="1")
  let alg = r.read_string_as_str()
  let out_blob = r.read_string()
  let out_sig = r.read_string()
  inspect(alg, content="ssh-ed25519")
  inspect(out_blob.length(), content="2")
  inspect(out_sig.length(), content="4")
  inspect(r.remaining(), content="0")
}

// ============== parse_auth_reply ==============

///|
test "parse_auth_reply/success" {
  // SSH_MSG_USERAUTH_SUCCESS = 52
  let payload = Bytes::from_array([b'\x34'])
  let reply = parse_auth_reply(payload)
  match reply {
    Success => ()
    _ => fail("expected Success")
  }
}

///|
test "parse_auth_reply/failure_with_methods" {
  // SSH_MSG_USERAUTH_FAILURE = 51:
  //   name-list  "publickey,password"
  //   boolean    FALSE
  let w = Writer::new()
  w.write_byte(0x33)
  w.write_name_list(["publickey", "password"])
  w.write_byte(0)
  let reply = parse_auth_reply(w.to_bytes())
  match reply {
    Failure(methods, partial) => {
      inspect(methods.length(), content="2")
      inspect(methods[0], content="publickey")
      inspect(methods[1], content="password")
      inspect(partial, content="false")
    }
    _ => fail("expected Failure")
  }
}

///|
test "parse_auth_reply/failure_partial" {
  // partial-success = TRUE（RFC 4252 §5.1）
  let w = Writer::new()
  w.write_byte(0x33)
  w.write_name_list(["password"])
  w.write_byte(1)
  let reply = parse_auth_reply(w.to_bytes())
  match reply {
    Failure(methods, partial) => {
      inspect(methods.length(), content="1")
      inspect(methods[0], content="password")
      inspect(partial, content="true")
    }
    _ => fail("expected Failure")
  }
}

///|
test "parse_auth_reply/pk_ok" {
  // SSH_MSG_USERAUTH_PK_OK = 60
  let w = Writer::new()
  w.write_byte(0x3c)
  w.write_string_from_str("ssh-rsa")
  w.write_string(Bytes::from_array([b'\xde', b'\xad', b'\xbe', b'\xef']))
  let reply = parse_auth_reply(w.to_bytes())
  match reply {
    PublicKeyOk(alg, blob) => {
      inspect(alg, content="ssh-rsa")
      inspect(blob.length(), content="4")
    }
    _ => fail("expected PublicKeyOk")
  }
}

///|
test "parse_auth_reply/service_accept" {
  // SSH_MSG_SERVICE_ACCEPT = 6
  let reply = parse_auth_reply(Bytes::from_array([b'\x06']))
  match reply {
    ServiceAccept => ()
    _ => fail("expected ServiceAccept")
  }
}

///|
test "parse_auth_reply/unknown_raises" {
  // 未知消息号应当抛出 ProtocolError
  try {
    let _ = parse_auth_reply(Bytes::from_array([b'\x99']))
    fail("expected ProtocolError")
  } catch {
    ProtocolError(_) => ()
    _ => fail("expected ProtocolError, got other error")
  }
}

// ============== build_publickey_signature_input ==============

///|
test "build_publickey_signature_input/frame" {
  // RFC 4252 §7 串接顺序：session_id || 50 || user || service ||
  //   "publickey" || TRUE || alg || blob
  let session = Bytes::from_array([b'\x01', b'\x02'])
  let blob = Bytes::from_array([b'\xab', b'\xcd', b'\xef'])
  let buf = build_publickey_signature_input(
    session, "alice", "ssh-connection", "ssh-ed25519", blob,
  )
  let r = Reader::new(buf)
  let out_session = r.read_string()
  inspect(out_session.length(), content="2")
  let msg_type = r.read_byte()
  inspect(msg_type.to_int(), content="50")
  let user = r.read_string_as_str()
  inspect(user, content="alice")
  let svc = r.read_string_as_str()
  inspect(svc, content="ssh-connection")
  let m = r.read_string_as_str()
  inspect(m, content="publickey")
  let has_sig = r.read_byte()
  inspect(has_sig.to_int(), content="1")
  let alg = r.read_string_as_str()
  inspect(alg, content="ssh-ed25519")
  let out_blob = r.read_string()
  inspect(out_blob.length(), content="3")
  // 串接字段正好用完
  inspect(r.remaining(), content="0")
}

// ============== AuthContext::new / state machine ==============

///|
test "auth_context/new_is_idle" {
  let ctx = AuthContext::new("alice")
  inspect(ctx.user, content="alice")
  inspect(ctx.service, content="ssh-userauth")
  // 初始状态是 Idle，未认证
  inspect(ctx.is_authenticated(), content="false")
}

///|
test "auth_context/apply_success" {
  // 收到 Success → 状态变 Authenticated
  let ctx = AuthContext::new("alice")
  ctx.apply_reply(Success)
  inspect(ctx.is_authenticated(), content="true")
}

///|
test "auth_context/apply_failure_records_methods" {
  // 收到 Failure → 状态变 Rejected，方法列表被记录
  let ctx = AuthContext::new("alice")
  ctx.apply_reply(Failure(["publickey", "password"], false))
  inspect(ctx.is_authenticated(), content="false")
  match ctx.state {
    Rejected(methods) => {
      inspect(methods.length(), content="2")
      inspect(methods[0], content="publickey")
      inspect(methods[1], content="password")
    }
    _ => fail("expected Rejected")
  }
}

///|
test "auth_context/apply_pk_ok_moves_to_sign" {
  // 收到 PK_OK → 状态变 AwaitingSignature，等待私钥签名
  let blob = Bytes::from_array([b'\x01', b'\x02', b'\x03'])
  let ctx = AuthContext::new("alice")
  ctx.apply_reply(PublicKeyOk("ssh-ed25519", blob))
  inspect(ctx.is_authenticated(), content="false")
  match ctx.state {
    AwaitingSignature(alg, out_blob) => {
      inspect(alg, content="ssh-ed25519")
      inspect(out_blob.length(), content="3")
    }
    _ => fail("expected AwaitingSignature")
  }
}

///|
test "auth_context/apply_service_accept_keeps_idle" {
  // ServiceAccept 不改变状态机（仍处于 Idle）
  let ctx = AuthContext::new("alice")
  ctx.apply_reply(ServiceAccept)
  match ctx.state {
    Idle => ()
    _ => fail("expected Idle to be preserved")
  }
  inspect(ctx.is_authenticated(), content="false")
}

// ============== AuthContext builders ==============

///|
test "auth_context/build_initial" {
  // build_initial 应当对应 method="none" 的 userauth 请求
  let ctx = AuthContext::new("alice")
  let buf = ctx.build_initial()
  let (user, svc, m, rest) = parse_userauth_request(buf) catch {
    _ => ("", "", "", b"")
  }
  inspect(user, content="alice")
  inspect(svc, content="ssh-connection")
  inspect(m, content="none")
  inspect(rest.length(), content="0")
}

///|
test "auth_context/build_password" {
  // build_password 必须带 FALSE + 密码字符串
  let ctx = AuthContext::new("bob")
  let buf = ctx.build_password("hunter2")
  let (user, svc, m, rest) = parse_userauth_request(buf) catch {
    _ => ("", "", "", b"")
  }
  inspect(user, content="bob")
  inspect(svc, content="ssh-connection")
  inspect(m, content="password")
  let r = Reader::new(rest)
  let false_byte = r.read_byte()
  inspect(false_byte.to_int(), content="0")
  let pw = r.read_string_as_str()
  inspect(pw, content="hunter2")
  inspect(r.remaining(), content="0")
}

///|
test "auth_context/build_publickey_query_sign_differ" {
  // query vs sign：关键是 boolean 字段，query=FALSE, sign=TRUE
  let ctx = AuthContext::new("carol")
  let blob = Bytes::from_array([b'\x01'])
  let sig = Bytes::from_array([b'\x00', b'\x00'])
  let query = ctx.build_publickey_query("ssh-ed25519", blob)
  let sign = ctx.build_publickey_sign("ssh-ed25519", blob, sig)
  // query 的第 6 字节（user/service/method 之后）是 FALSE
  let (_, _, _, q_rest) = parse_userauth_request(query) catch {
    _ => ("", "", "", b"")
  }
  let (_, _, _, s_rest) = parse_userauth_request(sign) catch {
    _ => ("", "", "", b"")
  }
  let q_byte = q_rest.to_fixedarray().unsafe_get(0).to_int()
  let s_byte = s_rest.to_fixedarray().unsafe_get(0).to_int()
  inspect(q_byte, content="0")
  inspect(s_byte, content="1")
  // sign 应比 query 多出 4 字节长度前缀 + 签名长度
  let diff = sign.length() - query.length()
  inspect(diff, content=(4 + sig.length()).to_string())
}

///|
test "auth_context/build_keyboard_interactive_frame" {
  // 初始 kbd-int 请求：50 + user + service + method + "" (lang) + "" (submethods)
  let ctx = AuthContext::new("dave")
  let buf = ctx.build_keyboard_interactive()
  let (user, svc, m, rest) = parse_userauth_request(buf) catch {
    _ => ("", "", "", b"")
  }
  inspect(user, content="dave")
  inspect(svc, content="ssh-connection")
  inspect(m, content="keyboard-interactive")
  let r = Reader::new(rest)
  let lang = r.read_string_as_str()
  let sub = r.read_string_as_str()
  inspect(lang, content="")
  inspect(sub, content="")
  inspect(r.remaining(), content="0")
}

///|
test "auth_context/build_info_response" {
  // SSH_MSG_USERAUTH_INFO_RESPONSE = 61
  //   uint32  N
  //   string  response_1 ...
  let ctx = AuthContext::new("eve")
  let buf = ctx.build_info_response(["answer1", "answer2"])
  let r = Reader::new(buf)
  let msg_type = r.read_byte()
  inspect(msg_type.to_int(), content="61")
  let count = r.read_uint32()
  inspect(count, content="2")
  let r1 = r.read_string_as_str()
  let r2 = r.read_string_as_str()
  inspect(r1, content="answer1")
  inspect(r2, content="answer2")
  inspect(r.remaining(), content="0")
}

///|
test "auth_context/build_info_response_empty" {
  // 没有 prompt 时只有消息号 + 0
  let ctx = AuthContext::new("eve")
  let buf = ctx.build_info_response([])
  let r = Reader::new(buf)
  let msg_type = r.read_byte()
  inspect(msg_type.to_int(), content="61")
  let count = r.read_uint32()
  inspect(count, content="0")
  inspect(r.remaining(), content="0")
}
