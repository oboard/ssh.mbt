// Whitebox tests for src/kex.mbt.
// Run `moon test --target native` to execute.

// ============== Algorithm lists ==============

///|
test "kex_algorithms/contents" {
  // 客户端支持的 KEX 算法应当包含至少一个常用算法
  let algs = kex_algorithms()
  inspect(algs.length() > 0, content="true")
  // 应包含 ecdh-sha2-nistp256 与 dh-group14-sha256
  let mut has_ecdh = false
  let mut has_dh_sha256 = false
  for a in algs {
    if a == "ecdh-sha2-nistp256" {
      has_ecdh = true
    }
    if a == "diffie-hellman-group14-sha256" {
      has_dh_sha256 = true
    }
  }
  inspect(has_ecdh, content="true")
  inspect(has_dh_sha256, content="true")
}

///|
test "server_host_key_algorithms/contents" {
  // host key 算法列表至少包含 ssh-rsa / rsa-sha2-256
  let algs = server_host_key_algorithms()
  inspect(algs.length() >= 2, content="true")
  let mut has_rsa = false
  let mut has_rsa_sha2 = false
  for a in algs {
    if a == "ssh-rsa" {
      has_rsa = true
    }
    if a == "rsa-sha2-256" {
      has_rsa_sha2 = true
    }
  }
  inspect(has_rsa, content="true")
  inspect(has_rsa_sha2, content="true")
}

///|
test "encryption_algorithms/aes128_ctr" {
  // 当前仅支持 aes128-ctr
  let algs = encryption_algorithms()
  inspect(algs.length(), content="1")
  inspect(algs[0], content="aes128-ctr")
}

///|
test "mac_algorithms/contents" {
  // MAC 算法至少包含 hmac-sha2-256
  let algs = mac_algorithms()
  let mut has_sha256 = false
  for a in algs {
    if a == "hmac-sha2-256" {
      has_sha256 = true
    }
  }
  inspect(has_sha256, content="true")
}

///|
test "compression_algorithms/none_only" {
  // 当前仅支持 none
  let algs = compression_algorithms()
  inspect(algs.length(), content="1")
  inspect(algs[0], content="none")
}

// ============== Message-type constants ==============

///|
test "msg_constants/values" {
  // 消息号应当与 SSH 二进制协议一致
  inspect(SSH_MSG_KEXINIT.to_int(), content="20")
  inspect(SSH_MSG_NEWKEYS.to_int(), content="21")
  inspect(SSH_MSG_KEX_ECDH_INIT.to_int(), content="30")
  inspect(SSH_MSG_KEX_ECDH_REPLY.to_int(), content="31")
  inspect(SSH_MSG_KEX_DH_INIT.to_int(), content="30")
  inspect(SSH_MSG_KEX_DH_REPLY.to_int(), content="31")
  inspect(SSH_MSG_DISCONNECT.to_int(), content="1")
  inspect(SSH_MSG_IGNORE.to_int(), content="2")
  inspect(SSH_MSG_DEBUG.to_int(), content="4")
  inspect(SSH_MSG_EXT_INFO.to_int(), content="7")
}

// ============== build_kexinit_payload + parse_kexinit ==============

///|
test "kexinit/roundtrip" {
  // 构造的 KEXINIT 应当能被自身解析
  let cookie = Bytes::from_array([
    b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06', b'\x07', b'\x08', b'\x09',
    b'\x0a', b'\x0b', b'\x0c', b'\x0d', b'\x0e', b'\x0f', b'\x10',
  ])
  let payload = build_kexinit_payload(cookie)
  // 消息号
  inspect(payload[0].to_int(), content="20")
  // 应当被解析回原 cookie
  let parsed = parse_kexinit(payload) catch { _ => abort("unreachable") }
  inspect(parsed.cookie.length(), content="16")
  inspect(parsed.cookie[0].to_int(), content="1")
  inspect(parsed.cookie[15].to_int(), content="16")
  // 协商字段应非空（来自本端默认列表）
  inspect(parsed.kex_algs.length() > 0, content="true")
  inspect(parsed.host_key_algs.length() > 0, content="true")
  inspect(parsed.enc_c2s.length() > 0, content="true")
  inspect(parsed.mac_c2s.length() > 0, content="true")
}

///|
test "kexinit/wrong_msg_type_raises" {
  // 不是 KEXINIT 消息号应当抛 ProtocolError
  let bad = Bytes::from_array([b'\x99']) + Bytes::make(16, b'\x00')
  try {
    let _ = parse_kexinit(bad)
    fail("expected ProtocolError")
  } catch {
    ProtocolError(_) => ()
    _ => fail("expected ProtocolError, got other")
  }
}

// ============== KexInit negotiation helpers ==============

///|
test "kexinit/first_returns_match" {
  // first() 应当返回本端列表与服务端列表的交集第一项
  let ki : KexInit = {
    cookie: b"",
    kex_algs: ["foo", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"],
    host_key_algs: ["bar", "rsa-sha2-256"],
    enc_c2s: ["baz", "aes128-ctr"],
    enc_s2c: ["qux", "aes128-ctr"],
    mac_c2s: ["hmac-sha1"],
    mac_s2c: ["hmac-sha2-256", "hmac-sha1"],
    comp_c2s: ["none"],
    comp_s2c: ["none"],
  }
  inspect(ki.first(), content="Some(ecdh-sha2-nistp256)")
  inspect(ki.first_host_key(), content="Some(rsa-sha2-256)")
  inspect(ki.first_enc(), content="Some(aes128-ctr)")
  // 顺序：服务端优先列出 hmac-sha2-256，本端也包含，应当返回该算法
  inspect(ki.first_mac(), content="Some(hmac-sha2-256)")
  inspect(ki.first_comp(), content="Some(none)")
}

///|
test "kexinit/first_no_match_is_none" {
  // 没有交集时应当返回 None
  let ki : KexInit = {
    cookie: b"",
    kex_algs: ["unknown-alg-1", "unknown-alg-2"],
    host_key_algs: ["x"],
    enc_c2s: ["y"],
    enc_s2c: ["z"],
    mac_c2s: ["a"],
    mac_s2c: ["b"],
    comp_c2s: ["c"],
    comp_s2c: ["d"],
  }
  inspect(ki.first(), content="None")
  inspect(ki.first_host_key(), content="None")
  inspect(ki.first_enc(), content="None")
  inspect(ki.first_mac(), content="None")
  inspect(ki.first_comp(), content="None")
}

// ============== ECDH payloads ==============

///|
test "ecdh_init_payload/frame" {
  // 30 + string(client_public)
  let cpub = Bytes::from_array([b'\x04', b'\x01', b'\x02', b'\x03'])
  let payload = build_ecdh_init_payload(cpub)
  let r = Reader::new(payload)
  inspect(r.read_byte().to_int(), content="30") // SSH_MSG_KEX_ECDH_INIT
  let cpub_back = r.read_string()
  inspect(cpub_back.length(), content="4")
  inspect(cpub_back[0].to_int(), content="4")
  inspect(r.remaining(), content="0")
}

///|
test "ecdh_reply/roundtrip" {
  // 31 + host_key + server_public + signature
  let host_key = Bytes::from_array([b'\x01', b'\x02'])
  let server_pub = Bytes::from_array([b'\x03', b'\x04', b'\x05'])
  let sig = Bytes::from_array([b'\x06', b'\x07'])
  let w = Writer::new()
  w.write_byte(0x1f) // SSH_MSG_KEX_ECDH_REPLY
  w.write_string(host_key)
  w.write_string(server_pub)
  w.write_string(sig)
  let reply = parse_ecdh_reply_payload(w.to_bytes()) catch {
    _ => abort("unreachable")
  }
  inspect(reply.host_key.length(), content="2")
  inspect(reply.server_public.length(), content="3")
  inspect(reply.signature.length(), content="2")
  inspect(reply.host_key[0].to_int(), content="1")
  inspect(reply.server_public[2].to_int(), content="5")
}

///|
test "ecdh_reply/wrong_msg_raises" {
  let bad = Bytes::from_array([b'\x99']) +
    encode_string(b"") +
    encode_string(b"") +
    encode_string(b"")
  try {
    let _ = parse_ecdh_reply_payload(bad)
    fail("expected ProtocolError")
  } catch {
    ProtocolError(_) => ()
    _ => fail("expected ProtocolError, got other")
  }
}

// ============== DH payloads ==============

// ///|
// test "dh_init_payload/frame" {
//   // 30 + mpint(e)
//   let e = @bigint.BigInt::from_int(0xdeadbeef)
//   let payload = build_dh_init_payload(e)
//   let r = Reader::new(payload)
//   inspect(r.read_byte().to_int(), content="30")
//   // 后面是 mpint，长度取决于其大端字节数
//   let m = r.read_mpint()
//   inspect(m.to_int(), content="-559038737")
// }

///|
test "dh_reply/roundtrip" {
  // 31 + host_key + mpint(f) + signature
  let w = Writer::new()
  w.write_byte(0x1f) // SSH_MSG_KEX_DH_REPLY
  w.write_string(Bytes::from_array([b'\xab']))
  w.write_mpint(@bigint.BigInt::from_int(0x1234))
  w.write_string(Bytes::from_array([b'\xcd', b'\xef']))
  let reply = parse_dh_reply_payload(w.to_bytes()) catch {
    _ => abort("unreachable")
  }
  inspect(reply.host_key.length(), content="1")
  inspect(reply.f.to_int(), content="4660") // 0x1234
  inspect(reply.signature.length(), content="2")
}

///|
test "dh_reply/wrong_msg_raises" {
  let bad = Bytes::from_array([b'\x99']) +
    encode_string(b"") +
    encode_string(b"") +
    encode_string(b"")
  try {
    let _ = parse_dh_reply_payload(bad)
    fail("expected ProtocolError")
  } catch {
    ProtocolError(_) => ()
    _ => fail("expected ProtocolError, got other")
  }
}

// ============== Signature blob ==============

///|
test "signature_blob/roundtrip" {
  // signature blob = alg string || sig bytes
  let w = Writer::new()
  w.write_string_from_str("ssh-rsa")
  w.write_string(Bytes::from_array([b'\xaa', b'\xbb']))
  let sb = parse_signature_blob(w.to_bytes()) catch {
    _ => abort("unreachable")
  }
  inspect(sb.alg, content="ssh-rsa")
  inspect(sb.sig.length(), content="2")
  inspect(sb.sig[0].to_int(), content="170")
}

///|
test "parse_host_key_algorithm/extracts_first_string" {
  // 公钥 blob 的第一项是算法名
  let w = Writer::new()
  w.write_string_from_str("ssh-ed25519")
  w.write_string(Bytes::from_array([b'\x01', b'\x02']))
  let alg = parse_host_key_algorithm(w.to_bytes()) catch {
    _ => abort("unreachable")
  }
  inspect(alg, content="ssh-ed25519")
}

// ============== NEWKEYS ==============

///|
test "newkeys/frame_and_detection" {
  // NEWKEYS 是单字节 0x15
  let payload = build_newkeys_payload()
  inspect(payload.length(), content="1")
  inspect(payload[0].to_int(), content="21")
  inspect(is_newkeys_payload(payload), content="true")
}

///|
test "newkeys/is_newkeys_payload_rejects_others" {
  // 非 NEWKEYS 应当返回 false
  inspect(is_newkeys_payload(b""), content="false")
  inspect(
    is_newkeys_payload(Bytes::from_array([b'\x15', b'\x15'])),
    content="false",
  )
  inspect(is_newkeys_payload(Bytes::from_array([b'\x14'])), content="false")
}

// ============== KexContext ==============

///|
test "kex_context/new_initial_state" {
  // 新建 KexContext 状态为 Initial，各算法字段为空
  let ctx = KexContext::new(b"client", b"server")
  match ctx.state {
    Initial => ()
    _ => fail("expected Initial")
  }
  inspect(ctx.kex_alg, content="")
  inspect(ctx.host_key_alg, content="")
  inspect(ctx.enc_alg, content="")
  inspect(ctx.mac_alg, content="")
  inspect(ctx.session_id_set, content="false")
  // 应当已经构造好本端 KEXINIT（i_c 非空、消息号 = 20）
  inspect(ctx.i_c[0].to_int(), content="20")
}

// ============== KexState ==============

///|
test "kex_state/eq_and_debug" {
  // 状态枚举应支持 == 与 Debug
  let s1 : KexState = Initial
  let s2 : KexState = SentKexinit
  let s3 : KexState = Initial
  inspect(s1 == s3, content="true")
  inspect(s1 == s2, content="false")
}
