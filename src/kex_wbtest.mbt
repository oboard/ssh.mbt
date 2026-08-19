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
  @debug.debug_inspect(ki.first(), content="Some(\"ecdh-sha2-nistp256\")")
  @debug.debug_inspect(ki.first_host_key(), content="Some(\"rsa-sha2-256\")")
  @debug.debug_inspect(ki.first_enc(), content="Some(\"aes128-ctr\")")
  // 顺序：服务端优先列出 hmac-sha2-256，本端也包含，应当返回该算法
  @debug.debug_inspect(ki.first_mac(), content="Some(\"hmac-sha2-256\")")
  @debug.debug_inspect(ki.first_comp(), content="Some(\"none\")")
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
  @debug.debug_inspect(ki.first(), content="None")
  @debug.debug_inspect(ki.first_host_key(), content="None")
  @debug.debug_inspect(ki.first_enc(), content="None")
  @debug.debug_inspect(ki.first_mac(), content="None")
  @debug.debug_inspect(ki.first_comp(), content="None")
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

///|
test "dh_init_payload/frame" {
  // 这个 0xdeadbeef 数存在问题，会导致 BEGIN MError: failed to run test for target Native
  // 30 + mpint(e)
  // let e = @bigint.BigInt::from_int(0xdeadbeef)
  // 
  let e = @bigint.BigInt::from_int(1234567890)
  let payload = build_dh_init_payload(e)
  let r = Reader::new(payload)
  inspect(r.read_byte().to_int(), content="30")
  // 后面是 mpint，长度取决于其大端字节数
  let m = r.read_mpint()
  inspect(m.to_int(), content="1234567890")
}

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

// ============== hash_alg_for_kex ==============

///|
test "kex/hash_alg_for_kex_sha1" {
  let alg = hash_alg_for_kex("diffie-hellman-group14-sha1")
  // SHA-1 输出 20 字节
  let h = @crypto.Hasher::new(alg)
  h.update(b"test")
  let digest = h.finalize()
  inspect(digest.length(), content="20")
}

///|
test "kex/hash_alg_for_kex_sha256_ecdh" {
  let alg = hash_alg_for_kex("ecdh-sha2-nistp256")
  let h = @crypto.Hasher::new(alg)
  h.update(b"test")
  let digest = h.finalize()
  inspect(digest.length(), content="32")
}

///|
test "kex/hash_alg_for_kex_sha256_dh" {
  let alg = hash_alg_for_kex("diffie-hellman-group14-sha256")
  let h = @crypto.Hasher::new(alg)
  h.update(b"test")
  let digest = h.finalize()
  inspect(digest.length(), content="32")
}

///|
test "kex/hash_alg_for_kex_unknown_raises" {
  try {
    let _ = hash_alg_for_kex("unknown-alg")
    fail("expected ProtocolError")
  } catch {
    ProtocolError(msg) => {
      inspect(msg.contains("no hash for"), content="true")
      inspect(msg.contains("unknown-alg"), content="true")
    }
    _ => fail("expected ProtocolError")
  }
}

// ============== is_ecdh_alg / is_dh_alg ==============

///|
test "kex/is_ecdh_alg_true" {
  inspect(is_ecdh_alg("ecdh-sha2-nistp256"), content="true")
}

///|
test "kex/is_ecdh_alg_false" {
  inspect(is_ecdh_alg("diffie-hellman-group14-sha256"), content="false")
  inspect(is_ecdh_alg("unknown"), content="false")
}

///|
test "kex/is_dh_alg_sha256" {
  inspect(is_dh_alg("diffie-hellman-group14-sha256"), content="true")
}

///|
test "kex/is_dh_alg_sha1" {
  inspect(is_dh_alg("diffie-hellman-group14-sha1"), content="true")
}

///|
test "kex/is_dh_alg_false" {
  inspect(is_dh_alg("ecdh-sha2-nistp256"), content="false")
  inspect(is_dh_alg("unknown"), content="false")
}

// ============== compute_ecdh_exchange_hash ==============

///|
test "kex/compute_ecdh_exchange_hash_deterministic" {
  // 相同输入应产生相同哈希
  let v_c = b"SSH-2.0-MoonSSH_0.1.0"
  let v_s = b"SSH-2.0-OpenSSH_8.9"
  let i_c = Bytes::make(20, b'\x01')
  let i_s = Bytes::make(20, b'\x02')
  let k_s = Bytes::from_array([b'\x00', b'\x01', b'\x02'])
  let q_c = Bytes::make(32, b'\x03')
  let q_s = Bytes::make(32, b'\x04')
  let k = Bytes::from_array([b'\x00', b'\x05'])

  let h1 = compute_ecdh_exchange_hash(
    @crypto.Algorithm::sha256(),
    v_c,
    v_s,
    i_c,
    i_s,
    k_s,
    q_c,
    q_s,
    k,
  ) catch {
    e => fail("compute_ecdh_exchange_hash: \{Repr(e)}")
  }
  let h2 = compute_ecdh_exchange_hash(
    @crypto.Algorithm::sha256(),
    v_c,
    v_s,
    i_c,
    i_s,
    k_s,
    q_c,
    q_s,
    k,
  ) catch {
    e => fail("compute_ecdh_exchange_hash: \{Repr(e)}")
  }
  // SHA-256 输出 32 字节
  inspect(h1.length(), content="32")
  // 相同输入 -> 相同输出
  let mut same = true
  for i in 0..<h1.length() {
    if h1[i] != h2[i] {
      same = false
    }
  }
  inspect(same, content="true")
}

///|
test "kex/compute_ecdh_exchange_hash_different_input" {
  let v_c = b"SSH-2.0-MoonSSH_0.1.0"
  let v_s = b"SSH-2.0-OpenSSH_8.9"
  let i_c = Bytes::make(20, b'\x01')
  let i_s = Bytes::make(20, b'\x02')
  let k_s = Bytes::from_array([b'\x00', b'\x01', b'\x02'])
  let q_c = Bytes::make(32, b'\x03')
  let q_s = Bytes::make(32, b'\x04')
  let k1 = Bytes::from_array([b'\x00', b'\x05'])
  let k2 = Bytes::from_array([b'\x00', b'\x06'])

  let h1 = compute_ecdh_exchange_hash(
    @crypto.Algorithm::sha256(),
    v_c,
    v_s,
    i_c,
    i_s,
    k_s,
    q_c,
    q_s,
    k1,
  ) catch {
    e => fail("compute_ecdh_exchange_hash: \{Repr(e)}")
  }
  let h2 = compute_ecdh_exchange_hash(
    @crypto.Algorithm::sha256(),
    v_c,
    v_s,
    i_c,
    i_s,
    k_s,
    q_c,
    q_s,
    k2,
  ) catch {
    e => fail("compute_ecdh_exchange_hash: \{Repr(e)}")
  }
  // 不同 shared_secret -> 不同哈希
  let mut diff = false
  for i in 0..<h1.length() {
    if h1[i] != h2[i] {
      diff = true
    }
  }
  inspect(diff, content="true")
}

// ============== compute_dh_exchange_hash ==============

///|
test "kex/compute_dh_exchange_hash_deterministic" {
  let v_c = b"SSH-2.0-MoonSSH_0.1.0"
  let v_s = b"SSH-2.0-OpenSSH_8.9"
  let i_c = Bytes::make(20, b'\x01')
  let i_s = Bytes::make(20, b'\x02')
  let k_s = Bytes::from_array([b'\x00', b'\x01', b'\x02'])
  let e = Bytes::from_array([b'\x00', b'\x03'])
  let f = Bytes::from_array([b'\x00', b'\x04'])
  let k = Bytes::from_array([b'\x00', b'\x05'])

  let h1 = compute_dh_exchange_hash(
    @crypto.Algorithm::sha256(),
    v_c,
    v_s,
    i_c,
    i_s,
    k_s,
    e,
    f,
    k,
  ) catch {
    e => fail("compute_dh_exchange_hash: \{Repr(e)}")
  }
  let h2 = compute_dh_exchange_hash(
    @crypto.Algorithm::sha256(),
    v_c,
    v_s,
    i_c,
    i_s,
    k_s,
    e,
    f,
    k,
  ) catch {
    e => fail("compute_dh_exchange_hash: \{Repr(e)}")
  }
  inspect(h1.length(), content="32")
  let mut same = true
  for i in 0..<h1.length() {
    if h1[i] != h2[i] {
      same = false
    }
  }
  inspect(same, content="true")
}

///|
test "kex/compute_dh_exchange_hash_sha1" {
  let v_c = b"SSH-2.0-test"
  let v_s = b"SSH-2.0-server"
  let i_c = Bytes::make(16, b'\x10')
  let i_s = Bytes::make(16, b'\x20')
  let k_s = Bytes::from_array([b'\xab'])
  let e = Bytes::from_array([b'\x00', b'\x01'])
  let f = Bytes::from_array([b'\x00', b'\x02'])
  let k = Bytes::from_array([b'\x00', b'\x03'])

  let h = compute_dh_exchange_hash(
    @crypto.Algorithm::sha1(),
    v_c,
    v_s,
    i_c,
    i_s,
    k_s,
    e,
    f,
    k,
  ) catch {
    e => fail("compute_dh_exchange_hash sha1: \{Repr(e)}")
  }
  // SHA-1 输出 20 字节
  inspect(h.length(), content="20")
}

// ============== derive_keys ==============

///|
test "kex/derive_keys_sha256" {
  // RFC 4253 §7.2 密钥派生
  let session_id = Bytes::make(32, b'\xaa')
  let h = Bytes::make(32, b'\xbb')
  let k = Bytes::from_array([b'\x00', b'\xcc'])

  let (iv_c2s, iv_s2c, ek_c2s, ek_s2c, mk_c2s, mk_s2c) = derive_keys(
    @crypto.Algorithm::sha256(),
    h,
    k,
    session_id,
    16,
    16,
    32,
  ) catch {
    e => fail("derive_keys: \{Repr(e)}")
  }
  // IV 长度 = 16
  inspect(iv_c2s.length(), content="16")
  inspect(iv_s2c.length(), content="16")
  // 加密密钥长度 = 16
  inspect(ek_c2s.length(), content="16")
  inspect(ek_s2c.length(), content="16")
  // MAC 密钥长度 = 32
  inspect(mk_c2s.length(), content="32")
  inspect(mk_s2c.length(), content="32")
  // 相同输入应产生相同密钥
  let (iv_c2s2, _, _, _, _, _) = derive_keys(
    @crypto.Algorithm::sha256(),
    h,
    k,
    session_id,
    16,
    16,
    32,
  ) catch {
    e => fail("derive_keys 2: \{Repr(e)}")
  }
  let mut same = true
  for i in 0..<iv_c2s.length() {
    if iv_c2s[i] != iv_c2s2[i] {
      same = false
    }
  }
  inspect(same, content="true")
}

///|
test "kex/derive_keys_different_k_different_output" {
  let session_id = Bytes::make(32, b'\xaa')
  let h = Bytes::make(32, b'\xbb')
  let k1 = Bytes::from_array([b'\x00', b'\x01'])
  let k2 = Bytes::from_array([b'\x00', b'\x02'])

  let (iv1, _, _, _, _, _) = derive_keys(
    @crypto.Algorithm::sha256(),
    h,
    k1,
    session_id,
    16,
    16,
    32,
  ) catch {
    e => fail("derive_keys k1: \{Repr(e)}")
  }
  let (iv2, _, _, _, _, _) = derive_keys(
    @crypto.Algorithm::sha256(),
    h,
    k2,
    session_id,
    16,
    16,
    32,
  ) catch {
    e => fail("derive_keys k2: \{Repr(e)}")
  }
  let mut diff = false
  for i in 0..<iv1.length() {
    if iv1[i] != iv2[i] {
      diff = true
    }
  }
  inspect(diff, content="true")
}

// ============== kex_random_bytes ==============

///|
test "kex/kex_random_bytes_length" {
  let b1 = kex_random_bytes(16)
  inspect(b1.length(), content="16")
  let b32 = kex_random_bytes(32)
  inspect(b32.length(), content="32")
  let b0 = kex_random_bytes(0)
  inspect(b0.length(), content="0")
}

// ============== kdf multi-round (i > 0 branch) ==============

///|
test "kex/derive_keys_needs_multi_round_kdf" {
  // 当 requested key length > single hash output 时，kdf 循环多次
  // SHA-256 输出 32 字节；请求 48 字节 → 需要 2 轮
  let session_id = Bytes::make(32, b'\xcc')
  let h = Bytes::make(32, b'\xdd')
  let k = Bytes::from_array([b'\x00', b'\xee'])

  let (iv_c2s, iv_s2c, ek_c2s, ek_s2c, mk_c2s, mk_s2c) = derive_keys(
    @crypto.Algorithm::sha256(),
    h,
    k,
    session_id,
    48,
    48,
    48,
  ) catch {
    e => fail("derive_keys multi-round: \{Repr(e)}")
  }
  // 所有派生密钥应为请求的 48 字节
  inspect(iv_c2s.length(), content="48")
  inspect(iv_s2c.length(), content="48")
  inspect(ek_c2s.length(), content="48")
  inspect(ek_s2c.length(), content="48")
  inspect(mk_c2s.length(), content="48")
  inspect(mk_s2c.length(), content="48")
  // 不同用途的密钥应不同
  let mut diff = false
  for i in 0..<iv_c2s.length() {
    if iv_c2s[i] != ek_c2s[i] {
      diff = true
    }
  }
  inspect(diff, content="true")
}

///|
test "kex/derive_keys_exact_hash_length" {
  // requested length == hash output (32) → 单轮，无截断
  let session_id = Bytes::make(32, b'\x11')
  let h = Bytes::make(32, b'\x22')
  let k = Bytes::from_array([b'\x00', b'\x33'])

  let (iv, _, _, _, _, _) = derive_keys(
    @crypto.Algorithm::sha256(),
    h,
    k,
    session_id,
    32,
    32,
    32,
  ) catch {
    e => fail("derive_keys exact: \{Repr(e)}")
  }
  inspect(iv.length(), content="32")
}

///|
test "kex/derive_keys_sha1" {
  // SHA-1 输出 20 字节
  let session_id = Bytes::make(20, b'\x44')
  let h = Bytes::make(20, b'\x55')
  let k = Bytes::from_array([b'\x00', b'\x66'])

  let (iv, ek, _, _, mk, _) = derive_keys(
    @crypto.Algorithm::sha1(),
    h,
    k,
    session_id,
    16,
    16,
    20,
  ) catch {
    e => fail("derive_keys sha1: \{Repr(e)}")
  }
  inspect(iv.length(), content="16")
  inspect(ek.length(), content="16")
  inspect(mk.length(), content="20")
}
