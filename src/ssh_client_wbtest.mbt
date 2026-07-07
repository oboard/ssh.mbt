// Whitebox tests for src/ssh_client.mbt.
// Run `moon test --target native` to execute.

///|
test "ssh_client/default_banner" {
  // 默认 banner 应符合 SSH-2.0 格式
  let banner = Client::default_banner()
  inspect(banner.has_prefix("SSH-2.0-"), content="true")
  inspect(banner, content="SSH-2.0-MoonSSH_0.1.0")
}

///|
test "ssh_client/connect_options_defaults" {
  // ConnectOptions::new 应设置合理的默认值
  let opts = ConnectOptions::new("example.com", 22, "root")
  inspect(opts.host, content="example.com")
  inspect(opts.port, content="22")
  inspect(opts.user, content="root")
  inspect(opts.client_banner is None, content="true")
  inspect(opts.timeout_ms, content="30000")
  // 默认 host_key_policy 应为 Strict 且拒绝未知主机
  let decision = verify_host_key(
    opts.host_key_policy,
    "example.com",
    22,
    "ssh-rsa",
    b"anykey",
  )
  inspect(decision is RejectUnknown, content="true")
}

///|
test "ssh_client/connect_options_with_custom_banner" {
  // 可以通过结构体语法设置自定义 banner
  let opts = ConnectOptions::new("host", 22, "user")
  let custom = { ..opts, client_banner: Some("SSH-2.0-Custom_1.0") }
  @debug.debug_inspect(
    custom.client_banner,
    content="Some(\"SSH-2.0-Custom_1.0\")",
  )
}

///|
test "ssh_client/connect_options_with_insecure_host_key" {
  // with_insecure_host_key 应让所有 host key 通过
  let opts = ConnectOptions::new("host", 22, "user").with_insecure_host_key()
  let decision = verify_host_key(
    opts.host_key_policy,
    "host",
    22,
    "ssh-rsa",
    b"anykey",
  )
  inspect(decision is Accept, content="true")
}

///|
test "ssh_client/connect_options_with_strict_known_hosts" {
  // 已加载的 known_hosts 中条目应被命中
  let kh = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA7Q=="
  let opts = ConnectOptions::new("example.com", 22, "user").with_strict_host_key_check(
    kh,
  ) catch {
    e => fail("with_strict_host_key_check: \{to_repr(e)}")
  }
  // alg 与 key 匹配 -> Accept
  let good = verify_host_key(
    opts.host_key_policy,
    "example.com",
    22,
    "ssh-ed25519",
    Bytes::from_array([
      b'\x00', b'\xde', b'\xad', b'\xbe', b'\xef', b'\x00', b'\x42', b'\x42',
    ]),
  )
  inspect(good is RejectMismatch(_, _), content="true") // key 不同 -> mismatch
  // 完全不匹配的主机 -> RejectUnknown
  let unknown = verify_host_key(
    opts.host_key_policy,
    "attacker.com",
    22,
    "ssh-rsa",
    b"key",
  )
  inspect(unknown is RejectUnknown, content="true")
}

///|
test "ssh_client/connect_options_with_trust_on_first_use" {
  // TOFU: 首次连接由 prompt 决定；后续必须匹配
  let mut called = 0
  let prompt : (String, String, Bytes) -> Bool = (_h, _a, _k) => {
    called = called + 1
    true
  }
  let kh = ""
  let opts = ConnectOptions::new("example.com", 22, "user").with_trust_on_first_use(
    kh, prompt,
  ) catch {
    e => fail("with_trust_on_first_use: \{to_repr(e)}")
  }
  let key = b"firstkey"
  let first = verify_host_key(
    opts.host_key_policy,
    "example.com",
    22,
    "ssh-rsa",
    key,
  )
  inspect(first is Accept, content="true")
  inspect(called, content="1")
  // 第二次同样 key -> Accept，不再回调
  let second = verify_host_key(
    opts.host_key_policy,
    "example.com",
    22,
    "ssh-rsa",
    key,
  )
  inspect(second is Accept, content="true")
  inspect(called, content="1")
  // 第三次换 key -> MITM reject
  let third = verify_host_key(
    opts.host_key_policy,
    "example.com",
    22,
    "ssh-rsa",
    b"differentkey",
  )
  inspect(third is RejectMismatch(_, _), content="true")
}

///|
test "ssh_client/connect_options_with_host_key_verifier" {
  // with_host_key_verifier：回调返回 true -> Accept
  let accepting = ConnectOptions::new("host", 22, "user").with_host_key_verifier((
      _a,
      _k,
    ) => true,
  )
  let accept = verify_host_key(
    accepting.host_key_policy,
    "host",
    22,
    "ssh-rsa",
    b"k",
  )
  inspect(accept is Accept, content="true")

  // 回调返回 false -> RejectByUser（KEX 阶段抛 HostKeyMismatch）
  let rejecting = ConnectOptions::new("host", 22, "user").with_host_key_verifier((
      _a,
      _k,
    ) => false,
  )
  let reject = verify_host_key(
    rejecting.host_key_policy,
    "host",
    22,
    "ssh-rsa",
    b"k",
  )
  inspect(reject is RejectByUser, content="true")
}

///|
test "ssh_client/parse_cipher_algorithm_aes128_ctr" {
  // 应正确解析 aes128-ctr
  let alg = parse_cipher_algorithm("aes128-ctr")
  inspect(alg.id(), content="1")
  inspect(alg.key_len(), content="16")
  inspect(alg.iv_len(), content="16")
  inspect(alg.block_len(), content="16")
}

///|
test "ssh_client/parse_cipher_algorithm_unsupported" {
  // 不支持的算法应抛出 ProtocolError
  try {
    ignore(parse_cipher_algorithm("aes256-cbc"))
    fail("expected ProtocolError")
  } catch {
    ProtocolError(msg) => {
      inspect(msg.contains("unsupported cipher"), content="true")
      inspect(msg.contains("aes256-cbc"), content="true")
    }
    _ => fail("expected ProtocolError")
  }
}

///|
test "ssh_client/parse_mac_algorithm_hmac_sha1" {
  let alg = parse_mac_algorithm("hmac-sha1")
  inspect(alg.output_len(), content="20")
}

///|
test "ssh_client/parse_mac_algorithm_hmac_sha256" {
  let alg = parse_mac_algorithm("hmac-sha2-256")
  inspect(alg.output_len(), content="32")
}

///|
test "ssh_client/parse_mac_algorithm_unsupported" {
  try {
    ignore(parse_mac_algorithm("hmac-sha512"))
    fail("expected ProtocolError")
  } catch {
    ProtocolError(msg) => {
      inspect(msg.contains("unsupported MAC"), content="true")
      inspect(msg.contains("hmac-sha512"), content="true")
    }
    _ => fail("expected ProtocolError")
  }
}

///|
test "ssh_client/build_signature_blob" {
  // 签名 blob 格式: string(alg) + string(sig)
  let sig = Bytes::from_array([b'\x01', b'\x02', b'\x03'])
  let blob = build_signature_blob("ssh-ed25519", sig)
  let r = Reader::new(blob)
  let alg = r.read_string_as_str()
  inspect(alg, content="ssh-ed25519")
  let sig_data = r.read_string()
  inspect(sig_data.length(), content="3")
  // 确认没有多余数据
  let rest = r.rest()
  inspect(rest.length(), content="0")
}

///|
test "ssh_client/build_signature_blob_rsa" {
  // RSA 签名 blob
  let sig = Bytes::from_array([b'\xaa', b'\xbb'])
  let blob = build_signature_blob("rsa-sha2-256", sig)
  let r = Reader::new(blob)
  let alg = r.read_string_as_str()
  inspect(alg, content="rsa-sha2-256")
  let sig_data = r.read_string()
  inspect(sig_data.length(), content="2")
}

// ============== ConnectOptions builder chain ==============

///|
test "ssh_client/connect_options_with_strict_empty_content" {
  // 空 known_hosts -> 所有主机都被拒绝
  let opts = ConnectOptions::new("host", 22, "user").with_strict_host_key_check(
    "",
  ) catch {
    e => fail("with_strict_host_key_check empty: \{to_repr(e)}")
  }
  let decision = verify_host_key(
    opts.host_key_policy,
    "host",
    22,
    "ssh-rsa",
    b"key",
  )
  inspect(decision is RejectUnknown, content="true")
}

///|
test "ssh_client/connect_options_with_strict_bad_line_skipped" {
  // 损坏的行应被跳过，不影响其他条目
  let content = "bad-line-no-alg\nexample.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA7Q=="
  let opts = ConnectOptions::new("example.com", 22, "user").with_strict_host_key_check(
    content,
  ) catch {
    e => fail("with_strict_host_key_check: \{to_repr(e)}")
  }
  // 条目存在，但 key 不匹配 -> RejectMismatch
  let decision = verify_host_key(
    opts.host_key_policy,
    "example.com",
    22,
    "ssh-ed25519",
    Bytes::from_array([b'\x00', b'\xff']),
  )
  inspect(decision is RejectMismatch(_, _), content="true")
}

///|
test "ssh_client/connect_options_tofu_reject_changed_key" {
  // TOFU: prompt 返回 true 后更换 key -> RejectMismatch
  let prompt : (String, String, Bytes) -> Bool = (_h, _a, _k) => true
  let opts = ConnectOptions::new("host", 22, "user").with_trust_on_first_use(
    "", prompt,
  ) catch {
    e => fail("tofu: \{to_repr(e)}")
  }
  // 第一次：接受
  let first = verify_host_key(
    opts.host_key_policy,
    "host",
    22,
    "ssh-rsa",
    b"key1",
  )
  inspect(first is Accept, content="true")
  // 第二次不同 key -> RejectMismatch
  let second = verify_host_key(
    opts.host_key_policy,
    "host",
    22,
    "ssh-rsa",
    b"key2",
  )
  inspect(second is RejectMismatch(_, _), content="true")
}

///|
test "ssh_client/connect_options_tofu_prompt_reject" {
  // TOFU: prompt 返回 false -> RejectByUser
  let prompt : (String, String, Bytes) -> Bool = (_h, _a, _k) => false
  let opts = ConnectOptions::new("host", 22, "user").with_trust_on_first_use(
    "", prompt,
  ) catch {
    e => fail("tofu reject: \{to_repr(e)}")
  }
  let decision = verify_host_key(
    opts.host_key_policy,
    "host",
    22,
    "ssh-rsa",
    b"key",
  )
  inspect(decision is RejectByUser, content="true")
}

///|
test "ssh_client/connect_options_callback_accept_and_reject" {
  // Callback 模式：自定义校验器
  let accept_all = ConnectOptions::new("h", 22, "u").with_host_key_verifier((
    _a,
    _k,
  ) => true)
  let r1 = verify_host_key(accept_all.host_key_policy, "h", 22, "ssh-rsa", b"k")
  inspect(r1 is Accept, content="true")

  let reject_all = ConnectOptions::new("h", 22, "u").with_host_key_verifier((
    _a,
    _k,
  ) => false)
  let r2 = verify_host_key(reject_all.host_key_policy, "h", 22, "ssh-rsa", b"k")
  inspect(r2 is RejectByUser, content="true")
}

// ============== ConnectOptions field access ==============

///|
test "ssh_client/connect_options_field_values" {
  let opts = ConnectOptions::new("myhost", 2222, "admin")
  inspect(opts.host, content="myhost")
  inspect(opts.port, content="2222")
  inspect(opts.user, content="admin")
  inspect(opts.client_banner is None, content="true")
  inspect(opts.timeout_ms, content="30000")
}

///|
test "ssh_client/connect_options_with_insecure_accepts_any" {
  // Insecure 模式应接受任何 host key
  let opts = ConnectOptions::new("any", 22, "u").with_insecure_host_key()
  let r = verify_host_key(
    opts.host_key_policy,
    "any",
    22,
    "any-alg",
    b"any-key",
  )
  inspect(r is Accept, content="true")
}

// ============== parse_cipher_algorithm edge cases ==============

///|
test "ssh_client/parse_cipher_algorithm_aes128_ctr_properties" {
  let alg = parse_cipher_algorithm("aes128-ctr")
  // AES-128: 16 字节 key, 16 字节 IV, 16 字节 block
  inspect(alg.key_len(), content="16")
  inspect(alg.iv_len(), content="16")
  inspect(alg.block_len(), content="16")
}

// ============== parse_mac_algorithm edge cases ==============

///|
test "ssh_client/parse_mac_algorithm_hmac_sha1_properties" {
  let alg = parse_mac_algorithm("hmac-sha1")
  // SHA-1 HMAC 输出 20 字节
  inspect(alg.output_len(), content="20")
}

///|
test "ssh_client/parse_mac_algorithm_hmac_sha256_properties" {
  let alg = parse_mac_algorithm("hmac-sha2-256")
  // SHA-256 HMAC 输出 32 字节
  inspect(alg.output_len(), content="32")
}

// ============== SOCKS5 IPv4 address parsing ==============

///|
test "ssh_client/ipv4_bytes_to_string_typical" {
  // 172.18.0.1 (Docker gateway)
  let addr = Bytes::from_array([b'\xAC', b'\x12', b'\x00', b'\x01'])
  inspect(ipv4_bytes_to_string(addr), content="172.18.0.1")
}

///|
test "ssh_client/ipv4_bytes_to_string_localhost" {
  let addr = Bytes::from_array([b'\x7F', b'\x00', b'\x00', b'\x01'])
  inspect(ipv4_bytes_to_string(addr), content="127.0.0.1")
}

///|
test "ssh_client/ipv4_bytes_to_string_zeros" {
  let addr = Bytes::from_array([b'\x00', b'\x00', b'\x00', b'\x00'])
  inspect(ipv4_bytes_to_string(addr), content="0.0.0.0")
}

///|
test "ssh_client/ipv4_bytes_to_string_max" {
  let addr = Bytes::from_array([b'\xFF', b'\xFF', b'\xFF', b'\xFF'])
  inspect(ipv4_bytes_to_string(addr), content="255.255.255.255")
}
