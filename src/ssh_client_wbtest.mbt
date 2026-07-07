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
  // 默认 accept_host_key 应接受任何密钥
  let accepted = (opts.accept_host_key)("ssh-rsa", b"fakekey")
  inspect(accepted, content="true")
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
test "ssh_client/connect_options_with_host_key_verifier" {
  // with_host_key_verifier 应替换默认的验证函数
  let opts = ConnectOptions::new("host", 22, "user")
  let verified_opts = opts.with_host_key_verifier((_alg, _key) => false)
  // 新验证器应拒绝所有密钥
  let rejected = (verified_opts.accept_host_key)("ssh-rsa", b"key")
  inspect(rejected, content="false")
  // 原始 opts 的验证器仍应接受
  let accepted = (opts.accept_host_key)("ssh-rsa", b"key")
  inspect(accepted, content="true")
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
