///|
fn build_test_kexinit_payload(kex_algs : Array[String]) -> Bytes {
  let w = Writer::new()
  w.write_byte(SSH_MSG_KEXINIT)
  w.write_bytes(Bytes::make(16, b'\x01'))
  w.write_name_list(kex_algs)
  w.write_name_list(server_host_key_algorithms())
  w.write_name_list(encryption_algorithms())
  w.write_name_list(encryption_algorithms())
  w.write_name_list(mac_algorithms())
  w.write_name_list(mac_algorithms())
  w.write_name_list(compression_algorithms())
  w.write_name_list(compression_algorithms())
  w.write_name_list([""])
  w.write_name_list([""])
  w.write_byte(0)
  w.write_uint32(0)
  w.to_bytes()
}

///|
fn build_test_host_key_blob(alg : String, key : Bytes) -> Bytes {
  let w = Writer::new()
  w.write_string_from_str(alg)
  w.write_string(key)
  w.to_bytes()
}

///|
fn build_test_signature_blob(alg : String, sig : Bytes) -> Bytes {
  let w = Writer::new()
  w.write_string_from_str(alg)
  w.write_string(sig)
  w.to_bytes()
}

///|
fn build_test_ecdh_reply(
  host_key : Bytes,
  server_public : Bytes,
  signature : Bytes,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(SSH_MSG_KEX_ECDH_REPLY)
  w.write_string(host_key)
  w.write_string(server_public)
  w.write_string(signature)
  w.to_bytes()
}

///|
test "KexContext::drive sends KEXINIT and negotiates algorithms" {
  let ctx = KexContext::new(b"SSH-2.0-test-client", b"SSH-2.0-test-server")
  let server_payload = build_test_kexinit_payload([
    "diffie-hellman-group14-sha256",
  ])
  let sent : Array[Bytes] = []
  try
    ctx.drive(() => server_payload, payload => sent.push(payload), (_alg, _key) => {
      true
    })
  catch {
    ProtocolError(message) =>
      assert_true(message.contains("unsupported key exchange"))
    _ => fail("expected protocol error after KEXINIT negotiation")
  } noraise {
    _ => fail("expected unsupported KEX algorithm error")
  }
  assert_eq(sent.length(), 1)
  assert_eq(sent[0], ctx.i_c)
  assert_eq(ctx.state, Negotiating)
  assert_eq(ctx.kex_alg, "diffie-hellman-group14-sha256")
  assert_eq(ctx.host_key_alg, "ssh-ed25519")
  assert_eq(ctx.enc_alg, "chacha20-poly1305@openssh.com")
  assert_eq(ctx.mac_alg, "hmac-sha2-512")
  assert_eq(ctx.comp_alg, "none")
}

///|
test "ECDH payload helpers round trip wire fields" {
  let client_public = b"client-public"
  assert_eq(
    build_ecdh_init_payload(client_public),
    b"\x1e" + encode_string(client_public),
  )
  let host_key = build_test_host_key_blob(
    "ssh-ed25519",
    Bytes::make(32, b'\x02'),
  )
  let server_public = Bytes::make(32, b'\x03')
  let signature = build_test_signature_blob("ssh-ed25519", b"sig")
  let reply_payload = build_test_ecdh_reply(host_key, server_public, signature)
  let reply = parse_ecdh_reply_payload(reply_payload)
  assert_eq(reply.host_key, host_key)
  assert_eq(reply.server_public, server_public)
  assert_eq(reply.signature, signature)
  assert_eq(parse_host_key_algorithm(reply.host_key), "ssh-ed25519")
  let parsed_sig = parse_signature_blob(reply.signature)
  assert_eq(parsed_sig.alg, "ssh-ed25519")
  assert_eq(parsed_sig.sig, b"sig")
  assert_eq(build_newkeys_payload(), b"\x15")
  assert_true(is_newkeys_payload(build_newkeys_payload()))
  assert_false(is_newkeys_payload(b"\x14"))
}
