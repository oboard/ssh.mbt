///
/// MoonSSH 顶层 API。
/// 组装 KEX / auth / channel 模块，提供完整 SSH 客户端。

///|
pub struct ConnectOptions {
  host : String
  port : Int
  user : String
  client_banner : String?
  accept_host_key : (String, Bytes) -> Bool
  timeout_ms : Int
}

///|
pub fn ConnectOptions::new(
  host : String,
  port : Int,
  user : String,
) -> ConnectOptions {
  {
    host,
    port,
    user,
    client_banner: None,
    accept_host_key: (_alg, _key) => true,
    timeout_ms: 30_000,
  }
}

///|
pub fn ConnectOptions::with_host_key_verifier(
  self : ConnectOptions,
  f : (String, Bytes) -> Bool,
) -> ConnectOptions {
  { ..self, accept_host_key: f }
}

///|
pub struct Client {
  priv conn : ClientConn
  priv kex : KexContext
  priv auth : AuthContext
  priv accept_host_key : (String, Bytes) -> Bool
  priv mut session_id : Bytes
  mut next_channel_id : Int
  priv mut encrypted : Bool
  priv mut cipher_c2s : @crypto.Cipher?
  priv mut cipher_s2c : @crypto.Cipher?
  priv mut mac_c2s : @crypto.Mac?
  priv mut mac_s2c : @crypto.Mac?
  priv mut seq_send : UInt
  priv mut seq_recv : UInt
}

///|
priv enum ClientConn {
  Connected(@socket.Tcp)
}

///|
pub fn Client::default_banner() -> String {
  "SSH-2.0-MoonSSH_0.1.0"
}

///|
/// 连接 SSH 服务器并完成 banner 交换。不执行 KEX 或认证。
pub fn Client::connect(opts : ConnectOptions) -> Client raise SshError {
  let conn = @socket.Tcp::connect_to_host(opts.host, port=opts.port) catch {
    e => raise IoError("connect: \{e}")
  }
  let client_banner = match opts.client_banner {
    Some(b) => b
    None => Client::default_banner()
  }
  conn.write("\{client_banner}\r\n") catch {
    e => raise IoError("write banner: \{e}")
  }
  let banner_bytes = conn.read_until_newline() catch {
    e => raise IoError("read banner: \{e}")
  }
  if !banner_bytes.has_prefix(b"SSH-") {
    raise ProtocolError("server banner missing SSH- prefix")
  }
  // 使用 bytes_to_utf8_string 正确解码字节为字符串，
  // 避免 Bytes::to_string() 返回 Debug 格式 b"..."。
  let banner_line = bytes_to_utf8_string(banner_bytes)
  debug("server banner: '\{banner_line}'")
  let v_c = @utf8.encode(client_banner)
  let v_s = @utf8.encode(banner_line)
  let kex = KexContext::new(v_c, v_s)
  let auth = AuthContext::new(opts.user)
  {
    conn: Connected(conn),
    kex,
    auth,
    accept_host_key: opts.accept_host_key,
    session_id: b"",
    next_channel_id: 0,
    encrypted: false,
    cipher_c2s: None,
    cipher_s2c: None,
    mac_c2s: None,
    mac_s2c: None,
    seq_send: 0U,
    seq_recv: 0U,
  }
}

///|
/// 执行密钥交换。
pub fn Client::kex(self : Client) -> Unit raise SshError {
  self.kex.drive(
    () => self.read_plain_packet(),
    payload => self.write_plain_packet(payload),
    self.accept_host_key,
  )
  self.session_id = self.kex.session_id
  let keys = self.kex.derive_session_keys()
  self.install_encryption(keys)
}

///|
/// 密码认证。
pub fn Client::auth_password(
  self : Client,
  password : String,
) -> Unit raise SshError {
  if self.kex.state != Done {
    raise ProtocolError("auth_password: KEX not complete")
  }
  if !self.encrypted {
    raise NotEncrypted
  }

  let service_req = build_service_request(SERVICE_USERAUTH)
  self.write_encrypted_packet(service_req)
  let reply1 = self.read_auth_packet()
  match parse_auth_reply(reply1) {
    ServiceAccept => ()
    _ => raise ProtocolError("auth: expected SERVICE_ACCEPT")
  }
  let auth_req = self.auth.build_password(password)
  self.write_encrypted_packet(auth_req)
  let reply2 = self.read_auth_packet()
  match parse_auth_reply(reply2) {
    Success => self.auth.apply_reply(Success)
    Failure(methods, _) => raise AuthFailed("methods: \{methods}")
    _ => raise ProtocolError("auth: unexpected reply")
  }
}

///|
/// 公钥认证（two-step）。自动适配 ssh-rsa / ssh-ed25519。
/// 私钥路径支持 PEM（PKCS#1/PKCS#8/传统）和 OpenSSH openssh-key-v1 格式。
/// 对应的 .pub 文件必须是 OpenSSH 单行格式：`<alg> <base64> <comment>`。
pub fn Client::auth_publickey(
  self : Client,
  private_key_path : String,
) -> Unit raise SshError {
  if self.kex.state != Done {
    raise ProtocolError("auth_publickey: KEX not complete")
  }
  if !self.encrypted {
    raise NotEncrypted
  }

  // Step 0: 发送 SERVICE_REQUEST
  let service_req = build_service_request(SERVICE_USERAUTH)
  self.write_encrypted_packet(service_req)
  let reply0 = self.read_auth_packet()
  match parse_auth_reply(reply0) {
    ServiceAccept => ()
    _ => raise ProtocolError("auth: expected SERVICE_ACCEPT")
  }

  // 加载私钥
  let pkey = @crypto.PKey::load_private_key(private_key_path) catch {
    e => raise ProtocolError("auth: load key: \{e}")
  }
  defer pkey.close()

  // 从 .pub 文件读取公钥 (alg, blob)
  let pubkey_path = private_key_path + ".pub"
  let (pub_alg, pubkey_blob) = @crypto.read_openssh_pubkey(pubkey_path) catch {
    e => raise ProtocolError("auth: read pubkey \{pubkey_path}: \{e}")
  }

  // 根据私钥类型决定签名算法
  let (pubkey_alg, md_alg) : (String, Int) = match pkey.key_id() {
    1087 => ("ssh-ed25519", 0) // EdDSA, no pre-hash
    6 => ("rsa-sha2-256", 2) // RSA + SHA-256
    116 => ("ssh-dss", 1) // DSA + SHA-1
    408 => {
      // ECDSA: 根据曲线 NID 决定算法名和 digest
      let nid = pkey.ec_curve_nid()
      match nid {
        415 => ("ecdsa-sha2-nistp256", 2) // P-256 + SHA-256
        715 => ("ecdsa-sha2-nistp384", 3) // P-384 + SHA-384
        716 => ("ecdsa-sha2-nistp521", 4) // P-521 + SHA-521
        _ => raise ProtocolError("auth: unknown EC curve NID \{nid}")
      }
    }
    other => raise ProtocolError("auth: unsupported key type \{other}")
  }
  // 防止 .pub 文件声明的算法和私钥类型不匹配
  // RSA 公钥 blob 始终使用 'ssh-rsa'，但签名算法可以是 'rsa-sha2-256' 或 'rsa-sha2-512'（RFC 8332）
  let alg_compatible = pub_alg == pubkey_alg ||
    (
      pub_alg == "ssh-rsa" &&
      (pubkey_alg == "rsa-sha2-256" || pubkey_alg == "rsa-sha2-512")
    )
  if !alg_compatible {
    raise ProtocolError(
      "auth: pubkey file declares '\{pub_alg}' but private key is '\{pubkey_alg}'",
    )
  }

  // Step 1: 发送 publickey 查询（无签名）
  let query = self.auth.build_publickey_query(pubkey_alg, pubkey_blob)
  self.write_encrypted_packet(query)
  let reply1 = self.read_auth_packet()
  match parse_auth_reply(reply1) {
    PublicKeyOk(_alg, _blob) => ()
    Failure(methods, _) =>
      raise AuthFailed("publickey rejected: methods \{methods}")
    _ => raise ProtocolError("auth: expected PK_OK")
  }

  // Step 2: 构建签名输入并签名
  let sig_input = build_publickey_signature_input(
    self.session_id,
    self.auth.user,
    "ssh-connection",
    pubkey_alg,
    pubkey_blob,
  )
  let signature = pkey.sign(md_alg, sig_input) catch {
    e => raise ProtocolError("auth: sign: \{e}")
  }

  // 将签名打包为 SSH signature blob (alg || sig)
  let sig_blob = build_signature_blob(pubkey_alg, signature)

  // Step 3: 发送带签名的 publickey 请求
  let sign_req = self.auth.build_publickey_sign(
    pubkey_alg, pubkey_blob, sig_blob,
  )
  self.write_encrypted_packet(sign_req)
  let reply2 = self.read_auth_packet()
  match parse_auth_reply(reply2) {
    Success => self.auth.apply_reply(Success)
    _ => raise AuthFailed("publickey sign: authentication rejected")
  }
}

///|
/// keyboard-interactive 认证。
pub fn Client::auth_keyboard_interactive(
  self : Client,
  answer_fn : (String) -> String,
) -> Unit raise SshError {
  if self.kex.state != Done {
    raise ProtocolError("auth_kbdint: KEX not complete")
  }
  if !self.encrypted {
    raise NotEncrypted
  }

  let service_req = build_service_request(SERVICE_USERAUTH)
  self.write_encrypted_packet(service_req)
  let reply0 = self.read_auth_packet()
  match parse_auth_reply(reply0) {
    ServiceAccept => ()
    _ => raise ProtocolError("auth: expected SERVICE_ACCEPT")
  }

  let kbd_req = self.auth.build_keyboard_interactive()
  self.write_encrypted_packet(kbd_req)

  while true {
    let reply = self.read_auth_packet()
    match parse_auth_reply(reply) {
      Success => {
        self.auth.apply_reply(Success)
        return
      }
      Failure(methods, _) =>
        raise AuthFailed("kbd-int rejected: methods \{methods}")
      _ => {
        // 收到 INFO_REQUEST
        let responses = [answer_fn("Password: ")]
        let resp_payload = self.auth.build_info_response(responses)
        self.write_encrypted_packet(resp_payload)
      }
    }
  }
}

///|
/// 自动回退认证（none → publickey → password）。
pub fn Client::auth_auto(
  self : Client,
  password : String,
  key_path? : String,
) -> Unit raise SshError {
  if self.kex.state != Done {
    raise ProtocolError("auth_auto: KEX not complete")
  }
  if !self.encrypted {
    raise NotEncrypted
  }

  // 1. SERVICE_REQUEST
  let service_req = build_service_request(SERVICE_USERAUTH)
  self.write_encrypted_packet(service_req)
  let reply0 = self.read_auth_packet()
  match parse_auth_reply(reply0) {
    ServiceAccept => ()
    _ => raise ProtocolError("auth: expected SERVICE_ACCEPT")
  }

  // 2. none 探测
  let none_req = self.auth.build_initial()
  self.write_encrypted_packet(none_req)
  let reply1 = self.read_auth_packet()
  match parse_auth_reply(reply1) {
    Success => {
      self.auth.apply_reply(Success)
      return
    }
    Failure(methods, _) => {
      // 3. 尝试公钥
      let key_path_val = key_path.unwrap_or("~/.ssh/id_rsa")
      if methods.contains(method_publickey()) {
        self.auth_publickey(key_path_val) catch {
          AuthFailed(_) => ()
          _e => ()
        }
        if self.auth.is_authenticated() {
          return
        }
      }
      if methods.contains(method_keyboard_interactive()) {
        self.auth_keyboard_interactive(_prompt => password) catch {
          AuthFailed(_) => ()
          _e => ()
        }
        if self.auth.is_authenticated() {
          return
        }
      }
      // 5. 尝试密码
      if methods.contains(method_password()) {
        self.auth_password(password)
        return
      }
      raise AuthFailed("no supported auth methods: \{methods}")
    }
    _ => raise ProtocolError("auth: unexpected probe reply")
  }
}

// ============== Channel operations ==============

///|
pub fn Client::open_session(self : Client) -> Channel {
  let id = self.next_channel_id
  self.next_channel_id = self.next_channel_id + 1
  Channel::new(id)
}

///|
pub fn Client::exec(
  self : Client,
  channel : Channel,
  command : String,
) -> (String, String) raise SshError {
  // 1. 打开通道
  let open_msg = build_channel_open(channel.id(), 1024 * 1024, 32 * 1024)
  self.write_packet(open_msg)
  while true {
    let payload = self.read_packet()
    let responses = channel.handle_inbound(payload)
    for resp in responses {
      self.write_packet(resp)
    }
    if channel.is_open() {
      break
    }
    if channel.state() == Done {
      raise ProtocolError("channel: failed to open")
    }
  }

  // 2. 发送 exec 请求
  let exec_msg = build_channel_request_exec(channel.peer_id(), command)
  self.write_packet(exec_msg)

  // 3. 读取数据直到 EOF
  while true {
    let payload = self.read_packet()
    let responses = channel.handle_inbound(payload)
    for resp in responses {
      self.write_packet(resp)
    }
    if channel.state() == EofReceived || channel.state() == Done {
      break
    }
  }

  // 4. 等待 CLOSE
  if channel.state() != Done {
    while true {
      let payload = self.read_packet()
      let responses = channel.handle_inbound(payload)
      for resp in responses {
        self.write_packet(resp)
      }
      if channel.state() == Done {
        break
      }
    }
  }

  (channel.take_stdout(), channel.take_stderr())
}

///|
pub fn Client::shell(self : Client, channel : Channel) -> Unit raise SshError {
  // 1. 打开通道
  let open_msg = build_channel_open(channel.id(), 1024 * 1024, 32 * 1024)
  self.write_packet(open_msg)
  while true {
    let payload = self.read_packet()
    let responses = channel.handle_inbound(payload)
    for resp in responses {
      self.write_packet(resp)
    }
    if channel.is_open() {
      break
    }
    if channel.state() == Done {
      raise ProtocolError("channel: failed to open")
    }
  }

  // 2. 发送 shell 请求
  let shell_msg = build_channel_request_shell(channel.peer_id())
  self.write_packet(shell_msg)
}

///|
pub fn Client::close(self : Client) -> Unit {
  match self.conn {
    Connected(conn) => conn.close()
  }
}

// ============== Internal packet I/O ==============

///|
/// Read an encrypted packet, skipping SSH_MSG_IGNORE(2), DEBUG(4), EXT_INFO(7).
fn Client::read_auth_packet(self : Client) -> Bytes raise SshError {
  while true {
    let payload = self.read_encrypted_packet()
    if payload.length() == 0 {
      raise ProtocolError("read_auth_packet: empty packet")
    }
    let msg_type = payload.unsafe_get(0).to_int()
    match msg_type {
      2 | 4 | 7 => () // IGNORE, DEBUG, EXT_INFO — skip
      1 => raise ProtocolError("auth: server sent SSH_MSG_DISCONNECT")
      _ => return payload
    }
  }
  abort("unreachable")
}

///|
fn Client::read_packet(self : Client) -> Bytes raise SshError {
  if self.encrypted {
    self.read_encrypted_packet()
  } else {
    self.read_plain_packet()
  }
}

///|
fn Client::write_packet(self : Client, payload : Bytes) -> Unit raise SshError {
  if self.encrypted {
    self.write_encrypted_packet(payload)
  } else {
    self.write_plain_packet(payload)
  }
}

///|
fn Client::read_plain_packet(self : Client) -> Bytes raise SshError {
  match self.conn {
    Connected(conn) => {
      let len_raw = conn.read_exact(4) catch {
        e => raise IoError("read packet len: \{e}")
      }
      let pkt_len = decode_uint32(len_raw)
      debug("read_plain: pkt_len=\{pkt_len}, seq_recv=\{self.seq_recv}")
      let body = conn.read_exact(pkt_len) catch {
        e => raise IoError("read packet body (expect \{pkt_len}): \{e}")
      }
      hex_dump("Plain packet", len_raw + body)
      self.seq_recv = self.seq_recv + 1U
      let pad_len = body.unsafe_get(0).to_int()
      let payload_end = body.length() - pad_len
      let msg_type = if payload_end > 1 {
        body.unsafe_get(1).to_int()
      } else {
        -1
      }
      debug(
        "read_plain: pad_len=\{pad_len} payload_end=\{payload_end} msg_type=\{msg_type}",
      )
      match Bytes::get_view(body, start=1, end=payload_end) {
        Some(v) => BytesView::to_owned(v)
        None => raise ProtocolError("read_plain packet: slice")
      }
    }
  }
}

///|
fn Client::write_plain_packet(
  self : Client,
  payload : Bytes,
) -> Unit raise SshError {
  let packet = write_packet(payload, 8, false, _data => b"")
  let msg_type = if payload.length() > 0 {
    payload.unsafe_get(0).to_int()
  } else {
    -1
  }
  debug("write_plain: type=\{msg_type} total_len=\{packet.length()}")
  hex_dump("Plain packet", packet)
  match self.conn {
    Connected(conn) =>
      conn.write_bytes(packet) catch {
        e => raise IoError("write packet: \{e}")
      }
  }
  self.seq_send = self.seq_send + 1U
}

///|
fn Client::install_encryption(
  self : Client,
  keys : DerivedKeys,
) -> Unit raise SshError {
  let enc_alg = parse_cipher_algorithm(self.kex.enc_alg)
  let mac_alg = parse_mac_algorithm(self.kex.mac_alg)

  debug(
    "* install_encryption: enc=\{self.kex.enc_alg}, mac=\{self.kex.mac_alg}",
  )
  hex_dump("  IV c2s", keys.iv_c2s)
  hex_dump("  IV s2c", keys.iv_s2c)
  hex_dump("  Enc key c2s", keys.enc_key_c2s)
  hex_dump("  Enc key s2c", keys.enc_key_s2c)
  hex_dump("  MAC key c2s", keys.mac_key_c2s)
  hex_dump("  MAC key s2c", keys.mac_key_s2c)

  let cipher_c2s = @crypto.Cipher::new(
    enc_alg,
    keys.enc_key_c2s,
    keys.iv_c2s,
    encrypt=true,
  ) catch {
    e => raise ProtocolError("install cipher: \{e}")
  }
  let cipher_s2c = @crypto.Cipher::new(
    enc_alg,
    keys.enc_key_s2c,
    keys.iv_s2c,
    encrypt=false,
  ) catch {
    e => raise ProtocolError("install cipher: \{e}")
  }
  self.cipher_c2s = Some(cipher_c2s)
  self.cipher_s2c = Some(cipher_s2c)

  // RFC 4253 §7.2: Key E = mac_key_c2s, Key F = mac_key_s2c
  let mac_c2s = @crypto.Mac::new(mac_alg, keys.mac_key_c2s)
  let mac_s2c = @crypto.Mac::new(mac_alg, keys.mac_key_s2c)
  self.mac_c2s = Some(mac_c2s)
  self.mac_s2c = Some(mac_s2c)

  self.encrypted = true
}

///|
fn parse_cipher_algorithm(
  name : String,
) -> @crypto.CipherAlgorithm raise SshError {
  match name {
    "aes128-ctr" => @crypto.CipherAlgorithm::aes128_ctr()
    _ => raise ProtocolError("unsupported cipher: \{name}")
  }
}

///|
fn parse_mac_algorithm(name : String) -> @crypto.MacAlgorithm raise SshError {
  match name {
    "hmac-sha1" => @crypto.MacAlgorithm::hmac_sha1()
    "hmac-sha2-256" => @crypto.MacAlgorithm::hmac_sha256()
    _ => raise ProtocolError("unsupported MAC: \{name}")
  }
}

///|
fn Client::read_encrypted_packet(self : Client) -> Bytes raise SshError {
  match self.conn {
    Connected(conn) => {
      let cipher = match self.cipher_s2c {
        Some(c) => c
        None => raise NotEncrypted
      }
      let mac_size = match self.mac_s2c {
        Some(m) => m.alg.output_len()
        None => 0
      }
      debug("* recv: HMAC Len=\{mac_size}, seq_recv=\{self.seq_recv}")

      // RFC 4253 §6.3: For stream ciphers (AES-CTR), the entire packet
      // including packet_length is encrypted. Read and decrypt 4 bytes
      // first to get the actual packet_length.
      let enc_len = conn.read_exact(4) catch {
        e => raise IoError("read pkt len: \{e}")
      }
      let len_bytes = cipher.update(enc_len) catch {
        e => raise ProtocolError("decrypt pkt len: \{e}")
      }
      let packet_length = decode_uint32(len_bytes)
      debug(
        "* read_packet: packet_length=\{packet_length}, mac_size=\{mac_size}",
      )
      if packet_length < 1 || packet_length > MAX_PACKET {
        raise ProtocolError("read_packet: bad length \{packet_length}")
      }

      // Read remaining: encrypted body + MAC
      let total = packet_length + mac_size
      debug("* read_packet: reading \{total} more bytes")
      let raw = conn.read_exact(total) catch {
        e => raise IoError("read pkt body: \{e}")
      }

      let full_packet = enc_len + raw
      hex_dump("Encr body + HMAC (\{full_packet.length()} bytes)", full_packet)

      // Split: encrypted body + MAC
      let enc_body = match Bytes::get_view(raw, start=0, end=packet_length) {
        Some(v) => BytesView::to_owned(v)
        None => raise ProtocolError("read_packet: body slice")
      }
      let mac_tag = if mac_size > 0 {
        match
          Bytes::get_view(
            raw,
            start=packet_length,
            end=packet_length + mac_size,
          ) {
          Some(v) => BytesView::to_owned(v)
          None => raise ProtocolError("read_packet: mac slice")
        }
      } else {
        b""
      }

      hex_dump("  body (encrypted, \{enc_body.length()} bytes)", enc_body)

      // Decrypt body
      let plaintext_body = cipher.update(enc_body) catch {
        e => raise ProtocolError("decrypt: \{e}")
      }
      hex_dump(
        "  body (decrypted, \{plaintext_body.length()} bytes)",
        plaintext_body,
      )

      // RFC 4253 §6.4: MAC is over seq || unencrypted_packet (plaintext)
      // unencrypted_packet includes the packet_length field
      if mac_size > 0 {
        let computed = compute_mac_s2c(self, len_bytes + plaintext_body)
        hex_dump(
          "  recv MAC input (seq || plen || body)",
          encode_uint32(self.seq_recv.reinterpret_as_int()) +
          len_bytes +
          plaintext_body,
        )
        hex_dump("  expected MAC", mac_tag)
        hex_dump("  computed MAC", computed)
        if computed != mac_tag {
          debug("* verify_mac: MAC mismatch")
          raise MacMismatch
        }
        debug("* verify_mac: MAC OK")
      }
      self.seq_recv = self.seq_recv + 1U

      if plaintext_body.length() < 1 {
        raise ProtocolError("read_packet: empty plaintext")
      }
      let padding_length = plaintext_body.unsafe_get(0).to_int()
      let payload_end = plaintext_body.length() - padding_length
      let msg_type_val = if payload_end > 1 {
        plaintext_body.unsafe_get(1).to_int()
      } else {
        -1
      }
      debug(
        "* read_packet: pad_len=\{padding_length} payload_end=\{payload_end} msg_type=\{msg_type_val}",
      )
      if 1 + padding_length > plaintext_body.length() {
        raise ProtocolError("read_packet: padding_length too large")
      }
      match
        Bytes::get_view(
          plaintext_body,
          start=1,
          end=plaintext_body.length() - padding_length,
        ) {
        Some(v) => BytesView::to_owned(v)
        None => raise ProtocolError("read_packet: payload slice")
      }
    }
  }
}

///|
fn Client::write_encrypted_packet(
  self : Client,
  payload : Bytes,
) -> Unit raise SshError {
  match self.conn {
    Connected(conn) => {
      let cipher = match self.cipher_c2s {
        Some(c) => c
        None => raise NotEncrypted
      }
      let mac_enabled = match self.mac_c2s {
        Some(_) => true
        None => false
      }
      let mac_size = if mac_enabled {
        match self.mac_c2s {
          Some(m) => m.alg.output_len()
          None => 0
        }
      } else {
        0
      }
      let block_size = @crypto.CipherAlgorithm::aes128_ctr().block_len()
      let msg_type_val = if payload.length() > 0 {
        payload.unsafe_get(0).to_int()
      } else {
        -1
      }
      debug(
        "* write_encr: msg_type=\{msg_type_val} HMAC Len=\{mac_size}, seq_send=\{self.seq_send}, block_size=\{block_size}",
      )

      let packet = write_packet(payload, block_size, mac_enabled, data => {
        if mac_enabled {
          compute_mac(self, data)
        } else {
          b""
        }
      })

      let body_len = packet.length() - mac_size
      // RFC 4253 §6.3: For stream ciphers (incl. AES-CTR), the entire
      // packet including packet_length is encrypted as part of the stream.
      let full_plain = match Bytes::get_view(packet, start=0, end=body_len) {
        Some(v) => BytesView::to_owned(v)
        None => raise ProtocolError("write: plain slice")
      }
      let mac = if mac_size > 0 {
        match Bytes::get_view(packet, start=body_len, end=packet.length()) {
          Some(v) => BytesView::to_owned(v)
          None => raise ProtocolError("write: mac slice")
        }
      } else {
        b""
      }

      hex_dump(
        "  packet plaintext (len=\{full_plain.length()}, body=\{full_plain.length() - 4})",
        full_plain,
      )
      let encrypted = cipher.update(full_plain) catch {
        e => raise ProtocolError("encrypt: \{e}")
      }
      let wire_data = encrypted + mac
      hex_dump("  packet on wire (\{wire_data.length()} bytes)", wire_data)
      conn.write_bytes(wire_data) catch {
        e => raise IoError("write: \{e}")
      }
      self.seq_send = self.seq_send + 1U
    }
  }
}

///|
/// Compute MAC with s2c key for verification, using seq_recv.
fn compute_mac_s2c(client : Client, data : Bytes) -> Bytes raise SshError {
  let mac_ctx = match client.mac_s2c {
    Some(m) => m
    None => return b""
  }
  let seq_bytes = encode_uint32(client.seq_recv.reinterpret_as_int())
  mac_ctx.hmac_on(seq_bytes + data) catch {
    e => raise ProtocolError("MAC compute s2c: \{e}")
  }
}

///|
fn compute_mac(client : Client, data : Bytes) -> Bytes raise SshError {
  let mac_ctx = match client.mac_c2s {
    Some(m) => m
    None => return b""
  }
  let seq_bytes = encode_uint32(client.seq_send.reinterpret_as_int())
  mac_ctx.update(seq_bytes)
  mac_ctx.update(data)
  let tag = mac_ctx.finalize() catch {
    e => raise ProtocolError("MAC compute: \{e}")
  }
  debug(
    "* compute_mac: seq_send=\{client.seq_send}, data_len=\{data.length()}, tag_len=\{tag.length()}",
  )
  hex_dump("  MAC input (seq || packet)", seq_bytes + data)
  hex_dump("  MAC tag", tag)
  tag
}

// ============== Helpers ==============

///|
fn build_signature_blob(alg : String, sig : Bytes) -> Bytes {
  let w = Writer::new()
  w.write_string_from_str(alg)
  w.write_string(sig)
  w.to_bytes()
}
