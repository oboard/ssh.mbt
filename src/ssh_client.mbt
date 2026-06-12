///
/// MoonSSH 顶层 API。
/// 组装 KEX / auth / channel 模块，提供完整 SSH 客户端。

///
pub struct ConnectOptions {
  host : String
  port : Int
  user : String
  client_banner : String?
  accept_host_key : (String, Bytes) -> Bool
  timeout_ms : Int
}

pub fn ConnectOptions::new(host : String, port : Int, user : String) -> ConnectOptions {
  { host, port, user, client_banner: None, accept_host_key: (_alg, _key) => true, timeout_ms: 30_000 }
}

pub fn ConnectOptions::with_host_key_verifier(self : ConnectOptions, f : (String, Bytes) -> Bool) -> ConnectOptions {
  { ..self, accept_host_key: f }
}

///
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

priv enum ClientConn { Connected(@socket.Tcp) }

pub fn Client::default_banner() -> String { "SSH-2.0-MoonSSH_0.1.0" }

///
/// 连接 SSH 服务器并完成 banner 交换。不执行 KEX 或认证。
pub fn Client::connect(opts : ConnectOptions) -> Client raise SshError {
  let conn = @socket.Tcp::connect_to_host(opts.host, port=opts.port) catch {
    e => raise IoError("connect: \{e}")
  }
  let client_banner = match opts.client_banner {
    Some(b) => b; None => Client::default_banner()
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
  let banner_line = banner_bytes.to_string()
  let v_c = @utf8.encode(client_banner)
  let v_s = @utf8.encode(banner_line)
  let kex = KexContext::new(v_c, v_s)
  let auth = AuthContext::new(opts.user)
  {
    conn: Connected(conn), kex, auth,
    accept_host_key: opts.accept_host_key,
    session_id: b"", next_channel_id: 0,
    encrypted: false, cipher_c2s: None, cipher_s2c: None,
    mac_c2s: None, mac_s2c: None, seq_send: 0U, seq_recv: 0U,
  }
}

///
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

///
/// 密码认证。
pub fn Client::auth_password(self : Client, password : String) -> Unit raise SshError {
  if self.kex.state != Done { raise ProtocolError("auth_password: KEX not complete") }
  if !self.encrypted { raise NotEncrypted }

  let service_req = build_service_request(SERVICE_USERAUTH)
  self.write_encrypted_packet(service_req)
  let reply1 = self.read_encrypted_packet()
  match parse_auth_reply(reply1) {
    ServiceAccept => ()
    _ => raise ProtocolError("auth: expected SERVICE_ACCEPT")
  }
  let auth_req = self.auth.build_password(password)
  self.write_encrypted_packet(auth_req)
  let reply2 = self.read_encrypted_packet()
  match parse_auth_reply(reply2) {
    Success => self.auth.apply_reply(Success)
    Failure(methods, _) => raise AuthFailed("methods: \{methods}")
    _ => raise ProtocolError("auth: unexpected reply")
  }
}

///
/// 公钥认证（two-step）。
pub fn Client::auth_publickey(self : Client, private_key_path : String) -> Unit raise SshError {
  if self.kex.state != Done { raise ProtocolError("auth_publickey: KEX not complete") }
  if !self.encrypted { raise NotEncrypted }

  // Step 0: 发送 SERVICE_REQUEST
  let service_req = build_service_request(SERVICE_USERAUTH)
  self.write_encrypted_packet(service_req)
  let reply0 = self.read_encrypted_packet()
  match parse_auth_reply(reply0) {
    ServiceAccept => ()
    _ => raise ProtocolError("auth: expected SERVICE_ACCEPT")
  }

  // 加载私钥
  let pkey = match @crypto.PKey::load_private_key(private_key_path) {
    Ok(pk) => pk
    Err(e) => raise ProtocolError("auth: load key: \{e.message()}")
  }
  defer pkey.close()

  // 从私钥获取公钥 blob（简化：使用 PEM 公钥文件或构造）
  // 对于 rsa-sha2-256，构造 public key blob
  let pubkey_alg = "rsa-sha2-256"
  // 加载对应的公钥
  let pubkey_path = private_key_path + ".pub"
  let pubkey_blob = read_pubkey_blob(pubkey_path) catch {
    _ => raise ProtocolError("auth: cannot read \{pubkey_path}")
  }

  // Step 1: 发送 publickey 查询（无签名）
  let query = self.auth.build_publickey_query(pubkey_alg, pubkey_blob)
  self.write_encrypted_packet(query)
  let reply1 = self.read_encrypted_packet()
  match parse_auth_reply(reply1) {
    PublicKeyOk(_alg, _blob) => ()
    Failure(methods, _) => raise AuthFailed("publickey rejected: methods \{methods}")
    _ => raise ProtocolError("auth: expected PK_OK")
  }

  // Step 2: 构建签名输入并签名
  let sig_input = build_publickey_signature_input(
    self.session_id, self.auth.user, "ssh-connection", pubkey_alg, pubkey_blob,
  )
  let signature = match pkey.sign(2, sig_input) { // 2 = SHA-256
    Ok(sig) => sig
    Err(e) => raise ProtocolError("auth: sign: \{e.message()}")
  }

  // 将签名打包为 SSH signature blob (alg || sig)
  let sig_blob = build_signature_blob(pubkey_alg, signature)

  // Step 3: 发送带签名的 publickey 请求
  let sign_req = self.auth.build_publickey_sign(pubkey_alg, pubkey_blob, sig_blob)
  self.write_encrypted_packet(sign_req)
  let reply2 = self.read_encrypted_packet()
  match parse_auth_reply(reply2) {
    Success => self.auth.apply_reply(Success)
    _ => raise AuthFailed("publickey sign: authentication rejected")
  }
}

///
/// keyboard-interactive 认证。
pub fn Client::auth_keyboard_interactive(self : Client, answer_fn : (String) -> String) -> Unit raise SshError {
  if self.kex.state != Done { raise ProtocolError("auth_kbdint: KEX not complete") }
  if !self.encrypted { raise NotEncrypted }

  let service_req = build_service_request(SERVICE_USERAUTH)
  self.write_encrypted_packet(service_req)
  let reply0 = self.read_encrypted_packet()
  match parse_auth_reply(reply0) {
    ServiceAccept => ()
    _ => raise ProtocolError("auth: expected SERVICE_ACCEPT")
  }

  let kbd_req = self.auth.build_keyboard_interactive()
  self.write_encrypted_packet(kbd_req)

  while true {
    let reply = self.read_encrypted_packet()
    match parse_auth_reply(reply) {
      Success => { self.auth.apply_reply(Success); return }
      Failure(methods, _) => raise AuthFailed("kbd-int rejected: methods \{methods}")
      _ => {
        // 收到 INFO_REQUEST
        let responses = [answer_fn("Password: ")]
        let resp_payload = self.auth.build_info_response(responses)
        self.write_encrypted_packet(resp_payload)
      }
    }
  }
}

///
/// 自动回退认证（none → publickey → password）。
pub fn Client::auth_auto(self : Client, password : String, key_path? : String) -> Unit raise SshError {
  if self.kex.state != Done { raise ProtocolError("auth_auto: KEX not complete") }
  if !self.encrypted { raise NotEncrypted }

  // 1. SERVICE_REQUEST
  let service_req = build_service_request(SERVICE_USERAUTH)
  self.write_encrypted_packet(service_req)
  let reply0 = self.read_encrypted_packet()
  match parse_auth_reply(reply0) {
    ServiceAccept => ()
    _ => raise ProtocolError("auth: expected SERVICE_ACCEPT")
  }

  // 2. none 探测
  let none_req = self.auth.build_initial()
  self.write_encrypted_packet(none_req)
  let reply1 = self.read_encrypted_packet()
  match parse_auth_reply(reply1) {
    Success => { self.auth.apply_reply(Success); return }
    Failure(methods, _) => {
      // 3. 尝试公钥
      let key_path_val = key_path.unwrap_or("~/.ssh/id_rsa")
      if methods.contains(method_publickey()) {
        try {
          self.auth_publickey(key_path_val)
          return
        } catch { AuthFailed(_) => () }
      }
      // 4. 尝试键盘交互
      if methods.contains(method_keyboard_interactive()) {
        try {
          self.auth_keyboard_interactive(_prompt => password)
          return
        } catch { AuthFailed(_) => () }
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

pub fn Client::open_session(self : Client) -> Channel {
  let id = self.next_channel_id
  self.next_channel_id = self.next_channel_id + 1
  Channel::new(id)
}

pub fn Client::exec(self : Client, channel : Channel, command : String) -> String raise SshError {
  // 1. 打开通道
  let open_msg = build_channel_open(channel.id(), 1024 * 1024, 32 * 1024)
  self.write_packet(open_msg)
  while true {
    let payload = self.read_packet()
    let responses = channel.handle_inbound(payload)
    for resp in responses { self.write_packet(resp) }
    if channel.is_open() { break }
    if channel.state() == Done { raise ProtocolError("channel: failed to open") }
  }

  // 2. 发送 exec 请求
  let exec_msg = build_channel_request_exec(channel.peer_id(), command)
  self.write_packet(exec_msg)

  // 3. 读取数据直到 EOF
  while true {
    let payload = self.read_packet()
    let responses = channel.handle_inbound(payload)
    for resp in responses { self.write_packet(resp) }
    if channel.state() == EofReceived || channel.state() == Done { break }
  }

  // 4. 等待 CLOSE
  if channel.state() != Done {
    while true {
      let payload = self.read_packet()
      let responses = channel.handle_inbound(payload)
      for resp in responses { self.write_packet(resp) }
      if channel.state() == Done { break }
    }
  }

  channel.take_stdout()
}

pub fn Client::shell(self : Client, channel : Channel) -> Unit raise SshError {
  // 1. 打开通道
  let open_msg = build_channel_open(channel.id(), 1024 * 1024, 32 * 1024)
  self.write_packet(open_msg)
  while true {
    let payload = self.read_packet()
    let responses = channel.handle_inbound(payload)
    for resp in responses { self.write_packet(resp) }
    if channel.is_open() { break }
    if channel.state() == Done { raise ProtocolError("channel: failed to open") }
  }

  // 2. 发送 shell 请求
  let shell_msg = build_channel_request_shell(channel.peer_id())
  self.write_packet(shell_msg)
}

pub fn Client::close(self : Client) -> Unit {
  match self.conn {
    Connected(conn) => conn.close()
  }
}

// ============== Internal packet I/O ==============

fn Client::read_packet(self : Client) -> Bytes raise SshError {
  if self.encrypted { self.read_encrypted_packet() }
  else { self.read_plain_packet() }
}

fn Client::write_packet(self : Client, payload : Bytes) -> Unit raise SshError {
  if self.encrypted { self.write_encrypted_packet(payload) }
  else { self.write_plain_packet(payload) }
}

fn Client::read_plain_packet(self : Client) -> Bytes raise SshError {
  match self.conn {
    Connected(conn) => {
      let len_raw = conn.read_exact(4) catch { e => raise IoError("read packet: \{e}") }
      let pkt_len = decode_uint32(len_raw)
      let body = conn.read_exact(pkt_len) catch { e => raise IoError("read packet: body: \{e}") }
      let pad_len = body.unsafe_get(0).to_int()
      let payload_end = body.length() - pad_len
      match Bytes::get_view(body, start=1, end=payload_end) {
        Some(v) => BytesView::to_owned(v)
        None => raise ProtocolError("read_plain packet: slice")
      }
    }
  }
}

fn Client::write_plain_packet(self : Client, payload : Bytes) -> Unit raise SshError {
  let packet = write_packet(payload, 8, false, _data => b"")
  match self.conn {
    Connected(conn) => conn.write_bytes(packet) catch { e => raise IoError("write packet: \{e}") }
  }
}

fn Client::install_encryption(self : Client, keys : DerivedKeys) -> Unit raise SshError {
  let enc_alg = parse_cipher_algorithm(self.kex.enc_alg)
  let mac_alg = parse_mac_algorithm(self.kex.mac_alg)

  let cipher_c2s = @crypto.Cipher::new(enc_alg, keys.enc_key_c2s, keys.iv_c2s, encrypt=true) catch {
    e => raise ProtocolError("install cipher: \{e.message()}")
  }
  let cipher_s2c = @crypto.Cipher::new(enc_alg, keys.enc_key_s2c, keys.iv_s2c, encrypt=false) catch {
    e => raise ProtocolError("install cipher: \{e.message()}")
  }
  self.cipher_c2s = Some(cipher_c2s)
  self.cipher_s2c = Some(cipher_s2c)

  let mac_c2s = @crypto.Mac::new(mac_alg, keys.mac_key_c2s)
  let mac_s2c = @crypto.Mac::new(mac_alg, keys.mac_key_s2c)
  self.mac_c2s = Some(mac_c2s)
  self.mac_s2c = Some(mac_s2c)

  self.encrypted = true
  self.seq_send = 0U
  self.seq_recv = 0U
}

fn parse_cipher_algorithm(name : String) -> @crypto.CipherAlgorithm raise SshError {
  match name {
    "aes128-ctr" => @crypto.CipherAlgorithm::aes128_ctr()
    _ => raise ProtocolError("unsupported cipher: \{name}")
  }
}

fn parse_mac_algorithm(name : String) -> @crypto.MacAlgorithm raise SshError {
  match name {
    "hmac-sha1" => @crypto.MacAlgorithm::hmac_sha1()
    "hmac-sha2-256" => @crypto.MacAlgorithm::hmac_sha256()
    _ => raise ProtocolError("unsupported MAC: \{name}")
  }
}

fn Client::read_encrypted_packet(self : Client) -> Bytes raise SshError {
  match self.conn {
    Connected(conn) => {
      let cipher = match self.cipher_s2c { Some(c) => c; None => raise NotEncrypted }
      let mac_size = match self.mac_s2c { Some(m) => m.alg.output_len(); None => 0 }

      read_packet(
        size => { conn.read_exact(size) catch { e => raise IoError("read: \{e}") } },
        @crypto.CipherAlgorithm::aes128_ctr().block_len(),
        mac_size,
        body => { cipher.update(body) catch { e => raise ProtocolError("decrypt: \{e.message()}") } },
        (data, mac_tag) => {
          if mac_size > 0 { verify_mac(self, data, mac_tag) }
        },
      )
    }
  }
}

fn Client::write_encrypted_packet(self : Client, payload : Bytes) -> Unit raise SshError {
  match self.conn {
    Connected(conn) => {
      let cipher = match self.cipher_c2s { Some(c) => c; None => raise NotEncrypted }
      let mac_enabled = match self.mac_c2s { Some(_) => true; None => false }
      let block_size = @crypto.CipherAlgorithm::aes128_ctr().block_len()

      let packet = write_packet(payload, block_size, mac_enabled, data => {
        if mac_enabled { compute_mac(self, data) } else { b"" }
      })

      let mac_size = if mac_enabled { match self.mac_c2s { Some(m) => m.alg.output_len(); None => 0 } } else { 0 }
      let body_len = packet.length() - mac_size
      let body = match Bytes::get_view(packet, start=0, end=body_len) {
        Some(v) => BytesView::to_owned(v)
        None => raise ProtocolError("write: body slice")
      }
      let mac = if mac_size > 0 {
        match Bytes::get_view(packet, start=body_len, end=packet.length()) {
          Some(v) => BytesView::to_owned(v)
          None => raise ProtocolError("write: mac slice")
        }
      } else { b"" }

      let encrypted_body = cipher.update(body) catch { e => raise ProtocolError("encrypt: \{e.message()}") }
      conn.write_bytes(encrypted_body + mac) catch { e => raise IoError("write: \{e}") }
      self.seq_send = self.seq_send + 1U
    }
  }
}

fn verify_mac(client : Client, data : Bytes, expected_tag : Bytes) -> Unit raise SshError {
  let mac_ctx = match client.mac_s2c { Some(m) => m; None => return }
  let seq_bytes = encode_uint32(client.seq_recv.reinterpret_as_int())
  mac_ctx.update(seq_bytes)
  mac_ctx.update(data)
  let computed = mac_ctx.finalize() catch { e => raise ProtocolError("MAC: \{e.message()}") }
  if computed != expected_tag { raise MacMismatch }
  client.seq_recv = client.seq_recv + 1U
}

fn compute_mac(client : Client, data : Bytes) -> Bytes raise SshError {
  let mac_ctx = match client.mac_c2s { Some(m) => m; None => return b"" }
  let seq_bytes = encode_uint32(client.seq_send.reinterpret_as_int())
  mac_ctx.update(seq_bytes)
  mac_ctx.update(data)
  mac_ctx.finalize() catch { e => raise ProtocolError("MAC compute: \{e.message()}") }
}

// ============== Helpers ==============

fn read_pubkey_blob(path : String) -> Bytes raise SshError {
  raise ProtocolError("pubkey file reading not available")
}

fn build_signature_blob(alg : String, sig : Bytes) -> Bytes {
  let w = Writer::new()
  w.write_string_from_str(alg)
  w.write_string(sig)
  w.to_bytes()
}
