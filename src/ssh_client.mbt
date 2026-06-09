///|
/// MoonSSH 顶层 API。
///
/// 典型使用方式：
///   let conn = @async.TCP::connect(host, port)
///   let client = Client::new(conn)
///   let banner = client.read_server_banner()
///   client.send_client_banner()
///   client.kex()
///   client.auth_password("alice", "hunter2")
///   let ch = client.open_session()
///   let output = client.exec(ch, "ls -l")
///
/// 详细字段：
///   - `host_key_verifier`: 接收 (alg, key_bytes) 并允许/拒绝。
///   - `first_kex_follows_follows`: KEXINIT 标志位。
///   - 实际传输由底层的 `@async.TCP` 提供。

///|
/// Connect options.
pub struct ConnectOptions {
  host : String
  port : Int
  user : String
  /// If set, override the default banner. Otherwise we send
  /// `SSH-2.0-MoonSSH_0.1.0`.
  client_banner : String?
  /// Host key verifier (returns true to accept, false to reject).
  accept_host_key : (String, Bytes) -> Bool
  /// Connect timeout in milliseconds (0 = no timeout).
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
pub fn ConnectOptions::with_banner(
  self : ConnectOptions,
  banner : String,
) -> ConnectOptions {
  { ..self, client_banner: Some(banner) }
}

///|
/// Top-level client handle. Owns the connection state.
pub struct Client {
  priv conn : ClientConn
  priv banner_client : String
  priv banner_server : String
  priv kex : KexContext
  priv auth : AuthContext
  priv accept_host_key : (String, Bytes) -> Bool
  priv mut session_id : Bytes
  mut next_channel_id : Int
  // Encryption state (set after KEX)
  priv mut encrypted : Bool
  priv mut enc_alg : @crypto.CipherAlgorithm?
  priv mut mac_alg : @crypto.MacAlgorithm?
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
/// Connect to an SSH server and complete the banner exchange.
/// Does NOT yet run KEX or auth; call `kex` and `auth_*` afterwards.
pub fn Client::connect(opts : ConnectOptions) -> Client raise SshError {
  let conn = @socket.Tcp::connect_to_host(opts.host, port=opts.port) catch {
    e => raise IoError("connect: \{e}")
  }
  let client_banner = match opts.client_banner {
    Some(b) => b
    None => Client::default_banner()
  }
  // Send client banner (line ending with \r\n)
  conn.write("\{client_banner}\r\n") catch {
    e => raise IoError("write banner: \{e}")
  }
  // Read server banner
  let banner_line = read_line(conn) catch {
    e => raise IoError("read banner: \{e}")
  }
  if not(banner_line.has_prefix("SSH-")) {
    raise ProtocolError("server banner missing SSH- prefix: \{banner_line}")
  }
  let v_c = @utf8.encode(client_banner)
  let v_s = @utf8.encode(banner_line)
  let kex = KexContext::new(v_c, v_s)
  let auth = AuthContext::new(opts.user)
  {
    conn: Connected(conn),
    banner_client: client_banner,
    banner_server: banner_line,
    kex,
    auth,
    accept_host_key: opts.accept_host_key,
    session_id: b"",
    next_channel_id: 0,
    encrypted: false,
    enc_alg: None,
    mac_alg: None,
    cipher_c2s: None,
    cipher_s2c: None,
    mac_c2s: None,
    mac_s2c: None,
    seq_send: 0U,
    seq_recv: 0U,
  }
}

///|
/// Run the SSH key exchange (KEXINIT / KEXDH / NEWKEYS).
/// After successful KEX, installs encryption on the transport.
pub fn Client::kex(self : Client) -> Unit raise SshError {
  self.kex.drive(
    () => self.read_plain_packet(),
    payload => self.write_plain_packet(payload),
    self.accept_host_key,
  )
  self.session_id = self.kex.session_id

  // Derive and install encryption
  let keys = self.kex.derive_session_keys()
  self.install_encryption(keys)
}

///|
/// Authenticate with a password.
pub fn Client::auth_password(
  self : Client,
  password : String,
) -> Unit raise SshError {
  if self.kex.state != Done {
    raise ProtocolError("auth_password: key exchange is not complete")
  }
  if !self.encrypted {
    raise NotEncrypted
  }

  // Send SSH_MSG_SERVICE_REQUEST for "ssh-userauth"
  let service_req = build_service_request(SERVICE_USERAUTH)
  self.write_encrypted_packet(service_req)

  // Read SSH_MSG_SERVICE_ACCEPT
  let reply1 = self.read_encrypted_packet()
  let service_reply = parse_auth_reply(reply1)
  match service_reply {
    ServiceAccept => ()
    _ => raise ProtocolError("auth: expected SERVICE_ACCEPT")
  }

  // Send password authentication request
  let auth_req = self.auth.build_password(password)
  self.write_encrypted_packet(auth_req)

  // Read authentication result
  let reply2 = self.read_encrypted_packet()
  let auth_reply = parse_auth_reply(reply2)
  match auth_reply {
    Success => self.auth.apply_reply(auth_reply)
    Failure(methods, _) => raise AuthFailed("methods: \{methods}")
    _ => raise ProtocolError("auth: unexpected reply")
  }
}

///|
/// Authenticate with a public key.
pub fn Client::auth_publickey(
  self : Client,
  _key : Bytes,
  _signature : Bytes,
) -> Unit raise SshError {
  if self.kex.state != Done {
    raise ProtocolError("auth_publickey: key exchange is not complete")
  }
  raise NotEncrypted
}

///|
/// Open a new session channel.
pub fn Client::open_session(self : Client) -> Channel {
  let id = self.next_channel_id
  self.next_channel_id = self.next_channel_id + 1
  Channel::new(id, self.session_id)
}

///|
/// Send an `exec` request and read the resulting stdout / exit-status.
/// v0.1: stub — needs the full transport + channel pump.
pub fn Client::exec(
  self : Client,
  channel : Channel,
  command : String,
) -> String raise SshError {
  // 1. Open channel
  let open_msg = build_channel_open(channel.id(), 1024 * 1024, 32 * 1024)
  self.write_packet(open_msg)

  // Wait for CHANNEL_OPEN_CONFIRMATION
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

  // 2. Send exec request
  let exec_msg = build_channel_request_exec(channel.peer_id, command)
  self.write_packet(exec_msg)

  // 3. Read data until EOF
  while true {
    let payload = self.read_packet()
    let responses = channel.handle_inbound(payload)
    for resp in responses {
      self.write_packet(resp)
    }

    // Check if we've reached EOF
    if channel.state() == EofReceived || channel.state() == Done {
      break
    }
  }

  // 4. Wait for CLOSE and send our CLOSE
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

  // Return stdout
  channel.take_stdout()
}

///|
/// Close the SSH connection cleanly (sends DISCONNECT if possible).
pub fn Client::close(self : Client) -> Unit {
  match self.conn {
    Connected(conn) => conn.close()
  }
}

// --- Internal helpers -----------------------------------------------

///|
/// Read a packet (automatically uses encrypted or plain based on state).
fn Client::read_packet(self : Client) -> Bytes raise SshError {
  if self.encrypted {
    self.read_encrypted_packet()
  } else {
    self.read_plain_packet()
  }
}

///|
/// Write a packet (automatically uses encrypted or plain based on state).
fn Client::write_packet(self : Client, payload : Bytes) -> Unit raise SshError {
  if self.encrypted {
    self.write_encrypted_packet(payload)
  } else {
    self.write_plain_packet(payload)
  }
}

///|
fn read_line(conn : @socket.Tcp) -> String raise SshError {
  let line = conn.read_line() catch { e => raise IoError("read_line: \{e}") }
  strip_line_ending(line)
}

///|
fn Client::read_plain_packet(self : Client) -> Bytes raise SshError {
  match self.conn {
    Connected(conn) =>
      read_packet(
        size => {
          conn.read_exact(size) catch {
            e => raise IoError("read packet: \{e}")
          }
        },
        8,
        0,
        body => body,
        (_data, _mac) => (),
      )
  }
}

///|
fn Client::write_plain_packet(
  self : Client,
  payload : Bytes,
) -> Unit raise SshError {
  let packet = write_packet(payload, 8, false, _data => b"")
  match self.conn {
    Connected(conn) =>
      conn.write_bytes(packet) catch {
        e => raise IoError("write packet: \{e}")
      }
  }
}

///|
fn strip_line_ending(line : String) -> String {
  let arr = line.to_array()
  let mut end = arr.length()
  while end > 0 &&
        (arr.unsafe_get(end - 1) == '\n' || arr.unsafe_get(end - 1) == '\r') {
    end = end - 1
  }
  let sb = StringBuilder::new()
  for i in 0..<end {
    sb.write_char(arr.unsafe_get(i))
  }
  sb.to_string()
}

// --- Encryption support ---------------------------------------------

///|
/// Install encryption after successful KEX.
fn Client::install_encryption(
  self : Client,
  keys : DerivedKeys,
) -> Unit raise SshError {
  let enc_alg = parse_cipher_algorithm(self.kex.enc_alg)
  let mac_alg = parse_mac_algorithm(self.kex.mac_alg)

  // Create cipher contexts
  let cipher_c2s = @crypto.Cipher::new(
    enc_alg,
    keys.enc_key_c2s,
    keys.iv_c2s,
    encrypt=true,
  ) catch {
    e => raise ProtocolError("install cipher c2s: \{e.message()}")
  }

  let cipher_s2c = @crypto.Cipher::new(
    enc_alg,
    keys.enc_key_s2c,
    keys.iv_s2c,
    encrypt=false,
  ) catch {
    e => raise ProtocolError("install cipher s2c: \{e.message()}")
  }

  self.enc_alg = Some(enc_alg)
  self.mac_alg = Some(mac_alg)
  self.cipher_c2s = Some(cipher_c2s)
  self.cipher_s2c = Some(cipher_s2c)

  // Create MAC contexts if not AEAD
  if !enc_alg.is_aead() {
    let mac_c2s = @crypto.Mac::new(mac_alg, keys.mac_key_c2s)
    let mac_s2c = @crypto.Mac::new(mac_alg, keys.mac_key_s2c)
    self.mac_c2s = Some(mac_c2s)
    self.mac_s2c = Some(mac_s2c)
  }

  self.encrypted = true
  self.seq_send = 0U
  self.seq_recv = 0U
}

///|
fn parse_cipher_algorithm(
  name : String,
) -> @crypto.CipherAlgorithm raise SshError {
  match name {
    "aes128-ctr" => @crypto.CipherAlgorithm::aes128_ctr()
    "aes192-ctr" => @crypto.CipherAlgorithm::aes192_ctr()
    "aes256-ctr" => @crypto.CipherAlgorithm::aes256_ctr()
    "aes128-gcm@openssh.com" => @crypto.CipherAlgorithm::aes128_gcm()
    "aes256-gcm@openssh.com" => @crypto.CipherAlgorithm::aes256_gcm()
    "chacha20-poly1305@openssh.com" =>
      @crypto.CipherAlgorithm::chacha20_poly1305()
    _ => raise ProtocolError("unsupported cipher algorithm: \{name}")
  }
}

///|
fn parse_mac_algorithm(name : String) -> @crypto.MacAlgorithm raise SshError {
  match name {
    "hmac-sha1" => @crypto.MacAlgorithm::hmac_sha1()
    "hmac-sha2-256" => @crypto.MacAlgorithm::hmac_sha256()
    "hmac-sha2-384" => @crypto.MacAlgorithm::hmac_sha384()
    "hmac-sha2-512" => @crypto.MacAlgorithm::hmac_sha512()
    _ => raise ProtocolError("unsupported MAC algorithm: \{name}")
  }
}

///|
/// Read an encrypted packet from the connection.
fn Client::read_encrypted_packet(self : Client) -> Bytes raise SshError {
  match self.conn {
    Connected(conn) => {
      let cipher = match self.cipher_s2c {
        Some(c) => c
        None => raise NotEncrypted
      }

      let enc_alg = match self.enc_alg {
        Some(a) => a
        None => raise NotEncrypted
      }

      let mac_size = if enc_alg.is_aead() {
        0
      } else {
        match self.mac_alg {
          Some(a) => a.output_len()
          None => 0
        }
      }

      read_packet(
        size => {
          conn.read_exact(size) catch {
            e => raise IoError("read packet: \{e}")
          }
        },
        enc_alg.block_len(),
        mac_size,
        body => {
          cipher.update(body) catch {
            e => raise ProtocolError("decrypt failed: \{e.message()}")
          }
        },
        (data, mac_tag) => {
          if mac_size > 0 {
            verify_mac_etm(self, data, mac_tag)
          }
        },
      )
    }
  }
}

///|
/// Verify MAC for encrypt-then-MAC mode.
fn verify_mac_etm(
  client : Client,
  data : Bytes,
  expected_tag : Bytes,
) -> Unit raise SshError {
  let mac_ctx = match client.mac_s2c {
    Some(m) => m
    None => return
  }

  // MAC is computed over: uint32(seq) || packet_data
  let seq_bytes = encode_uint32(client.seq_recv.reinterpret_as_int())
  mac_ctx.update(seq_bytes)
  mac_ctx.update(data)

  let computed = mac_ctx.finalize() catch {
    e => raise ProtocolError("MAC computation failed: \{e.message()}")
  }

  if computed != expected_tag {
    raise MacMismatch
  }

  client.seq_recv = client.seq_recv + 1U
}

///|
/// Write an encrypted packet to the connection.
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

      let enc_alg = match self.enc_alg {
        Some(a) => a
        None => raise NotEncrypted
      }

      let mac_enabled = !enc_alg.is_aead()
      let block_size = enc_alg.block_len()

      let packet = write_packet(payload, block_size, mac_enabled, data => {
        if mac_enabled {
          compute_mac_etm(self, data)
        } else {
          b""
        }
      })

      // Encrypt the body (excluding MAC)
      let mac_size = if mac_enabled {
        match self.mac_alg {
          Some(a) => a.output_len()
          None => 0
        }
      } else {
        0
      }

      let body_len = packet.length() - mac_size
      let body = match Bytes::get_view(packet, start=0, end=body_len) {
        Some(v) => BytesView::to_owned(v)
        None => raise ProtocolError("write packet: body slice failed")
      }

      let mac = if mac_size > 0 {
        match Bytes::get_view(packet, start=body_len, end=packet.length()) {
          Some(v) => BytesView::to_owned(v)
          None => raise ProtocolError("write packet: mac slice failed")
        }
      } else {
        b""
      }

      let encrypted_body = cipher.update(body) catch {
        e => raise ProtocolError("encrypt failed: \{e.message()}")
      }

      conn.write_bytes(encrypted_body + mac) catch {
        e => raise IoError("write packet: \{e}")
      }

      self.seq_send = self.seq_send + 1U
    }
  }
}

///|
/// Compute MAC for encrypt-then-MAC mode.
fn compute_mac_etm(client : Client, data : Bytes) -> Bytes raise SshError {
  let mac_ctx = match client.mac_c2s {
    Some(m) => m
    None => return b""
  }

  // MAC is computed over: uint32(seq) || packet_data
  let seq_bytes = encode_uint32(client.seq_send.reinterpret_as_int())
  mac_ctx.update(seq_bytes)
  mac_ctx.update(data)

  mac_ctx.finalize() catch {
    e => raise ProtocolError("MAC computation failed: \{e.message()}")
  }
}
