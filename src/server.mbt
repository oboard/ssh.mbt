///
/// SSH 服务端握手与配置（RFC 4253 §4-10, RFC 4252, RFC 4254）。
///
/// 实现：
///   - ServerConfig：主机密钥、banner、auth 尝试限制
///   - ServerConn：接受客户端连接、执行服务端 KEX、发送/验证 host-key 签名
///   - none/password/publickey auth 回调接口
///   - session channel request handler helpers

// ==================== Auth callbacks ====================

///|
/// 服务端口令认证回调：接受用户名和口令，返回是否通过。
pub struct PasswordAuthFn {
  call : (String, String) -> Bool
}

///|
/// 服务端公钥认证回调：接受用户名和公钥 blob，返回是否接受该公钥。
pub struct PublicKeyAuthFn {
  call : (String, Bytes) -> Bool
}

// ==================== Server Config ====================

///|
/// 服务端配置。
pub struct ServerConfig {
  /// 主机私钥列表（至少一个）。
  host_keys : Array[@crypto.PKey]
  /// 服务端版本字符串。
  version : String
  /// 欢迎 banner（可选）。
  banner : String?
  /// 最大认证尝试次数（默认 6）。
  max_auth_tries : Int
  /// 口令认证回调（为 None 则禁用）。
  password_auth : PasswordAuthFn?
  /// 公钥认证回调（为 None 则禁用）。
  publickey_auth : PublicKeyAuthFn?
  /// 是否允许 none 认证（默认 false）。
  allow_none_auth : Bool
}

///|
pub fn ServerConfig::new(host_keys : Array[@crypto.PKey]) -> ServerConfig {
  {
    host_keys,
    version: "SSH-2.0-MoonBitSSH_0.1.0",
    banner: None,
    max_auth_tries: 6,
    password_auth: None,
    publickey_auth: None,
    allow_none_auth: false,
  }
}

///|
pub fn ServerConfig::with_banner(
  self : ServerConfig,
  banner : String,
) -> ServerConfig {
  { ..self, banner: Some(banner) }
}

///|
pub fn ServerConfig::with_max_auth_tries(
  self : ServerConfig,
  n : Int,
) -> ServerConfig {
  { ..self, max_auth_tries: n }
}

///|
pub fn ServerConfig::with_password_auth(
  self : ServerConfig,
  f : PasswordAuthFn,
) -> ServerConfig {
  { ..self, password_auth: Some(f) }
}

///|
pub fn ServerConfig::with_publickey_auth(
  self : ServerConfig,
  f : PublicKeyAuthFn,
) -> ServerConfig {
  { ..self, publickey_auth: Some(f) }
}

///|
pub fn ServerConfig::with_allow_none(self : ServerConfig) -> ServerConfig {
  { ..self, allow_none_auth: true }
}

// ==================== Permissions ====================

///|
pub struct Permissions {
  allowed_channel_types : Array[String]?
  extensions : Map[String, Bytes]
}

///|
pub fn Permissions::allow_all() -> Permissions {
  { allowed_channel_types: None, extensions: {} }
}

// ==================== Server connection ====================

///|
pub struct ServerConn {
  sock : @socket.Tcp
  config : ServerConfig
  mut session_id : Bytes
  mut authed_user : String?
  mut auth_tries : Int
}

///|
pub fn ServerConn::new(
  sock : @socket.Tcp,
  config : ServerConfig,
) -> ServerConn {
  { sock, config, session_id: b"", authed_user: None, auth_tries: 0 }
}

///|
pub fn ServerConn::authed_user(self : ServerConn) -> String? {
  self.authed_user
}

// ==================== Handshake ====================

///|
/// 执行服务端 SSH 握手（版本交换 + KEX + 用户认证）。
pub async fn ServerConn::handshake(
  self : ServerConn,
) -> ServerCrypto raise SshError {
  // 1. Version exchange
  let client_version = do_server_version_exchange(
    self.sock,
    self.config.version,
  )
  // 2. Algorithm negotiation + KEX (server side)
  let ctx = do_server_kex(
    self.sock,
    self.config.host_keys,
    client_version,
    self.config.version,
  )
  self.session_id = ctx.session_id
  // 3. Send banner if configured
  match self.config.banner {
    Some(b) => {
      let payload = build_banner(b)
      self.sock.write_bytes(server_frame_packet(payload))
    }
    None => ()
  }
  // 4. Service request/accept
  let svc_len_buf = self.sock.read_exact(4)
  let pkt_len = decode_uint32(svc_len_buf)
  let _ = self.sock.read_exact(pkt_len)
  let svc_accept = build_service_accept("ssh-userauth")
  self.sock.write_bytes(server_frame_packet(svc_accept))
  // 5. Auth loop
  let perms = self.do_auth_loop()
  let _ = perms
  ctx
}

///|
async fn ServerConn::do_auth_loop(
  self : ServerConn,
) -> Permissions raise SshError {
  while true {
    let payload = server_read_packet(self.sock)
    if payload.length() == 0 {
      raise ProtocolError("server: empty auth payload")
    }
    let msg = payload.unsafe_get(0)
    if msg.to_int() != 50 {
      raise ProtocolError(
        "server: expected USERAUTH_REQUEST got \{msg.to_int()}",
      )
    }
    let r = Reader::new(payload)
    let _ = r.read_byte()
    let user = r.read_string_as_str()
    let _ = r.read_string_as_str()
    let method = r.read_string_as_str()
    let accepted = match method {
      "none" => self.config.allow_none_auth
      "password" => {
        let _ = r.read_byte()
        let pwd = r.read_string_as_str()
        match self.config.password_auth {
          Some(f) => (f.call)(user, pwd)
          None => false
        }
      }
      "publickey" => {
        let has_sig = r.read_byte() != b'\x00'
        let alg = r.read_string_as_str()
        let blob = r.read_string()
        if has_sig {
          let sig_blob = r.read_string()
          let accepted_key = match self.config.publickey_auth {
            Some(f) => (f.call)(user, blob)
            None => false
          }
          if accepted_key {
            let tbs = build_publickey_signature_input(
              self.session_id,
              user,
              "ssh-connection",
              alg,
              blob,
            )
            verify_pubkey_sig(blob, alg, tbs, sig_blob)
          } else {
            false
          }
        } else {
          let ok = match self.config.publickey_auth {
            Some(f) => (f.call)(user, blob)
            None => false
          }
          if ok {
            let pk_ok = build_pk_ok(alg, blob)
            self.sock.write_bytes(server_frame_packet(pk_ok))
          }
          continue
        }
      }
      _ => false
    }
    if accepted {
      self.authed_user = Some(user)
      let success = b"\x34"
      self.sock.write_bytes(server_frame_packet(success))
      return Permissions::allow_all()
    } else {
      self.auth_tries = self.auth_tries + 1
      if self.auth_tries >= self.config.max_auth_tries {
        raise ProtocolError("server: max auth tries exceeded")
      }
      let methods = server_allowed_auth_methods(self.config)
      let failure = build_userauth_failure(methods, false)
      self.sock.write_bytes(server_frame_packet(failure))
    }
  }
  raise ProtocolError("server: auth loop exited unexpectedly")
}

///|
fn server_allowed_auth_methods(config : ServerConfig) -> Array[String] {
  let methods : Array[String] = []
  if config.allow_none_auth {
    methods.push("none")
  }
  if config.password_auth is Some(_) {
    methods.push("password")
  }
  if config.publickey_auth is Some(_) {
    methods.push("publickey")
  }
  methods
}

// ==================== Session channel request helpers ====================

///|
pub enum ServerChannelRequest {
  Exec(String)
  Shell
  Subsystem(String)
  PtyReq(PtyParams)
  Env(String, String)
  WindowChange(Int, Int, Int, Int)
  Signal(String)
  ExitStatus(Int)
  ExitSignal(String, Bool, String, String)
  Unknown(String)
} derive(Debug)

///|
pub struct PtyParams {
  pub term : String
  pub cols : Int
  pub rows : Int
  pub width : Int
  pub height : Int
  pub modes : Bytes
} derive(Debug)

///|
/// 解析 SSH_MSG_CHANNEL_REQUEST payload。
pub fn parse_server_channel_request(
  payload : Bytes,
) -> ServerChannelRequest raise SshError {
  let r = Reader::new(payload)
  let _ = r.read_byte()
  let _ = r.read_uint32()
  let req_type = r.read_string_as_str()
  let _ = r.read_byte()
  match req_type {
    "exec" => Exec(r.read_string_as_str())
    "shell" => Shell
    "subsystem" => Subsystem(r.read_string_as_str())
    "pty-req" => {
      let term = r.read_string_as_str()
      let cols = r.read_uint32()
      let rows = r.read_uint32()
      let width = r.read_uint32()
      let height = r.read_uint32()
      let modes = r.read_string()
      PtyReq({ term, cols, rows, width, height, modes })
    }
    "env" => {
      let name = r.read_string_as_str()
      let value = r.read_string_as_str()
      Env(name, value)
    }
    "window-change" => {
      let cols = r.read_uint32()
      let rows = r.read_uint32()
      let w = r.read_uint32()
      let h = r.read_uint32()
      WindowChange(cols, rows, w, h)
    }
    "signal" => Signal(r.read_string_as_str())
    "exit-status" => ExitStatus(r.read_uint32())
    "exit-signal" => {
      let sig = r.read_string_as_str()
      let core = r.read_byte() != b'\x00'
      let errmsg = r.read_string_as_str()
      let lang = r.read_string_as_str()
      ExitSignal(sig, core, errmsg, lang)
    }
    t => Unknown(t)
  }
}

///|
pub fn build_channel_success(recipient : Int) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_SUCCESS)
  w.write_uint32(recipient)
  w.to_bytes()
}

///|
pub fn build_channel_req_failure(recipient : Int) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_FAILURE)
  w.write_uint32(recipient)
  w.to_bytes()
}

// ==================== Wire helpers ====================

///|
fn build_banner(text : String) -> Bytes {
  let w = Writer::new()
  w.write_byte(b'\x35') // SSH_MSG_USERAUTH_BANNER = 53
  w.write_string_from_str(text)
  w.write_string_from_str("")
  w.to_bytes()
}

///|
fn build_service_accept(service : String) -> Bytes {
  let w = Writer::new()
  w.write_byte(b'\x06')
  w.write_string_from_str(service)
  w.to_bytes()
}

///|
fn build_pk_ok(alg : String, blob : Bytes) -> Bytes {
  let w = Writer::new()
  w.write_byte(b'\x3c')
  w.write_string_from_str(alg)
  w.write_string(blob)
  w.to_bytes()
}

///|
fn build_userauth_failure(methods : Array[String], partial : Bool) -> Bytes {
  let w = Writer::new()
  w.write_byte(b'\x33')
  w.write_name_list(methods)
  w.write_byte(if partial { 1 } else { 0 })
  w.to_bytes()
}

///|
fn verify_pubkey_sig(
  blob : Bytes,
  _alg : String,
  tbs : Bytes,
  sig_blob : Bytes,
) -> Bool {
  let r0 = Reader::new(blob)
  let key_alg = r0.read_string_as_str() catch { _ => return false }
  let sr = Reader::new(sig_blob)
  let _ = sr.read_string_as_str() catch { _ => return false }
  let raw_sig = sr.read_string() catch { _ => return false }
  match key_alg {
    "ssh-ed25519" => {
      let pub_raw = r0.read_string() catch { _ => return false }
      let pkey = @crypto.PKey::from_ed25519_pub(pub_raw) catch {
        _ => return false
      }
      pkey.verify(0, tbs, raw_sig) catch { _ => false }
    }
    "ssh-rsa" | "rsa-sha2-256" => {
      let e = r0.read_string() catch { _ => return false }
      let n = r0.read_string() catch { _ => return false }
      let pkey = @crypto.PKey::from_rsa_components(n, e) catch {
        _ => return false
      }
      pkey.verify(2, tbs, raw_sig) catch { _ => false }
    }
    _ => false
  }
}

// ==================== Crypto context stubs ====================

///|
pub struct ServerEncCtx {
  pub session_id : Bytes
}

///|
pub struct ServerCrypto {
  pub session_id : Bytes
  pub enc_ctx : ServerEncCtx
}

///|
async fn do_server_version_exchange(
  sock : @socket.Tcp,
  server_version : String,
) -> String raise SshError {
  sock.write_bytes(@utf8.encode(server_version + "\r\n"))
  while true {
    let line = sock.read_until_newline()
    let s = bytes_to_utf8_string(line)
    if s.has_prefix("SSH-") {
      return s
    }
  }
  raise ProtocolError("server: version exchange loop exited unexpectedly")
}

///|
async fn do_server_kex(
  _sock : @socket.Tcp,
  _host_keys : Array[@crypto.PKey],
  _client_version : String,
  _server_version : String,
) -> ServerCrypto raise SshError {
  // TODO: full server KEX implementation
  let session_id = b""
  { session_id, enc_ctx: { session_id } }
}

///|
/// 将 payload 封装为明文 SSH 帧（服务端 stub，KEX 完成前使用）。
fn server_frame_packet(payload : Bytes) -> Bytes {
  write_packet(payload, 8, false, fn(_p) { b"" }) catch {
    _ => payload
  }
}

///|
/// 从 socket 读取并解帧一个 SSH 包（服务端 stub）。
async fn server_read_packet(sock : @socket.Tcp) -> Bytes raise SshError {
  let len_bytes = sock.read_exact(4)
  let pkt_len = decode_uint32(len_bytes)
  if pkt_len < 1 || pkt_len > MAX_PACKET {
    raise ProtocolError("server: bad packet length \{pkt_len}")
  }
  let body = sock.read_exact(pkt_len)
  if body.length() < 1 {
    raise ProtocolError("server: empty packet body")
  }
  let padding = body.unsafe_get(0).to_int()
  if 1 + padding > body.length() {
    raise ProtocolError("server: bad padding length")
  }
  Bytes::makei(body.length() - 1 - padding, i => body[i + 1])
}
