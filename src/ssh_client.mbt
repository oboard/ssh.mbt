///
/// MoonSSH 顶层 API。
/// 组装 KEX / auth / channel 模块，提供完整 SSH 客户端。

///|
/// SSH 连接参数。
pub struct ConnectOptions {
  host : String
  port : Int
  user : String
  client_banner : String?
  host_key_policy : HostKeyPolicy
  timeout_ms : Int
}

///|
/// 创建默认连接参数。
///
/// host key 校验策略默认为 **Strict 且无条目**——这意味着默认行为是
/// **拒绝所有未知主机**。要允许连接，请显式调用以下之一：
///
/// - `with_strict_host_key_check(content)`
/// - `with_trust_on_first_use(content, prompt)`
/// - `with_insecure_host_key()`（不推荐）
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
    host_key_policy: Strict([], reject_unknown),
    timeout_ms: 30_000,
  }
}

///|
/// 设置 host key 校验为 **Strict 模式**，加载指定 known_hosts 内容。
/// 未在 entries 中的主机一律拒绝（除非 `on_unknown` 允许）。
/// 调用方负责读取 known_hosts 文件内容（例如通过 `@fs` 或外部 FFI），
/// 本库保持纯协议层、无文件系统依赖。
pub fn ConnectOptions::with_strict_host_key_check(
  self : ConnectOptions,
  known_hosts_content : String,
) -> ConnectOptions raise SshError {
  let entries = parse_file(known_hosts_content)
  { ..self, host_key_policy: Strict(entries, reject_unknown) }
}

///|
/// 设置 host key 校验为 **Trust On First Use**：
/// 首次连接由 `prompt(host, alg, key) -> Bool` 决定是否接受并持久化；
/// 之后按 Strict 行为校验。
pub fn ConnectOptions::with_trust_on_first_use(
  self : ConnectOptions,
  known_hosts_content : String,
  prompt : (String, String, Bytes) -> Bool,
) -> ConnectOptions raise SshError {
  let entries = parse_file(known_hosts_content)
  { ..self, host_key_policy: TrustOnFirstUse(entries, prompt) }
}

///|
/// 跳过 host key 校验。**仅用于受信任内网或本地回环测试**。
pub fn ConnectOptions::with_insecure_host_key(
  self : ConnectOptions,
) -> ConnectOptions {
  { ..self, host_key_policy: Insecure }
}

///|
/// 用自定义 `(alg, key) -> Bool` 回调完全接管 host key 校验。
/// 返回 `true` 接受；返回 `false` 时抛出 [HostKeyMismatch]。
///
/// 与 [with_strict_host_key_check] / [with_trust_on_first_use] 的区别：
/// 此方法不依赖 [KnownHost] 列表，把校验逻辑全部交给回调，
/// 适用于需要自定义指纹格式、对接外部 HSM / Trust Store
/// 或集成非 OpenSSH known_hosts 实现的场景。
pub fn ConnectOptions::with_host_key_verifier(
  self : ConnectOptions,
  f : (String, Bytes) -> Bool,
) -> ConnectOptions {
  { ..self, host_key_policy: Callback(f) }
}

///|
/// SSH 客户端。组装 KEX / auth / channel / 加密层，提供完整 SSH 连接能力。
pub struct Client {
  priv conn : ClientConn
  priv host : String
  priv port : Int
  priv kex : KexContext
  priv auth : AuthContext
  priv host_key_policy : HostKeyPolicy
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
/// 返回默认客户端 banner：`"SSH-2.0-MoonSSH_0.1.0"`。
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
    host: opts.host,
    port: opts.port,
    kex,
    auth,
    host_key_policy: opts.host_key_policy,
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
  let policy = self.host_key_policy
  let host = self.host
  let port = self.port
  let verify : (String, Bytes) -> Unit raise SshError = (alg, key) => {
    match verify_host_key(policy, host, port, alg, key) {
      Accept => ()
      RejectMismatch(stored_alg, _) =>
        raise HostKeyMismatch(
          "\{host}:\{port} (alg=\{alg}): key changed, stored=\{stored_alg} — possible MITM",
        )
      RejectUnknown =>
        raise HostKeyMismatch(
          "\{host}:\{port} (alg=\{alg}): not in known_hosts and policy rejects unknown hosts",
        )
      RejectByUser =>
        raise HostKeyMismatch(
          "\{host}:\{port} (alg=\{alg}): rejected by user callback",
        )
    }
  }
  self.kex.drive(
    () => self.read_plain_packet(),
    payload => self.write_plain_packet(payload),
    verify,
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
    Failure(methods, _) => raise AuthFailed("methods: \{to_repr(methods)}")
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
    e => raise ProtocolError("auth: load key: \{to_repr(e)}")
  }
  defer pkey.close()

  // 从 .pub 文件读取公钥 (alg, blob)
  let pubkey_path = private_key_path + ".pub"
  let (pub_alg, pubkey_blob) = @crypto.read_openssh_pubkey(pubkey_path) catch {
    e => raise ProtocolError("auth: read pubkey \{pubkey_path}: \{to_repr(e)}")
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
      raise AuthFailed("publickey rejected: methods \{to_repr(methods)}")
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
    e => raise ProtocolError("auth: sign: \{to_repr(e)}")
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
        raise AuthFailed("kbd-int rejected: methods \{to_repr(methods)}")
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
      raise AuthFailed("no supported auth methods: \{to_repr(methods)}")
    }
    _ => raise ProtocolError("auth: unexpected probe reply")
  }
}

// ============== Channel operations ==============

///|
/// 创建一个新的 session 通道（尚未打开，需配合 [Client::exec] 或 [Client::shell]）。
pub fn Client::open_session(self : Client) -> Channel {
  let id = self.next_channel_id
  self.next_channel_id = self.next_channel_id + 1
  Channel::new(id)
}

///|
/// 在远程主机上执行命令，阻塞直到命令结束。返回 `(stdout, stderr)`。
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
/// 请求远程 shell。发送 shell 请求后立即返回（非阻塞），后续通过 channel 交互。
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
/// 关闭底层 TCP 连接。
pub fn Client::close(self : Client) -> Unit {
  match self.conn {
    Connected(conn) => conn.close()
  }
}

// ============== Port forwarding ==============

///|
/// 本地端口转发（-L）。在本地监听端口，将连接通过 SSH 中转到远端目标。
/// 阻塞运行直到连接断开或出错。每次只能处理一个转发连接。
///
/// - `local_port`：本地监听端口
/// - `remote_host`：通过 SSH 连接的目标主机
/// - `remote_port`：通过 SSH 连接的目标端口
pub fn Client::forward_local_port(
  self : Client,
  local_port : Int,
  remote_host : String,
  remote_port : Int,
) -> Unit raise SshError {
  let listener = @socket.Tcp::bind_listen(local_port) catch {
    e => raise IoError("bind local port \{local_port}: \{e}")
  }
  debug(
    "* forward_local: listening on 127.0.0.1:\{local_port} → \{remote_host}:\{remote_port}",
  )

  while true {
    let local_conn = listener.accept() catch {
      e => {
        debug("* forward_local: accept error: \{e}")
        continue
      }
    }
    debug("* forward_local: new connection from client")

    let ch = self.open_direct_tcpip(remote_host, remote_port)
    self.relay_data(ch, local_conn)
    debug("* forward_local: connection closed, waiting for next")
  }
}

///|
/// 远程端口转发（-R）。在远端监听端口，将入站连接中转到本地目标。
/// 阻塞运行直到连接断开或出错。
///
/// - `remote_port`：远端监听端口
/// - `local_host`：本地目标主机
/// - `local_port`：本地目标端口
pub fn Client::forward_remote_port(
  self : Client,
  remote_port : Int,
  local_host : String,
  local_port : Int,
) -> Unit raise SshError {
  // 1. 注册远程转发
  let req = build_global_request_tcpip_forward("0.0.0.0", remote_port)
  self.write_packet(req)

  // 2. 读取响应（自动处理服务端插入的 GLOBAL_REQUEST / IGNORE / DEBUG 等消息）
  let reply = self.read_global_request_reply()
  let r = Reader::new(reply)
  let msg_type = r.read_byte()
  match msg_type {
    MSG_REQUEST_SUCCESS => {
      let assigned_port = if !r.eof() { r.read_uint32() } else { remote_port }
      debug("* remote forward registered on port \{assigned_port}")
    }
    MSG_REQUEST_FAILURE =>
      raise RequestDenied("tcpip-forward rejected by server")
    _ =>
      raise ProtocolError(
        "unexpected reply to tcpip-forward: \{msg_type.to_int()}",
      )
  }

  // 3. 事件循环
  self.remote_forward_loop(local_host, local_port)
}

///|
/// 动态端口转发 / SOCKS5 代理（-D）。在本地监听 SOCKS5 端口。
/// 阻塞运行直到连接断开或出错。
///
/// - `local_port`：本地 SOCKS5 监听端口
pub fn Client::forward_socks5(
  self : Client,
  local_port : Int,
) -> Unit raise SshError {
  let listener = @socket.Tcp::bind_listen(local_port) catch {
    e => raise IoError("bind SOCKS5 port \{local_port}: \{e}")
  }
  debug("* SOCKS5 proxy listening on 127.0.0.1:\{local_port}")

  while true {
    let conn = listener.accept() catch {
      e => {
        debug("* SOCKS5: accept error: \{e}")
        continue
      }
    }
    self.handle_socks5_connection(conn)
  }
}

///|
/// 取消远程端口转发。
pub fn Client::cancel_remote_forward(
  self : Client,
  address : String,
  port : Int,
) -> Unit raise SshError {
  let req = build_global_request_cancel_tcpip_forward(address, port)
  self.write_packet(req)

  let reply = self.read_global_request_reply()
  let msg_type = reply.unsafe_get(0)
  match msg_type {
    MSG_REQUEST_SUCCESS =>
      debug("* remote forward cancelled: \{address}:\{port}")
    MSG_REQUEST_FAILURE => raise RequestDenied("cancel-tcpip-forward rejected")
    _ => raise ProtocolError("unexpected reply to cancel-tcpip-forward")
  }
}

// ============== Forwarding internals ==============

///|
/// 打开 direct-tcpip 通道（本地转发用）。
fn Client::open_direct_tcpip(
  self : Client,
  host : String,
  port : Int,
) -> Channel raise SshError {
  let id = self.next_channel_id
  self.next_channel_id = self.next_channel_id + 1
  let ch = Channel::new(id)
  ch.channel_type = DirectTcpip(host, port)

  let open_msg = build_channel_open_direct_tcpip(
    id,
    1024 * 1024,
    32 * 1024,
    host,
    port,
    "127.0.0.1",
    0,
  )
  self.write_packet(open_msg)

  // 等待确认
  while true {
    let payload = self.read_packet()
    let responses = ch.handle_inbound(payload)
    for resp in responses {
      self.write_packet(resp)
    }
    if ch.is_open() {
      break
    }
    if ch.state() == Done {
      let detail = match (ch.open_failure_reason(), ch.open_failure_message()) {
        (Some(r), Some(m)) =>
          " (reason=\{open_failure_reason_name(r)}, msg=\"\{m}\")"
        (Some(r), None) => " (reason=\{open_failure_reason_name(r)})"
        _ => ""
      }
      raise ProtocolError("direct-tcpip: failed to open\{detail}")
    }
  }
  ch
}

///|
/// 双向数据中继：local_socket ↔ SSH channel。
/// 使用 select 轮询避免阻塞任一方向。
fn Client::relay_data(
  self : Client,
  ch : Channel,
  local_socket : @socket.Tcp,
) -> Unit raise SshError {
  // 设置数据去向为 socket（SSH 通道数据直接写入本地 socket）
  ch.data_sink = Socket(local_socket)

  // 设置本地 socket 为非阻塞
  local_socket.set_nonblocking() catch {
    e => debug("* relay_data: set_nonblocking failed: \{e}")
  }

  while ch.state() != Done && ch.state() != Closed {
    // 方向 A: SSH → 本地 socket
    let payload = self.read_packet_nonblocking()
    match payload {
      Some(data) => {
        let responses = ch.handle_inbound(data)
        for resp in responses {
          self.write_packet(resp)
        }
        // 检查通道是否收到数据（DataSink::Buffer 模式）
        if ch.has_stdout() {
          let out = ch.take_stdout()
          local_socket.write_bytes(@utf8.encode(out)) catch {
            _ => break
          }
        }
      }
      None => ()
    }

    // 方向 B: 本地 socket → SSH
    if local_socket.has_data() {
      let buf = Bytes::new(32 * 1024)
      let n = local_socket.recv(buf, 0, 32 * 1024)
      if n > 0 {
        let view = Bytes::get_view(buf, start=0, end=n)
        match view {
          Some(v) => {
            let data = BytesView::to_owned(v)
            let msg = build_channel_data(ch.peer_id(), data)
            self.write_packet(msg) catch {
              _ => break
            }
          }
          None => break
        }
      } else if n == 0 {
        // 本地连接关闭, 发送 EOF
        self.write_packet(build_channel_eof(ch.peer_id())) catch {
          _ => ()
        }
        break
      }
    }
  }

  // 清理
  if ch.state() != Done {
    self.write_packet(build_channel_close(ch.peer_id())) catch {
      _ => ()
    }
  }
  local_socket.close()
}

///|
/// 远程转发事件循环。
fn Client::remote_forward_loop(
  self : Client,
  local_host : String,
  local_port : Int,
) -> Unit raise SshError {
  while true {
    let payload = self.read_packet()
    let msg_type = payload.unsafe_get(0)

    match msg_type {
      MSG_CHANNEL_OPEN => {
        let r = Reader::new(payload)
        let _ = r.read_byte() // msg type
        let ch_type = r.read_string_as_str()
        if ch_type == "forwarded-tcpip" {
          let (sender_ch, win, max_pkt, addr, port, orig_ip, orig_port) = parse_inbound_forwarded_tcpip(
            r,
          )
          debug("* remote forward: connection from \{orig_ip}:\{orig_port}")

          // 连接本地目标
          let local_conn = @socket.Tcp::connect_to_host(
            local_host,
            port=local_port,
          ) catch {
            e => {
              debug(
                "* remote forward: cannot connect to local \{local_host}:\{local_port}: \{e}",
              )
              let fail_msg = build_channel_open_failure(
                sender_ch, 2, "connect failed", "en",
              )
              self.write_packet(fail_msg) catch {
                _ => ()
              }
              continue
            }
          }

          // 分配本地通道 ID, 发送确认
          let local_id = self.next_channel_id
          self.next_channel_id = self.next_channel_id + 1
          let ch = Channel::new(local_id)
          ch.channel_type = ForwardedTcpip(addr, port)
          // 入站通道：peer_id 必须设为服务端分配的 sender_ch，
          // 否则后续 CHANNEL_DATA / EOF / CLOSE 的 recipient channel 会错写成 0。
          ch.peer_id = sender_ch
          ch.remote_window = win
          // remote_max_packet 不可变，用结构体更新语法设置
          let ch = { ..ch, remote_max_packet: max_pkt }
          ch.state = Open

          let confirm = build_channel_open_confirmation(
            sender_ch,
            local_id,
            1024 * 1024,
            32 * 1024,
          )
          self.write_packet(confirm) catch {
            _ => continue
          }

          // 中继数据
          self.relay_data(ch, local_conn)
        } else {
          // 未知通道类型, 发送 OPEN_FAILURE
          let sender_ch = r.read_uint32()
          let fail_msg = build_channel_open_failure(
            sender_ch, 3, "unsupported channel type", "",
          )
          self.write_packet(fail_msg) catch {
            _ => ()
          }
        }
      }
      MSG_CHANNEL_OPEN_CONFIRMATION =>
        // 可能是其他通道的确认，忽略
        debug("* remote forward: ignoring channel open confirmation")
      MSG_GLOBAL_REQUEST => {
        // 服务端的全局请求，回复 FAILURE
        debug("* remote forward: ignoring global request")
        self.write_packet(Bytes::make(1, MSG_REQUEST_FAILURE)) catch {
          _ => ()
        }
      }
      _ => debug("* remote forward: ignoring msg \{msg_type.to_int()}")
    }
  }
}

///|
/// 处理单个 SOCKS5 连接。
fn Client::handle_socks5_connection(
  self : Client,
  conn : @socket.Tcp,
) -> Unit raise SshError {
  // SOCKS5 握手 + CONNECT 请求解析
  let (target_host, target_port) = socks5_handshake(conn) catch {
    _e => {
      conn.close()
      return
    }
  }

  debug("* SOCKS5 CONNECT → \{target_host}:\{target_port}")

  // 通过 SSH 打开 direct-tcpip 通道
  let ch = self.open_direct_tcpip(target_host, target_port) catch {
    _e => {
      debug("* SOCKS5: direct-tcpip failed")
      conn.write_bytes(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00") catch {
        _ => ()
      }
      conn.close()
      return
    }
  }

  // 回复成功
  conn.write_bytes(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00") catch {
    _ => {
      conn.close()
      return
    }
  }

  // 双向中继
  self.relay_data(ch, conn)
}

///|
/// SOCKS5 握手 + CONNECT 请求解析。返回 (target_host, target_port)。
fn socks5_handshake(conn : @socket.Tcp) -> (String, Int) raise SshError {
  // 1. 读取客户端握手
  let buf = conn.read_exact(2) catch {
    e => raise IoError("socks5: read handshake: \{e}")
  }
  let ver = buf.unsafe_get(0)
  let nmethods = buf.unsafe_get(1).to_int()
  if ver != b'\x05' {
    raise ProtocolError("socks5: unsupported version")
  }
  let _methods = conn.read_exact(nmethods) catch {
    e => raise IoError("socks5: read methods: \{e}")
  }

  // 2. 回复: 无需认证 (0x00)
  conn.write_bytes(b"\x05\x00") catch {
    e => raise IoError("socks5: write auth reply: \{e}")
  }

  // 3. 读取 CONNECT 请求
  let header = conn.read_exact(4) catch {
    e => raise IoError("socks5: read request: \{e}")
  }
  let cmd = header.unsafe_get(1)
  if cmd != b'\x01' {
    conn.write_bytes(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00") catch {
      _ => ()
    }
    raise ProtocolError("socks5: unsupported command")
  }
  let atyp = header.unsafe_get(3)

  // 4. 解析目标地址
  match atyp {
    b'\x01' => {
      let addr = conn.read_exact(4) catch {
        e => raise IoError("socks5: read ipv4: \{e}")
      }
      let port_raw = conn.read_exact(2) catch {
        e => raise IoError("socks5: read port: \{e}")
      }
      let ip = "\{addr.unsafe_get(0)}.\{addr.unsafe_get(1)}.\{addr.unsafe_get(2)}.\{addr.unsafe_get(3)}"
      let p = (port_raw.unsafe_get(0).to_int() << 8) |
        port_raw.unsafe_get(1).to_int()
      (ip, p)
    }
    b'\x03' => {
      let len_raw = conn.read_exact(1) catch {
        e => raise IoError("socks5: read domain len: \{e}")
      }
      let domain = conn.read_exact(len_raw.unsafe_get(0).to_int()) catch {
        e => raise IoError("socks5: read domain: \{e}")
      }
      let port_raw = conn.read_exact(2) catch {
        e => raise IoError("socks5: read port: \{e}")
      }
      let host = bytes_to_utf8_string(domain)
      let p = (port_raw.unsafe_get(0).to_int() << 8) |
        port_raw.unsafe_get(1).to_int()
      (host, p)
    }
    b'\x04' => {
      conn.write_bytes(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00") catch {
        _ => ()
      }
      raise ProtocolError("socks5: IPv6 not supported")
    }
    _ => {
      conn.write_bytes(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00") catch {
        _ => ()
      }
      raise ProtocolError("socks5: unknown address type")
    }
  }
}

// ============== Internal packet I/O ==============

///|
/// 读取对全局请求（tcpip-forward / cancel-tcpip-forward）的响应。
///
/// 服务端在回复 `REQUEST_SUCCESS` / `REQUEST_FAILURE` 之前，可能先发送
/// 一些非响应消息（例如认证后的 `hostkeys-00@openssh.com` 全局请求、
/// `IGNORE` / `DEBUG` / `EXT_INFO` 等）。本函数循环读取，自动处理这些
/// 插入消息，直到拿到真正的全局请求响应。
///
/// - `GLOBAL_REQUEST`(80)：解析 `want_reply`，需要时回复 `REQUEST_FAILURE`
/// - `IGNORE`(2) / `DEBUG`(4) / `EXT_INFO`(7)：跳过
/// - `DISCONNECT`(1)：抛错
/// - `REQUEST_SUCCESS`(81) / `REQUEST_FAILURE`(82)：返回该包
fn Client::read_global_request_reply(self : Client) -> Bytes raise SshError {
  while true {
    let payload = self.read_packet()
    if payload.length() == 0 {
      raise ProtocolError("read_global_request_reply: empty packet")
    }
    let msg_type = payload.unsafe_get(0)
    match msg_type {
      MSG_REQUEST_SUCCESS | MSG_REQUEST_FAILURE => return payload
      b'\x02' | b'\x04' | b'\x07' => () // IGNORE, DEBUG, EXT_INFO — skip
      b'\x01' => raise ProtocolError("server sent SSH_MSG_DISCONNECT")
      MSG_GLOBAL_REQUEST => {
        // 处理入站全局请求（如 hostkeys-00@openssh.com）
        let r = Reader::new(payload)
        let _ = r.read_byte() // 跳过消息号
        let req_name = r.read_string_as_str()
        let want_reply = if !r.eof() { r.read_byte() } else { b'\x00' }
        debug(
          "* GLOBAL_REQUEST during global-request reply: '\{req_name}', want_reply=\{want_reply != b'\x00'}",
        )
        if want_reply != b'\x00' {
          self.write_packet(Bytes::make(1, MSG_REQUEST_FAILURE)) catch {
            _ => ()
          }
        }
      }
      _ =>
        raise ProtocolError(
          "unexpected reply to global request: \{msg_type.to_int()}",
        )
    }
  }
  abort("unreachable")
}

///|
/// 读取加密包，自动跳过 IGNORE(2)、DEBUG(4)、EXT_INFO(7) 消息。
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
/// 读取一个 SSH 包（根据加密状态自动选择明文或密文读取）。
fn Client::read_packet(self : Client) -> Bytes raise SshError {
  if self.encrypted {
    self.read_encrypted_packet()
  } else {
    self.read_plain_packet()
  }
}

///|
/// 非阻塞读取一个 SSH 包。底层 socket 无数据时返回 None。
/// 用于端口转发的数据中继循环，避免阻塞某一方向。
fn Client::read_packet_nonblocking(self : Client) -> Bytes? raise SshError {
  match self.conn {
    Connected(conn) => {
      if !conn.has_data() {
        return None
      }
      Some(self.read_packet())
    }
  }
}

///|
/// 写出一个 SSH 包（根据加密状态自动选择明文或密文写出）。
fn Client::write_packet(self : Client, payload : Bytes) -> Unit raise SshError {
  if self.encrypted {
    self.write_encrypted_packet(payload)
  } else {
    self.write_plain_packet(payload)
  }
}

///|
/// 读取明文 SSH 包（KEX 阶段使用）。
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
/// 写出明文 SSH 包（KEX 阶段使用）。
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
/// KEX 完成后安装加密上下文（cipher + MAC），切换到加密模式。
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
    e => raise ProtocolError("install cipher: \{to_repr(e)}")
  }
  let cipher_s2c = @crypto.Cipher::new(
    enc_alg,
    keys.enc_key_s2c,
    keys.iv_s2c,
    encrypt=false,
  ) catch {
    e => raise ProtocolError("install cipher: \{to_repr(e)}")
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
/// 将 SSH 算法名映射到 [crypto.CipherAlgorithm]。
fn parse_cipher_algorithm(
  name : String,
) -> @crypto.CipherAlgorithm raise SshError {
  match name {
    "aes128-ctr" => @crypto.CipherAlgorithm::aes128_ctr()
    _ => raise ProtocolError("unsupported cipher: \{name}")
  }
}

///|
/// 将 SSH 算法名映射到 [crypto.MacAlgorithm]。
fn parse_mac_algorithm(name : String) -> @crypto.MacAlgorithm raise SshError {
  match name {
    "hmac-sha1" => @crypto.MacAlgorithm::hmac_sha1()
    "hmac-sha2-256" => @crypto.MacAlgorithm::hmac_sha256()
    _ => raise ProtocolError("unsupported MAC: \{name}")
  }
}

///|
/// 读取加密 SSH 包：解密 + MAC 验证 + 去 padding。
/// 使用 AES-CTR 流加密模式，整个包（含长度字段）都被加密。
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
        e => raise IoError("read pkt len: \{to_repr(e)}")
      }
      let len_bytes = cipher.update(enc_len) catch {
        e => raise ProtocolError("decrypt pkt len: \{to_repr(e)}")
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
        e => raise ProtocolError("decrypt: \{to_repr(e)}")
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
/// 写出加密 SSH 包：padding + 加密 + MAC。
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
        e => raise ProtocolError("encrypt: \{to_repr(e)}")
      }
      let wire_data = encrypted + mac
      hex_dump("  packet on wire (\{wire_data.length()} bytes)", wire_data)
      conn.write_bytes(wire_data) catch {
        e => raise IoError("write: \{to_repr(e)}")
      }
      self.seq_send = self.seq_send + 1U
    }
  }
}

///|
/// 使用 s2c MAC 密钥计算接收方向的消息认证码（用于验证）。
fn compute_mac_s2c(client : Client, data : Bytes) -> Bytes raise SshError {
  let mac_ctx = match client.mac_s2c {
    Some(m) => m
    None => return b""
  }
  let seq_bytes = encode_uint32(client.seq_recv.reinterpret_as_int())
  mac_ctx.hmac_on(seq_bytes + data) catch {
    e => raise ProtocolError("MAC compute s2c: \{to_repr(e)}")
  }
}

///|
/// 使用 c2s MAC 密钥计算发送方向的消息认证码。
fn compute_mac(client : Client, data : Bytes) -> Bytes raise SshError {
  let mac_ctx = match client.mac_c2s {
    Some(m) => m
    None => return b""
  }
  let seq_bytes = encode_uint32(client.seq_send.reinterpret_as_int())
  mac_ctx.update(seq_bytes)
  mac_ctx.update(data)
  let tag = mac_ctx.finalize() catch {
    e => raise ProtocolError("MAC compute: \{to_repr(e)}")
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
/// 将原始签名打包为 SSH signature blob（`string alg || string sig`）。
fn build_signature_blob(alg : String, sig : Bytes) -> Bytes {
  let w = Writer::new()
  w.write_string_from_str(alg)
  w.write_string(sig)
  w.to_bytes()
}
