///
/// SSH 代理协议（RFC 文件：draft-miller-ssh-agent-04）。
///
/// 实现 SSH 代理客户端（通过 Unix socket 与 ssh-agent 通信）：
///   - SSH_AGENTC_REQUEST_IDENTITIES / SSH_AGENT_IDENTITIES_ANSWER
///   - SSH_AGENTC_SIGN_REQUEST / SSH_AGENT_SIGN_RESPONSE
///   - SSH_AGENTC_ADD_IDENTITY / SSH_AGENTC_REMOVE_IDENTITY
///   - SSH_AGENTC_REMOVE_ALL_IDENTITIES
///   - SSH_AGENTC_LOCK / SSH_AGENTC_UNLOCK
///   - SSH_AGENTC_ADD_SMARTCARD_KEY（stub）
///   - agent forwarding helpers
///
/// 传输层：通过 @socket.UnixSocket（或 TCP）读写长度前缀帧。

// ==================== Message type constants ====================

///|
/// SSH 代理协议消息号（草案 §4）。
pub const AGENT_FAILURE : Byte = b'\x05' // 5

///|
pub const AGENT_SUCCESS : Byte = b'\x06' // 6

///|
pub const AGENTC_REQUEST_IDENTITIES : Byte = b'\x0b' // 11

///|
pub const AGENT_IDENTITIES_ANSWER : Byte = b'\x0c' // 12

///|
pub const AGENTC_SIGN_REQUEST : Byte = b'\x0d' // 13

///|
pub const AGENT_SIGN_RESPONSE : Byte = b'\x0e' // 14

///|
pub const AGENTC_ADD_IDENTITY : Byte = b'\x11' // 17

///|
pub const AGENTC_REMOVE_IDENTITY : Byte = b'\x12' // 18

///|
pub const AGENTC_REMOVE_ALL_IDENTITIES : Byte = b'\x13' // 19

///|
pub const AGENTC_LOCK : Byte = b'\x16' // 22

///|
pub const AGENTC_UNLOCK : Byte = b'\x17' // 23

///|
pub const AGENTC_ADD_ID_CONSTRAINED : Byte = b'\x1a' // 26

///|
/// SSH_AGENT_SIGN flag: use rsa-sha2-256 instead of ssh-rsa.
pub const AGENT_SIGN_FLAG_RSA_SHA2_256 : Int = 2

///|
/// SSH_AGENT_SIGN flag: use rsa-sha2-512 instead of ssh-rsa.
pub const AGENT_SIGN_FLAG_RSA_SHA2_512 : Int = 4

// ==================== Wire types ====================

///|
/// 代理中的一个身份（公钥 blob + 注释）。
pub struct AgentKey {
  /// SSH wire 格式的公钥 blob（如 `ssh-ed25519` 开头）。
  blob : Bytes
  /// 用户提供的注释（通常是文件名或空字符串）。
  comment : String
} derive(Debug)

///|
pub fn AgentKey::blob(self : AgentKey) -> Bytes {
  self.blob
}

///|
pub fn AgentKey::comment(self : AgentKey) -> String {
  self.comment
}

// ==================== Frame encoding ====================

///|
/// 将 payload 封装为代理协议帧（4 字节大端长度 + payload）。
pub fn agent_frame(payload : Bytes) -> Bytes {
  encode_uint32(payload.length()) + payload
}

///|
/// 从 Bytes 解码代理帧长度，返回 payload 起始偏移和 payload 长度。
/// 要求 `buf` 长度 ≥ 4。
pub fn agent_parse_frame_len(buf : Bytes) -> Int raise SshError {
  if buf.length() < 4 {
    raise ParseError("agent: frame too short for length")
  }
  decode_uint32(buf)
}

// ==================== Request builders ====================

///|
/// 构建 SSH_AGENTC_REQUEST_IDENTITIES 请求。
pub fn build_agent_request_identities() -> Bytes {
  let w = Writer::new()
  w.write_byte(AGENTC_REQUEST_IDENTITIES)
  agent_frame(w.to_bytes())
}

///|
/// 构建 SSH_AGENTC_SIGN_REQUEST。
///
/// `flags`: 0 = 默认（Ed25519/ECDSA 使用自己的方案；RSA 使用 SHA-1），
///          [AGENT_SIGN_FLAG_RSA_SHA2_256] = rsa-sha2-256，
///          [AGENT_SIGN_FLAG_RSA_SHA2_512] = rsa-sha2-512。
pub fn build_agent_sign_request(
  key_blob : Bytes,
  data : Bytes,
  flags : Int,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(AGENTC_SIGN_REQUEST)
  w.write_string(key_blob)
  w.write_string(data)
  w.write_uint32(flags)
  agent_frame(w.to_bytes())
}

///|
/// 构建 SSH_AGENTC_ADD_IDENTITY（Ed25519）。
///
/// `key_blob` 为 SSH wire 格式公钥，`priv_seed` 为 32 字节私钥种子，
/// `comment` 为注释字符串。
pub fn build_agent_add_ed25519(
  pub_bytes : Bytes,
  priv_seed_plus_pub : Bytes,
  comment : String,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(AGENTC_ADD_IDENTITY)
  w.write_string_from_str("ssh-ed25519")
  w.write_string(pub_bytes)
  w.write_string(priv_seed_plus_pub) // 64-byte blob: seed(32) || pub(32)
  w.write_string_from_str(comment)
  agent_frame(w.to_bytes())
}

///|
/// 构建 SSH_AGENTC_REMOVE_IDENTITY。
pub fn build_agent_remove_identity(key_blob : Bytes) -> Bytes {
  let w = Writer::new()
  w.write_byte(AGENTC_REMOVE_IDENTITY)
  w.write_string(key_blob)
  agent_frame(w.to_bytes())
}

///|
/// 构建 SSH_AGENTC_REMOVE_ALL_IDENTITIES。
pub fn build_agent_remove_all() -> Bytes {
  let w = Writer::new()
  w.write_byte(AGENTC_REMOVE_ALL_IDENTITIES)
  agent_frame(w.to_bytes())
}

///|
/// 构建 SSH_AGENTC_LOCK。
pub fn build_agent_lock(passphrase : String) -> Bytes {
  let w = Writer::new()
  w.write_byte(AGENTC_LOCK)
  w.write_string_from_str(passphrase)
  agent_frame(w.to_bytes())
}

///|
/// 构建 SSH_AGENTC_UNLOCK。
pub fn build_agent_unlock(passphrase : String) -> Bytes {
  let w = Writer::new()
  w.write_byte(AGENTC_UNLOCK)
  w.write_string_from_str(passphrase)
  agent_frame(w.to_bytes())
}

// ==================== Response parsers ====================

///|
/// 解析 SSH_AGENT_IDENTITIES_ANSWER，返回身份列表。
pub fn parse_agent_identities_answer(
  payload : Bytes,
) -> Array[AgentKey] raise SshError {
  let r = Reader::new(payload)
  let msg = r.read_byte()
  if msg != AGENT_IDENTITIES_ANSWER {
    if msg == AGENT_FAILURE {
      raise ProtocolError("agent: AGENT_FAILURE on request_identities")
    }
    raise ProtocolError(
      "agent: expected IDENTITIES_ANSWER got \{msg.to_int()}",
    )
  }
  let n = r.read_uint32()
  let keys : Array[AgentKey] = []
  for _ in 0..<n {
    let blob = r.read_string()
    let comment = r.read_string_as_str()
    keys.push({ blob, comment })
  }
  keys
}

///|
/// 解析 SSH_AGENT_SIGN_RESPONSE，返回签名 blob。
pub fn parse_agent_sign_response(payload : Bytes) -> Bytes raise SshError {
  let r = Reader::new(payload)
  let msg = r.read_byte()
  if msg == AGENT_FAILURE {
    raise ProtocolError("agent: AGENT_FAILURE on sign_request")
  }
  if msg != AGENT_SIGN_RESPONSE {
    raise ProtocolError(
      "agent: expected SIGN_RESPONSE got \{msg.to_int()}",
    )
  }
  r.read_string()
}

///|
/// 检查代理响应是否为 SUCCESS / FAILURE，返回 Bool。
pub fn parse_agent_success(payload : Bytes) -> Bool raise SshError {
  if payload.length() == 0 {
    raise ParseError("agent: empty response")
  }
  match payload.unsafe_get(0) {
    b => b == AGENT_SUCCESS
  }
}

// ==================== Agent connection ====================

///|
/// 代理连接上下文（包装底层异步 TCP socket；
/// 用于 agent forwarding tunnel，即 SSH 通道内的 agent 代理）。
pub struct AgentConn {
  sock : @socket.Tcp
}

///|
/// 通过 TCP 连接创建代理连接。
pub fn AgentConn::from_tcp(sock : @socket.Tcp) -> AgentConn {
  { sock }
}

///|
/// 发送一个代理协议帧并读取响应帧，返回响应 payload。
pub async fn AgentConn::roundtrip(
  self : AgentConn,
  req : Bytes,
) -> Bytes raise SshError {
  self.sock.write_bytes(req)
  let len_buf = self.sock.read_exact(4)
  let resp_len = decode_uint32(len_buf)
  if resp_len > 256 * 1024 {
    raise ProtocolError("agent: response too large (\{resp_len})")
  }
  self.sock.read_exact(resp_len)
}

///|
pub async fn AgentConn::list_keys(
  self : AgentConn,
) -> Array[AgentKey] raise SshError {
  let resp = self.roundtrip(build_agent_request_identities())
  parse_agent_identities_answer(resp)
}

///|
pub async fn AgentConn::sign(
  self : AgentConn,
  key_blob : Bytes,
  data : Bytes,
  flags : Int,
) -> Bytes raise SshError {
  let resp = self.roundtrip(build_agent_sign_request(key_blob, data, flags))
  parse_agent_sign_response(resp)
}

///|
pub async fn AgentConn::add_ed25519(
  self : AgentConn,
  pub_bytes : Bytes,
  priv_blob : Bytes,
  comment : String,
) -> Bool raise SshError {
  let resp = self.roundtrip(
    build_agent_add_ed25519(pub_bytes, priv_blob, comment),
  )
  parse_agent_success(resp)
}

///|
pub async fn AgentConn::remove_identity(
  self : AgentConn,
  key_blob : Bytes,
) -> Bool raise SshError {
  let resp = self.roundtrip(build_agent_remove_identity(key_blob))
  parse_agent_success(resp)
}

///|
pub async fn AgentConn::remove_all(self : AgentConn) -> Bool raise SshError {
  let resp = self.roundtrip(build_agent_remove_all())
  parse_agent_success(resp)
}

///|
pub async fn AgentConn::lock(
  self : AgentConn,
  passphrase : String,
) -> Bool raise SshError {
  let resp = self.roundtrip(build_agent_lock(passphrase))
  parse_agent_success(resp)
}

///|
pub async fn AgentConn::unlock(
  self : AgentConn,
  passphrase : String,
) -> Bool raise SshError {
  let resp = self.roundtrip(build_agent_unlock(passphrase))
  parse_agent_success(resp)
}

// ==================== Agent forwarding (channel helpers) ====================

///|
/// 构建请求 agent forwarding 的通道请求消息（auth-agent-req@openssh.com）。
pub fn build_agent_forward_request(recipient_channel : Int) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_REQUEST)
  w.write_uint32(recipient_channel)
  w.write_string_from_str("auth-agent-req@openssh.com")
  w.write_byte(0) // want_reply = false
  w.to_bytes()
}

///|
/// 构建打开 agent forwarding 通道的 CHANNEL_OPEN 消息。
/// `channel_type` = "auth-agent@openssh.com"。
pub fn build_agent_channel_open(
  sender_channel : Int,
  initial_window : Int,
  max_packet : Int,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_OPEN)
  w.write_string_from_str("auth-agent@openssh.com")
  w.write_uint32(sender_channel)
  w.write_uint32(initial_window)
  w.write_uint32(max_packet)
  w.to_bytes()
}

// ==================== Public key blob helpers ====================

///|
/// 将 Ed25519 公钥原始字节（32 字节）编码为 SSH wire 格式的公钥 blob。
/// 格式：string("ssh-ed25519") || string(pub_raw)。
pub fn encode_ed25519_pubkey_blob(pub_raw : Bytes) -> Bytes {
  let w = Writer::new()
  w.write_string_from_str("ssh-ed25519")
  w.write_string(pub_raw)
  w.to_bytes()
}

///|
/// 将 RSA 公钥组件编码为 SSH wire 格式的公钥 blob。
/// 格式：string("ssh-rsa") || mpint(e) || mpint(n)。
/// （注：wire 顺序为 e 在前，n 在后，与 PKCS#1 相反）
pub fn encode_rsa_pubkey_blob(n : Bytes, e : Bytes) -> Bytes {
  let w = Writer::new()
  w.write_string_from_str("ssh-rsa")
  w.write_bytes(encode_mpint_of_bytes(e))
  w.write_bytes(encode_mpint_of_bytes(n))
  w.to_bytes()
}

///|
/// 将 ECDSA P-256 公钥（未压缩点，65 字节）编码为 SSH wire 格式的公钥 blob。
/// 格式：string("ecdsa-sha2-nistp256") || string("nistp256") || string(point)。
pub fn encode_ecdsa_p256_pubkey_blob(point : Bytes) -> Bytes {
  let w = Writer::new()
  w.write_string_from_str("ecdsa-sha2-nistp256")
  w.write_string_from_str("nistp256")
  w.write_string(point)
  w.to_bytes()
}

// 注：build_signature_blob（ssh_client.mbt）和 parse_signature_blob（kex.mbt）
// 已在其他模块中定义，此处复用，不重复定义。
