///|
/// SSH 协议层 — KEX 状态机（RFC 4253 §6）。
///
/// 支持的密钥交换算法：
///   - ecdh-sha2-nistp256          (RFC 5656)
///   - diffie-hellman-group14-sha256
///   - diffie-hellman-group14-sha1
///
/// 支持的 host key 算法：
///   - rsa-sha2-256
///   - ssh-rsa

// ============== Algorithm lists ==============

///|
/// 返回客户端支持的密钥交换算法列表（按优先级排序）。
pub fn kex_algorithms() -> Array[String] {
  [
    "ext-info-c", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1",
  ]
}

///|
/// 返回客户端支持的 host key 算法列表（按优先级排序）。
pub fn server_host_key_algorithms() -> Array[String] {
  [
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-ed25519",
    "rsa-sha2-256", "ssh-rsa", "ssh-dss",
  ]
}

///|
/// 返回客户端支持的加密算法列表。
pub fn encryption_algorithms() -> Array[String] {
  ["aes128-ctr"]
}

///|
/// 返回客户端支持的 MAC 算法列表（按优先级排序）。
pub fn mac_algorithms() -> Array[String] {
  ["hmac-sha2-256", "hmac-sha1"]
}

///|
/// 返回客户端支持的压缩算法列表（仅 `"none"`，即不压缩）。
pub fn compression_algorithms() -> Array[String] {
  ["none"]
}

// ============== Message types ==============

///|
/// SSH 消息号：KEXINIT（20），密钥交换初始化。
pub const SSH_MSG_KEXINIT : Byte = b'\x14'

///|
/// SSH 消息号：NEWKEYS（21），通知对端开始使用新密钥。
pub const SSH_MSG_NEWKEYS : Byte = b'\x15'

///|
/// SSH 消息号：KEX_ECDH_INIT（30），ECDH 客户端公钥。
pub const SSH_MSG_KEX_ECDH_INIT : Byte = b'\x1e'

///|
/// SSH 消息号：KEX_ECDH_REPLY（31），ECDH 服务端公钥 + 签名。
pub const SSH_MSG_KEX_ECDH_REPLY : Byte = b'\x1f'

///|
/// SSH 消息号：KEX_DH_INIT（30），DH 客户端公钥。
pub const SSH_MSG_KEX_DH_INIT : Byte = b'\x1e'

///|
/// SSH 消息号：KEX_DH_REPLY（31），DH 服务端公钥 + 签名。
pub const SSH_MSG_KEX_DH_REPLY : Byte = b'\x1f'

///|
/// SSH 消息号：DISCONNECT（1），断开连接。
pub const SSH_MSG_DISCONNECT : Byte = b'\x01'

///|
/// SSH 消息号：IGNORE（2），可忽略的填充消息。
pub const SSH_MSG_IGNORE : Byte = b'\x02'

///|
/// SSH 消息号：DEBUG（4），调试信息。
pub const SSH_MSG_DEBUG : Byte = b'\x04'

///|
/// SSH 消息号：EXT_INFO（7），扩展信息（RFC 8308）。
pub const SSH_MSG_EXT_INFO : Byte = b'\x07'

// ============== KEXINIT ==============

///|
/// 解析后的 KEXINIT 消息（RFC 4253 §7.1）。
/// 包含双端协商的算法列表。
pub struct KexInit {
  cookie : Bytes
  kex_algs : Array[String]
  host_key_algs : Array[String]
  enc_c2s : Array[String]
  enc_s2c : Array[String]
  mac_c2s : Array[String]
  mac_s2c : Array[String]
  comp_c2s : Array[String]
  comp_s2c : Array[String]
}

///|
/// 构建 SSH_MSG_KEXINIT 消息体（含消息号）。
/// `cookie` 为 16 字节随机数。
pub fn build_kexinit_payload(cookie : Bytes) -> Bytes {
  let w = Writer::new()
  w.write_byte(SSH_MSG_KEXINIT)
  w.write_bytes(cookie)
  w.write_name_list(kex_algorithms())
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
/// 解析服务端 KEXINIT 消息体，返回 [KexInit] 结构。
pub fn parse_kexinit(payload : Bytes) -> KexInit raise SshError {
  let r = Reader::new(payload)
  let msg = r.read_byte()
  if msg != SSH_MSG_KEXINIT {
    raise ProtocolError("expected SSH_MSG_KEXINIT")
  }
  let cookie = r.read_bytes(16)
  let kex_algs = r.read_name_list()
  let host_key_algs = r.read_name_list()
  let enc_c2s = r.read_name_list()
  let enc_s2c = r.read_name_list()
  let mac_c2s = r.read_name_list()
  let mac_s2c = r.read_name_list()
  let comp_c2s = r.read_name_list()
  let comp_s2c = r.read_name_list()
  let _lang_c2s = r.read_name_list()
  let _lang_s2c = r.read_name_list()
  let _first_kex_follows = r.read_byte()
  let _reserved = r.read_uint32()
  {
    cookie,
    kex_algs,
    host_key_algs,
    enc_c2s,
    enc_s2c,
    mac_c2s,
    mac_s2c,
    comp_c2s,
    comp_s2c,
  }
}

///|
/// 从客户端列表中选择第一个同时出现在服务端列表中的算法。
fn pick_first(ours : Array[String], server : Array[String]) -> String? {
  for alg in ours {
    for srv in server {
      if alg == srv {
        return Some(alg)
      }
    }
  }
  None
}

///|
/// 协商第一个双方都支持的密钥交换算法。
pub fn KexInit::first(self : KexInit) -> String? {
  pick_first(kex_algorithms(), self.kex_algs)
}

///|
/// 协商第一个双方都支持的 host key 算法。
pub fn KexInit::first_host_key(self : KexInit) -> String? {
  pick_first(server_host_key_algorithms(), self.host_key_algs)
}

///|
/// 协商第一个双方都支持的加密算法（s2c 方向）。
pub fn KexInit::first_enc(self : KexInit) -> String? {
  pick_first(encryption_algorithms(), self.enc_s2c)
}

///|
/// 协商第一个双方都支持的 MAC 算法（s2c 方向）。
pub fn KexInit::first_mac(self : KexInit) -> String? {
  pick_first(mac_algorithms(), self.mac_s2c)
}

///|
/// 协商第一个双方都支持的压缩算法（s2c 方向）。
pub fn KexInit::first_comp(self : KexInit) -> String? {
  pick_first(compression_algorithms(), self.comp_s2c)
}

// ============== ECDH helpers ==============

///|
/// 构建 SSH_MSG_KEX_ECDH_INIT 消息体（含消息号），携带客户端 ECDH 公钥。
pub fn build_ecdh_init_payload(client_public : Bytes) -> Bytes {
  let w = Writer::new()
  w.write_byte(SSH_MSG_KEX_ECDH_INIT)
  w.write_string(client_public)
  w.to_bytes()
}

///|
/// 解析后的 SSH_MSG_KEX_ECDH_REPLY 消息。
pub struct EcdhReply {
  host_key : Bytes
  server_public : Bytes
  signature : Bytes
}

///|
/// 解析 SSH_MSG_KEX_ECDH_REPLY 消息体。
pub fn parse_ecdh_reply_payload(payload : Bytes) -> EcdhReply raise SshError {
  let r = Reader::new(payload)
  let msg = r.read_byte()
  if msg != SSH_MSG_KEX_ECDH_REPLY {
    raise ProtocolError("expected SSH_MSG_KEX_ECDH_REPLY")
  }
  let host_key = r.read_string()
  let server_public = r.read_string()
  let signature = r.read_string()
  { host_key, server_public, signature }
}

// ============== DH helpers ==============

///|
/// 解析后的 SSH_MSG_KEX_DH_REPLY 消息。
pub struct DhReply {
  host_key : Bytes
  f : @bigint.BigInt
  signature : Bytes
}

///|
/// 解析 SSH_MSG_KEX_DH_REPLY 消息体。
pub fn parse_dh_reply_payload(payload : Bytes) -> DhReply raise SshError {
  let r = Reader::new(payload)
  let msg = r.read_byte()
  if msg != SSH_MSG_KEX_DH_REPLY {
    raise ProtocolError("expected SSH_MSG_KEX_DH_REPLY")
  }
  let host_key = r.read_string()
  let f = r.read_mpint()
  let signature = r.read_string()
  { host_key, f, signature }
}

///|
/// 构建 SSH_MSG_KEX_DH_INIT 消息体（含消息号），携带客户端 DH 公钥。
pub fn build_dh_init_payload(e : @bigint.BigInt) -> Bytes {
  let w = Writer::new()
  w.write_byte(SSH_MSG_KEX_DH_INIT)
  w.write_mpint(e)
  w.to_bytes()
}

// ============== Signature helpers ==============

///|
/// SSH 签名 blob（算法名 + 原始签名）。
pub struct SignatureBlob {
  alg : String
  sig : Bytes
}

///|
/// 解析 SSH signature blob，提取算法名和原始签名。
pub fn parse_signature_blob(blob : Bytes) -> SignatureBlob raise SshError {
  let r = Reader::new(blob)
  let alg = r.read_string_as_str()
  let sig = r.read_string()
  { alg, sig }
}

///|
/// 从 host key blob 中提取算法名（第一个 string 字段）。
pub fn parse_host_key_algorithm(blob : Bytes) -> String raise SshError {
  let r = Reader::new(blob)
  r.read_string_as_str()
}

///|
/// 构建 SSH_MSG_NEWKEYS 消息体（单字节 0x15）。
pub fn build_newkeys_payload() -> Bytes {
  b"\x15"
}

///|
/// 判断消息体是否为 SSH_MSG_NEWKEYS。
pub fn is_newkeys_payload(payload : Bytes) -> Bool {
  payload.length() == 1 && payload.unsafe_get(0) == SSH_MSG_NEWKEYS
}

// ============== Exchange hash ==============

///|
/// 计算 ECDH 密钥交换的交换哈希 H（RFC 5656）。
pub fn compute_ecdh_exchange_hash(
  hash_alg : @crypto.Algorithm,
  v_c : Bytes,
  v_s : Bytes,
  i_c : Bytes,
  i_s : Bytes,
  k_s : Bytes,
  q_c : Bytes,
  q_s : Bytes,
  k : Bytes,
) -> Bytes raise @crypto.CryptoError {
  let h = @crypto.Hasher::new(hash_alg)
  update_exchange_prefix(h, v_c, v_s, i_c, i_s, k_s)
  h.update(encode_string(q_c))
  h.update(encode_string(q_s))
  h.update(encode_mpint_of_bytes(k))
  h.finalize()
}

///|
/// 计算 DH 密钥交换的交换哈希 H（RFC 4253 §8）。
pub fn compute_dh_exchange_hash(
  hash_alg : @crypto.Algorithm,
  v_c : Bytes,
  v_s : Bytes,
  i_c : Bytes,
  i_s : Bytes,
  k_s : Bytes,
  e : Bytes,
  f : Bytes,
  k : Bytes,
) -> Bytes raise @crypto.CryptoError {
  let h = @crypto.Hasher::new(hash_alg)
  update_exchange_prefix(h, v_c, v_s, i_c, i_s, k_s)
  h.update(encode_mpint_of_bytes(e))
  h.update(encode_mpint_of_bytes(f))
  h.update(encode_mpint_of_bytes(k))
  h.finalize()
}

///|
fn update_exchange_prefix(
  h : @crypto.Hasher,
  v_c : Bytes,
  v_s : Bytes,
  i_c : Bytes,
  i_s : Bytes,
  k_s : Bytes,
) -> Unit raise @crypto.CryptoError {
  h.update(encode_string(v_c))
  h.update(encode_string(v_s))
  h.update(encode_string(i_c))
  h.update(encode_string(i_s))
  h.update(encode_string(k_s))
}

// ============== Key derivation (RFC 4253 §7.2) ==============

///|
/// KEX 完成后派生的会话密钥（RFC 4253 §7.2）。
/// 包含 IV、加密密钥和 MAC 密钥各一对（c2s / s2c）。
pub struct DerivedKeys {
  iv_c2s : Bytes
  iv_s2c : Bytes
  enc_key_c2s : Bytes
  enc_key_s2c : Bytes
  mac_key_c2s : Bytes
  mac_key_s2c : Bytes
}

///|
/// RFC 4253 §7.2 密钥派生：从共享密钥 K、交换哈希 H 和会话 ID 派生 6 组密钥材料。
pub fn derive_keys(
  hash_alg : @crypto.Algorithm,
  h : Bytes,
  k : Bytes,
  session_id : Bytes,
  enc_key_len : Int,
  enc_iv_len : Int,
  mac_key_len : Int,
) -> (Bytes, Bytes, Bytes, Bytes, Bytes, Bytes) raise @crypto.CryptoError {
  let iv_c2s = kdf(hash_alg, k, h, "A", session_id, enc_iv_len)
  let iv_s2c = kdf(hash_alg, k, h, "B", session_id, enc_iv_len)
  let ek_c2s = kdf(hash_alg, k, h, "C", session_id, enc_key_len)
  let ek_s2c = kdf(hash_alg, k, h, "D", session_id, enc_key_len)
  let mk_c2s = kdf(hash_alg, k, h, "E", session_id, mac_key_len)
  let mk_s2c = kdf(hash_alg, k, h, "F", session_id, mac_key_len)
  (iv_c2s, iv_s2c, ek_c2s, ek_s2c, mk_c2s, mk_s2c)
}

///|
fn kdf(
  hash_alg : @crypto.Algorithm,
  k : Bytes,
  h : Bytes,
  x : String,
  session_id : Bytes,
  needed : Int,
) -> Bytes raise @crypto.CryptoError {
  // RFC 4253 §7.2: K in KDF is the shared secret encoded as mpint.
  // This matches OpenSSH and C++ reference (appendVectBuffer).
  let k_mpint = encode_mpint_of_bytes(k)
  let x_bytes = @utf8.encode(x)
  let mut out = b""
  let mut k1 = b""
  let mut i = 0
  while out.length() < needed {
    if i == 0 {
      let h1 = @crypto.Hasher::new(hash_alg)
      h1.update(k_mpint)
      h1.update(h)
      h1.update(x_bytes)
      h1.update(session_id)
      k1 = h1.finalize()
    } else {
      let h1 = @crypto.Hasher::new(hash_alg)
      h1.update(k_mpint)
      h1.update(h)
      h1.update(k1)
      k1 = h1.finalize()
    }
    out = out + k1
    i = i + 1
  }
  if out.length() <= needed {
    return out
  }
  let arr = out.to_fixedarray()
  Bytes::from_array(FixedArray::makei(needed, i => arr.unsafe_get(i)))
}

// ============== KEX state machine ==============

///|
/// KEX 状态机状态。
pub enum KexState {
  Initial
  SentKexinit
  Negotiating
  SentDhInit
  ComputingHash
  ReadyForNewKeys
  InstallKeys
  Done
} derive(Eq, Debug)

///|
/// 密钥交换上下文，保存 KEX 过程中的所有状态和协商结果。
pub struct KexContext {
  mut state : KexState
  mut kex_alg : String
  mut host_key_alg : String
  mut enc_alg : String
  mut mac_alg : String
  mut comp_alg : String
  v_c : Bytes
  v_s : Bytes
  i_c : Bytes
  mut i_s : Bytes
  cookie : Bytes
  mut peer_host_key : Bytes
  mut exchange_hash : Bytes
  mut shared_secret : Bytes
  mut session_id : Bytes
  mut session_id_set : Bool
}

///|
/// 创建 KEX 上下文。`v_c` / `v_s` 为客户端 / 服务端版本字符串。
pub fn KexContext::new(v_c : Bytes, v_s : Bytes) -> KexContext {
  let cookie = kex_random_bytes(16)
  let i_c = build_kexinit_payload(cookie)
  {
    state: Initial,
    kex_alg: "",
    host_key_alg: "",
    enc_alg: "",
    mac_alg: "",
    comp_alg: "",
    v_c,
    v_s,
    i_c,
    i_s: b"",
    cookie,
    peer_host_key: b"",
    exchange_hash: b"",
    shared_secret: b"",
    session_id: b"",
    session_id_set: false,
  }
}

///|
fn kex_random_bytes(n : Int) -> Bytes {
  @crypto.rand_bytes(n) catch {
    _ => Bytes::make(n, b'\x00')
  }
}

///|
fn hash_alg_for_kex(alg : String) -> @crypto.Algorithm raise SshError {
  match alg {
    "diffie-hellman-group14-sha1" => @crypto.Algorithm::sha1()
    "ecdh-sha2-nistp256" | "diffie-hellman-group14-sha256" =>
      @crypto.Algorithm::sha256()
    _ => raise ProtocolError("kex: no hash for \{alg}")
  }
}

///|
fn is_ecdh_alg(alg : String) -> Bool {
  alg == "ecdh-sha2-nistp256"
}

///|
fn is_dh_alg(alg : String) -> Bool {
  alg == "diffie-hellman-group14-sha256" || alg == "diffie-hellman-group14-sha1"
}

///|
/// 执行完整的密钥交换。
/// `verify_host_key` 由 [Client::kex] 从 `HostKeyPolicy` 包装得到：
/// 校验通过则正常返回，校验失败则抛出 [HostKeyMismatch]。
pub fn KexContext::drive(
  self : KexContext,
  read_packet : () -> Bytes raise SshError,
  write_packet : (Bytes) -> Unit raise SshError,
  verify_host_key : (String, Bytes) -> Unit raise SshError,
) -> Unit raise SshError {
  if self.state != Initial {
    raise ProtocolError("kex: invalid state")
  }
  let safe_read : () -> Bytes raise SshError = () => {
    read_packet_skip_extensions(read_packet)
  }

  // 1. 发送 KEXINIT
  write_packet(self.i_c)
  self.state = SentKexinit

  // 2. 接收服务器 KEXINIT
  let server_kexinit = safe_read()
  self.i_s = server_kexinit
  let server = parse_kexinit(server_kexinit)
  debug("Server KEX algorithms: \{to_repr(server.kex_algs)}")
  debug("Server host key algs: \{to_repr(server.host_key_algs)}")
  debug("Server enc algorithms: \{to_repr(server.enc_s2c)}")
  debug("Server mac algorithms: \{to_repr(server.mac_s2c)}")
  self.state = Negotiating

  // 3. 协商算法
  self.kex_alg = match server.first() {
    Some(a) => a
    None => raise ProtocolError("kex: no matching kex algorithm")
  }
  debug("Negotiated kex_alg: \{self.kex_alg}")
  self.host_key_alg = match server.first_host_key() {
    Some(a) => a
    None => raise ProtocolError("kex: no matching host key algorithm")
  }
  debug("Negotiated host_key_alg: \{self.host_key_alg}")
  self.enc_alg = match server.first_enc() {
    Some(a) => a
    None => raise ProtocolError("kex: no matching encryption algorithm")
  }
  self.mac_alg = match server.first_mac() {
    Some(a) => a
    None => raise ProtocolError("kex: no matching mac algorithm")
  }
  self.comp_alg = match server.first_comp() {
    Some(a) => a
    None => raise ProtocolError("kex: no matching compression algorithm")
  }
  debug("Negotiated enc: \{self.enc_alg} mac: \{self.mac_alg}")

  // 4. 根据协商的 KEX 算法执行交换
  if is_ecdh_alg(self.kex_alg) {
    self.drive_ecdh(safe_read, write_packet, verify_host_key)
  } else if is_dh_alg(self.kex_alg) {
    self.drive_dh(safe_read, write_packet, verify_host_key)
  } else {
    raise ProtocolError("kex: unsupported algorithm \{self.kex_alg}")
  }
}

///|
fn KexContext::drive_ecdh(
  self : KexContext,
  read_packet : () -> Bytes raise SshError,
  write_packet : (Bytes) -> Unit raise SshError,
  verify_host_key : (String, Bytes) -> Unit raise SshError,
) -> Unit raise SshError {
  // a. 生成 ECDH 密钥对
  let (priv_key, client_pub_bytes) = @crypto.ecdh_nistp256_generate() catch {
    e => raise ProtocolError("kex: ecdh gen: \{to_repr(e)}")
  }

  // b. 发送 ECDH_INIT(Q_C)
  let ecdh_payload = build_ecdh_init_payload(client_pub_bytes)
  debug(
    "drive_ecdh: sending ECDH_INIT payload of length=\{ecdh_payload.length()}",
  )
  write_packet(ecdh_payload)
  self.state = SentDhInit

  // c. 接收 ECDH_REPLY
  debug("drive_ecdh: about to read ECDH_REPLY...")
  let raw_reply = read_packet()
  debug(
    "drive_ecdh: got ECDH_REPLY, length=\{raw_reply.length()}, msg_type=\{raw_reply.unsafe_get(0).to_int()}",
  )
  let reply = parse_ecdh_reply_payload(raw_reply)

  // d. 验证 host key
  let host_key_alg = parse_host_key_algorithm(reply.host_key)
  verify_host_key(host_key_alg, reply.host_key)
  self.peer_host_key = reply.host_key

  // e. 计算共享密钥 K
  let shared = @crypto.ecdh_nistp256_derive(priv_key, reply.server_public) catch {
    e => raise ProtocolError("kex: ecdh derive: \{to_repr(e)}")
  }
  self.shared_secret = shared

  // f. 计算交换哈希 H
  let hash_alg = hash_alg_for_kex(self.kex_alg)
  self.exchange_hash = compute_ecdh_exchange_hash(
    hash_alg,
    self.v_c,
    self.v_s,
    self.i_c,
    self.i_s,
    reply.host_key,
    client_pub_bytes,
    reply.server_public,
    shared,
  ) catch {
    e => raise ProtocolError("kex: hash: \{to_repr(e)}")
  }
  if !self.session_id_set {
    self.session_id = self.exchange_hash
    self.session_id_set = true
  }
  self.state = ComputingHash

  // g. 验证签名
  let sig_blob = parse_signature_blob(reply.signature)
  verify_host_key_signature(
    host_key_alg,
    reply.host_key,
    self.exchange_hash,
    sig_blob,
  )

  // h. 发送 NEWKEYS
  self.state = ReadyForNewKeys
  write_packet(build_newkeys_payload())

  // i. 接收服务器 NEWKEYS
  let newkeys = read_packet()
  if !is_newkeys_payload(newkeys) {
    raise ProtocolError("kex: expected NEWKEYS")
  }
  self.state = InstallKeys
  self.state = Done

  priv_key.close()
}

///|
fn KexContext::drive_dh(
  self : KexContext,
  read_packet : () -> Bytes raise SshError,
  write_packet : (Bytes) -> Unit raise SshError,
  verify_host_key : (String, Bytes) -> Unit raise SshError,
) -> Unit raise SshError {
  let p = @crypto.dh_group14_prime()
  let g = @crypto.dh_group14_generator()

  // a. 生成随机私钥 x（256 字节），确保是奇数
  let x_bytes = @crypto.rand_bytes(256) catch {
    e => raise ProtocolError("kex: rand: \{to_repr(e)}")
  }
  let x_bi = @bigint.BigInt::from_octets(x_bytes)
  let two = @bigint.BigInt::from_int(2)
  let x_bi = if x_bi % two == @bigint.BigInt::from_int(0) {
    x_bi + two
  } else {
    x_bi
  }

  // b. e = g^x mod p
  let e = g.pow(x_bi, modulus=p)

  // c. 发送 DH_INIT(e)
  let dh_payload = build_dh_init_payload(e)
  write_packet(dh_payload)
  self.state = SentDhInit

  // d. 接收 DH_REPLY
  let raw_reply = read_packet()
  let reply = parse_dh_reply_payload(raw_reply)
  let f = reply.f

  // e. 验证 host key
  let host_key_alg = parse_host_key_algorithm(reply.host_key)
  verify_host_key(host_key_alg, reply.host_key)
  self.peer_host_key = reply.host_key

  // f. K = f^x mod p
  let k = f.pow(x_bi, modulus=p)
  let k_bytes = k.to_octets()

  self.shared_secret = k_bytes

  // g. 计算 H
  let hash_alg = hash_alg_for_kex(self.kex_alg)
  let e_bytes = e.to_octets()
  let f_bytes = f.to_octets()
  self.exchange_hash = compute_dh_exchange_hash(
    hash_alg,
    self.v_c,
    self.v_s,
    self.i_c,
    self.i_s,
    reply.host_key,
    e_bytes,
    f_bytes,
    k_bytes,
  ) catch {
    e => raise ProtocolError("kex: hash: \{to_repr(e)}")
  }
  if !self.session_id_set {
    self.session_id = self.exchange_hash
    self.session_id_set = true
  }
  self.state = ComputingHash

  // h. 验证签名
  let sig_blob = parse_signature_blob(reply.signature)
  verify_host_key_signature(
    host_key_alg,
    reply.host_key,
    self.exchange_hash,
    sig_blob,
  )

  // i. 发送 NEWKEYS
  self.state = ReadyForNewKeys
  write_packet(build_newkeys_payload())

  // j. 接收 NEWKEYS
  let newkeys = read_packet()
  if !is_newkeys_payload(newkeys) {
    raise ProtocolError("kex: expected NEWKEYS")
  }
  self.state = InstallKeys
  self.state = Done
}

// ============== Skip extension messages ==============

///|
fn read_packet_skip_extensions(
  raw_read : () -> Bytes raise SshError,
) -> Bytes raise SshError {
  while true {
    let pkt = raw_read()
    if pkt.length() == 0 {
      raise ProtocolError("read_packet: empty packet")
    }
    let msg_type = pkt.unsafe_get(0).to_int()
    match msg_type {
      2 | 4 | 7 => () // IGNORE, DEBUG, EXT_INFO — skip
      1 => raise ProtocolError("kex: server sent SSH_MSG_DISCONNECT")
      _ => return pkt
    }
  }
  abort("unreachable")
}

// ============== Host key verification ==============

///|
fn verify_host_key_signature(
  alg : String,
  host_key_blob : Bytes,
  exchange_hash : Bytes,
  sig_blob : SignatureBlob,
) -> Unit raise SshError {
  let pkey = parse_host_key_to_pkey(alg, host_key_blob)
  defer pkey.close()

  let md_alg = match sig_blob.alg {
    "rsa-sha2-256" => 2 // SHA-256
    "ssh-rsa" => 1 // SHA-1
    "ssh-dss" => 1 // SHA-1
    "ecdsa-sha2-nistp256" => 2 // SHA-256
    "ecdsa-sha2-nistp384" => 3 // SHA-384
    "ecdsa-sha2-nistp521" => 4 // SHA-521
    _ =>
      raise ProtocolError(
        "kex: unsupported signature algorithm \{sig_blob.alg}",
      )
  }

  let valid = pkey.verify(md_alg, exchange_hash, sig_blob.sig) catch {
    e => raise ProtocolError("kex: verify failed: \{to_repr(e)}")
  }
  if !valid {
    raise ProtocolError("kex: host key signature is invalid")
  }
}

///|
fn parse_host_key_to_pkey(
  alg : String,
  blob : Bytes,
) -> @crypto.PKey raise SshError {
  let r = Reader::new(blob)
  let key_type = r.read_string_as_str()
  if key_type != alg {
    raise ProtocolError(
      "kex: key type mismatch: expected \{alg}, got \{key_type}",
    )
  }
  match alg {
    "ssh-rsa" | "rsa-sha2-256" => {
      let e = r.read_string()
      let n = r.read_string()
      @crypto.PKey::from_rsa_components(n, e) catch {
        e => raise ProtocolError("kex: failed to load RSA key: \{to_repr(e)}")
      }
    }
    "ssh-dss" => {
      let p = r.read_string()
      let q = r.read_string()
      let g = r.read_string()
      let y = r.read_string()
      @crypto.PKey::from_dsa_components(p, q, g, y) catch {
        e => raise ProtocolError("kex: failed to load DSA key: \{to_repr(e)}")
      }
    }
    "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
      let curve_id = r.read_string_as_str()
      let point = r.read_string()
      @crypto.PKey::from_ec_point(curve_id, point) catch {
        e => raise ProtocolError("kex: failed to load ECDSA key: \{to_repr(e)}")
      }
    }
    _ => raise ProtocolError("kex: unsupported host key \{alg}")
  }
}

// ============== Key material sizes ==============

///|
fn key_material_sizes(enc_alg : String, mac_alg : String) -> (Int, Int, Int) {
  let (key_len, iv_len) = match enc_alg {
    "aes128-ctr" => (16, 16)
    _ => (16, 16)
  }
  let mac_key_len = match mac_alg {
    "hmac-sha1" => 20
    "hmac-sha2-256" => 32
    _ => 32
  }
  (key_len, iv_len, mac_key_len)
}

///|
/// 在 KEX 完成后派生会话加密密钥。
pub fn KexContext::derive_session_keys(
  self : KexContext,
) -> DerivedKeys raise SshError {
  if self.state != Done {
    raise ProtocolError("kex: cannot derive keys, KEX not complete")
  }
  let hash_alg = hash_alg_for_kex(self.kex_alg)
  let (enc_key_len, iv_len, mac_key_len) = key_material_sizes(
    self.enc_alg,
    self.mac_alg,
  )
  let (iv_c2s, iv_s2c, ek_c2s, ek_s2c, mk_c2s, mk_s2c) = derive_keys(
    hash_alg,
    self.exchange_hash,
    self.shared_secret,
    self.session_id,
    enc_key_len,
    iv_len,
    mac_key_len,
  ) catch {
    e => raise ProtocolError("kex: key derivation failed: \{to_repr(e)}")
  }
  {
    iv_c2s,
    iv_s2c,
    enc_key_c2s: ek_c2s,
    enc_key_s2c: ek_s2c,
    mac_key_c2s: mk_c2s,
    mac_key_s2c: mk_s2c,
  }
}
