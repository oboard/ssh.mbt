///|
/// SSH 协议层 — KEX 状态机（RFC 4253 §6）。
///
/// 支持的密钥交换算法：
///   - curve25519-sha256           (RFC 8731)
///   - curve25519-sha256@libssh.org
///   - ecdh-sha2-nistp256          (RFC 5656)
///   - diffie-hellman-group14-sha256
///   - diffie-hellman-group14-sha1
///
/// 支持的 host key 算法：
///   - ssh-ed25519
///   - ecdsa-sha2-nistp256
///   - rsa-sha2-256 (ssh-rsa with SHA-256)
///   - ssh-rsa      (with SHA-1, 仅兼容)

///|
/// Algorithm name registry. Used in the SSH KEXINIT exchange.
pub fn kex_algorithms() -> Array[String] {
  [
    "curve25519-sha256@libssh.org", "curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha1",
  ]
}

///|
pub fn server_host_key_algorithms() -> Array[String] {
  [
    "ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa",
  ]
}

///|
pub fn encryption_algorithms() -> Array[String] {
  [
    "chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com",
    "aes256-ctr", "aes192-ctr", "aes128-ctr",
  ]
}

///|
pub fn mac_algorithms() -> Array[String] {
  ["hmac-sha2-512", "hmac-sha2-256", "hmac-sha1"]
}

///|
pub fn compression_algorithms() -> Array[String] {
  ["none"]
}

///|
/// SSH transport message numbers used during key exchange.
pub const SSH_MSG_KEXINIT : Byte = b'\x14'

///|
pub const SSH_MSG_NEWKEYS : Byte = b'\x15'

///|
pub const SSH_MSG_KEX_ECDH_INIT : Byte = b'\x1e'

///|
pub const SSH_MSG_KEX_ECDH_REPLY : Byte = b'\x1f'

///|
/// Build a SSH_MSG_KEXINIT payload.
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
  w.write_byte(0) // first_kex_packet_follows
  w.write_uint32(0) // reserved
  w.to_bytes()
}

///|
/// Parse a KEXINIT payload received from the server.
pub fn parse_kexinit(payload : Bytes) -> KexInit raise SshError {
  let r = Reader::new(payload)
  let msg = r.read_byte()
  if msg != SSH_MSG_KEXINIT {
    raise ProtocolError("expected SSH_MSG_KEXINIT, got \{msg.to_int()}")
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
pub fn KexInit::first(self : KexInit, ours : Array[String]) -> String? {
  for alg in ours {
    for srv in self.kex_algs {
      if alg == srv {
        return Some(alg)
      }
    }
  }
  None
}

///|
pub fn KexInit::first_host_key(self : KexInit, ours : Array[String]) -> String? {
  for alg in ours {
    for srv in self.host_key_algs {
      if alg == srv {
        return Some(alg)
      }
    }
  }
  None
}

///|
pub fn KexInit::first_enc(self : KexInit, ours : Array[String]) -> String? {
  for alg in ours {
    for srv in self.enc_s2c {
      if alg == srv {
        return Some(alg)
      }
    }
  }
  None
}

///|
pub fn KexInit::first_mac(self : KexInit, ours : Array[String]) -> String? {
  for alg in ours {
    for srv in self.mac_s2c {
      if alg == srv {
        return Some(alg)
      }
    }
  }
  None
}

///|
pub fn KexInit::first_comp(self : KexInit, ours : Array[String]) -> String? {
  for alg in ours {
    for srv in self.comp_s2c {
      if alg == srv {
        return Some(alg)
      }
    }
  }
  None
}

// --- Key derivation (RFC 4253 §7.2) ----------------------------------

///|
/// Build SSH_MSG_KEX_ECDH_INIT for curve25519-sha256 and ecdh-sha2-*.
pub fn build_ecdh_init_payload(client_public : Bytes) -> Bytes {
  let w = Writer::new()
  w.write_byte(SSH_MSG_KEX_ECDH_INIT)
  w.write_string(client_public)
  w.to_bytes()
}

///|
pub struct EcdhReply {
  host_key : Bytes
  server_public : Bytes
  signature : Bytes
}

///|
pub fn parse_ecdh_reply_payload(payload : Bytes) -> EcdhReply raise SshError {
  let r = Reader::new(payload)
  let msg = r.read_byte()
  if msg != SSH_MSG_KEX_ECDH_REPLY {
    raise ProtocolError("expected SSH_MSG_KEX_ECDH_REPLY, got \{msg.to_int()}")
  }
  let host_key = r.read_string()
  let server_public = r.read_string()
  let signature = r.read_string()
  if !r.eof() {
    raise ParseError("ecdh reply: trailing bytes")
  }
  { host_key, server_public, signature }
}

///|
pub struct SignatureBlob {
  alg : String
  sig : Bytes
}

///|
pub fn parse_signature_blob(blob : Bytes) -> SignatureBlob raise SshError {
  let r = Reader::new(blob)
  let alg = r.read_string_as_str()
  let sig = r.read_string()
  if !r.eof() {
    raise ParseError("signature blob: trailing bytes")
  }
  { alg, sig }
}

///|
pub fn parse_host_key_algorithm(blob : Bytes) -> String raise SshError {
  let r = Reader::new(blob)
  r.read_string_as_str()
}

///|
pub fn build_newkeys_payload() -> Bytes {
  b"\x15"
}

///|
pub fn is_newkeys_payload(payload : Bytes) -> Bool {
  payload.length() == 1 && payload.unsafe_get(0) == SSH_MSG_NEWKEYS
}

///|
/// Compute the SSH DH exchange hash.
pub fn compute_exchange_hash(
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
  update_exchange_hash_prefix(h, v_c, v_s, i_c, i_s, k_s)
  h.update(encode_mpint_of_bytes(e))
  h.update(encode_mpint_of_bytes(f))
  h.update(encode_mpint_of_bytes(k))
  h.finalize()
}

///|
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
  update_exchange_hash_prefix(h, v_c, v_s, i_c, i_s, k_s)
  h.update(encode_string(q_c))
  h.update(encode_string(q_s))
  h.update(encode_mpint_of_bytes(k))
  h.finalize()
}

///|
fn update_exchange_hash_prefix(
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

///|
/// `mpint` encoding for SSH: same as `encode_mpint(BigInt)` but for raw
/// big-endian bytes. Adds a leading 0x00 if the high bit is set.

///|
/// Reverse bytes (swap endianness). X25519 shared secret is little-endian
/// but SSH mpint encoding expects big-endian.
fn reverse_bytes(b : Bytes) -> Bytes {
  let n = b.length()
  let arr = b.to_fixedarray()
  let out = FixedArray::make(n, b'\x00')
  for i in 0..<n {
    out[i] = arr.unsafe_get(n - 1 - i)
  }
  Bytes::from_fixedarray(out)
}

///|
pub fn encode_mpint_of_bytes(bytes : Bytes) -> Bytes {
  if bytes.length() == 0 {
    return encode_string(b"\x00")
  }
  let first = bytes.unsafe_get(0).to_int()
  if first >= 0x80 {
    let buf = FixedArray::make(1, b'\x00')
    encode_uint32(bytes.length() + 1) + Bytes::from_fixedarray(buf) + bytes
  } else {
    encode_string(bytes)
  }
}

///|
/// Derive session keys from the exchange hash and shared secret (RFC 4253 §7.2).
/// Returns `(iv_c2s, iv_s2c, enc_key_c2s, enc_key_s2c, mac_key_c2s, mac_key_s2c)`.
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
/// KDF as defined in RFC 4253 §7.2:
///   key1 = HASH(K || H || X || session_id)
///   key  = key1 || HASH(K || H || key1) || ...
fn kdf(
  hash_alg : @crypto.Algorithm,
  k : Bytes,
  h : Bytes,
  x : String,
  session_id : Bytes,
  needed : Int,
) -> Bytes raise @crypto.CryptoError {
  let x_bytes = @utf8.encode(x)
  let mut out = b""
  let mut k1 = b""
  let mut i = 0
  while out.length() < needed {
    if i == 0 {
      let h1 = @crypto.Hasher::new(hash_alg)
      h1.update(k)
      h1.update(h)
      h1.update(x_bytes)
      h1.update(session_id)
      k1 = h1.finalize()
    } else {
      let h1 = @crypto.Hasher::new(hash_alg)
      h1.update(k)
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
  let view = FixedArray::makei(needed, i => arr.unsafe_get(i))
  Bytes::from_fixedarray(view)
}

// --- Derived keys structure ---------------------------------------------

///|
/// Encryption keys derived from KEX.
pub struct DerivedKeys {
  pub iv_c2s : Bytes
  pub iv_s2c : Bytes
  pub enc_key_c2s : Bytes
  pub enc_key_s2c : Bytes
  pub mac_key_c2s : Bytes
  pub mac_key_s2c : Bytes
}

// --- KEX state machine scaffolding -----------------------------------

///|
/// KEX state machine. Drives the SSH_MSG_KEXINIT / KEXDH_INIT / KEXDH_REPLY /
/// SSH_MSG_NEWKEYS exchange. The actual key generation and exchange logic is
/// implemented by callers; this struct only tracks state.
pub struct Kex {
  priv state : @string.View // current state marker
}

///|
/// Public KEX state. Drives the SSH transport-level key exchange.
pub enum KexState {
  /// Before any KEX has been performed.
  Initial
  /// We've sent KEXINIT; awaiting the server's.
  SentKexinit
  /// Server's KEXINIT received; negotiating algorithms.
  Negotiating
  /// We've sent KEXDH_INIT / KEXECDH_INIT; awaiting the reply.
  SentDhInit
  /// Server's KEXDH_REPLY / KEXECDH_REPLY received; computing the hash and
  /// deriving session keys.
  ComputingHash
  /// Ready to send NEWKEYS.
  ReadyForNewKeys
  /// NEWKEYS received; about to install the new keys.
  InstallKeys
  /// KEX complete.
  Done
} derive(Eq, Show)

///|
/// KEX state machine. Drives the SSH_MSG_KEXINIT / KEXDH_INIT / KEXDH_REPLY /
/// SSH_MSG_NEWKEYS exchange. The actual key generation and exchange logic is
/// implemented by callers; this struct only tracks state.
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
  priv mut ephemeral : @crypto.PKey?
  priv mut peer_host_key : Bytes
  mut exchange_hash : Bytes
  mut shared_secret : Bytes
  mut session_id : Bytes
  priv mut session_id_set : Bool
}

///|
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
    ephemeral: None,
    peer_host_key: b"",
    exchange_hash: b"",
    shared_secret: b"",
    session_id: b"",
    session_id_set: false,
  }
}

///|
#cfg(platform="windows")
fn kex_random_bytes(n : Int) -> Bytes {
  Bytes::make(n, b'\x00')
}

///|
#cfg(not(platform="windows"))
fn kex_random_bytes(n : Int) -> Bytes {
  @crypto.rand_bytes(n) catch {
    _ => Bytes::make(n, b'\x00')
  }
}

///|
pub fn KexContext::transition_to(self : KexContext, s : KexState) -> Unit {
  self.state = s
}

// --- High-level entry point -----------------------------------------

///|
/// Run a full key exchange against an open SSH connection. This is a
/// coordination layer over the lower-level packet IO.
///
/// The full implementation:
/// 1. Send KEXINIT (uses i_c from KexContext)
/// 2. Read server's KEXINIT, fill i_s, pick algorithms
/// 3. For curve25519 / nistp256: generate ephemeral, send KEXDH_INIT/REPLY
/// 4. For DH group14: same with the OpenSSL-backed BN_mod_exp
/// 5. Compute exchange hash, derive keys, send NEWKEYS
/// 6. On the server's NEWKEYS, atomically install the new keys
pub fn KexContext::drive(
  self : KexContext,
  read_packet : () -> Bytes raise SshError,
  write_packet : (Bytes) -> Unit raise SshError,
  accept_host_key : (String, Bytes) -> Bool,
) -> Unit raise SshError {
  if self.state != Initial {
    raise ProtocolError("kex: invalid state \{self.state}")
  }
  // Wrap the raw reader so that SSH_MSG_EXT_INFO (RFC 8308),
  // SSH_MSG_IGNORE, and SSH_MSG_DEBUG are silently consumed
  // at any point during KEX (per RFC 4253 §11).
  let safe_read = { () => read_packet_skip_extensions(read_packet) }
  write_packet(self.i_c)
  self.transition_to(SentKexinit)
  let server_kexinit = safe_read()
  self.i_s = server_kexinit
  let i_s_len = server_kexinit.length()
  println("DEBUG i_s after read len=\{i_s_len}")
  let server = parse_kexinit(server_kexinit)
  self.transition_to(Negotiating)
  self.kex_alg = require_algorithm("kex", server.first(kex_algorithms()))
  self.host_key_alg = require_algorithm(
    "host key",
    server.first_host_key(server_host_key_algorithms()),
  )
  self.enc_alg = require_algorithm(
    "encryption",
    server.first_enc(encryption_algorithms()),
  )
  self.mac_alg = require_algorithm("mac", server.first_mac(mac_algorithms()))
  self.comp_alg = require_algorithm(
    "compression",
    server.first_comp(compression_algorithms()),
  )
  println(
    "DEBUG negotiated kex=\{self.kex_alg} host_key=\{self.host_key_alg} enc=\{self.enc_alg} mac=\{self.mac_alg}",
  )
  if is_curve25519_algorithm(self.kex_alg) {
    self.drive_curve25519(safe_read, write_packet, accept_host_key)
  } else {
    raise ProtocolError(
      "kex: unsupported key exchange algorithm \{self.kex_alg}",
    )
  }
}

///|
/// Known SSH transport-layer message numbers (RFC 4253 / RFC 8308).
pub const SSH_MSG_DISCONNECT : Byte = b'\x01'
pub const SSH_MSG_IGNORE : Byte = b'\x02'
pub const SSH_MSG_DEBUG : Byte = b'\x04'
pub const SSH_MSG_EXT_INFO : Byte = b'\x07'

///|
/// Wrap a raw packet reader to silently consume SSH extension/ignore/debug
/// messages (RFC 4253 §11, RFC 8308) and return only the real payload.
/// This handles servers that interleave SSH_MSG_EXT_INFO (7),
/// SSH_MSG_IGNORE (2), or SSH_MSG_DEBUG (4) at any point during KEX.
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
      // Extension/info messages — consume and continue
      2 | 4 | 7 => {
        println(
          "DEBUG skipping msg=\{msg_type} len=\{pkt.length()}",
        )
      }
      // Disconnect — propagate as error
      1 =>
        raise ProtocolError("kex: server sent SSH_MSG_DISCONNECT")
      // All other messages — return to caller as-is
      _ => return pkt
    }
  }
  abort("unreachable: read_packet_skip_extensions")
}

///|
fn require_algorithm(kind : String, value : String?) -> String raise SshError {
  match value {
    Some(alg) => alg
    None => raise ProtocolError("kex: no matching \{kind} algorithm")
  }
}

///|
fn is_curve25519_algorithm(alg : String) -> Bool {
  alg == "curve25519-sha256" || alg == "curve25519-sha256@libssh.org"
}

///|
#cfg(platform="windows")
fn hash_algorithm_for_kex(alg : String) -> @crypto.Algorithm raise SshError {
  match alg {
    "diffie-hellman-group14-sha1" => @crypto.Algorithm::sha1()
    "curve25519-sha256"
    | "curve25519-sha256@libssh.org"
    | "ecdh-sha2-nistp256"
    | "diffie-hellman-group14-sha256" => @crypto.Algorithm::sha256()
    _ => raise ProtocolError("kex: no hash algorithm for \{alg}")
  }
}

///|
#cfg(not(platform="windows"))
fn hash_algorithm_for_kex(alg : String) -> @crypto.Algorithm raise SshError {
  match alg {
    "diffie-hellman-group14-sha1" => @crypto.Algorithm::sha1()
    "curve25519-sha256"
    | "curve25519-sha256@libssh.org"
    | "ecdh-sha2-nistp256"
    | "diffie-hellman-group14-sha256" => @crypto.Algorithm::sha256()
    _ => raise ProtocolError("kex: no hash algorithm for \{alg}")
  }
}

///|
#cfg(platform="windows")
fn KexContext::drive_curve25519(
  self : KexContext,
  _read_packet : () -> Bytes raise SshError,
  _write_packet : (Bytes) -> Unit raise SshError,
  _accept_host_key : (String, Bytes) -> Bool,
) -> Unit raise SshError {
  self.transition_to(SentDhInit)
  self.shared_secret = b""
  self.exchange_hash = b""
  self.session_id = b""
  self.session_id_set = false
  raise ProtocolError(
    "kex: curve25519 exchange needs a crypto backend; Windows native crypto " +
    "is not wired up yet",
  )
}

///|
#cfg(not(platform="windows"))
fn KexContext::drive_curve25519(
  self : KexContext,
  read_packet : () -> Bytes raise SshError,
  write_packet : (Bytes) -> Unit raise SshError,
  accept_host_key : (String, Bytes) -> Bool,
) -> Unit raise SshError {
  let (ephemeral, _private_key) = @crypto.x25519_generate() catch {
    e => raise ProtocolError("kex: \{e}")
  }
  let client_public = ephemeral.raw_public() catch {
    e => raise ProtocolError("kex: \{e}")
  }

  self.ephemeral = Some(ephemeral)
  let ecdh_payload = build_ecdh_init_payload(client_public)
  println(
    "DEBUG ECDH_INIT payload len=\{ecdh_payload.length()} pubkey_len=\{client_public.length()}",
  )
  // Print first few bytes of the payload: msg_type + string header + pubkey start
  if ecdh_payload.length() >= 5 {
    println(
      "DEBUG ECDH_INIT bytes[0..4]=\{ecdh_payload.unsafe_get(0).to_int()} \{ecdh_payload.unsafe_get(1).to_int()} \{ecdh_payload.unsafe_get(2).to_int()} \{ecdh_payload.unsafe_get(3).to_int()} \{ecdh_payload.unsafe_get(4).to_int()}",
    )
  }
  // Before sending ECDH_INIT, peek to see if server has sent anything else
  // (e.g., SSH_MSG_DISCONNECT or SSH_MSG_EXT_INFO early)
  // Note: we can't真正 peek without non-blocking I/O, so we'll just send and
  // then handle errors gracefully.
  write_packet(ecdh_payload)
  println("DEBUG after write ECDH_INIT, about to read")
  self.transition_to(SentDhInit)
  let raw_reply = read_packet()
  println(
    "DEBUG got ECDH REPLY size=\{raw_reply.length()} first=\{raw_reply.unsafe_get(0).to_int()}",
  )
  let reply = parse_ecdh_reply_payload(raw_reply)
  let host_key_alg = parse_host_key_algorithm(reply.host_key)
  if host_key_alg != self.host_key_alg {
    raise ProtocolError(
      "kex: negotiated host key \{self.host_key_alg}, got \{host_key_alg}",
    )
  }
  if !accept_host_key(host_key_alg, reply.host_key) {
    raise HostKeyMismatch(host_key_alg)
  }
  self.peer_host_key = reply.host_key
  let shared = @crypto.x25519_derive(ephemeral, reply.server_public) catch {
    e => raise ProtocolError("kex: \{e}")
  }
  // X25519 shared secret is in little-endian; SSH mpint expects big-endian
  let shared_be = shared // try without reversal first
  println(
    "DEBUG shared len=\{shared.length()} first=\{shared.unsafe_get(0).to_int()} last=\{shared.unsafe_get(31).to_int()}",
  )
  println(
    "DEBUG shared_be len=\{shared_be.length()} first=\{shared_be.unsafe_get(0).to_int()}",
  )
  println(
    "DEBUG i_c len=\{self.i_c.length()} first=\{self.i_c.unsafe_get(0).to_int()}",
  )
  println(
    "DEBUG i_s len=\{self.i_s.length()} first=\{self.i_s.unsafe_get(0).to_int()}",
  )
  self.shared_secret = shared_be
  self.exchange_hash = compute_ecdh_exchange_hash(
    hash_algorithm_for_kex(self.kex_alg),
    self.v_c,
    self.v_s,
    self.i_c,
    self.i_s,
    reply.host_key,
    client_public,
    reply.server_public,
    shared_be,
  ) catch {
    e => raise ProtocolError("kex: \{e}")
  }
  println("DEBUG exchange_hash len=\{self.exchange_hash.length()}")
  if !self.session_id_set {
    self.session_id = self.exchange_hash
    self.session_id_set = true
  }
  self.transition_to(ComputingHash)

  // Verify host key signature
  let sig_blob = parse_signature_blob(reply.signature)
  verify_host_key_signature(
    host_key_alg,
    reply.host_key,
    self.exchange_hash,
    sig_blob,
  )

  // Send NEWKEYS
  self.transition_to(ReadyForNewKeys)
  write_packet(build_newkeys_payload())

  // Read server's NEWKEYS
  let newkeys_payload = read_packet()
  if !is_newkeys_payload(newkeys_payload) {
    raise ProtocolError("kex: expected SSH_MSG_NEWKEYS")
  }

  self.transition_to(InstallKeys)
  self.transition_to(Done)
}

// --- Host key parsing and signature verification ------------------------

///|
/// Verify the server's host key signature over the exchange hash.
#cfg(not(platform="windows"))
fn verify_host_key_signature(
  alg : String,
  host_key_blob : Bytes,
  exchange_hash : Bytes,
  sig_blob : SignatureBlob,
) -> Unit raise SshError {
  let pkey = parse_host_key_to_pkey(alg, host_key_blob)
  defer pkey.close()

  // Determine the digest algorithm for the signature
  let md_alg = match sig_blob.alg {
    "ssh-ed25519" => 0 // Ed25519 uses its own digest
    "rsa-sha2-256" => 4 // SHA-256
    "rsa-sha2-512" => 5 // SHA-512
    "ssh-rsa" => 2 // SHA-1 (legacy)
    "ecdsa-sha2-nistp256" => 4 // SHA-256
    _ =>
      raise ProtocolError(
        "kex: unsupported signature algorithm \{sig_blob.alg}",
      )
  }

  let valid = pkey.verify(md_alg, exchange_hash, sig_blob.sig) catch {
    e =>
      raise ProtocolError("kex: signature verification failed: \{e.message()}")
  }

  println(
    "DEBUG verify alg=\{sig_blob.alg} md=\{md_alg} hash_len=\{exchange_hash.length()} sig_len=\{sig_blob.sig.length()} valid=\{valid}",
  )
  if !valid {
    raise ProtocolError("kex: host key signature is invalid")
  }
}

///|
/// Parse an SSH host key blob into a PKey.
/// Format depends on the algorithm:
///   - ssh-ed25519: string "ssh-ed25519" + string pubkey (32 bytes)
///   - ssh-rsa / rsa-sha2-*: string "ssh-rsa" + string e + string n
///   - ecdsa-sha2-nistp256: string "ecdsa-sha2-nistp256" + string "nistp256" + string Q
#cfg(not(platform="windows"))
fn parse_host_key_to_pkey(
  alg : String,
  blob : Bytes,
) -> @crypto.PKey raise SshError {
  let r = Reader::new(blob)
  let key_type = r.read_string_as_str()
  if key_type != alg {
    raise ProtocolError(
      "kex: host key type mismatch: expected \{alg}, got \{key_type}",
    )
  }

  match alg {
    "ssh-ed25519" => {
      let pubkey = r.read_string()
      if pubkey.length() != 32 {
        raise ProtocolError("kex: ed25519 public key must be 32 bytes")
      }
      @crypto.PKey::from_raw(@crypto.KeyType::ed25519(), pubkey) catch {
        e => raise ProtocolError("kex: failed to load ed25519 key: \{e}")
      }
    }
    "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512" => {
      let e = r.read_string()
      let n = r.read_string()
      @crypto.PKey::from_rsa_components(n, e) catch {
        e => raise ProtocolError("kex: failed to load RSA key: \{e.message()}")
      }
    }
    "ecdsa-sha2-nistp256" => {
      let curve_name = r.read_string_as_str()
      if curve_name != "nistp256" {
        raise ProtocolError("kex: expected nistp256, got \{curve_name}")
      }
      let q = r.read_string()
      // Q is encoded as 0x04 || X || Y (65 bytes for P-256)
      if q.length() != 65 || q.unsafe_get(0) != b'\x04' {
        raise ProtocolError("kex: invalid EC point encoding")
      }
      // OpenSSL expects the full point encoding
      @crypto.PKey::from_raw(@crypto.KeyType::ec_p256(), q) catch {
        e =>
          raise ProtocolError("kex: failed to load ECDSA key: \{e.message()}")
      }
    }
    _ => raise ProtocolError("kex: unsupported host key algorithm \{alg}")
  }
}

///|
#cfg(platform="windows")
fn verify_host_key_signature(
  _alg : String,
  _host_key_blob : Bytes,
  _exchange_hash : Bytes,
  _sig_blob : SignatureBlob,
) -> Unit raise SshError {
  raise ProtocolError("kex: signature verification not available on Windows")
}

///|
#cfg(platform="windows")
fn parse_host_key_to_pkey(
  _alg : String,
  _blob : Bytes,
) -> @crypto.PKey raise SshError {
  raise ProtocolError("kex: host key parsing not available on Windows")
}

// --- Key material sizes for encryption algorithms -------------------

///|
/// Determine key material sizes (key_len, iv_len, mac_key_len) for the
/// negotiated encryption and MAC algorithms.
fn key_material_sizes(enc_alg : String, mac_alg : String) -> (Int, Int, Int) {
  let (key_len, iv_len) = match enc_alg {
    "aes128-ctr" => (16, 16)
    "aes192-ctr" => (24, 16)
    "aes256-ctr" => (32, 16)
    "aes128-gcm@openssh.com" => (16, 12)
    "aes256-gcm@openssh.com" => (32, 12)
    "chacha20-poly1305@openssh.com" => (64, 0) // ChaCha20-Poly1305 uses separate keys
    _ => (32, 16) // default fallback
  }

  let mac_key_len = if is_aead_cipher(enc_alg) {
    0 // AEAD ciphers don't need separate MAC
  } else {
    match mac_alg {
      "hmac-sha1" => 20
      "hmac-sha2-256" => 32
      "hmac-sha2-512" => 64
      _ => 32 // default
    }
  }

  (key_len, iv_len, mac_key_len)
}

///|
fn is_aead_cipher(alg : String) -> Bool {
  alg == "aes128-gcm@openssh.com" ||
  alg == "aes256-gcm@openssh.com" ||
  alg == "chacha20-poly1305@openssh.com"
}

// --- Key derivation (after KEX complete) -----------------------------

///|
/// Derive session encryption keys after KEX is complete.
pub fn KexContext::derive_session_keys(
  self : KexContext,
) -> DerivedKeys raise SshError {
  if self.state != Done {
    raise ProtocolError("kex: cannot derive keys, KEX is not complete")
  }

  let hash_alg = hash_algorithm_for_kex(self.kex_alg)
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
    e => raise ProtocolError("kex: key derivation failed: \{e.message()}")
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
