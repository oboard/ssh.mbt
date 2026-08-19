///
/// known_hosts 文件解析与主机指纹匹配（OpenSSH 格式）。

///|
/// 一个 known_hosts 条目。
pub struct KnownHost {
  patterns : Array[String]
  key_alg : String
  key : Bytes
}

///|
/// 返回该条目的公钥算法名（如 `"ssh-rsa"`）。
pub fn KnownHost::alg(self : KnownHost) -> String {
  self.key_alg
}

///|
/// 返回该条目的原始公钥字节（SSH wire 格式 blob）。
pub fn KnownHost::key_bytes(self : KnownHost) -> Bytes {
  self.key
}

///|
/// 检查条目是否匹配指定的 host:port。
pub fn KnownHost::matches(self : KnownHost, host : String, port : Int) -> Bool {
  let host_port = if port == 22 { host } else { "[\{host}]:\{port}" }
  for pat in self.patterns {
    if pattern_matches(pat, host_port) {
      return true
    }
    if pattern_matches(pat, host) {
      return true
    }
  }
  false
}

///|
/// 检查单个模式是否匹配目标主机名。
/// 不支持 hashed 形式（`|1|...`）；支持 `*` 和 `?` 通配符。
fn pattern_matches(pat : String, host : String) -> Bool {
  if pat.has_prefix("|1|") {
    return false
  } // hashed form not supported
  if !(pat.contains("*") || pat.contains("?")) {
    return pat == host
  }
  wildcard_match(pat, host)
}

///|
/// 通配符匹配：`*` 匹配任意序列，`?` 匹配单个字符。
fn wildcard_match(pat : String, s : String) -> Bool {
  let mut pi = 0
  let mut si = 0
  let mut star_pi = -1
  let mut star_si = 0
  let plen = pat.length()
  let slen = s.length()
  while si < slen {
    if pi < plen {
      let pc = pat.unsafe_get(pi)
      let sc = s.unsafe_get(si)
      if pc == '?' || pc == sc {
        pi = pi + 1
        si = si + 1
        continue
      }
      if pc == '*' {
        star_pi = pi
        star_si = si
        pi = pi + 1
        continue
      }
    }
    if star_pi >= 0 {
      pi = star_pi + 1
      star_si = star_si + 1
      si = star_si
      continue
    }
    return false
  }
  while pi < plen && pat.unsafe_get(pi) == '*' {
    pi = pi + 1
  }
  pi == plen
}

// ============== Host key verification policy ==============

///|
/// Host key 校验策略。决定服务端公钥如何被验证。
/// 默认 [Strict]：仅信任 known_hosts 中已有的条目；未知主机默认拒绝。
pub enum HostKeyPolicy {
  /// 严格模式：仅信任 known_hosts 中已有的条目。
  ///
  /// - 命中匹配条目（算法 + key 一致）→ 接受
  /// - 命中 host 模式但算法或 key 不一致 → 拒绝（[HostKeyDecision::RejectMismatch]）
  /// - 未命中任何 host 模式 → 调用 `on_unknown(host, alg, key)`，
  ///   返回 `true` 才接受；默认实现返回 `false`。
  Strict(Array[KnownHost], (String, String, Bytes) -> Bool)
  /// Trust On First Use：首次连接时记录 key 并接受；之后按 [Strict] 行为校验。
  ///
  /// - 命中匹配条目 → 接受
  /// - 命中 host 但 key 不一致 → 拒绝（MITM 警告）
  /// - 未命中 → 调用 `on_first_use(host, alg, key)`，返回 `true` 才接受，
  ///   并将 `{patterns, alg, key}` 持久化到 `entries`。
  TrustOnFirstUse(Array[KnownHost], (String, String, Bytes) -> Bool)
  /// 完全跳过 host key 校验。**仅用于受信任内网或本地回环测试**。
  /// 不推荐用于公网。
  Insecure
  /// 由调用方传入的 `(alg, key) -> Bool` 回调完全接管校验。
  /// 返回 `true` 接受；返回 `false` 时由 KEX 抛出 [HostKeyMismatch]。
  /// 适用于需要自定义指纹格式或对接外部 HSM/Trust Store 的场景。
  Callback((String, Bytes) -> Bool)
}

///|
/// Host key 校验的判定结果。KEX 阶段据此决定接受或抛 [HostKeyMismatch]。
pub enum HostKeyDecision {
  /// 校验通过，继续 KEX。
  Accept
  /// 服务端 key 与已知条目不一致（MITM 嫌疑）。
  RejectMismatch(String, Bytes)
  /// 主机不在 known_hosts 中，且 `on_unknown` 未授权。
  RejectUnknown
  /// 用户回调（`on_unknown` 或 `on_first_use`）返回 `false`。
  RejectByUser
}

///|
/// 默认未知主机处理函数：拒绝所有未知主机。
pub fn reject_unknown(_host : String, _alg : String, _key : Bytes) -> Bool {
  false
}

///|
/// 默认 TOFU 首次连接处理函数：接受并持久化。
pub fn accept_and_persist(_host : String, _alg : String, _key : Bytes) -> Bool {
  true
}

///|
/// 根据策略对服务端 host key 做最终判定。
///
/// - `host`：连接的目标主机名（如 `example.com`）
/// - `port`：端口（非 22 时按 `[host]:port` 匹配 known_hosts 模式）
/// - `alg`：服务端公钥算法（如 `ssh-rsa`、`ecdsa-sha2-nistp256`）
/// - `key`：服务端公钥原始字节
pub fn verify_host_key(
  policy : HostKeyPolicy,
  host : String,
  port : Int,
  alg : String,
  key : Bytes,
) -> HostKeyDecision {
  match policy {
    Strict(entries, on_unknown) =>
      match find_matching_entry(entries, host, port) {
        Some(entry) =>
          if entry.key_alg == alg && entry.key == key {
            Accept
          } else {
            RejectMismatch(entry.key_alg, entry.key)
          }
        None => if on_unknown(host, alg, key) { Accept } else { RejectUnknown }
      }
    TrustOnFirstUse(entries, on_first_use) =>
      match find_matching_entry(entries, host, port) {
        Some(entry) =>
          if entry.key_alg == alg && entry.key == key {
            Accept
          } else {
            RejectMismatch(entry.key_alg, entry.key)
          }
        None =>
          if on_first_use(host, alg, key) {
            entries.push({
              patterns: [host_pattern_for(host, port)],
              key_alg: alg,
              key,
            })
            Accept
          } else {
            RejectByUser
          }
      }
    Insecure => Accept
    Callback(f) => if f(alg, key) { Accept } else { RejectByUser }
  }
}

///|
/// 在条目列表中查找匹配给定 host:port 的条目。
fn find_matching_entry(
  entries : Array[KnownHost],
  host : String,
  port : Int,
) -> KnownHost? {
  for entry in entries {
    if entry.matches(host, port) {
      return Some(entry)
    }
  }
  None
}

///|
/// 生成单 host 模式字符串（端口 22 省略，否则用 `[host]:port`）。
fn host_pattern_for(host : String, port : Int) -> String {
  if port == 22 {
    host
  } else {
    "[\{host}]:\{port}"
  }
}

///|
/// 把 [HostKeyDecision] 渲染成可读的拒绝原因。
pub fn HostKeyDecision::reason(
  self : HostKeyDecision,
  host : String,
  alg : String,
) -> String {
  match self {
    Accept => "\{host} (alg=\{alg}): accepted"
    RejectMismatch(stored_alg, _) =>
      "\{host} (alg=\{alg}): key changed, stored=\{stored_alg} — possible MITM"
    RejectUnknown =>
      "\{host} (alg=\{alg}): not in known_hosts and policy rejects unknown hosts"
    RejectByUser => "\{host} (alg=\{alg}): rejected by user callback"
  }
}

// ============== Parsing ==============

///|
/// 解析 known_hosts 文件的一行，返回 [KnownHost] 条目。
/// 跳过空行和注释行；格式为 `hostnames algorithm base64-key`。
pub fn parse_line(line : String) -> KnownHost? raise SshError {
  let trimmed = trim_ascii(line)
  if trimmed.length() == 0 || trimmed.unsafe_get(0) == '#' {
    return None
  }
  let parts = trimmed.split(" ")
  let arr : Array[String] = []
  for v in parts {
    arr.push(v.to_owned())
  }
  if arr.length() < 3 {
    return None
  }
  let patterns = []
  for p in arr[0].split(",") {
    let s = p.to_owned()
    if s.length() > 0 {
      patterns.push(s)
    }
  }
  let key_alg = arr[1]
  let key = decode_base64(arr[2]) catch {
    e => raise ProtocolError("known_hosts: base64: \{Repr(e)}")
  }
  Some({ patterns, key_alg, key })
}

///|
/// 解析整个 known_hosts 文件内容，返回所有有效条目。
pub fn parse_file(content : String) -> Array[KnownHost] raise SshError {
  let out : Array[KnownHost] = []
  for line in content.split("\n") {
    match parse_line(line.to_owned()) {
      Some(entry) => out.push(entry)
      None => ()
    }
  }
  out
}

///|
/// 将条目序列化为 known_hosts 格式字符串（`hostnames algorithm base64-key`）。
pub fn KnownHost::format_entry(self : KnownHost) -> String {
  let pats = self.patterns.join(",")
  let key_b64 = encode_base64(self.key)
  "\{pats} \{self.key_alg} \{key_b64}"
}

// ============== Base64 ==============

///|
/// 标准 Base64 解码（RFC 4648），忽略空白和 `=` 填充。
pub fn decode_base64(s : String) -> Bytes raise SshError {
  let table = make_b64_decode_table()
  let mut buf = b""
  let mut n = 0
  let mut bits = 0
  for c in s {
    if c == '=' || c == '\n' || c == '\r' || c == ' ' {
      continue
    }
    let v = match table.get(c) {
      Some(x) => x
      None => raise ProtocolError("base64: invalid char '\{c}'")
    }
    n = (n << 6) | v
    bits = bits + 6
    if bits >= 8 {
      bits = bits - 8
      let byte = ((n >> bits) & 0xff).to_byte()
      buf = buf + Bytes::from_array([byte])
      n = n & ((1 << bits) - 1)
    }
  }
  buf
}

///|
/// 标准 Base64 编码（RFC 4648）。
pub fn encode_base64(bytes : Bytes) -> String {
  let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  let arr = bytes.to_fixedarray()
  let mut out = ""
  let len = arr.length()
  let mut i = 0
  while i + 2 < len {
    let b0 = arr.unsafe_get(i).to_int()
    let b1 = arr.unsafe_get(i + 1).to_int()
    let b2 = arr.unsafe_get(i + 2).to_int()
    out = out +
      alphabet.unsafe_get((b0 >> 2) & 0x3f).unsafe_to_char().to_string() +
      alphabet
      .unsafe_get(((b0 << 4) | (b1 >> 4)) & 0x3f)
      .unsafe_to_char()
      .to_string() +
      alphabet
      .unsafe_get(((b1 << 2) | (b2 >> 6)) & 0x3f)
      .unsafe_to_char()
      .to_string() +
      alphabet.unsafe_get(b2 & 0x3f).unsafe_to_char().to_string()
    i = i + 3
  }
  if i < len {
    let b0 = arr.unsafe_get(i).to_int()
    out = out +
      alphabet.unsafe_get((b0 >> 2) & 0x3f).unsafe_to_char().to_string()
    if i + 1 < len {
      let b1 = arr.unsafe_get(i + 1).to_int()
      out = out +
        alphabet
        .unsafe_get(((b0 << 4) | (b1 >> 4)) & 0x3f)
        .unsafe_to_char()
        .to_string() +
        alphabet.unsafe_get((b1 << 2) & 0x3f).unsafe_to_char().to_string() +
        "="
    } else {
      out = out +
        alphabet.unsafe_get((b0 << 4) & 0x3f).unsafe_to_char().to_string() +
        "=="
    }
  }
  out
}

///|
/// 构建 Base64 字符到 6 位值的查找表。
fn make_b64_decode_table() -> Map[Char, Int] {
  let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  let m : Map[Char, Int] = Map([])
  let mut i = 0
  while i < 64 {
    m.set(alphabet.unsafe_get(i).unsafe_to_char(), i)
    i = i + 1
  }
  m
}

///|
/// 去除字符串首尾的 ASCII 空白字符（空格、制表符、换行符、回车符）。
fn trim_ascii(s : String) -> String {
  let arr = s.to_array()
  let mut start = 0
  let mut end = arr.length()
  while start < end {
    let c = arr.unsafe_get(start)
    if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
      start = start + 1
    } else {
      break
    }
  }
  while end > start {
    let c = arr.unsafe_get(end - 1)
    if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
      end = end - 1
    } else {
      break
    }
  }
  let sb = StringBuilder::new()
  for i = start; i < end; i = i + 1 {
    sb.write_char(arr.unsafe_get(i))
  }
  sb.to_string()
}
