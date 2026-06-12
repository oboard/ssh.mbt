///
/// known_hosts 文件解析与主机指纹匹配（OpenSSH 格式）。

///
/// 一个 known_hosts 条目。
pub struct KnownHost {
  patterns : Array[String]
  key_alg : String
  key : Bytes
}

pub fn KnownHost::alg(self : KnownHost) -> String { self.key_alg }
pub fn KnownHost::key_bytes(self : KnownHost) -> Bytes { self.key }

///
/// 检查条目是否匹配指定的 host:port。
pub fn KnownHost::matches(self : KnownHost, host : String, port : Int) -> Bool {
  let host_port = if port == 22 { host } else { "[\{host}]:\{port}" }
  for pat in self.patterns {
    if pattern_matches(pat, host_port) { return true }
    if pattern_matches(pat, host) { return true }
  }
  false
}

fn pattern_matches(pat : String, host : String) -> Bool {
  if pat.has_prefix("|1|") { return false } // hashed form not supported
  if not(pat.contains("*") || pat.contains("?")) { return pat == host }
  wildcard_match(pat, host)
}

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
      if pc == '?' || pc == sc { pi = pi + 1; si = si + 1; continue }
      if pc == '*' { star_pi = pi; star_si = si; pi = pi + 1; continue }
    }
    if star_pi >= 0 { pi = star_pi + 1; star_si = star_si + 1; si = star_si; continue }
    return false
  }
  while pi < plen && pat.unsafe_get(pi) == '*' { pi = pi + 1 }
  pi == plen
}

// ============== Parsing ==============

pub fn parse_line(line : String) -> KnownHost? raise SshError {
  let trimmed = trim_ascii(line)
  if trimmed.length() == 0 || trimmed.unsafe_get(0) == '#' { return None }
  let parts = trimmed.split(" ")
  let arr : Array[String] = []
  for v in parts { arr.push(v.to_string()) }
  if arr.length() < 3 { return None }
  let patterns = []
  for p in arr[0].split(",") {
    let s = p.to_string()
    if s.length() > 0 { patterns.push(s) }
  }
  let key_alg = arr[1]
  let key = decode_base64(arr[2]) catch {
    e => raise ProtocolError("known_hosts: base64: \{e}")
  }
  Some({ patterns, key_alg, key })
}

pub fn parse_file(content : String) -> Array[KnownHost] raise SshError {
  let out : Array[KnownHost] = []
  for line in content.split("\n") {
    match parse_line(line.to_string()) {
      Some(entry) => out.push(entry)
      None => ()
    }
  }
  out
}

pub fn KnownHost::format_entry(self : KnownHost) -> String {
  let pats = self.patterns.join(",")
  let key_b64 = encode_base64(self.key)
  "\{pats} \{self.key_alg} \{key_b64}"
}

// ============== Base64 ==============

pub fn decode_base64(s : String) -> Bytes raise SshError {
  let table = make_b64_decode_table()
  let mut buf = b""
  let mut n = 0
  let mut bits = 0
  for c in s {
    if c == '=' || c == '\n' || c == '\r' || c == ' ' { continue }
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
      alphabet.unsafe_get(((b0 << 4) | (b1 >> 4)) & 0x3f).unsafe_to_char().to_string() +
      alphabet.unsafe_get(((b1 << 2) | (b2 >> 6)) & 0x3f).unsafe_to_char().to_string() +
      alphabet.unsafe_get(b2 & 0x3f).unsafe_to_char().to_string()
    i = i + 3
  }
  if i < len {
    let b0 = arr.unsafe_get(i).to_int()
    out = out + alphabet.unsafe_get((b0 >> 2) & 0x3f).unsafe_to_char().to_string()
    if i + 1 < len {
      let b1 = arr.unsafe_get(i + 1).to_int()
      out = out +
        alphabet.unsafe_get(((b0 << 4) | (b1 >> 4)) & 0x3f).unsafe_to_char().to_string() +
        alphabet.unsafe_get((b1 << 2) & 0x3f).unsafe_to_char().to_string() + "="
    } else {
      out = out + alphabet.unsafe_get((b0 << 4) & 0x3f).unsafe_to_char().to_string() + "=="
    }
  }
  out
}

fn make_b64_decode_table() -> Map[Char, Int] {
  let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  let m : Map[Char, Int] = Map::new()
  let mut i = 0
  while i < 64 {
    m.set(alphabet.unsafe_get(i).unsafe_to_char(), i)
    i = i + 1
  }
  m
}

fn trim_ascii(s : String) -> String {
  let arr = s.to_array()
  let mut start = 0
  let mut end = arr.length()
  while start < end {
    let c = arr.unsafe_get(start)
    if c == ' ' || c == '\t' || c == '\r' || c == '\n' { start = start + 1 }
    else { break }
  }
  while end > start {
    let c = arr.unsafe_get(end - 1)
    if c == ' ' || c == '\t' || c == '\r' || c == '\n' { end = end - 1 }
    else { break }
  }
  let sb = StringBuilder::new()
  for i = start; i < end; i = i + 1 { sb.write_char(arr.unsafe_get(i)) }
  sb.to_string()
}
