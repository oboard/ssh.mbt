///
/// SSH 传输层包读写（RFC 4253 §6）。
/// 包含 Reader / Writer 以及包帧化函数。

///|
/// SSH 协议层错误。
pub suberror SshError {
  IoError(String)
  ConnectionClosed
  ProtocolError(String)
  MacMismatch
  NotEncrypted
  HostKeyMismatch(String)
  AuthFailed(String)
  RequestDenied(String)
  ParseError(String)
} derive(Show, Eq)

// ============== Reader ==============

///|
/// 字节游标读取器。
pub struct Reader {
  priv data : Bytes
  priv mut pos : Int
}

///|
pub fn Reader::new(data : Bytes) -> Reader {
  { data, pos: 0 }
}

///|
pub fn Reader::remaining(self : Reader) -> Int {
  self.data.length() - self.pos
}

///|
pub fn Reader::pos(self : Reader) -> Int {
  self.pos
}

///|
pub fn Reader::eof(self : Reader) -> Bool {
  self.pos >= self.data.length()
}

///|
fn Reader::require(self : Reader, n : Int) -> Unit raise SshError {
  if self.remaining() < n {
    raise ParseError("reader: need \{n} bytes, have \{self.remaining()}")
  }
}

///|
pub fn Reader::read_byte(self : Reader) -> Byte raise SshError {
  self.require(1)
  let b = self.data.unsafe_get(self.pos)
  self.pos = self.pos + 1
  b
}

///|
pub fn Reader::read_uint32(self : Reader) -> Int raise SshError {
  self.require(4)
  let v0 = self.data.unsafe_get(self.pos).to_uint()
  let v1 = self.data.unsafe_get(self.pos + 1).to_uint()
  let v2 = self.data.unsafe_get(self.pos + 2).to_uint()
  let v3 = self.data.unsafe_get(self.pos + 3).to_uint()
  self.pos = self.pos + 4
  ((v0 << 24) | (v1 << 16) | (v2 << 8) | v3).reinterpret_as_int()
}

///|
pub fn Reader::read_bytes(self : Reader, n : Int) -> Bytes raise SshError {
  self.require(n)
  let view = match
    Bytes::get_view(self.data, start=self.pos, end=self.pos + n) {
    Some(v) => BytesView::to_owned(v)
    None => raise ParseError("reader: view out of range")
  }
  self.pos = self.pos + n
  view
}

///|
pub fn Reader::read_string(self : Reader) -> Bytes raise SshError {
  let len = self.read_uint32()
  self.read_bytes(len)
}

///|
pub fn Reader::read_string_as_str(self : Reader) -> String raise SshError {
  bytes_to_utf8_string(self.read_string())
}

///|
pub fn Reader::read_name_list(self : Reader) -> Array[String] raise SshError {
  let s = self.read_string_as_str()
  if s.length() == 0 {
    return []
  }
  let out : Array[String] = []
  for view in s.split(",") {
    let name = view.to_string()
    if name.length() > 0 {
      out.push(name)
    }
  }
  out
}

///|
pub fn Reader::read_mpint(self : Reader) -> @bigint.BigInt raise SshError {
  let bytes_val = self.read_string()
  if bytes_val.length() == 0 {
    return @bigint.BigInt::from_int(0)
  }
  @bigint.BigInt::from_octets(bytes_val) catch {
    e => raise ParseError("mpint: \{e}")
  }
}

///|
pub fn Reader::rest(self : Reader) -> Bytes {
  match Bytes::get_view(self.data, start=self.pos, end=self.data.length()) {
    Some(v) => BytesView::to_owned(v)
    None => b""
  }
}

// ============== Writer ==============

///|
pub struct Writer {
  priv buf : Array[Byte]
}

///|
pub fn Writer::new() -> Writer {
  { buf: [] }
}

///|
pub fn Writer::length(self : Writer) -> Int {
  self.buf.length()
}

///|
pub fn Writer::write_byte(self : Writer, b : Byte) -> Unit {
  self.buf.push(b)
}

///|
pub fn Writer::write_bytes(self : Writer, b : Bytes) -> Unit {
  for byte in b {
    self.buf.push(byte)
  }
}

///|
pub fn Writer::write_uint32(self : Writer, n : Int) -> Unit {
  let n_u = n.reinterpret_as_uint()
  self.buf.push(((n_u >> 24) & 0xffU).reinterpret_as_int().to_byte())
  self.buf.push(((n_u >> 16) & 0xffU).reinterpret_as_int().to_byte())
  self.buf.push(((n_u >> 8) & 0xffU).reinterpret_as_int().to_byte())
  self.buf.push((n_u & 0xffU).reinterpret_as_int().to_byte())
}

///|
pub fn Writer::write_string(self : Writer, s : Bytes) -> Unit {
  self.write_uint32(s.length())
  self.write_bytes(s)
}

///|
pub fn Writer::write_string_from_str(self : Writer, s : String) -> Unit {
  self.write_string(@utf8.encode(s))
}

///|
pub fn Writer::write_name_list(self : Writer, names : Array[String]) -> Unit {
  let mut s = ""
  for i, name in names {
    if i > 0 {
      s = s + ","
    }
    s = s + name
  }
  self.write_string_from_str(s)
}

///|
pub fn Writer::write_mpint(self : Writer, n : @bigint.BigInt) -> Unit {
  let bytes = n.to_octets() catch { _ => b"" }
  if bytes.length() == 0 {
    self.write_string(b"\x00")
    return
  }
  let first = bytes.unsafe_get(0).to_int()
  if first >= 0x80 {
    self.write_uint32(bytes.length() + 1)
    self.buf.push(b'\x00')
    self.write_bytes(bytes)
  } else {
    self.write_string(bytes)
  }
}

///|
pub fn Writer::to_bytes(self : Writer) -> Bytes {
  Bytes::from_array(self.buf)
}

// ============== Packet I/O ==============

///|
pub const MAX_PACKET : Int = 256 * 1024

///|
/// 读取一个 SSH 包。
pub fn read_packet(
  read_exact : (Int) -> Bytes raise SshError,
  block_size : Int,
  mac_size : Int,
  decrypt : (Bytes) -> Bytes raise SshError,
  verify_mac : (Bytes, Bytes) -> Unit raise SshError,
) -> Bytes raise SshError {
  let len_bytes = read_exact(4)
  let packet_length = decode_uint32(len_bytes)
  debug("* read_packet: packet_length=\{packet_length}, mac_size=\{mac_size}")
  if packet_length < 1 || packet_length > MAX_PACKET {
    raise ProtocolError("read_packet: bad length \{packet_length}")
  }
  let total = packet_length + mac_size
  debug("* read_packet: reading \{total} more bytes")
  let raw = read_exact(total)
  let full_packet = len_bytes + raw
  hex_dump("Encr body + HMAC (\{full_packet.length()} bytes)", full_packet)
  let body = match Bytes::get_view(raw, start=0, end=packet_length) {
    Some(v) => BytesView::to_owned(v)
    None => raise ProtocolError("read_packet: body slice")
  }
  let mac = if mac_size > 0 {
    match Bytes::get_view(raw, start=packet_length, end=total) {
      Some(v) => BytesView::to_owned(v)
      None => raise ProtocolError("read_packet: mac slice")
    }
  } else {
    b""
  }
  hex_dump("  body (encrypted, \{body.length()} bytes)", body)
  if mac_size > 0 {
    verify_mac(len_bytes + body, mac)
  }
  let plaintext = decrypt(body)
  hex_dump("  body (decrypted, \{plaintext.length()} bytes)", plaintext)
  if plaintext.length() < 1 {
    raise ProtocolError("read_packet: empty plaintext")
  }
  let padding_length = plaintext.unsafe_get(0).to_int()
  let payload_end = plaintext.length() - padding_length
  let msg_type_val = if payload_end > 1 {
    plaintext.unsafe_get(1).to_int()
  } else {
    -1
  }
  debug(
    "* read_packet: pad_len=\{padding_length} payload_end=\{payload_end} msg_type=\{msg_type_val}",
  )
  if 1 + padding_length > plaintext.length() {
    raise ProtocolError("read_packet: padding_length too large")
  }
  let payload_len = plaintext.length() - 1 - padding_length
  match
    Bytes::get_view(plaintext, start=1, end=plaintext.length() - padding_length) {
    Some(v) => BytesView::to_owned(v)
    None => raise ProtocolError("read_packet: payload slice")
  }
}

///|
/// 序列化一个 SSH 包。
pub fn write_packet(
  payload : Bytes,
  block_size : Int,
  mac_enabled : Bool,
  compute_mac : (Bytes) -> Bytes raise SshError,
) -> Bytes raise SshError {
  let bs = if block_size < 8 { 8 } else { block_size }
  let min_pad = 4
  let payload_len = payload.length()
  let mut padding_length = min_pad
  while (5 + payload_len + padding_length) % bs != 0 {
    padding_length = padding_length + 1
  }
  let padding = packet_random_bytes(padding_length)
  let body = Bytes::from_array(FixedArray::make(1, padding_length.to_byte())) +
    payload +
    padding
  let len_bytes = encode_uint32(body.length())
  let mut packet = len_bytes + body
  if mac_enabled {
    let tag = compute_mac(packet)
    packet = packet + tag
  }
  packet
}

///|
fn packet_random_bytes(n : Int) -> Bytes {
  @crypto.rand_bytes(n) catch {
    _ => Bytes::make(n, b'\x00')
  }
}

// ============== Low-level helpers ==============

///|
pub fn encode_string(s : Bytes) -> Bytes {
  encode_uint32(s.length()) + s
}

///|
pub fn encode_string_from_str(s : String) -> Bytes {
  encode_string(@utf8.encode(s))
}

///|
pub fn encode_uint32(n : Int) -> Bytes {
  let arr = FixedArray::make(4, b'\x00')
  let n_u = n.reinterpret_as_uint()
  arr[0] = ((n_u >> 24) & 0xffU).reinterpret_as_int().to_byte()
  arr[1] = ((n_u >> 16) & 0xffU).reinterpret_as_int().to_byte()
  arr[2] = ((n_u >> 8) & 0xffU).reinterpret_as_int().to_byte()
  arr[3] = (n_u & 0xffU).reinterpret_as_int().to_byte()
  Bytes::from_array(arr)
}

///|
pub fn decode_uint32(buf : Bytes) -> Int {
  let v = buf.to_fixedarray()
  let b0 = v.unsafe_get(0).to_uint()
  let b1 = v.unsafe_get(1).to_uint()
  let b2 = v.unsafe_get(2).to_uint()
  let b3 = v.unsafe_get(3).to_uint()
  ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3).reinterpret_as_int()
}

///|
pub fn encode_mpint(n : @bigint.BigInt) -> Bytes {
  let w = Writer::new()
  w.write_mpint(n)
  w.to_bytes()
}

///|
pub fn encode_mpint_of_bytes(bytes : Bytes) -> Bytes {
  if bytes.length() == 0 {
    return encode_string(b"\x00")
  }
  // Skip leading zero bytes (RFC 4251 §5: mpint stores the minimal
  // representation of the integer).  OpenSSH's sshbuf_put_bignum2_bytes
  // does the same.
  let mut start = 0
  let arr = bytes.to_fixedarray()
  while start < bytes.length() && arr.unsafe_get(start).to_int() == 0 {
    start = start + 1
  }
  if start >= bytes.length() {
    return encode_string(b"\x00")
  }
  let remaining = bytes.length() - start
  let first_nonzero = arr.unsafe_get(start).to_int()
  let body = if start > 0 {
    match Bytes::get_view(bytes, start~, end=bytes.length()) {
      Some(v) => BytesView::to_owned(v)
      None => encode_string(b"\x00")
    }
  } else {
    bytes
  }
  if first_nonzero >= 0x80 {
    encode_uint32(remaining + 1) +
    Bytes::from_array(FixedArray::make(1, b'\x00')) +
    body
  } else {
    encode_uint32(remaining) + body
  }
}

// ============== UTF-8 helper ==============

///|
fn bytes_to_utf8_string(b : Bytes) -> String {
  let mut s = ""
  let arr = b.to_fixedarray()
  let mut i = 0
  while i < arr.length() {
    let c = decode_utf8_char(arr, i)
    s = s + c.0.to_string()
    i = i + c.1
  }
  s
}

///|
fn decode_utf8_char(arr : FixedArray[Byte], i : Int) -> (Char, Int) {
  let b0 = arr.unsafe_get(i).to_int()
  if b0 < 0x80 {
    (b0.unsafe_to_char(), 1)
  } else if b0 < 0xC0 {
    (0xFFFD |> unsafe_int_to_char, 1)
  } else if b0 < 0xE0 {
    if i + 1 < arr.length() {
      let b1 = arr.unsafe_get(i + 1).to_int() & 0x3F
      ((((b0 & 0x1F) << 6) | b1).unsafe_to_char(), 2)
    } else {
      (0xFFFD |> unsafe_int_to_char, 1)
    }
  } else if b0 < 0xF0 {
    if i + 2 < arr.length() {
      let b1 = arr.unsafe_get(i + 1).to_int() & 0x3F
      let b2 = arr.unsafe_get(i + 2).to_int() & 0x3F
      let cp = ((b0 & 0x0F) << 12) | (b1 << 6) | b2
      (cp.unsafe_to_char(), 3)
    } else {
      (0xFFFD |> unsafe_int_to_char, 1)
    }
  } else {
    (0xFFFD |> unsafe_int_to_char, 1)
  }
}

///|
fn unsafe_int_to_char(n : Int) -> Char {
  n.unsafe_to_char()
}
