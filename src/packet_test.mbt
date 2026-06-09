///| Packet 协议单元测试：包序列化/反序列化、Reader/Writer。

test "Writer::write_uint32 / Reader::read_uint32 roundtrip" {
  let w = Writer::new()
  w.write_uint32(0)
  w.write_uint32(255)
  w.write_uint256)
  w.write_uint32(0x7FFFFFFF)
  let data = w.to_bytes()
  assert_eq(data.length(), 16)

  let r = Reader::new(data)
  assert_eq(r.read_uint32(), 0)
  assert_eq(r.read_uint32(), 255)
  assert_eq(r.read_uint32(), 65535)
  assert_eq(r.read_uint32(), 0x7FFFFFFF)
  assert_true(r.eof())
}

test "Writer::write_string / Reader::read_string roundtrip" {
  let w = Writer::new()
  w.write_string(b"")
  w.write_string(b"hello")
  w.write_bytes(b"\x00\xFF")
  let data = w.to_bytes()

  let r = Reader::new(data)
  assert_eq(r.read_string().length(), 0)
  assert_eq(r.read_string(), b"hello")
  // The raw bytes after the string are not string-prefixed
  assert_eq(r.read_bytes(2), b"\x00\xFF")
}

test "Writer::write_name_list roundtrip" {
  let names : Array[String] = ["aes128-ctr", "aes256-ctr", "chacha20-poly1305@openssh.com"]
  let w = Writer::new()
  w.write_name_list(names)
  let data = w.to_bytes()

  let r = Reader::new(data)
  let read_names = r.read_name_list()
  assert_eq(read_names.length(), 3)
  assert_eq(read_names[0], "aes128-ctr")
  assert_eq(read_names[2], "chacha20-poly1305@openssh.com")
}

test "Reader::read_byte" {
  let data = b"\x00\x01\x7F\x80\xFF"
  let r = Reader::new(data)
  assert_eq(r.read_byte().to_int(), 0)
  assert_eq(r.read_byte().to_int(), 1)
  assert_eq(r.read_byte().to_int(), 127)
  assert_eq(r.read_byte().to_int(), 128)
  assert_eq(r.read_byte().to_int(), 255)
  assert_true(r.eof())
}

test "Reader::read_bytes bounds checking" {
  let data = b"\x01\x02"
  let r = Reader::new(data)
  try
    r.read_bytes(3)
    raise "should have failed"
  catch {
    ParseError(_) => ()
    _ => fail("expected ParseError")
  }
}

test "Reader::remaining and pos tracking" {
  let data = b"\x01\x02\x03\x04\x05"
  let r = Reader::new(data)
  assert_eq(r.remaining(), 5)
  assert_eq(r.pos(), 0)
  r.read_bytes(2)
  assert_eq(r.remaining(), 3)
  assert_eq(r.pos(), 2)
  assert_false(r.eof())
  r.read_bytes(3)
  assert_true(r.eof())
}

test "encode_uint32 / decode_uint32 symmetry" {
  let values = [0, 1, 255, 256, 65535, 65536, 16777215, 2147483647]
  for v in values {
    let enc = encode_uint32(v)
    assert_eq(enc.length(), 4)
    let dec = decode_uint32(enc)
    assert_eq(dec, v, "roundtrip failed for \{v}")
  }
}

test "encode_string / parse_string symmetry" {
  let cases = [b"", b"a", b"abc", Bytes::make(255, b'\xAB')]
  for s in cases {
    let enc = encode_string(s)
    let (parsed, rest) = parse_string(enc)
    assert_eq(parsed, s, "string roundtrip failed")
    assert_eq(rest.length(), 0)
  }
}

test "encode_mpint of small positive number" {
  let n = @bigint.BigInt::from_int(12345)
  let encoded = encode_mpint(n)
  let r = Reader::new(encoded)
  let len = r.read_uint32()
  assert_true(len > 0 && len <= 5)
  let (decoded, _rest) = decode_mpint(encoded)
  assert_true(decoded == n)
}

test "encode_mpint of zero" {
  let n = @bigint.BigInt::from_int(0)
  let encoded = encode_mpint(n)
  assert_eq(encoded.length(), 5) // uint32(1) + 0x00
}

test "write_packet produces valid format with padding" {
  let payload = b"\x01\x02\x03\x04\x05"
  let packet = write_packet(payload, 8, false, _data => b"")
  // packet = 4-byte length + 1-byte padding_length + payload + padding
  let len = decode_uint32(Bytes::get_view(packet, start=0, end=4).unwrap_or(b""))
  assert_true(len >= payload.length() + 5) // at least 1 byte pad + padding_length
  assert_true(len <= MAX_PACKET)
}

test "Reader::eof on empty input" {
  let r = Reader::new(b"")
  assert_true(r.eof())
  assert_eq(r.remaining(), 0)
}

test "Writer::length tracks bytes written" {
  let w = Writer::new()
  assert_eq(w.length(), 0)
  w.write_byte(b'\x00')
  assert_eq(w.length(), 1)
  w.write_uint32(42)
  assert_eq(w.length(), 5)
  w.write_string(b"test")
  assert_eq(w.length(), 10) // 4 + 4 = 8 more
}
