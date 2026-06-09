///| Packet 协议单元测试：Reader/Writer 序列化。

test "Writer::write_uint32 / Reader::read_uint32 roundtrip" {
  let w = Writer::new()
  w.write_uint32(0)
  w.write_uint32(255)
  w.write_uint32(65535)
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
  r.read_bytes(2)
  assert_eq(r.remaining(), 3)
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
    assert_eq(dec, v)
  }
}

test "encode_string / parse_string symmetry" {
  let cases = [b"", b"a", b"abc", Bytes::make(255, b'\xAB')]
  for s in cases {
    let enc = encode_string(s)
    let (parsed, rest) = parse_string(enc)
    assert_eq(parsed, s)
    assert_eq(rest.length(), 0)
  }
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
  assert_eq(w.length(), 10)
}
