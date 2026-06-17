// Whitebox tests for src/packet.mbt.
// Run `moon test --target native` to execute.

///|
/// 提取 Bytes 前 n 字节为新的 Bytes（用于 decode_uint32 等场景）。
fn take_bytes(buf : Bytes, n : Int) -> Bytes {
  match Bytes::get_view(buf, start=0, end=n) {
    Some(v) => BytesView::to_owned(v)
    None => b""
  }
}

// ============== Reader ==============

///|
test "reader/new_and_basic_state" {
  // 新建 reader：位置 0，未结束，剩余长度等于缓冲长度
  let r = Reader::new(Bytes::from_array([b'\x01', b'\x02', b'\x03']))
  inspect(r.pos(), content="0")
  inspect(r.eof(), content="false")
  inspect(r.remaining(), content="3")
}

///|
test "reader/read_byte_advances" {
  // read_byte 应当按顺序返回单字节并前移位置
  let r = Reader::new(Bytes::from_array([b'\x41', b'\x42', b'\x43']))
  inspect(r.read_byte().to_int(), content="65") // 'A'
  inspect(r.read_byte().to_int(), content="66") // 'B'
  inspect(r.read_byte().to_int(), content="67") // 'C'
  inspect(r.eof(), content="true")
  inspect(r.remaining(), content="0")
}

///|
test "reader/read_byte_eof_raises" {
  // 缓冲区耗尽后再读应当抛 ParseError
  let r = Reader::new(b"")
  try {
    let _ = r.read_byte()
    fail("expected ParseError")
  } catch {
    ParseError(_) => ()
    _ => fail("expected ParseError, got other")
  }
}

///|
test "reader/read_uint32_big_endian" {
  // 大端序解码 32 位无符号
  let r = Reader::new(Bytes::from_array([b'\x00', b'\x00', b'\x00', b'\x2a']))
  inspect(r.read_uint32(), content="42")
  let r2 = Reader::new(Bytes::from_array([b'\xff', b'\xff', b'\xff', b'\xff']))
  // 0xFFFFFFFF reinterpret_as_int = -1
  inspect(r2.read_uint32(), content="-1")
  let r3 = Reader::new(Bytes::from_array([b'\x80', b'\x00', b'\x00', b'\x00']))
  // 0x80000000 = -2147483648
  inspect(r3.read_uint32(), content="-2147483648")
}

///|
test "reader/read_bytes_slices" {
  // read_bytes(n) 应当返回指定长度的子缓冲
  let r = Reader::new(Bytes::from_array([b'\x01', b'\x02', b'\x03', b'\x04']))
  let a = r.read_bytes(2)
  inspect(a.length(), content="2")
  inspect(a[0].to_int(), content="1")
  inspect(a[1].to_int(), content="2")
  // 位置正确推进
  inspect(r.remaining(), content="2")
}

///|
test "reader/read_string_decodes_ssh_string" {
  // SSH "string"：前 4 字节长度，后跟负载
  let buf = encode_string(Bytes::from_array([b'\x68', b'\x69'])) +
    encode_string(Bytes::from_array([b'\x21']))
  let r = Reader::new(buf)
  let s1 = r.read_string()
  inspect(s1.length(), content="2")
  inspect(s1[0].to_int(), content="104") // 'h'
  let s2 = r.read_string()
  inspect(s2.length(), content="1")
  inspect(s2[0].to_int(), content="33") // '!'
}

///|
test "reader/read_string_as_str" {
  // read_string_as_str 应当正确 UTF-8 解码
  let buf = encode_string_from_str("hello, 世界")
  let r = Reader::new(buf)
  inspect(r.read_string_as_str(), content="hello, 世界")
}

///|
test "reader/read_name_list_basic" {
  // name-list: "ssh-rsa,ssh-ed25519"
  let buf = encode_string_from_str("ssh-rsa,ssh-ed25519")
  let r = Reader::new(buf)
  let names = r.read_name_list()
  inspect(names.length(), content="2")
  inspect(names[0], content="ssh-rsa")
  inspect(names[1], content="ssh-ed25519")
}

///|
test "reader/read_name_list_empty" {
  // 空 name-list 应当返回空数组
  let buf = encode_string(b"")
  let r = Reader::new(buf)
  inspect(r.read_name_list().length(), content="0")
}

///|
test "reader/read_name_list_single" {
  // 单元素无需逗号
  let buf = encode_string_from_str("aes128-ctr")
  let r = Reader::new(buf)
  let names = r.read_name_list()
  inspect(names.length(), content="1")
  inspect(names[0], content="aes128-ctr")
}

///|
test "reader/read_mpint_zero" {
  // 空 mpint 字符串应当返回 0
  let r = Reader::new(encode_string(b""))
  let n = r.read_mpint()
  inspect(n.to_int(), content="0")
}

///|
test "reader/rest_returns_unread" {
  // rest() 返回未读部分，不推进位置
  let r = Reader::new(Bytes::from_array([b'\x01', b'\x02', b'\x03']))
  let _ = r.read_byte()
  let rest = r.rest()
  inspect(rest.length(), content="2")
  inspect(rest[0].to_int(), content="2")
  // 多次调用 rest() 不改变位置
  inspect(r.rest().length(), content="2")
  inspect(r.pos(), content="1")
}

// ============== Writer ==============

///|
test "writer/new_is_empty" {
  // 新 Writer 长度 0
  let w = Writer::new()
  inspect(w.length(), content="0")
  let buf = w.to_bytes()
  inspect(buf.length(), content="0")
}

///|
test "writer/write_byte_and_length" {
  // write_byte 累加并反映在 length() 中
  let w = Writer::new()
  w.write_byte(b'\xaa')
  inspect(w.length(), content="1")
  w.write_byte(b'\xbb')
  w.write_byte(b'\xcc')
  inspect(w.length(), content="3")
  let buf = w.to_bytes()
  inspect(buf[0].to_int(), content="170")
  inspect(buf[2].to_int(), content="204")
}

///|
test "writer/write_bytes_appends" {
  // write_bytes 完整追加
  let w = Writer::new()
  w.write_bytes(Bytes::from_array([b'\x01', b'\x02', b'\x03', b'\x04']))
  inspect(w.length(), content="4")
  let buf = w.to_bytes()
  inspect(buf[3].to_int(), content="4")
}

///|
test "writer/write_uint32_big_endian" {
  // 大端序写入
  let w = Writer::new()
  w.write_uint32(0x12345678)
  let buf = w.to_bytes()
  inspect(buf.length(), content="4")
  inspect(buf[0].to_int(), content="18") // 0x12
  inspect(buf[1].to_int(), content="52") // 0x34
  inspect(buf[2].to_int(), content="86") // 0x56
  inspect(buf[3].to_int(), content="120") // 0x78
}

///|
test "writer/write_string_layout" {
  // SSH "string"：4 字节长度 + 内容
  let w = Writer::new()
  w.write_string(Bytes::from_array([b'\x68', b'\x69', b'\x21']))
  let buf = w.to_bytes()
  inspect(buf.length(), content="7")
  // 长度 3 大端
  inspect(buf[0].to_int(), content="0")
  inspect(buf[1].to_int(), content="0")
  inspect(buf[2].to_int(), content="0")
  inspect(buf[3].to_int(), content="3")
  inspect(buf[4].to_int(), content="104")
}

///|
test "writer/write_string_from_str_utf8" {
  // 字符串应当先 UTF-8 编码再写
  let w = Writer::new()
  w.write_string_from_str("hi")
  let buf = w.to_bytes()
  inspect(buf.length(), content="6")
  // 长度 2
  inspect(decode_uint32(take_bytes(buf, 4)), content="2")
  // "hi"
  inspect(buf[4].to_int(), content="104") // 'h'
  inspect(buf[5].to_int(), content="105") // 'i'
}

///|
test "writer/write_name_list_csv" {
  // write_name_list 应当以逗号串联
  let w = Writer::new()
  w.write_name_list(["a", "b", "c"])
  let buf = w.to_bytes()
  let r = Reader::new(buf)
  let s = r.read_string_as_str()
  inspect(s, content="a,b,c")
}

///|
test "writer/write_name_list_empty" {
  // 空数组应写出长度 0 的 string
  let w = Writer::new()
  w.write_name_list([])
  let buf = w.to_bytes()
  inspect(buf.length(), content="4") // 仅 4 字节长度字段
  inspect(decode_uint32(take_bytes(buf, 4)), content="0")
}

///|
test "writer/write_mpint_positive_small" {
  // 127: 最高位为 0，无需补 0x00
  let w = Writer::new()
  w.write_mpint(@bigint.BigInt::from_int(127))
  let buf = w.to_bytes()
  inspect(decode_uint32(take_bytes(buf, 4)), content="1")
  inspect(buf[4].to_int(), content="127")
}

///|
test "writer/write_mpint_high_bit" {
  // 128: 最高位为 1，需要前导补 0x00
  let w = Writer::new()
  w.write_mpint(@bigint.BigInt::from_int(128))
  let buf = w.to_bytes()
  inspect(decode_uint32(take_bytes(buf, 4)), content="2")
  inspect(buf[4].to_int(), content="0")
  inspect(buf[5].to_int(), content="128")
}

///|
test "writer/to_bytes_does_not_reset" {
  // to_bytes 应当是快照：继续写仍会增加后续内容
  let w = Writer::new()
  w.write_byte(b'\x01')
  let first = w.to_bytes()
  inspect(first.length(), content="1")
  w.write_byte(b'\x02')
  let second = w.to_bytes()
  inspect(second.length(), content="2")
  inspect(first.length(), content="1")
}

// ============== encode/decode round-trip ==============

///|
test "encode_decode_uint32/roundtrip" {
  // 任意 32 位值应当 encode 后 decode 回来一致
  inspect(decode_uint32(encode_uint32(0)), content="0")
  inspect(decode_uint32(encode_uint32(1)), content="1")
  inspect(decode_uint32(encode_uint32(42)), content="42")
  inspect(decode_uint32(encode_uint32(0x7fffffff)), content="2147483647")
  // 负数按位 reinterpret
  inspect(decode_uint32(encode_uint32(-1)), content="-1")
  inspect(decode_uint32(encode_uint32(-2147483648)), content="-2147483648")
}

///|
test "encode_uint32/network_byte_order" {
  // 网络字节序：高位在前
  let buf = encode_uint32(0x12345678)
  inspect(buf.length(), content="4")
  inspect(buf[0].to_int(), content="18") // 0x12
  inspect(buf[3].to_int(), content="120") // 0x78
}

///|
test "encode_string/wraps_with_length" {
  // encode_string = uint32(length) || bytes
  let buf = encode_string(Bytes::from_array([b'\xab', b'\xcd']))
  inspect(buf.length(), content="6")
  inspect(buf[0].to_int(), content="0")
  inspect(buf[1].to_int(), content="0")
  inspect(buf[2].to_int(), content="0")
  inspect(buf[3].to_int(), content="2")
  inspect(buf[4].to_int(), content="171") // 0xab
  inspect(buf[5].to_int(), content="205") // 0xcd
}

///|
test "encode_string_from_str/utf8" {
  // 字符串先 UTF-8 编码
  let buf = encode_string_from_str("Z")
  inspect(decode_uint32(take_bytes(buf, 4)), content="1")
  inspect(buf[4].to_int(), content="90") // 'Z' = 0x5a
}

///|
test "encode_mpint/roundtrip" {
  // encode_mpint(BigInt) 后用 read_mpint 读出应当一致
  let cases : Array[Int] = [0, 1, 127, 128, 255, 256, 65535, 65536]
  for n in cases {
    let encoded = encode_mpint(@bigint.BigInt::from_int(n))
    let r = Reader::new(encoded)
    inspect(r.read_mpint().to_int(), content=n.to_string())
    ignore(r)
  }
}

///|
test "encode_mpint_of_bytes/strips_leading_zeros" {
  // 前导 0 应当被去除；0xab = 171 >= 0x80 → 触发 high-bit 补 0x00
  let bytes = Bytes::from_array([b'\x00', b'\x00', b'\x00', b'\xab', b'\xcd'])
  let encoded = encode_mpint_of_bytes(bytes)
  // 长度 = 3 (1 字节前导 0 + 0xab + 0xcd)
  inspect(decode_uint32(take_bytes(encoded, 4)), content="3")
  inspect(encoded[4].to_int(), content="0") // 补的 0x00
  inspect(encoded[5].to_int(), content="171") // 0xab
  inspect(encoded[6].to_int(), content="205") // 0xcd
}

///|
test "encode_mpint_of_bytes/pads_when_high_bit_set" {
  // 最高位为 1 时前导补 0x00
  let bytes = Bytes::from_array([b'\xff', b'\x01'])
  let encoded = encode_mpint_of_bytes(bytes)
  // 应当编码 [0x00, 0xff, 0x01]
  inspect(decode_uint32(take_bytes(encoded, 4)), content="3")
  inspect(encoded[4].to_int(), content="0")
  inspect(encoded[5].to_int(), content="255")
  inspect(encoded[6].to_int(), content="1")
}

///|
test "encode_mpint_of_bytes/empty_is_zero" {
  // 空序列应编码为单字节 0x00
  let encoded = encode_mpint_of_bytes(b"")
  inspect(decode_uint32(take_bytes(encoded, 4)), content="1")
  inspect(encoded[4].to_int(), content="0")
}

///|
test "encode_mpint_of_bytes/all_zeros_is_zero" {
  // 全零序列应编码为单字节 0x00
  let encoded = encode_mpint_of_bytes(
    Bytes::from_array([b'\x00', b'\x00', b'\x00']),
  )
  inspect(decode_uint32(take_bytes(encoded, 4)), content="1")
  inspect(encoded[4].to_int(), content="0")
}

// ============== writer/reader round-trip ==============

///|
test "roundtrip/uint32_via_writer_reader" {
  // Writer 写、Reader 读应当一致
  let w = Writer::new()
  w.write_uint32(0xdeadbeef)
  w.write_uint32(0x00000042)
  let r = Reader::new(w.to_bytes())
  inspect(r.read_uint32(), content="-559038737") // 0xdeadbeef as signed
  inspect(r.read_uint32(), content="66") // 0x42
  inspect(r.eof(), content="true")
}

///|
test "roundtrip/string_via_writer_reader" {
  // string 字段 Writer→Reader 应当一致
  let w = Writer::new()
  w.write_string_from_str("alice")
  w.write_string_from_str("bob")
  let r = Reader::new(w.to_bytes())
  inspect(r.read_string_as_str(), content="alice")
  inspect(r.read_string_as_str(), content="bob")
  inspect(r.eof(), content="true")
}

///|
test "roundtrip/name_list_via_writer_reader" {
  // name-list 应当可以往返
  let w = Writer::new()
  w.write_name_list(["ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256"])
  let r = Reader::new(w.to_bytes())
  let names = r.read_name_list()
  inspect(names.length(), content="3")
  inspect(names[0], content="ssh-rsa")
  inspect(names[1], content="ssh-ed25519")
  inspect(names[2], content="ecdsa-sha2-nistp256")
}
