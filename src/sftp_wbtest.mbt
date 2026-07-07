// Whitebox tests for src/sftp.mbt.
// Run `moon test --target native` to execute.

///|
test "sftp/encode_sftp_packet" {
  // 编码 SFTP 包：length(4) + type(1) + id(4) + payload
  let payload = encode_uint32(3) // 模拟一个小 payload
  let pkt = encode_sftp_packet(SSH_FXP_OPEN, 1, payload)
  let r = Reader::new(pkt)
  // length = 1(type) + 4(id) + 4(payload) = 9
  let len = r.read_uint32()
  inspect(len, content="9")
  // type
  let typ = r.read_byte()
  inspect(typ, content="b'\\x03'")
  // id
  let id = r.read_uint32()
  inspect(id, content="1")
  // payload
  let rest = r.rest()
  inspect(rest.length(), content="4")
}

///|
test "sftp/decode_sftp_packet" {
  // 构造一个 SFTP 包并解码
  let w = Writer::new()
  w.write_uint32(9) // length
  w.write_byte(SSH_FXP_STATUS)
  w.write_uint32(42) // id
  w.write_bytes(encode_uint32(0)) // status code = OK
  let pkt = decode_sftp_packet(w.to_bytes())
  inspect(pkt.typ, content="b'\\x65'")
  inspect(pkt.id, content="42")
  // data 应包含 status code
  let r = Reader::new(pkt.data)
  let code = r.read_uint32()
  inspect(code, content="0")
}

///|
test "sftp/parse_attrs_empty" {
  // flags = 0，无属性
  let w = Writer::new()
  w.write_uint32(0) // flags = 0
  let attrs = parse_attrs(w.to_bytes())
  inspect(attrs.flags, content="0")
  inspect(attrs.size is None, content="true")
  inspect(attrs.uid is None, content="true")
  inspect(attrs.gid is None, content="true")
  inspect(attrs.permissions is None, content="true")
  inspect(attrs.atime is None, content="true")
  inspect(attrs.mtime is None, content="true")
}

///|
test "sftp/parse_attrs_size_only" {
  // 仅设置 SIZE 标志
  let w = Writer::new()
  w.write_uint32(SSH_FILEXFER_ATTR_SIZE)
  w.write_uint32(1024) // size low 32 bits
  w.write_uint32(0) // size high 32 bits
  let attrs = parse_attrs(w.to_bytes())
  inspect(attrs.flags, content="1")
  @debug.debug_inspect(attrs.size, content="Some(1024)")
  inspect(attrs.uid is None, content="true")
}

///|
test "sftp/parse_attrs_full" {
  // 设置所有属性标志
  let w = Writer::new()
  w.write_uint32(
    SSH_FILEXFER_ATTR_SIZE
    .lor(SSH_FILEXFER_ATTR_UIDGID)
    .lor(SSH_FILEXFER_ATTR_PERMISSIONS)
    .lor(SSH_FILEXFER_ATTR_ACMODTIME),
  )
  w.write_uint32(2048) // size low
  w.write_uint32(0) // size high
  w.write_uint32(1000) // uid
  w.write_uint32(1000) // gid
  w.write_uint32(0o755) // permissions
  w.write_uint32(1700000000) // atime
  w.write_uint32(1700000001) // mtime
  let attrs = parse_attrs(w.to_bytes())
  @debug.debug_inspect(attrs.size, content="Some(2048)")
  @debug.debug_inspect(attrs.uid, content="Some(1000)")
  @debug.debug_inspect(attrs.gid, content="Some(1000)")
  @debug.debug_inspect(attrs.permissions, content="Some(493)")
  @debug.debug_inspect(attrs.atime, content="Some(1700000000)")
  @debug.debug_inspect(attrs.mtime, content="Some(1700000001)")
}

///|
test "sftp/parse_attrs_from_reader" {
  // 测试从 Reader 中解析属性（内联格式）
  let w = Writer::new()
  w.write_uint32(SSH_FILEXFER_ATTR_PERMISSIONS)
  w.write_uint32(0o644)
  // 在后面追加额外数据，验证 Reader 位置正确推进
  w.write_uint32(999)
  let r = Reader::new(w.to_bytes())
  let attrs = parse_attrs_from_reader(r)
  @debug.debug_inspect(attrs.permissions, content="Some(420)")
  // Reader 应该已经推进到额外数据
  let extra = r.read_uint32()
  inspect(extra, content="999")
}

///|
test "sftp/parse_status_ok" {
  // SSH_FX_OK 状态
  let w = Writer::new()
  w.write_uint32(SSH_FX_OK) // code
  w.write_string_from_str("Success") // message
  let (code, msg) = parse_status(w.to_bytes())
  inspect(code, content="0")
  inspect(msg, content="Success")
}

///|
test "sftp/parse_status_error" {
  // 非 OK 状态
  let w = Writer::new()
  w.write_uint32(2) // SSH_FX_NO_SUCH_FILE
  w.write_string_from_str("No such file")
  let (code, msg) = parse_status(w.to_bytes())
  inspect(code, content="2")
  inspect(msg, content="No such file")
}

///|
test "sftp/check_ok_succeeds" {
  // OK 状态不应抛出
  let w = Writer::new()
  w.write_uint32(SSH_FX_OK)
  w.write_string_from_str("OK")
  check_ok(w.to_bytes())
}

///|
test "sftp/check_ok_raises_on_error" {
  // 非 OK 状态应抛出 ProtocolError
  let w = Writer::new()
  w.write_uint32(2)
  w.write_string_from_str("No such file")
  try {
    check_ok(w.to_bytes())
    fail("expected ProtocolError")
  } catch {
    ProtocolError(msg) => {
      inspect(msg.contains("SFTP status 2:"), content="true")
      inspect(msg.contains("No such file"), content="true")
    }
    _ => fail("expected ProtocolError")
  }
}

///|
test "sftp/parse_name_entries_single" {
  // 解析单个目录条目
  let w = Writer::new()
  w.write_uint32(1) // count
  w.write_string_from_str("file.txt")
  w.write_string_from_str("-rw-r--r-- 1 user group 1024 Jan 1 00:00 file.txt")
  // attrs (inline)
  w.write_uint32(SSH_FILEXFER_ATTR_SIZE.lor(SSH_FILEXFER_ATTR_PERMISSIONS))
  w.write_uint32(1024) // size low
  w.write_uint32(0) // size high
  w.write_uint32(0o644) // permissions
  let entries = parse_name_entries(w.to_bytes())
  inspect(entries.length(), content="1")
  inspect(entries[0].filename, content="file.txt")
  inspect(
    entries[0].longname,
    content="-rw-r--r-- 1 user group 1024 Jan 1 00:00 file.txt",
  )
  @debug.debug_inspect(entries[0].attrs.size, content="Some(1024)")
  @debug.debug_inspect(entries[0].attrs.permissions, content="Some(420)")
}

///|
test "sftp/parse_name_entries_multiple" {
  // 解析多个目录条目
  let w = Writer::new()
  w.write_uint32(2) // count
  // entry 1
  w.write_string_from_str(".")
  w.write_string_from_str("drwxr-xr-x 2 user group 4096 Jan 1 00:00 .")
  w.write_uint32(SSH_FILEXFER_ATTR_PERMISSIONS)
  w.write_uint32(0o755)
  // entry 2
  w.write_string_from_str("..")
  w.write_string_from_str("drwxr-xr-x 3 user group 4096 Jan 1 00:00 ..")
  w.write_uint32(SSH_FILEXFER_ATTR_PERMISSIONS)
  w.write_uint32(0o755)
  let entries = parse_name_entries(w.to_bytes())
  inspect(entries.length(), content="2")
  inspect(entries[0].filename, content=".")
  inspect(entries[1].filename, content="..")
}

///|
test "sftp/parse_name_entries_empty" {
  // 空目录
  let w = Writer::new()
  w.write_uint32(0) // count = 0
  let entries = parse_name_entries(w.to_bytes())
  inspect(entries.length(), content="0")
}

///|
test "sftp/constants/request_types" {
  // 验证请求类型常量值
  inspect(SSH_FXP_OPEN, content="b'\\x03'")
  inspect(SSH_FXP_CLOSE, content="b'\\x04'")
  inspect(SSH_FXP_READ, content="b'\\x05'")
  inspect(SSH_FXP_WRITE, content="b'\\x06'")
  inspect(SSH_FXP_OPENDIR, content="b'\\x0B'")
  inspect(SSH_FXP_READDIR, content="b'\\x0C'")
  inspect(SSH_FXP_REMOVE, content="b'\\x0D'")
  inspect(SSH_FXP_MKDIR, content="b'\\x0E'")
  inspect(SSH_FXP_RMDIR, content="b'\\x0F'")
  inspect(SSH_FXP_REALPATH, content="b'\\x10'")
  inspect(SSH_FXP_STAT, content="b'\\x11'")
  inspect(SSH_FXP_RENAME, content="b'\\x12'")
}

///|
test "sftp/constants/response_types" {
  // 验证响应类型常量值
  inspect(SSH_FXP_VERSION, content="b'\\x02'")
  inspect(SSH_FXP_STATUS, content="b'\\x65'")
  inspect(SSH_FXP_HANDLE, content="b'\\x66'")
  inspect(SSH_FXP_DATA, content="b'\\x67'")
  inspect(SSH_FXP_NAME, content="b'\\x68'")
  inspect(SSH_FXP_ATTRS, content="b'\\x69'")
}

///|
test "sftp/constants/status_codes" {
  inspect(SSH_FX_OK, content="0")
  inspect(SSH_FX_EOF, content="1")
}

///|
test "sftp/constants/file_open_flags" {
  inspect(SSH_FXF_READ, content="1")
  inspect(SSH_FXF_WRITE, content="2")
  inspect(SSH_FXF_APPEND, content="4")
  inspect(SSH_FXF_CREAT, content="8")
  inspect(SSH_FXF_TRUNC, content="16")
  inspect(SSH_FXF_EXCL, content="32")
}

///|
test "sftp/constants/attr_flags" {
  inspect(SSH_FILEXFER_ATTR_SIZE, content="1")
  inspect(SSH_FILEXFER_ATTR_UIDGID, content="2")
  inspect(SSH_FILEXFER_ATTR_PERMISSIONS, content="4")
  inspect(SSH_FILEXFER_ATTR_ACMODTIME, content="8")
}

///|
test "sftp/attrs_parse_consistency" {
  // 多次解析相同数据应产生一致的结果
  let w = Writer::new()
  w.write_uint32(SSH_FILEXFER_ATTR_SIZE)
  w.write_uint32(512)
  w.write_uint32(0)
  let data = w.to_bytes()
  let a1 = parse_attrs(data)
  let a2 = parse_attrs(data)
  inspect(a1.flags, content=a2.flags.to_string())
  @debug.debug_inspect(a1.size, content=@debug.to_string(a2.size))
}
