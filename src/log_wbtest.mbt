// Whitebox tests for src/log.mbt.
// Run `moon test --target native` to execute.

///|
test "log/enable_disable_roundtrip" {
  // 全局开关应当支持 enable / disable / is_enabled 三态切换
  // 关闭状态下应当为 false
  disable_debug()
  inspect(is_debug_enabled(), content="false")
  // 开启后变 true
  enable_debug()
  inspect(is_debug_enabled(), content="true")
  // 再次关闭恢复 false
  disable_debug()
  inspect(is_debug_enabled(), content="false")
}

///|
test "log/debug_does_not_raise_when_disabled" {
  // 关闭调试时 debug() 仍可安全调用，不应抛错也不应输出
  disable_debug()
  debug("this should be silently dropped")
  inspect(is_debug_enabled(), content="false")
  // 恢复关闭状态以避免污染后续测试
  disable_debug()
}

///|
test "log/debug_does_not_raise_when_enabled" {
  // 开启调试时 debug() 应当正常输出到 stdout 且不抛错
  enable_debug()
  debug("debug line 1")
  debug("debug line 2 with payload: 0xdeadbeef")
  inspect(is_debug_enabled(), content="true")
  // 恢复关闭状态
  disable_debug()
}

///|
test "log/hex_dump_empty" {
  // 空字节序列的 hex dump 不应抛错
  enable_debug()
  hex_dump("empty buffer", b"")
  inspect(is_debug_enabled(), content="true")
  disable_debug()
}

///|
test "log/hex_dump_short" {
  // 短数据（一行内）
  enable_debug()
  hex_dump("short", Bytes::from_array([b'\xde', b'\xad', b'\xbe', b'\xef']))
  disable_debug()
}

///|
test "log/hex_dump_multiline" {
  // 多行数据（>16 字节需要换行）
  let data = Bytes::makei(40, i => i.to_byte())
  enable_debug()
  hex_dump("40 bytes", data)
  disable_debug()
}

///|
test "log/hex_dump_binary" {
  // 含不可打印 ASCII 的数据，hex_dump 会用 '.' 替代
  enable_debug()
  hex_dump(
    "binary",
    Bytes::from_array([b'\x00', b'\x01', b'\x7f', b'\x80', b'\xff', b'\x20']),
  )
  disable_debug()
}
