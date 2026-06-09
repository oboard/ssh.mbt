///| Channel 通道协议单元测试（RFC 4254）。

test "Channel::new sets correct defaults" {
  let ch = Channel::new(0, b"session-id")
  assert_eq(ch.id(), 0)
  assert_eq(ch.state(), Closed)
  assert_false(ch.is_open())
  assert_eq(ch.exit_status(), None)
}

test "build_channel_open session channel" {
  let open_msg = build_channel_open(0, 1048576, 32768)
  let r = Reader::new(open_msg)
  assert_eq(r.read_byte().to_int(), 90) // MSG_CHANNEL_OPEN
  assert_eq(r.read_string_as_str(), "session")
  assert_eq(r.read_uint32(), 0) // sender_channel
  assert_eq(r.read_uint32(), 1048576) // initial_window
  assert_eq(r.read_uint32(), 32768) // max_packet
}

test "build_channel_request_exec" {
  let exec_msg = build_channel_request_exec(5, "uname -a")
  let r = Reader::new(exec_msg)
  assert_eq(r.read_byte().to_int(), 98) // MSG_CHANNEL_REQUEST
  assert_eq(r.read_uint32(), 5) // recipient_channel
  assert_eq(r.read_string_as_str(), "exec")
  assert_eq(r.read_byte().to_int(), 1) // want_reply=true
  assert_eq(r.read_string_as_str(), "uname -a")
}

test "handle_inbound CHANNEL_OPEN_CONFIRMATION opens channel" {
  let ch = Channel::new(0, b"sid")

  let w = Writer::new()
  w.write_byte(91) // OPEN_CONFIRMATION
  w.write_uint32(0) // sender (us)
  w.write_uint32(100) // peer's id
  w.write_uint32(2097152) // peer's window
  w.write_uint32(32768) // peer's max_packet

  let responses = ch.handle_inbound(w.to_bytes())
  assert_true(ch.is_open())
  assert_eq(responses.length(), 0) // No auto-responses needed
}

test "handle_inbound CHANNEL_DATA buffers stdout" {
  let ch = Channel::new(0, b"sid")

  // First open the channel
  let open_w = Writer::new()
  open_w.write_byte(91)
  open_w.write_uint32(0); open_w.write_uint32(100)
  open_w.write_uint32(2000000); open_w.write_uint32(32000)
  ignore(ch.handle_inbound(open_w.to_bytes()))

  // Send some DATA
  let data_w = Writer::new()
  data_w.write_byte(94) // CHANNEL_DATA
  data_w.write_uint32(100) // sender (peer)
  data_w.write_string(b"Hello from server!")
  let responses = ch.handle_inbound(data_w.to_bytes())

  assert_true(ch.has_stdout())

  // Should send WINDOW_ADJUST back
  assert_eq(responses.length(), 1)
}

test "take_stdout clears buffer" {
  let ch = Channel::new(0, b"sid")

  // Open channel first
  let open_w = Writer::new()
  open_w.write_byte(91)
  open_w.write_uint32(0); open_w.write_uint32(100)
  open_w.write_uint32(2000000); open_w.write_uint32(32000)
  ignore(ch.handle_inbound(open_w.to_bytes()))

  // Send data
  let data_w = Writer::new()
  data_w.write_byte(94)
  data_w.write_uint32(100)
  data_w.write_string(b"output line 1\n")
  ignore(ch.handle_inbound(data_w.to_bytes()))

  let stdout1 = ch.take_stdout()
  assert_eq(stdout1, "output line 1\n")
  assert_false(ch.has_stdout()) // buffer should be cleared
}

test "handle_inbound CHANNEL_EOF changes state" {
  let ch = Channel::new(0, b"sid")

  // Open first
  let open_w = Writer::new()
  open_w.write_byte(91)
  open_w.write_uint32(0); open_w.write_uint32(100)
  open_w.write_uint32(2000000); open_w.write_uint32(32000)
  ignore(ch.handle_inbound(open_w.to_bytes()))

  // Send EOF
  let eof_w = Writer::new()
  eof_w.write_byte(95) // CHANNEL_EOF
  eof_w.write_uint32(100)
  ignore(ch.handle_inbound(eof_w.to_bytes()))

  assert_eq(ch.state(), EofReceived)
}

test "handle_inbound exit-status records code" {
  let ch = Channel::new(0, b"sid")

  let req_w = Writer::new()
  req_w.write_byte(98) // CHANNEL_REQUEST
  req_w.write_uint32(0)
  req_w.write_string_from_str("exit-status")
  req_w.write_byte(0) // want_reply=false
  req_w.write_uint32(42) // exit code

  ignore(ch.handle_inbound(req_w.to_bytes()))
  let status = ch.exit_status()
  match status {
    Some(s) => assert_eq(s, 42)
    None => fail("exit_status should be Some")
  }
}

test "handle_inbound CHANNEL_CLOSE transitions to Done" {
  let ch = Channel::new(0, b"sid")

  let close_w = Writer::new()
  close_w.write_byte(96) // CHANNEL_CLOSE
  close_w.write_uint32(0)

  let responses = ch.handle_inbound(close_w.to_bytes())
  assert_eq(ch.state(), Done)
  // Should produce a CLOSE response
  assert_eq(responses.length(), 1)
}

test "handle_inbound CHANNEL_OPEN_FAILURE" {
  let ch = Channel::new(0, b"sid")

  let fail_w = Writer::new()
  fail_w.write_byte(92) // CHANNEL_OPEN_FAILURE
  fail_w.write_uint32(0) // sender
  fail_w.write_uint32(2) // reason: SSH_OPEN_ADMINISTRATIVELY_PROHIBITED
  fail_w.write_string_from_str("denied by policy")
  fail_w.write_string_from_str("") // language

  ignore(ch.handle_inbound(fail_w.to_bytes()))
  assert_eq(ch.state(), Done)
}

test "CHANNEL_EXTENDED_DATA buffers stderr" {
  let ch = Channel::new(0, b"sid")

  // Open first
  let open_w = Writer::new()
  open_w.write_byte(91)
  open_w.write_uint32(0); open_w.write_uint32(100)
  open_w.write_uint32(2000000); open_w.write_uint32(32000)
  ignore(ch.handle_inbound(open_w.to_bytes()))

  let ext_w = Writer::new()
  ext_w.write_byte(127) // CHANNEL_EXTENDED_DATA
  ext_w.write_uint32(100) // sender
  ext_w.write_uint32(1) // data_type=stderr
  ext_w.write_string(b"error message")

  ignore(ch.handle_inbound(ext_w.to_bytes()))
  let stderr = ch.take_stderr()
  assert_eq(stderr, "error message")
}

test "message constants are unique" {
  assert_neq(MSG_CHANNEL_OPEN, MSG_CHANNEL_OPEN_CONFIRMATION)
  assert_neq(MSG_CHANNEL_DATA, MSG_CHANNEL_CLOSE)
  assert_neq(MSG_CHANNEL_EOF, MSG_CHANNEL_REQUEST)
}

test "request_type helpers" {
  assert_eq(request_type_exec(), "exec")
  assert_eq(request_type_shell(), "shell")
  assert_eq(request_type_env(), "env")
}
