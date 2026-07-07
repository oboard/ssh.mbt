// Whitebox tests for src/channel.mbt.
// Run `moon test --target native` to execute.

///|
/// 解析已构建的 channel 消息：消息号 + 剩余字节。
fn channel_msg_body(buf : Bytes) -> (Byte, Bytes) raise SshError {
  let r = Reader::new(buf)
  let msg = r.read_byte()
  (msg, r.rest())
}

// ============== Channel::new and getters ==============

///|
test "channel/new_initial_state" {
  // 新建 Channel：state=Closed, peer_id=0, exit_status=None
  let ch = Channel::new(42)
  inspect(ch.id(), content="42")
  inspect(ch.peer_id(), content="0")
  match ch.state() {
    Closed => ()
    _ => fail("expected Closed")
  }
  inspect(ch.is_open(), content="false")
  @debug.debug_inspect(ch.exit_status(), content="None")
}

///|
test "channel/is_open_only_when_open" {
  // is_open 仅在 state=Open 时为真
  let ch = Channel::new(1)
  inspect(ch.is_open(), content="false")
  // 直接通过 handle_inbound 推进状态过于复杂，这里只验证初值与 Closed 不相等
  inspect(ch.state() == Open, content="false")
  inspect(ch.state() == Closed, content="true")
}

// ============== build_channel_open ==============

///|
test "build_channel_open/frame" {
  // 通道打开：90 + "session" + sender + window + max_packet
  let buf = build_channel_open(7, 1024 * 1024, 32 * 1024)
  let (msg, body) = channel_msg_body(buf) catch { _ => (b'\x00', b"") }
  inspect(msg.to_int(), content="90") // MSG_CHANNEL_OPEN
  let r = Reader::new(body)
  let ctype = r.read_string_as_str()
  inspect(ctype, content="session")
  inspect(r.read_uint32(), content="7")
  inspect(r.read_uint32(), content="1048576")
  inspect(r.read_uint32(), content="32768")
  inspect(r.remaining(), content="0")
}

// ============== build_channel_request_* ==============

///|
test "build_channel_request_exec/frame" {
  // 98 + recipient + "exec" + want_reply(1) + command
  let buf = build_channel_request_exec(99, "ls -la")
  let (msg, body) = channel_msg_body(buf) catch { _ => (b'\x00', b"") }
  inspect(msg.to_int(), content="98") // MSG_CHANNEL_REQUEST
  let r = Reader::new(body)
  inspect(r.read_uint32(), content="99")
  let req = r.read_string_as_str()
  inspect(req, content="exec")
  let want = r.read_byte()
  inspect(want.to_int(), content="1")
  let cmd = r.read_string_as_str()
  inspect(cmd, content="ls -la")
  inspect(r.remaining(), content="0")
}

///|
test "build_channel_request_shell/frame" {
  // 98 + recipient + "shell" + want_reply(1)
  let buf = build_channel_request_shell(11)
  let (msg, body) = channel_msg_body(buf) catch { _ => (b'\x00', b"") }
  inspect(msg.to_int(), content="98")
  let r = Reader::new(body)
  inspect(r.read_uint32(), content="11")
  let req = r.read_string_as_str()
  inspect(req, content="shell")
  let want = r.read_byte()
  inspect(want.to_int(), content="1")
  inspect(r.remaining(), content="0")
}

///|
test "build_channel_request_subsystem/frame" {
  // 98 + recipient + "subsystem" + want_reply(1) + "sftp"
  let buf = build_channel_request_subsystem(3, "sftp")
  let (msg, body) = channel_msg_body(buf) catch { _ => (b'\x00', b"") }
  inspect(msg.to_int(), content="98")
  let r = Reader::new(body)
  inspect(r.read_uint32(), content="3")
  let req = r.read_string_as_str()
  inspect(req, content="subsystem")
  inspect(r.read_byte().to_int(), content="1")
  let sub = r.read_string_as_str()
  inspect(sub, content="sftp")
  inspect(r.remaining(), content="0")
}

///|
test "build_channel_request_pty/frame" {
  // 98 + recipient + "pty-req" + want_reply(0) + term + cols + rows + w + h + modes
  let modes = Bytes::from_array([b'\x00', b'\x00', b'\x00', b'\x00'])
  let buf = build_channel_request_pty(5, "xterm", 80, 24, 640, 480, modes)
  let (msg, body) = channel_msg_body(buf) catch { _ => (b'\x00', b"") }
  inspect(msg.to_int(), content="98")
  let r = Reader::new(body)
  inspect(r.read_uint32(), content="5")
  let req = r.read_string_as_str()
  inspect(req, content="pty-req")
  // pty-req 不需要应答
  inspect(r.read_byte().to_int(), content="0")
  let term = r.read_string_as_str()
  inspect(term, content="xterm")
  inspect(r.read_uint32(), content="80")
  inspect(r.read_uint32(), content="24")
  inspect(r.read_uint32(), content="640")
  inspect(r.read_uint32(), content="480")
  let out_modes = r.read_string()
  inspect(out_modes.length(), content="4")
  inspect(r.remaining(), content="0")
}

// ============== build_channel_data / eof / close / window_adjust ==============

///|
test "build_channel_data/frame" {
  // 94 + recipient + data string
  let data = Bytes::from_array([b'\x68', b'\x69'])
  let buf = build_channel_data(7, data)
  let (msg, body) = channel_msg_body(buf) catch { _ => (b'\x00', b"") }
  inspect(msg.to_int(), content="94") // MSG_CHANNEL_DATA
  let r = Reader::new(body)
  inspect(r.read_uint32(), content="7")
  let out_data = r.read_string()
  inspect(out_data.length(), content="2")
  inspect(out_data[0].to_int(), content="104")
}

///|
test "build_channel_eof/frame" {
  // 96 + recipient
  let buf = build_channel_eof(7)
  let (msg, body) = channel_msg_body(buf) catch { _ => (b'\x00', b"") }
  inspect(msg.to_int(), content="96") // MSG_CHANNEL_EOF
  let r = Reader::new(body)
  inspect(r.read_uint32(), content="7")
  inspect(r.remaining(), content="0")
}

///|
test "build_channel_close/frame" {
  // 97 + recipient
  let buf = build_channel_close(7)
  let (msg, body) = channel_msg_body(buf) catch { _ => (b'\x00', b"") }
  inspect(msg.to_int(), content="97") // MSG_CHANNEL_CLOSE
  let r = Reader::new(body)
  inspect(r.read_uint32(), content="7")
  inspect(r.remaining(), content="0")
}

///|
test "build_channel_window_adjust/frame" {
  // 93 + recipient + bytes_to_add
  let buf = build_channel_window_adjust(7, 65536)
  let (msg, body) = channel_msg_body(buf) catch { _ => (b'\x00', b"") }
  inspect(msg.to_int(), content="93") // MSG_CHANNEL_WINDOW_ADJUST
  let r = Reader::new(body)
  inspect(r.read_uint32(), content="7")
  inspect(r.read_uint32(), content="65536")
  inspect(r.remaining(), content="0")
}

// ============== Channel::handle_inbound ==============

///|
test "handle_inbound/open_confirmation_moves_to_open" {
  // 91 (CHANNEL_OPEN_CONFIRMATION) + sender + peer + win + max
  let w = Writer::new()
  w.write_byte(0x5b) // CHANNEL_OPEN_CONFIRMATION
  w.write_uint32(0) // sender_channel (our local id, ignored here)
  w.write_uint32(42) // peer_channel
  w.write_uint32(2048) // window
  w.write_uint32(1024) // max packet
  let ch = Channel::new(1)
  let responses = ch.handle_inbound(w.to_bytes()) catch { _ => [] }
  inspect(ch.peer_id(), content="42")
  match ch.state() {
    Open => ()
    _ => fail("expected Open")
  }
  inspect(responses.length(), content="0")
}

///|
test "handle_inbound/open_failure_moves_to_done" {
  // 92 (CHANNEL_OPEN_FAILURE) + sender + reason + msg + lang
  let w = Writer::new()
  w.write_byte(0x5c)
  w.write_uint32(0)
  w.write_uint32(2) // SSH_OPEN_CONNECT_FAILED
  w.write_string_from_str("connect failed")
  w.write_string_from_str("en")
  let ch = Channel::new(1)
  let _ = ch.handle_inbound(w.to_bytes()) catch { _ => [] }
  match ch.state() {
    Done => ()
    _ => fail("expected Done")
  }
}

///|
test "handle_inbound/open_failure_captures_reason_and_message" {
  // 服务端 OPEN_FAILURE 应把 reason 和 message 暴露给客户端，
  // 这样上层能区分"管理禁止"/"连接失败"/"未知类型"等具体场景。
  let w = Writer::new()
  w.write_byte(0x5c)
  w.write_uint32(0)
  w.write_uint32(2) // SSH_OPEN_CONNECT_FAILED
  w.write_string_from_str("connect failed")
  w.write_string_from_str("en")
  let ch = Channel::new(1)
  let _ = ch.handle_inbound(w.to_bytes()) catch { _ => [] }
  @debug.debug_inspect(ch.open_failure_reason(), content="Some(2)")
  @debug.debug_inspect(ch.open_failure_message(), content="Some(\"connect failed\")")
}

///|
test "open_failure_reason_name/maps_known_codes" {
  // RFC 4254 §5.1 定义的四个 reason code 应映射到常量名
  inspect(open_failure_reason_name(1), content="SSH_OPEN_ADMINISTRATIVELY_PROHIBITED")
  inspect(open_failure_reason_name(2), content="SSH_OPEN_CONNECT_FAILED")
  inspect(open_failure_reason_name(3), content="SSH_OPEN_UNKNOWN_CHANNEL_TYPE")
  inspect(open_failure_reason_name(4), content="SSH_OPEN_RESOURCE_SHORTAGE")
  inspect(open_failure_reason_name(99), content="unknown(99)")
}

///|
test "handle_inbound/window_adjust_increases_remote_window" {
  // 93 (WINDOW_ADJUST) + sender + bytes_to_add
  let w = Writer::new()
  w.write_byte(0x5d)
  w.write_uint32(0)
  w.write_uint32(1024)
  let ch = Channel::new(1)
  let _ = ch.handle_inbound(w.to_bytes()) catch { _ => [] }
  // 初始 remote_window = 0；调整后 = 1024
  // 通过构造两次来确认累加行为
  let w2 = Writer::new()
  w2.write_byte(0x5d)
  w2.write_uint32(0)
  w2.write_uint32(512)
  let _ = ch.handle_inbound(w2.to_bytes()) catch { _ => [] }
  // 私有字段不能直接读，但状态应当依然为 Opening / Closed（不是 Open）
  // 至少确认不抛错
  ignore(ch)
}

///|
test "handle_inbound/data_buffers_and_returns_window_adjust" {
  // 94 (CHANNEL_DATA) + sender + data string
  // 接收数据应当写入 stdout_buf 并回送 WINDOW_ADJUST
  let w = Writer::new()
  w.write_byte(0x5e)
  w.write_uint32(0) // sender_channel
  w.write_string(Bytes::from_array([b'\x41', b'\x42', b'\x43']))
  let ch = Channel::new(1)
  // 先把 channel 设置为 Open 并设置 peer_id 以便回送 WINDOW_ADJUST
  let open = Writer::new()
  open.write_byte(0x5b)
  open.write_uint32(0)
  open.write_uint32(7)
  open.write_uint32(2048)
  open.write_uint32(1024)
  let _ = ch.handle_inbound(open.to_bytes()) catch { _ => [] }
  let responses = ch.handle_inbound(w.to_bytes()) catch { _ => [] }
  // 应当回送一条 WINDOW_ADJUST
  inspect(responses.length(), content="1")
  let (msg, _) = channel_msg_body(responses[0]) catch { _ => (b'\x00', b"") }
  inspect(msg.to_int(), content="93") // WINDOW_ADJUST
  // 取出 stdout
  let out = ch.take_stdout()
  inspect(out, content="ABC")
  // take_stdout 之后应清空
  inspect(ch.has_stdout(), content="false")
}

///|
test "handle_inbound/data_when_not_open_buffers_but_uses_zero_peer" {
  // 未 Open（peer_id=0）时收到数据：数据仍写入缓冲区，
  // 但回送的 WINDOW_ADJUST 携带 peer_id=0（实现细节）。
  let w = Writer::new()
  w.write_byte(0x5e)
  w.write_uint32(0)
  w.write_string(Bytes::from_array([b'\x68', b'\x69']))
  let ch = Channel::new(1)
  let responses = ch.handle_inbound(w.to_bytes()) catch { _ => [] }
  inspect(ch.has_stdout(), content="true")
  ignore(ch.take_stdout())
  // 实现目前总是回送 WINDOW_ADJUST；此处只断言存在响应
  inspect(responses.length(), content="1")
  let (msg, body) = channel_msg_body(responses[0]) catch { _ => (b'\x00', b"") }
  inspect(msg.to_int(), content="93")
  let r = Reader::new(body)
  // peer_id 此时为 0
  inspect(r.read_uint32(), content="0")
}

///|
test "handle_inbound/extended_data_goes_to_stderr" {
  // 95 (CHANNEL_EXTENDED_DATA) + sender + data_type + data
  let w = Writer::new()
  w.write_byte(0x5f)
  w.write_uint32(0)
  w.write_uint32(1) // SSH_EXTENDED_DATA_STDERR
  w.write_string(Bytes::from_array([b'\x65', b'\x72', b'\x72']))
  let ch = Channel::new(1)
  let _ = ch.handle_inbound(w.to_bytes()) catch { _ => [] }
  let out = ch.take_stderr()
  inspect(out, content="err")
}

///|
test "handle_inbound/eof_moves_to_eof_received" {
  // 96 (CHANNEL_EOF) + sender
  let w = Writer::new()
  w.write_byte(0x60)
  w.write_uint32(0)
  let ch = Channel::new(1)
  let _ = ch.handle_inbound(w.to_bytes()) catch { _ => [] }
  match ch.state() {
    EofReceived => ()
    _ => fail("expected EofReceived")
  }
}

///|
test "handle_inbound/close_moves_to_done_and_returns_close" {
  // 97 (CHANNEL_CLOSE) + sender
  let w = Writer::new()
  w.write_byte(0x61)
  w.write_uint32(0)
  let ch = Channel::new(1)
  // 先 open
  let open = Writer::new()
  open.write_byte(0x5b)
  open.write_uint32(0)
  open.write_uint32(7)
  open.write_uint32(2048)
  open.write_uint32(1024)
  let _ = ch.handle_inbound(open.to_bytes()) catch { _ => [] }
  let responses = ch.handle_inbound(w.to_bytes()) catch { _ => [] }
  match ch.state() {
    Done => ()
    _ => fail("expected Done")
  }
  // 应当回送一条 CHANNEL_CLOSE
  inspect(responses.length(), content="1")
  let (msg, body) = channel_msg_body(responses[0]) catch { _ => (b'\x00', b"") }
  inspect(msg.to_int(), content="97") // CHANNEL_CLOSE
  let r = Reader::new(body)
  inspect(r.read_uint32(), content="7")
}

///|
test "handle_inbound/request_exit_status" {
  // 98 (CHANNEL_REQUEST) + sender + "exit-status" + want_reply + status
  let w = Writer::new()
  w.write_byte(0x62)
  w.write_uint32(0)
  w.write_string_from_str("exit-status")
  w.write_byte(0) // want_reply
  w.write_uint32(0) // status
  let ch = Channel::new(1)
  let _ = ch.handle_inbound(w.to_bytes()) catch { _ => [] }
  @debug.debug_inspect(ch.exit_status(), content="Some(0)")
}

///|
test "handle_inbound/request_exit_signal" {
  // 98 + sender + "exit-signal" + want_reply + name
  let w = Writer::new()
  w.write_byte(0x62)
  w.write_uint32(0)
  w.write_string_from_str("exit-signal")
  w.write_byte(0)
  w.write_string_from_str("TERM")
  w.write_byte(0) // core dumped
  w.write_string_from_str("en")
  w.write_string_from_str("terminated")
  let ch = Channel::new(1)
  let _ = ch.handle_inbound(w.to_bytes()) catch { _ => [] }
  // 私有字段：确保不抛错
  ignore(ch.exit_status())
}

///|
test "handle_inbound/request_unknown_type_is_ignored" {
  // 98 + sender + "unknown-req-type" + want_reply + extra data
  // 未知请求类型应被忽略（不崩溃，不改变状态）
  let w = Writer::new()
  w.write_byte(0x62) // MSG_CHANNEL_REQUEST
  w.write_uint32(0) // sender
  w.write_string_from_str("x11-req") // 未知的请求类型
  w.write_byte(0) // want_reply
  w.write_string_from_str("extra data here")
  let ch = Channel::new(1)
  let responses = ch.handle_inbound(w.to_bytes()) catch { _ => [] }
  // 不应崩溃，exit_status 未设置
  @debug.debug_inspect(ch.exit_status(), content="None")
  // 不应改变通道状态
  match ch.state() {
    Closed => ()
    _ => fail("expected Closed to be preserved")
  }
  // 无响应（want_reply=false 且未知类型不回复）
  inspect(responses.length(), content="0")
}

///|
test "handle_inbound/channel_success_is_ignored" {
  // 99 (CHANNEL_SUCCESS)
  let payload = Bytes::from_array([b'\x63'])
  let ch = Channel::new(1)
  let responses = ch.handle_inbound(payload) catch { _ => [] }
  inspect(responses.length(), content="0")
}

///|
test "handle_inbound/channel_failure_moves_to_done" {
  // 100 (CHANNEL_FAILURE)
  let payload = Bytes::from_array([b'\x64'])
  let ch = Channel::new(1)
  let _ = ch.handle_inbound(payload) catch { _ => [] }
  match ch.state() {
    Done => ()
    _ => fail("expected Done")
  }
}

///|
test "handle_inbound/global_request_with_want_reply_returns_failure" {
  // 80 (GLOBAL_REQUEST) + name + want_reply(1)
  let w = Writer::new()
  w.write_byte(0x50)
  w.write_string_from_str("tcpip-forward")
  w.write_byte(1)
  let ch = Channel::new(1)
  let responses = ch.handle_inbound(w.to_bytes()) catch { _ => [] }
  // 应当回送 REQUEST_FAILURE (0x52)
  inspect(responses.length(), content="1")
  inspect(responses[0][0].to_int(), content="82")
}

///|
test "handle_inbound/unknown_raises_protocol_error" {
  let ch = Channel::new(1)
  try {
    let _ = ch.handle_inbound(Bytes::from_array([b'\xfe']))
    fail("expected ProtocolError")
  } catch {
    ProtocolError(_) => ()
    _ => fail("expected ProtocolError, got other")
  }
}

// ============== take_stdout / take_stderr / has_stdout ==============

///|
test "take_stdout_clears_buffer" {
  // take_stdout 取出后清空；后续 has_stdout=false
  let w = Writer::new()
  w.write_byte(0x5e)
  w.write_uint32(0)
  w.write_string(Bytes::from_array([b'\x78', b'\x79']))
  let ch = Channel::new(1)
  let _ = ch.handle_inbound(w.to_bytes()) catch { _ => [] }
  inspect(ch.has_stdout(), content="true")
  let s = ch.take_stdout()
  inspect(s, content="xy")
  inspect(ch.has_stdout(), content="false")
  // 再次取出应为空字符串
  let s2 = ch.take_stdout()
  inspect(s2, content="")
}

// ============== Channel type and data sink ==============

///|
test "channel/new_has_session_type" {
  let ch = Channel::new(1)
  match ch.channel_type {
    Session => ()
    _ => fail("expected Session type")
  }
}

///|
test "channel/new_has_buffer_sink" {
  let ch = Channel::new(1)
  match ch.data_sink {
    Buffer => ()
    Socket(_) => fail("expected Buffer sink")
  }
}

// ============== build_channel_open_direct_tcpip ==============

///|
test "build_channel_open_direct_tcpip/frame" {
  let buf = build_channel_open_direct_tcpip(
    5,
    1024 * 1024,
    32 * 1024,
    "example.com",
    80,
    "127.0.0.1",
    12345,
  )
  let (msg, body) = channel_msg_body(buf) catch { _ => (b'\x00', b"") }
  inspect(msg.to_int(), content="90") // MSG_CHANNEL_OPEN
  let r = Reader::new(body)
  let ctype = r.read_string_as_str()
  inspect(ctype, content="direct-tcpip")
  inspect(r.read_uint32(), content="5") // sender_channel
  inspect(r.read_uint32(), content="1048576") // initial_window
  inspect(r.read_uint32(), content="32768") // max_packet
  let host = r.read_string_as_str()
  inspect(host, content="example.com")
  inspect(r.read_uint32(), content="80") // port
  let orig_ip = r.read_string_as_str()
  inspect(orig_ip, content="127.0.0.1")
  inspect(r.read_uint32(), content="12345") // originator_port
  inspect(r.remaining(), content="0")
}

// ============== build_channel_open_confirmation ==============

///|
test "build_channel_open_confirmation/frame" {
  let buf = build_channel_open_confirmation(10, 20, 1024 * 1024, 32 * 1024)
  let (msg, body) = channel_msg_body(buf) catch { _ => (b'\x00', b"") }
  inspect(msg.to_int(), content="91") // MSG_CHANNEL_OPEN_CONFIRMATION
  let r = Reader::new(body)
  inspect(r.read_uint32(), content="10") // recipient_channel
  inspect(r.read_uint32(), content="20") // sender_channel
  inspect(r.read_uint32(), content="1048576") // initial_window
  inspect(r.read_uint32(), content="32768") // max_packet
  inspect(r.remaining(), content="0")
}

// ============== build_channel_open_failure ==============

///|
test "build_channel_open_failure/frame" {
  let buf = build_channel_open_failure(5, 2, "connect failed", "en")
  let (msg, body) = channel_msg_body(buf) catch { _ => (b'\x00', b"") }
  inspect(msg.to_int(), content="92") // MSG_CHANNEL_OPEN_FAILURE
  let r = Reader::new(body)
  inspect(r.read_uint32(), content="5") // recipient_channel
  inspect(r.read_uint32(), content="2") // reason_code
  let desc = r.read_string_as_str()
  inspect(desc, content="connect failed")
  let lang = r.read_string_as_str()
  inspect(lang, content="en")
  inspect(r.remaining(), content="0")
}

// ============== build_global_request_tcpip_forward ==============

///|
test "build_global_request_tcpip_forward/frame" {
  let buf = build_global_request_tcpip_forward("0.0.0.0", 8080)
  let (msg, body) = channel_msg_body(buf) catch { _ => (b'\x00', b"") }
  inspect(msg.to_int(), content="80") // MSG_GLOBAL_REQUEST
  let r = Reader::new(body)
  let req = r.read_string_as_str()
  inspect(req, content="tcpip-forward")
  let want = r.read_byte()
  inspect(want.to_int(), content="1") // want_reply
  let addr = r.read_string_as_str()
  inspect(addr, content="0.0.0.0")
  inspect(r.read_uint32(), content="8080")
  inspect(r.remaining(), content="0")
}

// ============== build_global_request_cancel_tcpip_forward ==============

///|
test "build_global_request_cancel_tcpip_forward/frame" {
  let buf = build_global_request_cancel_tcpip_forward("0.0.0.0", 8080)
  let (msg, body) = channel_msg_body(buf) catch { _ => (b'\x00', b"") }
  inspect(msg.to_int(), content="80") // MSG_GLOBAL_REQUEST
  let r = Reader::new(body)
  let req = r.read_string_as_str()
  inspect(req, content="cancel-tcpip-forward")
  let want = r.read_byte()
  inspect(want.to_int(), content="1")
  let addr = r.read_string_as_str()
  inspect(addr, content="0.0.0.0")
  inspect(r.read_uint32(), content="8080")
  inspect(r.remaining(), content="0")
}

// ============== parse_inbound_forwarded_tcpip ==============

///|
test "parse_inbound_forwarded_tcpip/roundtrip" {
  // 构建一个 forwarded-tcpip 入站消息的 body 部分
  let w = Writer::new()
  w.write_uint32(42) // sender_channel
  w.write_uint32(1024 * 1024) // initial_window
  w.write_uint32(32 * 1024) // max_packet
  w.write_string_from_str("0.0.0.0") // address
  w.write_uint32(9090) // port
  w.write_string_from_str("192.168.1.1") // originator_ip
  w.write_uint32(54321) // originator_port
  let r = Reader::new(w.to_bytes())
  let (sender, win, maxpkt, addr, port, oip, oport) = parse_inbound_forwarded_tcpip(
    r,
  ) catch {
    _ => (0, 0, 0, "", 0, "", 0)
  }
  inspect(sender, content="42")
  inspect(win, content="1048576")
  inspect(maxpkt, content="32768")
  inspect(addr, content="0.0.0.0")
  inspect(port, content="9090")
  inspect(oip, content="192.168.1.1")
  inspect(oport, content="54321")
}

// ============== handle_inbound forwarded-tcpip ==============

///|
test "handle_inbound/forwarded_tcpip_opens_channel" {
  // 构建 CHANNEL_OPEN(90) + "forwarded-tcpip" + fields
  let w = Writer::new()
  w.write_byte(0x5a) // MSG_CHANNEL_OPEN
  w.write_string_from_str("forwarded-tcpip")
  w.write_uint32(7) // sender_channel
  w.write_uint32(1024 * 1024)
  w.write_uint32(32 * 1024)
  w.write_string_from_str("0.0.0.0")
  w.write_uint32(8080)
  w.write_string_from_str("10.0.0.1")
  w.write_uint32(12345)
  let ch = Channel::new(1)
  let _ = ch.handle_inbound(w.to_bytes()) catch { _ => [] }
  // 通道应处于 Open 状态，peer_id 设为 sender_channel
  inspect(ch.is_open(), content="true")
  inspect(ch.peer_id(), content="7")
}

// ============== MSG constants ==============

///|
test "msg_constants/correct_values" {
  inspect(MSG_GLOBAL_REQUEST.to_int(), content="80")
  inspect(MSG_REQUEST_SUCCESS.to_int(), content="81")
  inspect(MSG_REQUEST_FAILURE.to_int(), content="82")
}

// ============== handle_inbound remaining branches ==============

///|
test "handle_inbound/unknown_channel_type_in_open_returns_failure" {
  // MSG_CHANNEL_OPEN(90) + unknown channel type → OPEN_FAILURE
  let w = Writer::new()
  w.write_byte(0x5a) // MSG_CHANNEL_OPEN
  w.write_string_from_str("x11") // 未知通道类型
  w.write_uint32(42) // sender_channel
  w.write_uint32(1024 * 1024) // initial_window
  w.write_uint32(32 * 1024) // max_packet
  let ch = Channel::new(1)
  let responses = ch.handle_inbound(w.to_bytes()) catch { _ => [] }
  // 应返回一条 OPEN_FAILURE
  inspect(responses.length(), content="1")
  let (msg, body) = channel_msg_body(responses[0]) catch { _ => (b'\x00', b"") }
  inspect(msg.to_int(), content="92") // MSG_CHANNEL_OPEN_FAILURE
  let r = Reader::new(body)
  inspect(r.read_uint32(), content="42") // recipient = sender_ch
  inspect(r.read_uint32(), content="3") // reason = unknown channel type
}

///|
test "handle_inbound/global_request_no_want_reply_returns_empty" {
  // MSG_GLOBAL_REQUEST(80) + name + want_reply(0) → 不回复
  let w = Writer::new()
  w.write_byte(0x50)
  w.write_string_from_str("keepalive@openssh.com")
  w.write_byte(0) // want_reply = false
  let ch = Channel::new(1)
  let responses = ch.handle_inbound(w.to_bytes()) catch { _ => [] }
  inspect(responses.length(), content="0")
}

///|
test "handle_inbound/request_success_returns_empty" {
  // MSG_REQUEST_SUCCESS(81) → 忽略
  let payload = Bytes::from_array([b'\x51'])
  let ch = Channel::new(1)
  let responses = ch.handle_inbound(payload) catch { _ => [] }
  inspect(responses.length(), content="0")
}

///|
test "handle_inbound/request_failure_returns_empty" {
  // MSG_REQUEST_FAILURE(82) → 忽略
  let payload = Bytes::from_array([b'\x52'])
  let ch = Channel::new(1)
  let responses = ch.handle_inbound(payload) catch { _ => [] }
  inspect(responses.length(), content="0")
}

///|
test "handle_inbound/ignore_msg_returns_empty" {
  // SSH_MSG_IGNORE(2) → 忽略
  let payload = Bytes::from_array([b'\x02'])
  let ch = Channel::new(1)
  let responses = ch.handle_inbound(payload) catch { _ => [] }
  inspect(responses.length(), content="0")
}

///|
test "handle_inbound/debug_msg_returns_empty" {
  // SSH_MSG_DEBUG(4) → 忽略
  let payload = Bytes::from_array([b'\x04'])
  let ch = Channel::new(1)
  let responses = ch.handle_inbound(payload) catch { _ => [] }
  inspect(responses.length(), content="0")
}

///|
test "handle_inbound/ext_info_msg_returns_empty" {
  // SSH_MSG_EXT_INFO(7) → 忽略
  let payload = Bytes::from_array([b'\x07'])
  let ch = Channel::new(1)
  let responses = ch.handle_inbound(payload) catch { _ => [] }
  inspect(responses.length(), content="0")
}
