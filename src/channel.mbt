///|
/// SSH 连接通道协议（RFC 4254）。
///
/// v0.1 实现的子集：
///   - 打开 `session` 通道
///   - 发送 `exec` 请求（执行命令）
///   - 接收 stdout（SSH_MSG_CHANNEL_DATA）到 EOF
///   - 接收 exit-status
///   - 关闭窗口
///
/// 不实现：
///   - 端口转发 / X11 / agent 转发
///   - shell / pty
///   - subsystem

///|
/// 通道消息类型。
pub const MSG_CHANNEL_OPEN : Byte = b'\x5a' // 90

///|
pub const MSG_CHANNEL_OPEN_CONFIRMATION : Byte = b'\x5b' // 91

///|
pub const MSG_CHANNEL_OPEN_FAILURE : Byte = b'\x5c' // 92

///|
pub const MSG_CHANNEL_WINDOW_ADJUST : Byte = b'\x5d' // 93

///|
pub const MSG_CHANNEL_DATA : Byte = b'\x5e' // 94

///|
pub const MSG_CHANNEL_EXTENDED_DATA : Byte = b'\x7f' // 127

///|
pub const MSG_CHANNEL_EOF : Byte = b'\x5f' // 95

///|
pub const MSG_CHANNEL_CLOSE : Byte = b'\x60' // 96

///|
pub const MSG_CHANNEL_REQUEST : Byte = b'\x62' // 98

///|
pub const MSG_CHANNEL_SUCCESS : Byte = b'\x62' // 99

///|
/// 请求类型名常量。
pub fn request_type_exec() -> String {
  "exec"
}

///|
pub fn request_type_shell() -> String {
  "shell"
}

///|
pub fn request_type_env() -> String {
  "env"
}

///|
pub struct Channel {
  priv id : Int
  mut peer_id : Int
  priv local_window : Int
  priv local_max_packet : Int
  mut remote_window : Int
  remote_max_packet : Int
  mut state : ChannelState
  priv session_id : Bytes
  stdout_buf : Array[Byte]
  stderr_buf : Array[Byte]
  mut exit_status : Int?
  mut exit_signal : String?
}

///|
pub enum ChannelState {
  /// Channel not yet opened.
  Closed
  /// Sent `SSH_MSG_CHANNEL_OPEN`; awaiting confirmation.
  Opening
  /// Open; ready to send / receive data.
  Open
  /// Sent `exec` request; awaiting response.
  ExecPending
  /// Remote sent EOF.
  EofReceived
  /// Local sent `SSH_MSG_CHANNEL_CLOSE`.
  Closing
  /// Channel fully closed.
  Done
} derive(Eq, Show)

// Factory functions for cross-package construction
pub fn ChannelState::closed() -> ChannelState { Closed }
pub fn ChannelState::opening() -> ChannelState { Opening }
pub fn ChannelState::open_state() -> ChannelState { Open }
pub fn ChannelState::exec_pending() -> ChannelState { ExecPending }
pub fn ChannelState::eof_received() -> ChannelState { EofReceived }
pub fn ChannelState::closing() -> ChannelState { Closing }
pub fn ChannelState::done() -> ChannelState { Done }

///|
pub fn Channel::new(local_id : Int, session_id : Bytes) -> Channel {
  {
    id: local_id,
    peer_id: 0,
    local_window: 1024 * 1024,
    local_max_packet: 32 * 1024,
    remote_window: 0,
    remote_max_packet: 0,
    state: Closed,
    session_id,
    stdout_buf: [],
    stderr_buf: [],
    exit_status: None,
    exit_signal: None,
  }
}

///|
pub fn Channel::id(self : Channel) -> Int {
  self.id
}

///|
pub fn Channel::state(self : Channel) -> ChannelState {
  self.state
}

///|
pub fn Channel::is_open(self : Channel) -> Bool {
  self.state == Open
}

///|
pub fn Channel::exit_status(self : Channel) -> Int? {
  self.exit_status
}

///|
pub fn Channel::exit_signal(self : Channel) -> String? {
  self.exit_signal
}

// --- Wire format builders -------------------------------------------

///|
/// Build `SSH_MSG_CHANNEL_OPEN` (session channel) per RFC 4254 §5.1.
pub fn build_channel_open(
  sender_channel : Int,
  initial_window : Int,
  max_packet : Int,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_OPEN)
  w.write_string_from_str("session")
  w.write_uint32(sender_channel)
  w.write_uint32(initial_window)
  w.write_uint32(max_packet)
  w.to_bytes()
}

///|
/// Build `SSH_MSG_CHANNEL_REQUEST` (exec) per RFC 4254 §6.5.
pub fn build_channel_request_exec(
  recipient_channel : Int,
  command : String,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_REQUEST)
  w.write_uint32(recipient_channel)
  w.write_string_from_str(request_type_exec())
  w.write_byte(1) // want_reply
  w.write_string_from_str(command)
  w.to_bytes()
}

///|
/// Build `SSH_MSG_CHANNEL_DATA` per RFC 4254 §5.2.
pub fn build_channel_data(recipient_channel : Int, data : Bytes) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_DATA)
  w.write_uint32(recipient_channel)
  w.write_string(data)
  w.to_bytes()
}

///|
/// Build `SSH_MSG_CHANNEL_EOF`.
pub fn build_channel_eof(recipient_channel : Int) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_EOF)
  w.write_uint32(recipient_channel)
  w.to_bytes()
}

///|
/// Build `SSH_MSG_CHANNEL_CLOSE`.
pub fn build_channel_close(recipient_channel : Int) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_CLOSE)
  w.write_uint32(recipient_channel)
  w.to_bytes()
}

///|
/// Build `SSH_MSG_CHANNEL_WINDOW_ADJUST`.
pub fn build_channel_window_adjust(
  recipient_channel : Int,
  bytes_to_add : Int,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_WINDOW_ADJUST)
  w.write_uint32(recipient_channel)
  w.write_uint32(bytes_to_add)
  w.to_bytes()
}

// --- Incoming message handler ----------------------------------------

///|
/// Handle an incoming channel request (server → client, e.g. `exit-status`).
/// Returns any outbound messages to send in response.
fn handle_channel_request(
  ch : Channel,
  r : Reader,
) -> Array[Bytes] raise SshError {
  let _sender = r.read_uint32()
  let req_type = r.read_string_as_str()
  let _want_reply = r.read_byte()
  match req_type {
    "exit-status" => {
      let status = r.read_uint32()
      ch.exit_status = Some(status)
      []
    }
    "exit-signal" => {
      let signal_name = r.read_string_as_str()
      ch.exit_signal = Some(signal_name)
      []
    }
    _ => {
      // Unknown channel request — ignore
      let _rest = r.rest()
      []
    }
  }
}

///|
/// Handle an incoming `SSH_MSG_CHANNEL_*` message.
///
/// Returns a list of outbound messages that the channel wants to send
/// back (e.g. WINDOW_ADJUST, EOF, CLOSE). The caller pumps these through
/// the transport.
pub fn Channel::handle_inbound(
  self : Channel,
  payload : Bytes,
) -> Array[Bytes] raise SshError {
  let r = Reader::new(payload)
  let msg = r.read_byte()
  match msg {
    MSG_CHANNEL_OPEN_CONFIRMATION => {
      let _sender = r.read_uint32()
      let peer = r.read_uint32()
      let _win = r.read_uint32()
      let _max = r.read_uint32()
      self.peer_id = peer
      self.state = Open
      []
    }
    MSG_CHANNEL_OPEN_FAILURE => {
      let _sender = r.read_uint32()
      let _reason = r.read_uint32()
      let _msg = r.read_string_as_str()
      let _lang = r.read_string_as_str()
      self.state = Done
      []
    }
    MSG_CHANNEL_WINDOW_ADJUST => {
      let _sender = r.read_uint32()
      let bytes_to_add = r.read_uint32()
      self.remote_window = self.remote_window + bytes_to_add
      []
    }
    MSG_CHANNEL_DATA => {
      let _sender = r.read_uint32()
      let data = r.read_string()
      for b in data {
        self.stdout_buf.push(b)
      }
      [build_channel_window_adjust(self.peer_id, self.local_max_packet)]
    }
    MSG_CHANNEL_EXTENDED_DATA => {
      let _sender = r.read_uint32()
      let _data_type = r.read_uint32()
      let data = r.read_string()
      for b in data {
        self.stderr_buf.push(b)
      }
      []
    }
    MSG_CHANNEL_EOF => {
      let _sender = r.read_uint32()
      self.state = EofReceived
      []
    }
    MSG_CHANNEL_CLOSE => {
      let _sender = r.read_uint32()
      self.state = Done
      [build_channel_close(self.peer_id)]
    }
    MSG_CHANNEL_REQUEST => handle_channel_request(self, r)
    b'\x63' =>
      // 99 = CHANNEL_SUCCESS
      // Reply to want_reply=true. For exec this just means: server
      // accepted the request. We stay in Open state.
      []
    b'\x64' => {
      // 100 = CHANNEL_FAILURE: server rejected our `exec` request.
      self.state = Done
      []
    }
    _ => raise ProtocolError("channel: unexpected message \{msg.to_int()}")
  }
}

// --- Helpers ---------------------------------------------------------

///|
/// Take any buffered stdout and clear the buffer.
pub fn Channel::take_stdout(self : Channel) -> String {
  let s = bytes_to_utf8_string(Bytes::from_array(self.stdout_buf))
  self.stdout_buf.clear()
  s
}

///|
/// Take any buffered stderr and clear the buffer.
pub fn Channel::take_stderr(self : Channel) -> String {
  let s = bytes_to_utf8_string(Bytes::from_array(self.stderr_buf))
  self.stderr_buf.clear()
  s
}

///|
pub fn Channel::has_stdout(self : Channel) -> Bool {
  self.stdout_buf.length() > 0
}
