///|
/// SSH 连接通道协议（RFC 4254）。
/// 实现：open session / exec / shell / pty / close

// ============== Message types ==============

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
pub const MSG_CHANNEL_EXTENDED_DATA : Byte = b'\x5f' // 95

///|
pub const MSG_CHANNEL_EOF : Byte = b'\x60' // 96

///|
pub const MSG_CHANNEL_CLOSE : Byte = b'\x61' // 97

///|
pub const MSG_CHANNEL_REQUEST : Byte = b'\x62' // 98

///|
pub const MSG_CHANNEL_SUCCESS : Byte = b'\x63' // 99

///|
pub const MSG_CHANNEL_FAILURE : Byte = b'\x64' // 100

// ============== Channel ==============

///|
#warnings("-unused_field")
pub struct Channel {
  priv id : Int
  mut peer_id : Int
  priv local_window : Int
  priv local_max_packet : Int
  mut remote_window : Int
  remote_max_packet : Int
  mut state : ChannelState
  stdout_buf : Array[Byte]
  stderr_buf : Array[Byte]
  mut exit_status : Int?
  mut exit_signal : String?
}

///|
#warnings("-unused_constructor")
pub enum ChannelState {
  Closed
  Opening
  Open
  ExecPending
  EofReceived
  Closing
  Done
} derive(Eq, Debug)

///|
pub fn Channel::new(local_id : Int) -> Channel {
  {
    id: local_id,
    peer_id: 0,
    local_window: 1024 * 1024,
    local_max_packet: 32 * 1024,
    remote_window: 0,
    remote_max_packet: 0,
    state: Closed,
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
pub fn Channel::peer_id(self : Channel) -> Int {
  self.peer_id
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

// ============== Wire format builders ==============

///|
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
pub fn build_channel_request_exec(
  recipient_channel : Int,
  command : String,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_REQUEST)
  w.write_uint32(recipient_channel)
  w.write_string_from_str("exec")
  w.write_byte(1) // want_reply
  w.write_string_from_str(command)
  w.to_bytes()
}

///|
pub fn build_channel_request_shell(recipient_channel : Int) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_REQUEST)
  w.write_uint32(recipient_channel)
  w.write_string_from_str("shell")
  w.write_byte(1) // want_reply
  w.to_bytes()
}

///|
pub fn build_channel_request_pty(
  recipient_channel : Int,
  term : String,
  cols : Int,
  rows : Int,
  width : Int,
  height : Int,
  modes : Bytes,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_REQUEST)
  w.write_uint32(recipient_channel)
  w.write_string_from_str("pty-req")
  w.write_byte(0) // want_reply=false
  w.write_string_from_str(term)
  w.write_uint32(cols)
  w.write_uint32(rows)
  w.write_uint32(width)
  w.write_uint32(height)
  w.write_string(modes)
  w.to_bytes()
}

///|
pub fn build_channel_data(recipient_channel : Int, data : Bytes) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_DATA)
  w.write_uint32(recipient_channel)
  w.write_string(data)
  w.to_bytes()
}

///|
pub fn build_channel_eof(recipient_channel : Int) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_EOF)
  w.write_uint32(recipient_channel)
  w.to_bytes()
}

///|
pub fn build_channel_close(recipient_channel : Int) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_CLOSE)
  w.write_uint32(recipient_channel)
  w.to_bytes()
}

///|
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

// ============== Inbound handler ==============

///|
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
      let _rest = r.rest()
      []
    }
  }
}

///|
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
    b'\x63' => [] // CHANNEL_SUCCESS
    b'\x64' => {
      self.state = Done
      []
    }
    // SSH_MSG_GLOBAL_REQUEST(80), REQUEST_SUCCESS(81), REQUEST_FAILURE(82)
    // SSH_MSG_IGNORE(2), DEBUG(4), EXT_INFO(7) — skip
    b'\x50' => {
      // SSH_MSG_GLOBAL_REQUEST: 解析 want_reply 字段
      let req_name = r.read_string_as_str()
      let want_reply = if !r.eof() { r.read_byte() } else { b'\x00' }
      debug(
        "* GLOBAL_REQUEST: '\{req_name}', want_reply=\{want_reply != b'\x00'}",
      )
      if want_reply != b'\x00' {
        [b"\x52"] // SSH_MSG_REQUEST_FAILURE
      } else {
        []
      }
    }
    b'\x51' | b'\x52' | b'\x02' | b'\x04' | b'\x07' => []
    _ => raise ProtocolError("channel: unexpected msg \{msg.to_int()}")
  }
}

// ============== Helpers ==============

///|
pub fn Channel::take_stdout(self : Channel) -> String {
  let s = bytes_to_utf8_string(Bytes::from_array(self.stdout_buf))
  self.stdout_buf.clear()
  s
}

///|
pub fn Channel::take_stderr(self : Channel) -> String {
  let s = bytes_to_utf8_string(Bytes::from_array(self.stderr_buf))
  self.stderr_buf.clear()
  s
}

///|
pub fn Channel::has_stdout(self : Channel) -> Bool {
  self.stdout_buf.length() > 0
}
