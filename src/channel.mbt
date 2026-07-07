///|
/// SSH 连接通道协议（RFC 4254）。
/// 实现：open session / exec / shell / pty / close

// ============== Message types ==============

///|
/// SSH 消息号：CHANNEL_OPEN（90），请求打开通道。
pub const MSG_CHANNEL_OPEN : Byte = b'\x5a' // 90

///|
/// SSH 消息号：CHANNEL_OPEN_CONFIRMATION（91），通道打开成功。
pub const MSG_CHANNEL_OPEN_CONFIRMATION : Byte = b'\x5b' // 91

///|
/// SSH 消息号：CHANNEL_OPEN_FAILURE（92），通道打开失败。
pub const MSG_CHANNEL_OPEN_FAILURE : Byte = b'\x5c' // 92

///|
/// SSH 消息号：CHANNEL_WINDOW_ADJUST（93），调整窗口大小。
pub const MSG_CHANNEL_WINDOW_ADJUST : Byte = b'\x5d' // 93

///|
/// SSH 消息号：CHANNEL_DATA（94），通道数据。
pub const MSG_CHANNEL_DATA : Byte = b'\x5e' // 94

///|
/// SSH 消息号：CHANNEL_EXTENDED_DATA（95），扩展数据（如 stderr）。
pub const MSG_CHANNEL_EXTENDED_DATA : Byte = b'\x5f' // 95

///|
/// SSH 消息号：CHANNEL_EOF（96），通道 EOF。
pub const MSG_CHANNEL_EOF : Byte = b'\x60' // 96

///|
/// SSH 消息号：CHANNEL_CLOSE（97），关闭通道。
pub const MSG_CHANNEL_CLOSE : Byte = b'\x61' // 97

///|
/// SSH 消息号：CHANNEL_REQUEST（98），通道请求（exec/shell/subsystem 等）。
pub const MSG_CHANNEL_REQUEST : Byte = b'\x62' // 98

///|
/// SSH 消息号：CHANNEL_SUCCESS（99），请求成功。
pub const MSG_CHANNEL_SUCCESS : Byte = b'\x63' // 99

///|
/// SSH 消息号：CHANNEL_FAILURE（100），请求失败。
pub const MSG_CHANNEL_FAILURE : Byte = b'\x64' // 100

///|
/// SSH 消息号：GLOBAL_REQUEST（80），全局请求（如 tcpip-forward）。
pub const MSG_GLOBAL_REQUEST : Byte = b'\x50' // 80

///|
/// SSH 消息号：REQUEST_SUCCESS（81），全局请求成功。
pub const MSG_REQUEST_SUCCESS : Byte = b'\x51' // 81

///|
/// SSH 消息号：REQUEST_FAILURE（82），全局请求失败。
pub const MSG_REQUEST_FAILURE : Byte = b'\x52' // 82

// ============== Channel ==============

///|
/// SSH 通道（RFC 4254）。管理通道状态机、窗口和数据缓冲区。
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
  /// 通道类型（session / direct-tcpip / forwarded-tcpip）
  mut channel_type : ChannelType
  /// 数据去向（缓冲区或直连 socket）
  mut data_sink : DataSink
  /// OPEN_FAILURE 服务端返回的原因码（RFC 4254 §5.1）；未失败时为 None
  mut open_failure_reason : Int?
  /// OPEN_FAILURE 服务端返回的可读描述；未失败时为 None
  mut open_failure_message : String?
}

///|
/// 通道状态机。
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
/// 通道类型。
pub enum ChannelType {
  Session
  DirectTcpip(String, Int)
  ForwardedTcpip(String, Int)
} derive(Eq, Debug)

///|
/// 通道数据处理方式。
pub enum DataSink {
  Buffer
  Socket(@socket.Tcp)
}

///|
/// 创建本地通道。
///
/// 初始状态为 [ChannelState::Closed]；`local_window` 与 `local_max_packet` 取常用默认值
/// （1 MiB / 32 KiB），由 `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` 携带的对端参数覆写。
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
    channel_type: Session,
    data_sink: Buffer,
    open_failure_reason: None,
    open_failure_message: None,
  }
}

///|
/// 本地分配的通道号。
pub fn Channel::id(self : Channel) -> Int {
  self.id
}

///|
/// 服务端分配的通道号；在收到 `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` 之后才有值。
pub fn Channel::peer_id(self : Channel) -> Int {
  self.peer_id
}

///|
/// 当前状态机。
pub fn Channel::state(self : Channel) -> ChannelState {
  self.state
}

///|
/// 是否处于打开状态（[ChannelState::Open]）。
pub fn Channel::is_open(self : Channel) -> Bool {
  self.state == Open
}

///|
/// 远端 exec 退出码；若 `exec` 尚未结束或未触发 `exit-status` 请求则为 `None`。
pub fn Channel::exit_status(self : Channel) -> Int? {
  self.exit_status
}

///|
/// OPEN_FAILURE 服务端返回的原因码（RFC 4254 §5.1）。通道被服务端拒绝时为 `Some(reason)`，
/// 成功打开或尚未收到 OPEN_FAILURE 时为 `None`。
pub fn Channel::open_failure_reason(self : Channel) -> Int? {
  self.open_failure_reason
}

///|
/// OPEN_FAILURE 服务端返回的可读描述；通道被拒绝时为 `Some(msg)`，否则为 `None`。
pub fn Channel::open_failure_message(self : Channel) -> String? {
  self.open_failure_message
}

///|
/// 将 OPEN_FAILURE reason code 映射为 RFC 4254 §5.1 定义的常量名。
/// 未识别的值返回 `"unknown(<n>)"`。
pub fn open_failure_reason_name(reason : Int) -> String {
  match reason {
    1 => "SSH_OPEN_ADMINISTRATIVELY_PROHIBITED"
    2 => "SSH_OPEN_CONNECT_FAILED"
    3 => "SSH_OPEN_UNKNOWN_CHANNEL_TYPE"
    4 => "SSH_OPEN_RESOURCE_SHORTAGE"
    _ => "unknown(\{reason})"
  }
}

// ============== Wire format builders ==============

///|
/// 构建 SSH_MSG_CHANNEL_OPEN 消息体，请求打开一个 `"session"` 通道。
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
/// 构建 exec 通道请求消息体。
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
/// 构建 shell 通道请求消息体。
pub fn build_channel_request_shell(recipient_channel : Int) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_REQUEST)
  w.write_uint32(recipient_channel)
  w.write_string_from_str("shell")
  w.write_byte(1) // want_reply
  w.to_bytes()
}

///|
/// 构建 subsystem 通道请求消息体（如 `"sftp"`）。
pub fn build_channel_request_subsystem(
  recipient_channel : Int,
  subsystem : String,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_REQUEST)
  w.write_uint32(recipient_channel)
  w.write_string_from_str("subsystem")
  w.write_byte(1) // want_reply
  w.write_string_from_str(subsystem)
  w.to_bytes()
}

///|
/// 构建 PTY 通道请求消息体（伪终端分配）。
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
/// 构建 CHANNEL_DATA 消息体。
pub fn build_channel_data(recipient_channel : Int, data : Bytes) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_DATA)
  w.write_uint32(recipient_channel)
  w.write_string(data)
  w.to_bytes()
}

///|
/// 构建 CHANNEL_EOF 消息体。
pub fn build_channel_eof(recipient_channel : Int) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_EOF)
  w.write_uint32(recipient_channel)
  w.to_bytes()
}

///|
/// 构建 CHANNEL_CLOSE 消息体。
pub fn build_channel_close(recipient_channel : Int) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_CLOSE)
  w.write_uint32(recipient_channel)
  w.to_bytes()
}

///|
/// 构建 CHANNEL_WINDOW_ADJUST 消息体，通知对端增加窗口大小。
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

///|
/// 构建 direct-tcpip 通道打开消息（本地转发，RFC 4254 §7.2）。
pub fn build_channel_open_direct_tcpip(
  sender_channel : Int,
  initial_window : Int,
  max_packet : Int,
  host_to_connect : String,
  port_to_connect : Int,
  originator_ip : String,
  originator_port : Int,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_OPEN)
  w.write_string_from_str("direct-tcpip")
  w.write_uint32(sender_channel)
  w.write_uint32(initial_window)
  w.write_uint32(max_packet)
  w.write_string_from_str(host_to_connect)
  w.write_uint32(port_to_connect)
  w.write_string_from_str(originator_ip)
  w.write_uint32(originator_port)
  w.to_bytes()
}

///|
/// 构建通道打开确认消息（接受入站通道，RFC 4254 §5.1）。
pub fn build_channel_open_confirmation(
  recipient_channel : Int,
  sender_channel : Int,
  initial_window : Int,
  max_packet : Int,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_OPEN_CONFIRMATION)
  w.write_uint32(recipient_channel)
  w.write_uint32(sender_channel)
  w.write_uint32(initial_window)
  w.write_uint32(max_packet)
  w.to_bytes()
}

///|
/// 构建通道打开失败消息（拒绝入站通道，RFC 4254 §5.1）。
pub fn build_channel_open_failure(
  recipient_channel : Int,
  reason_code : Int,
  description : String,
  language : String,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_OPEN_FAILURE)
  w.write_uint32(recipient_channel)
  w.write_uint32(reason_code)
  w.write_string_from_str(description)
  w.write_string_from_str(language)
  w.to_bytes()
}

///|
/// 构建 tcpip-forward 全局请求（远程转发注册，RFC 4254 §7.1）。
pub fn build_global_request_tcpip_forward(
  address : String,
  port : Int,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_GLOBAL_REQUEST)
  w.write_string_from_str("tcpip-forward")
  w.write_byte(1) // want_reply = true
  w.write_string_from_str(address)
  w.write_uint32(port)
  w.to_bytes()
}

///|
/// 构建 cancel-tcpip-forward 全局请求（取消远程转发，RFC 4254 §7.1）。
pub fn build_global_request_cancel_tcpip_forward(
  address : String,
  port : Int,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_GLOBAL_REQUEST)
  w.write_string_from_str("cancel-tcpip-forward")
  w.write_byte(1) // want_reply = true
  w.write_string_from_str(address)
  w.write_uint32(port)
  w.to_bytes()
}

///|
/// 解析入站 forwarded-tcpip 通道打开消息（RFC 4254 §7.2）。
/// 返回 (sender_channel, initial_window, max_packet, address, port, originator_ip, originator_port)。
pub fn parse_inbound_forwarded_tcpip(
  r : Reader,
) -> (Int, Int, Int, String, Int, String, Int) raise SshError {
  let sender_channel = r.read_uint32()
  let initial_window = r.read_uint32()
  let max_packet = r.read_uint32()
  let address = r.read_string_as_str()
  let port = r.read_uint32()
  let originator_ip = r.read_string_as_str()
  let originator_port = r.read_uint32()
  (
    sender_channel, initial_window, max_packet, address, port, originator_ip, originator_port,
  )
}

// ============== Inbound handler ==============

///|
/// 处理 CHANNEL_REQUEST 子类型：exit-status / exit-signal。
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
/// 处理入站通道消息，更新状态并返回需要回复的消息列表。
/// 自动处理窗口调整、数据缓冲、EOF、CLOSE 等。
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
      let reason = r.read_uint32()
      let msg = r.read_string_as_str()
      let _lang = r.read_string_as_str()
      self.open_failure_reason = Some(reason)
      self.open_failure_message = Some(msg)
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
      match self.data_sink {
        Buffer =>
          for b in data {
            self.stdout_buf.push(b)
          }
        Socket(sock) =>
          sock.write_bytes(data) catch {
            e => debug("* channel data → socket write failed: \{e}")
          }
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
    // SSH_MSG_CHANNEL_OPEN(90): 处理入站通道（如 forwarded-tcpip）
    MSG_CHANNEL_OPEN => {
      let ch_type = r.read_string_as_str()
      match ch_type {
        "forwarded-tcpip" => {
          let (sender_ch, _win, _max_pkt, _addr, _port, _orig_ip, _orig_port) = parse_inbound_forwarded_tcpip(
            r,
          )
          // 通知上层需要创建新 Channel 并连接本地目标
          // 通过设置 peer_id 和状态让 Client 知道有入站通道
          self.peer_id = sender_ch
          self.state = Open
          debug(
            "* INBOUND: forwarded-tcpip from server, sender_ch=\{sender_ch}",
          )
          []
        }
        _ => {
          // 未知通道类型, 发送 OPEN_FAILURE
          let sender_ch = r.read_uint32()
          [build_channel_open_failure(sender_ch, 3, "unknown channel type", "")]
        }
      }
    }
    // SSH_MSG_GLOBAL_REQUEST(80), REQUEST_SUCCESS(81), REQUEST_FAILURE(82)
    // SSH_MSG_IGNORE(2), DEBUG(4), EXT_INFO(7) — skip
    MSG_GLOBAL_REQUEST => {
      // SSH_MSG_GLOBAL_REQUEST: 解析 want_reply 字段
      let req_name = r.read_string_as_str()
      let want_reply = if !r.eof() { r.read_byte() } else { b'\x00' }
      debug(
        "* GLOBAL_REQUEST: '\{req_name}', want_reply=\{want_reply != b'\x00'}",
      )
      if want_reply != b'\x00' {
        [Bytes::make(1, MSG_REQUEST_FAILURE)]
      } else {
        []
      }
    }
    MSG_REQUEST_SUCCESS | MSG_REQUEST_FAILURE | b'\x02' | b'\x04' | b'\x07' =>
      []
    _ => raise ProtocolError("channel: unexpected msg \{msg.to_int()}")
  }
}

// ============== Helpers ==============

///|
/// 取出并清空 stdout 缓冲区内容（UTF-8 解码）。
pub fn Channel::take_stdout(self : Channel) -> String {
  let s = bytes_to_utf8_string(Bytes::from_array(self.stdout_buf))
  self.stdout_buf.clear()
  s
}

///|
/// 取出并清空 stderr 缓冲区内容（UTF-8 解码）。
pub fn Channel::take_stderr(self : Channel) -> String {
  let s = bytes_to_utf8_string(Bytes::from_array(self.stderr_buf))
  self.stderr_buf.clear()
  s
}

///|
/// 检查 stdout 缓冲区是否有数据。
pub fn Channel::has_stdout(self : Channel) -> Bool {
  self.stdout_buf.length() > 0
}
