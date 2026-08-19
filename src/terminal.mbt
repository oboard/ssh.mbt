///
/// SSH 终端辅助工具（对应 golang.org/x/term）。
///
/// 提供：
///   - 终端尺寸查询（通过 FFI 系统调用）
///   - 终端模式（raw/restore）
///   - 密码输入（不回显）
///   - VT100 行编辑辅助（上下翻历史、回删、光标移动）
///   - PTY 窗口大小改变通知（SIGWINCH 封装）
///
/// 注：完整的 raw 模式和 PTY 操作需要 native FFI；此模块提供纯 MoonBit 的
/// 类型和协议编码层，FFI 绑定在 terminal_ffi.c 中（或通过 @sys 包）。

// ==================== Terminal size ====================

///|
/// 终端尺寸。
pub struct TerminalSize {
  pub rows : Int
  pub cols : Int
} derive(Debug, Eq)

///|
pub fn TerminalSize::default_() -> TerminalSize {
  { rows: 24, cols: 80 }
}

///|
pub fn TerminalSize::to_pty_modes(_self : TerminalSize) -> Bytes {
  // TTY modes: end-of-list (0)
  b"\x00"
}

// ==================== PTY window change ====================

///|
/// 构建 SSH_MSG_CHANNEL_REQUEST window-change（RFC 4254 §6.7）。
///
/// 当本地终端尺寸发生变化时，向服务端发送此消息以同步 PTY 尺寸。
pub fn build_channel_request_window_change(
  recipient_channel : Int,
  cols : Int,
  rows : Int,
  pixel_width : Int,
  pixel_height : Int,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_REQUEST)
  w.write_uint32(recipient_channel)
  w.write_string_from_str("window-change")
  w.write_byte(0) // want_reply = false
  w.write_uint32(cols)
  w.write_uint32(rows)
  w.write_uint32(pixel_width)
  w.write_uint32(pixel_height)
  w.to_bytes()
}

///|
/// 构建 SSH_MSG_CHANNEL_REQUEST env（RFC 4254 §6.4）。
///
/// 在 exec/shell 之前设置环境变量。
pub fn build_channel_request_env(
  recipient_channel : Int,
  name : String,
  value : String,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_REQUEST)
  w.write_uint32(recipient_channel)
  w.write_string_from_str("env")
  w.write_byte(0) // want_reply = false
  w.write_string_from_str(name)
  w.write_string_from_str(value)
  w.to_bytes()
}

///|
/// 构建 SSH_MSG_CHANNEL_REQUEST signal（RFC 4254 §6.9）。
///
/// 向远端进程发送信号（如 SIGINT、SIGTERM）。
pub fn build_channel_request_signal(
  recipient_channel : Int,
  signal_name : String,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_REQUEST)
  w.write_uint32(recipient_channel)
  w.write_string_from_str("signal")
  w.write_byte(0) // want_reply = false
  w.write_string_from_str(signal_name)
  w.to_bytes()
}

///|
/// 构建 SSH_MSG_CHANNEL_REQUEST exit-status（RFC 4254 §6.10）。
///
/// 服务端在进程退出时发送此消息告知客户端退出码。
pub fn build_channel_request_exit_status(
  recipient_channel : Int,
  exit_status : Int,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_REQUEST)
  w.write_uint32(recipient_channel)
  w.write_string_from_str("exit-status")
  w.write_byte(0) // want_reply = false
  w.write_uint32(exit_status)
  w.to_bytes()
}

///|
/// 构建 SSH_MSG_CHANNEL_REQUEST exit-signal（RFC 4254 §6.10）。
///
/// 服务端在进程被信号终止时发送此消息。
pub fn build_channel_request_exit_signal(
  recipient_channel : Int,
  signal_name : String,
  core_dumped : Bool,
  error_message : String,
  language_tag : String,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(MSG_CHANNEL_REQUEST)
  w.write_uint32(recipient_channel)
  w.write_string_from_str("exit-signal")
  w.write_byte(0) // want_reply = false
  w.write_string_from_str(signal_name)
  w.write_byte(if core_dumped { 1 } else { 0 })
  w.write_string_from_str(error_message)
  w.write_string_from_str(language_tag)
  w.to_bytes()
}

// ==================== SSH PTY terminal modes encoding ====================

///|
/// SSH PTY 模式编码（RFC 4254 §8）。
/// 模式代码常量（POSIX termios 速记）。
pub const TTYMODE_VINTR : Byte = b'\x01'

///|
pub const TTYMODE_VQUIT : Byte = b'\x02'

///|
pub const TTYMODE_VERASE : Byte = b'\x03'

///|
pub const TTYMODE_VKILL : Byte = b'\x04'

///|
pub const TTYMODE_VEOF : Byte = b'\x05'

///|
pub const TTYMODE_VEOL : Byte = b'\x06'

///|
pub const TTYMODE_VSTART : Byte = b'\x08'

///|
pub const TTYMODE_VSTOP : Byte = b'\x09'

///|
pub const TTYMODE_ECHOE : Byte = b'\x33' // 51

///|
pub const TTYMODE_ECHO : Byte = b'\x35' // 53

///|
pub const TTYMODE_ECHOCTL : Byte = b'\x3d' // 61

///|
pub const TTYMODE_ICANON : Byte = b'\x41' // 65

///|
pub const TTYMODE_ISIG : Byte = b'\x43' // 67

///|
/// 构建 SSH PTY 终端模式字节串。
/// `modes` 为 `(opcode, value)` 对的数组；末尾自动追加 TTY_OP_END (0)。
pub fn build_pty_modes(modes : Array[(Byte, Int)]) -> Bytes {
  let w = Writer::new()
  for entry in modes {
    let (opcode, value) = entry
    w.write_byte(opcode)
    w.write_uint32(value)
  }
  w.write_byte(b'\x00') // TTY_OP_END
  w.to_bytes()
}

///|
/// 构建一组常用的 PTY 终端模式（适用于大多数交互式 shell 场景）。
pub fn default_pty_modes() -> Bytes {
  build_pty_modes(
    [
      (TTYMODE_ECHO, 1),
      (TTYMODE_ECHOE, 1),
      (TTYMODE_ECHOCTL, 1),
      (TTYMODE_ICANON, 1),
      (TTYMODE_ISIG, 1),
      (TTYMODE_VINTR, 3),    // Ctrl-C
      (TTYMODE_VQUIT, 28),   // Ctrl-\
      (TTYMODE_VERASE, 127), // DEL
      (TTYMODE_VKILL, 21),   // Ctrl-U
      (TTYMODE_VEOF, 4),     // Ctrl-D
      (TTYMODE_VSTART, 17),  // Ctrl-Q
      (TTYMODE_VSTOP, 19),   // Ctrl-S
    ],
  )
}

// ==================== VT100 / ANSI escape sequences ====================

///|
/// 常用 ANSI/VT100 转义序列。
pub const ANSI_CLEAR_SCREEN : String = "\u{1b}[2J\u{1b}[H"

///|
pub const ANSI_CLEAR_LINE : String = "\u{1b}[2K\r"

///|
pub const ANSI_CURSOR_UP : String = "\u{1b}[A"

///|
pub const ANSI_CURSOR_DOWN : String = "\u{1b}[B"

///|
pub const ANSI_CURSOR_FORWARD : String = "\u{1b}[C"

///|
pub const ANSI_CURSOR_BACK : String = "\u{1b}[D"

///|
pub const ANSI_BOLD : String = "\u{1b}[1m"

///|
pub const ANSI_RESET : String = "\u{1b}[0m"

///|
/// 移动光标到指定行列（1-based）。
pub fn ansi_cursor_position(row : Int, col : Int) -> String {
  "\u{1b}[\{row};\{col}H"
}

///|
/// 设置 256 色前景色。
pub fn ansi_fg256(color_idx : Int) -> String {
  "\u{1b}[38;5;\{color_idx}m"
}

///|
/// 设置 256 色背景色。
pub fn ansi_bg256(color_idx : Int) -> String {
  "\u{1b}[48;5;\{color_idx}m"
}

// ==================== Line editor state ====================

///|
/// 简单的行编辑器状态（用于交互式 shell 的本地回显与历史）。
pub struct LineEditor {
  /// 当前行缓冲区。
  buf : Array[Char]
  /// 光标位置（0 到 buf.length()）。
  mut cursor : Int
  /// 历史记录（最旧在前）。
  history : Array[String]
  /// 历史浏览位置（-1 = 当前输入）。
  mut history_pos : Int
  /// 当浏览历史时，保存当前未提交的行。
  saved_input : Array[Char]
}

///|
/// 创建空行编辑器。
pub fn LineEditor::new() -> LineEditor {
  {
    buf: [],
    cursor: 0,
    history: [],
    history_pos: -1,
    saved_input: [],
  }
}

///|
/// 在光标位置插入字符。
pub fn LineEditor::insert(self : LineEditor, c : Char) -> Unit {
  self.buf.insert(self.cursor, c)
  self.cursor = self.cursor + 1
}

///|
/// 退格（删除光标前一个字符）。
pub fn LineEditor::backspace(self : LineEditor) -> Unit {
  if self.cursor > 0 {
    self.cursor = self.cursor - 1
    self.buf.remove(self.cursor) |> ignore
  }
}

///|
/// 删除光标处字符（Delete 键）。
pub fn LineEditor::delete(self : LineEditor) -> Unit {
  if self.cursor < self.buf.length() {
    self.buf.remove(self.cursor) |> ignore
  }
}

///|
/// 光标左移一格。
pub fn LineEditor::move_left(self : LineEditor) -> Unit {
  if self.cursor > 0 {
    self.cursor = self.cursor - 1
  }
}

///|
/// 光标右移一格。
pub fn LineEditor::move_right(self : LineEditor) -> Unit {
  if self.cursor < self.buf.length() {
    self.cursor = self.cursor + 1
  }
}

///|
/// 光标移动到行首。
pub fn LineEditor::move_home(self : LineEditor) -> Unit {
  self.cursor = 0
}

///|
/// 光标移动到行尾。
pub fn LineEditor::move_end(self : LineEditor) -> Unit {
  self.cursor = self.buf.length()
}

///|
/// 浏览历史：上（更旧）。
pub fn LineEditor::history_up(self : LineEditor) -> Unit {
  if self.history.length() == 0 {
    return
  }
  if self.history_pos == -1 {
    // save current input before navigating history
    self.saved_input.clear()
    for c in self.buf {
      self.saved_input.push(c)
    }
    self.history_pos = self.history.length() - 1
  } else if self.history_pos > 0 {
    self.history_pos = self.history_pos - 1
  } else {
    return
  }
  self.buf.clear()
  for c in self.history[self.history_pos] {
    self.buf.push(c)
  }
  self.cursor = self.buf.length()
}

///|
/// 浏览历史：下（更新）。
pub fn LineEditor::history_down(self : LineEditor) -> Unit {
  if self.history_pos == -1 {
    return
  }
  if self.history_pos < self.history.length() - 1 {
    self.history_pos = self.history_pos + 1
    self.buf.clear()
    for c in self.history[self.history_pos] {
      self.buf.push(c)
    }
  } else {
    // restore saved input
    self.history_pos = -1
    self.buf.clear()
    for c in self.saved_input {
      self.buf.push(c)
    }
  }
  self.cursor = self.buf.length()
}

///|
/// 提交当前行（Enter 键）。
/// 将当前行添加到历史并返回完整行字符串。
pub fn LineEditor::commit(self : LineEditor) -> String {
  let s = String::from_array(self.buf)
  if s.length() > 0 {
    self.history.push(s)
  }
  self.buf.clear()
  self.cursor = 0
  self.history_pos = -1
  s
}

///|
/// 清空当前行（Ctrl-C / Ctrl-U）。
pub fn LineEditor::clear(self : LineEditor) -> Unit {
  self.buf.clear()
  self.cursor = 0
  self.history_pos = -1
}

///|
/// 返回当前行内容（不提交）。
pub fn LineEditor::current(self : LineEditor) -> String {
  String::from_array(self.buf)
}
