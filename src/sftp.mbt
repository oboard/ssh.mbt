///|
/// SFTP 协议客户端（v0.1 stub）。
///
/// 仅声明公开 API 和请求/响应的 wire 编码常量。完整实现推迟到 v0.2。
/// RFC 4253 / RFC 9132 (SFTP v3) / draft-ietf-secsh-filexfer。

///|
/// SFTP 子系统名。
pub const SFTP_SUBSYSTEM : String = "sftp"

///|
/// SFTP 协议版本。
pub const SFTP_VERSION : Int = 3

///|
/// 客户端初始化消息（INIT）。
pub const FXP_INIT : Byte = b'\x01'

///|
/// 服务器版本消息（VERSION）。
pub const FXP_VERSION : Byte = b'\x02'

///|
/// 打开文件请求。
pub const FXP_OPEN : Byte = b'\x03'

///|
/// 关闭文件 handle 请求。
pub const FXP_CLOSE : Byte = b'\x04'

///|
/// 读文件请求。
pub const FXP_READ : Byte = b'\x05'

///|
/// 写文件请求。
pub const FXP_WRITE : Byte = b'\x06'

///|
/// lstat 请求。
pub const FXP_LSTAT : Byte = b'\x07'

///|
/// fstat 请求。
pub const FXP_FSTAT : Byte = b'\x08'

///|
/// setstat 请求。
pub const FXP_SETSTAT : Byte = b'\x09'

///|
/// fsetstat 请求。
pub const FXP_FSETSTAT : Byte = b'\x0a'

///|
/// opendir 请求。
pub const FXP_OPENDIR : Byte = b'\x0b'

///|
/// readdir 请求。
pub const FXP_READDIR : Byte = b'\x0c'

///|
/// remove 请求。
pub const FXP_REMOVE : Byte = b'\x0d'

///|
/// mkdir 请求。
pub const FXP_MKDIR : Byte = b'\x0e'

///|
/// rmdir 请求。
pub const FXP_RMDIR : Byte = b'\x0f'

///|
/// realpath 请求。
pub const FXP_REALPATH : Byte = b'\x10'

///|
/// stat 请求。
pub const FXP_STAT : Byte = b'\x11'

///|
/// rename 请求。
pub const FXP_RENAME : Byte = b'\x12'

///|
/// readlink 请求。
pub const FXP_READLINK : Byte = b'\x13'

///|
/// symlink 请求。
pub const FXP_SYMLINK : Byte = b'\x14'

// --- Public API (v0.1) -----------------------------------------------

///|
/// SFTP 客户端句柄。v0.1 仅声明；v0.2 完整实现。
pub struct Sftp {
  priv conn : @socket.Tcp // placeholder; real impl uses the SSH channel
  priv version : Int
}

///|
pub enum SftpError {
  /// Server returned an error status.
  Status(UInt, String)
  /// Unexpected response type.
  Protocol(String)
  /// File / directory not found.
  NotFound(String)
  /// Permission denied.
  PermissionDenied(String)
  /// Other I/O error.
  IoError(String)
} derive(Debug, Eq)

///|
/// Open an SFTP session on an existing SSH `Channel` (must already be in
/// the `session` subsystem). v0.1: stub.
pub fn Sftp::open(_ch : Channel) -> Sftp {
  // TODO(Step 4.6): implement SFTP v3 handshake (INIT/VERSION) and return
  // a usable Sftp handle. v0.1 only declares this method.
  abort("Sftp::open: not yet implemented (v0.1 stub)")
}

///|
/// Return the negotiated protocol version.
pub fn Sftp::version(self : Sftp) -> Int {
  self.version
}

///|
/// Read the entire contents of a remote file (v0.1: stub).
pub fn Sftp::read_all(_self : Sftp, _path : String) -> Bytes {
  abort("Sftp::read_all: not yet implemented (v0.1 stub)")
}

///|
/// Write the entire contents to a remote file (v0.1: stub).
pub fn Sftp::write_all(_self : Sftp, _path : String, _data : Bytes) -> Unit {
  abort("Sftp::write_all: not yet implemented (v0.1 stub)")
}

///|
/// List a directory (v0.1: stub).
pub fn Sftp::list_dir(_self : Sftp, _path : String) -> Array[String] {
  abort("Sftp::list_dir: not yet implemented (v0.1 stub)")
}

///|
/// Build an SFTP INIT packet (client → server).
pub fn build_sftp_init() -> Bytes {
  let w = Writer::new()
  w.write_byte(FXP_INIT)
  w.write_uint32(SFTP_VERSION)
  w.to_bytes()
}

///|
/// Parse a SFTP VERSION response (server → client).
pub fn parse_sftp_version(payload : Bytes) -> Int raise SshError {
  let r = Reader::new(payload)
  let msg = r.read_byte()
  if msg != FXP_VERSION {
    raise ProtocolError("SFTP: expected VERSION, got \{msg.to_int()}")
  }
  r.read_uint32()
}
