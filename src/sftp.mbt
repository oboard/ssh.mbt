///|
/// SFTP 协议实现（RFC draft-ietf-secsh-filexfer-02, version 3）
/// 提供文件上传、下载、目录管理等功能

// ============== SFTP 包类型 ==============

// 请求类型
const SSH_FXP_INIT : Byte = b'\x01'
const SSH_FXP_OPEN : Byte = b'\x03'
const SSH_FXP_CLOSE : Byte = b'\x04'
const SSH_FXP_READ : Byte = b'\x05'
const SSH_FXP_WRITE : Byte = b'\x06'
const SSH_FXP_LSTAT : Byte = b'\x07'
const SSH_FXP_FSTAT : Byte = b'\x08'
const SSH_FXP_SETSTAT : Byte = b'\x09'
const SSH_FXP_OPENDIR : Byte = b'\x0b'
const SSH_FXP_READDIR : Byte = b'\x0c'
const SSH_FXP_REMOVE : Byte = b'\x0d'
const SSH_FXP_MKDIR : Byte = b'\x0e'
const SSH_FXP_RMDIR : Byte = b'\x0f'
const SSH_FXP_REALPATH : Byte = b'\x10'
const SSH_FXP_STAT : Byte = b'\x11'
const SSH_FXP_RENAME : Byte = b'\x12'

// 响应类型
const SSH_FXP_VERSION : Byte = b'\x02'
const SSH_FXP_STATUS : Byte = b'\x65'
const SSH_FXP_HANDLE : Byte = b'\x66'
const SSH_FXP_DATA : Byte = b'\x67'
const SSH_FXP_NAME : Byte = b'\x68'
const SSH_FXP_ATTRS : Byte = b'\x69'

// SSH_FXP_STATUS 错误码
const SSH_FX_OK : Int = 0
const SSH_FX_EOF : Int = 1
const SSH_FX_NO_SUCH_FILE : Int = 2
const SSH_FX_PERMISSION_DENIED : Int = 3
const SSH_FX_FAILURE : Int = 4
const SSH_FX_BAD_MESSAGE : Int = 5
const SSH_FX_NO_CONNECTION : Int = 6
const SSH_FX_CONNECTION_LOST : Int = 7
const SSH_FX_OP_UNSUPPORTED : Int = 8

// 文件打开标志
pub const SSH_FXF_READ : Int = 0x00000001
pub const SSH_FXF_WRITE : Int = 0x00000002
pub const SSH_FXF_APPEND : Int = 0x00000004
pub const SSH_FXF_CREAT : Int = 0x00000008
pub const SSH_FXF_TRUNC : Int = 0x00000010
pub const SSH_FXF_EXCL : Int = 0x00000020

// 文件属性 flags
const SSH_FILEXFER_ATTR_SIZE : Int = 0x00000001
const SSH_FILEXFER_ATTR_UIDGID : Int = 0x00000002
const SSH_FILEXFER_ATTR_PERMISSIONS : Int = 0x00000004
const SSH_FILEXFER_ATTR_ACMODTIME : Int = 0x00000008
const SSH_FILEXFER_ATTR_EXTENDED : Int = 0x80000000

// SFTP 协议版本
const SFTP_VERSION : Int = 3

// ============== 数据结构 ==============

///|
/// SFTP 包
struct SftpPacket {
  typ : Byte
  id : Int
  data : Bytes
}

///|
/// 文件属性
pub struct SftpAttrs {
  pub flags : Int
  pub size : Int?
  pub uid : Int?
  pub gid : Int?
  pub permissions : Int?
  pub atime : Int?
  pub mtime : Int?
}

///|
/// 目录条目
pub struct SftpDirEntry {
  pub filename : String
  pub longname : String
  pub attrs : SftpAttrs
}

///|
/// SFTP 错误类型
enum SftpError {
  Status(Int, String)
  ProtocolError(String)
} derive(Show, Eq)

///|
/// 将 SftpError 转换为 SshError
fn sftp_error_to_ssh(err : SftpError) -> SshError {
  match err {
    Status(code, msg) => ProtocolError("SFTP status \{code}: \{msg}")
    ProtocolError(msg) => ProtocolError("SFTP: \{msg}")
  }
}

///|
/// SFTP 客户端
pub struct SftpClient {
  priv client : Client
  priv channel : Channel
  priv version : Int
  mut request_id : Int
}

// ============== 帧编解码 ==============

///|
/// 编码 SFTP 包（写入 channel data 前）
fn encode_sftp_packet(typ : Byte, id : Int, payload : Bytes) -> Bytes {
  let w = Writer::new()
  w.write_uint32(1 + 4 + payload.length())
  w.write_byte(typ)
  w.write_uint32(id)
  w.write_bytes(payload)
  w.to_bytes()
}

///|
/// 从 channel data 解码 SFTP 包
fn decode_sftp_packet(data : Bytes) -> SftpPacket raise SshError {
  let r = Reader::new(data)
  let _len = r.read_uint32()
  let typ = r.read_byte()
  let id = r.read_uint32()
  let rest = r.rest()
  { typ, id, data: rest }
}

///|
/// 从 SSH channel 中读取一个完整的 SFTP 数据包
fn sftp_recv(client : Client, channel : Channel) -> Bytes raise SshError {
  while true {
    let payload = client.read_packet()
    let responses = channel.handle_inbound(payload)
    for resp in responses {
      client.write_packet(resp)
    }

    // 检查是否为 CHANNEL_DATA
    if payload.length() > 0 && payload.unsafe_get(0) == MSG_CHANNEL_DATA {
      let r = Reader::new(payload)
      let _msg = r.read_byte()
      let _sender = r.read_uint32()
      let data = r.read_string()
      return data
    }

    // EOF/DONE 说明通道关闭
    if channel.state() == EofReceived || channel.state() == Done {
      raise ProtocolError("SFTP: channel closed unexpectedly")
    }
  }
  raise ProtocolError("SFTP: unreachable in sftp_recv")
}

// ============== SFTP Client 初始化 ==============

///|
/// 等待 channel open confirmation
fn recv_until_open(client : Client, channel : Channel) -> Unit raise SshError {
  while channel.state() != Open && channel.state() != Done {
    let payload = client.read_packet()
    let responses = channel.handle_inbound(payload)
    for resp in responses {
      client.write_packet(resp)
    }
  }
  if channel.state() != Open {
    raise RequestDenied("channel open failed")
  }
}

///|
/// 等待 subsystem ready
fn recv_until_subsystem_ready(
  client : Client,
  channel : Channel,
) -> Unit raise SshError {
  while true {
    let payload = client.read_packet()
    let responses = channel.handle_inbound(payload)
    for resp in responses {
      client.write_packet(resp)
    }
    if payload.length() > 0 {
      let msg_type = payload.unsafe_get(0)
      if msg_type == MSG_CHANNEL_SUCCESS {
        return
      }
      if msg_type == MSG_CHANNEL_FAILURE {
        raise RequestDenied("subsystem request denied")
      }
    }
  }
}

///|
/// 打开 SFTP 通道（subsystem 请求 + INIT/VERSION 握手）
pub fn SftpClient::open(client : Client) -> SftpClient raise SshError {
  // 1. 打开 session channel
  let channel = Channel::new(0)
  let open_msg = build_channel_open(channel.id(), 1024 * 1024, 32 * 1024)
  client.write_packet(open_msg)
  // 等待 CHANNEL_OPEN_CONFIRMATION
  recv_until_open(client, channel)

  // 2. 请求 sftp subsystem
  let req = build_channel_request_subsystem(channel.peer_id(), "sftp")
  client.write_packet(req)
  // 等待 CHANNEL_SUCCESS
  recv_until_subsystem_ready(client, channel)

  // 3. 发送 SFTP INIT (version 3)
  // INIT 消息格式: uint32 length, byte type, uint32 version (无 request_id)
  let init_payload = encode_uint32(SFTP_VERSION)
  let w = Writer::new()
  w.write_uint32(1 + init_payload.length())
  w.write_byte(SSH_FXP_INIT)
  w.write_bytes(init_payload)
  let init_pkt = w.to_bytes()
  let data_msg = build_channel_data(channel.peer_id(), init_pkt)
  client.write_packet(data_msg)

  // 4. 读取 VERSION 响应
  // VERSION 格式: uint32 length, byte type, uint32 version (无 request_id)
  let reply_data = sftp_recv(client, channel)
  let r = Reader::new(reply_data)
  let _len = r.read_uint32()
  let typ = r.read_byte()
  if typ != SSH_FXP_VERSION {
    raise ProtocolError("SFTP: expected VERSION, got \{typ.to_int()}")
  }
  let _server_version = r.read_uint32()

  { client, channel, version: SFTP_VERSION, request_id: 1 }
}

// ============== 核心收发方法 ==============

///|
/// 分配下一个请求 ID
fn SftpClient::next_id(self : SftpClient) -> Int {
  let id = self.request_id
  self.request_id = self.request_id + 1
  id
}

///|
/// 发送 SFTP 请求并等待匹配响应
fn SftpClient::send_recv(
  self : SftpClient,
  typ : Byte,
  payload : Bytes,
) -> SftpPacket raise SshError {
  let id = self.next_id()
  let pkt = encode_sftp_packet(typ, id, payload)
  let data_msg = build_channel_data(self.channel.peer_id(), pkt)
  self.client.write_packet(data_msg)

  // 循环读取直到匹配 id（跳过无关包）
  while true {
    let reply = sftp_recv(self.client, self.channel)
    let resp = decode_sftp_packet(reply)
    if resp.id == id {
      return resp
    }
    // 不匹配的包可能是 unsolicited 通知，忽略
  }
  raise ProtocolError("SFTP: unreachable in send_recv")
}

// ============== 辅助解析函数 ==============

///|
/// 解析 SFTP 文件属性
fn parse_attrs(data : Bytes) -> SftpAttrs raise SshError {
  let r = Reader::new(data)
  let flags = r.read_uint32()
  let size = if flags.land(SSH_FILEXFER_ATTR_SIZE) != 0 {
    let lo = r.read_uint32()
    let _hi = r.read_uint32() // 跳过高 32 位（暂不支持 >4GB 文件）
    Some(lo)
  } else {
    None
  }
  let (uid, gid) = if flags.land(SSH_FILEXFER_ATTR_UIDGID) != 0 {
    (Some(r.read_uint32()), Some(r.read_uint32()))
  } else {
    (None, None)
  }
  let permissions = if flags.land(SSH_FILEXFER_ATTR_PERMISSIONS) != 0 {
    Some(r.read_uint32())
  } else {
    None
  }
  let (atime, mtime) = if flags.land(SSH_FILEXFER_ATTR_ACMODTIME) != 0 {
    (Some(r.read_uint32()), Some(r.read_uint32()))
  } else {
    (None, None)
  }
  { flags, size, uid, gid, permissions, atime, mtime }
}

///|
/// 解析 SSH_FXP_NAME 响应中的目录条目
fn parse_name_entries(data : Bytes) -> Array[SftpDirEntry] raise SshError {
  let r = Reader::new(data)
  let count = r.read_uint32()
  let entries : Array[SftpDirEntry] = []
  for _i = 0; _i < count; _i = _i + 1 {
    let filename = r.read_string_as_str()
    let longname = r.read_string_as_str()
    // attrs 直接内联在响应中，不是一个独立的 string
    let attrs = parse_attrs_from_reader(r)
    entries.push({ filename, longname, attrs })
  }
  entries
}

///|
/// 从 Reader 中解析 SFTP 文件属性（内联格式）
fn parse_attrs_from_reader(r : Reader) -> SftpAttrs raise SshError {
  let flags = r.read_uint32()
  let size = if flags.land(SSH_FILEXFER_ATTR_SIZE) != 0 {
    let lo = r.read_uint32()
    let _hi = r.read_uint32() // 跳过高 32 位（暂不支持 >4GB 文件）
    Some(lo)
  } else {
    None
  }
  let (uid, gid) = if flags.land(SSH_FILEXFER_ATTR_UIDGID) != 0 {
    (Some(r.read_uint32()), Some(r.read_uint32()))
  } else {
    (None, None)
  }
  let permissions = if flags.land(SSH_FILEXFER_ATTR_PERMISSIONS) != 0 {
    Some(r.read_uint32())
  } else {
    None
  }
  let (atime, mtime) = if flags.land(SSH_FILEXFER_ATTR_ACMODTIME) != 0 {
    (Some(r.read_uint32()), Some(r.read_uint32()))
  } else {
    (None, None)
  }
  { flags, size, uid, gid, permissions, atime, mtime }
}

///|
/// 解析 SSH_FXP_STATUS 响应
fn parse_status(data : Bytes) -> (Int, String) raise SshError {
  let r = Reader::new(data)
  let code = r.read_uint32()
  let message = r.read_string_as_str()
  (code, message)
}

///|
/// 检查 STATUS 是否为 OK
fn check_ok(data : Bytes) -> Unit raise SshError {
  let (code, msg) = parse_status(data)
  if code != SSH_FX_OK {
    raise ProtocolError("SFTP status \{code}: \{msg}")
  }
}

///|
/// 抛出 STATUS 错误
fn[T] raise_status(data : Bytes) -> T raise SshError {
  let (code, msg) = parse_status(data)
  raise ProtocolError("SFTP status \{code}: \{msg}")
}

// ============== 核心文件操作 ==============

///|
/// 打开文件
pub fn SftpClient::open_file(
  self : SftpClient,
  path : String,
  flags : Int,
) -> Bytes raise SshError {
  let w = Writer::new()
  w.write_string_from_str(path)
  w.write_uint32(flags)
  w.write_uint32(0) // attrs flags = 0（无属性）
  let resp = self.send_recv(SSH_FXP_OPEN, w.to_bytes())
  match resp.typ {
    SSH_FXP_HANDLE => {
      let r = Reader::new(resp.data)
      r.read_string()
    }
    SSH_FXP_STATUS => raise_status(resp.data)
    _ => raise ProtocolError("SFTP OPEN: unexpected type \{resp.typ.to_int()}")
  }
}

///|
/// 读文件
pub fn SftpClient::read(
  self : SftpClient,
  handle : Bytes,
  offset : Int,
  length : Int,
) -> Bytes raise SshError {
  let w = Writer::new()
  w.write_string(handle)
  // offset 是 uint64，分高低 32 位写入
  w.write_uint32(offset) // 低 32 位
  w.write_uint32(0) // 高 32 位（暂不支持 >4GB 文件）
  w.write_uint32(length)
  let resp = self.send_recv(SSH_FXP_READ, w.to_bytes())
  match resp.typ {
    SSH_FXP_DATA => {
      let r = Reader::new(resp.data)
      r.read_string()
    }
    SSH_FXP_STATUS => raise_status(resp.data)
    _ => raise ProtocolError("SFTP READ: unexpected type")
  }
}

///|
/// 写文件
pub fn SftpClient::write(
  self : SftpClient,
  handle : Bytes,
  offset : Int,
  data : Bytes,
) -> Unit raise SshError {
  let w = Writer::new()
  w.write_string(handle)
  w.write_uint32(offset)
  w.write_uint32(0)
  w.write_string(data)
  let resp = self.send_recv(SSH_FXP_WRITE, w.to_bytes())
  match resp.typ {
    SSH_FXP_STATUS => check_ok(resp.data)
    _ => raise ProtocolError("SFTP WRITE: unexpected type")
  }
}

///|
/// 关闭句柄
pub fn SftpClient::close_handle(
  self : SftpClient,
  handle : Bytes,
) -> Unit raise SshError {
  let w = Writer::new()
  w.write_string(handle)
  let resp = self.send_recv(SSH_FXP_CLOSE, w.to_bytes())
  match resp.typ {
    SSH_FXP_STATUS => check_ok(resp.data)
    _ => raise ProtocolError("SFTP CLOSE: unexpected type")
  }
}

///|
/// 获取文件属性
pub fn SftpClient::stat(
  self : SftpClient,
  path : String,
) -> SftpAttrs raise SshError {
  let w = Writer::new()
  w.write_string_from_str(path)
  let resp = self.send_recv(SSH_FXP_STAT, w.to_bytes())
  match resp.typ {
    SSH_FXP_ATTRS => parse_attrs(resp.data)
    SSH_FXP_STATUS => raise_status(resp.data)
    _ => raise ProtocolError("SFTP STAT: unexpected type")
  }
}

///|
/// 打开目录
fn SftpClient::opendir(
  self : SftpClient,
  path : String,
) -> Bytes raise SshError {
  let w = Writer::new()
  w.write_string_from_str(path)
  let resp = self.send_recv(SSH_FXP_OPENDIR, w.to_bytes())
  match resp.typ {
    SSH_FXP_HANDLE => {
      let r = Reader::new(resp.data)
      r.read_string()
    }
    SSH_FXP_STATUS => raise_status(resp.data)
    _ => raise ProtocolError("SFTP OPENDIR: unexpected type")
  }
}

///|
/// 列目录
pub fn SftpClient::readdir(
  self : SftpClient,
  handle : Bytes,
) -> Array[SftpDirEntry]? raise SshError {
  let w = Writer::new()
  w.write_string(handle)
  let resp = self.send_recv(SSH_FXP_READDIR, w.to_bytes())
  match resp.typ {
    SSH_FXP_NAME => Some(parse_name_entries(resp.data))
    SSH_FXP_STATUS => {
      // EOF 表示目录读完
      let (code, _) = parse_status(resp.data)
      if code == SSH_FX_EOF {
        None
      } else {
        raise_status(resp.data)
      }
    }
    _ => raise ProtocolError("SFTP READDIR: unexpected type")
  }
}

///|
/// 删除文件
pub fn SftpClient::remove(
  self : SftpClient,
  path : String,
) -> Unit raise SshError {
  let w = Writer::new()
  w.write_string_from_str(path)
  let resp = self.send_recv(SSH_FXP_REMOVE, w.to_bytes())
  match resp.typ {
    SSH_FXP_STATUS => check_ok(resp.data)
    _ => raise ProtocolError("SFTP REMOVE: unexpected type")
  }
}

///|
/// 创建目录
pub fn SftpClient::mkdir(
  self : SftpClient,
  path : String,
  permissions : Int,
) -> Unit raise SshError {
  let w = Writer::new()
  w.write_string_from_str(path)
  w.write_uint32(SSH_FILEXFER_ATTR_PERMISSIONS)
  w.write_uint32(permissions)
  let resp = self.send_recv(SSH_FXP_MKDIR, w.to_bytes())
  match resp.typ {
    SSH_FXP_STATUS => check_ok(resp.data)
    _ => raise ProtocolError("SFTP MKDIR: unexpected type")
  }
}

///|
/// 删除目录
pub fn SftpClient::rmdir(
  self : SftpClient,
  path : String,
) -> Unit raise SshError {
  let w = Writer::new()
  w.write_string_from_str(path)
  let resp = self.send_recv(SSH_FXP_RMDIR, w.to_bytes())
  match resp.typ {
    SSH_FXP_STATUS => check_ok(resp.data)
    _ => raise ProtocolError("SFTP RMDIR: unexpected type")
  }
}

///|
/// 重命名
pub fn SftpClient::rename(
  self : SftpClient,
  oldpath : String,
  newpath : String,
) -> Unit raise SshError {
  let w = Writer::new()
  w.write_string_from_str(oldpath)
  w.write_string_from_str(newpath)
  let resp = self.send_recv(SSH_FXP_RENAME, w.to_bytes())
  match resp.typ {
    SSH_FXP_STATUS => check_ok(resp.data)
    _ => raise ProtocolError("SFTP RENAME: unexpected type")
  }
}

///|
/// 解析真实路径
pub fn SftpClient::realpath(
  self : SftpClient,
  path : String,
) -> String raise SshError {
  let w = Writer::new()
  w.write_string_from_str(path)
  let resp = self.send_recv(SSH_FXP_REALPATH, w.to_bytes())
  match resp.typ {
    SSH_FXP_NAME => {
      let entries = parse_name_entries(resp.data)
      if entries.length() > 0 {
        entries[0].filename
      } else {
        raise ProtocolError("SFTP REALPATH: empty response")
      }
    }
    SSH_FXP_STATUS => raise_status(resp.data)
    _ => raise ProtocolError("SFTP REALPATH: unexpected type")
  }
}

///|
/// 设置文件属性
fn SftpClient::setstat(
  self : SftpClient,
  path : String,
  permissions : Int,
) -> Unit raise SshError {
  let w = Writer::new()
  w.write_string_from_str(path)
  w.write_uint32(SSH_FILEXFER_ATTR_PERMISSIONS)
  w.write_uint32(permissions)
  let resp = self.send_recv(SSH_FXP_SETSTAT, w.to_bytes())
  match resp.typ {
    SSH_FXP_STATUS => check_ok(resp.data)
    _ => raise ProtocolError("SFTP SETSTAT: unexpected type")
  }
}

// ============== 高层便捷 API ==============

///|
/// 读取整个文件（自动分块）
pub fn SftpClient::read_file(
  self : SftpClient,
  path : String,
) -> Bytes raise SshError {
  let handle = self.open_file(path, SSH_FXF_READ)
  let result : Array[Byte] = []
  let chunk_size = 32 * 1024
  let mut offset = 0

  while true {
    let chunk = self.read(handle, offset, chunk_size) catch {
      ProtocolError(msg) as e => {
        if msg.contains("status 1:") {
          // EOF
          break
        }
        raise e
      }
      e => raise e
    }
    if chunk.length() == 0 {
      break
    }
    for b in chunk {
      result.push(b)
    }
    offset = offset + chunk.length()
  }

  self.close_handle(handle)
  Bytes::from_array(result)
}

///|
/// 写入整个文件（自动分块）
pub fn SftpClient::write_file(
  self : SftpClient,
  path : String,
  data : Bytes,
  permissions : Int,
) -> Unit raise SshError {
  let flags = SSH_FXF_WRITE.lor(SSH_FXF_CREAT).lor(SSH_FXF_TRUNC)
  let handle = self.open_file(path, flags)
  let chunk_size = 32 * 1024
  let mut offset = 0

  while offset < data.length() {
    let end_pos = if offset + chunk_size < data.length() {
      offset + chunk_size
    } else {
      data.length()
    }
    let chunk = match Bytes::get_view(data, start=offset, end=end_pos) {
      Some(v) => BytesView::to_owned(v)
      None => raise ProtocolError("SFTP: slice error in write_file")
    }
    self.write(handle, offset, chunk)
    offset = end_pos
  }

  self.close_handle(handle)
  // 设置权限
  self.setstat(path, permissions)
}

///|
/// 列出目录内容
pub fn SftpClient::listdir(
  self : SftpClient,
  path : String,
) -> Array[SftpDirEntry] raise SshError {
  let entries : Array[SftpDirEntry] = []

  // 使用 OPENDIR 专用方法
  let opendir_handle = self.opendir(path)
  while true {
    let batch = self.readdir(opendir_handle) catch {
      ProtocolError(msg) as e => {
        if msg.contains("status 1:") {
          // EOF
          break
        }
        raise e
      }
      e => raise e
    }
    match batch {
      None => break
      Some(items) => {
        for item in items {
          entries.push(item)
        }
      }
    }
  }

  self.close_handle(opendir_handle)
  entries
}

///|
/// 关闭 SFTP 通道
pub fn SftpClient::close(self : SftpClient) -> Unit {
  let eof_msg = build_channel_eof(self.channel.peer_id())
  self.client.write_packet(eof_msg) catch { _ => () }
  let close_msg = build_channel_close(self.channel.peer_id())
  self.client.write_packet(close_msg) catch { _ => () }
}
