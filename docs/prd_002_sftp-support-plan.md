# SFTP 协议支持实现计划

## 背景

当前 MoonSSH 客户端支持 `exec` 和 `shell` 通道，但不支持 SFTP（SSH File Transfer Protocol）。SFTP 是 SSH 上最常用的文件传输协议，实现后可提供文件上传/下载/目录管理等能力。

SFTP 运行在 SSH 通道的 `subsystem` 之上，协议独立于 SSH packet 层，有自己的二进制帧格式。

| 参考 | 说明 |
|------|------|
| [draft-ietf-secsh-filexfer-02](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02) | SFTP version 3 草案（最广泛实现） |
| [draft-ietf-secsh-filexfer-13](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-13) | SFTP version 6 草案 |
| OpenSSH `sftp-server` | 服务端参考实现（支持 version 3） |

**目标版本：SFTP v3**（兼容性最好，OpenSSH 默认支持）

---

## 架构概览

```
┌─────────────────────────────────────────────────────────┐
│  cmd/sftp/                    ── CLI 入口               │
└────────────────────────┬────────────────────────────────┘
                         │  @src.SftpClient
┌────────────────────────▼────────────────────────────────┐
│  src/sftp.mbt             ── SFTP 协议层                │
│   • SftpClient            ── 高层 API                   │
│   • SftpPacket            ── SFTP 帧编解码              │
│   • SftpHandle            ── 文件/目录句柄              │
│   • SftpAttrs             ── 文件属性                   │
│   • SftpError             ── 错误类型                   │
└────────────────────────┬────────────────────────────────┘
                         │  SSH subsystem request
┌────────────────────────▼────────────────────────────────┐
│  src/channel.mbt          ── 通道层                     │
│   • build_channel_request_subsystem()  (新增)           │
│   • Channel::handle_inbound()          (现有)           │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│  src/ssh_client.mbt       ── 顶层 API                   │
│   • Client::read_packet() / write_packet()  (现有)      │
└─────────────────────────────────────────────────────────┘
```

---

## SFTP 协议帧格式

SFTP 包嵌套在 SSH channel data 中，有独立的帧头：

```
SSH Channel Data:
┌──────────┬──────┬────────┬──────────────────────┐
│ uint32   │ byte │ uint32 │  payload             │
│ length   │ type │ id     │  (type-specific)     │
└──────────┴──────┴────────┴──────────────────────┘
```

- `length`：`1 + 4 + payload.length()`（不含 length 自身的 4 字节）
- `type`：操作类型码
- `id`：请求/响应匹配 ID（INIT/VERSION 除外，id=0）

---

## 修改清单

### 1. 通道层新增 subsystem 请求 (`src/channel.mbt`)

新增 `build_channel_request_subsystem` 函数，用于向服务器请求启动 SFTP subsystem：

```moonbit
///|
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
```

---

### 2. SFTP 协议层 (`src/sftp.mbt` — 新增文件)

#### 2.1 常量定义

```moonbit
// ============== SFTP 包类型 ==============

// 请求类型
const SSH_FXP_INIT : Byte = 1
const SSH_FXP_OPEN : Byte = 3
const SSH_FXP_CLOSE : Byte = 4
const SSH_FXP_READ : Byte = 5
const SSH_FXP_WRITE : Byte = 6
const SSH_FXP_LSTAT : Byte = 7
const SSH_FXP_FSTAT : Byte = 8
const SSH_FXP_SETSTAT : Byte = 9
const SSH_FXP_OPENDIR : Byte = 11
const SSH_FXP_READDIR : Byte = 12
const SSH_FXP_REMOVE : Byte = 13
const SSH_FXP_MKDIR : Byte = 14
const SSH_FXP_RMDIR : Byte = 15
const SSH_FXP_REALPATH : Byte = 16
const SSH_FXP_STAT : Byte = 17
const SSH_FXP_RENAME : Byte = 18

// 响应类型
const SSH_FXP_VERSION : Byte = 2
const SSH_FXP_STATUS : Byte = 101
const SSH_FXP_HANDLE : Byte = 102
const SSH_FXP_DATA : Byte = 103
const SSH_FXP_NAME : Byte = 104
const SSH_FXP_ATTRS : Byte = 105

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
const SSH_FXF_READ : Int = 0x00000001
const SSH_FXF_WRITE : Int = 0x00000002
const SSH_FXF_APPEND : Int = 0x00000004
const SSH_FXF_CREAT : Int = 0x00000008
const SSH_FXF_TRUNC : Int = 0x00000010
const SSH_FXF_EXCL : Int = 0x00000020

// 文件属性 flags
const SSH_FILEXFER_ATTR_SIZE : Int = 0x00000001
const SSH_FILEXFER_ATTR_UIDGID : Int = 0x00000002
const SSH_FILEXFER_ATTR_PERMISSIONS : Int = 0x00000004
const SSH_FILEXFER_ATTR_ACMODTIME : Int = 0x00000008
const SSH_FILEXFER_ATTR_EXTENDED : Int = 0x80000000

// SFTP 协议版本
const SFTP_VERSION : Int = 3
```

#### 2.2 数据结构

```moonbit
/// SFTP 包
pub struct SftpPacket {
  typ : Byte
  id : Int
  data : Bytes
}

/// 文件属性
pub struct SftpAttrs {
  flags : Int
  size : Int?
  uid : Int?
  gid : Int?
  permissions : Int?
  atime : Int?
  mtime : Int?
}

/// 目录条目
pub struct SftpDirEntry {
  filename : String
  longname : String
  attrs : SftpAttrs
}

/// SFTP 状态错误
pub enum SftpError {
  Status(code : Int, message : String)
  ProtocolError(msg : String)
  IoError(msg : String)
} derive(Show)

/// SFTP 客户端
pub struct SftpClient {
  priv client : Client
  priv channel : Channel
  priv version : Int
  mut request_id : Int
}
```

#### 2.3 帧编解码

```moonbit
/// 编码 SFTP 包（写入 channel data 前）
fn encode_sftp_packet(typ : Byte, id : Int, payload : Bytes) -> Bytes {
  let w = Writer::new()
  w.write_uint32(1 + 4 + payload.length())
  w.write_byte(typ)
  w.write_uint32(id)
  w.write_bytes(payload)
  w.to_bytes()
}

/// 从 channel data 解码 SFTP 包
fn decode_sftp_packet(data : Bytes) -> SftpPacket raise SshError {
  let r = Reader::new(data)
  let _len = r.read_uint32()
  let typ = r.read_byte()
  let id = r.read_uint32()
  let rest = r.rest()
  { typ, id, data: rest }
}
```

#### 2.4 SFTP Client 初始化

```moonbit
/// 打开 SFTP 通道（subsystem 请求 + INIT/VERSION 握手）
pub fn SftpClient::open(client : Client) -> SftpClient raise SshError {
  // 1. 打开 session channel
  let channel = client.open_session()

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
  let init_pkt = encode_sftp_packet(SSH_FXP_INIT, 0, encode_uint32(SFTP_VERSION))
  let data_msg = build_channel_data(channel.peer_id(), init_pkt)
  client.write_packet(data_msg)

  // 4. 读取 VERSION 响应
  let reply_data = sftp_recv(client, channel)
  let version_pkt = decode_sftp_packet(reply_data)
  if version_pkt.typ != SSH_FXP_VERSION {
    raise SftpError::ProtocolError("expected VERSION, got \{version_pkt.typ.to_int()}")
  }

  {
    client,
    channel,
    version: SFTP_VERSION,
    request_id: 1,
  }
}
```

#### 2.5 核心收发方法

```moonbit
/// 分配下一个请求 ID
fn SftpClient::next_id(self : SftpClient) -> Int {
  let id = self.request_id
  self.request_id = self.request_id + 1
  id
}

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
}
```

#### 2.6 核心文件操作

```moonbit
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
    _ => raise SftpError::ProtocolError("OPEN: unexpected type \{resp.typ.to_int()}")
  }
}

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
  w.write_uint32(offset)    // 低 32 位
  w.write_uint32(0)         // 高 32 位（暂不支持 >4GB 文件）
  w.write_uint32(length)
  let resp = self.send_recv(SSH_FXP_READ, w.to_bytes())
  match resp.typ {
    SSH_FXP_DATA => {
      let r = Reader::new(resp.data)
      r.read_string()
    }
    SSH_FXP_STATUS => raise_status(resp.data)
    _ => raise SftpError::ProtocolError("READ: unexpected type")
  }
}

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
    _ => raise SftpError::ProtocolError("WRITE: unexpected type")
  }
}

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
    _ => raise SftpError::ProtocolError("CLOSE: unexpected type")
  }
}

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
    _ => raise SftpError::ProtocolError("STAT: unexpected type")
  }
}

/// 列目录
pub fn SftpClient::readdir(
  self : SftpClient,
  handle : Bytes,
) -> Array[SftpDirEntry]? raise SshError {
  let w = Reader::new(handle) // 复用 Reader 意图不对，此处用 Writer
  let ww = Writer::new()
  ww.write_string(handle)
  let resp = self.send_recv(SSH_FXP_READDIR, ww.to_bytes())
  match resp.typ {
    SSH_FXP_NAME => Some(parse_name_entries(resp.data))
    SSH_FXP_STATUS => {
      // EOF 表示目录读完
      let (code, _) = parse_status(resp.data)
      if code == SSH_FXP_EOF {
        None
      } else {
        raise_status(resp.data)
      }
    }
    _ => raise SftpError::ProtocolError("READDIR: unexpected type")
  }
}

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
    _ => raise SftpError::ProtocolError("REMOVE: unexpected type")
  }
}

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
    _ => raise SftpError::ProtocolError("MKDIR: unexpected type")
  }
}

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
    _ => raise SftpError::ProtocolError("RMDIR: unexpected type")
  }
}

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
    _ => raise SftpError::ProtocolError("RENAME: unexpected type")
  }
}

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
        raise SftpError::ProtocolError("REALPATH: empty response")
      }
    }
    SSH_FXP_STATUS => raise_status(resp.data)
    _ => raise SftpError::ProtocolError("REALPATH: unexpected type")
  }
}
```

#### 2.7 辅助解析函数

```moonbit
/// 解析 SFTP 文件属性
fn parse_attrs(data : Bytes) -> SftpAttrs raise SshError {
  let r = Reader::new(data)
  let flags = r.read_uint32()
  let size = if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
    Some(r.read_uint32()) // 低 32 位
  } else {
    None
  }
  // 跳过高 32 位（>4GB）
  if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
    let _hi = r.read_uint32() // TODO: 组合为 uint64
  }
  let uid = if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
    Some(r.read_uint32())
  } else {
    None
  }
  let gid = if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
    Some(r.read_uint32())
  } else {
    None
  }
  let permissions = if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
    Some(r.read_uint32())
  } else {
    None
  }
  let atime = if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
    Some(r.read_uint32())
  } else {
    None
  }
  let mtime = if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
    Some(r.read_uint32())
  } else {
    None
  }
  { flags, size, uid, gid, permissions, atime, mtime }
}

/// 解析 SSH_FXP_NAME 响应中的目录条目
fn parse_name_entries(data : Bytes) -> Array[SftpDirEntry] raise SshError {
  let r = Reader::new(data)
  let count = r.read_uint32()
  let entries : Array[SftpDirEntry] = []
  for _ in range(count) {
    let filename = r.read_string_as_str()
    let longname = r.read_string_as_str()
    let attrs = parse_attrs(r.read_string())
    entries.push({ filename, longname, attrs })
  }
  entries
}

/// 解析 SSH_FXP_STATUS 响应
fn parse_status(data : Bytes) -> (Int, String) raise SshError {
  let r = Reader::new(data)
  let code = r.read_uint32()
  let message = r.read_string_as_str()
  (code, message)
}

/// 检查 STATUS 是否为 OK
fn check_ok(data : Bytes) raise SshError {
  let (code, msg) = parse_status(data)
  if code != SSH_FX_OK {
    raise SftpError::Status(code, msg)
  }
}

/// 抛出 STATUS 错误
fn raise_status(data : Bytes) raise SshError {
  let (code, msg) = parse_status(data)
  raise SftpError::Status(code, msg)
}
```

#### 2.8 高层便捷 API

```moonbit
/// 读取整个文件（自动分块）
pub fn SftpClient::read_file(
  self : SftpClient,
  path : String,
) -> Bytes raise SshError {
  let handle = self.open_file(path, SSH_FXF_READ)
  let mut result : Array[Byte] = []
  let chunk_size = 32 * 1024
  let mut offset = 0

  while true {
    let chunk = self.read(handle, offset, chunk_size) catch {
      SftpError::Status(code, _) => {
        if code == SSH_FX_EOF {
          break
        }
        raise SftpError::Status(code, "read_file failed")
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

/// 写入整个文件（自动分块）
pub fn SftpClient::write_file(
  self : SftpClient,
  path : String,
  data : Bytes,
  permissions : Int,
) -> Unit raise SshError {
  let flags = SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC
  let handle = self.open_file(path, flags)
  let chunk_size = 32 * 1024
  let mut offset = 0

  while offset < data.length() {
    let end = if offset + chunk_size < data.length() {
      offset + chunk_size
    } else {
      data.length()
    }
    let chunk = match Bytes::get_view(data, start=offset, end=end) {
      Some(v) => BytesView::to_owned(v)
      None => raise SftpError::ProtocolError("slice error")
    }
    self.write(handle, offset, chunk)
    offset = end
  }

  // 设置权限
  self.setstat(path, permissions)
  self.close_handle(handle)
}

/// 列出目录内容
pub fn SftpClient::listdir(
  self : SftpClient,
  path : String,
) -> Array[SftpDirEntry] raise SshError {
  let handle = self.open_file(path, SSH_FXF_READ) // OPENDIR 复用 OPEN
  let entries : Array[SftpDirEntry] = []

  // 使用 OPENDIR 专用方法
  let opendir_handle = self.opendir(path)
  while true {
    let batch = self.readdir(opendir_handle) catch {
      SftpError::Status(code, _) => {
        if code == SSH_FX_EOF {
          break
        }
        raise
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
    _ => raise SftpError::ProtocolError("SETSTAT: unexpected type")
  }
}

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
    _ => raise SftpError::ProtocolError("OPENDIR: unexpected type")
  }
}

/// 关闭 SFTP 通道
pub fn SftpClient::close(self : SftpClient) -> Unit {
  let eof_msg = build_channel_eof(self.channel.peer_id())
  self.client.write_packet(eof_msg) catch { _ => () }
  let close_msg = build_channel_close(self.channel.peer_id())
  self.client.write_packet(close_msg) catch { _ => () }
}
```

---

### 3. 包类型注册 (`src/ssh_client.mbt`)

`Client::read_packet()` 已有的包类型过滤（`MSG_IGNORE`, `MSG_DEBUG`, `MSG_EXT_INFO`）不需要修改。`handle_inbound` 中已正确处理 `MSG_CHANNEL_DATA`，SFTP 数据通过 channel data 透明传输。

**无需修改 `ssh_client.mbt`**，SFTP 层通过 `Client::read_packet()` / `Client::write_packet()` 透明使用现有通道。

---

### 4. SFTP 包解码辅助 (`src/sftp.mbt`)

从 channel data 中提取 SFTP payload（剥离 SSH channel data 头）：

```moonbit
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
      raise SftpError::ProtocolError("channel closed unexpectedly")
    }
  }
}
```

---

### 5. CLI 入口 (`cmd/sftp/` — 新增)

#### 5.1 目录结构

```
cmd/sftp/
├── main.mbt          CLI 入口
├── moon.pkg           包配置
├── .env               环境变量
└── run.sh             运行脚本
```

#### 5.2 `cmd/sftp/main.mbt`

```moonbit
fn main {
  // 解析参数：user@host --port <port> --password <pwd> --command <cmd> <path>
  // 示例命令：
  //   sftp get /remote/file.txt /local/file.txt
  //   sftp put /local/file.txt /remote/file.txt
  //   sftp ls /remote/dir

  let args = @env.get_cli_args()
  // ... 参数解析 ...

  let opts = @src.ConnectOptions::new(host, port, user)
  let client = @src.Client::connect(opts)
  defer client.close()

  client.kex()
  client.auth_auto(password)

  let sftp = @src.SftpClient::open(client)
  defer sftp.close()

  match command {
    "get" => {
      let data = sftp.read_file(remote_path)
      // 写入本地文件
    }
    "put" => {
      // 读取本地文件
      sftp.write_file(remote_path, local_data, 0o644)
    }
    "ls" => {
      let entries = sftp.listdir(remote_path)
      for entry in entries {
        println("\{entry.longname}")
      }
    }
    "rm" => sftp.remove(remote_path)
    "mkdir" => sftp.mkdir(remote_path, 0o755)
    _ => println("unknown command: \{command}")
  }
}
```

#### 5.3 `cmd/sftp/moon.pkg`

```moonbit
import {
  "moonbitlang/core/env",
  "PaiGack/ssh_client/src",
}

options(
  is_main: true,
  supported_targets: "+native",
)
```

#### 5.4 `cmd/sftp/run.sh`

```bash
#!/bin/bash
set -e
source ../../scripts/ssh-server/.env
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command ls /"
moon clean
moon build . --target native
../../_build/native/debug/build/cmd/sftp/sftp.exe
```

---

### 6. 测试脚本 (`scripts/ssh-server/`)

现有 Docker sshd 镜像已内置 `sftp-server`，**无需额外配置**。SFTP subsystem 通常默认启用。

验证方式：

```bash
# 使用标准 sftp 客户端验证
sftp -P 1022 admin@127.0.0.1
sftp> ls
sftp> put local.txt
sftp> get remote.txt
```

---

## 关键技术细节

### SFTP offset 编码

SFTP version 3 的文件偏移量是 `uint64`，当前实现只写低 32 位（支持最大 4GB 文件）。完整实现需要：

```moonbit
// 写入 uint64（分两个 uint32）
fn Writer::write_uint64(self : Writer, n : Int) -> Unit {
  // 低 32 位
  self.write_uint32(n)
  // 高 32 位（暂为 0）
  self.write_uint32(0)
}
```

### 属性编码

SFTP ATTRS 使用 flags 位掩码决定哪些字段存在：

```
flags & 0x01 → uint64 size
flags & 0x02 → uint32 uid, uint32 gid
flags & 0x04 → uint32 permissions
flags & 0x08 → uint32 atime, uint32 mtime
flags & 0x80000000 → uint32 count + pairs of (string, string) extended
```

### 大文件分块

单次 READ/WRITE 受 SSH 通道 `remote_max_packet` 限制（通常 32KB-256KB）。高层 `read_file` / `write_file` 需循环分块。

### 请求/响应匹配

SFTP 通过 `request_id` 匹配请求和响应。`INIT` 和 `VERSION` 使用 id=0。通道中可能夹杂 `MSG_IGNORE` / `MSG_DEBUG` 等无关 SSH 包，需在 `sftp_recv` 中过滤。

### 窗口调整

大文件传输时，SFTP READ 会产生大量 channel data，需正确处理 `WINDOW_ADJUST` 消息，否则通道会阻塞。`handle_inbound` 已自动回复 `WINDOW_ADJUST`。

---

## 执行顺序

1. **`src/channel.mbt`** — 新增 `build_channel_request_subsystem()`
2. **`src/sftp.mbt`** — SFTP 协议层（帧编解码 + SftpClient + 高层 API）
3. **`cmd/sftp/`** — CLI 入口
4. **测试验证** — 使用 Docker sshd + 标准 sftp 客户端对比

## 验证方式

1. `moon build --target native` 编译通过
2. 启动密码模式 Docker sshd：`bash scripts/ssh-server/password.sh`
3. 运行 `cmd/sftp/run.sh`，执行 `ls /` 验证目录列表
4. 对比 `sftp -P 1022 admin@127.0.0.1` 的输出是否一致
5. 测试文件上传/下载：`put` / `get` 命令

---

## 里程碑

| 阶段 | 内容 | 产出 |
|------|------|------|
| **M1** | subsystem 请求 + INIT/VERSION 握手 | `SftpClient::open()` 可连通 |
| **M2** | OPEN + READ + WRITE + CLOSE | 基本文件读写 |
| **M3** | STAT + OPENDIR + READDIR | 目录列表和文件属性 |
| **M4** | 高层 API | `read_file` / `write_file` / `listdir` |
| **M5** | CLI + 测试 | `cmd/sftp/` 完整可用 |
