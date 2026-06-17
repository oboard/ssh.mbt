# SSH 端口转发支持设计文档

## 背景

SSH 端口转发（Tunneling）是 SSH 协议最强大的网络功能之一，允许通过已加密的 SSH 连接中转任意 TCP 流量。当前 MoonSSH 仅支持 `session` 通道类型（exec/shell），不支持任何端口转发功能。本文档设计三种端口转发的完整实现方案。

### 端口转发类型总览

| 类型 | SSH 命令 | 协议机制 | 用途 |
|------|---------|---------|------|
| 本地转发 (-L) | `ssh -L 8080:example.com:80 host` | `direct-tcpip` channel open | 本地监听 → SSH 中转 → 远端目标 |
| 远程转发 (-R) | `ssh -R 9090:localhost:3000 host` | `tcpip-forward` global request + `forwarded-tcpip` channel open | 远端监听 → SSH 中转 → 本地目标 |
| 动态转发 (-D) | `ssh -D 1080 host` | `direct-tcpip` + SOCKS5 协议 | 本地 SOCKS 代理 → SSH 中转 → 任意目标 |

### 协议规范引用

- **RFC 4254 §7** — TCP/IP Forwarding（`tcpip-forward`, `cancel-tcpip-forward`, `direct-tcpip`, `forwarded-tcpip`）
- **RFC 4254 §7.1** — Requesting Port Forwarding（全局请求）
- **RFC 4254 §7.2** — TCP/IP Forwarding Channels（通道打开）
- **RFC 1928** — SOCKS Protocol Version 5（动态转发需要）

---

## 当前架构分析

### 现有通道流程

```
Client::open_session()  →  Channel::new(id)
Client::exec(ch, cmd)   →  build_channel_open("session") → write_packet
                             → read_packet loop → handle_inbound
                             → build_channel_request_exec → write_packet
                             → read data until EOF
```

### 关键限制

1. **`build_channel_open` 只支持 `"session"` 类型** — `channel.mbt:114-126` 硬编码 `w.write_string_from_str("session")`
2. **Socket 层只有 connect，没有 bind/listen/accept** — `socket.mbt` 仅暴露 `connect_to_host`
3. **通道数据只进 stdout/stderr buffer** — `channel.mbt:272-278` 的 `MSG_CHANNEL_DATA` 处理将数据 push 到 `stdout_buf`，没有回调机制
4. **没有全局请求发送能力** — `channel.mbt:307-319` 只处理收到的 `GLOBAL_REQUEST`（回复 FAILURE），没有发送 `tcpip-forward` 的能力
5. **没有多路复用/事件循环** — `exec` 是阻塞式的读取循环，不支持同时处理多个通道

---

## 设计方案

### 整体架构变更

```
                        ┌─────────────────────────────┐
                        │        Client API            │
                        │  exec / shell / forward_*    │
                        └──────────┬──────────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
             session ch      direct-tcpip    forwarded-tcpip
             (existing)      (local fwd)     (remote fwd)
                    │              │              │
                    └──────┬───────┴──────┬───────┘
                           ▼              ▼
                    Channel Manager    Data Relay
                    (多通道管理)       (socket ↔ channel)
                           │
                    ┌──────┴──────┐
                    ▼             ▼
              SSH Transport    Local TCP
              (现有加密层)    Listener (新增)
```

---

### 第一层：Socket 层扩展 (`src/socket/`)

#### 1.1 新增 C FFI 函数

**文件**: `src/socket/socket.c`

```c
// ===== 新增: TCP 服务器功能 =====

/*
 * 绑定并监听指定端口
 * handle: socket_create() 返回的句柄
 * port: 监听端口
 * backlog: 等待队列长度 (建议 128)
 * 返回: 0 成功, -1 失败
 */
int socket_bind_listen(int handle, int port, int backlog);

/*
 * 接受一个入站连接
 * handle: 监听 socket 句柄
 * 返回: 新连接的 socket 句柄, -1 失败
 */
int socket_accept(int handle);

/*
 * 非阻塞检查是否有入站连接
 * handle: 监听 socket 句柄
 * 返回: 1 有连接等待, 0 无连接, -1 错误
 */
int socket_poll_accept(int handle);

/*
 * 设置 socket 为非阻塞模式
 * 返回: 0 成功, -1 失败
 */
int socket_set_nonblocking(int handle);

/*
 * 检查 socket 是否有数据可读 (select with timeout=0)
 * handle: socket 句柄
 * 返回: 1 有数据, 0 无数据, -1 错误
 */
int socket_poll_readable(int handle);
```

**POSIX 实现要点**:

```c
int socket_bind_listen(int handle, int port, int backlog) {
    int opt = 1;
    setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(handle, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;
    if (listen(handle, backlog) < 0)
        return -1;
    return 0;
}

int socket_accept(int handle) {
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int client = accept(handle, (struct sockaddr *)&addr, &addrlen);
    return client;  // -1 on error
}

int socket_poll_accept(int handle) {
    fd_set fds;
    struct timeval tv = {0, 0}; // 非阻塞
    FD_ZERO(&fds);
    FD_SET(handle, &fds);
    return select(handle + 1, &fds, NULL, NULL, &tv);
}

int socket_set_nonblocking(int handle) {
    int flags = fcntl(handle, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(handle, F_SETFL, flags | O_NONBLOCK);
}

int socket_poll_readable(int handle) {
    fd_set fds;
    struct timeval tv = {0, 0};
    FD_ZERO(&fds);
    FD_SET(handle, &fds);
    return select(handle + 1, &fds, NULL, NULL, &tv);
}
```

**Windows 实现要点**: 使用 `ioctlsocket(FIONBIO)` 设置非阻塞，`select()` 实现 poll。

#### 1.2 新增 MoonBit 绑定

**文件**: `src/socket/socket.mbt`

```moonbit
// ===== 新增 FFI 声明 =====

extern "C" fn socket_bind_listen(handle : Int, port : Int, backlog : Int) -> Int
  = "socket_bind_listen"

extern "C" fn socket_accept(handle : Int) -> Int
  = "socket_accept"

extern "C" fn socket_poll_accept(handle : Int) -> Int
  = "socket_accept_poll"

extern "C" fn socket_set_nonblocking(handle : Int) -> Int
  = "socket_set_nonblocking"

extern "C" fn socket_poll_readable(handle : Int) -> Int
  = "socket_poll_readable"

// ===== 新增 Tcp 方法 =====

/// 创建一个 TCP 监听器，绑定到指定端口
pub fn Tcp::bind_listen(port : Int, backlog~ : Int) -> Tcp raise {
  let init_result = winsock_init()
  if init_result != 0 {
    raise IoError("Failed to initialize socket: code \{init_result}")
  }
  let handle = socket_create()
  if handle < 0 {
    raise IoError("Failed to create socket")
  }
  let rc = socket_bind_listen(handle, port, backlog)
  if rc != 0 {
    socket_close(handle)
    raise IoError("Failed to bind/listen on port \{port}")
  }
  { handle, host: "0.0.0.0", port }
}

/// 接受一个入站 TCP 连接
pub fn Tcp::accept(self : Tcp) -> Tcp raise {
  let client_handle = socket_accept(self.handle)
  if client_handle < 0 {
    raise IoError("Failed to accept connection")
  }
  socket_set_nodelay(client_handle)  // SSH 场景保持低延迟
  { handle: client_handle, host: "", port: 0 }
}

/// 非阻塞检查是否有入站连接
pub fn Tcp::has_pending_connection(self : Tcp) -> Bool {
  socket_poll_accept(self.handle) > 0
}

/// 非阻塞检查是否有数据可读
pub fn Tcp::has_data(self : Tcp) -> Bool {
  socket_poll_readable(self.handle) > 0
}
```

---

### 第二层：通道协议扩展 (`src/channel.mbt`)

#### 2.1 新增消息常量

```moonbit
// 全局请求相关 (已在 handle_inbound 中定义，但需要发送能力)
pub const MSG_GLOBAL_REQUEST : Byte = b'\x50'  // 80
pub const MSG_REQUEST_SUCCESS : Byte = b'\x51'  // 81
pub const MSG_REQUEST_FAILURE : Byte = b'\x52'  // 82
```

#### 2.2 扩展 Channel 结构体

当前 `Channel` 结构体 `channel.mbt:42-55` 缺少通道类型信息和数据回调机制。端口转发需要区分通道类型，并将数据转发到本地 socket 而非 stdout buffer。

```moonbit
/// 通道类型
pub enum ChannelType {
  Session                          // 现有: exec / shell
  DirectTcpip(String, Int)         // 本地转发: (host, port)
  ForwardedTcpip(String, Int)      // 远程转发: (host, port)
} derive(Eq, Debug)

/// 通道数据处理方式
pub enum DataSink {
  Buffer                           // 现有: 存入 stdout_buf / stderr_buf
  Socket(@socket.Tcp)              // 端口转发: 直接写入本地 socket
}
```

**扩展后的 Channel 结构体**:

```moonbit
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
  // ===== 新增: 端口转发支持 =====
  mut channel_type : ChannelType    // 通道类型
  mut data_sink : DataSink          // 数据去向
}
```

#### 2.3 新增 `direct-tcpip` 通道打开消息构建

**协议格式** (RFC 4254 §7.2):

```
byte      SSH_MSG_CHANNEL_OPEN (90)
string    "direct-tcpip"
uint32    sender_channel
uint32    initial_window_size
uint32    maximum_packet_size
string    host_to_connect           // 目标主机
uint32    port_to_connect           // 目标端口
string    originator_ip             // 发起方 IP (可为空)
uint32    originator_port           // 发起方端口 (可为 0)
```

```moonbit
/// 构建 direct-tcpip 通道打开消息 (本地转发)
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
```

#### 2.4 新增 `forwarded-tcpip` 通道确认解析

当远端通知有入站连接时，客户端收到 `SSH_MSG_CHANNEL_OPEN`，类型为 `"forwarded-tcpip"`。

**协议格式** (RFC 4254 §7.2):

```
byte      SSH_MSG_CHANNEL_OPEN (90)
string    "forwarded-tcpip"
uint32    sender_channel            // 服务端分配的通道 ID
uint32    initial_window_size
uint32    maximum_packet_size
string    address_to_connect        // 远端监听的地址
uint32    port_to_connect           // 远端监听的端口
string    originator_ip             // 连接发起方 IP
uint32    originator_port           // 连接发起方端口
```

```moonbit
/// 解析入站 forwarded-tcpip 通道打开
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
  (sender_channel, initial_window, max_packet, address, port, originator_ip, originator_port)
}
```

#### 2.5 新增全局请求构建

**`tcpip-forward` 请求** (RFC 4254 §7.1) — 远程转发注册:

```
byte      SSH_MSG_GLOBAL_REQUEST (80)
string    "tcpip-forward"
boolean   want_reply = true
string    address_to_bind           // 要监听的地址 ("0.0.0.0" 或具体 IP)
uint32    port_to_bind              // 要监听的端口 (0 = 服务端分配)
```

```moonbit
/// 构建 tcpip-forward 全局请求 (远程转发注册)
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

/// 构建 cancel-tcpip-forward 请求 (取消远程转发)
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
```

#### 2.6 修改 `handle_inbound` 支持入站 `forwarded-tcpip`

当前 `channel.mbt:305-321` 的全局请求处理仅回复 `REQUEST_FAILURE`。需要扩展以处理远程转发场景中服务端打开的 `forwarded-tcpip` 通道。

**修改 `handle_inbound` 中 `b'\x5a'` (MSG_CHANNEL_OPEN) 分支**:

```moonbit
// 在 handle_inbound 的 match msg 中新增:
MSG_CHANNEL_OPEN => {
  let ch_type = r.read_string_as_str()
  match ch_type {
    "forwarded-tcpip" => {
      let (sender_ch, win, max_pkt, addr, port, orig_ip, orig_port) =
        parse_inbound_forwarded_tcpip(r)
      debug("* INBOUND: forwarded-tcpip from \{orig_ip}:\{orig_port} → \{addr}:\{port}")
      // 返回消息通知上层: 需要创建新 Channel 并连接本地目标
      // 通过新的回调机制通知 Client
      []
    }
    _ => {
      // 未知通道类型, 发送 OPEN_FAILURE
      let sender_ch = r.read_uint32()
      build_channel_open_failure(sender_ch, 2, "unknown channel type", "")
    }
  }
}
```

#### 2.7 新增 `build_channel_open_failure`

```moonbit
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
```

#### 2.8 通道打开确认构建 (用于接受入站通道)

当客户端接受 `forwarded-tcpip` 入站通道时，需要发送 `CHANNEL_OPEN_CONFIRMATION`:

```moonbit
/// 构建通道打开确认 (接受入站 forwarded-tcpip)
pub fn build_channel_open_confirmation(
  recipient_channel : Int,   // 对方的 sender_channel
  sender_channel : Int,      // 本地分配的通道 ID
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
```

---

### 第三层：Client API 扩展 (`src/ssh_client.mbt`)

#### 3.1 Client 结构体扩展

```moonbit
pub struct Client {
  // ... 现有字段 ...
  mut next_channel_id : Int

  // ===== 新增: 端口转发状态 =====
  /// 本地监听器列表 (local_port → Tcp listener)
  priv mut local_listeners : Array[ForwardListener]
  /// 远程转发注册信息 (remote_port → ForwardEntry)
  priv mut remote_forwards : Array[ForwardEntry]
  /// 活跃的转发通道 (channel_id → ForwardChannel)
  priv mut forward_channels : Array[ForwardChannel]
}

/// 本地转发监听器
struct ForwardListener {
  local_port : Int
  remote_host : String
  remote_port : Int
  listener : @socket.Tcp
}

/// 远程转发注册信息
struct ForwardEntry {
  remote_address : String
  remote_port : Int
  local_host : String
  local_port : Int
}

/// 转发通道关联
struct ForwardChannel {
  ssh_channel : Channel
  local_socket : @socket.Tcp
}
```

#### 3.2 本地转发 (`-L`)

**核心流程**:

```
1. 在本地端口创建 TCP 监听器
2. 接受本地连接
3. 通过 SSH 打开 direct-tcpip 通道
4. 进入双向数据中继循环:
   local_socket → SSH channel (via CHANNEL_DATA)
   SSH channel  → local_socket (via DataSink::Socket)
5. 任一端关闭时, 清理通道和 socket
```

```moonbit
/// 本地端口转发 (-L)
/// local_port: 本地监听端口
/// remote_host: 通过 SSH 连接的目标主机
/// remote_port: 通过 SSH 连接的目标端口
pub fn Client::forward_local_port(
  self : Client,
  local_port : Int,
  remote_host : String,
  remote_port : Int,
) -> Unit raise SshError {
  // 1. 创建本地监听器
  let listener = @socket.Tcp::bind_listen(local_port) catch {
    e => raise IoError("bind local port \{local_port}: \{e}")
  }
  debug("* forward_local: listening on 127.0.0.1:\{local_port} → \{remote_host}:\{remote_port}")

  // 2. 主循环: 接受连接并创建转发通道
  while true {
    let local_conn = listener.accept() catch {
      e => {
        debug("* forward_local: accept error: \{e}")
        continue
      }
    }
    debug("* forward_local: new connection from client")

    // 3. 打开 direct-tcpip 通道
    let ch = self.open_direct_tcpip(remote_host, remote_port)

    // 4. 启动数据中继 (阻塞直到通道关闭)
    self.relay_data(ch, local_conn)
  }
}

/// 打开 direct-tcpip 通道
fn Client::open_direct_tcpip(
  self : Client,
  host : String,
  port : Int,
) -> Channel raise SshError {
  let id = self.next_channel_id
  self.next_channel_id = self.next_channel_id + 1
  let ch = Channel::new(id)
  ch.channel_type = DirectTcpip(host, port)

  let open_msg = build_channel_open_direct_tcpip(
    id, 1024 * 1024, 32 * 1024,
    host, port, "127.0.0.1", 0,
  )
  self.write_packet(open_msg)

  // 等待确认
  while true {
    let payload = self.read_packet()
    let responses = ch.handle_inbound(payload)
    for resp in responses {
      self.write_packet(resp)
    }
    if ch.is_open() { break }
    if ch.state() == Done {
      raise ProtocolError("direct-tcpip: failed to open")
    }
  }
  ch
}
```

#### 3.3 数据中继

这是端口转发的核心——在本地 socket 和 SSH 通道之间双向搬运数据。

```moonbit
/// 双向数据中继: local_socket ↔ SSH channel
fn Client::relay_data(
  self : Client,
  ch : Channel,
  local_socket : @socket.Tcp,
) -> Unit raise SshError {
  // 设置本地 socket 为非阻塞 (用于 poll)
  local_socket.set_nonblocking()

  while ch.state() != Done && ch.state() != Closed {
    // 方向 A: SSH → 本地 socket
    // 检查 SSH 通道是否有数据
    let payload = self.read_packet_nonblocking()
    match payload {
      Some(data) => {
        let responses = ch.handle_inbound(data)
        for resp in responses {
          self.write_packet(resp)
        }
        // 检查通道是否收到数据
        if ch.has_stdout() {
          let out = ch.take_stdout()
          local_socket.write_bytes(@utf8.encode(out)) catch {
            _ => break  // 本地连接断开
          }
        }
      }
      None => ()
    }

    // 方向 B: 本地 socket → SSH
    if local_socket.has_data() {
      let buf = Bytes::new(32 * 1024)
      let n = local_socket.recv(buf) catch { _ => 0 }
      if n > 0 {
        let data = Bytes::get_view(buf, start=0, end=n) match {
          Some(v) => BytesView::to_owned(v)
          None => break
        }
        let msg = build_channel_data(ch.peer_id(), data)
        self.write_packet(msg) catch { _ => break }
      } else if n == 0 {
        // 本地连接关闭, 发送 EOF
        self.write_packet(build_channel_eof(ch.peer_id())) catch { _ => () }
        break
      }
    }
  }

  // 清理: 关闭通道和本地 socket
  if ch.state() != Done {
    self.write_packet(build_channel_close(ch.peer_id())) catch { _ => () }
  }
  local_socket.close()
}
```

#### 3.4 远程转发 (`-R`)

**核心流程**:

```
1. 发送 tcpip-forward 全局请求, 注册远端监听端口
2. 进入事件循环, 处理两种消息:
   a. forwarded-tcpip 通道打开 → 创建本地连接 → 确认通道 → 中继数据
   b. 其他 SSH 消息 → 正常处理
3. 退出时发送 cancel-tcpip-forward
```

```moonbit
/// 远程端口转发 (-R)
/// remote_port: 远端监听端口
/// local_host: 本地目标主机
/// local_port: 本地目标端口
pub fn Client::forward_remote_port(
  self : Client,
  remote_port : Int,
  local_host : String,
  local_port : Int,
) -> Unit raise SshError {
  // 1. 注册远程转发
  let req = build_global_request_tcpip_forward("0.0.0.0", remote_port)
  self.write_packet(req)

  // 2. 读取响应
  let reply = self.read_packet()
  let r = Reader::new(reply)
  let msg_type = r.read_byte()
  match msg_type {
    MSG_REQUEST_SUCCESS => {
      // 有些服务端在 port=0 时返回实际分配的端口
      let assigned_port = if !r.eof() { r.read_uint32() } else { remote_port }
      debug("* remote forward registered on port \{assigned_port}")
    }
    MSG_REQUEST_FAILURE => {
      raise RequestDenied("tcpip-forward rejected by server")
    }
    _ => raise ProtocolError("unexpected reply to tcpip-forward: \{msg_type.to_int()}")
  }

  // 3. 事件循环: 处理入站 forwarded-tcpip 通道
  self.remote_forward_loop(local_host, local_port)
}

/// 远程转发事件循环
fn Client::remote_forward_loop(
  self : Client,
  local_host : String,
  local_port : Int,
) -> Unit raise SshError {
  while true {
    let payload = self.read_packet()
    let msg_type = payload.unsafe_get(0)

    match msg_type {
      MSG_CHANNEL_OPEN => {
        // 可能是 forwarded-tcpip
        let r = Reader::new(payload)
        let _ = r.read_byte() // msg type
        let ch_type = r.read_string_as_str()
        if ch_type == "forwarded-tcpip" {
          let (sender_ch, win, max_pkt, addr, port, orig_ip, orig_port) =
            parse_inbound_forwarded_tcpip(r)
          debug("* remote forward: connection from \{orig_ip}:\{orig_port}")

          // 连接本地目标
          let local_conn = @socket.Tcp::connect_to_host(local_host, port=local_port) catch {
            e => {
              debug("* remote forward: cannot connect to local \{local_host}:\{local_port}: \{e}")
              let fail_msg = build_channel_open_failure(
                sender_ch, 2, "connect failed", "en",
              )
              self.write_packet(fail_msg) catch { _ => () }
              continue
            }
          }

          // 分配本地通道 ID, 发送确认
          let local_id = self.next_channel_id
          self.next_channel_id = self.next_channel_id + 1
          let ch = Channel::new(local_id)
          ch.channel_type = ForwardedTcpip(addr, port)
          ch.data_sink = Socket(local_conn)

          let confirm = build_channel_open_confirmation(
            sender_ch, local_id, 1024 * 1024, 32 * 1024,
          )
          self.write_packet(confirm) catch { _ => continue }

          // 中继数据 (阻塞)
          self.relay_data(ch, local_conn)
        }
        // 其他 channel open 类型忽略或处理
      }
      // 其他消息类型 (KEEPALIVE, GLOBAL_REQUEST 等) — 忽略或转发给其他处理器
      _ => {
        debug("* remote forward: ignoring msg \{msg_type.to_int()}")
      }
    }
  }
}
```

#### 3.5 动态转发 (`-D` / SOCKS5)

**核心流程**:

```
1. 在本地端口创建 SOCKS5 监听器
2. 接受连接, 进行 SOCKS5 握手:
   a. 认证协商 (METHOD selection)
   b. CONNECT 请求解析 (获取目标 host:port)
3. 通过 SSH 打开 direct-tcpip 通道到目标
4. 进入双向数据中继
```

```moonbit
/// 动态端口转发 / SOCKS5 代理 (-D)
pub fn Client::forward_socks5(
  self : Client,
  local_port : Int,
) -> Unit raise SshError {
  let listener = @socket.Tcp::bind_listen(local_port) catch {
    e => raise IoError("bind SOCKS5 port \{local_port}: \{e}")
  }
  debug("* SOCKS5 proxy listening on 127.0.0.1:\{local_port}")

  while true {
    let conn = listener.accept() catch {
      e => {
        debug("* SOCKS5: accept error: \{e}")
        continue
      }
    }
    // 每个连接在独立流程中处理
    self.handle_socks5_connection(conn)
  }
}

/// 处理单个 SOCKS5 连接
fn Client::handle_socks5_connection(
  self : Client,
  conn : @socket.Tcp,
) -> Unit raise SshError {
  // ===== SOCKS5 握手 =====

  // 1. 读取客户端握手
  let buf = conn.read_exact(2) catch { _ => return }
  let ver = buf.unsafe_get(0)
  let nmethods = buf.unsafe_get(1).to_int()
  if ver != b'\x05' {
    conn.close()
    return
  }
  let methods = conn.read_exact(nmethods) catch { _ => conn.close(); return }

  // 2. 回复: 无需认证 (0x00)
  conn.write_bytes(b"\x05\x00") catch { _ => conn.close(); return }

  // 3. 读取 CONNECT 请求
  let header = conn.read_exact(4) catch { _ => conn.close(); return }
  let cmd = header.unsafe_get(1)
  if cmd != b'\x01' {
    // 仅支持 CONNECT (0x01), 不支持 BIND (0x02) / UDP (0x03)
    conn.write_bytes(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00") catch { _ => () }
    conn.close()
    return
  }
  let atyp = header.unsafe_get(3)

  // 4. 解析目标地址
  let (target_host, target_port) = match atyp {
    b'\x01' => {
      // IPv4: 4 bytes
      let addr = conn.read_exact(4) catch { _ => conn.close(); return }
      let port_raw = conn.read_exact(2) catch { _ => conn.close(); return }
      let ip = "\{addr.unsafe_get(0)}.\{addr.unsafe_get(1)}.\{addr.unsafe_get(2)}.\{addr.unsafe_get(3)}"
      let port = (port_raw.unsafe_get(0).to_int() << 8) | port_raw.unsafe_get(1).to_int()
      (ip, port)
    }
    b'\x03' => {
      // Domain: 1 byte len + domain
      let len_raw = conn.read_exact(1) catch { _ => conn.close(); return }
      let domain = conn.read_exact(len_raw.unsafe_get(0).to_int()) catch { _ => conn.close(); return }
      let port_raw = conn.read_exact(2) catch { _ => conn.close(); return }
      let host = bytes_to_utf8_string(domain)
      let port = (port_raw.unsafe_get(0).to_int() << 8) | port_raw.unsafe_get(1).to_int()
      (host, port)
    }
    b'\x04' => {
      // IPv6: 16 bytes — 当前不支持, 返回 address type not supported
      conn.write_bytes(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00") catch { _ => () }
      conn.close()
      return
    }
    _ => {
      conn.write_bytes(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00") catch { _ => () }
      conn.close()
      return
    }
  }

  debug("* SOCKS5 CONNECT → \{target_host}:\{target_port}")

  // 5. 通过 SSH 打开 direct-tcpip 通道
  let ch = self.open_direct_tcpip(target_host, target_port) catch {
    e => {
      debug("* SOCKS5: direct-tcpip failed: \{e}")
      conn.write_bytes(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00") catch { _ => () }
      conn.close()
      return
    }
  }

  // 6. 回复成功
  conn.write_bytes(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00") catch {
    _ => conn.close(); return
  }

  // 7. 双向中继
  self.relay_data(ch, conn)
}
```

#### 3.6 取消远程转发

```moonbit
/// 取消远程端口转发
pub fn Client::cancel_remote_forward(
  self : Client,
  address : String,
  port : Int,
) -> Unit raise SshError {
  let req = build_global_request_cancel_tcpip_forward(address, port)
  self.write_packet(req)

  let reply = self.read_packet()
  let msg_type = reply.unsafe_get(0)
  match msg_type {
    MSG_REQUEST_SUCCESS => debug("* remote forward cancelled: \{address}:\{port}")
    MSG_REQUEST_FAILURE => raise RequestDenied("cancel-tcpip-forward rejected")
    _ => raise ProtocolError("unexpected reply to cancel-tcpip-forward")
  }
}
```

#### 3.7 非阻塞读取支持

当前 `read_packet` 是阻塞的。端口转发的数据中继需要非阻塞读取，避免一方无数据时阻塞另一方。

```moonbit
/// 非阻塞读取一个 SSH 包 (使用 select 检查底层 socket)
fn Client::read_packet_nonblocking(self : Client) -> Option[Bytes] raise SshError {
  match self.conn {
    Connected(conn) => {
      if !conn.has_data() {
        return None
      }
      Some(self.read_packet())
    }
  }
}
```

**替代方案**: 如果不引入非阻塞 I/O，可以用两个独立线程/协程分别处理两个方向。当前 MoonBit 运行时不支持多线程，因此推荐使用 select/poll 非阻塞方式。

---

### 第四层：CLI 入口 (`cmd/`)

#### 4.1 新增本地转发入口

**目录**: `cmd/forward-local/`

```
cmd/forward-local/
├── main.mbt
├── moon.pkg
├── .env
└── run.sh
```

**`main.mbt`**:

```moonbit
fn {
  main : Array[String] -> Unit
} = "@func(main/fn.main)"

fn main(args : Array[String]) -> Unit {
  // 参数解析:
  //   user@host -p PORT -L local_port:remote_host:remote_port --key KEY_PATH
  //   或
  //   user@host -p PORT -L local_port:remote_host:remote_port --password PWD

  let parsed = parse_args(args)
  let opts = ConnectOptions::new(parsed.host, parsed.port, parsed.user)
  let client = Client::connect(opts)
  client.kex()
  client.auth_password(parsed.password)

  println("Forwarding 127.0.0.1:\{parsed.local_port} → \{parsed.remote_host}:\{parsed.remote_port}")
  client.forward_local_port(parsed.local_port, parsed.remote_host, parsed.remote_port)
}
```

**`run.sh`**:

```bash
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT -L 8080:example.com:80 --password $MSSH_PASSWORD"
```

#### 4.2 新增远程转发入口

**目录**: `cmd/forward-remote/`

```bash
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT -R 9090:localhost:3000 --password $MSSH_PASSWORD"
```

#### 4.3 新增 SOCKS5 动态转发入口

**目录**: `cmd/forward-socks5/`

```bash
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT -D 1080 --password $MSSH_PASSWORD"
```

#### 4.4 CLI 参数解析扩展

**文件**: `cmd/utils/args.mbt` — 新增转发参数解析

```moonbit
/// 解析端口转发参数
pub fn parse_forward_arg(
  arg : String,
) -> (Int, String, Int) raise { // (local_port, remote_host, remote_port)
  // 格式: local_port:host:port  或  local_port:host:host_port
  let parts = arg.split(":")
  // ... 解析逻辑
}
```

---

### 第五层：Channel 数据处理改造

#### 5.1 现有 `MSG_CHANNEL_DATA` 处理的改造

当前 `channel.mbt:272-278`:

```moonbit
MSG_CHANNEL_DATA => {
  let _sender = r.read_uint32()
  let data = r.read_string()
  for b in data {
    self.stdout_buf.push(b)  // ← 只进 buffer
  }
  [build_channel_window_adjust(self.peer_id(), self.local_max_packet)]
}
```

**改造后**:

```moonbit
MSG_CHANNEL_DATA => {
  let _sender = r.read_uint32()
  let data = r.read_string()
  match self.data_sink {
    Buffer => {
      // 现有行为: 存入 buffer
      for b in data {
        self.stdout_buf.push(b)
      }
    }
    Socket(sock) => {
      // 端口转发: 直接写入本地 socket
      sock.write_bytes(data) catch {
        e => debug("* channel data → socket write failed: \{e}")
      }
    }
  }
  [build_channel_window_adjust(self.peer_id(), self.local_max_packet)]
}
```

---

## 关键技术细节

### SSH 通道消息类型对照

| 消息类型 | 值 | 方向 | 用途 |
|---------|-----|------|------|
| `SSH_MSG_GLOBAL_REQUEST` | 80 | C→S | 注册远程转发 |
| `SSH_MSG_REQUEST_SUCCESS` | 81 | S→C | 请求成功 |
| `SSH_MSG_REQUEST_FAILURE` | 82 | S→C | 请求失败 |
| `SSH_MSG_CHANNEL_OPEN` | 90 | 双向 | 打开通道 (direct-tcpip / forwarded-tcpip) |
| `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` | 91 | 双向 | 确认通道打开 |
| `SSH_MSG_CHANNEL_OPEN_FAILURE` | 92 | 双向 | 拒绝通道打开 |
| `SSH_MSG_CHANNEL_DATA` | 94 | 双向 | 转发数据 |
| `SSH_MSG_CHANNEL_EOF` | 96 | 双向 | 数据结束 |
| `SSH_MSG_CHANNEL_CLOSE` | 97 | 双向 | 关闭通道 |
| `SSH_MSG_CHANNEL_WINDOW_ADJUST` | 93 | 双向 | 流量控制 |

### 通道打开失败原因码 (RFC 4254 §5.1)

| 值 | 含义 |
|----|------|
| 1 | administratively prohibited |
| 2 | connect failed |
| 3 | unknown channel type |
| 4 | resource shortage |

### SOCKS5 协议要点 (RFC 1928)

```
客户端 → 服务端 (握手):
  +----+----------+----------+
  |VER | NMETHODS | METHODS  |
  +----+----------+----------+
  | 1  |    1     | 1-255    |
  +----+----------+----------+

服务端 → 客户端 (选择):
  +----+--------+
  |VER | METHOD |
  +----+--------+
  | 1  |   1    |  (0x00 = 无认证)
  +----+--------+

客户端 → 服务端 (请求):
  +----+-----+-------+------+----------+----------+
  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
  +----+-----+-------+------+----------+----------+
  | 1  |  1  | X'00' |  1   | Variable |    2     |
  +----+-----+-------+------+----------+----------+
  CMD: 0x01=CONNECT, 0x02=BIND, 0x03=UDP
  ATYP: 0x01=IPv4, 0x03=Domain, 0x04=IPv6

服务端 → 客户端 (响应):
  +----+-----+-------+------+----------+----------+
  |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
  +----+-----+-------+------+----------+----------+
  | 1  |  1  | X'00' |  1   | Variable |    2     |
  +----+-----+-------+------+----------+----------+
  REP: 0x00=成功, 0x01=一般失败, 0x02=规则不允许,
       0x03=网络不可达, 0x04=主机不可达, 0x05=连接被拒,
       0x06=TTL过期, 0x07=不支持的命令, 0x08=不支持的地址类型
```

### 流量控制窗口管理

端口转发的数据量可能远大于 exec/shell。需要注意:

1. **初始窗口大小**: 当前 `Channel::new` 设置 `local_window = 1MB`，对端口转发足够
2. **窗口消耗**: 每收到 `MSG_CHANNEL_DATA`，`local_window` 减少数据量
3. **窗口补充**: 当 `local_window` 低于阈值时，发送 `MSG_CHANNEL_WINDOW_ADJUST`
4. **发送端检查**: 发送数据前需检查 `remote_window > 0`，否则等待 `WINDOW_ADJUST`

```moonbit
// 在 relay_data 中发送数据前检查窗口
if ch.remote_window < data.length() {
  // 等待 WINDOW_ADJUST
  // ...
}
let msg = build_channel_data(ch.peer_id(), data)
self.write_packet(msg)
ch.remote_window = ch.remote_window - data.length()
```

---

## 执行顺序

### Phase 1: 基础设施 (Socket 层 + Channel 消息)

| 序号 | 文件 | 改动 | 说明 |
|------|------|------|------|
| 1.1 | `src/socket/socket.c` | 新增 `socket_bind_listen`, `socket_accept`, `socket_poll_accept`, `socket_set_nonblocking`, `socket_poll_readable` | C FFI: TCP 服务器 + 轮询 |
| 1.2 | `src/socket/socket.mbt` | 新增 FFI 声明 + `Tcp::bind_listen`, `Tcp::accept`, `Tcp::has_pending_connection`, `Tcp::has_data` | MoonBit 绑定 |
| 1.3 | `src/channel.mbt` | 新增 `ChannelType`, `DataSink` 枚举; 扩展 `Channel` 结构体 | 通道类型区分 |
| 1.4 | `src/channel.mbt` | 新增 `build_channel_open_direct_tcpip`, `build_channel_open_confirmation`, `build_channel_open_failure`, `build_global_request_tcpip_forward`, `build_global_request_cancel_tcpip_forward`, `parse_inbound_forwarded_tcpip` | 消息构建器 |
| 1.5 | `src/channel.mbt` | 修改 `handle_inbound` 中 `MSG_CHANNEL_DATA` 分支, 根据 `data_sink` 决定存 buffer 还是写 socket | 数据分流 |
| 1.6 | `src/channel.mbt` | 新增 `MSG_CHANNEL_OPEN` 分支处理 `forwarded-tcpip` 入站通道 | 入站通道处理 |

### Phase 2: Client API

| 序号 | 文件 | 改动 | 说明 |
|------|------|------|------|
| 2.1 | `src/ssh_client.mbt` | 扩展 `Client` 结构体, 新增 `ForwardListener`, `ForwardEntry`, `ForwardChannel` | 状态管理 |
| 2.2 | `src/ssh_client.mbt` | 新增 `Client::open_direct_tcpip` | direct-tcpip 通道打开 |
| 2.3 | `src/ssh_client.mbt` | 新增 `Client::relay_data` | 双向数据中继 |
| 2.4 | `src/ssh_client.mbt` | 新增 `Client::forward_local_port` | 本地转发 API |
| 2.5 | `src/ssh_client.mbt` | 新增 `Client::forward_remote_port` + `Client::remote_forward_loop` | 远程转发 API |
| 2.6 | `src/ssh_client.mbt` | 新增 `Client::forward_socks5` + `Client::handle_socks5_connection` | SOCKS5 动态转发 API |
| 2.7 | `src/ssh_client.mbt` | 新增 `Client::cancel_remote_forward` | 取消远程转发 |
| 2.8 | `src/ssh_client.mbt` | 新增 `Client::read_packet_nonblocking` | 非阻塞读取 |

### Phase 3: CLI 入口

| 序号 | 文件 | 改动 | 说明 |
|------|------|------|------|
| 3.1 | `cmd/utils/args.mbt` | 新增 `-L`, `-R`, `-D` 参数解析 | 参数解析 |
| 3.2 | `cmd/forward-local/` | 新建目录: `main.mbt`, `moon.pkg`, `.env`, `run.sh` | 本地转发入口 |
| 3.3 | `cmd/forward-remote/` | 新建目录: `main.mbt`, `moon.pkg`, `.env`, `run.sh` | 远程转发入口 |
| 3.4 | `cmd/forward-socks5/` | 新建目录: `main.mbt`, `moon.pkg`, `.env`, `run.sh` | SOCKS5 代理入口 |

### Phase 4: 测试与验证

| 序号 | 内容 | 说明 |
|------|------|------|
| 4.1 | `scripts/ssh-server/forward-test.sh` | Docker 测试脚本: 启动 SSH 服务器 + 目标 HTTP 服务 |
| 4.2 | 本地转发测试 | `cmd/forward-local` 转发到 Docker 内 HTTP 服务 |
| 4.3 | 远程转发测试 | `cmd/forward-remote` 让远端端口转发到本地服务 |
| 4.4 | SOCKS5 测试 | `cmd/forward-socks5` + curl 通过 SOCKS5 代理访问 |

---

## 测试脚本

### `scripts/ssh-server/forward-test.sh`

```bash
#!/bin/bash
set -e

# 1. 启动 SSH 服务器
docker rm -f openssh-server_forward
docker run -d \
  --name=openssh-server_forward \
  -e PUID=1000 -e PGID=1000 -e TZ=Etc/UTC \
  -e PASSWORD_ACCESS=true -e USER_NAME=admin -e USER_PASSWORD=test123 \
  -p 6022:2222 \
  lscr.io/linuxserver/openssh-server:latest

# 2. 启动目标 HTTP 服务 (用于测试转发)
docker rm -f target-http
docker run -d \
  --name=target-http \
  -p 8888:80 \
  nginx:alpine

echo "=== 测试环境就绪 ==="
echo "SSH:  admin@127.0.0.1:6022 (密码: test123)"
echo "HTTP: 127.0.0.1:8888"
echo ""
echo "本地转发测试:  forward-local  admin@127.0.0.1 -p 6022 -L 9090:target-http:80 --password test123"
echo "                然后访问 http://127.0.0.1:9090"
echo ""
echo "SOCKS5 测试:   forward-socks5 admin@127.0.0.1 -p 6022 -D 1080 --password test123"
echo "                然后 curl --socks5 127.0.0.1:1080 http://target-http"
```

---

## 已知限制与后续优化

| 限制 | 说明 | 后续方案 |
|------|------|---------|
| 单线程阻塞 | `relay_data` 使用 select 轮询, CPU 空转时有开销 | 引入 epoll/kqueue 或 MoonBit 协程 |
| IPv6 不支持 | SOCKS5 仅处理 IPv4 和域名 | 扩展 ATYP 0x04 处理 |
| 无认证 | SOCKS5 仅支持无认证 (0x00) | 新增 0x02 用户名/密码认证 |
| 无多路复用 | 每个转发连接占用一个 SSH 通道 | 支持 OpenSSH 多路复用协议 |
| 窗口管理简化 | 中继循环中窗口补充策略为简单阈值 | 实现自适应窗口管理 |
| 无 ProxyJump | 不支持跳板机链式转发 | 递归创建 Client 连接 |

---

## 验证方式

1. **编译验证**: `moon build` 全部通过
2. **单元测试**: 各消息构建器的序列化/反序列化测试
3. **集成测试**: 使用 Docker 测试环境验证三种转发类型
4. **兼容性测试**: 与 OpenSSH 客户端/服务器互操作验证
