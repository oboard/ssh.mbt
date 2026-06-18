///|
/// 简化的 TCP socket 实现（基于 Winsock2 FFI）。
/// 替代 moonbitlang/async/socket 以避免 MSVC 依赖。

///|
/// TCP 连接句柄。
pub struct Tcp {
  handle : Int // Socket handle (SOCKET on Windows)
  host : String
  port : Int
}

///|
/// 初始化 Winsock（仅 Windows，使用 socket 前必须调用）。
extern "C" fn winsock_init() -> Int = "socket_init"

///|
/// 创建 TCP socket。
extern "C" fn socket_create() -> Int = "socket_create"

///|
/// 连接到指定主机（IP 地址字符串 + 端口）。
#borrow(host)
extern "C" fn socket_connect(handle : Int, host : String, port : Int) -> Int = "socket_connect"

///|
/// 通过 socket 发送字符串数据。
#borrow(data)
extern "C" fn socket_send(handle : Int, data : String) -> Int = "socket_send"

///|
/// 通过 socket 发送原始字节数据。
#borrow(data)
extern "C" fn socket_send_bytes(handle : Int, data : Bytes, len : Int) -> Int = "socket_send_bytes"

///|
/// 从 socket 接收数据到缓冲区指定偏移位置。
#borrow(buffer)
extern "C" fn socket_recv(
  handle : Int,
  buffer : Bytes,
  offset : Int,
  size : Int,
) -> Int = "socket_recv"

///|
/// 关闭 socket。
extern "C" fn socket_close(handle : Int) -> Unit = "socket_close"

///|
/// 设置 TCP_NODELAY（禁用 Nagle 算法）。
/// 对 SSH 等交互式协议至关重要，确保小包立即发送。
extern "C" fn socket_set_nodelay(handle : Int) -> Int = "socket_set_nodelay"

///|
/// 设置 C 层调试输出的全局开关（控制 socket/openssl 的 stderr 输出）。
extern "C" fn moonbit_set_moonssh_debug(val : Int) -> Unit = "moonbit_set_moonssh_debug"

///|
/// 绑定端口并开始监听。
extern "C" fn socket_bind_listen(
  handle : Int,
  port : Int,
  backlog : Int,
) -> Int = "socket_bind_listen"

///|
/// 接受一个入站 TCP 连接，返回新 socket 句柄。
extern "C" fn socket_accept(handle : Int) -> Int = "socket_accept"

///|
/// 非阻塞检查是否有入站连接等待。
extern "C" fn socket_poll_accept(handle : Int) -> Int = "socket_poll_accept"

///|
/// 设置 socket 为非阻塞模式。
extern "C" fn socket_set_nonblocking(handle : Int) -> Int = "socket_set_nonblocking"

///|
/// 非阻塞检查 socket 是否有数据可读。
extern "C" fn socket_poll_readable(handle : Int) -> Int = "socket_poll_readable"

///|
/// 启用或禁用 C 层调试输出。
pub fn set_debug(enabled : Bool) -> Unit {
  moonbit_set_moonssh_debug(if enabled { 1 } else { 0 })
}

///|
/// 连接到远程主机。自动初始化 Winsock、创建 socket、设置 TCP_NODELAY。
pub fn Tcp::connect_to_host(host : String, port~ : Int) -> Tcp raise {
  // Initialize Winsock on Windows
  let init_result = winsock_init()
  if init_result != 0 {
    raise IoError("Failed to initialize Winsock: code \{init_result}")
  }

  // Create socket
  let handle = socket_create()
  if handle < 0 {
    raise IoError("Failed to create socket")
  }

  // Connect
  let conn_result = socket_connect(handle, host, port)
  if conn_result != 0 {
    socket_close(handle)
    raise IoError(
      "Failed to connect to \{host}:\{port}, error code: \{conn_result}",
    )
  }

  // Disable Nagle's algorithm for SSH-style interactive protocols
  let nodelay_result = socket_set_nodelay(handle)
  if nodelay_result < 0 {
    // Non-fatal: log but continue; some environments may not support it
    println("Warning: failed to set TCP_NODELAY")
  }

  { handle, host, port }
}

///|
/// 向连接写入字符串数据。
pub fn Tcp::write(self : Tcp, data : String) -> Unit raise {
  let result = socket_send(self.handle, data)
  if result < 0 {
    raise IoError("Failed to send data: error code \{result}")
  }
}

///|
/// 向连接写入原始字节数据。
pub fn Tcp::write_bytes(self : Tcp, data : Bytes) -> Unit raise {
  let result = socket_send_bytes(self.handle, data, data.length())
  if result < 0 {
    raise IoError("Failed to send bytes: error code \{result}")
  }
}

///|
/// 从连接读取一行（直到 `\n` 或 `\r\n`）。
pub fn Tcp::read_line(self : Tcp) -> String raise {
  let buffer = Bytes::new(4096)
  let mut total_read = 0
  let mut found_newline = false

  // Read byte by byte until we find a newline
  while !found_newline && total_read < 4096 {
    let bytes_read = socket_recv(self.handle, buffer, total_read, 1)
    if bytes_read <= 0 {
      if total_read == 0 {
        raise IoError("Connection closed or error reading")
      }
      break
    }

    let byte = buffer[total_read]
    total_read = total_read + 1

    if byte == b'\n' {
      found_newline = true
    }
  }

  if total_read == 0 {
    raise IoError("No data read")
  }

  // Convert only the bytes actually read into a line string.
  let result = Bytes::makei(total_read, i => buffer[i])
  result.to_string()
}

///|
/// 精确读取指定字节数（阻塞直到读满）。
pub fn Tcp::read_exact(self : Tcp, size : Int) -> Bytes raise {
  let buffer = Bytes::new(size)
  let mut total_read = 0

  while total_read < size {
    let bytes_read = socket_recv(
      self.handle,
      buffer,
      total_read,
      size - total_read,
    )
    if bytes_read <= 0 {
      raise IoError(
        "Connection closed or error reading, read \{total_read}/\{size} bytes",
      )
    }
    total_read = total_read + bytes_read
  }

  buffer
}

///|
/// 读取字节直到遇到换行符 `\n`。
/// 返回换行前的所有字节，末尾 `\r` 会被去除（兼容 `\r\n`）。
pub fn Tcp::read_until_newline(self : Tcp) -> Bytes raise {
  let buffer = Bytes::new(4096)
  let mut total_read = 0
  let mut found_newline = false

  while !found_newline && total_read < 4096 {
    let bytes_read = socket_recv(self.handle, buffer, total_read, 1)
    if bytes_read <= 0 {
      if total_read == 0 {
        raise IoError("Connection closed or error reading")
      }
      break
    }
    let byte = buffer[total_read]
    if byte == b'\n' {
      found_newline = true
    } else {
      total_read = total_read + 1
    }
  }

  if total_read == 0 {
    raise IoError("No data read")
  }

  // Strip trailing \r (for \r\n line endings)
  if total_read > 0 && buffer[total_read - 1] == b'\r' {
    total_read = total_read - 1
  }

  Bytes::makei(total_read, i => buffer[i])
}

///|
/// 关闭连接。
pub fn Tcp::close(self : Tcp) -> Unit {
  socket_close(self.handle)
}

///|
/// 创建一个 TCP 监听器，绑定到指定端口并开始监听。
/// backlog 控制等待队列长度（默认 128）。
pub fn Tcp::bind_listen(port : Int, backlog~ : Int = 128) -> Tcp raise {
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

///|
/// 接受一个入站 TCP 连接。阻塞直到有连接到达。
pub fn Tcp::accept(self : Tcp) -> Tcp raise {
  let client_handle = socket_accept(self.handle)
  if client_handle < 0 {
    raise IoError("Failed to accept connection")
  }
  let _ = socket_set_nodelay(client_handle)
  { handle: client_handle, host: "", port: 0 }
}

///|
/// 非阻塞检查是否有入站连接等待。
pub fn Tcp::has_pending_connection(self : Tcp) -> Bool {
  socket_poll_accept(self.handle) > 0
}

///|
/// 设置 socket 为非阻塞模式。
pub fn Tcp::set_nonblocking(self : Tcp) -> Unit raise {
  let rc = socket_set_nonblocking(self.handle)
  if rc != 0 {
    raise IoError("Failed to set non-blocking mode")
  }
}

///|
/// 非阻塞检查是否有数据可读。
pub fn Tcp::has_data(self : Tcp) -> Bool {
  socket_poll_readable(self.handle) > 0
}

///|
/// 接收数据到缓冲区。返回实际读取的字节数，0 表示连接关闭，负数表示错误。
/// 用于非阻塞 socket 上的数据中继。
pub fn Tcp::recv(self : Tcp, buffer : Bytes, offset : Int, size : Int) -> Int {
  socket_recv(self.handle, buffer, offset, size)
}

///|
/// I/O 错误类型。
pub suberror IoError {
  IoError(String)
} derive(Eq, Debug)
