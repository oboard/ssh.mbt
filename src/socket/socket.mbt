///|
/// Simplified TCP socket implementation using Winsock2 FFI
/// This replaces moonbitlang/async/socket to avoid MSVC dependency

///|
/// A TCP connection
pub struct Tcp {
  handle : Int // Socket handle (SOCKET on Windows)
  host : String
  port : Int
}

///|
/// Initialize Winsock (Windows only, must be called before using sockets)
extern "C" fn winsock_init() -> Int = "socket_init"

///|
/// Create a TCP socket
extern "C" fn socket_create() -> Int = "socket_create"

///|
/// Connect to a host (by IP address string and port)
#borrow(host)
extern "C" fn socket_connect(handle : Int, host : String, port : Int) -> Int = "socket_connect"

///|
/// Send data through socket
#borrow(data)
extern "C" fn socket_send(handle : Int, data : String) -> Int = "socket_send"

///|
/// Send raw bytes through socket
#borrow(data)
extern "C" fn socket_send_bytes(handle : Int, data : Bytes, len : Int) -> Int = "socket_send_bytes"

///|
/// Receive data from socket into buffer starting at offset
#borrow(buffer)
extern "C" fn socket_recv(
  handle : Int,
  buffer : Bytes,
  offset : Int,
  size : Int,
) -> Int = "socket_recv"

///|
/// Close a socket
extern "C" fn socket_close(handle : Int) -> Unit = "socket_close"

///|
/// Connect to a remote host
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

  { handle, host, port }
}

///|
/// Write data to the connection
pub fn Tcp::write(self : Tcp, data : String) -> Unit raise {
  let result = socket_send(self.handle, data)
  if result < 0 {
    raise IoError("Failed to send data: error code \{result}")
  }
}

///|
/// Write raw bytes to the connection.
pub fn Tcp::write_bytes(self : Tcp, data : Bytes) -> Unit raise {
  let result = socket_send_bytes(self.handle, data, data.length())
  if result < 0 {
    raise IoError("Failed to send bytes: error code \{result}")
  }
}

///|
/// Read a line from the connection (reads until \n or \r\n)
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
/// Read exact number of bytes
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
/// Read bytes until a newline (\n) is encountered.
/// Returns all content bytes up to (but not including) the newline.
/// Trailing \r is stripped (for \r\n line endings).
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
/// Close the connection
pub fn Tcp::close(self : Tcp) -> Unit {
  socket_close(self.handle)
}

///|
/// IO error type
pub suberror IoError {
  IoError(String)
} derive(Eq, Debug)
