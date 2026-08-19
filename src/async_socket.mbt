///|
/// Local convenience methods for the async TCP transport.
/// They remain in the SSH package so no compatibility wrapper package is needed.
async fn @socket.Tcp::write_bytes(
  self : @socket.Tcp,
  data : Bytes,
) -> Unit raise SshError {
  self.write(data) catch {
    e => raise IoError("socket write: \{Repr(e)}")
  }
}

///|
async fn @socket.Tcp::read_exact(
  self : @socket.Tcp,
  size : Int,
) -> Bytes raise SshError {
  self.read_exactly(size) catch {
    e => raise IoError("socket read \{size} bytes: \{Repr(e)}")
  }
}

///|
async fn @socket.Tcp::read_until_newline(
  self : @socket.Tcp,
) -> Bytes raise SshError {
  let line = self.read_until("\n") catch {
    e => raise IoError("socket read line: \{Repr(e)}")
  }
  match line {
    Some(line) => {
      let bytes = @utf8.encode(line)
      if bytes.length() > 0 && bytes[bytes.length() - 1] == b'\r' {
        Bytes::makei(bytes.length() - 1, i => bytes[i])
      } else {
        bytes
      }
    }
    None => raise ConnectionClosed
  }
}

///|
async fn bind_tcp_listener(port : Int) -> @socket.TcpServer raise SshError {
  @socket.TcpServer(@socket.Addr::new(0U, port), reuse_addr=true) catch {
    e => raise IoError("bind local port \{port}: \{Repr(e)}")
  }
}

///|
async fn accept_tcp(listener : @socket.TcpServer) -> @socket.Tcp raise SshError {
  let (conn, _) = listener.accept() catch {
    e => raise IoError("accept: \{Repr(e)}")
  }
  conn
}
