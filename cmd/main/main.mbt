///
/// MoonSSH 命令行客户端。

fn main {
  let argv = get_argv()
  let (opts, password, command, key_path) = parse_args(argv) catch {
    msg => {
      println("error: " + msg.to_string())
      println("usage: moonssh user@host [-p port] [-l user] [-i identity] [-T]")
      abort("invalid arguments")
    }
  }
  let client = @src.Client::connect(opts) catch {
    e => abort("connect: " + e.to_string())
  }
  defer client.close()
  client.kex() catch { e => abort("kex: " + e.to_string()) }

  // 尝试自动认证
  client.auth_auto(password, key_path~) catch {
    AuthFailed(msg) => abort("auth failed: " + msg)
    e => abort("auth error: " + e.to_string())
  }

  if command.length() > 0 {
    let ch = client.open_session()
    let output = client.exec(ch, command) catch { e => abort("exec: " + e.to_string()) }
    println(output)
  } else {
    let ch = client.open_session()
    client.shell(ch) catch { e => abort("shell: " + e.to_string()) }
    // 简单交互循环
    println("Shell opened (interactive not fully implemented)")
    // 读取返回数据
    let mut buf = ""
    while true {
      let payload = client.read_encrypted_packet() catch {
        _ => { buf = "Connection closed" ; break }
      }
      let responses = ch.handle_inbound(payload) catch {
        _ => break
      }
      for resp in responses { client.write_packet(resp) catch { _ => () } }
      if ch.has_stdout() {
        buf = buf + ch.take_stdout()
      }
      if ch.state() == EofReceived || ch.state() == Done { break }
    }
    print(buf)
  }
}

fn get_argv() -> Array[String] {
  let s = @env.get_env_var("MOONBIT_CLI_ARGS").unwrap_or("")
  if s.length() == 0 { [] }
  else { s.split(" ").map(v => v.to_owned()).collect() }
}

fn parse_args(argv : Array[String]) -> (@src.ConnectOptions, String, String, String) raise {
  if argv.length() == 0 { raise CliError("missing user@host") }
  let userhost = argv[0]
  let (mut user, host) = split_user_host(userhost)
  let mut port = 22
  let mut password = ""
  let mut command = ""
  let mut identity = "~/.ssh/id_rsa"
  let mut i = 1
  while i < argv.length() {
    match argv[i] {
      "-p" | "--port" if i + 1 < argv.length() => {
        port = parse_int(argv[i + 1]); i = i + 2
      }
      "-l" | "--user" if i + 1 < argv.length() => {
        user = argv[i + 1]; i = i + 2
      }
      "-i" | "--identity" if i + 1 < argv.length() => {
        identity = argv[i + 1]; i = i + 2
      }
      "--exec" | "-e" if i + 1 < argv.length() => {
        command = argv[i + 1]; i = i + 2
      }
      "--password" if i + 1 < argv.length() => {
        password = argv[i + 1]; i = i + 2
      }
      _ => i = i + 1
    }
  }
  (@src.ConnectOptions::new(host, port, user), password, command, identity)
}

fn split_user_host(s : String) -> (String, String) {
  let view = s
  let arr = view.to_array()
  let mut at_idx = -1
  let mut i = 0
  while i < arr.length() {
    if arr.unsafe_get(i) == '@' { at_idx = i; break }
    i = i + 1
  }
  if at_idx < 0 { ("root", s) }
  else {
    let sb1 = StringBuilder::new()
    for j = 0; j < at_idx; j = j + 1 { sb1.write_char(arr.unsafe_get(j)) }
    let sb2 = StringBuilder::new()
    for j = at_idx + 1; j < s.length(); j = j + 1 { sb2.write_char(arr.unsafe_get(j)) }
    (sb1.to_string(), sb2.to_string())
  }
}

fn parse_int(s : String) -> Int {
  let arr = s.to_array()
  let mut n = 0
  let mut i = 0
  let mut neg = false
  if arr.length() > 0 && arr.unsafe_get(0) == '-' { neg = true; i = 1 }
  while i < arr.length() {
    let c = arr.unsafe_get(i)
    if c < '0' || c > '9' { break }
    n = n * 10 + (c.to_int() - '0'.to_int())
    i = i + 1
  }
  if neg { -n } else { n }
}

suberror CliError { CliError(String) } derive(Eq)
