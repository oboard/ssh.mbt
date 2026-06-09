///|
/// MoonSSH 命令行客户端演示（v0.1）。
///
/// 用法：
///   moon run cmd/main -- <user>@<host> [--port 22] [--exec "ls -l"] [--password PWD]
///
///   示例：
///     moon run cmd/main -- alice@example.com --exec "uname -a"
///     moon run cmd/main -- bob@192.168.1.10 --port 2222 --password hunter2 --exec "uptime"
///
/// v0.1 限制：
///   - 仅支持 `password` 认证（公钥认证见 `docs/prd_001.md` Step 4.3）
///   - 协议层多个函数是 stub：若需真连接，请先实现 KEX / auth / channel
///     的完整版本（`src/kex.mbt`、`src/auth.mbt`、`src/channel.mbt`）。
fn main {
  let argv = get_argv()
  let (opts, password, command) = parse_args(argv) catch {
    msg => {
      println("error: " + msg.to_string())
      println(
        "usage: moonssh user@host [--port 22] [--exec CMD] [--password PWD]",
      )
      abort("invalid arguments")
    }
  }
  let client = @src.Client::connect(opts) catch {
    e => abort("connect: " + e.to_string())
  }
  defer client.close()
  client.kex() catch {
    e => abort("kex: " + e.to_string())
  }
  client.auth_password(password) catch {
    e => abort("auth: " + e.to_string())
  }
  let ch = client.open_session()
  let output = client.exec(ch, command) catch {
    e => abort("exec: " + e.to_string())
  }
  println(output)
}

// --- argv from environment ------------------------------------------

///|
/// Read command-line args from a single env var `MOONBIT_CLI_ARGS`
/// (the moon runtime convention) or fall back to an empty list.
fn get_argv() -> Array[String] {
  let s = @env.get_env_var("MOONBIT_CLI_ARGS").unwrap_or("")
  if s.length() == 0 {
    []
  } else {
    s.split(" ").map(v => v.to_owned()).collect()
  }
}

// --- Minimal argument parser ----------------------------------------

///|
fn parse_args(
  argv : Array[String],
) -> (@src.ConnectOptions, String, String) raise {
  if argv.length() == 0 {
    raise CliError("missing user@host positional")
  }
  let userhost = argv[0]
  let (user, host) = split_user_host(userhost)
  let mut port = 22
  let mut password = ""
  let mut command = "uname -a"
  let mut i = 1
  while i < argv.length() {
    match argv[i] {
      "--port" if i + 1 < argv.length() => {
        port = parse_int(argv[i + 1])
        i = i + 2
      }
      "--password" if i + 1 < argv.length() => {
        password = argv[i + 1]
        i = i + 2
      }
      "--exec" if i + 1 < argv.length() => {
        command = argv[i + 1]
        i = i + 2
      }
      _ => i = i + 1
    }
  }
  (@src.ConnectOptions::new(host, port, user), password, command)
}

///|
fn split_user_host(s : String) -> (String, String) {
  let view = s
  let arr = view.to_array()
  let mut at_idx = -1
  let mut i = 0
  while i < arr.length() {
    if arr.unsafe_get(i) == '@' {
      at_idx = i
      break
    }
    i = i + 1
  }
  if at_idx < 0 {
    ("root", s)
  } else {
    let user = slice_string(s, 0, at_idx)
    let host = slice_string(s, at_idx + 1, s.length())
    (user, host)
  }
}

///|
fn slice_string(s : String, start : Int, end : Int) -> String {
  let arr = s.to_array()
  let sb = StringBuilder::new()
  for i = start; i < end; i = i + 1 {
    sb.write_char(arr.unsafe_get(i))
  }
  sb.to_string()
}

///|
fn parse_int(s : String) -> Int {
  let arr = s.to_array()
  let mut n = 0
  let mut i = 0
  let mut neg = false
  if arr.length() > 0 && arr.unsafe_get(0) == '-' {
    neg = true
    i = 1
  }
  while i < arr.length() {
    let c = arr.unsafe_get(i)
    if c < '0' || c > '9' {
      break
    }
    n = n * 10 + (c.to_int() - '0'.to_int())
    i = i + 1
  }
  if neg {
    -n
  } else {
    n
  }
}

///|
suberror CliError {
  CliError(String)
} derive(Eq)
