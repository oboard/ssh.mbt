///|
/// MoonSSH 命令行客户端 — Ed25519 公钥认证版本。
fn main {
  let env_debug = @env.get_env_var("MOONBIT_SSH_DEBUG").unwrap_or("")
  if env_debug == "1" || env_debug == "true" {
    @src.enable_debug()
  }

  let argv = get_argv()
  if argv.length() == 0 {
    println(
      "usage: moonssh-key-ed25519 user@host [-p port] [-l user] [--key PATH] [--exec CMD] [--debug]",
    )
    abort("no arguments")
  }
  let (opts, key_path, command) = parse_args(argv)
  let client = @src.Client::connect(opts) catch {
    e => abort("connect: " + e.to_string())
  }
  defer client.close()
  client.kex() catch {
    e => abort("kex: " + e.to_string())
  }
  client.auth_publickey(key_path) catch {
    e => abort("auth: " + e.to_string())
  }

  let ch = client.open_session()
  let (stdout, stderr) = client.exec(ch, command) catch {
    e => abort("exec: " + e.to_string())
  }
  if stdout.length() > 0 {
    println(stdout)
  }
  if stderr.length() > 0 {
    println(stderr)
  }
}

///|
fn tokenize_args(s : String) -> Array[String] {
  let arr = s.to_array()
  let mut i = 0
  let result : Array[String] = []
  while i < arr.length() {
    let c = arr.unsafe_get(i)
    if c == ' ' || c == '\t' {
      i = i + 1
    } else if c == '\'' {
      i = i + 1
      let mut buf = ""
      while i < arr.length() && arr.unsafe_get(i) != '\'' {
        buf = buf + arr.unsafe_get(i).to_string()
        i = i + 1
      }
      if i < arr.length() {
        i = i + 1
      }
      result.push(buf)
    } else if c == '"' {
      i = i + 1
      let mut buf = ""
      while i < arr.length() && arr.unsafe_get(i) != '"' {
        buf = buf + arr.unsafe_get(i).to_string()
        i = i + 1
      }
      if i < arr.length() {
        i = i + 1
      }
      result.push(buf)
    } else {
      let mut buf = ""
      while i < arr.length() &&
            arr.unsafe_get(i) != ' ' &&
            arr.unsafe_get(i) != '\t' {
        buf = buf + arr.unsafe_get(i).to_string()
        i = i + 1
      }
      result.push(buf)
    }
  }
  result
}

///|
fn get_argv() -> Array[String] {
  let s = @env.get_env_var("MOONBIT_CLI_ARGS").unwrap_or("")
  if s.length() == 0 {
    []
  } else {
    tokenize_args(s)
  }
}

///|
fn parse_args(argv : Array[String]) -> (@src.ConnectOptions, String, String) {
  if argv.length() == 0 {
    abort("missing user@host")
  }
  let userhost = argv[0]
  let (tmp_user, host) = split_user_host(userhost)
  let mut result_user = tmp_user
  let mut port = 22
  let mut key_path = "~/.ssh/id_ed25519"
  let mut command = "uname -a"
  let mut i = 1
  while i < argv.length() {
    match argv[i] {
      "-p" | "--port" if i + 1 < argv.length() => {
        port = parse_int(argv[i + 1])
        i = i + 2
      }
      "-l" | "--user" if i + 1 < argv.length() => {
        result_user = argv[i + 1]
        i = i + 2
      }
      "--exec" | "-e" if i + 1 < argv.length() => {
        command = argv[i + 1]
        i = i + 2
      }
      "-i" | "--key" | "--identity" if i + 1 < argv.length() => {
        key_path = argv[i + 1]
        i = i + 2
      }
      "--debug" | "-d" => {
        @src.enable_debug()
        i = i + 1
      }
      _ => i = i + 1
    }
  }
  (@src.ConnectOptions::new(host, port, result_user), key_path, command)
}

///|
fn split_user_host(s : String) -> (String, String) {
  let arr = s.to_array()
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
    let sb1 = StringBuilder::new()
    let sb2 = StringBuilder::new()
    for j = 0; j < at_idx; j = j + 1 {
      sb1.write_char(arr.unsafe_get(j))
    }
    for j = at_idx + 1; j < s.length(); j = j + 1 {
      sb2.write_char(arr.unsafe_get(j))
    }
    (sb1.to_string(), sb2.to_string())
  }
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
