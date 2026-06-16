///|
/// MoonSSH 命令行客户端。
fn main {
  let env_debug = @env.get_env_var("MOONBIT_SSH_DEBUG").unwrap_or("")
  if env_debug == "1" || env_debug == "true" {
    @src.enable_debug()
  }

  let argv = @utils.get_argv()
  if argv.length() == 0 {
    println(
      "usage: moonssh user@host [-p port] [-l user] [--exec CMD] [--password PWD] [--debug]",
    )
    abort("no arguments")
  }
  let (opts, password, command) = parse_args(argv)
  let client = @src.Client::connect(opts) catch {
    e => abort("connect: " + e.to_string())
  }
  defer client.close()
  client.kex() catch {
    e => abort("kex: " + e.to_string())
  }
  client.auth_auto(password) catch {
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
fn parse_args(argv : Array[String]) -> (@src.ConnectOptions, String, String) {
  if argv.length() == 0 {
    abort("missing user@host")
  }
  let userhost = argv[0]
  let (tmp_user, host) = @utils.split_user_host(userhost)
  let mut result_user = tmp_user
  let mut port = 22
  let mut password = ""
  let mut command = "uname -a"
  let mut i = 1
  while i < argv.length() {
    match argv[i] {
      "-p" | "--port" if i + 1 < argv.length() => {
        port = @utils.parse_int(argv[i + 1])
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
      "--password" if i + 1 < argv.length() => {
        password = argv[i + 1]
        i = i + 2
      }
      "--debug" | "-d" => {
        @src.enable_debug()
        i = i + 1
      }
      _ => i = i + 1
    }
  }
  (@src.ConnectOptions::new(host, port, result_user), password, command)
}
