///|
/// SFTP 客户端 CLI 入口
/// 支持 get/put/ls/rm/mkdir 等命令
fn main {
  let env_debug = @env.get_env_var("MOONBIT_SSH_DEBUG").unwrap_or("")
  if env_debug == "1" || env_debug == "true" {
    @src.enable_debug()
  }

  let argv = @utils.get_argv()
  if argv.length() == 0 {
    print_usage()
    return
  }

  let (opts, password, command, paths) = parse_args(argv)
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

  // 打开 SFTP 会话
  let sftp = @src.SftpClient::open(client) catch {
    e => abort("open: " + e.to_string())
  }
  defer sftp.close()

  // 执行命令
  cmd(sftp, command, paths) catch {
    e => abort("cmd: " + e.to_string())
  }
}

///|
/// 解析参数：user@host --port <port> --password <pwd> --command <cmd> <path>
fn parse_args(
  argv : Array[String],
) -> (@src.ConnectOptions, String, String, Array[String]) {
  // 解析连接字符串 user@host
  let mut connection = ""
  let mut port = 22
  let mut password = ""
  let mut command = ""
  let paths : Array[String] = []

  let mut i = 0
  while i < argv.length() {
    let arg = argv[i]
    if arg == "--port" && i + 1 < argv.length() {
      i = i + 1
      port = @utils.parse_int(argv[i])
    } else if arg == "--password" && i + 1 < argv.length() {
      i = i + 1
      password = argv[i]
    } else if arg == "--command" && i + 1 < argv.length() {
      i = i + 1
      command = argv[i]
    } else if arg.contains("@") {
      connection = arg
    } else {
      paths.push(arg)
    }
    i = i + 1
  }

  if connection.is_empty() {
    abort("Error: connection string (user@host) required")
  }

  // 解析 user@host
  let parts = connection.split("@")
  let user_host : Array[String] = []
  for part in parts {
    user_host.push(part.to_owned())
  }
  if user_host.length() != 2 {
    abort("missing user@host")
  }
  let user = user_host[0]
  let host = user_host[1]

  (@src.ConnectOptions::new(host, port, user), password, command, paths)
}

///|
fn print_usage() -> Unit {
  println(
    "Usage: sftp user@host --port <port> --password <pwd> --command <cmd> <args>",
  )
  println("")
  println("Commands:")
  println("  ls <path>              List directory")
  println("  get <remote>           Download file")
  println("  put <local> <remote>   Upload file")
  println("  rm <path>              Remove file")
  println("  mkdir <path>           Create directory")
  println("  rmdir <path>           Remove directory")
  println("  stat <path>            Show file attributes")
}

///|
fn cmd(
  sftp : @src.SftpClient,
  command : String,
  paths : Array[String],
) -> Unit raise @src.SshError {
  match command {
    "ls" => cmd_ls(sftp, paths)
    "get" => cmd_get(sftp, paths)
    "put" => cmd_put(sftp, paths)
    "rm" => cmd_rm(sftp, paths)
    "mkdir" => cmd_mkdir(sftp, paths)
    "rmdir" => cmd_rmdir(sftp, paths)
    "stat" => cmd_stat(sftp, paths)
    _ => {
      println("Unknown command: \{command}")
      print_usage()
    }
  }
}

///|
fn cmd_ls(
  sftp : @src.SftpClient,
  paths : Array[String],
) -> Unit raise @src.SshError {
  let path = if paths.length() > 0 { paths[0] } else { "." }
  let entries = sftp.listdir(path)
  for entry in entries {
    println("\{entry.longname}")
  }
}

///|
fn cmd_get(
  sftp : @src.SftpClient,
  paths : Array[String],
) -> Unit raise @src.SshError {
  if paths.length() < 1 {
    abort("get requires remote path")
  }
  let remote_path = paths[0]
  let data = sftp.read_file(remote_path)
  println("Downloaded \{data.length()} bytes")
  // 这里简化处理，实际应该写入本地文件
  // 为了演示，只打印前 100 字节
  let preview_len = if data.length() < 100 { data.length() } else { 100 }
  let mut preview = "Content preview: "
  for i = 0; i < preview_len; i = i + 1 {
    let b = data.unsafe_get(i)
    if b.to_int() >= 32 && b.to_int() < 127 {
      preview = preview + b.to_int().unsafe_to_char().to_string()
    } else {
      preview = preview + "."
    }
  }
  println(preview)
}

///|
fn cmd_put(
  sftp : @src.SftpClient,
  paths : Array[String],
) -> Unit raise @src.SshError {
  if paths.length() < 2 {
    abort("put requires local and remote paths")
  }

  let remote = paths[1]

  // 简化演示，上传一个测试字符串
  let test_data = b"Hello from MoonSSH SFTP client!\n"
  sftp.write_file(remote, test_data, 0o644)
  println("Uploaded \{test_data.length()} bytes to \{remote}")
}

///|
fn cmd_rm(
  sftp : @src.SftpClient,
  paths : Array[String],
) -> Unit raise @src.SshError {
  if paths.length() < 1 {
    abort("rm requires path")
  }
  let path = paths[0]
  sftp.remove(path)
  println("Removed \{path}")
}

///|
fn cmd_mkdir(
  sftp : @src.SftpClient,
  paths : Array[String],
) -> Unit raise @src.SshError {
  if paths.length() < 1 {
    abort("mkdir requires path")
  }

  let path = paths[0]
  sftp.mkdir(path, 0o755)
  println("Created directory \{path}")
}

///|
fn cmd_rmdir(
  sftp : @src.SftpClient,
  paths : Array[String],
) -> Unit raise @src.SshError {
  if paths.length() < 1 {
    abort("rmdir requires path")
  }

  let path = paths[0]
  sftp.rmdir(path)
  println("Removed directory \{path}")
}

///|
fn cmd_stat(
  sftp : @src.SftpClient,
  paths : Array[String],
) -> Unit raise @src.SshError {
  if paths.length() < 1 {
    abort("stat requires path")
  }

  let path = paths[0]
  let attrs = sftp.stat(path)
  println("File attributes for \{path}:")
  match attrs.size {
    Some(s) => println("  Size: \{s} bytes")
    None => ()
  }
  match attrs.permissions {
    Some(p) => println("  Permissions: 0o\{p.to_string()}")
    None => ()
  }
  match attrs.uid {
    Some(u) => println("  UID: \{u}")
    None => ()
  }
  match attrs.gid {
    Some(g) => println("  GID: \{g}")
    None => ()
  }
  match attrs.mtime {
    Some(m) => println("  MTime: \{m}")
    None => ()
  }
}
