///|
/// SFTP 客户端 CLI 入口
/// 支持 get/put/ls/rm/mkdir 等命令

fn init {
  // 初始化
}

fn main {
  run_main() catch { e => println("Error: \{e}") }
}

fn run_main() -> Unit raise @src.SshError {
  // 解析参数：user@host --port <port> --password <pwd> --command <cmd> <path>
  let args = @utils.get_argv()
  if args.length() == 0 {
    print_usage()
    return
  }

  // 解析连接字符串 user@host
  let mut connection = ""
  let mut port = 22
  let mut password = ""
  let mut command = ""
  let paths : Array[String] = []

  let mut i = 0
  while i < args.length() {
    let arg = args[i]
    if arg == "--port" && i + 1 < args.length() {
      i = i + 1
      port = @strconv.parse_int(args[i]) catch {
        _ => {
          println("Invalid port: \{args[i]}")
          return
        }
      }
    } else if arg == "--password" && i + 1 < args.length() {
      i = i + 1
      password = args[i]
    } else if arg == "--command" && i + 1 < args.length() {
      i = i + 1
      command = args[i]
    } else if arg.contains("@") {
      connection = arg
    } else {
      paths.push(arg)
    }
    i = i + 1
  }

  if connection.is_empty() {
    println("Error: connection string (user@host) required")
    print_usage()
    return
  }

  // 解析 user@host
  let parts = connection.split("@")
  let user_host : Array[String] = []
  for part in parts {
    user_host.push(part.to_owned())
  }
  if user_host.length() != 2 {
    println("Error: invalid connection string '\{connection}'")
    return
  }
  let user = user_host[0]
  let host = user_host[1]

  // 连接并认证
  let opts = @src.ConnectOptions::new(host, port, user)
  let client = @src.Client::connect(opts)
  client.kex()
  client.auth_password(password)

  // 打开 SFTP 会话
  let sftp = @src.SftpClient::open(client)

  // 执行命令
  match command {
    "ls" => {
      let remote_path = if paths.length() > 0 { paths[0] } else { "." }
      cmd_ls(sftp, remote_path)
    }
    "get" => {
      if paths.length() < 1 {
        println("Error: get requires remote path")
        return
      }
      cmd_get(sftp, paths[0])
    }
    "put" => {
      if paths.length() < 2 {
        println("Error: put requires local and remote paths")
        return
      }
      cmd_put(sftp, paths[0], paths[1])
    }
    "rm" => {
      if paths.length() < 1 {
        println("Error: rm requires path")
        return
      }
      cmd_rm(sftp, paths[0])
    }
    "mkdir" => {
      if paths.length() < 1 {
        println("Error: mkdir requires path")
        return
      }
      cmd_mkdir(sftp, paths[0])
    }
    "rmdir" => {
      if paths.length() < 1 {
        println("Error: rmdir requires path")
        return
      }
      cmd_rmdir(sftp, paths[0])
    }
    "stat" => {
      if paths.length() < 1 {
        println("Error: stat requires path")
        return
      }
      cmd_stat(sftp, paths[0])
    }
    "" => {
      println("Error: command required")
      print_usage()
    }
    _ => println("Unknown command: \{command}")
  }

  sftp.close()
  client.close()
}

fn print_usage() -> Unit {
  println("Usage: sftp user@host --port <port> --password <pwd> --command <cmd> <args>")
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

fn cmd_ls(sftp : @src.SftpClient, path : String) -> Unit raise @src.SshError {
  let entries = sftp.listdir(path)
  for entry in entries {
    println("\{entry.longname}")
  }
}

fn cmd_get(
  sftp : @src.SftpClient,
  remote_path : String
) -> Unit raise @src.SshError {
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

fn cmd_put(
  sftp : @src.SftpClient,
  _local : String,
  remote : String
) -> Unit raise @src.SshError {
  // 简化演示，上传一个测试字符串
  let test_data = b"Hello from MoonSSH SFTP client!\n"
  sftp.write_file(remote, test_data, 0o644)
  println("Uploaded \{test_data.length()} bytes to \{remote}")
}

fn cmd_rm(sftp : @src.SftpClient, path : String) -> Unit raise @src.SshError {
  sftp.remove(path)
  println("Removed \{path}")
}

fn cmd_mkdir(
  sftp : @src.SftpClient,
  path : String
) -> Unit raise @src.SshError {
  sftp.mkdir(path, 0o755)
  println("Created directory \{path}")
}

fn cmd_rmdir(
  sftp : @src.SftpClient,
  path : String
) -> Unit raise @src.SshError {
  sftp.rmdir(path)
  println("Removed directory \{path}")
}

fn cmd_stat(sftp : @src.SftpClient, path : String) -> Unit raise @src.SshError {
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
