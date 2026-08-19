///|
/// SSH 端口转发 CLI。
/// 支持三种转发模式：
///   -L local:host:port    本地转发
///   -R remote:host:port   远程转发
///   -D port               SOCKS5 动态代理
fn main {
  let env_debug = @env.get_env_var("MOONBIT_SSH_DEBUG").unwrap_or("")
  if env_debug == "1" || env_debug == "true" {
    @src.enable_debug()
  }

  let argv = @utils.get_argv()
  if argv.length() == 0 {
    println("usage: forward user@host [-p port] <-L|-R|-D> spec --password PWD")
    println("  -L local_port:remote_host:remote_port   local forwarding")
    println("  -R remote_port:local_host:local_port    remote forwarding")
    println("  -D local_port                            SOCKS5 proxy")
    abort("no arguments")
  }
  let parsed = parse_args(argv)
  let opts = parsed.opts.with_insecure_host_key()
  let client = @src.Client::connect(opts) catch {
    e => abort("connect: \{Repr(e)}")
  }
  defer client.close()
  client.kex() catch {
    e => abort("kex: \{Repr(e)}")
  }
  client.auth_auto(parsed.password) catch {
    e => abort("auth: \{Repr(e)}")
  }

  match parsed.mode {
    Local(lp, rh, rp) => {
      println("Forwarding 127.0.0.1:\{lp} → \{rh}:\{rp}")
      client.forward_local_port(lp, rh, rp) catch {
        e => abort("forward: \{Repr(e)}")
      }
    }
    Remote(rp, lh, lp) => {
      println("Remote forwarding port \{rp} → \{lh}:\{lp}")
      client.forward_remote_port(rp, lh, lp) catch {
        e => abort("forward: \{Repr(e)}")
      }
    }
    Socks5(sp) => {
      println("SOCKS5 proxy listening on 127.0.0.1:\{sp}")
      client.forward_socks5(sp) catch {
        e => abort("forward: \{Repr(e)}")
      }
    }
  }
}

///|
/// 转发模式。
enum ForwardMode {
  Local(Int, String, Int)
  Remote(Int, String, Int)
  Socks5(Int)
}

///|
/// 解析后的参数。
struct ParsedArgs {
  opts : @src.ConnectOptions
  password : String
  mode : ForwardMode
}

///|
fn parse_args(argv : Array[String]) -> ParsedArgs {
  if argv.length() == 0 {
    abort("missing user@host")
  }
  let userhost = argv[0]
  let (tmp_user, host) = @utils.split_user_host(userhost)
  let mut user = tmp_user
  let mut port = 22
  let mut password = ""
  let mut mode : ForwardMode? = None
  let mut i = 1
  while i < argv.length() {
    match argv[i] {
      "-p" | "--port" if i + 1 < argv.length() => {
        port = @utils.parse_int(argv[i + 1])
        i = i + 2
      }
      "-l" | "--user" if i + 1 < argv.length() => {
        user = argv[i + 1]
        i = i + 2
      }
      "-L" if i + 1 < argv.length() => {
        let (lp, rh, rp) = @utils.parse_forward_arg(argv[i + 1])
        mode = Some(Local(lp, rh, rp))
        i = i + 2
      }
      "-R" if i + 1 < argv.length() => {
        let (rp, lh, lp) = @utils.parse_forward_arg(argv[i + 1])
        mode = Some(Remote(rp, lh, lp))
        i = i + 2
      }
      "-D" if i + 1 < argv.length() => {
        mode = Some(Socks5(@utils.parse_int(argv[i + 1])))
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
  let m = match mode {
    Some(m) => m
    None => abort("missing forwarding mode: use -L, -R, or -D")
  }
  { opts: @src.ConnectOptions::new(host, port, user), password, mode: m }
}
