// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "PaiGack/ssh_client"

version = "0.3.0"

readme = "README.md"

repository = "https://github.com/PaiGack/moonbitlang-OSC2026.git"

license = "Apache-2.0"

keywords = [
  "ssh",
  "sshv2",
  "ssh-client",
  "sftp",
  "port-forwarding",
  "socks5",
  "publickey-auth",
  "password-auth",
  "ffi",
]

description = "SSHv2 client library for MoonBit with password and publickey authentication, SFTP v3, and local/remote/SOCKS5 port forwarding. / 使用 MoonBit 实现的 SSHv2 客户端库，支持密码/公钥认证、SFTP v3 文件传输及本地/远程/SOCKS5 端口转发"

options(
  "include": [ "README.md", "README.mbt.md", "src", "cmd", "scripts" ],
)
