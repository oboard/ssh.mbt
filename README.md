# MoonSSH — MoonBit SSH 客户端库

使用 **MoonBit** 实现的 **SSHv2 客户端库**

- 协议层完全 MoonBit 原创
- 密码学原语通过 FFI 复用系统 OpenSSL `libcrypto`，不重复造轮子
- TCP 传输层使用自带的 Winsock/POSIX socket FFI（不依赖 MSVC/异步运行时）

## 1. 项目状态

**当前版本：v0.1.2**

| 能力 | 状态 | 说明 |
|------|------|------|
| TCP 传输层 | ✅ | `src/socket/socket.mbt` + `socket.c`（自带 socket FFI，支持 POSIX 与 Winsock2） |
| Banner 交换 | ✅ | `Client::connect()` |
| 包二进制编解码 | ✅ | `src/packet.mbt`：length / padding / payload / MAC（EtM 流加密模式） |
| KEXINIT 协商 | ✅ | `src/kex.mbt`：`ecdh-sha2-nistp256` / `diffie-hellman-group14-sha256` / `diffie-hellman-group14-sha1` |
| 密钥派生 | ✅ | RFC 4253 §7.2 派生（`derive_keys()`），HMAC-SHA-1/256 扩展 |
| 主机密钥验证 | ✅ | `ssh-rsa` / `rsa-sha2-256` / `ssh-dss` / `ecdsa-sha2-nistp256/384/521` / `ssh-ed25519` |
| 密码认证 | ✅ | `Client::auth_password()` 完整流程 |
| 公钥认证 | ✅ | `Client::auth_publickey()`（two-step 查询 + 签名）；私钥支持 RSA / Ed25519 / DSA / ECDSA；公钥文件必须是 OpenSSH 单行格式 |
| keyboard-interactive 认证 | ✅ | `Client::auth_keyboard_interactive()` |
| 自动回退认证 | ✅ | `Client::auth_auto()`：none → publickey → keyboard-interactive → password |
| `exec` 命令执行 | ✅ | `Client::exec()` 返回 `(stdout, stderr)` |
| `shell` 通道 | ✅ | `Client::shell()`（不管理交互式 I/O，仅打开 shell 通道） |
| `known_hosts` 解析 | ✅ | 基础解析 + 通配符；HMAC-SHA1 哈希形式（`\|1\|…`）待支持 |
| 端口转发 / X11 | ❌ | 未实现 |
| SFTP | ❌ | 未实现（无 `src/sftp.mbt`） |

## 2. 架构

```
┌─────────────────────────────────────────────────────────┐
│  cmd/{password,key-ed25519,key-rsa,key-ecdsa}/          │
│                       ── CLI 入口（按认证方式分命令）     │
└────────────────────────┬────────────────────────────────┘
                         │  @src.Client
┌────────────────────────▼────────────────────────────────┐
│  src/ssh_client.mbt       ── 顶层 API                   │
│   • ConnectOptions        ── 连接选项（含 verifier）     │
│   • Client::connect       ── Banner 交换                │
│   • Client::kex           ── 密钥协商                    │
│   • Client::auth_password ── 密码认证                    │
│   • Client::auth_publickey── 公钥认证（two-step）        │
│   • Client::auth_keyboard_interactive ── kbd-int 认证   │
│   • Client::auth_auto     ── 自动回退认证                │
│   • Client::open_session  ── 打开 session 通道           │
│   • Client::exec          ── 命令执行（stdout,stderr）   │
│   • Client::shell         ── shell 通道                 │
│   • Client::close         ── 清理                       │
└────────────────────────┬────────────────────────────────┘
                         │
   ┌─────────────────────┼─────────────────────┐
   │                     │                     │
┌──▼────────┐   ┌────────▼─────┐   ┌───────────▼──┐
│ packet.mbt│   │  kex.mbt     │   │  auth.mbt    │
│  • length │   │  • KexContext│   │  • AuthContext│
│  • padding│   │  • 状态机    │   │  • password  │
│  • MAC    │   │  • 算法协商  │   │  • publickey │
└─────┬─────┘   └──────┬──────┘   │  • kbd-int   │
      │                │          └──────┬───────┘
      │                │                 │
      │     ┌──────────▼──────────┐      │
      │     │  channel.mbt        │      │
      │     │  • session / exec   │      │
      │     │  • shell / pty-req  │      │
      │     │  • window adjust    │      │
      │     │  • stdout/stderr    │      │
      │     └──────────┬──────────┘      │
      │                │                 │
      │     ┌──────────▼──────────┐      │
      │     │  known_hosts.mbt    │      │
      │     │  • 通配符匹配       │      │
      │     │  • base64 编解码    │      │
      │     └──────────┬──────────┘      │
      │                │                 │
      │     ┌──────────▼──────────┐      │
      │     │  log.mbt            │      │
      │     │  • debug / hex_dump │      │
      │     └─────────────────────┘      │
      │                                  │
┌─────▼──────────────────────────────────▼───────────────┐
│  src/socket/*   ── TCP 传输层（自实现 socket FFI）     │
│   • socket.mbt  ── Tcp::connect_to_host / write / …   │
│   • socket.c    ── Winsock2 / POSIX socket 实现       │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│  src/crypto/*  ── 密码学原语（FFI 调 OpenSSL libcrypto）│
│  • digest / mac / cipher / pkey / kex / error          │
│  • openssl.c  ── dlopen libcrypto + EVP_* 包装         │
│  • openssl_loader.mbt / crypto_util.mbt                │
└────────────────────────┬────────────────────────────────┘
                         │  FFI
┌────────────────────────▼────────────────────────────────┐
│  libcrypto.so.3 / libcrypto.dylib / libcrypto-3-x64.dll │
└─────────────────────────────────────────────────────────┘
```

### 2.1 协议状态机

```
                connect()
                  │
                  ▼
              [INIT] ───────► send_banner / recv_banner
                  │
                  ▼
              [KEXINIT] ◄──► KexContext::drive
                  │              │ KEXDH_INIT / KEX_ECDH_INIT
                  │              ▼
                  │          [KEXDH_REPLY / KEX_ECDH_REPLY]
                  │              │
                  │              ▼
                  │          [NEWKEYS] ──► 启用新密钥
                  ▼
              [AUTH] ◄──► AuthContext
                  │         • none 探测
                  │         • password / publickey / kbd-int
                  ▼
              [CHANNEL] ◄──► Channel::open_session
                  │              │ exec / shell
                  │              ▼
                  │          [DATA + EXIT-STATUS]
                  ▼
              [CLOSE]
```

## 3. 项目结构

```
moonbit-ssh-client/
├── AGENTS.md                    项目开发规范
├── README.md
├── README.mbt.md                mooncakes.io 简介
├── LICENSE                      Apache-2.0
├── moon.mod                     模块清单（name: PaiGack/ssh_client, version: 0.1.1）
├── moon.pkg                     根包（仅导入子包）
├── ssh_client.mbt               根包占位（实际 API 在 src/ssh_client.mbt）
├── ssh_client_test.mbt          黑盒测试（占位注释）
├── ssh_client_wbtest.mbt        白盒测试（占位注释）
├── pkg.generated.mbti           根包生成接口
├── .cnb.yml                     CNB 开发环境配置（含 docker sshd 自启）
├── src/                         ★ 核心库
│   ├── moon.pkg                 子包：PaiGack/ssh_client/src
│   ├── pkg.generated.mbti       生成接口
│   ├── log.mbt                  调试输出（debug / hex_dump / 开关）
│   ├── ssh_client.mbt           顶层 API（ConnectOptions / Client）
│   ├── packet.mbt               包序列化（length/padding/payload/MAC）+ Reader/Writer
│   ├── kex.mbt                  KEXINIT 状态机、密钥派生
│   ├── auth.mbt                 用户认证（password / publickey / kbd-int / none）
│   ├── channel.mbt              通道（session/exec/shell/pty-req，状态机 + stdout/stderr）
│   ├── known_hosts.mbt          known_hosts 解析 + 通配符匹配
│   ├── socket/                  ★ TCP 传输层（自实现 FFI）
│   │   ├── moon.pkg
│   │   ├── pkg.generated.mbti
│   │   ├── socket.mbt           Tcp::connect_to_host / write / read_*
│   │   └── socket.c             Winsock2 / POSIX socket 实现 + TCP_NODELAY
│   └── crypto/                  ★ 密码学子包
│       ├── moon.pkg
│       ├── pkg.generated.mbti
│       ├── openssl.c            OpenSSL dlopen + EVP_* / BN_* 包装
│       ├── openssl_loader.mbt   动态加载 libcrypto
│       ├── crypto_util.mbt      RAND_bytes / ERR_*
│       ├── digest.mbt           SHA-1/256/384/512
│       ├── mac.mbt              HMAC-SHA-1 / HMAC-SHA-256
│       ├── cipher.mbt           AES-128-CTR
│       ├── pkey.mbt             RSA/Ed25519/DSA/ECDSA 签名/验证 + 加载 PEM/OpenSSH 私钥
│       ├── kex.mbt              DH Group14 + BigInt FFI（BN_*）
│       └── error.mbt            CryptoError
├── cmd/                         ★ CLI 入口（按认证方式分多个子命令）
│   ├── output/                  Hello MoonBit 演示
│   ├── password/                密码认证（auth_auto）
│   ├── key-ed25519/             Ed25519 公钥认证
│   ├── key-rsa/                 RSA 公钥认证
│   └── key-ecdsa/               ECDSA 公钥认证
├── docs/
│   ├── prd_000.md                       设计 PRD
│   ├── prd_001_ssh-key-types-support-plan.md   密钥类型扩展计划
│   └── crypto-replacement-plan.md       OpenSSL 替换为 MoonBit 原生实现的方案
└── scripts/
    └── ssh-server/              本地 docker sshd 脚本（每个认证方式独立）
        ├── .env                 密码（password="123456"）
        ├── .gitignore           忽略本地生成的密钥对
        ├── password.sh          密码认证 sshd（端口 1022→2222）
        ├── key-ed25519.sh       生成 ed25519 密钥 + 公钥认证 sshd（端口 2022→2222）
        ├── key-rsa.sh           生成 rsa 密钥 + 公钥认证 sshd（端口 3022→2222）
        └── key-ecdsa.sh         生成 ecdsa 密钥 + 公钥认证 sshd（端口 4022→2222）
```

## 4. 快速开始

### 4.1 前置依赖

| 依赖 | 版本 | 说明 |
|------|------|------|
| MoonBit toolchain | ≥ 0.19 | https://www.moonbitlang.com/ |
| OpenSSL `libcrypto` | 1.1.1+ 或 3.x | 系统库（Linux/macOS 自带；Windows 用 MinGW OpenSSL） |
| Docker（可选） | 任意 | 用于本地启动测试 sshd |
| OpenSSH 客户端（可选） | 任意 | 调试用 `ssh -i` 验证 sshd |

Windows 额外依赖 MinGW：

```bash
# add C:\msys64\ucrt64\bin to PATH
pacman -S mingw-w64-ucrt-x86_64-gcc
pacman -S mingw-w64-ucrt-x86_64-openssl
```

Linux
```bash
apt-get install -y gcc libssl-dev
```

### 4.2 启动测试 sshd

`scripts/ssh-server/` 下提供本地 docker sshd 启动脚本（每个脚本独立监听端口）：

| 脚本 | 用途 | 主机端口 |
|------|------|----------|
| `password.sh` | 启动 `lscr.io/linuxserver/openssh-server`（密码模式） | `1022` |
| `key-ed25519.sh` | 生成 ed25519 密钥并启动公钥认证 sshd | `2022` |
| `key-rsa.sh` | 生成 4096 位 RSA 密钥并启动公钥认证 sshd | `3022` |
| `key-ecdsa.sh` | 生成 ecdsa 密钥并启动公钥认证 sshd | `4022` |

> **注意：** 每次启动 `key-*.sh` 都会清空并重新生成同名密钥对（id_ed25519 / id_rsa / id_ecdsa）；生成位置在 `scripts/ssh-server/` 内，已被 `.gitignore` 排除。

例如启动密码模式 sshd：

```bash
bash scripts/ssh-server/password.sh
# 在另一个终端：ssh admin@127.0.0.1 -p 1022  # 密码 123456
```

### 4.3 构建与运行

仓库根没有统一 `run.sh`，每个 `cmd/*` 子包自带 `run.sh`，它们做：
1. `source ../scripts/ssh-server/.env` 注入 `password`
2. `export MOONBIT_CLI_ARGS="..."`
3. `moon clean && moon build . --target native`
4. 执行 `_build/native/debug/build/cmd/<name>/<name>.exe`

> 因为 `cmd` 包在 `moon build` 时链接了 FFI，`moon run` 不会拿到 stdout；因此 `run.sh` 用 `build` + 手动执行。

#### 4.3.1 密码认证

```bash
# 前置：bash scripts/ssh-server/password.sh
cd cmd/password
./run.sh
# 内部：
#   export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --exec 'uname -a' --password $MSSH_PASSWORD"
#   moon build . --target native
#   ../../_build/native/debug/build/cmd/password/password.exe
```

等价的手动调用：

```bash
export MOONBIT_CLI_ARGS="admin@127.0.0.1 --port 1022 --exec 'uname -a' --password 123456"
cd cmd/password
moon build . --target native
./_build/native/debug/build/cmd/password/password.exe
```

#### 4.3.2 公钥认证（Ed25519 / RSA / ECDSA）

```bash
# 前置：bash scripts/ssh-server/key-ed25519.sh  # 或 key-rsa.sh / key-ecdsa.sh
cd cmd/key-ed25519
./run.sh
# 内部使用：--key /workspace/scripts/ssh-server/id_ed25519
#          （路径是 docker 容器内的位置；如果你直接在本地运行，请改为宿主机路径）
```

> **路径注意：** `run.sh` 默认 `--key` 指向 docker 容器内路径 `/workspace/scripts/ssh-server/id_*`；如果 sshd 跑在本地而非 docker，请把路径改成宿主机上的实际位置。

## 5. CLI 参数

每个 `cmd/*/main.mbt` 通过 `MOONBIT_CLI_ARGS` 传入参数（支持单/双引号包裹空格）：

| 参数 | 别名 | 说明 | 默认 |
|------|------|------|------|
| `user@host` | — | 必填，用户名 + 主机（无 `@` 时默认用户 `root`） | — |
| `-p <port>` | `--port` | SSH 端口 | `22` |
| `-l <user>` | `--user` | 用户名（覆盖 `user@host` 中的 user） | `user@host` 中的 user |
| `-e <cmd>` | `--exec` | 远端要执行的命令 | `uname -a` |
| `--password <pwd>` | — | 密码（仅 `cmd/password`） | `""` |
| `-i <path>` | `--key` / `--identity` | 私钥路径（仅 `cmd/key-*`） | `~/.ssh/id_<alg>` |
| `-d` | `--debug` | 启用 MoonBit / C 层 debug 输出 | 关 |

也可以设置 `MOONBIT_SSH_DEBUG=1`（或 `true`）从环境变量开启 debug。

## 6. 作为库使用

`moon.mod` 中声明的模块名是 `PaiGack/ssh_client`，核心 API 落在子包 `PaiGack/ssh_client/src`：

```moonbit
import {
  "PaiGack/ssh_client/src",
}

async fn example() -> Unit raise {
  let opts = @src.ConnectOptions::new("example.com", 22, "alice")
  let client = @src.Client::connect(opts)
  defer client.close()

  client.kex()

  // 任意一种认证方式：
  client.auth_password("hunter2")
  // 或：client.auth_publickey("~/.ssh/id_rsa")
  // 或：client.auth_keyboard_interactive(prompt => password)
  // 或：client.auth_auto(password, key_path="~/.ssh/id_rsa")

  let ch = client.open_session()
  let (stdout, stderr) = client.exec(ch, "ls -l")
  println("stdout: \{stdout}")
  println("stderr: \{stderr}")
}
```

### 6.1 `ConnectOptions`

```moonbit
pub struct ConnectOptions {
  host : String
  port : Int
  user : String
  client_banner : String?                  // 默认 "SSH-2.0-MoonSSH_0.1.0"
  accept_host_key : (String, Bytes) -> Bool  // 验证器；默认放行
  timeout_ms : Int                          // 默认 30_000
}
```

构造与链式配置：

```moonbit
let opts = @src.ConnectOptions::new("example.com", 22, "alice")
  .with_host_key_verifier((alg, key) => {
    // 返回 true 接受；false 拒绝
    inspect(alg)
    inspect(key.length())
    true
  })
```

> **注：** `ConnectOptions` 当前只暴露 `with_host_key_verifier()`；自定义 banner / 超时等字段暂未提供 `with_*` setter。

### 6.2 `Client` 顶层 API

| 方法 | 说明 |
|------|------|
| `Client::connect(opts) -> Client raise SshError` | TCP 连接 + banner 交换 |
| `Client::kex() -> Unit raise SshError` | 完整 KEX（KEXINIT → DH/ECDH → NEWKEYS → 安装加密） |
| `Client::auth_password(pwd) -> Unit raise SshError` | 密码认证 |
| `Client::auth_publickey(key_path) -> Unit raise SshError` | 公钥认证（two-step），自动适配 `ssh-rsa` / `rsa-sha2-256` / `ssh-ed25519` / `ecdsa-sha2-nistp256/384/521` / `ssh-dss` |
| `Client::auth_keyboard_interactive(answer_fn) -> Unit raise SshError` | keyboard-interactive 认证 |
| `Client::auth_auto(pwd, key_path?) -> Unit raise SshError` | none → publickey → kbd-int → password 自动回退 |
| `Client::open_session() -> Channel` | 创建本地 channel（id 自增） |
| `Client::exec(ch, cmd) -> (String, String) raise SshError` | 执行命令，返回 `(stdout, stderr)` |
| `Client::shell(ch) -> Unit raise SshError` | 打开 shell 通道（不管理交互式 I/O） |
| `Client::close() -> Unit` | 关闭 TCP 连接 |

### 6.3 `Channel`

```moonbit
pub struct Channel {
  id : Int         // 本地 channel id
  peer_id : Int    // 服务端分配的 channel id
  state : ChannelState  // Closed / Opening / Open / ExecPending / EofReceived / Closing / Done
  // ...
}

pub fn Channel::id(self) -> Int
pub fn Channel::peer_id(self) -> Int
pub fn Channel::state(self) -> ChannelState
pub fn Channel::is_open(self) -> Bool
pub fn Channel::exit_status(self) -> Int?
```

通道底层消息：OPEN / OPEN_CONFIRMATION / OPEN_FAILURE / WINDOW_ADJUST / DATA / EXTENDED_DATA / EOF / CLOSE / REQUEST（含 `exit-status` / `exit-signal` / `exec` / `shell` / `pty-req`）。

### 6.4 `known_hosts`

`src/known_hosts.mbt` 提供 OpenSSH `known_hosts` 文件的解析与匹配：

```moonbit
pub struct KnownHost {
  patterns : Array[String]
  key_alg : String
  key : Bytes
}

pub fn KnownHost::matches(self, host : String, port : Int) -> Bool
pub fn KnownHost::alg(self) -> String
pub fn KnownHost::key_bytes(self) -> Bytes
```

支持通配符（`*` / `?`）；`host:port` 形式自动展开为 `[host]:port`（当 port ≠ 22）。
**尚未支持** HMAC-SHA1 哈希形式（`|1|…`）——遇到会直接返回不匹配。

## 7. 开发流程

### 7.1 修改后必跑

```bash
moon fmt                          # 格式化
moon info                         # 更新 .mbti 接口
moon build --target native        # 编译
moon test --target native         # 测试
```

### 7.2 覆盖率

```bash
moon coverage analyze > uncovered.log
# 目标：uncovered.log 中 packet / kex / auth 关键路径为空
```

### 7.3 派生代码

`src/socket/`（`socket.mbt` / `socket.c`）派生于 `moonbitlang/async/tls`（Apache 2.0）。任何修改请保留：

- 原 Apache 2.0 版权头
- 命名空间调整记录（`moonbitlang/async/socket` → `src/socket`）

## 8. 路线图

| 版本 | 内容 | 状态 |
|------|------|------|
| **v0.1**（当前 v0.1.2） | 协议骨架：packet / kex 状态机 / auth（密码 + 公钥 + kbd-int + auto）/ channel / crypto FFI / 自带 socket FFI | ✅ 已发布 |
| **v0.2** | shell 交互式 I/O（stdin 转发）；pty-req 对接 Client 高层 API；端口转发；SFTP 协议层 | 📋 待开发 |
| **v1.0** | 文档补全 + CI 矩阵（Linux/macOS/Windows）+ 发布到 mooncakes.io | 📋 待开发 |

**v0.1 待完成项：**
- [ ] shell 交互（stdin/stdout 转发）
- [ ] `Client::exec_pty()` 高层封装（`build_channel_request_pty` 已就绪）
- [ ] `known_hosts` 哈希形式（`|1|…`）支持
- [ ] 与真实 sshd 的自动化集成测试（CI 拉起 docker sshd）

## 9. 跨平台注意

| 平台 | 编译 | 运行 | 说明 |
|------|------|------|------|
| Linux glibc | ✅ | ✅ | 完全支持 |
| macOS | ✅ | ✅ | 完全支持 |
| Windows MinGW (Winsock2) | ✅ | ✅ | 完全支持 |

## 10. 引用

- [RFC 4251](https://tools.ietf.org/html/rfc4251) — SSH Protocol Architecture
- [RFC 4252](https://tools.ietf.org/html/rfc4252) — SSH Authentication Protocol
- [RFC 4253](https://tools.ietf.org/html/rfc4253) — SSH Transport Layer Protocol
- [RFC 4254](https://tools.ietf.org/html/rfc4254) — SSH Connection Protocol
- [RFC 4344](https://tools.ietf.org/html/rfc4344) — SSH Transport Layer Encryption Modes
- [RFC 5656](https://tools.ietf.org/html/rfc5656) — SSH ECC Algorithm Integration
- [RFC 6668](https://tools.ietf.org/html/rfc6668) — SHA-2 Data Integrity Verification for SSH
- [RFC 8332](https://tools.ietf.org/html/rfc8332) — Use of RSA Keys with SHA-256/512
- [OpenSSL EVP](https://docs.openssl.org/3.0/manuals/) — 密码学 API
- [moonbitlang/async](https://mooncakes.io/docs/moonbitlang/async) — 派生来源（Apache 2.0）

## 11. License

Apache-2.0。详见 [LICENSE](LICENSE)。
