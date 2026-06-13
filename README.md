# MoonSSH — MoonBit SSH 客户端库

使用 **MoonBit** 实现的 **SSHv2 客户端库**。协议层完全 MoonBit 原创；密码学原语通过 FFI 复用系统 OpenSSL `libcrypto`，不重复造轮子；TCP 传输层使用自带的 Winsock/POSIX socket FFI（不依赖 MSVC/异步运行时）。

## 1. 项目状态

**当前版本：v0.1.1**

| 能力 | 状态 | 说明 |
|------|------|------|
| TCP 传输层 | ✅ | `src/socket/socket.mbt` + `socket.c`（自带 socket FFI，支持 POSIX 与 Winsock2） |
| Banner 交换 | ✅ | `Client::connect()` 完成 |
| 包二进制编解码 | ✅ | `src/packet.mbt`：length / padding / payload / MAC（EtM 流加密模式） |
| KEXINIT 协商 | ✅ | `src/kex.mbt`：`ecdh-sha2-nistp256` / `diffie-hellman-group14-sha256` / `diffie-hellman-group14-sha1` |
| 密钥派生 | ✅ | RFC 4253 §7.2 派生（`derive_keys()`），HMAC-SHA-1/256 扩展 |
| 主机密钥验证 | ✅ | `rsa-sha2-256` / `ssh-rsa` |
| 密码认证 | ✅ | `Client::auth_password()` 完整流程 |
| 公钥认证 | ✅ | `Client::auth_publickey()`（two-step 查询 + 签名），支持 `rsa-sha2-256` |
| keyboard-interactive 认证 | ✅ | `Client::auth_keyboard_interactive()` |
| 自动回退认证 | ✅ | `Client::auth_auto()`：none → publickey → keyboard-interactive → password |
| `exec` 命令执行 | ✅ | `Client::exec()` 返回 `(stdout, stderr)` |
| `shell` 通道 | ✅ | `Client::shell()`（不管理交互式 I/O，仅打开 shell 通道） |
| pty / 端口转发 / X11 | ❌ | 未实现 |
| `known_hosts` 解析 | ✅ | 基础解析 + 通配符；HMAC-SHA1 哈希形式（`\|1\|…`）待支持 |
| SFTP | ❌ | 未实现（无 `src/sftp.mbt`） |
| Windows KEX | ⚠️ | socket/crypto 链接桩就位；当前主线目标是非 Windows 主机 |

## 2. 架构

```
┌─────────────────────────────────────────────────────────┐
│  cmd/main/main.mbt        ── CLI 入口（参数解析 + 演示）│
└────────────────────────┬────────────────────────────────┘
                         │  @src.Client
┌────────────────────────▼────────────────────────────────┐
│  src/ssh_client.mbt       ── 顶层 API                   │
│   • ConnectOptions        ── 连接选项（含 verifier）    │
│   • Client::connect       ── Banner 交换                │
│   • Client::kex           ── 密钥协商                   │
│   • Client::auth_password ── 密码认证                   │
│   • Client::auth_publickey── 公钥认证（two-step）       │
│   • Client::auth_keyboard_interactive ── kbd-int 认证  │
│   • Client::auth_auto     ── 自动回退认证               │
│   • Client::open_session  ── 打开 session 通道         │
│   • Client::exec          ── 命令执行（stdout,stderr） │
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
      │     │  • window adjust    │      │
      │     │  • stdout/stderr    │      │
      │     └──────────┬──────────┘      │
      │                │                 │
      │     ┌──────────▼──────────┐      │
      │     │  known_hosts.mbt    │      │
      │     │  • 通配符匹配       │      │
      │     │  • base64 编解码    │      │
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
├── run.sh                       一键运行脚本（docker sshd + moon build + run）
├── .env                         运行脚本的环境变量
├── src/                         ★ 核心库
│   ├── moon.pkg                 子包：PaiGack/ssh_client/src
│   ├── pkg.generated.mbti       生成接口
│   ├── log.mbt                  调试输出（@debug 封装）
│   ├── ssh_client.mbt           顶层 API（ConnectOptions / Client）
│   ├── packet.mbt               包序列化（length/padding/payload/MAC）+ Reader/Writer
│   ├── kex.mbt                  KEXINIT 状态机、密钥派生
│   ├── auth.mbt                 用户认证（password / publickey / kbd-int / none）
│   ├── channel.mbt              通道（session/exec/shell，状态机 + stdout/stderr）
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
│       ├── pkey.mbt             RSA 签名/验证 / 加载 PEM 私钥
│       ├── kex.mbt              DH Group14 + BigInt FFI（BN_*）
│       └── error.mbt            CryptoError
├── cmd/main/                    ★ CLI 演示
│   ├── moon.pkg                 main 包
│   └── main.mbt                 解析参数 → connect → kex → auth_auto → exec
├── docs/
│   ├── prd_000.md               设计 PRD
│   └── crypto-replacement-plan.md
└── scripts/
    └── ssh-server/              本地 docker sshd（密码 / 公钥两种模式）
        ├── password.sh          启动密码认证 sshd（1022:2222）
        ├── publickey.sh         生成本地 ed25519 密钥并启动公钥 sshd（2022:2222）
        ├── id_ed25519(.pub)
        └── .env
```

## 4. 快速开始

### 4.1 前置依赖

| 依赖 | 版本 | 说明 |
|------|------|------|
| MoonBit toolchain | ≥ 0.19 | https://www.moonbitlang.com/ |
| OpenSSL `libcrypto` | 1.1.1+ 或 3.x | 系统库（Linux/macOS 自带；Windows 用 MinGW OpenSSL） |
| Docker（可选） | 任意 | 用于本地启动测试 sshd |

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

### 4.2 构建与运行

```bash
# 一次性：启动 docker sshd（密码模式）
bash scripts/ssh-server/password.sh

# 配置 .env（参见仓库根 .env）
# MSSH_HOST="127.0.0.1"
# MSSH_PORT="1022"
# MSSH_USERNAME="admin"
# MSSH_PASSWORD="123456"

# 一键运行
bash run.sh
```

`run.sh` 内部做：
1. `source .env` 注入 `MSSH_*`
2. `export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --exec 'uname -a' --password $MSSH_PASSWORD"`
3. `moon build cmd/main --target native`
4. 执行 `./_build/native/debug/build/cmd/main/main.exe`

等价的手动调用：

```bash
export MOONBIT_CLI_ARGS="admin@127.0.0.1 --port 1022 --exec 'uname -a' --password 123456"
moon run cmd/main --target native
```

或使用 `--` 分隔直接传参：

```bash
moon run cmd/main --target native -- admin@127.0.0.1 --port 1022 --exec 'uname -a' --password 123456
```

### 4.3 CLI 参数

`cmd/main/main.mbt` 支持以下参数（全部通过 `MOONBIT_CLI_ARGS` 传入，支持单/双引号包裹空格）：

| 参数 | 别名 | 说明 | 默认 |
|------|------|------|------|
| `user@host` | — | 必填，用户名 + 主机（无 `@` 时默认用户 `root`） | — |
| `-p <port>` | `--port` | SSH 端口 | `22` |
| `-l <user>` | `--user` | 用户名（覆盖 `user@host` 中的 user） | `user@host` 中的 user |
| `-e <cmd>` | `--exec` | 远端要执行的命令 | `uname -a` |
| `--password <pwd>` | — | 密码（`auth_auto` 时使用） | `""` |
| `-d` | `--debug` | 启用 C 层 debug（`moonbit_set_moonssh_debug`） | 关 |

典型用法：

```bash
export MOONBIT_CLI_ARGS="alice@example.com --port 22 --exec 'ls -l' --password hunter2 --debug"
moon run cmd/main --target native
```

### 4.4 调试脚本

`scripts/ssh-server/` 下提供本地 docker sshd 启动脚本：

| 脚本 | 用途 |
|------|------|
| `password.sh` | 启动 `lscr.io/linuxserver/openssh-server`（密码模式，端口 1022→2222） |
| `publickey.sh` | 生成 ed25519 密钥并启动公钥认证 sshd（端口 2022→2222） |

`run.sh` 是把 `.env` 注入、`moon build`、执行整合在一起的入口脚本。

### 4.5 作为库使用

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

#### `ConnectOptions`

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

## 5. 开发流程

### 5.1 修改后必跑

```bash
moon fmt                          # 格式化
moon info                         # 更新 .mbti 接口
moon build --target native        # 编译
moon test --target native         # 测试
```

### 5.2 覆盖率

```bash
moon coverage analyze > uncovered.log
# 目标：uncovered.log 中 packet / kex / auth 关键路径为空
```

### 5.3 派生代码

`src/socket/`（`socket.mbt` / `socket.c`）派生于 `moonbitlang/async/tls`（Apache 2.0）。任何修改请保留：

- 原 Apache 2.0 版权头
- 命名空间调整记录（`moonbitlang/async/socket` → `src/socket`）

## 6. 路线图

| 版本 | 内容 | 状态 |
|------|------|------|
| **v0.1**（当前） | 协议骨架：packet / kex 状态机 / auth（密码 + 公钥 + kbd-int + auto）/ channel / crypto FFI / 自带 socket FFI | ✅ 已发布 |
| **v0.2** | shell 交互式 I/O（stdin 转发）；pty；端口转发；SFTP 协议层 | 📋 待开发 |
| **v1.0** | 文档补全 + CI 矩阵（Linux/macOS/Windows）+ 发布到 mooncakes.io | 📋 待开发 |

**v0.1 待完成项：**
- [ ] shell 交互（stdin/stdout 转发）
- [ ] pty-req
- [ ] known_hosts 哈希形式（`|1|…`）支持
- [ ] 与真实 sshd 的自动化集成测试（CI 拉起 docker sshd）

## 7. 跨平台注意

| 平台 | 编译 | 运行 | 说明 |
|------|------|------|------|
| Linux glibc | ✅ | ✅ | 完全支持 |
| macOS | ✅ | ✅ | 完全支持 |
| Windows MinGW (Winsock2) | ✅ | ⚠️ | 编译通过；`src/socket` 自带 Winsock 初始化；KEX/Crypto 操作需非 Windows 主机 |

## 8. 引用

- [RFC 4251](https://tools.ietf.org/html/rfc4251) — SSH Protocol Architecture
- [RFC 4252](https://tools.ietf.org/html/rfc4252) — SSH Authentication Protocol
- [RFC 4253](https://tools.ietf.org/html/rfc4253) — SSH Transport Layer Protocol
- [RFC 4254](https://tools.ietf.org/html/rfc4254) — SSH Connection Protocol
- [RFC 4344](https://tools.ietf.org/html/rfc4344) — SSH Transport Layer Encryption Modes
- [RFC 5656](https://tools.ietf.org/html/rfc5656) — SSH ECC Algorithm Integration
- [RFC 6668](https://tools.ietf.org/html/rfc6668) — SHA-2 Data Integrity Verification for SSH
- [OpenSSL EVP](https://docs.openssl.org/3.0/manuals/) — 密码学 API
- [moonbitlang/async](https://mooncakes.io/docs/moonbitlang/async) — 派生来源（Apache 2.0）

## 9. License

Apache-2.0。详见 [LICENSE](LICENSE)。