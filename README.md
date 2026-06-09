# MoonSSH — MoonBit SSH 客户端库

使用 **MoonBit** 实现的 **SSHv2 客户端库**。协议层完全 MoonBit 原创；密码学原语通过 FFI 复用系统 OpenSSL `libcrypto`，不重复造轮子。

## 1. 项目状态

**当前版本：v0.1（协议骨架）**

| 能力 | 状态 | 说明 |
|------|------|------|
| TCP 传输层 | ✅ | 基于 `moonbitlang/async/socket` |
| Banner 交换 | ✅ | `Client::connect()` 完成 |
| 包二进制编解码 | ✅ | `src/packet.mbt`：length / padding / payload / MAC，支持 EtM 和 AEAD 模式 |
| KEXINIT 协商 | ✅ | `src/kex.mbt`：curve25519-sha256 / ecdh-sha2-nistp256 / diffie-hellman-group14 |
| 密钥派生 | ✅ | HKDF-SHA256/SHA512，`derive_keys()` 实现 |
| 主机密钥验证 | ✅ | 支持 ssh-ed25519 / rsa-sha2-* / ecdsa-sha2-nistp256 |
| 密码认证 | ✅ | `Client::auth_password()` 完整流程 |
| 公钥认证 | ⚠️ | `auth.mbt` 实现中，`Client::auth_publickey()` 待接线 |
| `exec` 命令执行 | ✅ | `Client::exec()` 完整流程：open_session → exec → 读取 stdout → exit-status |
| `shell` / pty | ❌ | 未实现 |
| 端口转发 / X11 | ❌ | 未实现 |
| `known_hosts` 解析 | ✅ | 基础解析；HMAC-SHA1 哈希形式待支持 |
| SFTP | ❌ | `src/sftp.mbt` 为 v0.2 stub |
| Windows KEX | ⚠️ | 链接桩就位，运行时需非 Windows 主机 |

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
│   • Client::auth_password ── 认证                       │
│   • Client::exec          ── 命令执行                   │
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
└─────┬─────┘   └──────┬──────┘   └──────┬───────┘
      │                │                 │
      │     ┌──────────▼──────────┐      │
      │     │  channel.mbt        │      │
      │     │  • session / exec   │      │
      │     │  • window adjust    │      │
      │     └──────────┬──────────┘      │
      │                │                 │
      │     ┌──────────▼──────────┐      │
      │     │  sftp.mbt (stub)    │      │
      │     └─────────────────────┘      │
      │                                  │
┌─────▼──────────────────────────────────▼───────────────┐
│  src/crypto/*  ── 密码学原语（FFI 调 OpenSSL libcrypto）│
│  • digest / mac / cipher / pkey / kex / bignum / error  │
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
                  │              │ KEXDH_INIT
                  │              ▼
                  │          [KEXDH_REPLY]
                  │              │
                  │              ▼
                  │          [NEWKEYS] ──► 启用新密钥
                  ▼
              [AUTH] ◄──► AuthContext::build_password / publickey
                  │
                  ▼
              [CHANNEL] ◄──► Channel::open_session
                  │              │ exec
                  │              ▼
                  │          [DATA + EXIT-STATUS]
                  ▼
              [CLOSE]
```

## 3. 项目结构

```
code/
├── AGENTS.md                    项目开发规范
├── CLAUDE.md                    Claude Code 指引
├── README.md
├── README.mbt.md                mooncakes.io 简介
├── LICENSE                      Apache-2.0
├── moon.mod                     模块清单（name: PaiGack/ssh_client）
├── moon.pkg                     根包（仅导入子包）
├── ssh_client.mbt
├── ssh_client_test.mbt          黑盒测试
├── ssh_client_wbtest.mbt        白盒测试
├── tests/                       测试脚本（调试 / 协议验证）
│   ├── test_ssh.sh             SSH 协议完整握手测试
│   ├── test_kexinit.sh         KEXINIT 协商测试
│   ├── test_ecdh_reply.sh      ECDH 密钥交换测试
│   ├── debug_kex.sh            KEX 调试脚本
│   └── *.sh                    其他调试与集成测试
├── src/                         ★ 核心库
│   ├── moon.pkg                 子包：PaiGack/ssh_client/src
│   ├── ssh_client.mbt           顶层 API（ConnectOptions / Client）
│   ├── packet.mbt               包序列化（length/padding/payload/MAC）
│   ├── kex.mbt                  KEXINIT 状态机、密钥派生
│   ├── auth.mbt                 用户认证（password / publickey）
│   ├── channel.mbt              通道（session/exec/shell）
│   ├── known_hosts.mbt          known_hosts 解析
│   ├── sftp.mbt                 SFTP（v0.2 stub）
│   └── crypto/                  密码学子包
│       ├── NOTICE               Apache 2.0 派生声明
│       ├── moon.pkg
│       ├── openssl.c            OpenSSL dlopen + EVP 包装
│       ├── openssl_loader.mbt
│       ├── crypto_util.mbt      RAND_bytes / ERR_*
│       ├── digest.mbt           SHA-1/256/384/512
│       ├── mac.mbt              HMAC-SHA*
│       ├── cipher.mbt           AES-CTR / AES-GCM / ChaCha20-Poly1305
│       ├── pkey.mbt             Ed25519 / RSA / ECDSA / ECDH
│       ├── kex.mbt              X25519 / nistp256 ECDH / DH group14
│       └── error.mbt            CryptoError
├── cmd/main/                    ★ CLI 演示
│   ├── moon.pkg                 main 包
│   └── main.mbt                 解析参数 → connect → auth → exec
├── docs/
└── scripts/
    ├── build.bat                Windows 一键构建
    ├── build.bat                Windows 一键运行
    └── test.bat                 Windows 一键测试
```

## 4. 快速开始

### 4.1 前置依赖

| 依赖 | 版本 | 说明 |
|------|------|------|
| MoonBit toolchain | ≥ 0.19 | https://www.moonbitlang.com/ |
| OpenSSL `libcrypto` | 1.1.1+ 或 3.x | 系统库（Linux/macOS 自带；Windows 用 minGW OpenSSL  |

Windows 依赖 MinGW

```bash
# add C:\msys64\ucrt64\bin to path

pacman -S mingw-w64-ucrt-x86_64-gcc
pacman -S mingw-w64-ucrt-x86_64-openssh
```

### 4.2 构建与运行

```bash
moon run cmd/main --target native -- user@host --port 22 --exec "uname -a"
```

### 4.3 CLI 用法

通过 `MOONBIT_CLI_ARGS` 环境变量传递参数：

```bash
export MOONBIT_CLI_ARGS="<user>@<host> [--port 22] [--exec 'CMD'] [--password PWD]"

moon run cmd/main --target native
```

示例：

```bash
export MOONBIT_CLI_ARGS="xxx@xxx --port 22 --exec 'uname -a'"

moon run cmd/main --target native
```

直接传参（需 `--` 分隔）：

```bash
moon run cmd/main --target native -- xxx@xxx --port 22 --exec 'uname -a'
```

### 4.4 调试与测试脚本

`tests/` 目录下包含用于调试和协议验证的 shell 脚本：

| 脚本 | 用途 |
|------|------|
| `test_ssh.sh` | SSH 协议完整握手流程测试 |
| `test_kexinit.sh` | KEXINIT 协商过程测试 |
| `test_ecdh_reply.sh` | ECDH 密钥交换响应测试 |
| `debug_kex.sh` | KEX 算法协商调试 |
| `test_normal.sh` | 标准 SSH 连接测试 |
| `test_combined*.sh` | 组合测试 |
| `test_ecd.sh` | ECDH 相关测试 |

运行示例：

```bash
cd tests
chmod +x test_ssh.sh
timeout 10 ./test_ssh.sh
```

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
  client.auth_password("hunter2")

  let ch = client.open_session()
  let output = client.exec(ch, "ls -l")
  println(output)
}
```

#### `ConnectOptions`

```moonbit
pub struct ConnectOptions {
  host : String
  port : Int
  user : String
  client_banner : String?                  // 默认 "SSH-2.0-MoonSSH_0.1.0"
  accept_host_key : (String, Bytes) -> Bool  // 验证器；v0.1 默认放行
  timeout_ms : Int                          // 默认 30_000
}
```

构造与链式配置：

```moonbit
let opts = @src.ConnectOptions::new("example.com", 22, "alice")
  .with_banner("SSH-2.0-MyClient_1.0")
  .with_host_key_verifier((alg, key) => {
    // 返回 true 接受；false 拒绝
    inspect(alg)
    inspect(key.length())
    true
  })
```

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

`src/crypto/` 下的 `openssl.c`、`openssl_loader.mbt`、`crypto_util.mbt` 派生自 `moonbitlang/async`（Apache 2.0）。详见 [src/crypto/NOTICE](src/crypto/NOTICE)。任何修改请保留：

- 原 Apache 2.0 版权头
- `NOTICE` 中列出的派生关系
- 命名空间 `moonbitlang/async/tls` → `crypto` 的改动记录

## 6. 路线图

| 版本 | 内容 | 状态 |
|------|------|------|
| **v0.1**（当前） | 协议骨架：packet / kex 状态机 / auth 框架 / channel 框架 / crypto FFI 全套 | 🚧 实现中 |
| **v0.2** | KEX 驱动循环接通真实 transport；公钥认证完整链路；`exec` 端到端验证；集成测试（`openssh-server` 容器） | 📋 待开发 |
| **v0.3** | SFTP 协议层（基于现有 `sftp.mbt` 类型签名落地） | 📋 待开发 |
| **v1.0** | 文档补全 + CI 矩阵（Linux/macOS/Windows）+ 发布到 mooncakes.io | 📋 待开发 |

**v0.1 待完成项：**
- [ ] 公钥认证（`auth_publickey()`）接线
- [ ] 主机密钥验证（`known_hosts` 哈希形式支持）
- [ ] 与真实 sshd 完整集成测试

## 7. 跨平台注意

| 平台 | 编译 | 运行 | 说明 |
|------|------|------|------|
| Linux glibc | ✅ | ✅ | 完全支持 |
| macOS | ✅ | ✅ | 完全支持 |
| Windows MinGW | ✅ | ⚠️ | 编译通过；KEX/Crypto 操作需非 Windows 主机 |

## 8. 引用

- [RFC 4251](https://tools.ietf.org/html/rfc4251) — SSH Protocol Architecture
- [RFC 4252](https://tools.ietf.org/html/rfc4252) — SSH Authentication Protocol
- [RFC 4253](https://tools.ietf.org/html/rfc4253) — SSH Transport Layer Protocol
- [RFC 4254](https://tools.ietf.org/html/rfc4254) — SSH Connection Protocol
- [RFC 4344](https://tools.ietf.org/html/rfc4344) — SSH Transport Layer Encryption Modes
- [RFC 5656](https://tools.ietf.org/html/rfc5656) — SSH ECC Algorithm Integration
- [RFC 6668](https://tools.ietf.org/html/rfc6668) — SHA-2 Data Integrity Verification for SSH
- [moonbitlang/async](https://mooncakes.io/docs/moonbitlang/async) — 异步运行时与 socket FFI
- [OpenSSL EVP](https://docs.openssl.org/3.0/manuals/) — 密码学 API

## 9. License

Apache-2.0。详见 [LICENSE](LICENSE)。
