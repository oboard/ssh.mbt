# MoonSSH — MoonBit SSH 客户端库

使用 **MoonBit** 实现的 **SSHv2 客户端库**。协议层完全 MoonBit 原创；密码学原语通过 FFI 复用系统 OpenSSL `libcrypto`，不重复造轮子。

## 1. 项目状态

**当前版本：v0.1（协议骨架）**

| 能力 | 状态 |
|------|------|
| TCP 传输层 | ✅ 基于 `moonbitlang/async/socket` |
| 客户端/服务端 Banner 交换 | ✅ 落地 |
| 包二进制编解码（packet） | ✅ `src/packet.mbt`（length / padding / payload / MAC） |
| KEXINIT 帧与算法协商 | ✅ `src/kex.mbt` |
| KEX 状态机（X25519 / nistp256 ECDH） | ✅ 状态机写完；驱动循环（transport 接线）仍为 stub |
| 密码认证 | ⚠️ `auth.mbt` 构建请求；传输层接线为 stub |
| 公钥认证 | ⚠️ 同上 |
| `exec` / `shell` 通道 | ⚠️ `channel.mbt` 框架在；完整 pump 仍为 stub |
| `known_hosts` 解析 | ✅ 基础解析 |
| SFTP | ⚠️ 仅类型签名（v0.2） |
| Windows 编译 | ✅ 链接桩已就位（运行时仍需非 Windows 主机完成真实 KEX） |

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
├── src/                         ★ 核心库
│   ├── moon.pkg                 子包：PaiGack/ssh_client/src
│   ├── ssh_client.mbt           顶层 API（ConnectOptions / Client）
│   ├── packet.mbt               包序列化（length/padding/payload/MAC）
│   ├── kex.mbt                  KEXINIT 状态机
│   ├── auth.mbt                 用户认证
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

```text
moon run cmd/main --target native -- <user>@<host> [--port 22] [--exec "ls -l"] [--password PWD]
```

示例：

```bash
# 交互式（用 SSH agent 或预置公钥的服务器）
moon run cmd/main --target native -- alice@example.com --exec "uname -a"

# 显式密码
moon run cmd/main --target native -- bob@192.168.1.10 --port 2222 --password hunter2 --exec "uptime"
```

### 4.4 作为库使用

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

| 版本 | 内容 |
|------|------|
| **v0.1**（当前） | 协议骨架：packet / kex 状态机 / auth 框架 / channel 框架 / crypto FFI 全套 |
| **v0.2** | KEX 驱动循环接通真实 transport；密码/公钥认证全链路；`exec` 端到端；集成测试（`openssh-server` 容器） |
| **v0.3** | SFTP 协议层（基于现有 `sftp.mbt` 类型签名落地） |
| **v1.0** | 文档补全 + CI 矩阵（Linux/macOS/Windows）+ 发布到 mooncakes.io |

## 7. 跨平台注意

| 平台 | 编译 | 运行 |
|------|------|------|
| Linux glibc | ✅ | ✅ |
| macOS | ✅ | ✅ |
| Windows MinGW | ✅ | ✅ |

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
