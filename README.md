# MoonSSH — MoonBit SSH 客户端库

使用 **MoonBit** 实现的 **SSHv2 客户端库**

- 协议层完全 MoonBit 原创
- 密码学原语通过 FFI 复用系统 OpenSSL `libcrypto`，不重复造轮子
- TCP 传输层使用 socket FFI：
  - **Windows**：Winsock socket FFI（不依赖 MSVC）
  - **POSIX（Linux / macOS）**：POSIX socket FFI

## 1. 项目状态

| 能力 | 状态 | 说明 |
|------|------|------|
| TCP 传输层 | ✅ | `src/socket/socket.mbt` + `socket.c`（自带 socket FFI，支持 POSIX 与 Winsock2） |
| Banner 交换 | ✅ | `Client::connect()` |
| 包二进制编解码 | ✅ | `src/packet.mbt`：length / padding / payload / MAC（EtM 流加密模式） |
| KEXINIT 协商 | ✅ | `src/kex.mbt`：`ecdh-sha2-nistp256` / `diffie-hellman-group14-sha256` / `diffie-hellman-group14-sha1` |
| 密钥派生 | ✅ | RFC 4253 §7.2 派生（`derive_keys()`），HMAC-SHA-1/256 扩展 |
| 主机密钥验证 | ✅ | `ssh-rsa` / `rsa-sha2-256` / `rsa-sha2-512` / `ssh-dss` / `ecdsa-sha2-nistp256/384/521` / `ssh-ed25519` |
| 密码认证 | ✅ | `Client::auth_password()` 完整流程 |
| 公钥认证 | ✅ | `Client::auth_publickey()`（two-step 查询 + 签名）；私钥支持 RSA / Ed25519 / DSA / ECDSA；公钥文件必须是 OpenSSH 单行格式 |
| keyboard-interactive 认证 | ✅ | `Client::auth_keyboard_interactive()` |
| 自动回退认证 | ✅ | `Client::auth_auto()`：none → publickey → keyboard-interactive → password |
| `exec` 命令执行 | ✅ | `Client::exec()` 返回 `(stdout, stderr)` |
| `shell` 通道 | ✅ | `Client::shell()`（不管理交互式 I/O，仅打开 shell 通道） |
| `known_hosts` 解析 | ✅ | 基础解析 + 通配符；HMAC-SHA1 哈希形式（`\|1\|…`）待支持 |
| SFTP | ✅ | SFTP v3 协议实现（`src/sftp.mbt`）|
| 远程端口转发 (-R) | ✅ | `Client::forward_remote_port()` — `tcpip-forward` 全局请求 + `forwarded-tcpip` 通道 |
| 本地端口转发 (-L) | ✅ | `Client::forward_local_port()` — `direct-tcpip` 通道（双向 `relay_data` 中继） |
| SOCKS5 动态转发 (-D) | ✅ | `Client::forward_socks5()` — SOCKS5 代理 |

## 2. 架构

```
┌─────────────────────────────────────────────────────────┐
│  cmd/{password,key,sftp,forwarding,output}/             │
│                       ── CLI 入口（按认证方式/场景分命令）│
└────────────────────────┬────────────────────────────────┘
                         │  @src.Client / @src.SftpClient
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
│   • Client::forward_local_port  ── 本地转发 (-L)       │
│   • Client::forward_remote_port ── 远程转发 (-R)       │
│   • Client::forward_socks5      ── SOCKS5 代理 (-D)    │
│   • Client::cancel_remote_forward  ── 取消远程转发     │
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
      │     │  • subsystem (sftp) │      │
      │     │  • window adjust    │      │
      │     │  • stdout/stderr    │      │
      │     └──────────┬──────────┘      │
      │                │                 │
      │     ┌──────────▼──────────┐      │
      │     │  sftp.mbt           │      │
      │     │  • SFTP v3 协议     │      │
      │     │  • 文件传输         │      │
      │     │  • 目录管理         │      │
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
├── moon.mod                     模块清单
├── moon.pkg                     根包（仅导入子包）
├── ssh_client.mbt               根包占位
├── ssh_client_test.mbt          黑盒测试
├── ssh_client_wbtest.mbt        白盒测试
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
│   ├── channel.mbt              通道（session/exec/shell/pty-req/subsystem，状态机 + stdout/stderr）
│   ├── sftp.mbt                 SFTP v3 协议（文件传输 / 目录管理）
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
├── cmd/                         ★ CLI 入口（按认证方式/场景分多个子命令）
│   ├── output/                  Hello MoonBit 演示（println "Hello MoonBit!"）
│   ├── utils/                   CMD args 工具：tokenize / split_user_host / parse_forward_arg / parse_int
│   ├── password/                密码认证（auth_auto）
│   ├── key/                     Ed25519/RSA/ECDSA 公钥认证
│   ├── sftp/                    SFTP 文件传输客户端（ls/get/put/rm/mkdir/rmdir/stat）
│   └── forwarding/              端口转发（-L / -R / -D），三个独立 run-*.sh
├── docs/
│   ├── prd_000.md                       设计 PRD
│   ├── prd_001_ssh-key-types-support-plan.md   密钥类型扩展计划
│   ├── prd_002_sftp-support-plan.md     SFTP 实现计划
│   ├── prd_003_port-forwarding-plan.md         端口转发设计文档
│   └── crypto-replacement-plan.md       OpenSSL 替换为 MoonBit 原生实现的方案
└── scripts/
    └── ssh-server/              本地 docker sshd 脚本（每个认证方式独立）
        ├── .env                 密码（password="123456"）
        ├── .gitignore           忽略本地生成的密钥对
        ├── password.sh          密码认证 sshd（端口 1022→2222）
        ├── key-ed25519.sh       生成 ed25519 密钥 + 公钥认证 sshd（端口 2022→2222）
        ├── key-rsa.sh           生成 4096 位 rsa 密钥 + 公钥认证 sshd（端口 3022→2222）
        ├── key-ecdsa.sh         生成 ecdsa 密钥 + 公钥认证 sshd（端口 4022→2222）
        └── forwarding.sh        密码认证 sshd（端口 5022→2222，AllowTcpForwarding=yes）+ nginx(1080) 验证目标
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

macOS：
```bash
brew install gcc openssl
```

### 4.2 启动测试 sshd

`scripts/ssh-server/` 下提供本地 docker sshd 启动脚本（每个脚本独立监听端口）：

| 脚本 | 用途 | 主机端口 |
|------|------|----------|
| `password.sh` | 启动 `lscr.io/linuxserver/openssh-server`（密码模式） | `1022` |
| `key-ed25519.sh` | 生成 ed25519 密钥并启动公钥认证 sshd | `2022` |
| `key-rsa.sh` | 生成 4096 位 RSA 密钥并启动公钥认证 sshd | `3022` |
| `key-ecdsa.sh` | 生成 ecdsa 密钥并启动公钥认证 sshd | `4022` |
| `forwarding.sh` | 启动密码认证 sshd 并开启端口转发 | `5022` |

> **注意：** 每次启动 `key-*.sh` 都会清空并重新生成同名密钥对（id_ed25519 / id_rsa / id_ecdsa）；生成位置在 `scripts/ssh-server/` 内，已被 `.gitignore` 排除。

例如启动密码模式 sshd：

```bash
bash scripts/ssh-server/password.sh
# 在另一个终端：ssh admin@127.0.0.1 -p 1022  # 密码 123456
```

### 4.3 构建与运行

仓库根没有统一 `run.sh`，每个 `cmd/*` 子包自带 `run-*.sh` 脚本（除 `output/` 仅作演示外），它们做：
1. `source .env` 注入 `MSSH_HOST` / `MSSH_PORT` / `MSSH_USERNAME` / `MSSH_PASSWORD` 等变量
2. `export MOONBIT_CLI_ARGS="..."`（CLI 参数通过环境变量传入 main，避免对 argv 解析的兼容问题）
3. `moon clean && moon run . --target native`（一次完成编译 + 运行）

CLI 参数在 main 里通过 `@utils.get_argv()` 从 `MOONBIT_CLI_ARGS` 读取并 tokenize，因此所有命令行参数都集中在一个环境变量里。

#### 4.3.1 密码认证

```bash
# 前置：bash scripts/ssh-server/password.sh
cd cmd/password
./run.sh
# 内部：
#   source .env       # 注入 MSSH_HOST=127.0.0.1 MSSH_PORT=1022 MSSH_USERNAME=admin MSSH_PASSWORD=123456
#   export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --exec 'uname -a' --password $MSSH_PASSWORD"
#   moon clean && moon run . --target native
```

等价的手动调用：

```bash
export MOONBIT_CLI_ARGS="admin@127.0.0.1 --port 1022 --exec 'uname -a' --password 123456"
cd cmd/password
moon run . --target native
```

#### 4.3.2 公钥认证（Ed25519 / RSA / ECDSA）

`cmd/key/` 提供三个独立脚本，对应三种密钥类型：

```bash
# 前置：bash scripts/ssh-server/key-ed25519.sh   # 或 key-rsa.sh / key-ecdsa.sh
cd cmd/key
./run-ed25519.sh     # 默认 --key ${workspace}/scripts/ssh-server/id_ed25519
./run-rsa.sh         # 默认 --key ${workspace}/scripts/ssh-server/id_rsa
./run-ecdsa.sh       # 默认 --key ${workspace}/scripts/ssh-server/id_ecdsa
# 内部：
#   export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --exec 'uname -a' --key ${workspace}/scripts/ssh-server/id_<alg>"
#   moon clean && moon run . --target native
```

`cmd/key/.env` 注入 `workspace`（docker 容器内的工作目录）。如果 sshd 直接跑在本地，请把 `${workspace}/scripts/ssh-server/id_*` 改成宿主机路径。

#### 4.3.3 SFTP 文件传输

`cmd/sftp/run.sh` 是一个端到端冒烟脚本：依次执行 ls / → mkdir → ls → put → ls → get → stat → rm → rmdir → ls。脚本先 `moon build` 一次，再多次切换 `MOONBIT_CLI_ARGS` 调用同一个二进制：

```bash
# 前置：bash scripts/ssh-server/password.sh
cd cmd/sftp
./run.sh
# 内部：
#   moon clean && moon build . --target native
#   export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --password $MSSH_PASSWORD --command ls /"
#   ../../_build/native/debug/build/cmd/sftp/sftp.exe
#   …（依次 mkdir / ls / put / ls / get / stat / rm / rmdir / ls）
```

支持的子命令：`ls <path>` / `get <remote>` / `put <local> <remote>` / `rm <path>` / `mkdir <path>` / `rmdir <path>` / `stat <path>`。

> **注意：** 当前 `cmd_get` 把内容以 hex 预览打印到 stdout，并未真正写入本地文件；`cmd_put` 上传的是一个固定的演示字符串（`Hello from MoonSSH SFTP client!`）。

#### 4.3.4 端口转发

端口转发通过 `cmd/forwarding/` 入口；每种模式对应一个独立 `run-*.sh` 脚本：

```bash
# 前置：bash scripts/ssh-server/forwarding.sh
#   （启动 sshd 5022→2222，并把 1080 端口绑定到 nginx 作为统一目标；
#    同时配置 AllowTcpForwarding=yes / GatewayPorts=yes / PermitOpen=any）
cd cmd/forwarding

# 1. 远程转发 (-R)：远端 8080 → SSH 隧道 → 本地 localhost:1080 (nginx)
./run-remote.sh
# 内部默认：
#   export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT -R 8080:localhost:1080 --password $MSSH_PASSWORD"
#   moon clean && moon run . --target native
# 验证（在 sshd 容器内）：
#   docker exec openssh-server_forwarding curl http://127.0.0.1:8080

# 2. 本地转发 (-L)：本地 2080 → SSH 隧道 → 远端 gateway:1080 (宿主机 nginx)
./run-local.sh
# 内部默认：
#   export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT -L 2080:$GATEWAY_IP:1080 --password $MSSH_PASSWORD"
# 验证（在宿主机）：
#   curl http://127.0.0.1:2080

# 3. SOCKS5 动态代理 (-D)：本地 SOCKS5:3080 → SSH 隧道 → 任意远端目标
./run-socks5.sh
# 内部默认：
#   export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT -D 3080 --password $MSSH_PASSWORD"
# 验证（在宿主机，通过 SOCKS5 访问远端 nginx）：
#   curl --socks5 127.0.0.1:3080 http://$GATEWAY_IP:1080
```

> **实现要点：**
> - 三种模式都共用一个 `relay_data()` 双向中继实现（`select`-style 轮询，避免阻塞任一方向）。
> - SOCKS5 当前仅支持 IPv4（`ATYP=0x01`）与域名（`ATYP=0x03`），IPv6（`ATYP=0x04`）直接返回 `0x08` 并关闭。
> - `relay_data` 内部把 channel 的 `data_sink` 切到 `Socket(local_socket)` 模式，绕开 `Buffer` 缓冲。
> - 集成测试在 `.github/workflows/integration.yml` 中跑全：依次 `run-remote.sh` → `run-local.sh` → `run-socks5.sh`。

## 5. 核心模块

### 5.1 `ConnectOptions`

```moonbit
pub struct ConnectOptions {
  host : String
  port : Int
  user : String
  client_banner : String?                  // 默认 "SSH-2.0-MoonSSH_0.1.0"
  host_key_policy : HostKeyPolicy          // 默认 Strict, 无条目 -> 拒绝所有未知主机
  timeout_ms : Int                          // 默认 30_000
}
```

**安全默认值**：`ConnectOptions::new(...)` 默认策略是
`Strict(entries=[], on_unknown=reject)`——未显式配置则**拒绝所有未知主机**。
请按下列四种模式之一显式启用校验：

| 方法 | 适用场景 |
|---|---|
| `.with_strict_host_key_check(content)` | 加载 OpenSSH 格式 known_hosts；命中放行，未命中拒绝；key 不一致抛 `HostKeyMismatch`（MITM 警告）。 |
| `.with_trust_on_first_use(content, prompt)` | 首次连接由 `prompt(host, alg, key) -> Bool` 决定是否接受并**持久化**到 entries；之后按 Strict 校验。 |
| `.with_host_key_verifier(f)` | 由 `(alg, key) -> Bool` 回调完全接管校验；适用于自定义指纹格式、HSM / 外部 Trust Store 集成。 |
| `.with_insecure_host_key()` | **跳过 host key 校验**。仅用于受信任内网 / 本地回环。**公网禁用**。 |

`content` 由调用方读取 known_hosts 文件得到（本库不直接依赖文件系统，保持协议层纯净）。

构造示例：

```moonbit
// 1. 严格模式：加载本地 known_hosts
let kh = read_known_hosts("~/.ssh/known_hosts")  // 调用方自己读
let opts = @src.ConnectOptions::new("example.com", 22, "alice")
  .with_strict_host_key_check(kh)

// 2. TOFU：首次询问用户
let opts2 = @src.ConnectOptions::new("new.host.com", 22, "alice")
  .with_trust_on_first_use("", (host, alg, key) => {
    let fp = fingerprint(alg, key)
    confirm("Trust \{host} (fp=\{fp})? [y/N]")
  })

// 3. 自定义校验（HSM / 外部 Trust Store）
let opts3 = @src.ConnectOptions::new("example.com", 22, "alice")
  .with_host_key_verifier((alg, key) => hsm.verify("ssh-host", alg, key))

// 4. 内网测试：跳过校验
let opts4 = @src.ConnectOptions::new("127.0.0.1", 2222, "test")
  .with_insecure_host_key()
```

KEX 阶段在收到服务端公钥时根据策略产出 `HostKeyDecision`：
`Accept` → 继续；`RejectMismatch` / `RejectUnknown` / `RejectByUser`
→ 抛出 `HostKeyMismatch`，原因见 `HostKeyDecision::reason(host, alg)`。

### 5.2 `Client` 顶层 API

| 方法 | 说明 |
|------|------|
| `Client::connect(opts) -> Client raise SshError` | TCP 连接 + banner 交换 |
| `Client::kex() -> Unit raise SshError` | 完整 KEX（KEXINIT → DH/ECDH → NEWKEYS → 安装加密） |
| `Client::auth_password(pwd) -> Unit raise SshError` | 密码认证 |
| `Client::auth_publickey(key_path) -> Unit raise SshError` | 公钥认证（two-step），自动适配 `ssh-rsa` / `rsa-sha2-256` / `rsa-sha2-512` / `ssh-ed25519` / `ecdsa-sha2-nistp256/384/521` / `ssh-dss` |
| `Client::auth_keyboard_interactive(answer_fn) -> Unit raise SshError` | keyboard-interactive 认证 |
| `Client::auth_auto(pwd, key_path?) -> Unit raise SshError` | none → publickey → kbd-int → password 自动回退 |
| `Client::open_session() -> Channel` | 创建本地 channel（id 自增） |
| `Client::exec(ch, cmd) -> (String, String) raise SshError` | 执行命令，返回 `(stdout, stderr)` |
| `Client::shell(ch) -> Unit raise SshError` | 打开 shell 通道（不管理交互式 I/O） |
| `Client::forward_local_port(local_port, remote_host, remote_port) -> Unit raise SshError` | 本地端口转发（-L），阻塞运行 |
| `Client::forward_remote_port(remote_port, local_host, local_port) -> Unit raise SshError` | 远程端口转发（-R），阻塞运行 |
| `Client::forward_socks5(local_port) -> Unit raise SshError` | SOCKS5 动态代理（-D），阻塞运行；支持 IPv4 + 域名，不支持 IPv6 |
| `Client::cancel_remote_forward(address, port) -> Unit raise SshError` | 取消远程端口转发 |
| `Client::close() -> Unit` | 关闭 TCP 连接 |

### 5.3 `Channel`

```moonbit
pub struct Channel {
  id : Int         // 本地 channel id
  peer_id : Int    // 服务端分配的 channel id
  state : ChannelState  // Closed / Opening / Open / ExecPending / EofReceived / Closing / Done
  channel_type : ChannelType  // Session / DirectTcpip(host, port) / ForwardedTcpip(host, port)
  data_sink : DataSink        // Buffer / Socket(Tcp)
  // ...
}

pub fn Channel::id(self) -> Int
pub fn Channel::peer_id(self) -> Int
pub fn Channel::state(self) -> ChannelState
pub fn Channel::is_open(self) -> Bool
pub fn Channel::exit_status(self) -> Int?
```

通道底层消息：OPEN / OPEN_CONFIRMATION / OPEN_FAILURE / WINDOW_ADJUST / DATA / EXTENDED_DATA / EOF / CLOSE / REQUEST（含 `exit-status` / `exit-signal` / `exec` / `shell` / `pty-req`）。

通道类型：
- `Session` — exec / shell / subsystem
- `DirectTcpip(host, port)` — 本地转发（-L），客户端发起
- `ForwardedTcpip(host, port)` — 远程转发（-R），服务端发起

### 5.4 `SftpClient`

SFTP v3 文件传输协议客户端：

```moonbit
pub struct SftpClient {
  // 内部字段
  priv client : Client
  priv channel : Channel
  priv version : Int       // SFTP 协议版本，当前固定为 3
  priv mut request_id : Int
}

pub struct SftpAttrs {
  priv flags : Int
  size : Int?
  uid : Int?
  gid : Int?
  permissions : Int?
  atime : Int?
  mtime : Int?
}

pub struct SftpDirEntry {
  filename : String
  longname : String
  attrs : SftpAttrs
}

// 初始化
pub fn SftpClient::open(client : Client) -> SftpClient raise SshError

// 高层 API
pub fn SftpClient::read_file(path : String) -> Bytes raise SshError
pub fn SftpClient::write_file(path : String, data : Bytes, permissions : Int) -> Unit raise SshError
pub fn SftpClient::listdir(path : String) -> Array[SftpDirEntry] raise SshError

// 底层 API
pub fn SftpClient::readdir(path : String) -> Array[SftpDirEntry] raise SshError
pub fn SftpClient::read(handle : Bytes, offset : Int, length : Int) -> Bytes raise SshError
pub fn SftpClient::write(handle : Bytes, offset : Int, data : Bytes) -> Unit raise SshError
pub fn SftpClient::close_handle(handle : Bytes) -> Unit raise SshError
pub fn SftpClient::stat(path : String) -> SftpAttrs raise SshError
pub fn SftpClient::remove(path : String) -> Unit raise SshError
pub fn SftpClient::mkdir(path : String, permissions : Int) -> Unit raise SshError
pub fn SftpClient::rmdir(path : String) -> Unit raise SshError
pub fn SftpClient::rename(oldpath : String, newpath : String) -> Unit raise SshError
pub fn SftpClient::realpath(path : String) -> String raise SshError
pub fn SftpClient::close() -> Unit
```

> **当前限制：** 文件大小按 32 位 `Int` 读取，超过 4 GiB 的文件会被截断；`SftpAttrs` 仅解析 `SSH_FILEXFER_ATTR_SIZE / UIDGID / PERMISSIONS / ACCESSTIME / MODIFYTIME`，未识别的 flags 字段被忽略。

### 5.5 `known_hosts`

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

## 6. 开发流程

### 6.1 修改后必跑

```bash
moon fmt                          # 格式化
moon info                         # 更新 .mbti 接口
moon build --target native        # 编译
moon test --target native         # 测试
```

### 6.2 覆盖率

```bash
moon coverage analyze > uncovered.log
# 目标：uncovered.log 中 packet / kex / auth 关键路径为空
```

### 6.3 派生代码

`src/socket/`（`socket.mbt` / `socket.c`）派生于 `moonbitlang/async/tls`（Apache 2.0）。任何修改请保留：

- 原 Apache 2.0 版权头
- 命名空间调整记录（`moonbitlang/async/socket` → `src/socket`）

## 7. 路线图

| 版本 | 内容 | 状态 |
|------|------|------|
| **v0.1** | 协议骨架：packet / kex 状态机 / auth（密码 + 公钥 + kbd-int + auto）/ channel / crypto FFI / 自带 socket FFI | ✅ 已发布 |
| **v0.2** | SFTP 协议 | ✅ 已发布 |
| **v0.3** | 端口转发（remote） | ✅ 已发布 |
| **v0.4** | 端口转发（local / SOCKS5） | ✅ 已发布 |
| **v0.5** | shell 交互式 I/O / pty-req 对接 | 📋 待开发 |
| **v0.6** | X11 转发（`x11-req` + `x11` 通道，RFC 4254 §6.3.2） | 📋 待开发 |

**进展：**
- [ ] shell 交互（stdin/stdout 转发）
- [ ] `Client::exec_pty()` 高层封装（`build_channel_request_pty` 已就绪）
- [ ] X11 转发（`x11-req` 全局请求 + `x11` 通道类型 + `X11FakeCookie` / `MIT-MAGIC-COOKIE-1` 协议）
- [ ] HMAC-SHA1 形式的 known_hosts 条目（`|1|…`）

## 8. 跨平台注意

| 平台 | 编译 | 运行 | 说明 |
|------|------|------|------|
| Linux glibc | ✅ | ✅ | 完全支持 |
| Windows MinGW (Winsock2) | ✅ | ✅ | 完全支持 |
| macOS | ✅ | ✅ | 完全支持 |

## 9. 引用

- [RFC 4251](https://tools.ietf.org/html/rfc4251) — SSH Protocol Architecture
- [RFC 4252](https://tools.ietf.org/html/rfc4252) — SSH Authentication Protocol
- [RFC 4253](https://tools.ietf.org/html/rfc4253) — SSH Transport Layer Protocol
- [RFC 4254](https://tools.ietf.org/html/rfc4254) — SSH Connection Protocol（含 TCP/IP Forwarding §7）
- [RFC 1928](https://tools.ietf.org/html/rfc1928) — SOCKS Protocol Version 5
- [RFC 4344](https://tools.ietf.org/html/rfc4344) — SSH Transport Layer Encryption Modes
- [RFC 5656](https://tools.ietf.org/html/rfc5656) — SSH ECC Algorithm Integration
- [RFC 6668](https://tools.ietf.org/html/rfc6668) — SHA-2 Data Integrity Verification for SSH
- [RFC 8332](https://tools.ietf.org/html/rfc8332) — Use of RSA Keys with SHA-256/512
- [OpenSSL EVP](https://docs.openssl.org/3.0/manuals/) — 密码学 API
- [draft-ietf-secsh-filexfer-02](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02) — SSH File Transfer Protocol v3
- [OpenSSH sftp-server](https://github.com/openssh/openssh-portable) - SFTP
- [moonbitlang/async](https://mooncakes.io/docs/moonbitlang/async) — 派生来源（Apache 2.0）

## 10. License

Apache-2.0。详见 [LICENSE](LICENSE)。
