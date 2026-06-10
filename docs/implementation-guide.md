# MoonSSH 客户端实现指南

> 本文档供 AI Agent 使用，描述当前实现状态、协议细节和后续开发任务。
> 基于 RFC 4251-4254 + RFC 4419 (DH Group Exchange) + RFC 3526 (MODP Groups)。

---

## 目录

1. [项目概览](#1-项目概览)
2. [目录结构](#2-目录结构)
3. [SSH 协议架构](#3-ssh-协议架构)
4. [核心数据类型](#4-核心数据类型)
5. [总体流程（5 阶段）](#5-总体流程5-阶段)
6. [Binary Packet Protocol](#6-binary-packet-protocol)
7. [密钥交换详细流程](#7-密钥交换详细流程)
8. [加密与 MAC 详细说明](#8-加密与-mac-详细说明)
9. [各模块当前状态](#9-各模块当前状态)
10. [待完成任务清单](#10-待完成任务清单)
11. [调试指南](#11-调试指南)

---

## 1. 项目概览

| 属性 | 值 |
|------|-----|
| 项目名 | `PaiGack/ssh_client` |
| 版本 | 0.1.0 |
| 语言 | MoonBit (native target) |
| 密码学后端 | OpenSSL FFI (`libcrypto`) |
| 目标服务器 | OpenSSH 8.2p1 (Ubuntu) |
| 测试环境 | `linuxserver/openssh-server` Docker |

### 目标算法配置

| 参数 | 值 | 备选值 |
|------|-----|--------|
| Key Exchange | `curve25519-sha256@libssh.org` | `diffie-hellman-group14-sha256` |
| Encryption | `aes256-ctr` / `chacha20-poly1305` | `aes128-gcm@openssh.com` |
| MAC | `hmac-sha2-256` | AEAD 内置 |
| Host Key | `ssh-ed25519` / `rsa-sha2-256` | `ecdsa-sha2-nistp256` |
| Compression | `none` | — |

---

## 2. 目录结构

```
/workspace/
├── moon.mod                          # 模块元数据
├── moon.pkg                         # 根包依赖
├── src/                             # 核心源码
│   ├── moon.pkg                     # src 包: bigint, utf8, crypto, socket; native only
│   ├── ssh_client.mbt               # 顶层 API: Client, ConnectOptions, connect/kex/auth/exec
│   ├── packet.mbt                   # Binary Packet Protocol: Reader/Writer, read_packet/write_packet
│   ├── kex.mbt                      # KEX 状态机: KexContext, drive(), derive_keys()
│   ├── auth.mbt                     # 用户认证: AuthContext, password/publickey 方法
│   ├── channel.mbt                  # 通道协议: Channel, exec/data/close
│   ├── known_hosts.mbt              # known_hosts 文件解析与指纹匹配
│   ├── sftp.mbt                     # SFTP v3 stub (未实现)
│   ├── crypto/                      # 密码学 FFI 层
│   │   ├── moon.pkg                 # crypto 包: bigint, utf8; native only
│   │   ├── cipher.mbt               # AES-CTR/GCM, ChaCha20-Poly1305 (FFI → EVP_CIPHER_*)
│   │   ├── digest.mbt               # SHA-1/256/384/512 (FFI → EVP_Digest*)
│   │   ├── mac.mbt                  # HMAC-SHA1/256/384/512 (FFI → EVP_MAC)
│   │   ├── kex.mbt                  # X25519, nistp256 ECDH, DH Group14 (FFI → EVP_PKEY_derive)
│   │   ├── pkey.mbt                 # Ed25519/RSA/ECDSA 签名验签 (FFI → EVP_PKEY_sign/verify)
│   │   ├── crypto_util.mbt          # RAND_bytes, 错误处理工具函数 (FFI)
│   │   ├── error.mbt                # CryptoError 统一错误类型
│   │   ├── openssl_loader.mbt       # OpenSSL 动态加载 (dlopen/dlsym)
│   │   └── openssl.c                # C FFI glue: 所有 C 函数实现
│   └── socket/                      # TCP 传输层
│       ├── moon.pkg                 # socket 包; native only
│       └── socket.mbt               # Tcp 结构体: connect/read_exact/write_bytes/read_until_newline
├── cmd/main/
│   ├── moon.pkg                     # main 入口包: argparse, env, src; is_main=true
│   └── main.mbt                     # CLI 演示程序: 解析参数 → 连接 → 认证 → 执行命令
├── tests/                           # 测试脚本 (.sh) 和测试 C 辅助文件
├── docs/                            # 文档
│   ├── ssh-1.md                     # SSH 协议学习笔记（原始参考）
│   ├── prd_000.md                   # 技术决策分析
│   ├── prd_001.md                   # 实现规约（AI 执行版）
│   └── implementation-guide.md      # 本文档 ← 你在这里
├── ssh_client_test.mbt              # 黑盒测试入口
└── ssh_client_wbtest.mbt            # 白盒测试入口
```

---

## 3. SSH 协议架构

```
┌─────────────────────────────────────────────────────────────┐
│                    Connection Protocol (RFC 4254)           │
│   channel open/close | exec | shell | port-forwarding       │
├─────────────────────────────────────────────────────────────┤
│                  User Auth Protocol (RFC 4252)             │
│   none | password | publickey | keyboard-interactive        │
├─────────────────────────────────────────────────────────────┤
│                 Transport Layer Protocol (RFC 4253)         │
│   version exchange | algorithm negotiation | key exchange    │
│   encryption (AES-CTR/GCM/ChaCha20) | integrity (HMAC)     │
└─────────────────────────────────────────────────────────────┘
                          TCP/IP (@socket.Tcp)
                          FFI C Socket (POSIX / Winsock2)
```

**消息编号范围 (RFC 4250)**:

| 范围 | 用途 |
|------|------|
| 1–19 | 传输层通用 (disconnect=1, ignore=2, debug=4, etc.) |
| 20–29 | 算法协商 (kexinit=20, newkeys=21) |
| 30–49 | Key Exchange 方法 (dh_gex_request=30~34, ecdh_init=30, ecdh_reply=31) |
| 50–59 | 用户认证通用 (service_request=5, service_accept=6, userauth_req=50, success=52, failure=51) |
| 60–79 | 认证特定方法 (pk_ok=60, passwd_changereq=60) |
| 80–89 | 连接协议通用 |
| 90–127 | 通道相关 (channel_open=90, data=94, eof=95, close=96, request=98, success=99, failure=100) |
| 128–191 | 本地扩展保留 |
| 192–255 | 本地扩展可用 |

---

## 4. 核心数据类型

所有多字节数据均为 **大端序 (network byte order)**。

### 4.1 基础类型

| 类型 | 编码 | 示例 |
|------|------|------|
| `byte` | 8 位无符号 | `0x00` ~ `0xFF` |
| `boolean` | 1 byte: 0=false, 1=true | `0x01` |
| `uint32` | 4 bytes 大端序 | `0x29B7F4AA` → `29 B7 F4 AA` |
| `uint64` | 8 bytes 大端序 | 同上，8 字节 |
| `string` | `uint32(length)` + `byte[length]` | `"abc"` → `00 00 00 03 61 62 63` |
| `mpint` | string 格式的补码多精度整数 | 见下方表格 |
| `name-list` | `uint32(total_len)` + ASCII 逗号分隔字符串 | 见下方表格 |

### 4.2 mpint 编码规则 (RFC 4253 §5)

mpint = string(2的补码表示)。关键规则：
- 负数：第一 bit 必须为 1（补码符号位）
- 正数：如果最高 bit 为 1，前面加 `0x00` 字节区分负数

| value (hex) | representation (hex) |
|-------------|---------------------|
| `0` | `00 00 00 00` |
| `9A378F9B2E332A7` | `00 00 00 08 09 A3 78 F9 B2 E3 32 A7` |
| `80` | `00 00 00 02 00 80` （加前导0x00） |
| `-1234` | `00 00 00 02 ED CC` |
| `-DEADBEEF` | `00 00 00 05 FF 21 52 41 11` |

**MoonBit 实现**: `packet.mbt` 中 `Writer::write_mpint()` 和 `Reader::read_mpint()`。

### 4.3 name-list 示例

| value | hex |
|-------|-----|
| `()` 空 | `00 00 00 00` |
| `(zlib)` | `00 00 00 04 7A 6C 69 62` |
| `(zlib,none)` | `00 00 00 09 7A 6C 69 62 2C 6E 6F 6E 65` |

---

## 5. 总体流程（5 阶段）

完整连接建立过程如下：

```
Client                                    Server
  │                                         │
  │  ═══════ 阶段1: 版本交换 ════════════    │
  │  "SSH-2.0-MoonSSH_x.x\r\n"  ──→        │
  │                        ←── "SSH-2.0-OpenSSH_8.2p1...\r\n"
  │                                         │
  │  ═══════ 阶段2: 算法协商 (KEXINIT) ══    │
  │  SSH_MSG_KEX_INIT (20)  ──→            │
  │                       ←──  SSH_MSG_KEX_INIT (20)
  │  (两端各自选择第一个匹配算法)              │
  │                                         │
  │  ═══════ 阶段3: Key Exchange ════════    │
  │  [curve25519] 或 [DH Group14]           │
  │  SSH_MSG_KEX_ECDH_INIT(30)  ──→        │
  │                       ←──  SSH_MSG_KEX_ECDH_REPLY(31)
  │          (K_S host_key, Q_s, signature)  │
  │  计算 H (exchange hash), 验证签名         │
  │                                         │
  │  ═══════ 切换到 NEWKEYS ════════════    │
  │  SSH_MSG_NEWKEYS(21)  ──→              │
  │                    ←──  SSH_MSG_NEWKEYS(21)
  │  (此后所有数据用新密钥加密+MAC)            │
  │                                         │
  │  ═══════ 阶段4: 服务请求 ═══════════    │
  │  SERVICE_REQUEST("ssh-userauth") ─→     │
  │                           ←──  SERVICE_ACCEPT(6)
  │                                         │
  │  ═══════ 阶段5: 用户认证 ═══════════    │
  │  USERAUTH_REQUEST(password)  ─→         │
  │                           ←──  USERAUTH_SUCCESS(52)
  │                                         │
  │  ═══════ 加密通道就绪 ══════════════    │
  │  CHANNEL_OPEN(session) ─→               │
  │                    ←──  CHANNEL_OPEN_CONFIRMATION(91)
  │  CHANNEL_REQUEST(exec, "ls") ─→         │
  │  CHANNEL_DATA(stdout) ←── ...           │
  │  CHANNEL_EOF/CLOSE ←── ...              │
```

---

## 6. Binary Packet Protocol

### 6.1 数据包格式 (RFC 4253 §6)

```
┌──────────┬─────────┬──────────────┬──────────────┬─────────────┐
│ uint32   │ byte    │ byte[n1]     │ byte[n2]     │ byte[m]     │
│ packet   │ padding │ payload      │ random        │ MAC         │
│ length   │ length  │ (n1=len-     │ padding       │             │
│          │         │  padlen-1)   │ (n2=padlen)   │             │
└──────────┴─────────┴──────────────┴──────────────┴─────────────┘
```

**约束条件**:

- `packet_length = 1 + padlen + payload_length`（不含 MAC 和自己）
- `packet_length` 必须是 `cipher_block_size` 的倍数（最小 8 字节）
- 实际要求：`(payload_length + padlen) % block_size == 4`
- `padlen ∈ [4, 255]`：使总长度对齐到 block_size 的最小填充
- 最大 payload：**35000 bytes**（实际限制），规范说 32768
- `padding` 为密码学安全随机字节

### 6.2 发送流程 (encrypt-then-MAC)

```
输入: payload (Bytes)

1. 计算 padding_length 使 (payload_len + padding_length) % block_size == 4
2. 组装 unencrypted_packet = [uint32(packet_length)][padding_byte][payload][random_padding]
3. 计算 MAC = HMAC(mac_key, uint32(seq_num) || unencrypted_packet); seq_num++
4. encrypted_block = AES_CTR_Encrypt(enc_key, iv, unencrypted_packet)
5. 发送: [encrypted_block][MAC]
```

**关键点**: MAC 是在**明文包**上计算的，然后整个 body（不含 MAC）被加密。这就是 **EtM (Encrypt-then-MAC)** 模式。OpenSSH 默认使用此模式。

对于 **AEAD 模式** (GCM, ChaCha20-Poly1305):
- 不需要独立 MAC
- tag 附在密文后面
- aad = packet_length (4 bytes)

### 6.3 接收流程 (AES-CTR)

由于 AES-CTR 是流模式（按块独立解密），可以利用以下特性：

```
1. 读 16 字节 → AES_CTR_Decrypt → 得到 packet_length (前4字节) + padding_length (第5字节)
2. 读剩余 packet_length - 1 字节 → 解密 → 得到 payload + padding
3. 读 mac_size 字节的 MAC (如 hmac-sha2-256 则 32 字节)
4. 验证 MAC: HMAC(mac_key, uint32(seq_recv) || decrypted_body); seq_recv++
5. 提取 payload: 跳过 1 字节 padding_length + padlen 字节 padding
```

**TCP 边界问题**: TCP 可能分包或合包。但由于 CTR 模式可以先解密头部获取长度，所以不存在真正的边界模糊。

### 6.4 MoonBit 实现

位置: `src/packet.mbt`

| 函数/方法 | 功能 |
|-----------|------|
| `Writer::new()` / `to_bytes()` | 可追加字节缓冲区 |
| `Reader::new(data)` / `read_byte()`, `read_uint32()`, `read_string()`, `read_mpint()`, `read_name_list()` | 游标式读取器 |
| `write_packet(payload, block_size, mac_enabled, compute_mac)` | 组装完整包（含随机padding） |
| `read_packet(read_exact, block_size, mac_size, decrypt, verify_mac)` | 解析完整包（含解密+验签） |
| `encode_uint32(n)` / `decode_uint32(buf)` | 大端序编解码 |
| `encode_string(s)` / `parse_string(buf)` | SSH string 编解码 |
| `encode_mpint(n)` / `decode_mpint(buf)` | SSH mpint 编解码 |

---

## 7. 密钥交换详细流程

### 7.1 支持的 KEX 算法

当前项目支持两种 KEX 算法路径：

#### Path A: curve25519-sha256 (首选, 已部分实现)

```
Client                                    Server
 │                                         │
 │  生成 X25519 密钥对 (priv, pub=Q_c)     │
 │  SSH_MSG_KEX_ECDH_INIT(30) + Q_c  ──→  │
 │                              ←──  SSH_MSG_KEX_ECDH_REPLY(31)
 │           K_S (host key blob)           │
 │           Q_s (server public key)        │
 │           signature (H 的签名)            │
 │                                         │
 │  shared_secret = X25519(priv_c, Q_s)    │
 │  H = SHA256(V_C || V_S || I_C || I_S || │
 │            K_S || Q_c || Q_s || K)       │
 │  验证 signature over H using K_S         │
 │  session_id = H (首次KEX时设置)          │
```

**H 的计算输入格式**:
```
string  V_C  (客户端版本串,不含 \r\n)
string  V_S  (服务端版本串,不含 \r\n)
string  I_C  (客户端 KEXINIT payload 全文)
string  I_S  (服务端 KEXINIT payload 全文)
string  K_S  (host key blob)
string  Q_c  (客户端公钥, 作为 string 非 mpint)
string  Q_s  (服务端公钥, 作为 string 非 mpint)
mpint   K    (共享密钥, mpint 编码)
```

**注意**: curve25519 的 Q_c/Q_s 用 **string** 编码（非 mpint），K 用 **mpint** 编码。
X25519 共享密钥是小端序，需转为大端序再编码为 mpint。

#### Path B: diffie-hellman-group14-sha256 (备选, 框架已有)

```
Client                                    Server
 │                                         │
 │  SSH_MSG_KEX_DH_GEX_REQUEST(34)  ──→   │
 │     min=2048, n=2048, max=2048          │
 │                              ←──  SSH_MSG_KEX_DH_GEX_GROUP(31)
 │     p (RFC 3526 2048-bit prime)         │
 │     g (=2)                               │
 │                                         │
 │  生成随机 x;  e = g^x mod p             │
 │  SSH_MSG_KEX_DH_GEX_INIT(32) + e  ──→  │
 │                              ←──  SSH_MSG_KEX_DH_GEX_REPLY(33)
 │     K_S (host key)                      │
 │     f (= g^y mod p)                     │
 │     signature                            │
 │                                         │
 │  K = f^x mod p                          │
 │  H = SHA256(V_C||V_S||I_C||I_S||K_S||  │
 │            min||n||max||p||g||e||f||K)  │
```

**DH Group14 p 值** (RFC 3526 §3, 2048-bit MODP group):

```
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
```
generator g = 2.

### 7.2 算法协商 (KEXINIT)

消息类型: `SSH_MSG_KEXINIT = 20 (0x14)`

**发送结构**:
```
byte         0x14                    (消息类型)
byte[16]     cookie                  (16 字节随机数)
name-list    kex_algorithms          (支持的 KEX 算法)
name-list    server_host_key_algorithms (host key 类型)
name-list    encryption_algorithms_client_to_server
name-list    encryption_algorithms_server_to_client
name-list    mac_algorithms_client_to_server
name-list    mac_algorithms_server_to_client
name-list    compression_algorithms_client_to_server
name-list    compression_algorithms_server_to_client
name-list    languages_client_to_server
name-list    languages_server_to_server
boolean      first_kex_packet_follows
uint32       0                       (保留字段)
```

**匹配规则**: client 列表中第一个 server 也支持的算法（左优先/first-match）。任何一类匹配不上则断开连接。

**MoonBit 实现**: `src/kex.mbt` 中 `build_kexinit_payload()` 和 `parse_kexinit()`。

### 7.3 密钥派生 (RFC 4253 §7.2)

KEX 完成后，从共享密钥 K 和 exchange hash H 派生 6 个 session key：

```python
IV_c2s  = HASH(K || H || "A" || session_id)   # Client→Server 加密 IV
IV_s2c  = HASH(K || H || "B" || session_id)   # Server→Client 加密 IV
EncKey_c2s = HASH(K || H || "C" || session_id) # Client→Server 加密密钥
EncKey_s2c = HASH(K || H || "D" || session_id) # Server→Client 加密密钥
MacKey_c2s = HASH(K || H || "E" || session_id) # Client→Server MAC 密钥
MacKey_s2c = HASH(K || H || "F" || session_id) # Server→Client MAC 密钥
```

**KDF 迭代规则**: 当 hash output < needed length 时迭代：
```
key1 = HASH(K || H || letter || session_id)
key2 = HASH(K || H || key1)
...
key = key1 || key2 || ...
截取前 needed 字节
```

**session_id**: 首次 KEX 的 H 值。后续 rekey 不改变 session_id。

**密钥长度示例**:

| 算法 | Key Len | IV Len | Mac Key Len |
|------|---------|--------|-------------|
| aes128-ctr | 16 | 16 | 20(hmac-sha1) or 32(hmac-sha2-256) |
| aes256-ctr | 32 | 16 | 32 |
| aes128-gcm | 16 | 12 | 0 (AEAD) |
| aes256-gcm | 32 | 12 | 0 (AEAD) |
| chacha20-poly1305 | 64 | 0 | 0 (AEAD) |

**MoonBit 实现**: `src/kex.mbt` 中 `derive_keys()` 和 `kdf()` 函数。

### 7.4 Host Key 签名验证

Server 在 KEX reply 中返回 host key blob + signature。Client 必须：

1. **解析 host key blob** (按算法):
   - `ssh-ed25519`: string("ssh-ed25519") + string(pubkey_32bytes)
   - `ssh-rsa` / `rsa-sha2-*`: string("ssh-rsa") + string(e) + string(n)
   - `ecdsa-sha2-nistp256`: string("ecdsa-sha2-nistp256") + string("nistp256") + string(Q_65bytes)

2. **解析 signature blob**: string(algorithm_name) + string(signature_bytes)

3. **验签**: verify(host_key_public, exchange_hash_H, signature)

4. **可选信任检查**: 调用用户提供的 `accept_host_key(alg, key_bytes)` 回调

**MoonBit 实现**: `src/kex.mbt` 中 `verify_host_key_signature()` 和 `parse_host_key_to_pkey()`。

---

## 8. 加密与 MAC 详细说明

### 8.1 AES-256-CTR

- **密钥长度**: 32 bytes
- **IV/Nonce 长度**: 16 bytes
- **Block size**: 16 bytes
- **模式特点**: 流密码模式，无需 padding，可并行加解密
- **安全性**: 只要 nonce 不重复即可（SSH 每个方向使用固定 IV + 递增 counter）

### 8.2 ChaCha20-Poly1305 (@openssh.com)

- **密钥长度**: 32 bytes (用于加密) + 32 bytes (用于 Poly1305，但 SSH 把它们当做一个 64-byte key)
- **IV 长度**: 12 bytes（实际上 SSH 中为 0，因为使用内部 counter 构造 nonce）
- **Tag 长度**: 16 bytes
- **模式**: AEAD (Authenticated Encryption with Associated Data)
- **AAD**: packet_length (4 bytes, big-endian)

### 8.3 HMAC-SHA2-256

- **密钥长度**: 32 bytes
- **输出长度**: 32 bytes
- **计算方式**: `MAC = HMAC-SHA256(key, sequence_number(4 bytes BE) || unencrypted_packet)`
- **sequence_number**: 每发一个包递增 1，从 0 开始，达到 2^32 归零

### 8.4 序列号管理

每个方向 (c2s, s2c) 维护独立的序列号:
- `seq_send`: 发送方向，初始 0，每次 `write_encrypted_packet` 后 ++
- `seq_recv`: 接收方向，初始 0，每次 `read_encrypted_packet` 并通过 MAC 验证后 ++

---

## 9. 各模块当前状态

### 9.1 crypto/ 密码学层 ✅ 基本完成

| 文件 | 状态 | 说明 |
|------|------|------|
| `error.mbt` | ✅ 完成 | `CryptoError` suberror 定义 |
| `crypto_util.mbt` | ✅ 完成 | `rand_bytes()`, `err_get_and_clear()`, OpenSSL 错误处理 |
| `openssl_loader.mbt` | ✅ 完成 | `ensure_openssl()`, dlopen/dlsym 加载 libcrypto |
| `openssl.c` | ✅ 完成 | 所有 C glue 函数 (~600 行) |
| `digest.mbt` | ✅ 完成 | `Hasher::new/update/finalize()`, SHA-1/256/384/512 |
| `mac.mbt` | ✅ 完成 | `hmac()` oneshot, `Mac` incremental, truncate |
| `cipher.mbt` | ✅ 完成 | `Cipher::new/update/finalize/close()`, AES-CTR/GCM, ChaCha20-Poly1305 |
| `pkey.mbt` | ✅ 完成 | `PKey` generate/from_raw/from_rsa_components/sign/verify/close |
| `kex.mbt` | ✅ 完成 | x25519_generate/derive, nistp256, dh_group14_prime/keygen/shared, HKDF |

**注意**: 以上仅在 Linux/macOS (非 Windows) 上有完整 OpenSSL 支持。Windows 平台有 fallback stub。

### 9.2 socket/ 传输层 ✅ 完成

| 文件 | 状态 | 说明 |
|------|------|------|
| `socket.mbt` | ✅ 完成 | `Tcp::connect_to_host()`, `read_exact()`, `write_bytes()`, `read_until_newline()`, `close()` |

基于 POSIX socket / Winsock2 的 FFI 封装。已启用 `TCP_NODELAY`。

### 9.3 协议核心层 ⚠️ 框架完成，需联调验证

| 文件 | 状态 | 说明 |
|------|------|------|
| `packet.mbt` | ✅ 完成 | Reader/Writer, encode/decode, read_packet/write_packet |
| `kex.mbt` | ⚠️ 框架 | KEX 状态机完整，curve25519 路径已实现，DH Group14 有框架 |
| `auth.mbt` | ✅ 完成 | Service request, password/publickey/none 方法, 签名 input 构建 |
| `channel.mbt` | ✅ 完成 | Session channel open, exec, data, eof, close, exit-status |
| `known_hosts.mbt` | ✅ 完成 | 解析、匹配、base64 编解码 |

### 9.4 顶层 API ⚠️ 联调中

| 文件 | 状态 | 说明 |
|------|------|------|
| `ssh_client.mbt` | ⚠️ 框架 | `Client::connect()` 含 banner 交换; `kex()` 调用 KexContext::drive(); `auth_password()` 完整流程; `exec()` 含 channel 管理 |
| `cmd/main/main.mbt` | ⚠️ 框架 | CLI 参数解析, connect→kex→auth→exec 流程 |

### 9.5 关键代码引用

**Client::connect()** (`src/ssh_client.mbt:102-145`):
- 创建 TCP 连接
- 发送/接收版本 banner ("SSH-2.0-MoonSSH_0.1.0")
- 初始化 `KexContext` 和 `AuthContext`

**Client::kex()** (`src/ssh_client.mbt:150-161`):
- 调用 `self.kex.drive(read_fn, write_fn, accept_host_key)`
- 保存 session_id
- 调用 `install_encryption(keys)` 安装加密

**KexContext::drive()** (`src/kex.mbt:536-581`):
- 发送 KEXINIT → 接收 server KEXINIT
- 协商算法 (first match)
- 分派到 `drive_curve25519()` 或其他 KEX 方法

**KexContext::drive_curve25519()** (`src/kex.mbt:681-786`):
- 生成 X25519 密钥对
- 发送 ECDH_INIT
- 接收 ECDH_REPLY
- 计算共享密钥 + exchange hash
- 验证 host key 签名
- 发送/接收 NEWKEYS

---

## 10. 待完成任务清单

以下是按优先级排序的任务列表，供 AI Agent 逐步执行：

### P0: 跑通完整链路 (connect → kex → auth → exec)

**前置条件**: Linux/macOS 环境, 安装了 OpenSSL dev library

**步骤**:

1. **确认构建通过**
   ```bash
   cd /workspace
   moon build --target native
   ```
   期望: 无编译错误

2. **确认 crypto FFI 正常**
   ```bash
   moon test --target native
   ```
   如果有 crypto 相关测试，确认通过

3. **准备测试 SSH server**
   ```bash
   docker run -d --name test-sshd -p 2222:22 \
     -e USER_NAME=test -e USER_PASSWORD=test123 \
     linuxserver/openssh-server:latest
   ```

4. **运行 CLI 测试**
   ```bash
   moon run cmd/main --target native -- test@localhost --port 2222 --password test123 --exec "echo hello"
   ```

5. **根据报错信息调试** (见第11节调试指南)

### P1: 修复已知潜在问题

根据代码审查，以下是需要关注的问题点：

| # | 问题 | 位置 | 建议 |
|---|------|------|------|
| 1 | X25519 shared secret 字节序 | `kex.mbt:731` | 确认是否需要 `reverse_bytes()`；OpenSSL EVP_PKEY_derive 输出可能是大端序 |
| 2 | DEBUG println 残留 | 多处 | 清理或改为条件日志 |
| 3 | Windows 平台 fallback | `kex.mbt:662-677`, `ssh_client.mbt:207-216` | Windows 路径直接 raise error |
| 4 | `read_packet` 中 decrypt 顺序 | `packet.mbt:274` | 当前先 verify_mac 再 decrypt，应确认是否与 EtM 一致 |
| 5 | `read_encrypted_packet` CTR 头部解密 | `ssh_client.mbt:448-491` | CTR 模式下读 16 字节解密获取长度的逻辑是否正确 |
| 6 | `MSG_CHANNEL_SUCCESS` 消息号 | `channel.mbt:346` | 写的是 `b'\x63'`(99)，但注释说 99=CHANNEL_SUCCESS，正确；但 `MSG_CHANNEL_REQUEST` 也是 `b'\x62'`(98) —— 检查是否有笔误 |
| 7 | `AuthReply::PasswordChangeRequired` 消息号 | `auth.mbt:105` | 注释写 60 但实际是 `b'\x34'`(52)；PK_OK 是 `b'\x3c'`(60)——确认消息号正确性 |

### P2: 补充测试

| 测试类型 | 文件 | 内容 |
|---------|------|------|
| 单元测试 | `*_wbtest.mbt` | Reader/Writer 编解码正确性 |
| 单元测试 | `digest_wbtest.mbt` | SHA-256 已知向量 (NIST) |
| 单元测试 | `mac_wbtest.mbt` | HMAC-SHA2-256 已知向量 (RFC 4231) |
| 单元测试 | `cipher_wbtest.mbt` | AES-256-CTR NIST 向量 |
| 集成测试 | 脚本或 `_test.mbt` | 连接真实 sshd 完成 KEX |
| 集成测试 | 脚本或 `_test.mbt` | 密码认证 + exec 命令 |

### P3: 文档完善

- [ ] 更新 README.md 含完整使用示例
- [ ] 创建 docs/architecture.md 含架构图
- [ ] 代码注释中清理 DEBUG 信息

---

## 11. 调试指南

### 11.1 常见错误与原因

| 错误信息 | 可能原因 | 解决方法 |
|----------|---------|---------|
| `bad packet length` | 加密/MAC 配置不匹配 | 检查 cipher algorithm 是否一致；block_size 是否正确 |
| `mac corrupted` | MAC key 错误或序列号不同步 | 检查 derive_keys 的输入参数；确认 seq_num 管理 |
| `host key signature is invalid` | exchange hash 计算错误 | 打印并对比 H 值；检查 mpint 编码 |
| `kex: no matching xxx algorithm` | 服务端不支持客户端的首选算法 | 检查 kex_algorithms() 列表顺序 |
| `ProtocolError: expected SSH_MSG_NEWKEYS` | KEX 流程中消息丢失或乱序 | 检查是否正确跳过了 EXT_INFO/IGNORE/DEBUG 消息 |
| `disconnect` | 服务端主动断开 | 通常伴随 reason code 和 message；检查算法兼容性 |

### 11.2 服务端 Debug 模式

在测试机器上启动 debug 模式的 sshd 可以看到详细的协议日志：

```bash
# 停止系统 sshd 后手动启动
/usr/sbin/sshd -ddd -p 2222
```

这会输出每次 KEX、加密操作的详细信息，是最佳调试手段。

### 11.3 客户端 Debug 策略

当前代码中有大量 `println("DEBUG ...")` 语句。关键调试节点：

1. **Banner 交换** (`ssh_client.mbt:121-122`): 确认 V_C, V_S 正确
2. **KEXINIT 收发** (`kex.mbt:554-573`): 确认协商结果
3. **ECDH 交换** (`kex.mbt:696-757`): 确认 pubkey 长度、shared secret、exchange hash
4. **包读写** (`ssh_client.mbt:326-339`, `356-362`): 确认 packet length, padding, msg type
5. **加密安装** (`ssh_client.mbt:376-417`): 确认 key/iv 长度

### 11.4 Wireshark 抓包

如果网络层面调试：
```bash
wireshark -i lo -f "port 2222"
```
- KEX 阶段前的流量是**明文**（version exchange + KEXINIT）
- NEWKEYS 之后的所有流量都是**加密**的

---

## 附录 A: 重要常量速查

```moonbit
// Transport layer messages (RFC 4253)
SSH_MSG_DISCONNECT          = 1   // 0x01
SSH_MSG_IGNORE              = 2   // 0x02
SSH_MSG_UNIMPLEMENTED       = 3   // 0x03
SSH_MSG_DEBUG               = 4   // 0x04
SSH_MSG_SERVICE_REQUEST     = 5   // 0x05
SSH_MSG_SERVICE_ACCEPT      = 6   // 0x06
SSH_MSG_KEXINIT             = 20  // 0x14
SSH_MSG_NEWKEYS             = 21  // 0x15

// KEX specific (RFC 4253 / RFC 5656 / RFC 4419)
SSH_MSG_KEX_ECDH_INIT       = 30  // 0x1e  (also used for DH_GEX_REQUEST in some impls)
SSH_MSG_KEX_ECDH_REPLY      = 31  // 0x1f  (also used for DH_GEX_GROUP/REPLY)
// Note: actual message numbers vary by KEX method.
// curve25519 uses 30/31 as ECDH_INIT/REPLY (RFC 5656 maps to generic range 30-49)
// DH-GEX uses 34 (REQUEST), 31 (GROUP), 32 (INIT), 33 (REPLY) per RFC 4419

// Authentication (RFC 4252)
SSH_MSG_USERAUTH_REQUEST    = 50  // 0x32
SSH_MSG_USERAUTH_FAILURE    = 51  // 0x33
SSH_MSG_USERAUTH_SUCCESS    = 52  // 0x34
SSH_MSG_USERAUTH_PK_OK      = 60  // 0x3c

// Channel (RFC 4254)
SSH_MSG_CHANNEL_OPEN        = 90  // 0x5a
SSH_MSG_CHANNEL_OPEN_CONF  = 91  // 0x5b
SSH_MSG_CHANNEL_OPEN_FAIL  = 92  // 0x5c
SSH_MSG_CHANNEL_WINDOW_ADJ  = 93  // 0x5d
SSH_MSG_CHANNEL_DATA        = 94  // 0x5e
SSH_MSG_CHANNEL_EXTENDED    = 127 // 0x7f
SSH_MSG_CHANNEL_EOF         = 95  // 0x5f
SSH_MSG_CHANNEL_CLOSE       = 96  // 0x60
SSH_MSG_CHANNEL_REQUEST     = 98  // 0x62
SSH_MSG_CHANNEL_SUCCESS     = 99  // 0x63
SSH_MSG_CHANNEL_FAILURE     = 100 // 0x64
```

## 附录 B: 算法名称映射

| SSH 算法名 | CipherAlgorithm 枚举 | key_len | iv_len | block_len | mac_needed |
|-----------|----------------------|---------|--------|-----------|------------|
| aes128-ctr | Aes128Ctr | 16 | 16 | 16 | yes |
| aes192-ctr | Aes192Ctr | 24 | 16 | 16 | yes |
| aes256-ctr | Aes256Ctr | 32 | 16 | 16 | yes |
| aes128-gcm@openssh.com | Aes128Gcm | 16 | 12 | 16 | no (AEAD) |
| aes256-gcm@openssh.com | Aes256Gcm | 32 | 12 | 16 | no (AEAD) |
| chacha20-poly1305@openssh.com | ChaCha20Poly1305 | 64 | 0 | 64 | no (AEAD) |

| SSH MAC 名 | MacAlgorithm 枚举 | output_len |
|-----------|-------------------|------------|
| hmac-sha1 | HmacSha1 | 20 |
| hmac-sha2-256 | HmacSha256 | 32 |
| hmac-sha2-384 | HmacSha384 | 48 |
| hmac-sha2-512 | HmacSha512 | 64 |

## 参考资料

- RFC 4250 — SSH Protocol Assigned Numbers
- RFC 4251 — SSH Protocol Architecture
- RFC 4252 — SSH Authentication Protocol
- RFC 4253 — SSH Transport Layer Protocol (**最核心**)
- RFC 4254 — SSH Connection Protocol
- RFC 4344 — SSH Transport Layer Encryption Modes
- RFC 4419 — SSH Diffie-Hellman Group Exchange
- RFC 5656 — SSH ECC Algorithm Integration (Curve25519/NISTP256)
- RFC 6668 — SHA-2 Data Integrity for SSH
- RFC 8308 — Extension Negotiation in SSH
- RFC 8731 — Secure Shell (SSH) Key Exchange Method Using Curve25519
- RFC 3526 — MODP Diffie-Hellman groups (Group14 prime)
- [golang.org/x/crypto/ssh](https://github.com/golang/crypto/tree/main/ssh) — 参考实现
- [OpenSSH source](https://github.com/openssh/openssh-portable) — 权威参考
