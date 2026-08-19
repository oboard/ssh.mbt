# `golang.org/x/crypto/ssh` 功能对齐计划

目标参考版本：`golang.org/x/crypto@v0.55.0/ssh`。

本项目不会复制 Go API 的名称或并发模型；目标是对齐其 SSHv2 协议能力，并为 MoonBit 提供等价、异步且类型安全的 API。

## 当前基线

已存在：客户端 banner/KEX/认证、基本 channel、exec/shell、SFTP v3、三种 TCP 转发，以及基础 `known_hosts` 解析。TCP 已迁移到 `moonbitlang/async/socket`。

当前 `src/crypto/openssl.c` 仍承担 SSH 密码学。其移除要求下述纯 MoonBit crypto 和 key parser 里程碑完成，不能先删除。

## 已引入的纯 MoonBit 密码学依赖

| 库 | 可用能力 | 结论 |
| --- | --- | --- |
| `cc06b/mooncry@0.20.0` | SHA-1/SHA-2、HMAC-SHA1/SHA256、AES-CTR、RSA-SHA256、Ed25519、X25519 | 主密码学候选 |
| `Tigls/mb-p256@0.1.0` | P-256 ECDH、P-256 ECDSA、SEC1 非压缩点 | `ecdh-sha2-nistp256` 候选 |
| `gmlewis/sha1@0.12.11` | SHA-1 | 冗余；mooncry 已有 SHA-1/HMAC-SHA1 |
| `Rutubet/moon_rsa@0.2.0` | RSA key generation | 冗余；签名/验签仍是 roadmap |

`moonbitlang/core/random` 的 `Rand` 是可播种的通用 PRNG，不能未经系统熵验证而作为 SSH CSPRNG。

## 阶段 1：纯 MoonBit crypto 与 key support

- [ ] 新建 crypto provider abstraction，支持哈希、HMAC、AES-CTR、签名和密钥交换。
- [ ] 接入 mooncry：SHA-1/SHA-256、HMAC-SHA1/HMAC-SHA256、AES-CTR、Ed25519、RSA-SHA256、X25519。
- [ ] 接入 mb-p256：P-256 ECDH 及 `ecdsa-sha2-nistp256`。
- [ ] 选择并接入 OS CSPRNG（macOS/Linux/Windows）；在未完成前保留现有随机数来源。
- [ ] 实现 `openssh-key-v1` 未加密私钥解析：Ed25519、RSA、ECDSA P-256。
- [ ] 实现 SSH public-key blob、authorized_keys 文本与 signature blob 编解码。
- [ ] 实现加密 OpenSSH 私钥所需的 `bcrypt_pbkdf`，或明确返回不支持错误。
- [ ] 降级/移除无纯 MoonBit 支持且不推荐的算法：DSA、RSA-SHA1、ECDSA P-384/P-521（除非后续补齐）。

验收：与 OpenSSH 对 `curve25519-sha256` / `ecdh-sha2-nistp256`、`ssh-ed25519` / `rsa-sha2-256` / `ecdsa-sha2-nistp256`、`aes128-ctr`、`hmac-sha2-256` 互通；移除本项目 OpenSSL FFI 后原生检查和测试通过。

## 阶段 2：SSH transport、handshake 与 client

对应 Go：`transport.go`、`handshake.go`、`client.go`、`client_auth.go`、`cipher.go`、`mac.go`、`kex.go`。

- [ ] 完整 rekey（按字节数和时间阈值）。
- [ ] algorithm negotiation、`first_kex_packet_follows`、strict-KEX/ext-info。
- [ ] 现代 KEX：curve25519-sha256 与 P-256 ECDH；可选 group14 兼容。
- [ ] 客户端 auth method pipeline、auth banners、partial success。
- [ ] 全局请求调度、keepalive、disconnect 语义。

## 阶段 3：mux、channel、session、forwarding

对应 Go：`mux.go`、`channel.go`、`session.go`、`tcpip.go`、`streamlocal.go`。

- [ ] 多通道注册表与独立的异步读写任务。
- [ ] channel request/reply 流、窗口背压、EOF/CLOSE、扩展数据。
- [ ] Session：PTY、环境变量、exec、shell、subsystem、signal、window-change、exit-status/signal。
- [ ] TCP/IP forwarding：listen、dial、cancel、remote/local forwarding。
- [ ] streamlocal forwarding。

## 阶段 4：server

对应 Go：`server.go`、`connection.go`、`messages.go`。

- [ ] `ServerConfig`：host keys、版本、banner、auth 尝试限制。
- [ ] none/password/publickey/keyboard-interactive auth callbacks。
- [ ] server handshake/KEX/host-key signing、permissions/extensions。
- [ ] accepted channels、global requests、session request handler helpers。
- [ ] auth 日志与 pre-auth callback。
- [ ] 可选：GSSAPI-with-MIC。

## 阶段 5：keys、certificates、known_hosts

对应 Go：`keys.go`、`certs.go`、`knownhosts/knownhosts.go`。

- [ ] AuthorizedKeys 的 quoted options / restrictions。
- [ ] known_hosts 的 hashed host (`|1|...`)、markers（revoked / cert-authority）、端口格式、文件行号错误。
- [ ] OpenSSH user/host certificate parse、marshal、verify、certificate checker。
- [ ] PEM / PKCS#1 / PKCS#8（未加密优先）；加密 PEM 后续支持。
- [ ] 安全密钥（sk-ssh-ed25519 / sk-ecdsa）视平台 API 决定是否实现。

## 阶段 6：agent 与 terminal

对应 Go：`agent/`、`terminal/terminal.go`。

- [ ] SSH agent wire protocol：list, sign, add, remove, lock, extension。
- [ ] 本地 keyring、client/server over async Unix socket；Windows named pipe 适配。
- [ ] agent forwarding request 与 channel proxy。
- [ ] terminal package：raw mode、restore、size、password input、VT100 line editor。

说明：Go v0.55 的 `ssh/terminal` 实际是 `golang.org/x/term` 的 deprecated forwarding wrapper；MoonBit 实现应提供等价终端能力，而不是仅复制 wrapper。

## 非核心或后续特性

- [ ] SSH certificates
- [ ] GSSAPI-with-MIC
- [ ] ML-KEM hybrid KEX
- [ ] FIPS policy mode
- [ ] streamlocal forwarding
- [ ] security key / FIDO support

## 验证策略

每阶段均要求：

```sh
moon fmt
moon info --target native
moon check --target native
moon test --target native
```

并新增针对 OpenSSH server/client 的互操作测试。协议和密码学改动必须包含 RFC/OpenSSH 测试向量；不能只依赖本项目内部 round-trip。
