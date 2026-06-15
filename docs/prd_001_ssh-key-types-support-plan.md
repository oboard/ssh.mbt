# SSH 密钥类型支持扩展计划

## 背景

当前 MoonSSH 客户端仅支持 Ed25519 和 RSA 两种密钥类型。需要扩展支持全部四种标准 SSH 密钥类型：

| 类型 | 算法名 | 状态 |
|------|--------|------|
| DSA | ssh-dss | 🔲 待实现 |
| RSA | ssh-rsa, rsa-sha2-256 | ✅ 已支持 |
| ECDSA | ecdsa-sha2-nistp256/384/521 | 🔲 待实现 |
| Ed25519 | ssh-ed25519 | ✅ 已支持 |

---

## 修改清单

### 1. C FFI 层 (`src/crypto/openssl.c`)

#### 1.1 符号表新增 (L47 宏)

```c
// ECDSA P-384/P-521 需要
IMPORT_FUNC(const EVP_MD *, EVP_sha384, (void))
IMPORT_FUNC(const EVP_MD *, EVP_sha521, (void))
```

#### 1.2 新增 `build_ecdsa_pkey()` 辅助函数

从 EC 参数构建 EVP_PKEY：
- group: "prime256v1" / "secp384r1" / "secp521r1"
- pub: 原始未压缩 EC 点 (04 || x || y)
- priv: 私钥标量 d

#### 1.3 新增 `build_dsa_pkey()` 辅助函数

从 DSA 参数 (p, q, g, y, x) 构建 EVP_PKEY，使用 `OSSL_PARAM_BLD` + `EVP_PKEY_fromdata`。

#### 1.4 扩展 `openssh_decode_plain()` (L938)

新增 DSA 和 ECDSA 分支：

- **`"ssh-dss"`**: 解析 p, q, g, y, x, comment → `build_dsa_pkey()`
- **`"ecdsa-sha2-nistp256/384/521"`**: 解析 curve_id, pub, priv → `build_ecdsa_pkey()`

SSH curve name → OpenSSL group 映射：
- `"nistp256"` → `"prime256v1"` (NID 415, 公钥 65 bytes)
- `"nistp384"` → `"secp384r1"` (NID 715, 公钥 97 bytes)
- `"nistp521"` → `"secp521r1"` (NID 716, 公钥 133 bytes)

#### 1.5 修改 `moonbitlang_ssh_pkey_sign()` (L728)

按 key type 分流：
- **Ed25519 (1087)**: `EVP_DigestSign` 无 digest（现有逻辑）
- **ECDSA (408)**: `EVP_DigestSign` + 对应 digest + DER→raw 转换
- **DSA (116)**: `EVP_DigestSign` + SHA-1
- **RSA (6)**: `EVP_PKEY_sign`（现有逻辑）

#### 1.6 新增签名格式转换

```c
// DER → r||s（ECDSA 签名后转换）
static int ecdsa_der_to_raw(const unsigned char *der, int der_len,
                            unsigned char *out, int out_cap, int key_size);

// r||s → DER（ECDSA 验签前转换）
static int ecdsa_raw_to_der(const unsigned char *raw, int raw_len,
                            unsigned char *out, int out_cap);
```

#### 1.7 新增 FFI 函数

| 函数 | 用途 |
|------|------|
| `pkey_ec_curve_nid()` | 返回 EC curve NID (415/715/716) |
| `pkey_from_ec_point()` | 从 curve name + raw point 构建 EC 公钥 |
| `pkey_from_dsa_components()` | 从 p, q, g, y 构建 DSA 公钥 |
| `pkey_verify()` | 通用验签（RSA/ECDSA/DSA） |

#### 1.8 扩展 `wrap_raw_point_in_spki()` (L406)

支持 P-384 (97 bytes) 和 P-521 (133 bytes) 的 SPKI 包装。

---

### 2. MoonBit 绑定层 (`src/crypto/pkey.mbt`)

#### 2.1 新增 FFI 声明

- `pkey_ec_curve_nid_ffi`
- `pkey_from_ec_point_ffi`
- `pkey_from_dsa_components_ffi`
- `pkey_verify_ffi`（通用验签）

#### 2.2 新增方法

- `PKey::ec_curve_nid()` — 返回 EC curve NID
- `PKey::from_ec_point()` — 从 curve name + raw point 构建 PKey
- `PKey::from_dsa_components()` — 从 p, q, g, y 构建 DSA PKey

#### 2.3 更新 `PKey::verify()`

委托给新的通用 `pkey_verify_ffi`，替代现有的 `rsa_verify_ffi`。

#### 2.4 更新 `PKey::key_id()` 文档

- 6 = RSA
- 116 = DSA
- 408 = EC (ECDSA)
- 1087 = Ed25519

---

### 3. 认证层 (`src/ssh_client.mbt`)

#### 3.1 `Client::auth_publickey()` 修改 (L192-206)

```moonbit
let (pubkey_alg, md_alg) : (String, Int) = match pkey.key_id() {
  1087 => ("ssh-ed25519", 0)
  6    => ("rsa-sha2-256", 2)
  116  => ("ssh-dss", 1)
  408  => {
    let nid = pkey.ec_curve_nid()
    match nid {
      415 => ("ecdsa-sha2-nistp256", 2)
      715 => ("ecdsa-sha2-nistp384", 3)
      716 => ("ecdsa-sha2-nistp521", 4)
      _ => raise ProtocolError("auth: unknown EC curve NID \{nid}")
    }
  }
  other => raise ProtocolError("auth: unsupported key type \{other}")
}
```

---

### 4. KEX 层 (`src/kex.mbt`)

#### 4.1 `server_host_key_algorithms()` (L22)

```moonbit
["ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
 "ssh-ed25519", "rsa-sha2-256", "ssh-rsa", "ssh-dss"]
```

#### 4.2 `parse_host_key_to_pkey()` (L781) — 新增分支

- `"ssh-dss"`: 读取 p, q, g, y → `PKey::from_dsa_components()`
- `"ecdsa-sha2-*"`: 读取 curve_id + raw point → `PKey::from_ec_point()`

#### 4.3 `verify_host_key_signature()` (L763) — md_alg 映射扩展

```moonbit
"ssh-dss"             => 1  // SHA-1
"ecdsa-sha2-nistp256" => 2  // SHA-256
"ecdsa-sha2-nistp384" => 3  // SHA-384
"ecdsa-sha2-nistp521" => 4  // SHA-521
```

---

### 5. Cmd 入口按 key 类型拆分 (`cmd/`)

当前 `cmd/key/` 是一个通用公钥入口。需要拆分为四个独立入口，各自绑定默认密钥路径和端口。

#### 5.1 目标结构

```
cmd/
├── key-ed25519/     # Ed25519 公钥认证
│   ├── main.mbt
│   ├── moon.pkg
│   ├── .env
│   └── run.sh
├── key-rsa/         # RSA 公钥认证
│   ├── main.mbt
│   ├── moon.pkg
│   ├── .env
│   └── run.sh
├── key-ecdsa/       # ECDSA 公钥认证
│   ├── main.mbt
│   ├── moon.pkg
│   ├── .env
│   └── run.sh
├── key-dsa/         # DSA 公钥认证
│   ├── main.mbt
│   ├── moon.pkg
│   ├── .env
│   └── run.sh
├── password/        # 密码认证（保持不变）
│   └── ...
└── output/          # 输出（保持不变）
    └── ...
```

#### 5.2 各入口 `.env` 配置

```bash
# key-ed25519/.env
MSSH_HOST="127.0.0.1"
MSSH_PORT="2022"
MSSH_USERNAME="admin"

# key-rsa/.env
MSSH_HOST="127.0.0.1"
MSSH_PORT="3022"
MSSH_USERNAME="admin"

# key-ecdsa/.env
MSSH_HOST="127.0.0.1"
MSSH_PORT="4022"
MSSH_USERNAME="admin"

# key-dsa/.env
MSSH_HOST="127.0.0.1"
MSSH_PORT="5022"
MSSH_USERNAME="admin"
```

#### 5.3 各入口 `run.sh` 示例

```bash
# key-ed25519/run.sh
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --exec 'uname -a' --key /workspace/scripts/ssh-server/id_ed25519"

# key-rsa/run.sh
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --exec 'uname -a' --key /workspace/scripts/ssh-server/id_rsa"

# key-ecdsa/run.sh
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --exec 'uname -a' --key /workspace/scripts/ssh-server/id_ecdsa"

# key-dsa/run.sh
export MOONBIT_CLI_ARGS="$MSSH_USERNAME@$MSSH_HOST --port $MSSH_PORT --exec 'uname -a' --key /workspace/scripts/ssh-server/id_dsa"
```

#### 5.4 各入口 `main.mbt` 和 `moon.pkg`

`main.mbt` 内容与现有 `cmd/key/main.mbt` 完全相同（通用公钥认证逻辑，通过 `--key` 参数指定密钥）。

`moon.pkg` 与现有 `cmd/key/moon.pkg` 相同：
```moonbit
import {
  "moonbitlang/core/env",
  "PaiGack/ssh_client/src",
}

options(
  is_main: true,
  supported_targets: "+native",
)
```

#### 5.5 删除旧 `cmd/key/`

拆分完成后删除 `cmd/key/` 目录，由四个新入口替代。

---

### 6. 测试脚本 (`scripts/ssh-server/`)

#### 6.1 新增 `key-ecdsa.sh`

```bash
#!/bin/bash
set -e
# ssh -i id_ecdsa admin@127.0.0.1 -p 4022
rm -f id_ecdsa id_ecdsa.pub
ssh-keygen -t ecdsa -b 256 -N "" -f id_ecdsa
publickey=$(cat id_ecdsa.pub)
docker rm -f openssh-server_key_ecdsa
docker run -d \
  --name=openssh-server_key_ecdsa \
  --hostname=openssh-server_key_ecdsa \
  -e PUID=1000 -e PGID=1000 -e TZ=Etc/UTC \
  -e PUBLIC_KEY="$publickey" \
  -e SUDO_ACCESS=true -e USER_NAME=admin \
  -p 4022:2222 \
  lscr.io/linuxserver/openssh-server:latest
```

#### 6.2 新增 `key-dsa.sh`

```bash
#!/bin/bash
set -e
# ssh -i id_dsa admin@127.0.0.1 -p 5022
rm -f id_dsa id_dsa.pub
ssh-keygen -t dsa -N "" -f id_dsa
publickey=$(cat id_dsa.pub)
docker rm -f openssh-server_key_dsa
docker run -d \
  --name=openssh-server_key_dsa \
  --hostname=openssh-server_key_dsa \
  -e PUID=1000 -e PGID=1000 -e TZ=Etc/UTC \
  -e PUBLIC_KEY="$publickey" \
  -e SUDO_ACCESS=true -e USER_NAME=admin \
  -p 5022:2222 \
  lscr.io/linuxserver/openssh-server:latest
```

---

## 关键技术细节

| 密钥类型 | EVP_PKEY ID | SSH 算法名 | 签名 digest | 签名格式 |
|----------|-------------|-----------|------------|---------|
| RSA | 6 | ssh-rsa / rsa-sha2-256 | SHA-1 / SHA-256 | PKCS#1 |
| DSA | 116 | ssh-dss | SHA-1 | DER (r,s) |
| ECDSA | 408 | ecdsa-sha2-nistp256/384/521 | SHA-256/384/521 | r\|\|s 固定宽度 |
| Ed25519 | 1087 | ssh-ed25519 | (内置) | 64 字节 |

### EC 曲线映射

| SSH curve | OpenSSL group | NID | 公钥点大小 | 私钥大小 |
|-----------|--------------|-----|----------|---------|
| nistp256 | prime256v1 | 415 | 65 bytes | 32 bytes |
| nistp384 | secp384r1 | 715 | 97 bytes | 48 bytes |
| nistp521 | secp521r1 | 716 | 133 bytes | 66 bytes |

---

## 执行顺序

1. `src/crypto/openssl.c` — C 层改动（核心，最大）
2. `src/crypto/pkey.mbt` — FFI 绑定更新
3. `src/ssh_client.mbt` — 认证逻辑扩展
4. `src/kex.mbt` — KEX host key 算法扩展
5. `cmd/key-*` — 按 key 类型拆分入口目录
6. `scripts/ssh-server/` — 测试脚本
7. 删除旧 `cmd/key/`

## 验证方式

1. `moon build` 编译通过
2. 启动各类型 Docker 测试容器
3. 使用对应 cmd 入口 + 密钥进行 SSH 连接测试
