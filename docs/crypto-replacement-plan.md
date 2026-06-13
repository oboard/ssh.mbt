# Crypto 模块替换方案

> 将 OpenSSL 依赖替换为 MoonBit 原生实现

## 目录

- [当前架构分析](#当前架构分析)
- [需要替换的加密原语](#需要替换的加密原语)
- [推荐的替换策略](#推荐的替换策略)
- [具体实现建议](#具体实现建议)
- [注意事项](#注意事项)
- [快速启动建议](#快速启动建议)

---

## 当前架构分析

项目的 crypto 模块完全依赖 OpenSSL，通过以下方式调用：

```
src/crypto/
├── openssl.c              # 666 行 C FFI 绑定代码
├── openssl_loader.mbt     # 动态加载 libcrypto
├── digest.mbt             # SHA-1/SHA-256 哈希
├── mac.mbt                # HMAC-SHA1/HMAC-SHA256
├── cipher.mbt             # AES-128-CTR 对称加密
├── kex.mbt                # DH Group14 密钥交换
├── pkey.mbt               # RSA 签名/验证 + ECDH P-256
└── crypto_util.mbt        # 随机数生成和错误处理
```

### OpenSSL 依赖关系

```
所有 crypto 操作
    ↓
openssl_loader.mbt::ensure_openssl()
    ↓
load_openssl_ffi() [C FFI]
    ↓
动态加载 libcrypto.so/dll
    ↓
134 个 OpenSSL 函数指针
```

---

## 需要替换的加密原语

### 1️⃣ 易于替换（建议优先实现）

| 算法 | 当前实现 | 文件位置 | 替换方案 | 难度 | 估计工作量 |
|------|---------|---------|---------|------|-----------|
| **SHA-1** | OpenSSL `EVP_sha1` | `digest.mbt:11` | 纯 MoonBit 实现 | ⭐️ 低 | 2-3 天 |
| **SHA-256** | OpenSSL `EVP_sha256` | `digest.mbt:17` | 纯 MoonBit 实现 | ⭐️ 低 | 2-3 天 |
| **HMAC** | OpenSSL `HMAC` | `mac.mbt:36` | 基于 SHA 的实现 | ⭐️ 低 | 1 天 |
| **AES-128-CTR** | OpenSSL `EVP_aes_128_ctr` | `cipher.mbt:40` | 纯 MoonBit 实现 | ⭐️⭐️ 中 | 5-7 天 |

### 2️⃣ 中等难度

| 算法 | 当前实现 | 文件位置 | 替换方案 | 难度 | 估计工作量 |
|------|---------|---------|---------|------|-----------|
| **DH Group14** | OpenSSL `BIGNUM` + `@bigint` | `kex.mbt:55` | 完全迁移到 `@bigint.BigInt` | ⭐️⭐️ 中 | 2-3 天 |
| **随机数生成** | OpenSSL `RAND_bytes` | `crypto_util.mbt:4` | OS 系统调用（轻量 FFI） | ⭐️⭐️ 中 | 1-2 天 |

### 3️⃣ 困难（可选/长期目标）

| 算法 | 当前实现 | 文件位置 | 替换方案 | 难度 | 估计工作量 |
|------|---------|---------|---------|------|-----------|
| **ECDH P-256** | OpenSSL `EVP_PKEY` | `pkey.mbt:199` | 椭圆曲线算法库 | ⭐️⭐️⭐️⭐️ 高 | 2-3 周 |
| **RSA 签名/验证** | OpenSSL `EVP_PKEY` | `pkey.mbt:159` | RSA + PKCS#1 v1.5 | ⭐️⭐️⭐️⭐️ 高 | 2-3 周 |

---

## 推荐的替换策略

### 方案 A：渐进式替换（推荐）

逐步移除 OpenSSL 依赖，最终实现完全独立。

```
阶段 1: 哈希和 MAC（无 OpenSSL 依赖）
├─ SHA-1 纯 MoonBit 实现           [2-3 天]
├─ SHA-256 纯 MoonBit 实现         [2-3 天]
└─ HMAC 纯 MoonBit 实现            [1 天]
   → 可移除 OpenSSL digest/HMAC 依赖

阶段 2: 对称加密
└─ AES-128-CTR 纯 MoonBit 实现     [5-7 天]
   → 可移除 OpenSSL cipher 依赖

阶段 3: 密钥交换
├─ DH Group14 完全使用 @bigint     [2-3 天]
└─ 系统随机数（轻量 FFI）          [1-2 天]
   → 可移除 OpenSSL BIGNUM/RAND 依赖

阶段 4: 公钥算法（可选）
├─ 引入第三方椭圆曲线库            [2-3 周]
└─ RSA 实现                        [2-3 周]
   → 完全移除 OpenSSL 依赖
```

### 方案 B：混合模式

保留 OpenSSL 作为可选后端，同时提供纯 MoonBit 实现。

```moonbit
// crypto/backend.mbt
pub enum Backend {
  Pure      // 纯 MoonBit 实现
  OpenSSL   // OpenSSL FFI（fallback）
}

pub let current_backend : Ref[Backend] = Ref(Pure)

pub fn set_backend(backend : Backend) -> Unit {
  current_backend.val = backend
}
```

**优点：**
- 平滑过渡，可逐个算法切换
- 保留性能优势（OpenSSL 通常更快）
- 降低风险（可回退到 OpenSSL）

**缺点：**
- 维护两套实现
- 仍需分发 OpenSSL 依赖

---

## 具体实现建议

### 1. SHA-256 实现

```moonbit
// crypto/sha256_pure.mbt

/// SHA-256 状态
pub struct Sha256 {
  state : FixedArray[UInt]     // 8 个 32-bit 状态 (H0-H7)
  buffer : Array[Byte]          // 输入缓冲区（最多 64 字节）
  total_len : UInt64            // 总字节数
}

/// 创建新的 SHA-256 哈希器
pub fn Sha256::new() -> Sha256 {
  let state = FixedArray::from_array([
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
  ])
  { state, buffer: [], total_len: 0UL }
}

/// 更新哈希
pub fn Sha256::update(self : Sha256, data : Bytes) -> Unit {
  for b in data {
    self.buffer.push(b)
    if self.buffer.length() == 64 {
      self.process_block()
      self.buffer.clear()
    }
  }
  self.total_len = self.total_len + data.length().to_uint64()
}

/// 最终化并输出 32 字节哈希值
pub fn Sha256::finalize(self : Sha256) -> Bytes {
  // 1. 填充：添加 0x80，然后补零到 56 字节，最后 8 字节是长度
  self.buffer.push(0x80)
  while self.buffer.length() % 64 != 56 {
    self.buffer.push(0x00)
  }
  
  // 2. 添加原始消息长度（以 bits 为单位，大端序）
  let bit_len = self.total_len * 8UL
  for i in 0..8 {
    self.buffer.push((bit_len >> (56 - i * 8)).to_byte())
  }
  
  // 3. 处理最后的块
  while self.buffer.length() > 0 {
    self.process_block()
  }
  
  // 4. 输出状态（大端序）
  let result = FixedArray::make(32, b'\x00')
  for i in 0..8 {
    let h = self.state[i]
    result[i * 4 + 0] = (h >> 24).to_byte()
    result[i * 4 + 1] = (h >> 16).to_byte()
    result[i * 4 + 2] = (h >> 8).to_byte()
    result[i * 4 + 3] = h.to_byte()
  }
  Bytes::from_array(result)
}

/// 处理 512-bit (64 字节) 块
fn Sha256::process_block(self : Sha256) -> Unit {
  // SHA-256 压缩函数
  // 1. 准备消息调度表 W[0..63]
  // 2. 初始化工作变量 a-h
  // 3. 64 轮主循环
  // 4. 更新状态
  // 实现细节参考 RFC 6234
}

/// 一次性哈希
pub fn sha256(data : Bytes) -> Bytes {
  let h = Sha256::new()
  h.update(data)
  h.finalize()
}
```

**测试向量（RFC 4634）：**

```moonbit
test "SHA-256 empty string" {
  let hash = sha256(b"")
  assert_eq!(
    hash.to_hex(),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  )
}

test "SHA-256 'abc'" {
  let hash = sha256(b"abc")
  assert_eq!(
    hash.to_hex(),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  )
}
```

---

### 2. HMAC 实现

基于 SHA-256 的 HMAC（RFC 2104）：

```moonbit
// crypto/hmac_pure.mbt

pub fn hmac_sha256(key : Bytes, message : Bytes) -> Bytes {
  let block_size = 64  // SHA-256 块大小
  let output_size = 32  // SHA-256 输出大小
  
  // 1. 如果 key 太长，先哈希它
  let key_adjusted = if key.length() > block_size {
    sha256(key)
  } else {
    key
  }
  
  // 2. 补零到块大小
  let key_padded = pad_to_size(key_adjusted, block_size)
  
  // 3. 计算 inner 和 outer padding
  let i_key_pad = xor_bytes(key_padded, 0x36)  // ipad = 0x36 repeated
  let o_key_pad = xor_bytes(key_padded, 0x5c)  // opad = 0x5c repeated
  
  // 4. HMAC = H(o_key_pad || H(i_key_pad || message))
  let inner_hash = sha256(concat_bytes(i_key_pad, message))
  sha256(concat_bytes(o_key_pad, inner_hash))
}

fn xor_bytes(data : Bytes, byte : Byte) -> Bytes {
  let arr = data.to_fixedarray()
  FixedArray::makei(arr.length(), fn(i) { arr[i] ^ byte })
  |> Bytes::from_array
}
```

---

### 3. AES-128-CTR 实现

```moonbit
// crypto/aes_pure.mbt

/// AES-128 加密状态
struct AesState {
  round_keys : FixedArray[UInt32]  // 44 个 32-bit 字（11 轮）
  counter : FixedArray[Byte]        // 16 字节计数器
}

/// AES-128 密钥扩展
fn aes_key_expansion(key : Bytes) -> FixedArray[UInt32] {
  // 实现 AES-128 密钥调度算法
  // 从 16 字节密钥生成 44 个 32-bit 轮密钥
  // 参考：FIPS 197
}

/// AES 加密单个块（16 字节）
fn aes_encrypt_block(round_keys : FixedArray[UInt32], block : Bytes) -> Bytes {
  // 1. AddRoundKey (初始轮)
  // 2. 9 轮：SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
  // 3. 最后一轮：SubBytes -> ShiftRows -> AddRoundKey
  // 参考：FIPS 197
}

/// AES-128-CTR 加密/解密（相同操作）
pub fn aes_128_ctr_crypt(
  key : Bytes,
  iv : Bytes,
  data : Bytes
) -> Bytes {
  if key.length() != 16 { abort("key must be 16 bytes") }
  if iv.length() != 16 { abort("iv must be 16 bytes") }
  
  let round_keys = aes_key_expansion(key)
  let counter = iv.to_fixedarray().to_array()  // 可变计数器
  let result = []
  
  let mut offset = 0
  while offset < data.length() {
    // 1. 加密计数器
    let keystream_block = aes_encrypt_block(
      round_keys,
      Bytes::from_array(FixedArray::from_array(counter))
    )
    
    // 2. XOR 数据块
    let block_size = min(16, data.length() - offset)
    for i in 0..<block_size {
      result.push(data[offset + i] ^ keystream_block[i])
    }
    
    // 3. 递增计数器（大端序）
    increment_counter(counter)
    offset = offset + 16
  }
  
  Bytes::from_array(FixedArray::from_array(result))
}

fn increment_counter(counter : Array[Byte]) -> Unit {
  // 从最低字节开始递增（大端序）
  for i in 15..0 by -1 {
    counter[i] = counter[i] + 1
    if counter[i] != 0 { break }  // 无进位，停止
  }
}
```

---

### 4. DH Group14 改造

当前代码已部分使用 `@bigint.BigInt`，只需移除 OpenSSL BIGNUM 依赖：

```moonbit
// crypto/kex_pure.mbt

// ✅ 保留：已经是纯 MoonBit
pub fn dh_group14_prime() -> @bigint.BigInt { /* ... */ }
pub fn dh_group14_generator() -> @bigint.BigInt { /* ... */ }
pub fn dh_group14_keygen(x : @bigint.BigInt) -> (@bigint.BigInt, @bigint.BigInt)
pub fn dh_group14_shared(x : @bigint.BigInt, peer_pub : @bigint.BigInt) -> @bigint.BigInt

// ❌ 移除：OpenSSL BIGNUM FFI
// - bn_from_bytes
// - bn_to_bytes
// - bn_to_mpint
// - bn_mod_exp
// - bn_rand_range

// ✅ 替换为：
pub fn bigint_to_bytes(bn : @bigint.BigInt, size : Int) -> Bytes {
  // 使用 @bigint.BigInt 内置方法
}

pub fn bigint_from_bytes(bytes : Bytes) -> @bigint.BigInt {
  // 使用 @bigint.BigInt::from_bytes
}
```

---

### 5. 系统随机数生成（轻量 FFI）

不依赖 OpenSSL，直接调用 OS API：

```c
// crypto/random_os.c

#ifdef _WIN32
  #include <windows.h>
  #include <bcrypt.h>
  #pragma comment(lib, "bcrypt.lib")
  
  int moonssh_rand_bytes(unsigned char *buf, int num) {
    NTSTATUS status = BCryptGenRandom(
      NULL,  // 默认算法提供者
      buf,
      (ULONG)num,
      BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    return status == 0 ? 1 : 0;
  }
  
#else  // Unix/Linux/macOS
  #include <fcntl.h>
  #include <unistd.h>
  
  int moonssh_rand_bytes(unsigned char *buf, int num) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    
    int total_read = 0;
    while (total_read < num) {
      int r = read(fd, buf + total_read, num - total_read);
      if (r <= 0) {
        close(fd);
        return 0;
      }
      total_read += r;
    }
    
    close(fd);
    return 1;
  }
#endif
```

MoonBit 绑定：

```moonbit
// crypto/random_pure.mbt

#borrow(buf)
extern "C" fn rand_bytes_os_ffi(
  buf : FixedArray[Byte],
  num : Int
) -> Int = "moonssh_rand_bytes"

pub fn rand_bytes(num : Int) -> Bytes raise CryptoError {
  let result = FixedArray::make(num, b'\x00')
  let rc = rand_bytes_os_ffi(result, num)
  if rc != 1 {
    raise CryptoError::RandomFailed("OS random failed")
  }
  Bytes::from_array(result)
}
```

---

## 注意事项

### 🔒 安全性

1. **常量时间比较**：防止时序攻击

```moonbit
/// 常量时间字节数组比较
fn constant_time_compare(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() { return false }
  
  let mut result = 0
  for i in 0..<a.length() {
    result = result | (a[i].to_int() ^ b[i].to_int())
  }
  result == 0
}
```

2. **敏感数据清零**：使用后立即清除

```moonbit
fn secure_zero(arr : FixedArray[Byte]) -> Unit {
  for i in 0..<arr.length() {
    arr[i] = b'\x00'
  }
}
```

3. **专业审计**：加密算法实现需要安全专家审计

### ⚡ 性能

| 算法 | OpenSSL | 纯 MoonBit 预估 | 差距 |
|------|---------|----------------|------|
| SHA-256 | 基准线 | 2-5x 慢 | 可接受 |
| AES-128 | 基准线（硬件加速） | 5-10x 慢 | 需优化 |
| HMAC | 基准线 | 2-5x 慢 | 可接受 |

**优化方向：**
- 使用查找表（S-box）
- 批量处理
- SIMD 指令（如果 MoonBit 支持）

### ✅ 测试

每个算法都需要：

1. **标准测试向量**（RFC/NIST）
2. **边界条件测试**
3. **互操作性测试**（与 OpenSSL 对比）
4. **性能基准测试**

```moonbit
// 测试向量示例
test "SHA-256 NIST test vector 1" {
  let input = b"abc"
  let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  assert_eq!(sha256(input).to_hex(), expected)
}

test "AES-128-CTR NIST SP 800-38A" {
  let key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c")
  let iv = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
  let plaintext = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a")
  let expected = hex_to_bytes("874d6191b620e3261bef6864990db6ce")
  
  let ciphertext = aes_128_ctr_crypt(key, iv, plaintext)
  assert_eq!(ciphertext, expected)
}
```

---

## 快速启动建议

### 第一步：实现 SHA-256

1. **创建文件**：`src/crypto/sha256_pure.mbt`
2. **参考标准**：[RFC 6234](https://datatracker.ietf.org/doc/html/rfc6234)
3. **测试向量**：[NIST CAVP](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program)
4. **对照实现**：与 OpenSSL 输出逐字节比较

### 第二步：实现 HMAC-SHA256

1. **基于 SHA-256**：复用上一步的实现
2. **参考标准**：[RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104)
3. **测试**：确保与 OpenSSL HMAC 结果一致

### 第三步：切换 digest 和 mac 模块

```moonbit
// crypto/digest.mbt
pub fn digest(alg : Algorithm, data : Bytes) -> Bytes raise CryptoError {
  match alg {
    Sha256 => sha256_pure::sha256(data)  // ← 切换到纯实现
    Sha1 => digest_openssl(alg, data)     // ← 暂时保留 OpenSSL
  }
}
```

### 第四步：性能测试和优化

```moonbit
fn benchmark_sha256() -> Unit {
  let data = Bytes::make(1024 * 1024, b'\x00')  // 1 MB
  
  let start = @time.now()
  for _ in 0..<100 {
    let _ = sha256(data)
  }
  let elapsed = @time.now() - start
  
  println("SHA-256 throughput: \{100.0 / elapsed} MB/s")
}
```

---

## 参考资源

### 标准文档

- [RFC 6234](https://datatracker.ietf.org/doc/html/rfc6234) - SHA-1/SHA-256
- [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) - HMAC
- [FIPS 197](https://csrc.nist.gov/publications/detail/fips/197/final) - AES
- [RFC 3526](https://datatracker.ietf.org/doc/html/rfc3526) - DH Group14

### 测试向量

- [NIST CAVP](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program)
- [Wycheproof](https://github.com/google/wycheproof) - Google 加密测试套件

### 参考实现

- [RustCrypto](https://github.com/RustCrypto) - Rust 纯实现
- [Tink](https://github.com/google/tink) - Google 加密库
- [Monocypher](https://monocypher.org/) - 轻量级 C 实现

---

## 进度追踪

- [ ] 阶段 1：哈希和 MAC
  - [ ] SHA-256 实现
  - [ ] SHA-1 实现
  - [ ] HMAC 实现
  - [ ] 测试向量验证
  - [ ] 性能基准测试
- [ ] 阶段 2：对称加密
  - [ ] AES-128-CTR 实现
  - [ ] 测试向量验证
  - [ ] 性能优化
- [ ] 阶段 3：密钥交换
  - [ ] DH Group14 纯 @bigint 实现
  - [ ] 系统随机数 FFI
  - [ ] 移除 OpenSSL BIGNUM 依赖
- [ ] 阶段 4：公钥算法（可选）
  - [ ] ECDH P-256 调研
  - [ ] RSA 调研
  - [ ] 第三方库集成

---