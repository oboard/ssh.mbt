///|
/// 公钥操作封装。包含：
/// - RSA 签名/验签（ssh-rsa, rsa-sha2-256）
/// - Ed25519 签名（ssh-ed25519）
/// - PEM 加载（PKCS#1 / PKCS#8 / traditional）
/// - OpenSSH 私钥格式加载（openssh-key-v1，未加密）
/// - ECDH P-256 密钥生成和派生
#external
type Pkey

///|
extern "C" fn pkey_new_ffi() -> Pkey = "moonbitlang_ssh_pkey_new"

///|
extern "C" fn pkey_free_ffi(p : Pkey) = "moonbitlang_ssh_pkey_free"

///|
extern "C" fn pkey_size_ffi(p : Pkey) -> Int = "moonbitlang_ssh_pkey_size"

///|
extern "C" fn pkey_id_ffi(p : Pkey) -> Int = "moonbitlang_ssh_pkey_id"

///|
#borrow(tbs, sig, sig_len)
extern "C" fn pkey_sign_ffi(
  p : Pkey,
  md_alg : Int,
  tbs : Bytes,
  tbs_len : Int,
  sig : FixedArray[Byte],
  sig_len : Ref[Int],
) -> Int = "moonbitlang_ssh_pkey_sign"

///|
#borrow(path, out)
extern "C" fn load_private_key_ffi(
  path : Bytes,
  path_len : Int,
  out : Ref[Pkey],
) -> Int = "moonbitlang_ssh_load_private_key"

///|
#borrow(path, out)
extern "C" fn pem_read_public_key_ffi(
  path : Bytes,
  path_len : Int,
  out : Ref[Pkey],
) -> Int = "moonbitlang_ssh_pem_read_public_key"

///|
#borrow(name, buf, out_len)
extern "C" fn pkey_get_octet_param_ffi(
  p : Pkey,
  name : Bytes,
  name_len : Int,
  buf : FixedArray[Byte],
  buf_len : Int,
  out_len : Ref[Int],
) -> Int = "moonbitlang_ssh_pkey_get_octet_param"

///|
#borrow(name, buf, out_len)
extern "C" fn pkey_get_bn_bytes_ffi(
  p : Pkey,
  name : Bytes,
  name_len : Int,
  buf : FixedArray[Byte],
  buf_len : Int,
  out_len : Ref[Int],
) -> Int = "moonbitlang_ssh_pkey_get_bn_bytes"

///|
#borrow(src, out, out_len)
extern "C" fn base64_decode_ffi(
  src : Bytes,
  src_len : Int,
  out : FixedArray[Byte],
  out_len : Ref[Int],
) -> Int = "moonbitlang_ssh_base64_decode"

///|
#borrow(path, alg_buf, alg_len, blob, blob_len)
extern "C" fn read_openssh_pubkey_ffi(
  path : Bytes,
  path_len : Int,
  alg_buf : FixedArray[Byte],
  alg_cap : Int,
  alg_len : Ref[Int],
  blob : FixedArray[Byte],
  blob_cap : Int,
  blob_len : Ref[Int],
) -> Int = "moonbitlang_ssh_read_openssh_pubkey"

// ECDH P-256

///|
#borrow(priv_out, pub_buf, pub_len)
extern "C" fn ecdh_gen_key_ffi(
  priv_out : Ref[Pkey],
  pub_buf : FixedArray[Byte],
  pub_len : Ref[Int],
) -> Int = "moonbitlang_ssh_ecdh_gen_key"

///|
#borrow(peer_pub, out, out_len)
extern "C" fn ecdh_derive_ffi(
  our : Pkey,
  peer_pub : Bytes,
  peer_len : Int,
  out : FixedArray[Byte],
  out_len : Ref[Int],
) -> Int = "moonbitlang_ssh_ecdh_derive"

///|
#borrow(n, e, d, out)
extern "C" fn pkey_new_rsa_ffi(
  n : Bytes,
  n_len : Int,
  e : Bytes,
  e_len : Int,
  d : Bytes,
  d_len : Int,
  out : Ref[Pkey],
) -> Int = "moonbitlang_ssh_pkey_new_rsa"

///|
/// 公钥/私钥对象包装（基于 OpenSSL EVP_PKEY）。
/// 支持 RSA、DSA、ECDSA、Ed25519 等算法。
pub struct PKey {
  ptr : Pkey
}

///|
/// 加载私钥。
/// 自动检测 PEM（PKCS#1/PKCS#8/传统）和 OpenSSH `openssh-key-v1` 格式。
/// 目前仅支持未加密的私钥。
pub fn PKey::load_private_key(path : String) -> PKey raise CryptoError {
  ensure_openssl()
  let out : Ref[Pkey] = Ref(pkey_new_ffi())
  let path_bytes = @utf8.encode(path)
  let rc = load_private_key_ffi(path_bytes, path_bytes.length(), out)
  if rc != 1 {
    pkey_free_ffi(out.val)
    raise CryptoError::OperationFailed(
      "load_private_key (PEM or OPENSSH)",
      err_get_and_clear(),
    )
  }
  { ptr: out.val }
}

///|
/// 从 PEM 文件加载公钥。
pub fn PKey::load_public_key(path : String) -> PKey raise CryptoError {
  ensure_openssl()
  let out : Ref[Pkey] = Ref(pkey_new_ffi())
  let path_bytes = @utf8.encode(path)
  let rc = pem_read_public_key_ffi(path_bytes, path_bytes.length(), out)
  if rc != 1 {
    pkey_free_ffi(out.val)
    raise CryptoError::OperationFailed(
      "PEM_read_bio_PUBKEY",
      err_get_and_clear(),
    )
  }
  { ptr: out.val }
}

///|
/// 从 RSA 公钥组件（模数 n、指数 e）构建仅公钥 PKey。
/// 用于 host key 验证。
pub fn PKey::from_rsa_components(
  n : Bytes,
  e : Bytes,
) -> PKey raise CryptoError {
  ensure_openssl()
  let out : Ref[Pkey] = Ref(pkey_new_ffi())
  let d = b""
  let rc = pkey_new_rsa_ffi(n, n.length(), e, e.length(), d, 0, out)
  if rc != 1 {
    pkey_free_ffi(out.val)
    raise CryptoError::OperationFailed("RSA fromdata", err_get_and_clear())
  }
  { ptr: out.val }
}

///|
/// 释放密钥资源。
pub fn PKey::close(self : PKey) -> Unit {
  pkey_free_ffi(self.ptr)
}

///|
/// 返回密钥的字节大小。
pub fn PKey::size(self : PKey) -> Int {
  pkey_size_ffi(self.ptr)
}

///|
/// 返回 OpenSSL `EVP_PKEY_get_id()` 的结果：
///   6    -> RSA
///   116  -> DSA
///   408  -> EC (ECDSA)
///   1087 -> Ed25519
pub fn PKey::key_id(self : PKey) -> Int {
  pkey_id_ffi(self.ptr)
}

///|
/// 通用签名。
/// `md_alg`：
///   0 -> 使用密钥自己的签名方案（EdDSA 用于 ed25519）
///   1 -> SHA-1
///   2 -> SHA-256
///   3 -> SHA-384
///   4 -> SHA-521
/// 输出格式：
///   Ed25519 -> 64 字节
///   RSA     -> 与 key 大小一致
///   DSA     -> DER 编码
///   ECDSA   -> r||s 固定宽度
pub fn PKey::sign(
  self : PKey,
  md_alg : Int,
  data : Bytes,
) -> Bytes raise CryptoError {
  let sig_cap = 1024
  let arr = FixedArray::make(sig_cap, b'\x00')
  let sig_len = Ref(sig_cap)
  let rc = pkey_sign_ffi(self.ptr, md_alg, data, data.length(), arr, sig_len)
  if rc != 1 {
    raise CryptoError::OperationFailed("EVP_PKEY_sign", err_get_and_clear())
  }
  let view = FixedArray::makei(sig_len.val, i => arr.unsafe_get(i))
  Bytes::from_array(view)
}

///|
/// 取 ed25519 的 32 字节原始公钥。
/// 仅在 key_id() == 1087 时有意义。
pub fn PKey::ed25519_pub_raw(self : PKey) -> Bytes raise CryptoError {
  let cap = 32
  let buf = FixedArray::make(cap, b'\x00')
  let name = @utf8.encode("pub")
  let out_len = Ref(0)
  let rc = pkey_get_octet_param_ffi(
    self.ptr,
    name,
    name.length(),
    buf,
    cap,
    out_len,
  )
  if rc != 1 {
    raise CryptoError::OperationFailed(
      "EVP_PKEY_get_octet_string_param(pub)",
      err_get_and_clear(),
    )
  }
  let view = FixedArray::makei(out_len.val, i => buf.unsafe_get(i))
  Bytes::from_array(view)
}

///|
/// 取 RSA 公钥模数（n）或指数（e）原始字节。
/// 仅在 key_id() == 6 时有意义。
pub fn PKey::rsa_get_bn(self : PKey, name : String) -> Bytes raise CryptoError {
  let cap = 1024
  let buf = FixedArray::make(cap, b'\x00')
  let nb = @utf8.encode(name)
  let out_len = Ref(0)
  let rc = pkey_get_bn_bytes_ffi(self.ptr, nb, nb.length(), buf, cap, out_len)
  if rc != 1 {
    raise CryptoError::OperationFailed(
      "EVP_PKEY_get_bn_param(\{name})",
      err_get_and_clear(),
    )
  }
  let view = FixedArray::makei(out_len.val, i => buf.unsafe_get(i))
  Bytes::from_array(view)
}

///|
/// RSA 签名（向后兼容，相当于 sign(2, data)）。
/// md_alg: 1=SHA1, 2=SHA256。
pub fn PKey::rsa_sign(
  self : PKey,
  md_alg : Int,
  data : Bytes,
) -> Bytes raise CryptoError {
  self.sign(md_alg, data)
}

///|
/// 通用验签（支持 RSA/ECDSA/DSA）。
pub fn PKey::verify(
  self : PKey,
  md_alg : Int,
  data : Bytes,
  sig : Bytes,
) -> Bool raise CryptoError {
  let rc = pkey_verify_ffi(
    self.ptr,
    md_alg,
    data,
    data.length(),
    sig,
    sig.length(),
  )
  if rc < 0 {
    raise CryptoError::OperationFailed("pkey_verify", err_get_and_clear())
  }
  rc == 1
}

///|
#borrow(tbs, sig)
extern "C" fn pkey_verify_ffi(
  p : Pkey,
  md_alg : Int,
  tbs : Bytes,
  tbs_len : Int,
  sig : Bytes,
  sig_len : Int,
) -> Int = "moonbitlang_ssh_pkey_verify"

// ==================== ECDH P-256 ====================

///|
pub fn ecdh_nistp256_generate() -> (PKey, Bytes) raise CryptoError {
  ensure_openssl()
  let priv_out : Ref[Pkey] = Ref(pkey_new_ffi())
  let pub_buf = FixedArray::make(256, b'\x00')
  let pub_len = Ref(256)
  let rc = ecdh_gen_key_ffi(priv_out, pub_buf, pub_len)
  if rc != 1 {
    pkey_free_ffi(priv_out.val)
    raise CryptoError::OperationFailed("ecdh_gen_key", err_get_and_clear())
  }
  let pub_arr = FixedArray::makei(pub_len.val, i => pub_buf.unsafe_get(i))
  ({ ptr: priv_out.val }, Bytes::from_array(pub_arr))
}

///|
pub fn ecdh_nistp256_derive(
  our : PKey,
  peer_pub_sec1 : Bytes,
) -> Bytes raise CryptoError {
  ensure_openssl()
  let out = FixedArray::make(32, b'\x00')
  let out_len = Ref(32)
  let rc = ecdh_derive_ffi(
    our.ptr,
    peer_pub_sec1,
    peer_pub_sec1.length(),
    out,
    out_len,
  )
  if rc != 1 {
    raise CryptoError::OperationFailed("ecdh_derive", err_get_and_clear())
  }
  let view = FixedArray::makei(out_len.val, i => out.unsafe_get(i))
  Bytes::from_array(view)
}

///|
/// Base64 解码（标准 RFC 4648 字母表，忽略空白）。
/// 失败时抛出 CryptoError。
pub fn base64_decode(s : String) -> Bytes raise CryptoError {
  let src = @utf8.encode(s)
  let cap = src.length() // 4 * 3 + 16
  let buf = FixedArray::make(cap, b'\x00')
  let out_len = Ref(cap)
  let rc = base64_decode_ffi(src, src.length(), buf, out_len)
  if rc != 1 {
    raise CryptoError::OperationFailed("base64_decode", "")
  }
  let view = FixedArray::makei(out_len.val, i => buf.unsafe_get(i))
  Bytes::from_array(view)
}

///|
/// 读取 OpenSSH 格式的公钥文件（单行：`<alg> <base64-blob> <comment>`）。
/// 返回 `(alg_name, pubkey_blob)`：blob 是 SSH 线协议中使用的字节
/// （已是 SSH_MSG_USERAUTH_REQUEST 中 "publickey" 字段的完整数据）。
pub fn read_openssh_pubkey(path : String) -> (String, Bytes) raise CryptoError {
  let path_bytes = @utf8.encode(path)
  let alg_buf = FixedArray::make(64, Byte::default())
  let blob_cap = 4096
  let blob_buf = FixedArray::make(blob_cap, b'\x00')
  let alg_len = Ref(0)
  let blob_len = Ref(0)
  let rc = read_openssh_pubkey_ffi(
    path_bytes,
    path_bytes.length(),
    alg_buf,
    64,
    alg_len,
    blob_buf,
    blob_cap,
    blob_len,
  )
  if rc != 1 {
    raise CryptoError::OperationFailed("read_openssh_pubkey", "")
  }
  let alg_arr = FixedArray::makei(alg_len.val, i => alg_buf.unsafe_get(i))
  let alg = @utf8.decode(Bytes::from_array(alg_arr)) catch {
    _ => raise CryptoError::OperationFailed("read_openssh_pubkey: alg utf8", "")
  }
  let blob_arr = FixedArray::makei(blob_len.val, i => blob_buf.unsafe_get(i))
  (alg, Bytes::from_array(blob_arr))
}

// ==================== EC / DSA key construction ====================

///|
extern "C" fn pkey_ec_curve_nid_ffi(p : Pkey) -> Int = "moonbitlang_ssh_pkey_ec_curve_nid"

///|
#borrow(curve, point, out)
extern "C" fn pkey_from_ec_point_ffi(
  curve : Bytes,
  curve_len : Int,
  point : Bytes,
  point_len : Int,
  out : Ref[Pkey],
) -> Int = "moonbitlang_ssh_pkey_from_ec_point"

///|
#borrow(p, q, g, y, out)
extern "C" fn pkey_from_dsa_components_ffi(
  p : Bytes,
  p_len : Int,
  q : Bytes,
  q_len : Int,
  g : Bytes,
  g_len : Int,
  y : Bytes,
  y_len : Int,
  out : Ref[Pkey],
) -> Int = "moonbitlang_ssh_pkey_from_dsa_components"

///|
/// 返回 EC 曲线 NID：
///   415 -> prime256v1 (P-256)
///   715 -> secp384r1  (P-384)
///   716 -> secp521r1  (P-521)
///   0   -> 非 EC 密钥
pub fn PKey::ec_curve_nid(self : PKey) -> Int {
  pkey_ec_curve_nid_ffi(self.ptr)
}

///|
/// 从 EC 曲线名和原始公钥点构建 PKey（仅公钥，用于 host key 验证）。
/// `curve` 为 SSH 曲线标识：`"nistp256"` / `"nistp384"` / `"nistp521"`。
/// `point` 为原始未压缩 EC 点（`04 || x || y`）。
pub fn PKey::from_ec_point(
  curve : String,
  point : Bytes,
) -> PKey raise CryptoError {
  ensure_openssl()
  let out : Ref[Pkey] = Ref(pkey_new_ffi())
  let curve_bytes = @utf8.encode(curve)
  let rc = pkey_from_ec_point_ffi(
    curve_bytes,
    curve_bytes.length(),
    point,
    point.length(),
    out,
  )
  if rc != 1 {
    pkey_free_ffi(out.val)
    raise CryptoError::OperationFailed("from_ec_point", err_get_and_clear())
  }
  { ptr: out.val }
}

///|
/// 从 DSA 组件构建公钥 PKey（用于 host key 验证）。
pub fn PKey::from_dsa_components(
  p : Bytes,
  q : Bytes,
  g : Bytes,
  y : Bytes,
) -> PKey raise CryptoError {
  ensure_openssl()
  let out : Ref[Pkey] = Ref(pkey_new_ffi())
  let rc = pkey_from_dsa_components_ffi(
    p,
    p.length(),
    q,
    q.length(),
    g,
    g.length(),
    y,
    y.length(),
    out,
  )
  if rc != 1 {
    pkey_free_ffi(out.val)
    raise CryptoError::OperationFailed(
      "from_dsa_components",
      err_get_and_clear(),
    )
  }
  { ptr: out.val }
}
