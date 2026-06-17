///|
/// SSH 密钥交换所需的密钥协商原语。
/// - DH Group14 (diffie-hellman-group14-sha256, diffie-hellman-group14-sha1)
/// - BIGNUM 工具函数
#external
type Bn

///|
extern "C" fn bn_new_ffi() -> Bn = "moonbitlang_ssh_bn_new"

///|
extern "C" fn bn_free_ffi(bn : Bn) = "moonbitlang_ssh_bn_free"

///|
#borrow(buf)
extern "C" fn bn_bin2bn_ffi(buf : Bytes, len : Int, bn : Bn) -> Int = "moonbitlang_ssh_bn_bin2bn"

///|
#borrow(buf)
extern "C" fn bn_bn2binpad_ffi(
  bn : Bn,
  buf : FixedArray[Byte],
  len : Int,
) -> Int = "moonbitlang_ssh_bn_bn2binpad"

///|
extern "C" fn bn_num_bytes_ffi(bn : Bn) -> Int = "moonbitlang_ssh_bn_num_bytes"

///|
extern "C" fn bn_num_bits_ffi(bn : Bn) -> Int = "moonbitlang_ssh_bn_num_bits"

///|
#borrow(r, a, p, m)
extern "C" fn bn_mod_exp_ffi(r : Bn, a : Bn, p : Bn, m : Bn) -> Int = "moonbitlang_ssh_bn_mod_exp"

///|
#borrow(rnd, range)
extern "C" fn bn_rand_range_ffi(rnd : Bn, range : Bn) -> Int = "moonbitlang_ssh_bn_rand_range"

///|
#borrow(buf, buf_len)
extern "C" fn bn_to_mpint_ffi(
  bn : Bn,
  buf : FixedArray[Byte],
  buf_len : Ref[Int],
) -> Int = "moonbitlang_ssh_bn_to_mpint"

// ==================== DH Group14 ====================

///|
pub fn dh_group14_prime() -> @bigint.BigInt {
  @bigint.BigInt::from_string(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    radix=16,
  )
}

///|
pub fn dh_group14_generator() -> @bigint.BigInt {
  @bigint.BigInt::from_int(2)
}

///|
pub fn dh_group14_keygen(
  x : @bigint.BigInt,
) -> (@bigint.BigInt, @bigint.BigInt) {
  let p = dh_group14_prime()
  let g = dh_group14_generator()
  let public_value = g.pow(x, modulus=p)
  (x, public_value)
}

///|
pub fn dh_group14_shared(
  x : @bigint.BigInt,
  peer_pub : @bigint.BigInt,
) -> @bigint.BigInt {
  let p = dh_group14_prime()
  peer_pub.pow(x, modulus=p)
}

// ==================== BIGNUM helpers ====================

///|
/// 从大端字节序列构造 BIGNUM。
pub fn bn_from_bytes(bytes : Bytes) -> Bn raise CryptoError {
  ensure_openssl()
  let bn = bn_new_ffi()
  if bn_bin2bn_ffi(bytes, bytes.length(), bn) != 1 {
    bn_free_ffi(bn)
    raise CryptoError::OperationFailed("BN_bin2bn", err_get_and_clear())
  }
  bn
}

///|
/// 将 BIGNUM 转为固定长度的大端字节序列。
pub fn bn_to_bytes(bn : Bn, size : Int) -> Bytes raise CryptoError {
  let arr = FixedArray::make(size, b'\x00')
  let rc = bn_bn2binpad_ffi(bn, arr, size)
  if rc <= 0 {
    raise CryptoError::OperationFailed("BN_bn2binpad", err_get_and_clear())
  }
  Bytes::from_array(arr)
}

///|
/// 将 BIGNUM 转为 SSH mpint 格式（含 uint32 长度前缀）。
pub fn bn_to_mpint(bn : Bn) -> Bytes raise CryptoError {
  let buf = FixedArray::make(512, b'\x00')
  let buf_len = Ref(512)
  let rc = bn_to_mpint_ffi(bn, buf, buf_len)
  if rc != 1 {
    raise CryptoError::OperationFailed("bn_to_mpint", err_get_and_clear())
  }
  let view = FixedArray::makei(buf_len.val, i => buf.unsafe_get(i))
  Bytes::from_array(view)
}

///|
/// 释放 BIGNUM 资源。
pub fn bn_free(bn : Bn) -> Unit {
  bn_free_ffi(bn)
}

///|
/// 生成 [0, range) 范围内的随机 BIGNUM。
pub fn bn_rand_range(range : Bn) -> Bn raise CryptoError {
  ensure_openssl()
  let rnd = bn_new_ffi()
  let rc = bn_rand_range_ffi(rnd, range)
  if rc != 1 {
    bn_free_ffi(rnd)
    raise CryptoError::OperationFailed("BN_rand_range", err_get_and_clear())
  }
  rnd
}

///|
/// 模幂运算：r = a^p mod m。
pub fn bn_mod_exp(a : Bn, p : Bn, m : Bn) -> Bn raise CryptoError {
  let r = bn_new_ffi()
  let rc = bn_mod_exp_ffi(r, a, p, m)
  if rc != 1 {
    bn_free_ffi(r)
    raise CryptoError::OperationFailed("BN_mod_exp", err_get_and_clear())
  }
  r
}

///|
/// 返回 BIGNUM 的字节长度。
pub fn bn_num_bytes(bn : Bn) -> Int {
  bn_num_bytes_ffi(bn)
}

///|
/// 返回 BIGNUM 的比特长度。
pub fn bn_num_bits(bn : Bn) -> Int {
  bn_num_bits_ffi(bn)
}
