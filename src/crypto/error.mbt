///|
/// 密码学操作中的错误类型。
#warnings("-unused_constructor")
pub suberror CryptoError {
  /// 随机数生成失败。
  RandomFailed(String)
  /// FFI 操作返回非成功状态。
  OperationFailed(String, String)
  /// 参数无效。
  InvalidArgument(String)
} derive(Eq, Debug)
