///
/// SSH 协议层统一错误类型。
/// 涵盖 I/O、协议帧、加密完整性、认证以及 known_hosts 等所有失败场景，
/// 参见 RFC 4253 / RFC 4252 / RFC 4251。

///|
/// SSH 错误。所有公开 API 抛出的异常都应是 `SshError` 的实例，
/// 调用方可通过 `match` 分支进行细粒度处理。
pub suberror SshError {
  ///
  /// 底层 I/O 失败（socket 读写、网络中断等）。
  /// 携带可读的诊断信息。
  IoError(String)
  ///
  /// 对端在未发送 disconnect 消息的情况下关闭了连接。
  ConnectionClosed
  ///
  /// SSH 协议层违反规范，例如包长度越界、字段缺失、
  /// 包类型与状态机不匹配等。属于不可恢复错误。
  ProtocolError(String)
  ///
  /// MAC 校验失败（RFC 4253 §6.4）。通常意味着
  /// 数据被篡改或加密 / MAC 密钥不一致。
  MacMismatch
  ///
  /// 当前操作要求加密传输，但会话尚未进入加密状态。
  NotEncrypted
  ///
  /// 远端主机公钥与本地 known_hosts 记录不一致，
  /// 字符串携带具体不匹配的主机名 / 指纹信息。
  HostKeyMismatch(String)
  ///
  /// 用户身份认证失败（RFC 4252）。字符串包含服务端返回的原因。
  AuthFailed(String)
  ///
  /// 通用请求被服务端拒绝（例如通道打开、exec、shell 请求等）。
  /// 字符串为拒绝原因。
  RequestDenied(String)
  ///
  /// 数据解析失败，例如 Reader 剩余字节不足、UTF-8 非法、
  /// mpint / name-list 格式错误等。
  ParseError(String)
} derive(Show, Eq)
