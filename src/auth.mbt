///|
/// SSH 用户认证协议（RFC 4252）。
///
/// 本模块实现 RFC 4252 定义的用户认证层，负责：
///   - `none`           — 探测服务端允许的认证方法
///   - `password`       — 口令认证
///   - `publickey`      — 公钥认证（两阶段：query → sign）
///   - `keyboard-interactive` — 通用 challenge/response
///

///|
/// 所有请求 / 回复均按 SSH 二进制协议帧编码（参见 [packet.mbt]）。
pub const SERVICE_USERAUTH : String = "ssh-userauth"

///|
/// 认证方法名 `"none"`（RFC 4252 §5.1）。
/// 用于首次连接时探测服务端允许的认证方法。
pub fn method_none() -> String {
  "none"
}

///|
/// 认证方法名 `"password"`（RFC 4252 §8）。
/// 用户名 + 口令的方式直接登录。
pub fn method_password() -> String {
  "password"
}

///|
/// 认证方法名 `"publickey"`（RFC 4252 §7）。
/// 先发送公钥 query，服务端返回 `PK_OK` 后再发送签名。
pub fn method_publickey() -> String {
  "publickey"
}

///|
/// 认证方法名 `"keyboard-interactive"`（RFC 4256）。
/// 通用 challenge/response 认证，常用于双因素、PAM 提示等场景。
pub fn method_keyboard_interactive() -> String {
  "keyboard-interactive"
}

///|
/// 构建 SSH_MSG_SERVICE_REQUEST（消息号 5，RFC 4253 §10）。
///
/// 客户端在完成密钥交换后必须发送该消息，请求开始 `ssh-userauth` 服务。
///
/// 参数：
/// * `service` — 服务名，通常为 `"ssh-userauth"`（见 [SERVICE_USERAUTH]）。
pub fn build_service_request(service : String) -> Bytes {
  let w = Writer::new()
  w.write_byte(5)
  w.write_string_from_str(service)
  w.to_bytes()
}

///|
/// 构建 SSH_MSG_USERAUTH_REQUEST（消息号 50，RFC 4252）。
///
/// 通用构造器：根据 `auth_method` 选择性追加方法特定字段：
///   - `"password"`                — 追加 `FALSE` + 口令。
///   - `"publickey"` 且无签名      — 追加 `FALSE` + alg + 公钥 blob。
///   - `"publickey"` 且带签名      — 追加 `TRUE` + alg + 公钥 blob + 签名。
///   - 其它（如 `"none"`、`"keyboard-interactive"`）— 不追加额外字段，
///     由调用方在子协议里再编码。
///
/// 参数均为可选（除 `user` / `service` / `auth_method` 外），缺失时按协议填零。
pub fn build_userauth_request(
  user : String,
  service : String,
  auth_method : String,
  has_signature? : Bool,
  pubkey_alg? : String,
  pubkey_blob? : Bytes,
  signature? : Bytes,
  password? : String,
) -> Bytes {
  let w = Writer::new()
  w.write_byte(50)
  w.write_string_from_str(user)
  w.write_string_from_str(service)
  w.write_string_from_str(auth_method)
  if auth_method == "password" {
    w.write_byte(0) // FALSE for password change
    w.write_string_from_str(password.unwrap_or(""))
  } else if auth_method == "publickey" {
    w.write_byte(if has_signature.unwrap_or(false) { 1 } else { 0 })
    w.write_string_from_str(pubkey_alg.unwrap_or(""))
    w.write_string(pubkey_blob.unwrap_or(b""))
    if has_signature.unwrap_or(false) {
      w.write_string(signature.unwrap_or(b""))
    }
  }
  w.to_bytes()
}

///|
/// 解析来自服务端的认证层消息（消息体，不含 SSH 传输层包头）。
///
/// 识别以下消息（按消息号）：
///   - `52` (`SSH_MSG_USERAUTH_SUCCESS`)    → [AuthReply::Success]
///   - `51` (`SSH_MSG_USERAUTH_FAILURE`)    → [AuthReply::Failure]，附带可继续尝试的方法名列表与 partial-success 标志
///   - `60` (`SSH_MSG_USERAUTH_PK_OK`)      → [AuthReply::PublicKeyOk]，附带算法名与公钥 blob
///   - `6`  (`SSH_MSG_SERVICE_ACCEPT`)      → [AuthReply::ServiceAccept]
///
/// 其它消息号抛出 [ProtocolError]。
pub fn parse_auth_reply(payload : Bytes) -> AuthReply raise SshError {
  let r = Reader::new(payload)
  let msg = r.read_byte()
  match msg {
    b'\x34' => Success // SSH_MSG_USERAUTH_SUCCESS = 52
    b'\x33' => {
      let methods = r.read_name_list()
      let partial = r.read_byte() != b'\x00'
      Failure(methods, partial)
    }
    b'\x3c' => {
      // SSH_MSG_USERAUTH_PK_OK = 60
      let alg = r.read_string_as_str()
      let blob = r.read_string()
      PublicKeyOk(alg, blob)
    }
    b'\x06' => ServiceAccept
    _ => raise ProtocolError("userauth: unexpected msg \{msg.to_int()}")
  }
}

///|
/// 服务端对 userauth 请求的回复。
///
/// 构造器：
///   - `Success` — 认证成功（`SSH_MSG_USERAUTH_SUCCESS`）。
///   - `Failure(methods, partial)` — 认证失败，附带服务端允许继续尝试的方法列表与
///     partial-success 标志（RFC 4252 §5.1）。
///   - `PublicKeyOk(alg, blob)` — 服务端接受该公钥，可继续发送签名（`SSH_MSG_USERAUTH_PK_OK`）。
///   - `ServiceAccept` — `SSH_MSG_SERVICE_ACCEPT`，对 SERVICE_REQUEST 的肯定响应。
pub enum AuthReply {
  Success
  Failure(Array[String], Bool)
  PublicKeyOk(String, Bytes)
  ServiceAccept
} derive(Debug, Eq)

///|
/// 构建公钥签名输入字节串（RFC 4252 §7）。
///
/// 串接顺序：
/// ```text
///   string    session_id
///   byte      SSH_MSG_USERAUTH_REQUEST (50)
///   string    user name
///   string    service name（"ssh-connection"）
///   string    "publickey"
///   boolean   TRUE
///   string    public key algorithm name
///   string    public key blob
/// ```
///
/// 客户端在拿到服务端 `PK_OK` 后，把该字节串作为私钥签名的输入，
/// 得到原始签名后再用 [build_signature_blob] 包装为 SSH signature blob。
pub fn build_publickey_signature_input(
  session_id : Bytes,
  user : String,
  service : String,
  pubkey_alg : String,
  pubkey_blob : Bytes,
) -> Bytes {
  let w = Writer::new()
  w.write_string(session_id)
  w.write_byte(50)
  w.write_string_from_str(user)
  w.write_string_from_str(service)
  w.write_string_from_str("publickey")
  w.write_byte(1) // TRUE
  w.write_string_from_str(pubkey_alg)
  w.write_string(pubkey_blob)
  w.to_bytes()
}

///|
/// 认证上下文，保存用户名与服务名，跟踪当前认证状态机。
///
/// 字段：
///   - `user`    — 本地用户名。
///   - `service` — 目标服务名，固定为 `"ssh-userauth"`。
///   - `state`   — 当前认证状态，初始为 [AuthState::Idle]。
pub struct AuthContext {
  user : String
  service : String
  mut state : AuthState
}

///|
/// 认证状态机。
///
/// 构造器：
///   - `Idle`                     — 初始状态，尚未发送任何 userauth 请求。
///   - `AwaitingReply`            — 已发请求，等待服务端回复。
///   - `AwaitingSignature(alg, blob)` — 公钥 query 已通过 `PK_OK`，等待用私钥签名。
///   - `Authenticated`            — 认证成功。
///   - `Rejected(methods)`        — 认证被拒，`methods` 为服务端允许继续尝试的方法列表。
#warnings("-unused_constructor")
pub enum AuthState {
  Idle
  AwaitingReply
  AwaitingSignature(String, Bytes)
  Authenticated
  Rejected(Array[String])
} derive(Eq, Debug)

///|
/// 用用户名构造认证上下文；服务名固定为 `"ssh-userauth"`，状态为 [AuthState::Idle]。
pub fn AuthContext::new(user : String) -> AuthContext {
  { user, service: SERVICE_USERAUTH, state: Idle }
}

///|
/// 是否已认证完成。
pub fn AuthContext::is_authenticated(self : AuthContext) -> Bool {
  self.state is Authenticated
}

// 各认证方法的消息构造器（都使用 "ssh-connection" 作为 service）

///|
/// 构建 `none` 探测请求，用于查询服务端允许的认证方法。
pub fn AuthContext::build_initial(self : AuthContext) -> Bytes {
  build_userauth_request(self.user, "ssh-connection", method_none())
}

///|
/// 构建口令认证请求。
pub fn AuthContext::build_password(
  self : AuthContext,
  password : String,
) -> Bytes {
  build_userauth_request(
    self.user,
    "ssh-connection",
    method_password(),
    password~,
  )
}

///|
/// 构建公钥认证的第一阶段请求：仅发送 alg + 公钥 blob，不带签名。
///
/// 服务端若接受该公钥则返回 `SSH_MSG_USERAUTH_PK_OK`，
/// 客户端随后再调用 [AuthContext::build_publickey_sign] 发送签名。
pub fn AuthContext::build_publickey_query(
  self : AuthContext,
  pubkey_alg : String,
  pubkey_blob : Bytes,
) -> Bytes {
  build_userauth_request(
    self.user,
    "ssh-connection",
    method_publickey(),
    has_signature=false,
    pubkey_alg~,
    pubkey_blob~,
  )
}

///|
/// 构建公钥认证的第二阶段请求：附带签名。
///
/// `signature` 必须是按 [build_publickey_signature_input] 的输入
/// 用私钥签出后，再经 [build_signature_blob] 包装的 SSH signature blob。
pub fn AuthContext::build_publickey_sign(
  self : AuthContext,
  pubkey_alg : String,
  pubkey_blob : Bytes,
  signature : Bytes,
) -> Bytes {
  build_userauth_request(
    self.user,
    "ssh-connection",
    method_publickey(),
    has_signature=true,
    pubkey_alg~,
    pubkey_blob~,
    signature~,
  )
}

///|
/// 构建 keyboard-interactive 初始请求（RFC 4256）。
///
/// 初始请求不携带任何 prompt 字段；服务端在 challenge 阶段会发送
/// `SSH_MSG_USERAUTH_INFO_REQUEST`（消息号 60），客户端用
/// [AuthContext::build_info_response] 回包。
pub fn AuthContext::build_keyboard_interactive(self : AuthContext) -> Bytes {
  let w = Writer::new()
  w.write_byte(50)
  w.write_string_from_str(self.user)
  w.write_string_from_str("ssh-connection")
  w.write_string_from_str(method_keyboard_interactive())
  w.write_string_from_str("") // lang
  w.write_string_from_str("") // submethods
  w.to_bytes()
}

///|
/// 构建 `SSH_MSG_USERAUTH_INFO_RESPONSE`（消息号 61，RFC 4256）。
///
/// 用于回复服务端下发的 challenge 列表；`responses` 的顺序与数量
/// 必须与 `SSH_MSG_USERAUTH_INFO_REQUEST` 中的 prompt 一一对应。
pub fn AuthContext::build_info_response(
  _self : AuthContext,
  responses : Array[String],
) -> Bytes {
  let w = Writer::new()
  w.write_byte(61) // SSH_MSG_USERAUTH_INFO_RESPONSE
  w.write_uint32(responses.length())
  for r in responses {
    w.write_string_from_str(r)
  }
  w.to_bytes()
}

///|
/// 根据服务端回复更新本地认证状态。
///
/// 状态转移：
///   - [AuthReply::Success]          → [AuthState::Authenticated]
///   - [AuthReply::Failure]          → [AuthState::Rejected]，记录可继续尝试的方法
///   - [AuthReply::PublicKeyOk]      → [AuthState::AwaitingSignature]，等待私钥签名
///   - [AuthReply::ServiceAccept]    → 状态保持不变
pub fn AuthContext::apply_reply(self : AuthContext, reply : AuthReply) -> Unit {
  match reply {
    Success => self.state = Authenticated
    Failure(methods, _) => self.state = Rejected(methods)
    PublicKeyOk(alg, blob) => self.state = AwaitingSignature(alg, blob)
    _ => ()
  }
}
