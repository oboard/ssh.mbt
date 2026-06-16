///|
/// SSH 用户认证协议（RFC 4252）。
/// 支持：none / password / publickey / keyboard-interactive
pub const SERVICE_USERAUTH : String = "ssh-userauth"

///|
pub fn method_none() -> String {
  "none"
}

///|
pub fn method_password() -> String {
  "password"
}

///|
pub fn method_publickey() -> String {
  "publickey"
}

///|
pub fn method_keyboard_interactive() -> String {
  "keyboard-interactive"
}

///|
/// 构建 SSH_MSG_SERVICE_REQUEST。
pub fn build_service_request(service : String) -> Bytes {
  let w = Writer::new()
  w.write_byte(5)
  w.write_string_from_str(service)
  w.to_bytes()
}

///|
/// 构建 SSH_MSG_USERAUTH_REQUEST。
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
/// 解析认证回复。
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
pub enum AuthReply {
  Success
  Failure(Array[String], Bool)
  PublicKeyOk(String, Bytes)
  ServiceAccept
} derive(Debug, Eq)

///|
/// 构建公钥签名输入（RFC 4252 §7）。
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
/// 认证上下文。
pub struct AuthContext {
  user : String
  service : String
  mut state : AuthState
}

///|
#warnings("-unused_constructor")
pub enum AuthState {
  Idle
  AwaitingReply
  AwaitingSignature(String, Bytes)
  Authenticated
  Rejected(Array[String])
} derive(Eq, Debug)

///|
pub fn AuthContext::new(user : String) -> AuthContext {
  { user, service: SERVICE_USERAUTH, state: Idle }
}

///|
pub fn AuthContext::is_authenticated(self : AuthContext) -> Bool {
  self.state is Authenticated
}

// 构建各种认证请求

///|
pub fn AuthContext::build_initial(self : AuthContext) -> Bytes {
  build_userauth_request(self.user, "ssh-connection", method_none())
}

///|
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
/// 更新认证状态。
pub fn AuthContext::apply_reply(self : AuthContext, reply : AuthReply) -> Unit {
  match reply {
    Success => self.state = Authenticated
    Failure(methods, _) => self.state = Rejected(methods)
    PublicKeyOk(alg, blob) => self.state = AwaitingSignature(alg, blob)
    _ => ()
  }
}
