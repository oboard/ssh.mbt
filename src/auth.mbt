///|
/// SSH 用户认证协议（RFC 4252）。
///
/// 支持：
///   - `none`            (用于探测服务器接受哪些方法)
///   - `password`        (密码认证)
///   - `publickey`       (公钥认证：query → sign → verify)
///
/// 不支持（v0.1 暂不实现）：
///   - keyboard-interactive
///   - gssapi-with-mic
///   - hostbased

///|
/// 服务请求的 userauth 服务名。
pub const SERVICE_USERAUTH : String = "ssh-userauth"

///|
/// 认证方法名常量。
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

// --- Service request / userauth request -----------------------------

///|
/// Build a `SSH_MSG_SERVICE_REQUEST` payload (RFC 4252 §5.1):
///   byte   SSH_MSG_SERVICE_REQUEST (5)
///   string service-name
pub fn build_service_request(service : String) -> Bytes {
  let w = Writer::new()
  w.write_byte(5)
  w.write_string_from_str(service)
  w.to_bytes()
}

///|
/// Build a `SSH_MSG_USERAUTH_REQUEST` payload (RFC 4252 §5.2):
///   byte     SSH_MSG_USERAUTH_REQUEST (50)
///   string   user name
///   string   service name ("ssh-connection")
///   string   auth_method name ("password" | "publickey" | "none")
///   ... method-specific fields
pub fn build_userauth_request(
  user : String,
  service : String,
  auth_method  : String,
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
  // "none" has no method-specific fields
  w.to_bytes()
}

///|
/// Parse a `SSH_MSG_USERAUTH_SUCCESS` / `SSH_MSG_USERAUTH_FAILURE` /
/// `SSH_MSG_USERAUTH_PK_OK` / `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ` /
/// `SSH_MSG_SERVICE_ACCEPT` reply.
pub fn parse_auth_reply(payload : Bytes) -> AuthReply raise SshError {
  let r = Reader::new(payload)
  let msg = r.read_byte()
  match msg {
    b'\x32' => Success // SSH_MSG_USERAUTH_SUCCESS = 52
    b'\x33' => {
      // SSH_MSG_USERAUTH_FAILURE = 51
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
    b'\x34' => PasswordChangeRequired // SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60
    b'\x06' => ServiceAccept // SSH_MSG_SERVICE_ACCEPT = 6
    _ =>
      raise ProtocolError("userauth: unexpected message type \{msg.to_int()}")
  }
}

///|
pub enum AuthReply {
  /// `SSH_MSG_USERAUTH_SUCCESS` (52): authentication complete.
  Success
  /// `SSH_MSG_USERAUTH_FAILURE` (51): `methods` are still acceptable.
  Failure(Array[String], Bool)
  /// `SSH_MSG_USERAUTH_PK_OK` (60): server accepts the public key.
  PublicKeyOk(String, Bytes)
  /// Server wants the password changed before continuing.
  PasswordChangeRequired
  /// Service request was accepted (e.g. `ssh-userauth`).
  ServiceAccept
} derive(Debug, Eq)

// Factory functions for cross-package construction

///|
pub fn AuthReply::success() -> AuthReply {
  Success
}

///|
pub fn AuthReply::failure(methods : Array[String], partial : Bool) -> AuthReply {
  Failure(methods, partial)
}

///|
pub fn AuthReply::public_key_ok(alg : String, blob : Bytes) -> AuthReply {
  PublicKeyOk(alg, blob)
}

///|
pub fn AuthReply::password_change_required() -> AuthReply {
  PasswordChangeRequired
}

///|
pub fn AuthReply::service_accept() -> AuthReply {
  ServiceAccept
}

// --- High-level auth flow --------------------------------------------

///|
/// Auth context: holds the user name and authentication state.
pub struct AuthContext {
  user : String
  service : String
  mut state : AuthState
}

///|
pub enum AuthState {
  /// Not yet requested.
  Idle
  /// Sent userauth request; awaiting reply.
  AwaitingReply
  /// `publickey` query accepted; need to sign a session-id-bound blob and
  /// resend with the signature.
  AwaitingSignature(String, Bytes)
  /// Authentication succeeded.
  Authenticated
  /// Authentication failed terminally.
  Rejected(Array[String])
} derive(Eq, Debug)

// Factory functions for cross-package construction

///|
pub fn AuthState::idle() -> AuthState {
  Idle
}

///|
pub fn AuthState::awaiting_reply() -> AuthState {
  AwaitingReply
}

///|
pub fn AuthState::awaiting_signature(alg : String, blob : Bytes) -> AuthState {
  AwaitingSignature(alg, blob)
}

///|
pub fn AuthState::authenticated() -> AuthState {
  Authenticated
}

///|
pub fn AuthState::rejected(methods : Array[String]) -> AuthState {
  Rejected(methods)
}

///|
pub fn AuthContext::new(user : String) -> AuthContext {
  { user, service: SERVICE_USERAUTH, state: Idle }
}

///|
pub fn AuthContext::is_authenticated(self : AuthContext) -> Bool {
  self.state is Authenticated
}

///|
/// Build the initial `none` request to probe the server.
pub fn AuthContext::build_initial(self : AuthContext) -> Bytes {
  build_userauth_request(self.user, "ssh-connection", method_none())
}

///|
/// Build a `password` request.
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
/// Build a `publickey` query (no signature).
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
/// Build a `publickey` request with the signature.
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
/// Compute the SSH `publickey` signature blob (RFC 4252 §7):
///   string   session identifier
///   byte     SSH_MSG_USERAUTH_REQUEST
///   string   user name
///   string   service
///   string   "publickey"
///   boolean  TRUE
///   string   public key algorithm
///   string   public key blob
pub fn build_publickkey_signature_input(
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
/// Update the auth state from a server reply.
pub fn AuthContext::apply_reply(self : AuthContext, reply : AuthReply) -> Unit {
  match reply {
    Success => self.state = Authenticated
    Failure(methods, _partial) => self.state = Rejected(methods)
    PublicKeyOk(alg, blob) => self.state = AwaitingSignature(alg, blob)
    _ => ()
  }
}
