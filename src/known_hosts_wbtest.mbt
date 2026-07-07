// Whitebox tests for src/known_hosts.mbt.
// Run `moon test --target native` to execute.

///|
test "wildcard_match/exact" {
  inspect(wildcard_match("example.com", "example.com"), content="true")
  inspect(wildcard_match("example.com", "other.com"), content="false")
  inspect(wildcard_match("", ""), content="true")
  inspect(wildcard_match("a", ""), content="false")
  inspect(wildcard_match("", "a"), content="false")
}

///|
test "wildcard_match/star" {
  // trailing star
  inspect(wildcard_match("*.example.com", "foo.example.com"), content="true")
  inspect(wildcard_match("*.example.com", "a.b.example.com"), content="true")
  inspect(wildcard_match("*.example.com", "example.com"), content="false")
  // leading star
  inspect(wildcard_match("foo.*", "foo.com"), content="true")
  inspect(wildcard_match("foo.*", "foo."), content="true")
  inspect(wildcard_match("foo.*", "bar.foo.com"), content="false")
  // star in middle
  inspect(wildcard_match("a*b", "ab"), content="true")
  inspect(wildcard_match("a*b", "axxxb"), content="true")
  inspect(wildcard_match("a*b", "axxxc"), content="false")
  inspect(wildcard_match("a*b", "a"), content="false")
  inspect(wildcard_match("a*b", "b"), content="false")
  // multiple stars
  inspect(wildcard_match("*.*", "a.b"), content="true")
  inspect(wildcard_match("*.*", "ab"), content="false")
  inspect(wildcard_match("a**b", "ab"), content="true")
  inspect(wildcard_match("a**b", "axxb"), content="true")
}

///|
test "wildcard_match/question" {
  inspect(wildcard_match("a?b", "axb"), content="true")
  inspect(wildcard_match("a?b", "ab"), content="false")
  inspect(wildcard_match("a?b", "axxb"), content="false")
  inspect(wildcard_match("?", ""), content="false")
  inspect(wildcard_match("?", "a"), content="true")
}

///|
test "pattern_matches/hashed_host_is_rejected" {
  // hashed hosts start with "|1|"; we don't support them
  inspect(pattern_matches("|1|abc/def=", "example.com"), content="false")
}

///|
test "pattern_matches/exact_only" {
  inspect(pattern_matches("example.com", "example.com"), content="true")
  inspect(pattern_matches("example.com", "other.com"), content="false")
}

///|
test "pattern_matches/wildcard_fallback" {
  inspect(pattern_matches("*.example.com", "foo.example.com"), content="true")
}

///|
test "trim_ascii/strips_whitespace" {
  inspect(trim_ascii("  hello  "), content="hello")
  inspect(trim_ascii("\t\n hello \r\n"), content="hello")
  inspect(trim_ascii(""), content="")
  inspect(trim_ascii("   "), content="")
  inspect(trim_ascii("no trim"), content="no trim")
  inspect(trim_ascii("  a  b  "), content="a  b")
}

// ============== HostKeyPolicy verification ==============

///|
fn make_entry(host : String, alg : String, key : Bytes) -> KnownHost {
  { patterns: [host], key_alg: alg, key }
}

///|
test "verify_host_key/Strict_match_accepts" {
  let entries = [make_entry("example.com", "ssh-rsa", b"key-a")]
  let policy = Strict(entries, reject_unknown)
  inspect(
    verify_host_key(policy, "example.com", 22, "ssh-rsa", b"key-a") is Accept,
    content="true",
  )
}

///|
test "verify_host_key/Strict_mismatch_rejects_mitm" {
  let entries = [make_entry("example.com", "ssh-rsa", b"key-a")]
  let policy = Strict(entries, reject_unknown)
  match verify_host_key(policy, "example.com", 22, "ssh-rsa", b"key-b") {
    RejectMismatch(stored_alg, _) => inspect(stored_alg, content="ssh-rsa")
    _ => fail("expected RejectMismatch")
  }
}

///|
test "verify_host_key/Strict_unknown_default_rejects" {
  let entries : Array[KnownHost] = []
  let policy = Strict(entries, reject_unknown)
  inspect(
    verify_host_key(policy, "unknown.com", 22, "ssh-rsa", b"k") is RejectUnknown,
    content="true",
  )
}

///|
test "verify_host_key/Strict_with_on_unknown_accepts" {
  let entries : Array[KnownHost] = []
  let policy = Strict(entries, accept_and_persist)
  inspect(
    verify_host_key(policy, "unknown.com", 22, "ssh-rsa", b"k") is Accept,
    content="true",
  )
}

///|
test "verify_host_key/Strict_port_brackets" {
  // 非 22 端口应按 [host]:port 匹配
  let entries = [
    { patterns: ["[example.com]:2222"], key_alg: "ssh-rsa", key: b"k" },
  ]
  let policy = Strict(entries, reject_unknown)
  inspect(
    verify_host_key(policy, "example.com", 2222, "ssh-rsa", b"k") is Accept,
    content="true",
  )
  // 端口不同 -> 不命中
  inspect(
    verify_host_key(policy, "example.com", 22, "ssh-rsa", b"k") is RejectUnknown,
    content="true",
  )
}

///|
test "verify_host_key/TOFU_first_use_prompts_and_persists" {
  let entries : Array[KnownHost] = []
  let policy = TrustOnFirstUse(entries, accept_and_persist)
  let r1 = verify_host_key(policy, "new.com", 22, "ssh-rsa", b"k1")
  inspect(r1 is Accept, content="true")
  inspect(entries.length(), content="1")
  // 第二次同样 key -> 直接命中（不回调）
  let r2 = verify_host_key(policy, "new.com", 22, "ssh-rsa", b"k1")
  inspect(r2 is Accept, content="true")
  inspect(entries.length(), content="1")
}

///|
test "verify_host_key/TOFU_mitm_after_first_use_rejects" {
  let entries : Array[KnownHost] = []
  let policy = TrustOnFirstUse(entries, accept_and_persist)
  ignore(verify_host_key(policy, "new.com", 22, "ssh-rsa", b"k1"))
  match verify_host_key(policy, "new.com", 22, "ssh-rsa", b"k2") {
    RejectMismatch(_, _) => ()
    _ => fail("expected RejectMismatch after key change")
  }
}

///|
test "verify_host_key/TOFU_reject_by_user" {
  let reject : (String, String, Bytes) -> Bool = (_h, _a, _k) => false
  let entries : Array[KnownHost] = []
  let policy = TrustOnFirstUse(entries, reject)
  inspect(
    verify_host_key(policy, "new.com", 22, "ssh-rsa", b"k") is RejectByUser,
    content="true",
  )
  inspect(entries.length(), content="0")
}

///|
test "verify_host_key/Insecure_always_accepts" {
  let policy = Insecure
  inspect(
    verify_host_key(policy, "any.com", 22, "ssh-rsa", b"any") is Accept,
    content="true",
  )
  inspect(
    verify_host_key(Insecure, "x", 99, "y", b"z") is Accept,
    content="true",
  )
}

///|
test "verify_host_key/Callback_accepts_on_true" {
  let policy = Callback((_alg, _key) => true)
  inspect(
    verify_host_key(policy, "any.com", 22, "ssh-rsa", b"any") is Accept,
    content="true",
  )
}

///|
test "verify_host_key/Callback_rejects_on_false" {
  let policy = Callback((_alg, _key) => false)
  match verify_host_key(policy, "any.com", 22, "ssh-rsa", b"any") {
    RejectByUser => ()
    _ => fail("expected RejectByUser when callback returns false")
  }
}

///|
test "host_key_decision/reason_string" {
  inspect(Accept.reason("h", "alg"), content="h (alg=alg): accepted")
  match RejectMismatch("stored", b"k") {
    _ =>
      inspect(
        RejectMismatch("stored", b"k").reason("h", "alg"),
        content="h (alg=alg): key changed, stored=stored — possible MITM",
      )
  }
  inspect(
    RejectUnknown.reason("h", "alg"),
    content="h (alg=alg): not in known_hosts and policy rejects unknown hosts",
  )
  inspect(
    RejectByUser.reason("h", "alg"),
    content="h (alg=alg): rejected by user callback",
  )
}
