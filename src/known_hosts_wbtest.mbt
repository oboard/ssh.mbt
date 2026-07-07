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

// ============== KnownHost getters ==============

///|
test "known_host/alg_returns_key_alg" {
  let entry : KnownHost = {
    patterns: ["example.com"],
    key_alg: "ssh-ed25519",
    key: Bytes::from_array([b'\x01', b'\x02']),
  }
  inspect(entry.alg(), content="ssh-ed25519")
}

///|
test "known_host/key_bytes_returns_key" {
  let entry : KnownHost = {
    patterns: ["example.com"],
    key_alg: "ssh-rsa",
    key: Bytes::from_array([b'\xab', b'\xcd', b'\xef']),
  }
  let kb = entry.key_bytes()
  inspect(kb.length(), content="3")
  inspect(kb[0].to_int(), content="171") // 0xab
  inspect(kb[2].to_int(), content="239") // 0xef
}

// ============== KnownHost::format_entry ==============

///|
test "known_host/format_entry_single_pattern" {
  let entry : KnownHost = {
    patterns: ["example.com"],
    key_alg: "ssh-ed25519",
    key: Bytes::from_array([b'\x00', b'\x01']),
  }
  let formatted = entry.format_entry()
  // 应包含 pattern、算法名和 base64 编码的 key
  inspect(formatted.has_prefix("example.com ssh-ed25519 "), content="true")
}

///|
test "known_host/format_entry_multiple_patterns" {
  let entry : KnownHost = {
    patterns: ["host1.com", "host2.com"],
    key_alg: "ssh-rsa",
    key: Bytes::from_array([b'\xff']),
  }
  let formatted = entry.format_entry()
  inspect(formatted.has_prefix("host1.com,host2.com ssh-rsa "), content="true")
}

// ============== KnownHost::matches with non-22 port ==============

///|
test "known_host/matches_non_22_port" {
  // 非 22 端口应匹配 [host]:port 格式
  let entry : KnownHost = {
    patterns: ["[example.com]:2222"],
    key_alg: "ssh-rsa",
    key: b"k",
  }
  // 端口 2222 匹配
  inspect(entry.matches("example.com", 2222), content="true")
  // 端口 22 不匹配（pattern 是 [host]:2222）
  inspect(entry.matches("example.com", 22), content="false")
  // 不同主机不匹配
  inspect(entry.matches("other.com", 2222), content="false")
}

///|
test "known_host/matches_non_22_fallback_to_plain_host" {
  // 当 pattern 不含端口时，也应匹配非 22 端口的主机名
  let entry : KnownHost = {
    patterns: ["example.com"],
    key_alg: "ssh-rsa",
    key: b"k",
  }
  // 端口 2222，pattern 是 "example.com" 无端口，应 fallback 匹配 host
  inspect(entry.matches("example.com", 2222), content="true")
  // 端口 22 也匹配
  inspect(entry.matches("example.com", 22), content="true")
}

///|
test "known_host/matches_wildcard_with_port" {
  let entry : KnownHost = {
    patterns: ["*.example.com"],
    key_alg: "ssh-rsa",
    key: b"k",
  }
  inspect(entry.matches("foo.example.com", 22), content="true")
  inspect(entry.matches("foo.example.com", 2222), content="true")
  inspect(entry.matches("bar.com", 22), content="false")
}

// ============== host_pattern_for ==============

///|
test "known_host/host_pattern_for_port_22" {
  let pat = host_pattern_for("example.com", 22)
  inspect(pat, content="example.com")
}

///|
test "known_host/host_pattern_for_non_22" {
  let pat = host_pattern_for("example.com", 2222)
  inspect(pat, content="[example.com]:2222")
}

///|
test "known_host/host_pattern_for_various_ports" {
  inspect(host_pattern_for("h", 80), content="[h]:80")
  inspect(host_pattern_for("h", 443), content="[h]:443")
  inspect(host_pattern_for("h", 22), content="h")
}

// ============== parse_line edge cases ==============

///|
test "parse_line/comment_returns_none" {
  let result = parse_line("# this is a comment")
  inspect(result is None, content="true")
}

///|
test "parse_line/empty_returns_none" {
  let result = parse_line("")
  inspect(result is None, content="true")
}

///|
test "parse_line/whitespace_only_returns_none" {
  let result = parse_line("   ")
  inspect(result is None, content="true")
}

///|
test "parse_line/too_few_parts_returns_none" {
  // 只有 2 个字段（缺少 key）
  let result = parse_line("example.com ssh-rsa")
  inspect(result is None, content="true")
}

///|
test "parse_line/valid_entry" {
  // 构造一个有效的 known_hosts 行
  let key_bytes = Bytes::from_array([b'\x00', b'\x01', b'\x02'])
  let key_b64 = encode_base64(key_bytes)
  let line = "example.com ssh-ed25519 \{key_b64}"
  let result = parse_line(line)
  match result {
    Some(entry) => {
      inspect(entry.patterns.length(), content="1")
      inspect(entry.patterns[0], content="example.com")
      inspect(entry.key_alg, content="ssh-ed25519")
      inspect(entry.key.length(), content="3")
    }
    None => fail("expected Some(KnownHost)")
  }
}

///|
test "parse_line/multiple_hosts" {
  let key_bytes = Bytes::from_array([b'\xaa'])
  let key_b64 = encode_base64(key_bytes)
  let line = "host1.com,host2.com ssh-rsa \{key_b64}"
  let result = parse_line(line)
  match result {
    Some(entry) => {
      inspect(entry.patterns.length(), content="2")
      inspect(entry.patterns[0], content="host1.com")
      inspect(entry.patterns[1], content="host2.com")
    }
    None => fail("expected Some(KnownHost)")
  }
}

// ============== encode_base64 / decode_base64 roundtrip ==============

///|
test "base64/roundtrip_short" {
  let original = Bytes::from_array([b'\x00', b'\xff', b'\x7f', b'\x80'])
  let encoded = encode_base64(original)
  let decoded = decode_base64(encoded) catch {
    e => fail("decode_base64: \{to_repr(e)}")
  }
  inspect(decoded.length(), content="4")
  inspect(decoded[0].to_int(), content="0")
  inspect(decoded[1].to_int(), content="255")
  inspect(decoded[2].to_int(), content="127")
  inspect(decoded[3].to_int(), content="128")
}

///|
test "base64/roundtrip_empty" {
  let encoded = encode_base64(b"")
  let decoded = decode_base64(encoded) catch {
    e => fail("decode_base64 empty: \{to_repr(e)}")
  }
  inspect(decoded.length(), content="0")
}

///|
test "base64/roundtrip_longer" {
  let original = Bytes::from_array([
    b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06',
  ])
  let encoded = encode_base64(original)
  let decoded = decode_base64(encoded) catch {
    e => fail("decode_base64 longer: \{to_repr(e)}")
  }
  let mut same = true
  for i in 0..<original.length() {
    if original[i] != decoded[i] {
      same = false
    }
  }
  inspect(same, content="true")
}

///|
test "base64/decode_ignores_whitespace" {
  let original = Bytes::from_array([b'\xab', b'\xcd'])
  let encoded = encode_base64(original)
  // 插入空格和换行
  let with_spaces = "\{encoded} \n \r"
  let decoded = decode_base64(with_spaces) catch {
    e => fail("decode_base64 spaces: \{to_repr(e)}")
  }
  inspect(decoded.length(), content="2")
  inspect(decoded[0].to_int(), content="171") // 0xab
  inspect(decoded[1].to_int(), content="205") // 0xcd
}
