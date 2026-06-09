///| known_hosts 解析单元测试：OpenSSH 兼容格式。

test "parse_line basic entry" {
  let line = "myhost.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICXYZ"
  let entry = parse_line(line) ?? fail("should parse")
  assert_eq(entry.patterns.length(), 1)
  assert_eq(entry.patterns[0], "myhost.example.com")
  assert_eq(entry.key_alg, "ssh-ed25519")
  assert_true(entry.key.length() > 0)
}

test "parse_line multiple comma patterns" {
  let line = "host1,host2,*.example.com ssh-rsa ABCDEFGHIJKLMNOP"
  let entry = parse_line(line) ?? fail("should parse")
  assert_eq(entry.patterns.length(), 3)
  assert_eq(entry.patterns[0], "host1")
  assert_eq(entry.patterns[1], "host2")
  assert_eq(entry.patterns[2], "*.example.com")
}

test "parse_line comment returns None" {
  let result = parse_line("# this is a comment")
  match result {
    None => ()
    Some(_) => fail("comment should return None")
  }
}

test "parse_line empty line returns None" {
  let result = parse_line("")
  match result {
    None => ()
    Some(_) => fail("empty line should return None")
  }
}

test "parse_line too few fields returns None" {
  let result = parse_line("justonefield")
  match result {
    None => ()
    Some(_) => fail("too few fields should return None")
  }
}

test "parse_file multi-line content" {
  let content = "host1 ssh-ed25519 AAAA\n#comment\nhost2 ssh-rsa BBBB\n\n"
  let entries = parse_file(content)
  assert_eq(entries.length(), 2)
  assert_eq(entries[0].patterns[0], "host1")
  assert_eq(entries[1].patterns[0], "host2")
}

test "KnownHost matches exact hostname" {
  let entry : KnownHost = {
    patterns: ["exact.example.com"],
    key_alg: "ssh-ed25519",
    key: b"key",
  }
  assert_true(entry.matches("exact.example.com", 22))
  assert_false(entry.matches("other.example.com", 22))
}

test "KnownHost matches wildcard pattern" {
  let entry : KnownHost = {
    patterns: ["*.example.com"],
    key_alg: "ssh-ed25519",
    key: b"key",
  }
  assert_true(entry.matches("foo.example.com", 22))
  assert_true(entry.matches("bar.example.com", 22))
  assert_false(entry.matches("notexample.org", 22))
}

test "KnownHost matches port in brackets" {
  let entry : KnownHost = {
    patterns: ["[host.example.com]:2222"],
    key_alg: "ssh-ed25519",
    key: b"key",
  }
  assert_true(entry.matches("host.example.com", 2222))
  assert_false(entry.matches("host.example.com", 22))
}

test "pattern_matches question mark wildcard" {
  // This tests internal function indirectly via KnownHost
  let entry : KnownHost = {
    patterns: ["host?.example.com"],
    key_alg: "ssh-ed25519",
    key: b"key",
  }
  assert_true(entry.matches("hosta.example.com", 22))
  assert_true(entry.matches("hostZ.example.com", 22))
  assert_false(entry.matches("hostname.example.com", 22))
}

test "format_entry roundtrip preserves key type" {
  let entry : KnownHost = {
    patterns: ["myhost"],
    key_alg: "ecdsa-sha2-nistp256",
    key: b"\x00\x01\x02\x03",
  }
  let line = entry.format_entry()
  assert_true(line.contains("myhost"))
  assert_true(line.contains("ecdsa-sha2-nistp256"))
}

test "base64 encode-decode roundtrip" {
  let original = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
  let encoded = encode_base64(original)
  let decoded = decode_base64(encoded)
  assert_eq(decoded, original)
}

test "base64 decode rejects invalid characters" {
  try
    decode_base64("!!!invalid!!!")
    raise "should have raised"
  catch {
    ProtocolError(msg) => assert_true(msg.contains("base64"))
    _ => fail("expected ProtocolError")
  }
}

test "trim_ascii strips whitespace" {
  // Indirect test through parsing
  let line = "   host ssh-ed25519 AAAA   "
  let entry = parse_line(line) ?? fail("should parse trimmed line")
  assert_eq(entry.patterns[0], "host")
}
