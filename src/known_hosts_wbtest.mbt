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
