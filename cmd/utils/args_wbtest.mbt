// Whitebox tests for cmd/utils/args.mbt.
// Run `moon test` to execute.

///|
test "tokenize_args/empty" {
  inspect(tokenize_args(""), content="[]")
  // 纯空白应当返回空数组
  inspect(tokenize_args(" "), content="[]")
  inspect(tokenize_args("   "), content="[]")
  inspect(tokenize_args("\t\t"), content="[]")
  inspect(tokenize_args(" \t \t "), content="[]")
}

///|
test "tokenize_args/single_token" {
  inspect(tokenize_args("hello"), content="[hello]")
  // 前后空白被忽略
  inspect(tokenize_args("  hello  "), content="[hello]")
  inspect(tokenize_args("\thello\t"), content="[hello]")
}

///|
test "tokenize_args/multiple_tokens" {
  inspect(
    tokenize_args("user@host --exec uname -a"),
    content="[user@host, --exec, uname, -a]",
  )
  // 多个空格/制表符视为一个分隔符
  inspect(tokenize_args("a   b\t\tc"), content="[a, b, c]")
}

///|
test "tokenize_args/single_quoted" {
  // 来自 args.mbt 文档的样例
  inspect(
    tokenize_args("user@host --exec 'uname -a' --password \"my pass\""),
    content="[user@host, --exec, uname -a, --password, my pass]",
  )
  // 纯单引号字符串
  inspect(tokenize_args("'hello world'"), content="[hello world]")
  // 引号紧贴分词
  inspect(tokenize_args("foo'bar baz'qux"), content="[foo'bar, baz'qux]")
}

///|
test "tokenize_args/double_quoted" {
  // 含空格的双引号字符串
  inspect(tokenize_args("\"my pass\""), content="[my pass]")
  inspect(tokenize_args("\"hello world\" foo"), content="[hello world, foo]")
}

///|
test "tokenize_args/empty_quoted_produces_one_token" {
  // 空引号应当产生一个空字符串元素；通过长度来校验，
  // 因为 Show 把空字符串渲染为空。
  let a = tokenize_args("''")
  inspect(a.length(), content="1")
  let b = tokenize_args("\"\"")
  inspect(b.length(), content="1")
  // 空引号夹在普通 token 中
  let c = tokenize_args("a '' b")
  inspect(c.length(), content="3")
  inspect(c[0], content="a")
  inspect(c[1], content="")
  inspect(c[2], content="b")
  let d = tokenize_args("a \"\" b")
  inspect(d.length(), content="3")
  inspect(d[1], content="")
}

///|
test "tokenize_args/unmatched_quote_reads_to_end" {
  // 没有结束引号时，函数读取至字符串末尾
  inspect(tokenize_args("'unterminated"), content="[unterminated]")
  inspect(tokenize_args("\"unterminated"), content="[unterminated]")
  // 引号内的尾部空白也一并吞下
  inspect(tokenize_args("'hello   "), content="[hello   ]")
}

///|
test "split_user_host/normal" {
  let (u, h) = split_user_host("user@host")
  inspect(u, content="user")
  inspect(h, content="host")
}

///|
test "split_user_host/no_at_defaults_to_root" {
  // 没有 @ 时默认用户为 root
  let (u, h) = split_user_host("host")
  inspect(u, content="root")
  inspect(h, content="host")
  let (u2, h2) = split_user_host("192.168.1.1")
  inspect(u2, content="root")
  inspect(h2, content="192.168.1.1")
}

///|
test "split_user_host/empty_user_or_host" {
  // @ 在开头 —— 用户名为空
  let (u, h) = split_user_host("@host")
  inspect(u, content="")
  inspect(h, content="host")
  // @ 在末尾 —— 主机名为空
  let (u2, h2) = split_user_host("user@")
  inspect(u2, content="user")
  inspect(h2, content="")
  // 只有一个 @ —— 用户和主机都为空
  let (u3, h3) = split_user_host("@")
  inspect(u3, content="")
  inspect(h3, content="")
}

///|
test "split_user_host/uses_last_at" {
  // 多个 @ 时以第一个作为分隔符
  let (u, h) = split_user_host("user@host@extra")
  inspect(u, content="user")
  inspect(h, content="host@extra")
  let (u2, h2) = split_user_host("a@b@c@d")
  inspect(u2, content="a")
  inspect(h2, content="b@c@d")
}

///|
test "split_user_host/empty_string" {
  // 空串视为无 @，因此 user = "root"，host = ""
  let (u, h) = split_user_host("")
  inspect(u, content="root")
  inspect(h, content="")
}

///|
test "parse_int/positive" {
  inspect(parse_int("0"), content="0")
  inspect(parse_int("1"), content="1")
  inspect(parse_int("42"), content="42")
  inspect(parse_int("12345"), content="12345")
  // 前导 0 仍然正确解析
  inspect(parse_int("007"), content="7")
  inspect(parse_int("00042"), content="42")
}

///|
test "parse_int/negative" {
  inspect(parse_int("-1"), content="-1")
  inspect(parse_int("-42"), content="-42")
  inspect(parse_int("-12345"), content="-12345")
}

///|
test "parse_int/non_numeric" {
  // 非数字返回 0
  inspect(parse_int(""), content="0")
  inspect(parse_int("abc"), content="0")
  inspect(parse_int("-"), content="0")
  // 数字后跟非数字 —— 截断到首个非数字
  inspect(parse_int("123abc"), content="123")
  inspect(parse_int("42xyz"), content="42")
  // 负号后无数字
  inspect(parse_int("-abc"), content="0")
  // 数字中混入字符（在中段遇到非数字即停止）
  inspect(parse_int("12x34"), content="12")
}

///|
test "get_argv/empty_when_unset" {
  // 清除可能由其它测试设置的变量
  @env.set_env_var("MOONBIT_CLI_ARGS", "")
  let argv = get_argv()
  inspect(argv, content="[]")
}

///|
test "get_argv/tokenizes_env_value" {
  // get_argv 应当对环境变量值复用 tokenize_args
  @env.set_env_var("MOONBIT_CLI_ARGS", "user@host --exec 'uname -a'")
  let argv = get_argv()
  inspect(argv, content="[user@host, --exec, uname -a]")
  // 测试结束后清理，避免影响其它测试
  @env.set_env_var("MOONBIT_CLI_ARGS", "")
}

// ============== parse_forward_arg ==============

///|
test "parse_forward_arg/basic" {
  let (lp, rh, rp) = parse_forward_arg("8080:example.com:80")
  inspect(lp, content="8080")
  inspect(rh, content="example.com")
  inspect(rp, content="80")
}

///|
test "parse_forward_arg/localhost" {
  let (lp, rh, rp) = parse_forward_arg("9090:localhost:3000")
  inspect(lp, content="9090")
  inspect(rh, content="localhost")
  inspect(rp, content="3000")
}

///|
test "parse_forward_arg/ip_address" {
  let (lp, rh, rp) = parse_forward_arg("1080:192.168.1.1:22")
  inspect(lp, content="1080")
  inspect(rh, content="192.168.1.1")
  inspect(rp, content="22")
}

///|
test "panic_parse_forward_arg/none" {
  let _ = parse_forward_arg("")
}
