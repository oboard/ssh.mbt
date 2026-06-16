///|
pub fn get_argv() -> Array[String] {
  let s = @env.get_env_var("MOONBIT_CLI_ARGS").unwrap_or("")
  if s.length() == 0 {
    []
  } else {
    tokenize_args(s)
  }
}

///|
/// 简单的命令行参数 tokenizer，支持单引号和双引号。
/// 例如：`user@host --exec 'uname -a' --password "my pass"`
/// 解析为：["user@host", "--exec", "uname -a", "--password", "my pass"]
pub fn tokenize_args(s : String) -> Array[String] {
  let arr = s.to_array()
  let mut i = 0
  let result : Array[String] = []
  while i < arr.length() {
    let c = arr.unsafe_get(i)
    if c == ' ' || c == '\t' {
      i = i + 1
    } else if c == '\'' {
      // 单引号：读取直到下一个单引号
      i = i + 1
      let mut buf = ""
      while i < arr.length() && arr.unsafe_get(i) != '\'' {
        buf = buf + arr.unsafe_get(i).to_string()
        i = i + 1
      }
      if i < arr.length() {
        i = i + 1
      } // 跳过结束引号
      result.push(buf)
    } else if c == '"' {
      // 双引号：读取直到下一个双引号
      i = i + 1
      let mut buf = ""
      while i < arr.length() && arr.unsafe_get(i) != '"' {
        buf = buf + arr.unsafe_get(i).to_string()
        i = i + 1
      }
      if i < arr.length() {
        i = i + 1
      } // 跳过结束引号
      result.push(buf)
    } else {
      // 普通字符：读取直到空格
      let mut buf = ""
      while i < arr.length() &&
            arr.unsafe_get(i) != ' ' &&
            arr.unsafe_get(i) != '\t' {
        buf = buf + arr.unsafe_get(i).to_string()
        i = i + 1
      }
      result.push(buf)
    }
  }
  result
}

///|
pub fn split_user_host(s : String) -> (String, String) {
  let arr = s.to_array()
  let mut at_idx = -1
  let mut i = 0
  while i < arr.length() {
    if arr.unsafe_get(i) == '@' {
      at_idx = i
      break
    }
    i = i + 1
  }
  if at_idx < 0 {
    ("root", s)
  } else {
    let sb1 = StringBuilder::new()
    let sb2 = StringBuilder::new()
    for j = 0; j < at_idx; j = j + 1 {
      sb1.write_char(arr.unsafe_get(j))
    }
    for j = at_idx + 1; j < s.length(); j = j + 1 {
      sb2.write_char(arr.unsafe_get(j))
    }
    (sb1.to_string(), sb2.to_string())
  }
}

///|
pub fn parse_int(s : String) -> Int {
  let arr = s.to_array()
  let mut n = 0
  let mut i = 0
  let mut neg = false
  if arr.length() > 0 && arr.unsafe_get(0) == '-' {
    neg = true
    i = 1
  }
  while i < arr.length() {
    let c = arr.unsafe_get(i)
    if c < '0' || c > '9' {
      break
    }
    n = n * 10 + (c.to_int() - '0'.to_int())
    i = i + 1
  }
  if neg {
    -n
  } else {
    n
  }
}
