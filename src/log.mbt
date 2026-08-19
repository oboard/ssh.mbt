///|
/// SSH 调试日志模块。
/// 通过全局开关控制调试输出，仅在启用时输出日志和 hex dump。

///|
/// 全局调试开关。默认关闭。
let debug_enabled : Ref[Bool] = Ref(false)

///|
/// 启用调试输出。
pub fn enable_debug() -> Unit {
  debug_enabled.val = true
}

///|
/// 禁用调试输出。
pub fn disable_debug() -> Unit {
  debug_enabled.val = false
}

///|
/// 查询调试输出是否启用。
pub fn is_debug_enabled() -> Bool {
  debug_enabled.val
}

///|
/// 仅在调试模式开启时输出日志。
pub fn debug(msg : String) -> Unit {
  if debug_enabled.val {
    println(msg)
  }
}

///|
fn hex_nibble_to_string(n : Int) -> String {
  if n < 10 {
    (n + 48).unsafe_to_char().to_string()
  } else {
    (n - 10 + 97).unsafe_to_char().to_string()
  }
}

///|
/// 以 Wireshark 风格打印字节的 hex dump（仅调试模式）。
pub fn hex_dump(label : String, data : Bytes) -> Unit {
  if !debug_enabled.val {
    return
  }
  println("* \{label}:")
  let len = data.length()
  let arr = data.to_fixedarray()
  let mut i = 0
  while i < len {
    let addr_str = hex_nibble_to_string((i >> 16) & 0xf) +
      hex_nibble_to_string((i >> 12) & 0xf) +
      hex_nibble_to_string((i >> 8) & 0xf) +
      hex_nibble_to_string((i >> 4) & 0xf) +
      hex_nibble_to_string(i & 0xf)
    let mut hex_part = ""
    let mut ascii_part = ""
    for j = 0; j < 16; j = j + 1 {
      let idx = i + j
      if idx < len {
        let b_val = arr.unsafe_get(idx).to_int()
        hex_part = hex_part +
          hex_nibble_to_string((b_val >> 4) & 0xf) +
          hex_nibble_to_string(b_val & 0xf) +
          " "
        if b_val >= 0x20 && b_val < 0x7f {
          ascii_part = ascii_part + b_val.unsafe_to_char().to_string()
        } else {
          ascii_part = ascii_part + "."
        }
      } else {
        hex_part = hex_part + "   "
        ascii_part = ascii_part + " "
      }
    }
    println(addr_str + ":  " + hex_part + " " + ascii_part)
    i = i + 16
  }
}
