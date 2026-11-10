module zvm::ints;

public fun arith_u8(a: u8, b: u8): (u8, u8, u8, u8, u8) { (a + b, a - b, a * b, a / b, a % b) }
public fun wrap_u8(a: u8, b: u8): u8 { let mut x = a; let mut i = 0; while (i < 4) { x = (x ^ b) | (x & b); i = i + 1; }; x }
public fun bits_u8(a: u8, b: u8, s: u8): (u8, u8, u8, u8, u8) { (a & b, a | b, a ^ b, a << s, b >> s) }
public fun cmp_u8(a: u8, b: u8): (bool, bool, bool, bool, bool, bool) { (a < b, a > b, a <= b, a >= b, a == b, a != b) }
public fun casts_u8(a: u8): (u8, u16, u32, u64, u128, u256) { ((a as u8), (a as u16), (a as u32), (a as u64), (a as u128), (a as u256)) }
public fun safe_casts_u8(a: u8): (u8, u16, u32, u64, u128, u256) { (((a & 0xff) as u8), ((a & 0xff) as u16), ((a & 0xff) as u32), ((a & 0xff) as u64), (a as u128) / 1 + 0, (a as u256)) }
public fun sum_u8(v: vector<u8>): u8 { let mut s = 0; let mut i = 0; let n = v.length(); while (i < n) { s = s + *v.borrow(i); i = i + 1; }; s }
public fun shl_loop_u8(a: u8, n: u8): u8 { let mut x = a; let mut i = 0; while (i < n) { x = (x << 1) | (x >> 7); i = i + 1; }; x }
public fun max_u8(v: &vector<u8>): u8 { let mut m = 0; let mut i = 0; while (i < v.length()) { if (v[i] > m) m = v[i]; i = i + 1; }; m }

public fun arith_u16(a: u16, b: u16): (u16, u16, u16, u16, u16) { (a + b, a - b, a * b, a / b, a % b) }
public fun wrap_u16(a: u16, b: u16): u16 { let mut x = a; let mut i = 0; while (i < 4) { x = (x ^ b) | (x & b); i = i + 1; }; x }
public fun bits_u16(a: u16, b: u16, s: u8): (u16, u16, u16, u16, u16) { (a & b, a | b, a ^ b, a << s, b >> s) }
public fun cmp_u16(a: u16, b: u16): (bool, bool, bool, bool, bool, bool) { (a < b, a > b, a <= b, a >= b, a == b, a != b) }
public fun casts_u16(a: u16): (u8, u16, u32, u64, u128, u256) { ((a as u8), (a as u16), (a as u32), (a as u64), (a as u128), (a as u256)) }
public fun safe_casts_u16(a: u16): (u8, u16, u32, u64, u128, u256) { (((a & 0xff) as u8), ((a & 0xff) as u16), ((a & 0xff) as u32), ((a & 0xff) as u64), (a as u128) / 1 + 0, (a as u256)) }
public fun sum_u16(v: vector<u16>): u16 { let mut s = 0; let mut i = 0; let n = v.length(); while (i < n) { s = s + *v.borrow(i); i = i + 1; }; s }
public fun shl_loop_u16(a: u16, n: u8): u16 { let mut x = a; let mut i = 0; while (i < n) { x = (x << 1) | (x >> 7); i = i + 1; }; x }
public fun max_u16(v: &vector<u16>): u16 { let mut m = 0; let mut i = 0; while (i < v.length()) { if (v[i] > m) m = v[i]; i = i + 1; }; m }

public fun arith_u32(a: u32, b: u32): (u32, u32, u32, u32, u32) { (a + b, a - b, a * b, a / b, a % b) }
public fun wrap_u32(a: u32, b: u32): u32 { let mut x = a; let mut i = 0; while (i < 4) { x = (x ^ b) | (x & b); i = i + 1; }; x }
public fun bits_u32(a: u32, b: u32, s: u8): (u32, u32, u32, u32, u32) { (a & b, a | b, a ^ b, a << s, b >> s) }
public fun cmp_u32(a: u32, b: u32): (bool, bool, bool, bool, bool, bool) { (a < b, a > b, a <= b, a >= b, a == b, a != b) }
public fun casts_u32(a: u32): (u8, u16, u32, u64, u128, u256) { ((a as u8), (a as u16), (a as u32), (a as u64), (a as u128), (a as u256)) }
public fun safe_casts_u32(a: u32): (u8, u16, u32, u64, u128, u256) { (((a & 0xff) as u8), ((a & 0xff) as u16), ((a & 0xff) as u32), ((a & 0xff) as u64), (a as u128) / 1 + 0, (a as u256)) }
public fun sum_u32(v: vector<u32>): u32 { let mut s = 0; let mut i = 0; let n = v.length(); while (i < n) { s = s + *v.borrow(i); i = i + 1; }; s }
public fun shl_loop_u32(a: u32, n: u8): u32 { let mut x = a; let mut i = 0; while (i < n) { x = (x << 1) | (x >> 7); i = i + 1; }; x }
public fun max_u32(v: &vector<u32>): u32 { let mut m = 0; let mut i = 0; while (i < v.length()) { if (v[i] > m) m = v[i]; i = i + 1; }; m }

public fun arith_u64(a: u64, b: u64): (u64, u64, u64, u64, u64) { (a + b, a - b, a * b, a / b, a % b) }
public fun wrap_u64(a: u64, b: u64): u64 { let mut x = a; let mut i = 0; while (i < 4) { x = (x ^ b) | (x & b); i = i + 1; }; x }
public fun bits_u64(a: u64, b: u64, s: u8): (u64, u64, u64, u64, u64) { (a & b, a | b, a ^ b, a << s, b >> s) }
public fun cmp_u64(a: u64, b: u64): (bool, bool, bool, bool, bool, bool) { (a < b, a > b, a <= b, a >= b, a == b, a != b) }
public fun casts_u64(a: u64): (u8, u16, u32, u64, u128, u256) { ((a as u8), (a as u16), (a as u32), (a as u64), (a as u128), (a as u256)) }
public fun safe_casts_u64(a: u64): (u8, u16, u32, u64, u128, u256) { (((a & 0xff) as u8), ((a & 0xff) as u16), ((a & 0xff) as u32), ((a & 0xff) as u64), (a as u128) / 1 + 0, (a as u256)) }
public fun sum_u64(v: vector<u64>): u64 { let mut s = 0; let mut i = 0; let n = v.length(); while (i < n) { s = s + *v.borrow(i); i = i + 1; }; s }
public fun shl_loop_u64(a: u64, n: u8): u64 { let mut x = a; let mut i = 0; while (i < n) { x = (x << 1) | (x >> 7); i = i + 1; }; x }
public fun max_u64(v: &vector<u64>): u64 { let mut m = 0; let mut i = 0; while (i < v.length()) { if (v[i] > m) m = v[i]; i = i + 1; }; m }

public fun arith_u128(a: u128, b: u128): (u128, u128, u128, u128, u128) { (a + b, a - b, a * b, a / b, a % b) }
public fun wrap_u128(a: u128, b: u128): u128 { let mut x = a; let mut i = 0; while (i < 4) { x = (x ^ b) | (x & b); i = i + 1; }; x }
public fun bits_u128(a: u128, b: u128, s: u8): (u128, u128, u128, u128, u128) { (a & b, a | b, a ^ b, a << s, b >> s) }
public fun cmp_u128(a: u128, b: u128): (bool, bool, bool, bool, bool, bool) { (a < b, a > b, a <= b, a >= b, a == b, a != b) }
public fun casts_u128(a: u128): (u8, u16, u32, u64, u128, u256) { ((a as u8), (a as u16), (a as u32), (a as u64), (a as u128), (a as u256)) }
public fun safe_casts_u128(a: u128): (u8, u16, u32, u64, u128, u256) { (((a & 0xff) as u8), ((a & 0xff) as u16), ((a & 0xff) as u32), ((a & 0xff) as u64), (a as u128) / 1 + 0, (a as u256)) }
public fun sum_u128(v: vector<u128>): u128 { let mut s = 0; let mut i = 0; let n = v.length(); while (i < n) { s = s + *v.borrow(i); i = i + 1; }; s }
public fun shl_loop_u128(a: u128, n: u8): u128 { let mut x = a; let mut i = 0; while (i < n) { x = (x << 1) | (x >> 7); i = i + 1; }; x }
public fun max_u128(v: &vector<u128>): u128 { let mut m = 0; let mut i = 0; while (i < v.length()) { if (v[i] > m) m = v[i]; i = i + 1; }; m }

public fun arith_u256(a: u256, b: u256): (u256, u256, u256, u256, u256) { (a + b, a - b, a * b, a / b, a % b) }
public fun wrap_u256(a: u256, b: u256): u256 { let mut x = a; let mut i = 0; while (i < 4) { x = (x ^ b) | (x & b); i = i + 1; }; x }
public fun bits_u256(a: u256, b: u256, s: u8): (u256, u256, u256, u256, u256) { (a & b, a | b, a ^ b, a << s, b >> s) }
public fun cmp_u256(a: u256, b: u256): (bool, bool, bool, bool, bool, bool) { (a < b, a > b, a <= b, a >= b, a == b, a != b) }
public fun casts_u256(a: u256): (u8, u16, u32, u64, u128, u256) { ((a as u8), (a as u16), (a as u32), (a as u64), (a as u128), (a as u256)) }
public fun safe_casts_u256(a: u256): (u8, u16, u32, u64, u128, u256) { (((a & 0xff) as u8), ((a & 0xff) as u16), ((a & 0xff) as u32), ((a & 0xff) as u64), (a as u128) / 1 + 0, (a as u256)) }
public fun sum_u256(v: vector<u256>): u256 { let mut s = 0; let mut i = 0; let n = v.length(); while (i < n) { s = s + *v.borrow(i); i = i + 1; }; s }
public fun shl_loop_u256(a: u256, n: u8): u256 { let mut x = a; let mut i = 0; while (i < n) { x = (x << 1) | (x >> 7); i = i + 1; }; x }
public fun max_u256(v: &vector<u256>): u256 { let mut m = 0; let mut i = 0; while (i < v.length()) { if (v[i] > m) m = v[i]; i = i + 1; }; m }

public fun logic(a: bool, b: bool): (bool, bool, bool, bool) { (a && b, a || b, !a, a != b) }
public fun mixed(a: u64, b: u128, c: u256, d: u8): u256 { ((a as u256) * (b as u256) + c) >> (d % 200) }
public fun safe_mixed(a: u64, b: u128, c: u8): u256 { ((a as u256) * (b as u256)) >> (c % 255) }
public fun abort_if(a: u64, code: u64): u64 { if (a % 3 == 0) abort code; a + 0 }
public fun assert_lt(a: u64, b: u64): u64 { assert!(a < b, 77); b - a }
