module zvm::rec;

public fun fib(n: u8): u64 { let n = n % 16; if (n < 2) n as u64 else fib(n - 1) + fib(n - 2) }
public fun deep(n: u64): u64 { if (n == 0) 0 else 1 + deep(n - 1) }
public fun deep_held(n: u64): u64 { if (n == 0) 0 else n + (n * 2 + (n / 2 + deep_held(n - 1))) }
public fun even(n: u64): bool { if (n == 0) true else odd(n - 1) }
public fun odd(n: u64): bool { if (n == 0) false else even(n - 1) }
public fun gen_deep<T: copy + drop>(x: T, n: u64): T { if (n == 0) x else gen_deep(x, n - 1) }
public fun start_gen(x: vector<u8>, n: u16): vector<u8> { gen_deep(x, n as u64) }
public fun ack(m: u8, n: u8): u64 { ackr((m % 3) as u64, (n % 6) as u64) }
fun ackr(m: u64, n: u64): u64 { if (m == 0) n + 1 else if (n == 0) ackr(m - 1, 1) else ackr(m - 1, ackr(m, n - 1)) }
public fun spin(n: u64): u64 { let n = n % 3000; let mut i = 0; let mut x = 0; while (i < n) { x = x ^ i; i = i + 1; }; x }
public fun nested_loops(a: u8, b: u8): u64 { let mut s = 0; let mut i = 0; while (i < a) { let mut j = 0; while (j < b) { if (j == 7) break; s = s + (i as u64) * (j as u64); j = j + 1; }; i = i + 1; if (s > 100000) return s; }; s }
public fun loop_abort(n: u64): u64 { let mut i = 0; loop { i = i + 1; if (i == n % 50) abort i; if (i > 40) return i } }
