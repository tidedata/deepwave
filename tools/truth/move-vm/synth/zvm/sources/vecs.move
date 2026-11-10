module zvm::vecs;

public struct S has copy, drop, store { a: u64, b: vector<u8>, c: bool }

const BIG: vector<u64> = vector[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
const BYTES: vector<u8> = b"the quick brown fox jumps over the lazy dog";
const ADDRS: vector<address> = vector[@0x1, @0x2, @0xabc];
const NEST: vector<vector<u16>> = vector[vector[1, 2], vector[], vector[3]];

public fun get(v: vector<u64>, i: u64): u64 { v[i] }
public fun get_ref(v: &vector<u64>, i: u64): u64 { *v.borrow(i) }
public fun set(v: &mut vector<u64>, i: u64, x: u64) { *v.borrow_mut(i) = x; }
public fun pop2(v: &mut vector<u8>): (u8, u8) { let a = v.pop_back(); let b = v.pop_back(); (a, b) }
public fun swap(v: &mut vector<address>, i: u64, j: u64) { v.swap(i, j); }
public fun swap_u256(mut v: vector<u256>, i: u64, j: u64): vector<u256> { v.swap(i, j); v }
public fun push_n(v: &mut vector<u128>, x: u128, n: u8) { let mut i = 0; while (i < n) { v.push_back(x + (i as u128)); i = i + 1; } }
public fun rev(mut v: vector<u32>): vector<u32> { v.reverse(); v }
public fun rev_s(mut v: vector<S>): vector<S> { v.reverse(); v }
public fun drain(mut v: vector<S>): u64 { let mut s = 0; while (!v.is_empty()) { let S { a, b, c } = v.pop_back(); s = s + a % 1000 + b.length(); if (c) s = s + 1; }; v.destroy_empty(); s }
public fun eqv(a: vector<u64>, b: vector<u64>): bool { a == b }
public fun eqs(a: S, b: S): bool { a == b }
public fun eq_nested(a: vector<vector<bool>>, b: vector<vector<bool>>): bool { a == b && &a == &b }
public fun eq_refs(a: &vector<S>, b: &vector<S>): bool { a == b }
public fun consts(): (vector<u64>, vector<u8>, vector<address>, vector<vector<u16>>) { (BIG, BYTES, ADDRS, NEST) }
public fun const_len(i: u64): u64 { BIG[i % 20] + BYTES.length() + NEST[i % 3].length() }
public fun lit(a: u64, b: u64): vector<u64> { vector[a, b, a, b, 1, 2, 3] }
public fun lit_s(a: S, b: S): vector<S> { vector[a, b, a] }
public fun lit_empty(): (vector<S>, vector<vector<u8>>) { (vector[], vector[vector[]]) }
public fun unpack3(v: vector<u64>): u64 { let mut v = v; let a = v.pop_back(); let b = v.pop_back(); let c = v.pop_back(); v.destroy_empty(); a + b + c }
public fun field_vec(s: &mut S, x: u8) { s.b.push_back(x); s.a = s.a / 2; s.c = !s.c; }
public fun copy_big(s: S, n: u8): vector<S> { let mut v = vector[]; let mut i = 0; while (i < n) { v.push_back(copy s); i = i + 1; }; v }
public fun read_big(v: &vector<S>): vector<S> { *v }
public fun contains(v: &vector<u64>, x: u64): bool { v.contains(&x) }
public fun index_of(v: &vector<address>, x: address): (bool, u64) { v.index_of(&x) }
public fun remove(mut v: vector<u16>, i: u64): (u16, vector<u16>) { let x = v.remove(i); (x, v) }
public fun insert(mut v: vector<u16>, x: u16, i: u64): vector<u16> { v.insert(x, i); v }
public fun append(mut a: vector<u8>, b: vector<u8>): vector<u8> { a.append(b); a }
public fun bools(v: vector<bool>): u64 { let mut n = 0; let mut i = 0; while (i < v.length()) { if (v[i]) n = n + 1; i = i + 1; }; n }
public fun many(n: u64): u64 { let n = n % 2000; let mut v = vector[]; let mut i = 0; while (i < n) { v.push_back(i); i = i + 1; }; v.length() }
