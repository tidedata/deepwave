module zvm::refs;

public struct Pt has copy, drop, store { x: u64, y: u64 }
public struct Box<T> has copy, drop, store { v: T, tag: u8 }
public struct Deep has copy, drop { a: Box<Box<vector<Pt>>>, b: vector<Box<u128>> }

public fun mv(p: &mut Pt, dx: u64) { p.x = p.x + dx; let y = &mut p.y; *y = *y / 2; }
public fun swap(a: &mut Pt, b: &mut Pt) { let t = *a; *a = *b; *b = t; }
public fun sum(p: &Pt): u64 { p.x / 2 + p.y / 2 }
public fun boxed<T: copy + drop>(b: &mut Box<T>, v: T) { b.v = v; b.tag = b.tag / 2 + 1; }
public fun unbox<T: copy + drop>(b: Box<T>): (T, u8) { let Box { v, tag } = b; (v, tag) }
public fun deep_read(d: &Deep): vector<Pt> { d.a.v.v }
public fun deep_write(d: &mut Deep, p: Pt) { d.a.v.v.push_back(p); d.a.tag = 1; d.b.push_back(Box { v: 1, tag: 2 }); }
public fun deep_eq(a: &Deep, b: &Deep): bool { a == b && *a == *b }
public fun freeze_it(p: &mut Pt): u64 { let f: &Pt = p; f.x / 3 }
public fun local_refs(a: u64, b: u64): u64 { let mut x = a; let r = &mut x; *r = *r / 2; let y = &b; *y / 2 + x }
public fun vec_of_refs(v: &mut vector<Pt>, i: u64) { let p = &mut v[i]; p.x = 0; }
public fun copy_deep(d: Deep, n: u8): vector<Deep> { let mut v = vector[]; let mut i = 0; while (i < n % 8) { v.push_back(copy d); i = i + 1; }; v }
public fun tuple_ret(p: Pt): (u64, u64, Pt, Box<Pt>) { (p.x, p.y, p, Box { v: p, tag: 0 }) }
public fun unbox_into<T: copy + drop>(x: T): Box<T> { Box { v: x, tag: 7 } }
