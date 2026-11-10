module zvm::enums;

public enum Shape has copy, drop, store {
    Empty,
    Dot(u8),
    Line { from: u64, to: u64 },
    Poly(vector<u64>, bool),
    Nested(Inner),
}

public enum Inner has copy, drop, store { X, Y(u128), Z { s: vector<u8> } }

public enum Maybe<T> has copy, drop, store { No, Yes(T) }

public enum Big has copy, drop { V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10(u8), V11 { a: u256 } }

public fun area(s: Shape): u64 {
    match (s) {
        Shape::Empty => 0,
        Shape::Dot(x) => x as u64,
        Shape::Line { from, to } => if (to > from) to - from else from - to,
        Shape::Poly(v, closed) => if (closed) v.length() * 2 else v.length(),
        Shape::Nested(i) => match (i) { Inner::X => 1, Inner::Y(y) => (y % 1000) as u64, Inner::Z { s } => s.length() },
    }
}

public fun area_ref(s: &Shape): u64 {
    match (s) {
        Shape::Empty => 0,
        Shape::Dot(x) => *x as u64,
        Shape::Line { from, to } => *from / 2 + *to / 2,
        Shape::Poly(v, _) => v.length(),
        Shape::Nested(_) => 9,
    }
}

public fun grow(s: &mut Shape, k: u8) {
    match (s) {
        Shape::Empty => { *s = Shape::Dot(k) },
        Shape::Dot(x) => { *x = *x / 2 + k / 2 },
        Shape::Line { from, to: _ } => { *from = *from / 3 },
        Shape::Poly(v, c) => { v.push_back(k as u64); *c = !*c },
        Shape::Nested(i) => { *i = Inner::Y(k as u128) },
    }
}

public fun make(t: u8, a: u64, b: u64): Shape {
    match (t % 6) {
        0 => Shape::Empty,
        1 => Shape::Dot((a % 256) as u8),
        2 => Shape::Line { from: a, to: b },
        3 => Shape::Poly(vector[a, b], a > b),
        4 => Shape::Nested(Inner::Z { s: b"zz" }),
        _ => Shape::Nested(Inner::X),
    }
}

public fun big(b: Big): u256 {
    match (b) {
        Big::V0 => 0, Big::V1 => 1, Big::V2 => 2, Big::V3 => 3, Big::V4 => 4, Big::V5 => 5,
        Big::V6 => 6, Big::V7 => 7, Big::V8 => 8, Big::V9 => 9,
        Big::V10(x) => x as u256, Big::V11 { a } => a / 2,
    }
}

public fun get_or<T: copy + drop>(m: Maybe<T>, d: T): T { match (m) { Maybe::No => d, Maybe::Yes(x) => x } }
public fun wrap<T: copy + drop>(x: T, b: bool): Maybe<T> { if (b) Maybe::Yes(x) else Maybe::No }
public fun shapes(v: vector<Shape>): u64 { let mut s = 0; let mut i = 0; while (i < v.length()) { s = s + area_ref(&v[i]); i = i + 1; }; s }
public fun eq(a: Shape, b: Shape): bool { a == b }
public fun eq_maybe(a: Maybe<vector<u8>>, b: Maybe<vector<u8>>): bool { a == b }
public fun swap_in(v: &mut vector<Shape>, i: u64, s: Shape): Shape { v.push_back(s); v.swap_remove(i) }
public fun is_dot(s: &Shape): bool { match (s) { Shape::Dot(_) => true, _ => false } }
public fun nested_maybe(m: Maybe<Maybe<Shape>>): u64 { match (m) { Maybe::Yes(Maybe::Yes(s)) => area(s), Maybe::Yes(Maybe::No) => 1, Maybe::No => 0 } }
