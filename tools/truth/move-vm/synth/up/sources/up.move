module zvm::up;

use zvm::enums::{Self, Shape, Maybe};
use zvm::refs::{Pt, Box};

public enum Tri<T> has copy, drop, store { A(T), B(T, T), C { t: vector<T> } }

public fun tri_len<T: copy + drop>(t: &Tri<T>): u64 { match (t) { Tri::A(_) => 1, Tri::B(_, _) => 2, Tri::C { t } => t.length() } }
public fun from_shape(s: Shape): Tri<Shape> { if (enums::is_dot(&s)) Tri::A(s) else Tri::B(s, s) }
public fun maybe_pt(m: Maybe<Pt>, p: Pt): Pt { enums::get_or(m, p) }
public fun boxes(b: vector<Box<Tri<u8>>>): u64 { b.length() }
public fun area_all(v: vector<Shape>): u64 { enums::shapes(v) }
public fun tri_a<T>(x: T): Tri<T> { Tri::A(x) }
