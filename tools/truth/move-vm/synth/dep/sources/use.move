module zdep::use_it;

use zvm::enums::{Self, Shape, Maybe};
use zvm::up::{Self, Tri};
use zvm::refs::{Self, Pt, Box};
use zvm::depth;

public struct Holder<T> has copy, drop { shapes: vector<Shape>, tri: Tri<T>, m: Maybe<Box<T>> }

public fun hold<T: copy + drop>(h: &Holder<T>): u64 { enums::shapes(h.shapes) + up::tri_len(&h.tri) }
public fun cross(s: Shape, p: Pt): (u64, Tri<Shape>, Pt) { let a = enums::area(s); (a, up::from_shape(s), up::maybe_pt(enums::wrap(p, a % 2 == 0), p)) }
public fun cross_depth(n: u8): u64 { depth::start_w(n) + depth::start_p(n % 12) }
public fun mutate(p: &mut Pt, h: &mut Holder<u16>, x: u16) { refs::mv(p, x as u64); h.shapes.push_back(enums::make((x % 256) as u8, 1, 2)); }
public fun generic_hold<T: copy + drop>(x: T, n: u8): Holder<T> { Holder { shapes: vector[enums::make(n, 3, 4)], tri: up::tri_a(x), m: enums::wrap(refs::unbox_into(x), n % 2 == 0) } }
