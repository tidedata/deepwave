/// The truth tool rotates every jump table of this module after compiling it (synth_packages),
/// so variant unpacks meet the wrong tag at run time: VARIANT_TAG_MISMATCH paths.
module zvm::mis;

public enum Shape has copy, drop, store {
    Empty,
    Dot(u8),
    Line { from: u64, to: u64 },
    Poly(vector<u64>, bool),
    Nested(vector<u8>),
}

public enum Maybe<T> has copy, drop, store { No, Yes(T) }

public fun area(s: Shape): u64 {
    match (s) {
        Shape::Empty => 0,
        Shape::Dot(x) => x as u64,
        Shape::Line { from, to } => from / 2 + to / 2,
        Shape::Poly(v, closed) => if (closed) v.length() * 2 else v.length(),
        Shape::Nested(_) => 7,
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
        Shape::Empty => {},
        Shape::Dot(x) => { *x = *x / 2 + k / 2 },
        Shape::Line { from, to: _ } => { *from = *from / 3 },
        Shape::Poly(v, c) => { v.push_back(k as u64); *c = !*c },
        Shape::Nested(_) => {},
    }
}

public fun get_or<T: copy + drop>(m: Maybe<T>, d: T): T { match (m) { Maybe::No => d, Maybe::Yes(x) => x } }
