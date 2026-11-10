// Reviewer edge cases (round 1) taken from move-vm-runtime 1.83.1 `values_impl.rs`:
// the vector length limit (`push_back` against `max_move_vector_len`), in-place swaps with equal
// indices, Eq between an indexed (primitive vector element) reference and a local reference,
// and writes through element references of u256 and struct vectors.
module zvm::rv;

public struct B has copy, drop, store { a: u64 }

const LIMIT: u64 = 262144;

// LIMIT + (n % 2) pushes: odd n fails the last push with VEC_SIZE_LIMIT_REACHED. The loops are
// unrolled 16 times so the whole fill fits the default budget.
public fun fill_u8(n: u64): u64 {
    let mut v = vector<u8>[];
    let r = &mut v;
    let mut i = 0;
    while (i < LIMIT / 16) {
        r.push_back(7);
        r.push_back(7);
        r.push_back(7);
        r.push_back(7);
        r.push_back(7);
        r.push_back(7);
        r.push_back(7);
        r.push_back(7);
        r.push_back(7);
        r.push_back(7);
        r.push_back(7);
        r.push_back(7);
        r.push_back(7);
        r.push_back(7);
        r.push_back(7);
        r.push_back(7);
        i = i + 1;
    };
    if (n % 2 == 1) r.push_back(8);
    v.length()
}

public fun fill_s(n: u64): u64 {
    let mut v = vector<B>[];
    let r = &mut v;
    let mut i = 0;
    while (i < LIMIT / 16) {
        r.push_back(B { a: 7 });
        r.push_back(B { a: 7 });
        r.push_back(B { a: 7 });
        r.push_back(B { a: 7 });
        r.push_back(B { a: 7 });
        r.push_back(B { a: 7 });
        r.push_back(B { a: 7 });
        r.push_back(B { a: 7 });
        r.push_back(B { a: 7 });
        r.push_back(B { a: 7 });
        r.push_back(B { a: 7 });
        r.push_back(B { a: 7 });
        r.push_back(B { a: 7 });
        r.push_back(B { a: 7 });
        r.push_back(B { a: 7 });
        r.push_back(B { a: 7 });
        i = i + 1;
    };
    if (n % 2 == 1) r.push_back(B { a: 8 });
    v.length()
}

public fun swap_same(mut v: vector<B>, i: u64): vector<B> {
    v.push_back(B { a: i });
    let k = i % v.length();
    v.swap(k, k);
    v.swap(0, k);
    v
}

public fun swap_same_u256(mut v: vector<u256>, i: u64): vector<u256> {
    v.push_back((i as u256));
    let k = i % v.length();
    v.swap(k, k);
    v.swap(k, 0);
    v
}

public fun eq_mixed(mut v: vector<u64>, x: u64): (bool, bool, bool) {
    v.push_back(x);
    let n = v.length();
    let a = &v[n - 1] == &x;
    let b = &x == &v[0];
    let c = &v[0] != &v[n - 1];
    (a, b, c)
}

public fun eq_mixed_addr(mut v: vector<address>, x: address): (bool, bool) {
    v.push_back(x);
    let n = v.length();
    (&v[n - 1] == &x, &x == &v[0])
}

public fun wr256(mut v: vector<u256>, x: u256): vector<u256> {
    v.push_back(1);
    let r = &mut v[0];
    *r = x;
    *r = *r / 2 + 1;
    v
}

public fun wr_struct(mut v: vector<B>, x: u64): vector<B> {
    v.push_back(B { a: 0 });
    let n = v.length();
    let r = &mut v[n - 1];
    r.a = x;
    *r = B { a: r.a / 3 };
    v
}

public fun pop_empty_s(): B {
    let mut v = vector<B>[];
    v.pop_back()
}

