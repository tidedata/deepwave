module zvm::depth;

public struct W<T> has copy, drop, store { v: T }
public struct P<A, B> has copy, drop, store { a: A, b: B }

public fun d0<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d1(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d1<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d2(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d2<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d3(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d3<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d4(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d4<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d5(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d5<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d6(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d6<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d7(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d7<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d8(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d8<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d9(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d9<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d10(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d10<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d11(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d11<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d12(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d12<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d13(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d13<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d14(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d14<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d15(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d15<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d16(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d16<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d17(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d17<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d18(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d18<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d19(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d19<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d20(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d20<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d21(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d21<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d22(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d22<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d23(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d23<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d24(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d24<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d25(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d25<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d26(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d26<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d27(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d27<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d28(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d28<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d29(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d29<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d30(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d30<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d31(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d31<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d32(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d32<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d33(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d33<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d34(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d34<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d35(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d35<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d36(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d36<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d37(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d37<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d38(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d38<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; d39(W { v: W { v: W { v: W { v: x } } } }, n - 1) }
public fun d39<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; n as u64 }
public fun p0<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; p1(P { a: x, b: x }, n - 1) }
public fun p1<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; p2(P { a: x, b: x }, n - 1) }
public fun p2<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; p3(P { a: x, b: x }, n - 1) }
public fun p3<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; p4(P { a: x, b: x }, n - 1) }
public fun p4<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; p5(P { a: x, b: x }, n - 1) }
public fun p5<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; p6(P { a: x, b: x }, n - 1) }
public fun p6<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; p7(P { a: x, b: x }, n - 1) }
public fun p7<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; p8(P { a: x, b: x }, n - 1) }
public fun p8<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; p9(P { a: x, b: x }, n - 1) }
public fun p9<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; p10(P { a: x, b: x }, n - 1) }
public fun p10<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; p11(P { a: x, b: x }, n - 1) }
public fun p11<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; p12(P { a: x, b: x }, n - 1) }
public fun p12<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; p13(P { a: x, b: x }, n - 1) }
public fun p13<T: copy + drop>(x: T, n: u8): u64 { if (n == 0) return 0; n as u64 }
public fun start_w(n: u8): u64 { d0(1u8, n) }
public fun start_p(n: u8): u64 { p0(true, n) }
public fun start_pv(n: u8): u64 { p0(vector[1u64, 2], n) }
public fun nest_vec(n: u8): u64 { let mut v = vector[vector[1u64]]; let mut i = 0; while (i < n) { v.push_back(vector[i as u64]); i = i + 1; }; v.length() }
