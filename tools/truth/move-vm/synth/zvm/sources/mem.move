// Memory bounds (reviewer round 1, finding 1): every loop runs until it is out of gas at the
// default budget. zui must keep a session's memory bounded by its live data, as Rust frees each
// frame on return and each value where it is dropped.
module zvm::mem;

public struct S has copy, drop { a: u64, b: vector<u64>, c: u256 }

public enum E<T> has copy, drop { A(T), B(T, u64), C }

// 1 parameter + 250 locals: the frame is the largest Move allows a body to have (255 locals).
public fun big(x: u64): u64 {
    let a0 = x + 0;
    let a1 = x + 1;
    let a2 = x + 2;
    let a3 = x + 3;
    let a4 = x + 4;
    let a5 = x + 5;
    let a6 = x + 6;
    let a7 = x + 7;
    let a8 = x + 8;
    let a9 = x + 9;
    let a10 = x + 10;
    let a11 = x + 11;
    let a12 = x + 12;
    let a13 = x + 13;
    let a14 = x + 14;
    let a15 = x + 15;
    let a16 = x + 16;
    let a17 = x + 17;
    let a18 = x + 18;
    let a19 = x + 19;
    let a20 = x + 20;
    let a21 = x + 21;
    let a22 = x + 22;
    let a23 = x + 23;
    let a24 = x + 24;
    let a25 = x + 25;
    let a26 = x + 26;
    let a27 = x + 27;
    let a28 = x + 28;
    let a29 = x + 29;
    let a30 = x + 30;
    let a31 = x + 31;
    let a32 = x + 32;
    let a33 = x + 33;
    let a34 = x + 34;
    let a35 = x + 35;
    let a36 = x + 36;
    let a37 = x + 37;
    let a38 = x + 38;
    let a39 = x + 39;
    let a40 = x + 40;
    let a41 = x + 41;
    let a42 = x + 42;
    let a43 = x + 43;
    let a44 = x + 44;
    let a45 = x + 45;
    let a46 = x + 46;
    let a47 = x + 47;
    let a48 = x + 48;
    let a49 = x + 49;
    let a50 = x + 50;
    let a51 = x + 51;
    let a52 = x + 52;
    let a53 = x + 53;
    let a54 = x + 54;
    let a55 = x + 55;
    let a56 = x + 56;
    let a57 = x + 57;
    let a58 = x + 58;
    let a59 = x + 59;
    let a60 = x + 60;
    let a61 = x + 61;
    let a62 = x + 62;
    let a63 = x + 63;
    let a64 = x + 64;
    let a65 = x + 65;
    let a66 = x + 66;
    let a67 = x + 67;
    let a68 = x + 68;
    let a69 = x + 69;
    let a70 = x + 70;
    let a71 = x + 71;
    let a72 = x + 72;
    let a73 = x + 73;
    let a74 = x + 74;
    let a75 = x + 75;
    let a76 = x + 76;
    let a77 = x + 77;
    let a78 = x + 78;
    let a79 = x + 79;
    let a80 = x + 80;
    let a81 = x + 81;
    let a82 = x + 82;
    let a83 = x + 83;
    let a84 = x + 84;
    let a85 = x + 85;
    let a86 = x + 86;
    let a87 = x + 87;
    let a88 = x + 88;
    let a89 = x + 89;
    let a90 = x + 90;
    let a91 = x + 91;
    let a92 = x + 92;
    let a93 = x + 93;
    let a94 = x + 94;
    let a95 = x + 95;
    let a96 = x + 96;
    let a97 = x + 97;
    let a98 = x + 98;
    let a99 = x + 99;
    let a100 = x + 100;
    let a101 = x + 101;
    let a102 = x + 102;
    let a103 = x + 103;
    let a104 = x + 104;
    let a105 = x + 105;
    let a106 = x + 106;
    let a107 = x + 107;
    let a108 = x + 108;
    let a109 = x + 109;
    let a110 = x + 110;
    let a111 = x + 111;
    let a112 = x + 112;
    let a113 = x + 113;
    let a114 = x + 114;
    let a115 = x + 115;
    let a116 = x + 116;
    let a117 = x + 117;
    let a118 = x + 118;
    let a119 = x + 119;
    let a120 = x + 120;
    let a121 = x + 121;
    let a122 = x + 122;
    let a123 = x + 123;
    let a124 = x + 124;
    let a125 = x + 125;
    let a126 = x + 126;
    let a127 = x + 127;
    let a128 = x + 128;
    let a129 = x + 129;
    let a130 = x + 130;
    let a131 = x + 131;
    let a132 = x + 132;
    let a133 = x + 133;
    let a134 = x + 134;
    let a135 = x + 135;
    let a136 = x + 136;
    let a137 = x + 137;
    let a138 = x + 138;
    let a139 = x + 139;
    let a140 = x + 140;
    let a141 = x + 141;
    let a142 = x + 142;
    let a143 = x + 143;
    let a144 = x + 144;
    let a145 = x + 145;
    let a146 = x + 146;
    let a147 = x + 147;
    let a148 = x + 148;
    let a149 = x + 149;
    let a150 = x + 150;
    let a151 = x + 151;
    let a152 = x + 152;
    let a153 = x + 153;
    let a154 = x + 154;
    let a155 = x + 155;
    let a156 = x + 156;
    let a157 = x + 157;
    let a158 = x + 158;
    let a159 = x + 159;
    let a160 = x + 160;
    let a161 = x + 161;
    let a162 = x + 162;
    let a163 = x + 163;
    let a164 = x + 164;
    let a165 = x + 165;
    let a166 = x + 166;
    let a167 = x + 167;
    let a168 = x + 168;
    let a169 = x + 169;
    let a170 = x + 170;
    let a171 = x + 171;
    let a172 = x + 172;
    let a173 = x + 173;
    let a174 = x + 174;
    let a175 = x + 175;
    let a176 = x + 176;
    let a177 = x + 177;
    let a178 = x + 178;
    let a179 = x + 179;
    let a180 = x + 180;
    let a181 = x + 181;
    let a182 = x + 182;
    let a183 = x + 183;
    let a184 = x + 184;
    let a185 = x + 185;
    let a186 = x + 186;
    let a187 = x + 187;
    let a188 = x + 188;
    let a189 = x + 189;
    let a190 = x + 190;
    let a191 = x + 191;
    let a192 = x + 192;
    let a193 = x + 193;
    let a194 = x + 194;
    let a195 = x + 195;
    let a196 = x + 196;
    let a197 = x + 197;
    let a198 = x + 198;
    let a199 = x + 199;
    let a200 = x + 200;
    let a201 = x + 201;
    let a202 = x + 202;
    let a203 = x + 203;
    let a204 = x + 204;
    let a205 = x + 205;
    let a206 = x + 206;
    let a207 = x + 207;
    let a208 = x + 208;
    let a209 = x + 209;
    let a210 = x + 210;
    let a211 = x + 211;
    let a212 = x + 212;
    let a213 = x + 213;
    let a214 = x + 214;
    let a215 = x + 215;
    let a216 = x + 216;
    let a217 = x + 217;
    let a218 = x + 218;
    let a219 = x + 219;
    let a220 = x + 220;
    let a221 = x + 221;
    let a222 = x + 222;
    let a223 = x + 223;
    let a224 = x + 224;
    let a225 = x + 225;
    let a226 = x + 226;
    let a227 = x + 227;
    let a228 = x + 228;
    let a229 = x + 229;
    let a230 = x + 230;
    let a231 = x + 231;
    let a232 = x + 232;
    let a233 = x + 233;
    let a234 = x + 234;
    let a235 = x + 235;
    let a236 = x + 236;
    let a237 = x + 237;
    let a238 = x + 238;
    let a239 = x + 239;
    let a240 = x + 240;
    let a241 = x + 241;
    let a242 = x + 242;
    let a243 = x + 243;
    let a244 = x + 244;
    let a245 = x + 245;
    let a246 = x + 246;
    let a247 = x + 247;
    let a248 = x + 248;
    let a249 = x + 249;
    (a0 ^ a1 ^ a2 ^ a3 ^ a4 ^ a5 ^ a6 ^ a7 ^ a8 ^ a9 ^ a10 ^ a11 ^ a12 ^ a13 ^ a14 ^ a15 ^ a16 ^ a17 ^ a18 ^ a19 ^ a20 ^ a21 ^ a22 ^ a23 ^ a24 ^ a25 ^ a26 ^ a27 ^ a28 ^ a29 ^ a30 ^ a31 ^ a32 ^ a33 ^ a34 ^ a35 ^ a36 ^ a37 ^ a38 ^ a39 ^ a40 ^ a41 ^ a42 ^ a43 ^ a44 ^ a45 ^ a46 ^ a47 ^ a48 ^ a49 ^ a50 ^ a51 ^ a52 ^ a53 ^ a54 ^ a55 ^ a56 ^ a57 ^ a58 ^ a59 ^ a60 ^ a61 ^ a62 ^ a63 ^ a64 ^ a65 ^ a66 ^ a67 ^ a68 ^ a69 ^ a70 ^ a71 ^ a72 ^ a73 ^ a74 ^ a75 ^ a76 ^ a77 ^ a78 ^ a79 ^ a80 ^ a81 ^ a82 ^ a83 ^ a84 ^ a85 ^ a86 ^ a87 ^ a88 ^ a89 ^ a90 ^ a91 ^ a92 ^ a93 ^ a94 ^ a95 ^ a96 ^ a97 ^ a98 ^ a99 ^ a100 ^ a101 ^ a102 ^ a103 ^ a104 ^ a105 ^ a106 ^ a107 ^ a108 ^ a109 ^ a110 ^ a111 ^ a112 ^ a113 ^ a114 ^ a115 ^ a116 ^ a117 ^ a118 ^ a119 ^ a120 ^ a121 ^ a122 ^ a123 ^ a124 ^ a125 ^ a126 ^ a127 ^ a128 ^ a129 ^ a130 ^ a131 ^ a132 ^ a133 ^ a134 ^ a135 ^ a136 ^ a137 ^ a138 ^ a139 ^ a140 ^ a141 ^ a142 ^ a143 ^ a144 ^ a145 ^ a146 ^ a147 ^ a148 ^ a149 ^ a150 ^ a151 ^ a152 ^ a153 ^ a154 ^ a155 ^ a156 ^ a157 ^ a158 ^ a159 ^ a160 ^ a161 ^ a162 ^ a163 ^ a164 ^ a165 ^ a166 ^ a167 ^ a168 ^ a169 ^ a170 ^ a171 ^ a172 ^ a173 ^ a174 ^ a175 ^ a176 ^ a177 ^ a178 ^ a179 ^ a180 ^ a181 ^ a182 ^ a183 ^ a184 ^ a185 ^ a186 ^ a187 ^ a188 ^ a189 ^ a190 ^ a191 ^ a192 ^ a193 ^ a194 ^ a195 ^ a196 ^ a197 ^ a198 ^ a199 ^ a200 ^ a201 ^ a202 ^ a203 ^ a204 ^ a205 ^ a206 ^ a207 ^ a208 ^ a209 ^ a210 ^ a211 ^ a212 ^ a213 ^ a214 ^ a215 ^ a216 ^ a217 ^ a218 ^ a219 ^ a220 ^ a221 ^ a222 ^ a223 ^ a224 ^ a225 ^ a226 ^ a227 ^ a228 ^ a229 ^ a230 ^ a231 ^ a232 ^ a233 ^ a234 ^ a235 ^ a236 ^ a237 ^ a238 ^ a239 ^ a240 ^ a241 ^ a242 ^ a243 ^ a244 ^ a245 ^ a246 ^ a247 ^ a248 ^ a249)
        + (a0 | a1 | a2 | a3 | a4 | a5 | a6 | a7 | a8 | a9 | a10 | a11 | a12 | a13 | a14 | a15 | a16 | a17 | a18 | a19 | a20 | a21 | a22 | a23 | a24 | a25 | a26 | a27 | a28 | a29 | a30 | a31 | a32 | a33 | a34 | a35 | a36 | a37 | a38 | a39 | a40 | a41 | a42 | a43 | a44 | a45 | a46 | a47 | a48 | a49 | a50 | a51 | a52 | a53 | a54 | a55 | a56 | a57 | a58 | a59 | a60 | a61 | a62 | a63 | a64 | a65 | a66 | a67 | a68 | a69 | a70 | a71 | a72 | a73 | a74 | a75 | a76 | a77 | a78 | a79 | a80 | a81 | a82 | a83 | a84 | a85 | a86 | a87 | a88 | a89 | a90 | a91 | a92 | a93 | a94 | a95 | a96 | a97 | a98 | a99 | a100 | a101 | a102 | a103 | a104 | a105 | a106 | a107 | a108 | a109 | a110 | a111 | a112 | a113 | a114 | a115 | a116 | a117 | a118 | a119 | a120 | a121 | a122 | a123 | a124 | a125 | a126 | a127 | a128 | a129 | a130 | a131 | a132 | a133 | a134 | a135 | a136 | a137 | a138 | a139 | a140 | a141 | a142 | a143 | a144 | a145 | a146 | a147 | a148 | a149 | a150 | a151 | a152 | a153 | a154 | a155 | a156 | a157 | a158 | a159 | a160 | a161 | a162 | a163 | a164 | a165 | a166 | a167 | a168 | a169 | a170 | a171 | a172 | a173 | a174 | a175 | a176 | a177 | a178 | a179 | a180 | a181 | a182 | a183 | a184 | a185 | a186 | a187 | a188 | a189 | a190 | a191 | a192 | a193 | a194 | a195 | a196 | a197 | a198 | a199 | a200 | a201 | a202 | a203 | a204 | a205 | a206 | a207 | a208 | a209 | a210 | a211 | a212 | a213 | a214 | a215 | a216 | a217 | a218 | a219 | a220 | a221 | a222 | a223 | a224 | a225 | a226 | a227 | a228 | a229 | a230 | a231 | a232 | a233 | a234 | a235 | a236 | a237 | a238 | a239 | a240 | a241 | a242 | a243 | a244 | a245 | a246 | a247 | a248 | a249)
}

public fun calls_big(): u64 {
    let mut s = 0;
    loop { s = big(s % 1000); }
}

public fun u256_add(): u256 {
    let mut x: u256 = 1;
    loop { x = x + 3; }
}

public fun u256_vec(): u256 {
    let mut v = vector<u256>[1, 2, 3, 4];
    let mut i = 0;
    loop {
        let r = &mut v[i % 4];
        *r = *r + 1;
        i = i + 1;
    }
}

public fun copy_vec(): u64 {
    let mut v = vector<u64>[];
    let mut i = 0;
    while (i < 64) { v.push_back(i); i = i + 1; };
    let mut n = 0;
    loop {
        let w = v;
        n = n + w.length();
    }
}

public fun grow_shrink(): u64 {
    let mut v = vector<S>[];
    let mut n = 0;
    loop {
        let mut i = 0;
        while (i < 100) { v.push_back(S { a: i, b: vector[i, i], c: 7 }); i = i + 1; };
        while (!v.is_empty()) { let S { a, b, c: _ } = v.pop_back(); n = n + a + b.length(); };
    }
}

public fun id<T: copy + drop>(x: T): T { x }

public fun n1<T: copy + drop>(x: T): u64 { n2<vector<T>>(vector[x]) + 1 }
public fun n2<T: copy + drop>(x: T): u64 { n3<vector<T>>(vector[x]) + 1 }
public fun n3<T: copy + drop>(x: T): u64 { n4<E<T>>(E::A(x)) + 1 }
public fun n4<T: copy + drop>(x: T): u64 { let v = vector[x, x]; v.length() }

public fun generic_calls(): u64 {
    let mut n = 0;
    loop {
        n = n + n1<u64>(id<u64>(n));
        let e = id<E<vector<u8>>>(E::B(vector[1], n));
        match (e) { E::A(_) => n = n + 1, E::B(_, k) => n = n + k % 2, E::C => n = n + 3 };
    }
}

public fun eq_loop(): u64 {
    let s = S { a: 1, b: vector[1, 2, 3], c: 9 };
    let mut n = 0;
    loop {
        if (copy s == S { a: 1, b: vector[1, 2, 3], c: 9 }) n = n + 1;
    }
}
