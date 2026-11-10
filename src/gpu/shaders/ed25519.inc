#define ED_WORDS 44
// Ed25519 over GF(2^255 - 19): ten limbs in radix 2^25.5 (26, 25, 26, ... bits), u32 limbs and
// u64 products (ref10 / dalek u32 layout). Bounds: R = a carried value (even limbs < 2^26, odd
// limbs < 2^25 + 2^18). fx_mul/fx_sq/fx_sub return R; fx_add does not carry (R + R = 2R).
// fx_mul(f, g): f, g <= 3R limbwise (19 g_j and 38 g_odd fit u32; the column sums stay < 2^63).
// fx_sub(a, b): a <= 3R, b <= 3R (a + 4p - b, then one carry pass).
struct fx_e { u32 v[10]; };
FN fx_e fx_zero() { fx_e r; for (int i = 0; i < 10; i++) r.v[i] = 0; return r; }
FN fx_e fx_one() { fx_e r = fx_zero(); r.v[0] = 1; return r; }
#define FX_CARRY64(h) { \
  { u64 c = h##0 >> 26; h##0 &= 0x3ffffffu; h##1 += c; } \
  { u64 c = h##4 >> 26; h##4 &= 0x3ffffffu; h##5 += c; } \
  { u64 c = h##1 >> 25; h##1 &= 0x1ffffffu; h##2 += c; } \
  { u64 c = h##5 >> 25; h##5 &= 0x1ffffffu; h##6 += c; } \
  { u64 c = h##2 >> 26; h##2 &= 0x3ffffffu; h##3 += c; } \
  { u64 c = h##6 >> 26; h##6 &= 0x3ffffffu; h##7 += c; } \
  { u64 c = h##3 >> 25; h##3 &= 0x1ffffffu; h##4 += c; } \
  { u64 c = h##7 >> 25; h##7 &= 0x1ffffffu; h##8 += c; } \
  { u64 c = h##4 >> 26; h##4 &= 0x3ffffffu; h##5 += c; } \
  { u64 c = h##8 >> 26; h##8 &= 0x3ffffffu; h##9 += c; } \
  { u64 c = h##9 >> 25; h##9 &= 0x1ffffffu; h##0 += c * 19u; } \
  { u64 c = h##0 >> 26; h##0 &= 0x3ffffffu; h##1 += c; } \
}
#define FX_CARRY32(h) { \
  { u32 c = h##0 >> 26; h##0 &= 0x3ffffffu; h##1 += c; } \
  { u32 c = h##4 >> 26; h##4 &= 0x3ffffffu; h##5 += c; } \
  { u32 c = h##1 >> 25; h##1 &= 0x1ffffffu; h##2 += c; } \
  { u32 c = h##5 >> 25; h##5 &= 0x1ffffffu; h##6 += c; } \
  { u32 c = h##2 >> 26; h##2 &= 0x3ffffffu; h##3 += c; } \
  { u32 c = h##6 >> 26; h##6 &= 0x3ffffffu; h##7 += c; } \
  { u32 c = h##3 >> 25; h##3 &= 0x1ffffffu; h##4 += c; } \
  { u32 c = h##7 >> 25; h##7 &= 0x1ffffffu; h##8 += c; } \
  { u32 c = h##4 >> 26; h##4 &= 0x3ffffffu; h##5 += c; } \
  { u32 c = h##8 >> 26; h##8 &= 0x3ffffffu; h##9 += c; } \
  { u32 c = h##9 >> 25; h##9 &= 0x1ffffffu; h##0 += c * 19u; } \
  { u32 c = h##0 >> 26; h##0 &= 0x3ffffffu; h##1 += c; } \
}
#ifndef FXFN
#define FXFN FN
#endif
FXFN fx_e fx_mul(fx_e f, fx_e g) {
  u32 f0 = f.v[0]; u32 f1 = f.v[1]; u32 f2 = f.v[2]; u32 f3 = f.v[3]; u32 f4 = f.v[4]; u32 f5 = f.v[5]; u32 f6 = f.v[6]; u32 f7 = f.v[7]; u32 f8 = f.v[8]; u32 f9 = f.v[9];
  u32 g0 = g.v[0]; u32 g1 = g.v[1]; u32 g2 = g.v[2]; u32 g3 = g.v[3]; u32 g4 = g.v[4]; u32 g5 = g.v[5]; u32 g6 = g.v[6]; u32 g7 = g.v[7]; u32 g8 = g.v[8]; u32 g9 = g.v[9];
  u32 g1_19 = 19u * g1; u32 g2_19 = 19u * g2; u32 g3_19 = 19u * g3; u32 g4_19 = 19u * g4; u32 g5_19 = 19u * g5; u32 g6_19 = 19u * g6; u32 g7_19 = 19u * g7; u32 g8_19 = 19u * g8; u32 g9_19 = 19u * g9;
  u32 f1_2 = 2u * f1; u32 f3_2 = 2u * f3; u32 f5_2 = 2u * f5; u32 f7_2 = 2u * f7; u32 f9_2 = 2u * f9;
  u64 h0 = MULW(f0, g0) + MULW(f1_2, g9_19) + MULW(f2, g8_19) + MULW(f3_2, g7_19) + MULW(f4, g6_19) + MULW(f5_2, g5_19) + MULW(f6, g4_19) + MULW(f7_2, g3_19) + MULW(f8, g2_19) + MULW(f9_2, g1_19);
  u64 h1 = MULW(f0, g1) + MULW(f1, g0) + MULW(f2, g9_19) + MULW(f3, g8_19) + MULW(f4, g7_19) + MULW(f5, g6_19) + MULW(f6, g5_19) + MULW(f7, g4_19) + MULW(f8, g3_19) + MULW(f9, g2_19);
  u64 h2 = MULW(f0, g2) + MULW(f1_2, g1) + MULW(f2, g0) + MULW(f3_2, g9_19) + MULW(f4, g8_19) + MULW(f5_2, g7_19) + MULW(f6, g6_19) + MULW(f7_2, g5_19) + MULW(f8, g4_19) + MULW(f9_2, g3_19);
  u64 h3 = MULW(f0, g3) + MULW(f1, g2) + MULW(f2, g1) + MULW(f3, g0) + MULW(f4, g9_19) + MULW(f5, g8_19) + MULW(f6, g7_19) + MULW(f7, g6_19) + MULW(f8, g5_19) + MULW(f9, g4_19);
  u64 h4 = MULW(f0, g4) + MULW(f1_2, g3) + MULW(f2, g2) + MULW(f3_2, g1) + MULW(f4, g0) + MULW(f5_2, g9_19) + MULW(f6, g8_19) + MULW(f7_2, g7_19) + MULW(f8, g6_19) + MULW(f9_2, g5_19);
  u64 h5 = MULW(f0, g5) + MULW(f1, g4) + MULW(f2, g3) + MULW(f3, g2) + MULW(f4, g1) + MULW(f5, g0) + MULW(f6, g9_19) + MULW(f7, g8_19) + MULW(f8, g7_19) + MULW(f9, g6_19);
  u64 h6 = MULW(f0, g6) + MULW(f1_2, g5) + MULW(f2, g4) + MULW(f3_2, g3) + MULW(f4, g2) + MULW(f5_2, g1) + MULW(f6, g0) + MULW(f7_2, g9_19) + MULW(f8, g8_19) + MULW(f9_2, g7_19);
  u64 h7 = MULW(f0, g7) + MULW(f1, g6) + MULW(f2, g5) + MULW(f3, g4) + MULW(f4, g3) + MULW(f5, g2) + MULW(f6, g1) + MULW(f7, g0) + MULW(f8, g9_19) + MULW(f9, g8_19);
  u64 h8 = MULW(f0, g8) + MULW(f1_2, g7) + MULW(f2, g6) + MULW(f3_2, g5) + MULW(f4, g4) + MULW(f5_2, g3) + MULW(f6, g2) + MULW(f7_2, g1) + MULW(f8, g0) + MULW(f9_2, g9_19);
  u64 h9 = MULW(f0, g9) + MULW(f1, g8) + MULW(f2, g7) + MULW(f3, g6) + MULW(f4, g5) + MULW(f5, g4) + MULW(f6, g3) + MULW(f7, g2) + MULW(f8, g1) + MULW(f9, g0);
  FX_CARRY64(h)
  fx_e r; r.v[0] = (u32)h0; r.v[1] = (u32)h1; r.v[2] = (u32)h2; r.v[3] = (u32)h3; r.v[4] = (u32)h4; r.v[5] = (u32)h5; r.v[6] = (u32)h6; r.v[7] = (u32)h7; r.v[8] = (u32)h8; r.v[9] = (u32)h9; return r;
}
FXFN fx_e fx_sq(fx_e f) {
  u32 f0 = f.v[0]; u32 f1 = f.v[1]; u32 f2 = f.v[2]; u32 f3 = f.v[3]; u32 f4 = f.v[4]; u32 f5 = f.v[5]; u32 f6 = f.v[6]; u32 f7 = f.v[7]; u32 f8 = f.v[8]; u32 f9 = f.v[9];
  u32 f1_2 = 2u * f1; u32 f1_4 = 4u * f1; u32 f2_2 = 2u * f2; u32 f3_2 = 2u * f3; u32 f3_4 = 4u * f3; u32 f4_2 = 2u * f4; u32 f5_2 = 2u * f5; u32 f5_4 = 4u * f5; u32 f5_19 = 19u * f5; u32 f6_2 = 2u * f6; u32 f6_19 = 19u * f6; u32 f7_2 = 2u * f7; u32 f7_4 = 4u * f7; u32 f7_19 = 19u * f7; u32 f8_2 = 2u * f8; u32 f8_19 = 19u * f8; u32 f9_2 = 2u * f9; u32 f9_19 = 19u * f9;
  u64 h0 = MULW(f0, f0) + MULW(f1_4, f9_19) + MULW(f2_2, f8_19) + MULW(f3_4, f7_19) + MULW(f4_2, f6_19) + MULW(f5_2, f5_19);
  u64 h1 = MULW(f0, f1_2) + MULW(f2_2, f9_19) + MULW(f3_2, f8_19) + MULW(f4_2, f7_19) + MULW(f5_2, f6_19);
  u64 h2 = MULW(f0, f2_2) + MULW(f1, f1_2) + MULW(f3_4, f9_19) + MULW(f4_2, f8_19) + MULW(f5_4, f7_19) + MULW(f6, f6_19);
  u64 h3 = MULW(f0, f3_2) + MULW(f1, f2_2) + MULW(f4_2, f9_19) + MULW(f5_2, f8_19) + MULW(f6_2, f7_19);
  u64 h4 = MULW(f0, f4_2) + MULW(f1_2, f3_2) + MULW(f2, f2) + MULW(f5_4, f9_19) + MULW(f6_2, f8_19) + MULW(f7_2, f7_19);
  u64 h5 = MULW(f0, f5_2) + MULW(f1, f4_2) + MULW(f2, f3_2) + MULW(f6_2, f9_19) + MULW(f7_2, f8_19);
  u64 h6 = MULW(f0, f6_2) + MULW(f1_2, f5_2) + MULW(f2, f4_2) + MULW(f3, f3_2) + MULW(f7_4, f9_19) + MULW(f8, f8_19);
  u64 h7 = MULW(f0, f7_2) + MULW(f1, f6_2) + MULW(f2, f5_2) + MULW(f3, f4_2) + MULW(f8_2, f9_19);
  u64 h8 = MULW(f0, f8_2) + MULW(f1_2, f7_2) + MULW(f2, f6_2) + MULW(f3_2, f5_2) + MULW(f4, f4) + MULW(f9_2, f9_19);
  u64 h9 = MULW(f0, f9_2) + MULW(f1, f8_2) + MULW(f2, f7_2) + MULW(f3, f6_2) + MULW(f4, f5_2);
  FX_CARRY64(h)
  fx_e r; r.v[0] = (u32)h0; r.v[1] = (u32)h1; r.v[2] = (u32)h2; r.v[3] = (u32)h3; r.v[4] = (u32)h4; r.v[5] = (u32)h5; r.v[6] = (u32)h6; r.v[7] = (u32)h7; r.v[8] = (u32)h8; r.v[9] = (u32)h9; return r;
}
FN fx_e fx_add(fx_e a, fx_e b) { fx_e r; for (int i = 0; i < 10; i++) r.v[i] = a.v[i] + b.v[i]; return r; }
FN fx_e fx_sub(fx_e a, fx_e b) {
  u32 h0 = a.v[0] + 268435380u - b.v[0]; u32 h1 = a.v[1] + 134217724u - b.v[1]; u32 h2 = a.v[2] + 268435452u - b.v[2]; u32 h3 = a.v[3] + 134217724u - b.v[3]; u32 h4 = a.v[4] + 268435452u - b.v[4]; u32 h5 = a.v[5] + 134217724u - b.v[5]; u32 h6 = a.v[6] + 268435452u - b.v[6]; u32 h7 = a.v[7] + 134217724u - b.v[7]; u32 h8 = a.v[8] + 268435452u - b.v[8]; u32 h9 = a.v[9] + 134217724u - b.v[9];
  FX_CARRY32(h)
  fx_e r; r.v[0] = (u32)h0; r.v[1] = (u32)h1; r.v[2] = (u32)h2; r.v[3] = (u32)h3; r.v[4] = (u32)h4; r.v[5] = (u32)h5; r.v[6] = (u32)h6; r.v[7] = (u32)h7; r.v[8] = (u32)h8; r.v[9] = (u32)h9; return r;
}
FN fx_e fx_neg(fx_e a) { return fx_sub(fx_zero(), a); }
// canonical representative in [0, p) (limbs exact); input limbs < 2^31
FN fx_e fx_canon(fx_e a) {
  u32 h0 = a.v[0]; u32 h1 = a.v[1]; u32 h2 = a.v[2]; u32 h3 = a.v[3]; u32 h4 = a.v[4]; u32 h5 = a.v[5]; u32 h6 = a.v[6]; u32 h7 = a.v[7]; u32 h8 = a.v[8]; u32 h9 = a.v[9];
  { u32 c = h0 >> 26; h0 &= 0x3ffffffu; h1 += c; }
  { u32 c = h1 >> 25; h1 &= 0x1ffffffu; h2 += c; }
  { u32 c = h2 >> 26; h2 &= 0x3ffffffu; h3 += c; }
  { u32 c = h3 >> 25; h3 &= 0x1ffffffu; h4 += c; }
  { u32 c = h4 >> 26; h4 &= 0x3ffffffu; h5 += c; }
  { u32 c = h5 >> 25; h5 &= 0x1ffffffu; h6 += c; }
  { u32 c = h6 >> 26; h6 &= 0x3ffffffu; h7 += c; }
  { u32 c = h7 >> 25; h7 &= 0x1ffffffu; h8 += c; }
  { u32 c = h8 >> 26; h8 &= 0x3ffffffu; h9 += c; }
  { u32 c = h9 >> 25; h9 &= 0x1ffffffu; h0 += c * 19u; }
  { u32 c = h0 >> 26; h0 &= 0x3ffffffu; h1 += c; }
  { u32 c = h1 >> 25; h1 &= 0x1ffffffu; h2 += c; }
  { u32 c = h2 >> 26; h2 &= 0x3ffffffu; h3 += c; }
  { u32 c = h3 >> 25; h3 &= 0x1ffffffu; h4 += c; }
  { u32 c = h4 >> 26; h4 &= 0x3ffffffu; h5 += c; }
  { u32 c = h5 >> 25; h5 &= 0x1ffffffu; h6 += c; }
  { u32 c = h6 >> 26; h6 &= 0x3ffffffu; h7 += c; }
  { u32 c = h7 >> 25; h7 &= 0x1ffffffu; h8 += c; }
  { u32 c = h8 >> 26; h8 &= 0x3ffffffu; h9 += c; }
  { u32 c = h9 >> 25; h9 &= 0x1ffffffu; h0 += c * 19u; }
  u32 q = (h0 + 19u) >> 26;
  q = (h1 + q) >> 25;
  q = (h2 + q) >> 26;
  q = (h3 + q) >> 25;
  q = (h4 + q) >> 26;
  q = (h5 + q) >> 25;
  q = (h6 + q) >> 26;
  q = (h7 + q) >> 25;
  q = (h8 + q) >> 26;
  q = (h9 + q) >> 25;
  h0 += 19u * q;
  { u32 c = h0 >> 26; h0 &= 0x3ffffffu; h1 += c; }
  { u32 c = h1 >> 25; h1 &= 0x1ffffffu; h2 += c; }
  { u32 c = h2 >> 26; h2 &= 0x3ffffffu; h3 += c; }
  { u32 c = h3 >> 25; h3 &= 0x1ffffffu; h4 += c; }
  { u32 c = h4 >> 26; h4 &= 0x3ffffffu; h5 += c; }
  { u32 c = h5 >> 25; h5 &= 0x1ffffffu; h6 += c; }
  { u32 c = h6 >> 26; h6 &= 0x3ffffffu; h7 += c; }
  { u32 c = h7 >> 25; h7 &= 0x1ffffffu; h8 += c; }
  { u32 c = h8 >> 26; h8 &= 0x3ffffffu; h9 += c; }
  h9 &= 0x1ffffffu;
  fx_e r; r.v[0] = (u32)h0; r.v[1] = (u32)h1; r.v[2] = (u32)h2; r.v[3] = (u32)h3; r.v[4] = (u32)h4; r.v[5] = (u32)h5; r.v[6] = (u32)h6; r.v[7] = (u32)h7; r.v[8] = (u32)h8; r.v[9] = (u32)h9; return r;
}
// 256-bit little-endian words to limbs (bit 255 folds in as +19)
FN fx_e fx_unpack(u32 w0, u32 w1, u32 w2, u32 w3, u32 w4, u32 w5, u32 w6, u32 w7) {
  fx_e r;
  r.v[0] = w0 & 0x3ffffffu;
  r.v[1] = ((w0 >> 26) | (w1 << 6)) & 0x1ffffffu;
  r.v[2] = ((w1 >> 19) | (w2 << 13)) & 0x3ffffffu;
  r.v[3] = ((w2 >> 13) | (w3 << 19)) & 0x1ffffffu;
  r.v[4] = (w3 >> 6) & 0x3ffffffu;
  r.v[5] = w4 & 0x1ffffffu;
  r.v[6] = ((w4 >> 25) | (w5 << 7)) & 0x3ffffffu;
  r.v[7] = ((w5 >> 19) | (w6 << 13)) & 0x1ffffffu;
  r.v[8] = ((w6 >> 12) | (w7 << 20)) & 0x3ffffffu;
  r.v[9] = (w7 >> 6) & 0x1ffffffu;
  r.v[0] += 19u * (w7 >> 31);
  return r;
}
FN fx_e fx_load(GLOBAL const u32* p) { return fx_unpack(p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]); }
// constants are stored in limb form (10 words, carried)
FN fx_e fx_cload(GLOBAL const u32* p) { fx_e r; for (int i = 0; i < 10; i++) r.v[i] = p[i]; return r; }
FN void fx_store(GLOBAL u32* p, fx_e a) {
  fx_e c = fx_canon(a);
  p[0] = c.v[0] | (c.v[1] << 26);
  p[1] = (c.v[1] >> 6) | (c.v[2] << 19);
  p[2] = (c.v[2] >> 13) | (c.v[3] << 13);
  p[3] = (c.v[3] >> 19) | (c.v[4] << 6);
  p[4] = c.v[5] | (c.v[6] << 25);
  p[5] = (c.v[6] >> 7) | (c.v[7] << 19);
  p[6] = (c.v[7] >> 13) | (c.v[8] << 12);
  p[7] = (c.v[8] >> 20) | (c.v[9] << 6);
}
FN bool fx_is_zero(fx_e a) { fx_e c = fx_canon(a); u32 o = 0; for (int i = 0; i < 10; i++) o |= c.v[i]; return o == 0; }
FN bool fx_eq(fx_e a, fx_e b) { return fx_is_zero(fx_sub(a, b)); }
FN bool fx_is_neg(fx_e a) { return (fx_canon(a).v[0] & 1u) != 0; }
FN fx_e fx_sqn(fx_e a, int n) { for (int i = 0; i < n; i++) a = fx_sq(a); return a; }

// x^(2^252 - 3)
FN fx_e fx_pow2523(fx_e x) {
  fx_e z2 = fx_sq(x);
  fx_e z9 = fx_mul(fx_sqn(z2, 2), x);
  fx_e z11 = fx_mul(z9, z2);
  fx_e z5 = fx_mul(fx_sq(z11), z9);              // 2^5 - 1
  fx_e z10 = fx_mul(fx_sqn(z5, 5), z5);          // 2^10 - 1
  fx_e z20 = fx_mul(fx_sqn(z10, 10), z10);       // 2^20 - 1
  fx_e z40 = fx_mul(fx_sqn(z20, 20), z20);       // 2^40 - 1
  fx_e z50 = fx_mul(fx_sqn(z40, 10), z10);       // 2^50 - 1
  fx_e z100 = fx_mul(fx_sqn(z50, 50), z50);      // 2^100 - 1
  fx_e z200 = fx_mul(fx_sqn(z100, 100), z100);   // 2^200 - 1
  fx_e z250 = fx_mul(fx_sqn(z200, 50), z50);     // 2^250 - 1
  return fx_mul(fx_sqn(z250, 2), x);             // 2^252 - 3
}

// Extended (X:Y:Z:T), projective (X:Y:Z), completed ((X:Z), (Y:T)) and Niels forms, as
// curve25519-dalek / sig.ed25519 (the same group law, so the same final point).
struct EdP { fx_e x; fx_e y; fx_e z; fx_e t; };
struct EdC { fx_e x; fx_e y; fx_e z; fx_e t; };
struct EdPN { fx_e ypx; fx_e ymx; fx_e z; fx_e t2d; };

// dalek CompressedEdwardsY::decompress (ZIP-215): y = low 255 bits as given, x from sqrt_ratio_i,
// sign bit flips x (negative zero accepted). Returns false when u/v is not a square.
FN bool ed_decompress(GLOBAL const u32* b, GLOBAL const u32* cs, THREAD EdP* out) {
  u32 sign = b[7] >> 31;
  fx_e y = fx_unpack(b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7] & 0x7fffffffu);
  fx_e d = fx_cload(cs);
  fx_e yy = fx_sq(y);
  fx_e u = fx_sub(yy, fx_one());
  fx_e v = fx_add(fx_mul(yy, d), fx_one());
  fx_e v3 = fx_mul(fx_sq(v), v);
  fx_e v7 = fx_mul(fx_sq(v3), v);
  fx_e r = fx_mul(fx_mul(u, v3), fx_pow2523(fx_mul(u, v7)));
  fx_e check = fx_mul(v, fx_sq(r));
  fx_e nu = fx_neg(u);
  bool correct = fx_eq(check, u);
  bool flipped = fx_eq(check, nu);
  fx_e sqm1 = fx_cload(cs + 20);
  bool flipped_i = fx_eq(check, fx_mul(nu, sqm1));
  if (flipped || flipped_i) r = fx_mul(r, sqm1);
  if (fx_is_neg(r)) r = fx_neg(r);
  if (!(correct || flipped)) return false;
  fx_e x = r;
  if (sign) x = fx_neg(x);
  out->x = x; out->y = y; out->z = fx_one(); out->t = fx_mul(x, y);
  return true;
}

FN EdC ed_dbl_c(fx_e X, fx_e Y, fx_e Z) {
  fx_e xx = fx_sq(X), yy = fx_sq(Y), zz = fx_sq(Z);
  fx_e zz2 = fx_add(zz, zz);
  fx_e xpy2 = fx_sq(fx_add(X, Y));
  fx_e yypxx = fx_add(yy, xx), yymxx = fx_sub(yy, xx);
  EdC c; c.x = fx_sub(xpy2, yypxx); c.y = yypxx; c.z = yymxx; c.t = fx_sub(zz2, yymxx);
  return c;
}
FN EdP ed_c_ext(EdC c) { EdP p; p.x = fx_mul(c.x, c.t); p.y = fx_mul(c.y, c.z); p.z = fx_mul(c.z, c.t); p.t = fx_mul(c.x, c.y); return p; }
FN EdPN ed_pniels(EdP p, fx_e d2) { EdPN n; n.ypx = fx_add(p.y, p.x); n.ymx = fx_sub(p.y, p.x); n.z = p.z; n.t2d = fx_mul(p.t, d2); return n; }
// p + q (neg: p - q), q in projective Niels form
FN EdC ed_add_pn(EdP p, EdPN q, bool neg) {
  fx_e pp = fx_mul(fx_add(p.y, p.x), neg ? q.ymx : q.ypx);
  fx_e mm = fx_mul(fx_sub(p.y, p.x), neg ? q.ypx : q.ymx);
  fx_e tt = fx_mul(p.t, q.t2d);
  fx_e zz = fx_mul(p.z, q.z);
  fx_e zz2 = fx_add(zz, zz);
  EdC c; c.x = fx_sub(pp, mm); c.y = fx_add(pp, mm);
  if (neg) { c.z = fx_sub(zz2, tt); c.t = fx_add(zz2, tt); } else { c.z = fx_add(zz2, tt); c.t = fx_sub(zz2, tt); }
  return c;
}
// p + q (neg: p - q), q affine Niels (ypx, ymx, xy2d) at q[0..30]
FN EdC ed_add_an(EdP p, GLOBAL const u32* q, bool neg) {
  fx_e ypx = fx_cload(q), ymx = fx_cload(q + 10), xy2d = fx_cload(q + 20);
  fx_e pp = fx_mul(fx_add(p.y, p.x), neg ? ymx : ypx);
  fx_e mm = fx_mul(fx_sub(p.y, p.x), neg ? ypx : ymx);
  fx_e tt = fx_mul(p.t, xy2d);
  fx_e z2 = fx_add(p.z, p.z);
  EdC c; c.x = fx_sub(pp, mm); c.y = fx_add(pp, mm);
  if (neg) { c.z = fx_sub(z2, tt); c.t = fx_add(z2, tt); } else { c.z = fx_add(z2, tt); c.t = fx_sub(z2, tt); }
  return c;
}

// One verification, half-size form (sig.ed25519 checkHalf): [8]([c0]A + [c1]R - [t]B) == 0 with
// t = t_lo + 2^128 t_hi, as a fixed-window chain so every thread of a SIMD group adds at the same
// steps (a NAF chain diverges: with 32 threads some thread has a nonzero digit at nearly every
// position, so every thread pays for every add).
// item: A bytes (8 words), R bytes (8), flags (word 16: bit 1 s not canonical), then signed digits
// from byte 68: c0 and c1 signed radix 16 in [-8, 8] (33 each, c0 negated when negative), t_lo and
// t_hi signed radix 256 in [-128, 127] (17 each; subtracted). cs (limb form, 10 words per element):
// d, 2d, sqrt(-1), then kB and k(2^128 B) for k = 1..128 (affine Niels, 30 words each). scr: 640
// words of per-item scratch. Returns 1 valid, 0 invalid signature, 2 public key does not decode.
// per-thread scratch: P..8P of A then of R, projective Niels, 40 words each (limb form)
#define ED_SCR_WORDS 640
FN void ed_pn_put(GLOBAL u32* p, EdPN n) {
  for (int i = 0; i < 10; i++) { p[i] = n.ypx.v[i]; p[10 + i] = n.ymx.v[i]; p[20 + i] = n.z.v[i]; p[30 + i] = n.t2d.v[i]; }
}
FN EdPN ed_pn_get(GLOBAL const u32* p) {
  EdPN n;
  for (int i = 0; i < 10; i++) { n.ypx.v[i] = p[i]; n.ymx.v[i] = p[10 + i]; n.z.v[i] = p[20 + i]; n.t2d.v[i] = p[30 + i]; }
  return n;
}
FN u32 ed_verify_hs(GLOBAL const u32* it, GLOBAL const u32* cs, GLOBAL u32* scr) {
  EdP A, R;
  if (!ed_decompress(it, cs, &A)) return 2u;
  u32 flags = it[16];
  if (flags & 2u) return 0u;          // s not canonical
  if (!ed_decompress(it + 8, cs, &R)) return 0u;
  fx_e d2 = fx_cload(cs + 10);
  GLOBAL const u32* tb0 = cs + 30;
  GLOBAL const u32* tb1 = cs + 30 + 128 * 30;
  GLOBAL const I8G* da_ = (GLOBAL const I8G*)(it + 17);
  GLOBAL const I8G* dr_ = da_ + 33;
  GLOBAL const I8G* d0_ = da_ + 66;
  GLOBAL const I8G* d1_ = da_ + 83;
  // P, 2P, ..., 8P of A at scr[0..320), of R at scr[320..640)
  GLOBAL u32* sa = scr;
  GLOBAL u32* sr = scr + 320;
  {
    EdPN a1 = ed_pniels(A, d2), r1 = ed_pniels(R, d2);
    EdP ca = A, cr = R;
    ed_pn_put(sa, a1); ed_pn_put(sr, r1);
    for (int i = 1; i < 8; i++) {
      ca = ed_c_ext(ed_add_pn(ca, a1, false));
      cr = ed_c_ext(ed_add_pn(cr, r1, false));
      ed_pn_put(sa + i * 40, ed_pniels(ca, d2)); ed_pn_put(sr + i * 40, ed_pniels(cr, d2));
    }
  }
  // the running point stays in completed form: 4M to extended before an add, 3M to projective
  // before a doubling (T is only needed by additions)
  EdC c; c.x = fx_zero(); c.y = fx_one(); c.z = fx_one(); c.t = fx_one();
  for (int j = 32; j >= 0; j--) {
    if (j != 32) {
      for (int k = 0; k < 4; k++) c = ed_dbl_c(fx_mul(c.x, c.t), fx_mul(c.y, c.z), fx_mul(c.z, c.t));
    }
    int da = da_[j], dr = dr_[j];
    if (da != 0) c = ed_add_pn(ed_c_ext(c), ed_pn_get(sa + ((da < 0 ? -da : da) - 1) * 40), da < 0);
    if (dr != 0) c = ed_add_pn(ed_c_ext(c), ed_pn_get(sr + ((dr < 0 ? -dr : dr) - 1) * 40), dr < 0);
    if ((j & 1) == 0) {
      int d0 = d0_[j >> 1], d1 = d1_[j >> 1];
      if (d0 != 0) c = ed_add_an(ed_c_ext(c), tb0 + ((d0 < 0 ? -d0 : d0) - 1) * 30, d0 > 0);
      if (d1 != 0) c = ed_add_an(ed_c_ext(c), tb1 + ((d1 < 0 ? -d1 : d1) - 1) * 30, d1 > 0);
    }
  }
  // [8]: three doublings, then the identity test x == 0, y == z
  for (int k = 0; k < 3; k++) c = ed_dbl_c(fx_mul(c.x, c.t), fx_mul(c.y, c.z), fx_mul(c.z, c.t));
  fx_e X = fx_mul(c.x, c.t), Y = fx_mul(c.y, c.z), Z = fx_mul(c.z, c.t);
  return (fx_is_zero(X) && fx_eq(Y, Z)) ? 1u : 0u;
}
