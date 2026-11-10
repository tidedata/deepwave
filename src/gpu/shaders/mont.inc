// 256-bit Montgomery field, R = 2^256, eight 32-bit limbs, modulus below 2^254.
// Instantiated once per field: MN(x) names the instance, MN(P) is the modulus, NINV = -p^-1 mod 2^32.
struct MN(e) { u32 v[8]; };
FN MN(e) MN(zero)() { MN(e) r; for (int i = 0; i < 8; i++) r.v[i] = 0; return r; }
FN MN(e) MN(one)() { MN(e) r; for (int i = 0; i < 8; i++) r.v[i] = MN(ONE)[i]; return r; }
FN bool MN(is_zero)(MN(e) a) { u32 o = 0; for (int i = 0; i < 8; i++) o |= a.v[i]; return o == 0; }
FN bool MN(eq)(MN(e) a, MN(e) b) { u32 o = 0; for (int i = 0; i < 8; i++) o |= a.v[i] ^ b.v[i]; return o == 0; }
FN MN(e) MN(load)(GLOBAL const u32* p) { MN(e) r; for (int i = 0; i < 8; i++) r.v[i] = p[i]; return r; }
FN void MN(store)(GLOBAL u32* p, MN(e) a) { for (int i = 0; i < 8; i++) p[i] = a.v[i]; }
// a < 2p -> a mod p
FN MN(e) MN(red)(MN(e) a) {
  MN(e) r; u64 b = 0;
  for (int i = 0; i < 8; i++) { u64 d = (u64)a.v[i] - (u64)MN(P)[i] - b; r.v[i] = (u32)d; b = (d >> 63) & 1; }
  return b ? a : r;
}
FN MN(e) MN(add)(MN(e) a, MN(e) b) {
  MN(e) r; u64 c = 0;
  for (int i = 0; i < 8; i++) { u64 s = (u64)a.v[i] + b.v[i] + c; r.v[i] = (u32)s; c = s >> 32; }
  return MN(red)(r);
}
FN MN(e) MN(dbl)(MN(e) a) { return MN(add)(a, a); }
FN MN(e) MN(sub)(MN(e) a, MN(e) b) {
  MN(e) r; u64 br = 0;
  for (int i = 0; i < 8; i++) { u64 d = (u64)a.v[i] - b.v[i] - br; r.v[i] = (u32)d; br = (d >> 63) & 1; }
  if (br) { u64 c = 0; for (int i = 0; i < 8; i++) { u64 s = (u64)r.v[i] + MN(P)[i] + c; r.v[i] = (u32)s; c = s >> 32; } }
  return r;
}
FN MN(e) MN(mul)(MN(e) a, MN(e) b) {
  u32 t[10];
  for (int i = 0; i < 10; i++) t[i] = 0;
  for (int i = 0; i < 8; i++) {
    u64 c = 0; u32 bi = b.v[i];
    for (int j = 0; j < 8; j++) { u64 x = MULW(a.v[j], bi) + t[j] + c; t[j] = (u32)x; c = x >> 32; }
    u64 x = (u64)t[8] + c; t[8] = (u32)x; t[9] = (u32)(x >> 32);
    u32 m = t[0] * NINV;
    x = MULW(m, MN(P)[0]) + t[0]; c = x >> 32;
    for (int j = 1; j < 8; j++) { x = MULW(m, MN(P)[j]) + t[j] + c; t[j - 1] = (u32)x; c = x >> 32; }
    x = (u64)t[8] + c; t[7] = (u32)x; t[8] = t[9] + (u32)(x >> 32);
  }
  MN(e) r; for (int j = 0; j < 8; j++) r.v[j] = t[j];
  return MN(red)(r);
}
FN MN(e) MN(sq)(MN(e) a) { return MN(mul)(a, a); }
