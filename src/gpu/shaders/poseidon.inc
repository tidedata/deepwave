// Poseidon over the BN254 scalar field: textbook circomlib permutation (width t = n + 1, state[0] = 0,
// x^5 S-box, 8 full rounds and rp partial ones), constants and MDS matrix in Montgomery form.
FN fr_e fr_pow5(fr_e x) { fr_e x2 = fr_sq(x); return fr_mul(fr_sq(x2), x); }
FN void poseidon_impl(GLOBAL const u32* in, GLOBAL const u32* cc, GLOBAL const u32* mm, GLOBAL u32* out, GLOBAL const u32* prm, u32 gid) {
  u32 n = prm[0], rp = prm[1], t = n + 1;
  fr_e s[17], ns[17];
  s[0] = fr_zero();
  for (u32 i = 0; i < n; i++) s[i + 1] = fr_load(in + ((u64)gid * n + i) * 8);
  u32 total = 8 + rp;
  for (u32 r = 0; r < total; r++) {
    for (u32 i = 0; i < t; i++) s[i] = fr_add(s[i], fr_load(cc + (r * t + i) * 8));
    if (r < 4 || r >= 4 + rp) { for (u32 i = 0; i < t; i++) s[i] = fr_pow5(s[i]); }
    else s[0] = fr_pow5(s[0]);
    for (u32 i = 0; i < t; i++) {
      fr_e acc = fr_zero();
      for (u32 j = 0; j < t; j++) acc = fr_add(acc, fr_mul(fr_load(mm + (i * t + j) * 8), s[j]));
      ns[i] = acc;
    }
    for (u32 i = 0; i < t; i++) s[i] = ns[i];
  }
  fr_store(out + (u64)gid * 8, s[0]);
}
