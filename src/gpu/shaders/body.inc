// selftest: op 0 fr_mul 1 fq_mul 2 fx_mul 3 fr_add 4 fr_sub 5 fx_add 6 fx_sub 7 fq_add 8 fq_sub 9 fx_sq. a, b, out: 8 words per lane.
FN void selftest_impl(GLOBAL const u32* a, GLOBAL const u32* b, GLOBAL u32* out, GLOBAL const u32* prm, u32 gid) {
  u32 op = prm[0];
  GLOBAL const u32* pa = a + (u64)gid * 8;
  GLOBAL const u32* pb = b + (u64)gid * 8;
  GLOBAL u32* po = out + (u64)gid * 8;
  if (op == 0) fr_store(po, fr_mul(fr_load(pa), fr_load(pb)));
  else if (op == 1) fq_store(po, fq_mul(fq_load(pa), fq_load(pb)));
  else if (op == 2) fx_store(po, fx_canon(fx_mul(fx_load(pa), fx_load(pb))));
  else if (op == 3) fr_store(po, fr_add(fr_load(pa), fr_load(pb)));
  else if (op == 4) fr_store(po, fr_sub(fr_load(pa), fr_load(pb)));
  else if (op == 5) fx_store(po, fx_canon(fx_add(fx_load(pa), fx_load(pb))));
  else if (op == 6) fx_store(po, fx_canon(fx_sub(fx_load(pa), fx_load(pb))));
  else if (op == 7) fq_store(po, fq_add(fq_load(pa), fq_load(pb)));
  else if (op == 8) fq_store(po, fq_sub(fq_load(pa), fq_load(pb)));
  else fx_store(po, fx_canon(fx_sq(fx_load(pa))));
}
// pts: x y (Montgomery, 8 words each) then an infinity flag, stride 24. scal: 8 standard words. out: Jacobian, stride 24.
FN void g1_mul_impl(GLOBAL const u32* pts, GLOBAL const u32* scal, GLOBAL u32* out, u32 gid) {
  GLOBAL const u32* pp = pts + (u64)gid * 24;
  G1J p;
  p.x = fq_load(pp); p.y = fq_load(pp + 8);
  p.z = pp[16] ? fq_zero() : fq_one();
  g1_store(out + (u64)gid * 24, g1_mul(p, scal + (u64)gid * 8));
}
FN void g1_add_pairs_impl(GLOBAL const u32* in, GLOBAL u32* out, u32 n_in, u32 gid) {
  u32 i = gid * 2;
  G1J a = g1_load(in + (u64)i * 24);
  if (i + 1 < n_in) a = g1_add(a, g1_load(in + (u64)(i + 1) * 24));
  g1_store(out + (u64)gid * 24, a);
}
