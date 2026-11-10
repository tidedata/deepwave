// BN254 G1 in Jacobian coordinates over fq (y^2 = x^3 + 3), formulas as src/crypto/zk/bn254/curve.zig.
struct G1J { fq_e x; fq_e y; fq_e z; };
FN G1J g1_ident() { G1J r; r.x = fq_one(); r.y = fq_one(); r.z = fq_zero(); return r; }
FN G1J g1_dbl(G1J p) {
  if (fq_is_zero(p.z)) return p;
  fq_e A = fq_sq(p.x);
  fq_e B = fq_sq(p.y);
  fq_e C = fq_sq(B);
  fq_e D = fq_dbl(fq_sub(fq_sub(fq_sq(fq_add(p.x, B)), A), C));
  fq_e E = fq_add(fq_dbl(A), A);
  fq_e F = fq_sq(E);
  G1J r;
  r.x = fq_sub(F, fq_dbl(D));
  fq_e c8 = fq_dbl(fq_dbl(fq_dbl(C)));
  r.y = fq_sub(fq_mul(E, fq_sub(D, r.x)), c8);
  r.z = fq_dbl(fq_mul(p.y, p.z));
  return r;
}
FN G1J g1_add(G1J p, G1J q) {
  if (fq_is_zero(p.z)) return q;
  if (fq_is_zero(q.z)) return p;
  fq_e z1z1 = fq_sq(p.z);
  fq_e z2z2 = fq_sq(q.z);
  fq_e uu1 = fq_mul(p.x, z2z2);
  fq_e uu2 = fq_mul(q.x, z1z1);
  fq_e s1 = fq_mul(fq_mul(p.y, q.z), z2z2);
  fq_e s2 = fq_mul(fq_mul(q.y, p.z), z1z1);
  if (fq_eq(uu1, uu2)) {
    if (fq_eq(s1, s2)) return g1_dbl(p);
    return g1_ident();
  }
  fq_e h = fq_sub(uu2, uu1);
  fq_e i = fq_sq(fq_dbl(h));
  fq_e j = fq_mul(h, i);
  fq_e r = fq_dbl(fq_sub(s2, s1));
  fq_e v = fq_mul(uu1, i);
  G1J o;
  o.x = fq_sub(fq_sub(fq_sq(r), j), fq_dbl(v));
  o.y = fq_sub(fq_mul(r, fq_sub(v, o.x)), fq_dbl(fq_mul(s1, j)));
  o.z = fq_mul(fq_sub(fq_sub(fq_sq(fq_add(p.z, q.z)), z1z1), z2z2), h);
  return o;
}
// k * p for a standard-form 256-bit scalar (little-endian words), 4-bit windows. Variable time (public inputs).
FN G1J g1_mul(G1J p, GLOBAL const u32* k) {
  G1J tab[16];
  tab[0] = g1_ident();
  tab[1] = p;
  for (int i = 2; i < 16; i++) tab[i] = g1_add(tab[i - 1], p);
  G1J r = g1_ident();
  bool started = false;
  for (int w = 63; w >= 0; w--) {
    u32 nib = (k[w >> 3] >> ((w & 7) * 4)) & 15u;
    if (started) { r = g1_dbl(r); r = g1_dbl(r); r = g1_dbl(r); r = g1_dbl(r); }
    if (nib != 0) { r = g1_add(r, tab[nib]); started = true; }
  }
  return r;
}
FN G1J g1_load(GLOBAL const u32* p) { G1J r; r.x = fq_load(p); r.y = fq_load(p + 8); r.z = fq_load(p + 16); return r; }
FN void g1_store(GLOBAL u32* p, G1J a) { fq_store(p, a.x); fq_store(p + 8, a.y); fq_store(p + 16, a.z); }
