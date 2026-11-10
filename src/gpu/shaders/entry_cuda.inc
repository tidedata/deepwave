#define GID (blockIdx.x * blockDim.x + threadIdx.x)
extern "C" __global__ void selftest_k(const u32* a, const u32* b, u32* out, const u32* prm) {
  u32 gid = GID; if (gid >= prm[1]) return;
  selftest_impl(a, b, out, prm, gid);
}
extern "C" __global__ void ed25519_k(const u32* items, const u32* cs, u32* out, const u32* prm, u32* scr) {
  u32 gid = GID; if (gid >= prm[0]) return;
  out[gid] = ed_verify_hs(items + (u64)gid * ED_WORDS, cs, scr + (u64)gid * ED_SCR_WORDS);
}
extern "C" __global__ void poseidon_k(const u32* in, const u32* cc, const u32* mm, u32* out, const u32* prm) {
  u32 gid = GID; if (gid >= prm[2]) return;
  poseidon_impl(in, cc, mm, out, prm, gid);
}
extern "C" __global__ void g1_mul_k(const u32* pts, const u32* scal, u32* out, const u32* prm) {
  u32 gid = GID; if (gid >= prm[0]) return;
  g1_mul_impl(pts, scal, out, gid);
}
extern "C" __global__ void g1_add_pairs_k(const u32* in, u32* out, const u32* prm) {
  u32 gid = GID; if (gid >= prm[0]) return;
  g1_add_pairs_impl(in, out, prm[1], gid);
}
