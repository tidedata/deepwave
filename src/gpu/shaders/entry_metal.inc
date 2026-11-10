kernel void selftest_k(device const u32* a [[buffer(0)]], device const u32* b [[buffer(1)]], device u32* out [[buffer(2)]], device const u32* prm [[buffer(3)]], uint gid [[thread_position_in_grid]]) {
  if (gid >= prm[1]) return;
  selftest_impl(a, b, out, prm, gid);
}
kernel void ed25519_k(device const u32* items [[buffer(0)]], device const u32* cs [[buffer(1)]], device u32* out [[buffer(2)]], device const u32* prm [[buffer(3)]], device u32* scr [[buffer(4)]], uint gid [[thread_position_in_grid]]) {
  if (gid >= prm[0]) return;
  out[gid] = ed_verify_hs(items + (u64)gid * ED_WORDS, cs, scr + (u64)gid * ED_SCR_WORDS);
}
kernel void poseidon_k(device const u32* in [[buffer(0)]], device const u32* cc [[buffer(1)]], device const u32* mm [[buffer(2)]], device u32* out [[buffer(3)]], device const u32* prm [[buffer(4)]], uint gid [[thread_position_in_grid]]) {
  if (gid >= prm[2]) return;
  poseidon_impl(in, cc, mm, out, prm, gid);
}
kernel void g1_mul_k(device const u32* pts [[buffer(0)]], device const u32* scal [[buffer(1)]], device u32* out [[buffer(2)]], device const u32* prm [[buffer(3)]], uint gid [[thread_position_in_grid]]) {
  if (gid >= prm[0]) return;
  g1_mul_impl(pts, scal, out, gid);
}
kernel void g1_add_pairs_k(device const u32* in [[buffer(0)]], device u32* out [[buffer(1)]], device const u32* prm [[buffer(2)]], uint gid [[thread_position_in_grid]]) {
  if (gid >= prm[0]) return;
  g1_add_pairs_impl(in, out, prm[1], gid);
}
