// node e2e-protocfg.mjs <deepwave url> <vector.bin | sui-node url>
// GetEpoch (latest) read_mask epoch,protocol_config from a running deepwave; compares the
// protocol_config message with a sui-node capture (file) or a live sui-node (URL), byte for byte.
// This is what the SDK's getProtocolConfig asks.
import { connect, call, fieldMask } from './grpc.mjs';
import fs from 'node:fs';
const [url, vec] = process.argv.slice(2);
function field(b, num) {
  let o = 0;
  const vint = () => { let v = 0n, s = 0n; for (;;) { const c = b[o++]; v |= BigInt(c & 0x7f) << s; s += 7n; if (!(c & 0x80)) return v; } };
  while (o < b.length) {
    const k = vint(); const wt = Number(k & 7n); const n = Number(k >> 3n);
    if (wt === 0) { const v = vint(); if (n === num) return v; continue; }
    if (wt !== 2) throw new Error('wire type ' + wt);
    const len = Number(vint()); if (n === num) return b.subarray(o, o + len); o += len;
  }
  return null;
}
const ask = async (u) => {
  const c = connect(u);
  const r = await call(c, '/sui.rpc.v2.LedgerService/GetEpoch', fieldMask(2, ['epoch', 'protocol_config']));
  c.close();
  return r;
};
let want;
if (/^https?:/.test(vec)) {
  const r = await ask(vec);
  if (r.status !== 0 || !r.body) { console.log(JSON.stringify({ ok: false, side: 'sui-node', status: r.status, message: r.message })); process.exit(3); }
  want = field(field(r.body, 1), 9);
} else want = field(field(fs.readFileSync(vec), 1), 9);
const s = connect(url);
const r = await call(s, '/sui.rpc.v2.LedgerService/GetEpoch', fieldMask(2, ['epoch', 'protocol_config']));
s.close();
if (r.status !== 0 || !r.body) { console.log(JSON.stringify({ ok: false, status: r.status, message: r.message })); process.exit(3); }
const ep = field(r.body, 1);
const got = field(ep, 9);
const names = ['check_groth16_pvk_length', 'secp256r1_ecrecover_checks_x_below_p'];
console.log(JSON.stringify({
  epoch: String(field(ep, 1)), equal: Buffer.compare(got, want) === 0, zui_len: got.length, sui_len: want.length,
  zui_has_184_fields: names.filter((n) => got.includes(Buffer.from(n))),
}));
process.exit(Buffer.compare(got, want) === 0 ? 0 : 1);
