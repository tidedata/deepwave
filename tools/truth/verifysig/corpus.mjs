// Transaction signatures from the corpus binpb checkpoints (sui.rpc.v2.Checkpoint, zstd):
// pairs each transaction's TransactionData BCS with its user signatures from contents.bcs.
import fs from 'node:fs';
import zlib from 'node:zlib';
import path from 'node:path';

export function varint(b, i) { let r = 0n, s = 0n; for (;;) { const x = b[i++]; r |= BigInt(x & 0x7f) << s; s += 7n; if (!(x & 0x80)) break; } return [r, i]; }
export function* fields(b) {
  let i = 0;
  while (i < b.length) {
    let k; [k, i] = varint(b, i); const n = Number(k >> 3n), w = Number(k & 7n);
    if (w === 0) { let v; [v, i] = varint(b, i); yield { n, w, v }; }
    else if (w === 2) { let l; [l, i] = varint(b, i); const d = b.subarray(i, i + Number(l)); i += Number(l); yield { n, w, d }; }
    else if (w === 1) { yield { n, w, d: b.subarray(i, i + 8) }; i += 8; }
    else if (w === 5) { yield { n, w, d: b.subarray(i, i + 4) }; i += 4; }
    else throw new Error('wire type ' + w);
  }
}
const sub = (b, n) => { for (const f of fields(b)) if (f.n === n && f.w === 2) return f.d; return null; };
const subAll = (b, n) => { const o = []; for (const f of fields(b)) if (f.n === n && f.w === 2) o.push(f.d); return o; };

function uleb(b, st) { let v = 0, s = 0; for (;;) { const x = b[st.i++]; v += (x & 0x7f) * 2 ** s; s += 7; if (!(x & 0x80)) return v; } }
function digest(b, st) { if (b[st.i] === 32) st.i += 33; else st.i += 32; }
function bytes(b, st) { const n = uleb(b, st); const d = b.subarray(st.i, st.i + n); st.i += n; return d; }

/** CheckpointContents V1/V2 -> [[sig bytes...] per transaction]. */
export function contentsSigs(c) {
  const st = { i: 1 }; const tag = c[0]; const out = [];
  if (tag === 0) {
    const n = uleb(c, st); for (let k = 0; k < n; k++) { digest(c, st); digest(c, st); }
    const m = uleb(c, st); for (let k = 0; k < m; k++) { const s = uleb(c, st); const a = []; for (let j = 0; j < s; j++) a.push(bytes(c, st)); out.push(a); }
  } else if (tag === 1) {
    const n = uleb(c, st);
    for (let k = 0; k < n; k++) { digest(c, st); digest(c, st); const s = uleb(c, st); const a = []; for (let j = 0; j < s; j++) { a.push(bytes(c, st)); if (c[st.i++] === 1) st.i += 8; } out.push(a); }
  } else throw new Error('contents tag ' + tag);
  return out;
}

/** Yields { seq, tx (TransactionData BCS), sigs } for every transaction in one binpb file. */
export function* checkpointTxs(file) {
  const b = zlib.zstdDecompressSync(fs.readFileSync(file));
  let seq = 0n; for (const f of fields(b)) if (f.n === 1 && f.w === 0) { seq = f.v; break; }
  const contents = sub(b, 5); if (!contents) return;
  const cb = sub(contents, 1); const cbv = cb && sub(cb, 2); if (!cbv) return;
  const sigs = contentsSigs(cbv);
  const txs = subAll(b, 6);
  for (let i = 0; i < txs.length; i++) {
    const tr = sub(txs[i], 2); const tb = tr && sub(tr, 1); const tv = tb && sub(tb, 2);
    if (tv && sigs[i]) yield { seq: Number(seq), tx: Buffer.from(tv), sigs: sigs[i].map(s => Buffer.from(s)) };
  }
}

export function corpusFiles(root) {
  const out = [];
  for (const d of ['binpb-done', 'binpb', 'binpb-r4', 'binpb-hist', 'binpb-exec']) {
    const dir = path.join(root, d); if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir)) if (f.endsWith('.binpb.zst')) out.push(path.join(dir, f));
  }
  return out;
}
