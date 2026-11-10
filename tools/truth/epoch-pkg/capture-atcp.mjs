// node capture-atcp.mjs <url> <seeds.json> <out dir>
// The package-version index capture for the epoch-pkg lane (DROP-IN G8): every lineage of the seed
// packages with the checkpoint that published each version, and sui-node's answers to
// ListPackageVersions and GetPackage `version` / `at_checkpoint` around those checkpoints, so the
// suite can build deepwave's index through the production feeds (onCheckpoint over the real publish
// checkpoints, restore floors for what predates sui-node's window) and compare.
//
// Writes into <out>:
//   cases.jsonl    {path, tag, req, status, message, details, body, info?} (info = GetServiceInfo
//                  taken right before and after a case whose answer depends on the moving window:
//                  {lowest, tip} before and after; the case is retried until both agree)
//   objects.jsonl  {id, version, bcs} every package version of every lineage
//   publish.jsonl  {storage, version, original, checkpoint, tx} the publishing checkpoint of each
//   meta.json      start/end GetServiceInfo, the publish checkpoints inside the window (tools/corpus-fetch.sh, then move them
//                  from chk/ to vectors/epoch-pkg/chk/: chk/ holds only plan blobs)
import fs from 'node:fs';
import { connect, call, fU64, fStr, fBytes, fieldMask, get, getAll, limiter } from './grpc.mjs';

const [url, seedsPath, out] = process.argv.slice(2);
const RATE = Number(process.env.RATE ?? 15);
const CONC = Number(process.env.CONC ?? 6);
const s = connect(url);
const tick = limiter(RATE);
const L = '/sui.rpc.v2.LedgerService/';
const P = '/sui.rpc.v2.MovePackageService/';
fs.mkdirSync(out, { recursive: true });
const casesF = fs.openSync(`${out}/cases.jsonl`, 'w');
const objsF = fs.openSync(`${out}/objects.jsonl`, 'w');
const pubF = fs.openSync(`${out}/publish.jsonl`, 'w');
let nCalls = 0;
const counts = {};

async function rpc(path, body) {
  await tick();
  nCalls++;
  for (let attempt = 0; ; attempt++) {
    const r = await call(s, path, body);
    if (r.status >= 0 || attempt >= 2) return r;
  }
}
function write(path, tag, body, r, info) {
  fs.writeSync(casesF, JSON.stringify({
    path, tag, req: Buffer.from(body).toString('hex'), status: r.status, message: r.message,
    details: r.details, body: r.body ? r.body.toString('hex') : '', ...(info ? { info } : {}),
  }) + '\n');
  const k = path.split('/').pop() + ':' + tag + ':' + r.status;
  counts[k] = (counts[k] ?? 0) + 1;
}
async function rec(path, body, tag) {
  const r = await rpc(path, body);
  write(path, tag, body, r);
  return r;
}
async function serviceInfo() {
  const r = await rpc(L + 'GetServiceInfo', Buffer.alloc(0));
  return { epoch: Number(get(r.body, 3)), tip: Number(get(r.body, 4)), lowest: Number(get(r.body, 6)) };
}
/** A case whose answer depends on sui-node's moving window: bracketed by GetServiceInfo. */
async function recWindowed(path, body, tag) {
  for (let attempt = 0; ; attempt++) {
    const before = await serviceInfo();
    const r = await rpc(path, body);
    const after = await serviceInfo();
    if ((before.lowest === after.lowest && before.tip === after.tip) || attempt >= 6) {
      write(path, tag, body, r, { before, after });
      return r;
    }
  }
}
const seen = new Set();
async function fetchObject(id) {
  const body = Buffer.concat([fStr(1, id), fieldMask(3, ['bcs', 'version', 'previous_transaction'])]);
  const r = await rpc(L + 'GetObject', body);
  if (r.status !== 0) return null;
  const o = get(r.body, 1);
  const bcs = get(o, 1) && get(get(o, 1), 2);
  if (!bcs) return null;
  const version = Number(get(o, 3));
  if (!seen.has(id + ':' + version)) {
    seen.add(id + ':' + version);
    fs.writeSync(objsF, JSON.stringify({ id, version: String(version), bcs: Buffer.from(bcs).toString('hex') }) + '\n');
  }
  return { bcs: Buffer.from(bcs), version, prev: get(o, 10)?.toString() };
}
async function txCheckpoint(digest) {
  const r = await rpc(L + 'GetTransaction', Buffer.concat([fStr(1, digest), fieldMask(2, ['checkpoint'])]));
  if (r.status !== 0) return null;
  const c = get(get(r.body, 1), 6);
  return c === undefined ? null : Number(c);
}
async function pool(items, n, fn) {
  let i = 0;
  await Promise.all(Array.from({ length: n }, async () => { while (i < items.length) { const k = i++; await fn(items[k], k); } }));
}
const pkgReq = (id, sel) => Buffer.concat([fStr(1, id), ...(sel?.version !== undefined ? [fU64(2, sel.version)] : []), ...(sel?.at !== undefined ? [fU64(3, sel.at)] : [])]);
const lpvReq = (id, size, token) => Buffer.concat([fStr(1, id), ...(size !== undefined ? [fU64(2, size)] : []), ...(token ? [fBytes(3, token)] : [])]);

const seeds = JSON.parse(fs.readFileSync(seedsPath, 'utf8'));
const info0 = await serviceInfo();
console.error(`tip ${info0.tip} lowest ${info0.lowest} epoch ${info0.epoch}`);
const meta = { start: info0, publish_in_window: [] };
const lineages = new Map(); // original -> [{storage, version, checkpoint}]
let done = 0;
await pool(seeds.pkgs, CONC, async (id) => {
  const latest = await fetchObject(id);
  if (!latest || latest.bcs[0] !== 1) return;
  const lpv = await rec(P + 'ListPackageVersions', lpvReq(id), 'lpv:default');
  if (lpv.status !== 0) return;
  const versions = getAll(lpv.body, 1).map((v) => ({ storage: get(v, 1).toString(), version: Number(get(v, 2)) }));
  const g = await rec(P + 'GetPackage', pkgReq(id), 'pkg:latest');
  const orig = g.status === 0 ? get(get(g.body, 1), 2).toString() : id;
  if (lineages.has(orig)) return;
  lineages.set(orig, versions);
  // publishing checkpoint of each version (a system package's older versions share its id: the
  // object at that version is not served, so they stay without one)
  for (const v of versions) {
    const o = await fetchObject(v.storage);
    if (!o || o.version !== v.version) { v.checkpoint = null; continue; }
    v.checkpoint = o.prev ? await txCheckpoint(o.prev) : null;
    fs.writeSync(pubF, JSON.stringify({ storage: v.storage, version: v.version, original: orig, checkpoint: v.checkpoint, tx: o.prev }) + '\n');
  }
  if (++done % 20 === 0) console.error(`lineages ${done} (${nCalls} calls)`);
});
// at_checkpoint around every publish inside the window, and the window's edges
const cases = [];
for (const [orig, versions] of lineages) {
  const latest = versions[versions.length - 1];
  const ids = [...new Set([orig, latest.storage])];
  for (const id of ids) {
    for (const v of versions) {
      if (v.checkpoint === null || v.checkpoint === undefined || v.checkpoint < info0.lowest) continue;
      cases.push([id, v.checkpoint - 1, 'pkg:at-before-publish']);
      cases.push([id, v.checkpoint, 'pkg:at-publish']);
    }
    cases.push([id, 'tip-50', 'pkg:at-tip']);
    cases.push([id, 'lowest', 'pkg:at-lowest']);
    cases.push([id, 'lowest-1', 'pkg:at-pruned']);
    cases.push([id, 'future', 'pkg:at-not-indexed']);
  }
}
for (const [orig, versions] of lineages) for (const v of versions) {
  if (v.checkpoint !== null && v.checkpoint !== undefined && v.checkpoint >= info0.lowest) meta.publish_in_window.push(v.checkpoint);
}
meta.publish_in_window = [...new Set(meta.publish_in_window)].sort((a, b) => a - b);
console.error(`${lineages.size} lineages, ${meta.publish_in_window.length} publish checkpoints in the window, ${cases.length} at_checkpoint cases`);
await pool(cases, CONC, async ([id, at, tag]) => {
  if (typeof at === 'number') { await recWindowed(P + 'GetPackage', pkgReq(id, { at }), tag); return; }
  // resolved against sui-node's window at request time (recorded with the case)
  const i = await serviceInfo();
  const v = at === 'tip-50' ? i.tip - 50 : at === 'lowest' ? i.lowest : at === 'lowest-1' ? i.lowest - 1 : i.tip + 1_000_000;
  await recWindowed(P + 'GetPackage', pkgReq(id, { at: v }), tag);
});
meta.end = await serviceInfo();
meta.counts = counts;
meta.calls = nCalls;
fs.writeFileSync(`${out}/meta.json`, JSON.stringify(meta, null, 1));
console.error(JSON.stringify(counts));
console.error(`done: ${nCalls} calls`);
s.close();
