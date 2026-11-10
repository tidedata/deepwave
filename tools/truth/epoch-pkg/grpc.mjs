// Minimal raw gRPC (h2c) client and protobuf helpers for the epoch-pkg lane's comparison tools.
// No dependencies: node:http2 only. A call returns the raw response message bytes and the
// trailers (grpc-status, grpc-message, grpc-status-details-bin) so two servers can be compared
// byte for byte.
import http2 from 'node:http2';

export function connect(url) {
  // Large windows: the default 64 KiB session window caps a 150 ms RTT tunnel at ~400 KB/s.
  const s = http2.connect(url, { settings: { initialWindowSize: 16 << 20 } });
  s.on('error', () => {});
  s.on('connect', () => { try { s.setLocalWindowSize(64 << 20); } catch {} });
  return s;
}

export function call(session, path, body, timeoutMs = 20000) {
  return new Promise((resolve) => {
    const frame = Buffer.alloc(5 + body.length);
    frame.writeUInt8(0, 0);
    frame.writeUInt32BE(body.length, 1);
    Buffer.from(body).copy(frame, 5);
    const req = session.request({
      ':method': 'POST', ':path': path, 'content-type': 'application/grpc', te: 'trailers',
    });
    const chunks = [];
    let headers = {};
    const done = (trailers) => {
      const h = { ...headers, ...trailers };
      const data = Buffer.concat(chunks);
      const msgs = [];
      for (let o = 0; o + 5 <= data.length;) { const n = data.readUInt32BE(o + 1); msgs.push(data.subarray(o + 5, o + 5 + n)); o += 5 + n; }
      resolve({
        status: Number(h['grpc-status'] ?? -1),
        message: h['grpc-message'] !== undefined ? decodeURIComponent(h['grpc-message']) : '',
        details: h['grpc-status-details-bin'] ?? '',
        body: msgs.length ? msgs[0] : null,
      });
    };
    req.setTimeout(timeoutMs, () => { req.close(); resolve({ status: -2, message: 'timeout', details: '', body: null }); });
    req.on('response', (h) => { headers = h; });
    req.on('data', (c) => chunks.push(c));
    let trailers = null;
    req.on('trailers', (t) => { trailers = t; });
    req.on('end', () => done(trailers ?? {}));
    req.on('error', (e) => resolve({ status: -3, message: String(e), details: '', body: null }));
    req.end(frame);
  });
}

// ---- protobuf encoding ----
export function varint(n) {
  let v = BigInt(n); const out = [];
  while (v >= 0x80n) { out.push(Number((v & 0x7fn) | 0x80n)); v >>= 7n; }
  out.push(Number(v));
  return Buffer.from(out);
}
const tag = (f, wt) => varint((f << 3) | wt);
export const fU64 = (f, n) => Buffer.concat([tag(f, 0), varint(n)]);
export const fBytes = (f, b) => { b = Buffer.from(b); return Buffer.concat([tag(f, 2), varint(b.length), b]); };
export const fStr = (f, s) => fBytes(f, Buffer.from(s, 'utf8'));
export const fieldMask = (f, paths) => fBytes(f, Buffer.concat(paths.map((p) => fStr(1, p))));

// ---- protobuf decoding (generic) ----
export function readVarint(b, o) {
  let v = 0n, s = 0n;
  for (;;) { const x = b[o++]; v |= BigInt(x & 0x7f) << s; s += 7n; if (!(x & 0x80)) break; }
  return [v, o];
}
/** Fields of one message: [{n, wt, v}] with v a BigInt (varint/fixed) or Buffer (len). */
export function fields(b) {
  const out = []; let o = 0;
  while (o < b.length) {
    let k; [k, o] = readVarint(b, o);
    const n = Number(k >> 3n), wt = Number(k & 7n);
    if (wt === 0) { let v; [v, o] = readVarint(b, o); out.push({ n, wt, v }); }
    else if (wt === 2) { let l; [l, o] = readVarint(b, o); out.push({ n, wt, v: b.subarray(o, o + Number(l)) }); o += Number(l); }
    else if (wt === 1) { out.push({ n, wt, v: b.readBigUInt64LE(o) }); o += 8; }
    else if (wt === 5) { out.push({ n, wt, v: BigInt(b.readUInt32LE(o)) }); o += 4; }
    else throw new Error('wire type ' + wt);
  }
  return out;
}
export const get = (b, n) => fields(b).find((f) => f.n === n)?.v;
export const getAll = (b, n) => fields(b).filter((f) => f.n === n).map((f) => f.v);

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Rate limiter: at most `perSec` calls per second across the process. */
export function limiter(perSec) {
  let next = 0;
  return async () => { const now = Date.now(); const t = Math.max(now, next); next = t + 1000 / perSec; if (t > now) await sleep(t - now); };
}
