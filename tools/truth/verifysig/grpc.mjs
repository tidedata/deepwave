// Minimal unary gRPC (HTTP/2, binary) client for recording sui-node answers, rate limited.
import http2 from 'node:http2';

export class Client {
  constructor(url, rps = 15) { this.url = url; this.gap = 1000 / rps; this.next = 0; this.s = http2.connect(url); this.s.on('error', () => {}); }
  async pace() { const now = Date.now(); const at = Math.max(now, this.next); this.next = at + this.gap; if (at > now) await new Promise(r => setTimeout(r, at - now)); }
  /** Returns { code, message, details (Buffer), body (Buffer: the response message) }. */
  async unary(path, msg) {
    await this.pace();
    if (this.s.closed || this.s.destroyed) { this.s = http2.connect(this.url); this.s.on('error', () => {}); }
    return new Promise((resolve, reject) => {
      const frame = Buffer.alloc(5 + msg.length); frame.writeUInt32BE(msg.length, 1); Buffer.from(msg).copy(frame, 5);
      const req = this.s.request({ ':method': 'POST', ':path': path, 'content-type': 'application/grpc', te: 'trailers' });
      const chunks = []; let headers = {};
      req.on('response', h => { headers = h; });
      req.on('data', c => chunks.push(c));
      req.on('trailers', t => { headers = { ...headers, ...t }; });
      req.on('error', reject);
      req.setTimeout(30000, () => { req.close(); reject(new Error('timeout')); });
      req.on('end', () => {
        const all = Buffer.concat(chunks);
        const body = all.length >= 5 ? all.subarray(5, 5 + all.readUInt32BE(1)) : Buffer.alloc(0);
        const code = Number(headers['grpc-status'] ?? -1);
        const message = headers['grpc-message'] ? decodeURIComponent(headers['grpc-message']) : '';
        const dbin = headers['grpc-status-details-bin'];
        const details = dbin ? Buffer.from(dbin, 'base64') : Buffer.alloc(0);
        resolve({ code, message, details, body, headers });
      });
      req.end(frame);
    });
  }
  close() { this.s.close(); }
}
