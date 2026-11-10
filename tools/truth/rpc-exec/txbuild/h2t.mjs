import http2 from 'node:http2';
import { UnaryCall, RpcError, mergeRpcOptions } from '@protobuf-ts/runtime-rpc';
import { GrpcWebFetchTransport } from '@protobuf-ts/grpcweb-transport';
// Routes SimulateTransaction to an h2c gRPC server (deepwave), everything else to sui-node gRPC-web.
export class RouteTransport {
  constructor(zuiUrl, nodeUrl, meta = {}) {
    this.session = http2.connect(zuiUrl);
    this.session.on('error', () => {});
    this.meta = meta;
    this.web = new GrpcWebFetchTransport({ baseUrl: nodeUrl, meta });
    this.stats = { zui: 0, node: 0 };
  }
  mergeOptions(o) { return mergeRpcOptions({}, o); }
  close() { this.session.close(); }
  // deepwave-simproxy parity hook: pin `latest` reads to the versions sui-node read ([[idHex, version], ...]).
  setPins(pins) {
    const body = Buffer.alloc(pins.length * 40);
    pins.forEach(([id, v], i) => { Buffer.from(id.slice(2).padStart(64, '0'), 'hex').copy(body, i * 40); body.writeBigUInt64LE(BigInt(v), i * 40 + 32); });
    const frame = Buffer.alloc(5 + body.length); frame.writeUInt32BE(body.length, 1); body.copy(frame, 5);
    return new Promise((res, rej) => {
      const req = this.session.request({ ':method': 'POST', ':path': '/zui.simproxy.Pins/Set', 'content-type': 'application/grpc', te: 'trailers' });
      let h = {};
      req.on('response', hh => { h = hh; });
      req.on('trailers', t => { h = { ...h, ...t }; });
      req.on('data', () => {});
      req.on('end', () => Number(h['grpc-status'] ?? 2) === 0 ? res() : rej(new Error(`pins: ${h['grpc-message']}`)));
      req.on('error', rej);
      req.end(frame);
    });
  }
  serverStreaming(m, i, o) { return this.web.serverStreaming(m, i, o); }
  clientStreaming(m, o) { return this.web.clientStreaming(m, o); }
  duplex(m, o) { return this.web.duplex(m, o); }
  unary(method, input, options) {
    if (method.name !== 'SimulateTransaction') { this.stats.node++; return this.web.unary(method, input, options); }
    this.stats.zui++;
    const path = `/${method.service.typeName}/${method.name}`;
    const msg = method.I.toBinary(input);
    const frame = Buffer.alloc(5 + msg.length); frame.writeUInt32BE(msg.length, 1); Buffer.from(msg).copy(frame, 5);
    let hdrRes, stRes, trRes, rspRes, rspRej;
    const headers = new Promise(r => hdrRes = r), status = new Promise(r => stRes = r), trailers = new Promise(r => trRes = r);
    const response = new Promise((r, j) => { rspRes = r; rspRej = j; });
    const req = this.session.request({ ':method': 'POST', ':path': path, 'content-type': 'application/grpc', te: 'trailers', ...this.meta });
    const chunks = [];
    let h = {};
    req.on('response', (hh) => { h = hh; hdrRes({}); });
    req.on('data', c => chunks.push(c));
    req.on('trailers', (t) => { h = { ...h, ...t }; });
    req.on('end', () => {
      const code = Number(h['grpc-status'] ?? 2);
      const message = decodeURIComponent(h['grpc-message'] ?? '');
      trRes({}); stRes({ code: String(code), detail: message });
      const meta = h['grpc-status-details-bin'] !== undefined ? { 'grpc-status-details-bin': String(h['grpc-status-details-bin']) } : {};
      if (code !== 0) { rspRej(new RpcError(message, ['OK','CANCELLED','UNKNOWN','INVALID_ARGUMENT','DEADLINE_EXCEEDED','NOT_FOUND','ALREADY_EXISTS','PERMISSION_DENIED','RESOURCE_EXHAUSTED','FAILED_PRECONDITION','ABORTED','OUT_OF_RANGE','UNIMPLEMENTED','INTERNAL','UNAVAILABLE','DATA_LOSS','UNAUTHENTICATED'][code] ?? 'UNKNOWN', meta)); return; }
      const b = Buffer.concat(chunks);
      rspRes(method.O.fromBinary(new Uint8Array(b.subarray(5, 5 + b.readUInt32BE(1)))));
    });
    req.on('error', e => { rspRej(e); stRes({ code: 'UNKNOWN', detail: String(e) }); trRes({}); hdrRes({}); });
    req.end(frame);
    return new UnaryCall(method, {}, input, headers, response, status, trailers);
  }
}
