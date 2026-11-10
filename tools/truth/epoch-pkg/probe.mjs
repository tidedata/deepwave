// node probe.mjs <url> <path> <hex request>  -> prints status, message, body hex
import { connect, call } from './grpc.mjs';
const [url, path, hex] = process.argv.slice(2);
const s = connect(url);
const r = await call(s, path, Buffer.from(hex ?? '', 'hex'));
console.log(JSON.stringify({ status: r.status, message: r.message, details: r.details, len: r.body?.length ?? null }));
if (r.body) console.log(r.body.toString('hex'));
s.close();
