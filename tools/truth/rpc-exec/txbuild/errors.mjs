// G9 error parity probe: handcrafted SimulateTransaction requests (no bcs, so sui-node resolves them)
// that reach the reviewed error paths, sent to sui-node and to deepwave; status code, message and
// grpc-status-details-bin must match byte for byte. Paced to --rate per second toward sui-node.
//
//   node errors.mjs --node http://127.0.0.1:19281 --zui http://127.0.0.1:9281
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { GrpcWebFetchTransport } from '@protobuf-ts/grpcweb-transport';
import { RouteTransport } from './h2t.mjs';

const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : d; };
const NODE = arg('node', 'http://127.0.0.1:19281');
const ZUI = arg('zui', 'http://127.0.0.1:9281');
const RATE = Number(arg('rate', 4));
let next = 0;
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  if (String(url).startsWith(NODE)) { const now = Date.now(), at = Math.max(now, next); next = at + 1000 / RATE; if (at > now) await new Promise(r => setTimeout(r, at - now)); }
  return realFetch(url, init);
};
const node = new SuiGrpcClient({ network: 'mainnet', transport: new GrpcWebFetchTransport({ baseUrl: NODE }) });
const rt = new RouteTransport(ZUI, NODE);
const zui = new SuiGrpcClient({ network: 'mainnet', transport: rt });

// an address with no objects and no balance (fresh, never used)
const EMPTY = '0x' + 'e7'.repeat(32);
const gas = { kind: 1 }; // Argument GAS
const inp = i => ({ kind: 2, input: i });
const pureU64 = v => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(v), true); return { kind: 1, pure: b }; };
const pureAddr = a => ({ kind: 1, pure: Uint8Array.from(Buffer.from(a.slice(2), 'hex')) });
const ptb = (inputs, commands) => ({ kind: { kind: 1, data: { oneofKind: 'programmableTransaction', programmableTransaction: { inputs, commands } } } });
const split = (coin, amounts) => ({ command: { oneofKind: 'splitCoins', splitCoins: { coin, amounts } } });
const transfer = (objects, address) => ({ command: { oneofKind: 'transferObjects', transferObjects: { objects, address } } });
const moveCall = (pkg, module, fn, typeArguments, args) => ({ command: { oneofKind: 'moveCall', moveCall: { package: pkg, module, function: fn, typeArguments, arguments: args } } });
const deep = n => 'vector<'.repeat(n) + 'u8' + '>'.repeat(n);
const splitTx = (sender, amount) => ({ sender, ...ptb([pureU64(amount), pureAddr(EMPTY)], [split(gas, [inp(0)]), transfer([{ kind: 3, result: 0 }], inp(1))]) });

const cases = {
  'sender without 0x (resolves)': { transaction: splitTx(EMPTY.slice(2), 1) },
  'sender with 0X (invalid)': { transaction: splitTx('0X' + EMPTY.slice(2), 1) },
  'sender empty': { transaction: splitTx('', 1) },
  'type argument 200 deep': { transaction: { sender: EMPTY, ...ptb([], [moveCall('0x2', 'coin', 'zero', [deep(200)], [])]) } },
  'type argument 260 wide': { transaction: { sender: EMPTY, ...ptb([], [moveCall('0x2', 'coin', 'zero', ['0x2::m::S<' + Array(256).fill('u8').join(',') + '>'], [])]) } },
  'type argument vector< u8>': { transaction: { sender: EMPTY, ...ptb([], [moveCall('0x2', 'coin', 'zero', ['vector< u8>'], [])]) } },
  'package without 0x (resolves)': { transaction: { sender: EMPTY, ...ptb([], [moveCall('2', 'coin', 'zero', ['0x2::sui::SUI'], [])]) } },
  'package invalid': { transaction: { sender: EMPTY, ...ptb([], [moveCall('0xzz', 'coin', 'zero', [], [])]) } },
  'module invalid': { transaction: { sender: EMPTY, ...ptb([], [moveCall('0x2', '9coin', 'zero', [], [])]) } },
  'argument input out of range': { transaction: { sender: EMPTY, ...ptb([], [split(gas, [inp(70000)])]) } },
  'argument kind unknown': { transaction: { sender: EMPTY, ...ptb([], [split({ kind: 0 }, [])]) } },
  'split without coin': { transaction: { sender: EMPTY, ...ptb([], [{ command: { oneofKind: 'splitCoins', splitCoins: { amounts: [] } } }]) } },
  'command missing': { transaction: { sender: EMPTY, ...ptb([], [{ command: { oneofKind: undefined } }]) } },
  'object_id invalid': { transaction: { sender: EMPTY, ...ptb([{ objectId: '0xqq' }], [moveCall('0x2', 'clock', 'timestamp_ms', [], [inp(0)])]) } },
  'digest invalid': { transaction: { sender: EMPTY, ...ptb([{ objectId: '0x6', digest: 'not-base58!' }], [moveCall('0x2', 'clock', 'timestamp_ms', [], [inp(0)])]) } },
  'gas owner invalid': { transaction: { ...splitTx(EMPTY, 1), gasPayment: { objects: [], owner: 'nope' } } },
  'gas owner short (0x2)': { transaction: { ...splitTx(EMPTY, 1), gasPayment: { objects: [], owner: '0x2' } } },
  'gas owner without 0x (resolves)': { transaction: { ...splitTx(EMPTY, 1), gasPayment: { objects: [], owner: EMPTY.slice(2) } } },
  'expiration epoch without value': { transaction: { ...splitTx(EMPTY, 1), expiration: { kind: 2 } } },
  'expiration validity, empty proposers': { transaction: { ...splitTx(EMPTY, 1), expiration: { kind: 4, chain: '4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S', nonce: 1, allowedProposers: { epoch: 1n, proposers: [] } } } },
  'expiration negative timestamp': { transaction: { ...splitTx(EMPTY, 1), expiration: { kind: 3, chain: '4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S', nonce: 1, minTimestamp: { seconds: -5n, nanos: 0 } } } },
  'gas selection: insufficient balance': { transaction: splitTx(EMPTY, 1), doGasSelection: true },
  'gas selection: estimation fails (InsufficientCoinBalance)': { transaction: splitTx(EMPTY, '18446744073709551615'), doGasSelection: true },
  'gas selection: estimation aborts in coin::zero type check': { transaction: { sender: EMPTY, ...ptb([pureU64(5)], [moveCall('0x2', 'balance', 'destroy_zero', ['0x2::sui::SUI'], [inp(0)])]) }, doGasSelection: true },
  'gasless candidate: balance::zero<SUI>': { transaction: { sender: EMPTY, ...ptb([], [moveCall('0x2', 'balance', 'zero', ['0x2::sui::SUI'], [])]) }, doGasSelection: true },
  'gasless candidate: balance::zero<USDC>': { transaction: { sender: EMPTY, ...ptb([], [moveCall('0x2', 'balance', 'zero', ['0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC'], [])]) }, doGasSelection: true },
  'gasless candidate: unused pure inputs': { transaction: { sender: EMPTY, ...ptb([pureU64(1), pureU64(2), pureU64(3), pureU64(4)], [moveCall('0x2', 'balance', 'zero', ['0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC'], [])]) }, doGasSelection: true },
  'MoveCall to a Move object id (0x6 Clock)': { transaction: { sender: EMPTY, ...ptb([], [moveCall('0x6', 'clock', 'timestamp_ms', [], [])]) } },
};

function grpcOf(e) { for (let x = e, i = 0; x && i < 8; x = x.cause, i++) if (x.code !== undefined && x.meta !== undefined) return x; return null; }
const b64 = v => (Array.isArray(v) ? v[0] : String(v ?? '')).replace(/=+$/, '');
async function call(client, req) {
  try {
    const { response } = await client.transactionExecutionService.simulateTransaction({ readMask: { paths: ['transaction.digest', 'transaction.effects.status', 'transaction.transaction.bcs'] }, checks: 0, ...req });
    return `OK ${Buffer.from(response.transaction?.transaction?.bcs?.value ?? []).toString('base64').slice(0, 60)} ${JSON.stringify(response.transaction?.effects?.status ?? null, (_, x) => typeof x === 'bigint' ? x.toString() : x)}`;
  } catch (e) { const g = grpcOf(e); let m = String(e.message).split('\n')[0]; try { m = decodeURIComponent(m); } catch {} return `${g?.code ?? '?'} ${m} details=${b64(g?.meta?.['grpc-status-details-bin'])}`; }
}
let same = 0, diff = 0;
for (const [name, req] of Object.entries(cases)) {
  const a = await call(node, req), b = await call(zui, req);
  const eq = a === b;
  eq ? same++ : diff++;
  console.log(`${eq ? 'same' : 'DIFF'}  ${name}\n   node: ${a.slice(0, 600)}${eq ? '' : `\n   zui:  ${b.slice(0, 600)}`}`);
}
console.log(JSON.stringify({ cases: same + diff, same, diff }));
rt.close();
