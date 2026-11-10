# RPC, metrics and admin

Deepwave serves the same `sui.rpc.v2` gRPC API as sui-node 1.83.1, on the same port, with the same
response bytes. Clients and SDKs that talk to sui-node over gRPC or gRPC-web work unchanged.

## Transports

One listener (`--serve ADDR`, fullnode.yaml `json-rpc-address`, default port 9000) carries:
- gRPC over HTTP/2 cleartext (h2c);
- gRPC-web, binary and text, over HTTP/1.1 and HTTP/2;
- zstd response compression when the client asks for it;
- CORS preflight (permissive, as sui-node);
- `GET /health[?threshold_seconds=N]`: `200 up`, or `503 down` when the latest checkpoint is
  unreadable, older than N seconds, or (with indexes on) the index lags the tip by more than 60.

`--serve-tls ADDR` (fullnode.yaml `rpc.https-address` and `rpc.tls`) serves the same API over TLS
1.3 with a PEM certificate chain and key (P-256, P-384, Ed25519 or RSA).

Limits follow sui-node's defaults: 200 streams per connection, a 4 MiB inbound message cap, a 60 s
server timeout or a shorter client `grpc-timeout`, connection max age 4 h plus 10 min grace. Every
response carries the `x-sui-*` headers (chain id, epoch, checkpoint height, timestamp, lowest
available checkpoint and objects).

## Services

| service | methods |
|---|---|
| `LedgerService` | GetServiceInfo, GetObject, BatchGetObjects, GetTransaction, BatchGetTransactions, GetCheckpoint, GetEpoch, ListCheckpoints, ListTransactions, ListEvents |
| `StateService` (needs `--indexes`) | ListOwnedObjects, ListDynamicFields, GetBalance, ListBalances, GetCoinInfo |
| `TransactionExecutionService` | ExecuteTransaction, SimulateTransaction |
| `MovePackageService` | GetPackage, GetDatatype, GetFunction, ListPackageVersions |
| `SignatureVerificationService` | VerifySignature (Ed25519, secp256k1, secp256r1, multisig, zkLogin, passkey) |
| `NameService` | LookupName, ReverseLookupName |
| `SubscriptionService` | SubscribeCheckpoints, SubscribeTransactions, SubscribeEvents |
| `v2alpha.ProofService` | GetCheckpointObjectProof |
| `grpc.health.v1.Health` | Check, Watch |
| `grpc.reflection` v1 and v1alpha | descriptors for v2, v2alpha and health |

Read masks, page sizes, page tokens, error codes and messages follow sui-node. JSON fields
(`json` on objects and events, Display) are rendered the way sui-node renders them.
ListTransactions, ListEvents and ListCheckpoints keep sui-node's budgets and limits, adjustable
with `--ledger-history`.

**ExecuteTransaction** submits to the validators of the current committee and returns effects
once a quorum has acknowledged. The default driver uses three proposers and takes the fastest
acknowledged effects; `--exec-driver sui-node` reproduces sui-node 1.83.1's driver exactly. The
responses are the same either way. Submitted transactions are logged and resubmitted after a
restart (`--pending-tx-dir`).

## How the answers are checked

Response bytes are compared with sui-node 1.83.1's for the same requests:

| check | result |
|---|---|
| `grpc-v2` suite: GetCheckpoint, GetTransaction, GetObject, MovePackageService over loopback HTTP/2 | 4,722,443 of 4,722,443 byte-equal |
| `index-parity`: StateService answers | 19,030 of 19,030 byte-equal |
| `verifysig`: VerifySignature status, message, details, bytes | 14,742 of 14,742 |
| `rpc-execute`: ExecuteTransaction responses | 6,990 of 6,990 |
| `epoch-pkg`: GetEpoch, package versions, names | 5,262 of 5,262 |
| `render-json`: object json, Display, event json | 31,963 of 31,963 |
| `rpc-simulate`: SimulateTransaction code, message, details, bytes | 1,726,232 pass, 0 fail, 45 skipped |

Live side-by-side runs at the mainnet tip match on every method that does not need the
StateService index, including all six checkpoint stream masks frame for frame.

## Known differences and open items

- **GetCheckpoint `signature`** can differ: the archive and a given sui-node may hold different
  valid quorum certificates for the same summary, with different signer sets. Both verify.
- **Lowest available checkpoint** on a store restored from a formal snapshot is the first
  checkpoint after the snapshot, as on a sui-node restored from the same snapshot.
- **StateService after a restore**: the index is built from the restored live set and then
  replayed over the stored checkpoints. Until it reaches the tip, StateService answers
  `UNAVAILABLE rpc indexes are being built`, as sui-node does while its index builds.
- **SimulateTransaction**: DevInspect command results and the `json` field of simulated objects
  and events are not complete. Gas selection needs the StateService index.
- **JSON-RPC and REST** are not served. sui-node 1.83.1 removed JSON-RPC too; unknown paths answer
  404 on both nodes.

## Metrics

`--metrics ADDR` serves Prometheus text at `/metrics`. Metric names match sui-node's where they
mean the same thing, so existing dashboards and health checks keep working:
- checkpoint progress: `last_executed_checkpoint`, `last_executed_checkpoint_timestamp_ms`,
  `highest_synced_checkpoint`, `highest_verified_checkpoint`, `last_executed_checkpoint_age`;
- epoch and protocol: `current_epoch`, `sui_current_protocol_version`,
  `sui_binary_max_protocol_version`;
- process: `uptime{process,version,chain_identifier}`;
- RPC: `rpc_requests{path,status}`, `rpc_request_latency`, `rpc_inflight_requests`;
- execution and submission: `total_transaction_certificates`, `total_transaction_effects`,
  `transaction_driver_*`, `validator_client_*`;
- network: `sui_quinn_network_peers`, `sui_quinn_network_peer_rtt`, `sui_{inbound,outbound}_*`;
- pruning: `last_pruned_checkpoint`, `num_pruned_objects`;
- store: `rocksdb_get_latency_seconds{cf_name}` and related families under typed-store names, plus
  Deepwave's own `zui_*` gauges.

`--metrics-push-url` pushes the registry as sui-node's `metrics.push-url` does (snappy protobuf),
without a client certificate.

## Admin interface

`--admin-port N` (default 1337, fullnode.yaml `admin-interface-port`) listens on 127.0.0.1 only,
without authentication, as sui-node:

| route | |
|---|---|
| `GET /logging`, `POST /logging` | read and replace the `RUST_LOG` filter at runtime |
| `POST /enable-tracing`, `POST /reset-tracing` | temporary trace filter |
| `GET /node-config` | the running configuration as `key = value` lines |
| `GET /version` | version line |
| `GET /capabilities` | empty on a full node |
| `GET /get-tx-cost?tx_digest=` | 400 on a bad digest, 404 otherwise; never crashes the node |
| `GET /transaction-deny-config`, `POST /traffic-control` | deny config dump, traffic controller tuning |
| `POST /update-endpoint` | override a peer's p2p address |
| `GET /db-shell/ls`, `GET /db-shell/read` | browse the store read-only |

## Native protocol (`zui/1`)

`--native-listen ADDR` adds a second, optional protocol on UDP: raw QUIC with ALPN `zui/1` for
native clients, and WebTransport over HTTP/3 for browsers. Both carry the same stream protocol:
- objects, checkpoints, transactions, effects and events are sent as the BCS bytes the node
  stored, inside a small BCS envelope, with no JSON, protobuf or base64 step;
- one request per bidirectional stream, so there is no head-of-line blocking between requests;
- subscriptions are filtered on the server, pushed on unidirectional streams with credit-based
  backpressure, and can resume from any retained checkpoint;
- responses can carry proofs that a light client checks against a BLS-certified checkpoint,
  without trusting the server.

The server presents a self-signed Ed25519 certificate that native clients pin; the node logs its
key, and `--native-cert-hash-file` writes the WebTransport certificate hash and the key for
browser clients. `deepwave-native` is a command-line test and benchmark client.
