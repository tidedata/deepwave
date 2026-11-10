# Compatibility with sui-node

Deepwave is built to replace Mysten's `sui-node` 1.83.1 as a full node without changes on the
client side or in operations. This page lists what is the same, what differs and what is not
done yet.

## The reference

Every behaviour is checked against Mysten's Rust code at the tag `mainnet-v1.83.1` (sui commit
`6a567faf`), run on real mainnet data. Protocol versions 1 to 142 are supported: 142 is the
version Sui 1.84 introduces, so Deepwave already follows the network across that upgrade.
`deepwave --protocol-range` prints the range in sui-node's format, so update scripts that check a
binary against the network's protocol version work unchanged.

## Drop-in surface

| sui-node | Deepwave |
|---|---|
| `sui-node --config-path fullnode.yaml` | `deepwave --config-path fullnode.yaml`: the same command line and file. A systemd unit changes only the binary path |
| `fullnode.yaml` | read directly; mapped keys listed in [configuration.md](configuration.md), the rest noted, never a failure |
| gRPC, gRPC-web and `/health` on `json-rpc-address` (0.0.0.0:9000) | the same, byte-equal responses ([rpc.md](rpc.md)) |
| TLS on `rpc.https-address` | the same, TLS 1.3 |
| Prometheus on `metrics-address` (9184) | the same port and the health-relevant metric names |
| admin interface on 127.0.0.1:1337 | the same routes and texts |
| p2p state sync and discovery on 8084/udp | client and server, anemo over QUIC; listening only when configured |
| `RUST_LOG`, `RUST_LOG_JSON`, `RUST_LOG_FILE` | the same |
| `--version` | `deepwave <version>-<commit>`, sui-node's shape |
| SIGTERM | finishes the checkpoint in hand, commits and exits in seconds |
| formal snapshot restore (`sui-tool download-formal-snapshot`) | built in: `deepwave run --snapshot EPOCH\|latest` |
| producing formal snapshots (`state-snapshot-write-config`) | `--snapshot-write DIR`, Mysten's format |
| retention (`num-epochs-to-retain`, `num-epochs-to-retain-for-checkpoints`) | the same knobs, smoothed pruning as sui-node |
| `transaction-deny-config`, `policy-config` | the same keys |
| expensive safety checks (state root, SUI conservation) | `--state-hash`, `--sui-conservation` |

The data directory format is Deepwave's own (no RocksDB). Only the bytes the node returns must
equal sui-node's; the `store-replay` suite checks every stored byte string reads back identical.

## Operator tools

`deepwave-tool` works on a stopped node's directory, like `sui-tool db-tool` on a closed database.
It takes the same lock the node does, so it cannot open a directory a running node is using.

| sui-tool / db-tool | deepwave-tool |
|---|---|
| `db-tool list-tables`, `table-summary` | `info` |
| `db-tool print-object` | `print-object --id HEX [--version V] [--bcs]` |
| `db-tool print-checkpoint`, `print-checkpoint-content` | `print-checkpoint --seq N [--bcs]` |
| `db-tool print-transaction` | `print-transaction --digest B58 [--bcs]` |
| (none; sui-node checks at runtime) | `verify-store [--live]` |
| expensive state-root check | `state-hash` |
| expensive SUI conservation check | `sui-conservation` |
| `db-tool prune-objects`, `prune-checkpoints`, `compact` | `prune` (segment cleaning is the compaction) |
| `state-snapshot-write-config` | `snapshot-write` |
| `db-checkpoint-config` | `db-checkpoint` |
| `restore-db` | `restore-db` |
| `download-formal-snapshot` | `deepwave run --snapshot E`, and `deepwave snapshot-check` |

Consensus and validator commands (`scan-consensus-commits`, `locked-object`, `dump-validators`,
anemo tools) and the `fetch-*` commands that query validators are not ported.

Other `deepwave` subcommands:
- `config-check FILE`: the flags a config becomes, with its notes;
- `check --dir DIR --against PATH --from A --to B`: compare everything stored with the checkpoint
  files it came from;
- `du DIR`: disk use per component;
- `store-compress DIR`: rewrite a stopped store's raw segments as compressed chunks.

## Expected differences

- **Quorum signatures.** GetCheckpoint's `signature` can differ when the source holds another
  valid quorum certificate for the same summary. Both verify under the committee.
- **Signature order of sponsored and multi-signer transactions.** The checkpoint bucket holds the
  signer order; sui-node serves the order the transaction was submitted with. Deepwave keeps the
  submitted order from p2p and stream sources, and asks a node for it when a checkpoint comes from
  the bucket (`--sig-order-from`).
- **p2p listener.** sui-node binds 0.0.0.0:8084 even without a configured key; Deepwave listens
  only when `listen-address` or `--p2p-listen` is set. It keeps 32 rotating discovered peer slots
  where sui-node targets 4 connections.
- **Metrics push** has no client certificate, so proxies that require mTLS reject it.
- **Startup** with `--config-path` and no `json-rpc-address` serves on 0.0.0.0:9000, as sui-node.

## Not done yet

- StateService index catch-up after a restore can take hours on a slow disk. StateService answers
  UNAVAILABLE until it is live, and SimulateTransaction's gas selection depends on it.
- SimulateTransaction: DevInspect command results and `json` on simulated objects and events.
- `fullnode-sync-mode: ConsensusObserver` (follow consensus instead of checkpoints).
- `run-with-range` by epoch (the checkpoint form maps to `--to`).
- `transaction-driver-config` allow and block lists for submission validators.
- `firewall-config` delegation.
- Automatic epoch-end DB checkpoints: use `deepwave-tool db-checkpoint` on a stopped node.
- Remote object stores for snapshot writing: write to a directory and sync it yourself.
- Archival history older than the restored snapshot is not backfilled.
- A genesis sync from checkpoint 0 has not been run end to end (every execution version is
  implemented and checked against mainnet transactions).

## Validators

Deepwave is a full node. Validator-only fullnode.yaml keys are noted and ignored.
