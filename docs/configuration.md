# Configuration

Deepwave is configured with command-line flags, a `key = value` file of the same flags, or
sui-node's own `fullnode.yaml`. `deepwave --help` prints the full list; this page groups it.

```
deepwave run --dir DIR [flags]                    run with flags
deepwave run --config FILE [flags]                flags from a file (key = value, or fullnode.yaml)
deepwave --config-path fullnode.yaml [flags]      sui-node's command line
deepwave config-check FILE                        print the flags a config file becomes, and its notes
```

In every form, flags given on the command line come after the file's and win.

## A mainnet full node

```
deepwave run --dir /var/lib/deepwave \
  --genesis /etc/deepwave/genesis.blob \
  --snapshot latest --snapshot-threads 16 \
  --mode execute --indexes \
  --p2p "$(tools/p2p/seeds.sh)" \
  --serve 0.0.0.0:9000 --metrics 127.0.0.1:9184
```

On an empty directory this restores Mysten's newest formal snapshot, checks it against the
certified state root, then follows mainnet from the snapshot's epoch, executing every transaction,
and serves `sui.rpc.v2` on port 9000. On later starts the same command resumes the store.

## Network and sources

| flag | meaning |
|---|---|
| `--network mainnet\|testnet` | chain to follow (default mainnet). Sets the chain id, protocol table, buckets, snapshot origin, stream node and p2p server name. Pair it with that network's `--genesis` |
| `--source http[:URL]\|s3\|dir:PATH\|p2p` | checkpoint source. Default `http`: `https://checkpoints.<network>.sui.io`, no credentials. `s3` reads Mysten's requester-pays archive (`s3://mysten-<network>-checkpoints`). `dir:PATH` reads a directory of checkpoint files |
| `--no-s3-fallback` | use the http source without falling back to S3 |
| `--stream URL[,URL...]\|off` | live SubscribeCheckpoints streams (gRPC-web) that race each other and the source. Default `https://fullnode.<network>.sui.io` with a network source |
| `--sig-order-from URL`, `--sig-order-rps N` | node asked for the submitted signature order of bucket checkpoints with sponsored or multi-signer transactions (the bucket holds only the signer order). Default: the first loopback `--stream` URL, else the first one; 20 req/s, 200 for loopback, 0 = off |
| `--s3-profile NAME`, `--s3-credentials FILE`, `--s3-budget USD` | credentials for the S3 source (default file `$AWS_SHARED_CREDENTIALS_FILE` or `~/.aws/credentials`) and a hard stop on estimated spend (default 5 USD) |
| `--from tip\|N`, `--to N` | first checkpoint for a fresh store (default tip; an existing store always resumes) and an optional last one |
| `--workers N`, `--fetchers N`, `--window N`, `--poll-ms N`, `--lookahead N` | verify threads, fetch threads, fetch-ahead depth, tip poll spacing (default 25 ms for http, 100 ms for s3) and tip lookahead (default 2) |

Every checkpoint is verified the same way whichever source delivers it first.

## Trust

| flag | meaning |
|---|---|
| `--genesis FILE` | the network's `genesis.blob`, the trust root |
| `--epochs FILE` | epoch index (`epochs.jsonl`) to find end-of-epoch checkpoints without searching |
| `--trust-dir PATH` | local checkpoints tried first during the committee walk |
| `--p2p-pinned SEQ:DIGEST[,...]` | pinned checkpoints: a summary at SEQ must have this digest |

## Mode

| flag | meaning |
|---|---|
| `--mode verify\|execute` | `verify` (default) checks the certificate, every digest and every output object against the certified effects. `execute` also runs every transaction in Deepwave's Move VM and accepts a checkpoint only when effects, events and objects equal the certified bytes |
| `--exec-threads N` | execute mode: threads running transactions across checkpoints (default half the CPUs, at most 16) |
| `--exec-window N`, `--exec-window-mb N` | checkpoints and bytes in flight between commit and execution (64, 128 MiB) |
| `--exec-cache-mb N` | memory shared by the threads' Move package caches (3072) |
| `--no-halt` | keep going after a mismatch (default: stop with exit code 3) |
| `--packages DIR`, `--packages-from URL` | package objects tried before the store, and a full node asked for packages found nowhere else |
| `--deny-state FILE` | deny-list state for a store started without the full live set |
| `--state-hash verify-only\|halt\|off` | end-of-epoch state root check (default verify-only) |
| `--sui-conservation verify-only\|halt\|off` | end-of-epoch SUI conservation check (default off, as sui-node) |

## Snapshot restore

| flag | meaning |
|---|---|
| `--snapshot EPOCH\|latest\|retained` | on an empty store, restore Mysten's formal snapshot, then follow. `retained` picks the newest one at or below the current epoch minus `--retention-epochs`, so the node holds every checkpoint sui-node holds |
| `--snapshot-origin URL\|dir:PATH` | where snapshot files come from (default `https://formal-snapshot.<network>.sui.io`) |
| `--snapshot-threads N` | partitions fetched and checked in parallel (default 8) |
| `--epoch-records N` | GetEpoch records filled for the N epochs before the current one (default 30) |
| `--snapshot-write DIR`, `--snapshot-write-threads N` | at every epoch end, write a formal snapshot in Mysten's format to `DIR/epoch_<E>/`, checked against the certified root |

Leave `--live-capacity` and `--memtable-versions` unset for a restore.

## Storage and retention

| flag | meaning |
|---|---|
| `--dir DIR` | data directory (store, committees, indexes) |
| `--sync none\|data\|full` | durability (default `data`: one fdatasync per checkpoint) |
| `--retention-epochs N` | sui-node `num-epochs-to-retain-for-checkpoints` (default 2) |
| `--object-retention-epochs N` | sui-node `num-epochs-to-retain` for superseded object versions (default 1) |
| `--age-out` | free data below the retention floors by punching holes in sealed segments (default off) |
| `--no-smooth` | prune whole epochs at once (default: smoothed over the epoch, as sui-node) |
| `--no-compress`, `--compress-threads N` | write segments uncompressed; threads compressing chunks (default min(4, cores)) |
| `--chunk-cache-mb N` | decoded-chunk cache (1024 MiB) |
| `--cp-cache-mb N` | pre-encoded GetCheckpoint response cache (256 MiB, 0 = off) |
| `--live-capacity N`, `--live-dirty-pages N`, `--index-flush-interval N`, `--memtable-versions N` | live table and index sizing |
| `--flush-writers N`, `--flush-direct` | live-table flush writers, optionally O_DIRECT |
| `--keep-spool`, `--no-read-sets` | keep fetched files after commit; skip storing input versions |

## Serving

| flag | meaning |
|---|---|
| `--serve ADDR` | `sui.rpc.v2` gRPC over h2c, gRPC-web over HTTP/1.1, and `/health`, e.g. `0.0.0.0:9000` |
| `--serve-tls ADDR`, `--serve-tls-cert FILE`, `--serve-tls-key FILE` | the same over TLS 1.3. Without a cert, a self-signed P-256 certificate for localhost |
| `--rpc KEY=VALUE` | `grpc-timeout-ms`, `max-connection-age-secs`, `max-connection-age-grace-secs`, `subscription-watermark-interval`, `subscription-max-subscribers` |
| `--rpc-release 1.83\|1.84\|N` | which sui-node release's protocol config fields GetEpoch lists |
| `--indexes`, `--no-indexes` | StateService indexes (owned objects, balances, dynamic fields, coin info) |
| `--rpc-index-dir PATH`, `--ledger-history-dir PATH` | index locations (default under DIR) |
| `--ledger-history KEY=VALUE` | ListTransactions, ListEvents and ListCheckpoints limits |
| `--tx-deny KEY=VALUE`, `--policy KEY=VALUE`, `--early-validation true\|false` | transaction-deny-config, policy-config and early validation |
| `--execute-epoch-from HOST:PORT`, `--exec-driver deepwave\|sui-node`, `--pending-tx-dir PATH\|off` | ExecuteTransaction: where the committee comes from, which submission driver, and the pending-transaction log resubmitted after a restart |
| `--drain-ms N`, `--shutdown-timeout S` | on SIGTERM, time open calls get (20000 ms) and the overall exit bound (110 s) |

## p2p

| flag | meaning |
|---|---|
| `--p2p HOST:PORT[@PEERID][,...]` | also follow over anemo state sync from these peers. `tools/p2p/seeds.sh` prints mainnet's seed peers in this form |
| `--p2p-only` | follow from p2p peers alone (needs a store to resume) |
| `--p2p-key FILE` | Ed25519 network key seed; random when absent |
| `--p2p-listen ADDR:PORT\|off`, `--p2p-external ADDR`, `--p2p-access public\|private\|trusted` | serve state sync and discovery to inbound peers (off unless set) |
| `--p2p-race N`, `--p2p-push-peers N`, `--p2p-discover N`, `--p2p-exec-threads N`, `--p2p-listen-threads N` | peer fan-out and threads |
| `--p2p-opt KEY=VALUE` | any sui-node `p2p-config` key, e.g. `discovery.peer-failure-cooldown-ms=3600000` |

## Native protocol, metrics and admin

| flag | meaning |
|---|---|
| `--native-listen ADDR`, `--native-cert-hash-file FILE` | the `zui/1` native protocol over QUIC and WebTransport (off by default), see [rpc.md](rpc.md) |
| `--native-cert FILE`, `--native-key FILE` | PEM certificate chain (leaf first) and key for `zui/1` and WebTransport (P-256, P-384, Ed25519 or RSA), reloaded on SIGHUP or when the files change. Without them, a self-signed P-256 certificate rotated every 7 days |
| `--metrics ADDR` | Prometheus text at `http://ADDR/metrics` |
| `--metrics-push-url URL`, `--metrics-push-interval S` | push the registry as sui-node does (no mTLS) |
| `--admin-port N` | admin interface on `127.0.0.1:N` (default 1337, 0 = off) |
| `--status-every S` | status line period |

## Environment

| variable | meaning |
|---|---|
| `RUST_LOG` | log filter (`info` by default; `debug`, `warn,serve=debug`), reloadable via `POST /logging` |
| `RUST_LOG_JSON=1` | JSON log lines in tracing-subscriber's layout |
| `RUST_LOG_FILE=PREFIX` | log to `PREFIX.YYYY-MM-DD` instead of stderr |
| `ZUI_AGE_OUT` | `1` turns on age-out like `--age-out`, `0` forces it off |
| `ZUI_INDEX_BUILD_GROUPS` | passes over the live set when building the StateService index (default 4; 1 needs temp space for every row) |
| `ZUI_NATIVE_PACING`, `ZUI_NATIVE_HYSTART`, `ZUI_NATIVE_CUBIC`, `ZUI_NATIVE_PMTUD`, `ZUI_NATIVE_IW_MTU`, `ZUI_NATIVE_EARLY_SETTINGS` | `1` turns on the native listener's QUIC pacing, HyStart++, CUBIC, path MTU discovery, datagram-sized initial window, and HTTP/3 SETTINGS with the handshake flight (all off by default) |

## fullnode.yaml

`deepwave --config-path fullnode.yaml` (or `run --config FILE.yaml`) reads sui-node's config.
The keys Deepwave has are mapped to the flags above; every other key becomes an `info` or `warn`
note, never a failure. Only YAML Deepwave cannot parse fails the load. Run
`deepwave config-check fullnode.yaml` to see the flags and notes before switching.

| fullnode.yaml key | Deepwave |
|---|---|
| `db-path` | `--dir` |
| `genesis.genesis-file-location` | `--genesis` |
| `json-rpc-address` | `--serve` (unset: `0.0.0.0:9000`, as sui-node) |
| `metrics-address` | `--metrics` |
| `admin-interface-port` | `--admin-port` |
| `rpc.enable-indexing` | `--indexes` |
| `rpc.tls`, `rpc.https-address` | `--serve-tls`, `--serve-tls-cert`, `--serve-tls-key` |
| `rpc.grpc-timeout-ms`, connection age, subscription keys | `--rpc KEY=VALUE` |
| `rpc.ledger-history.*` | `--ledger-history KEY=VALUE` |
| `p2p-config.seed-peers`, `listen-address`, `external-address`, `discovery.*`, `state-sync.*` | `--p2p`, `--p2p-listen`, `--p2p-external`, `--p2p-access`, `--p2p-pinned`, `--p2p-opt` |
| `authority-store-pruning-config.num-epochs-to-retain(-for-checkpoints)` | `--object-retention-epochs`, `--retention-epochs` |
| `state-archive-read-config` | `--source` |
| `enable-db-sync-to-disk` | `--sync` |
| `state-snapshot-write-config` (`object-store: File`) | `--snapshot-write` |
| `transaction-deny-config`, `policy-config`, `transaction-driver-config.enable-early-validation` | `--tx-deny`, `--policy`, `--early-validation` |
| `metrics.push-url`, `metrics.push-interval-seconds` | `--metrics-push-url`, `--metrics-push-interval` |
| `run-with-range: {checkpoint: N}` | `--to N` |
| `zui.rpc-index-path`, `zui.ledger-history-path` | `--rpc-index-dir`, `--ledger-history-dir` |

Validator-only keys, RocksDB tuning, JSON-RPC indexing keys and `grpc-load-shed` /
`grpc-concurrency-limit` (validator server only) are noted and ignored. Other keys are `warn`
notes. See [compatibility.md](compatibility.md).
