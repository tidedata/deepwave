# Architecture

Deepwave is a Sui full node written from scratch in Zig. It follows the chain checkpoint by
checkpoint, verifies each one, optionally re-executes every transaction in its own Move VM,
stores the result and serves it. There is no RocksDB and no Rust; the only C code is the vendored
zstd library.

## Pipeline

```
  public bucket    S3 archive    SubscribeCheckpoints    p2p peers
         \             |               /                    |
          +------> fetch-ahead <------+         execute every transaction,
                       |                         keep the checkpoint only if
                       v                         effects equal the certified ones
   trust     committee per epoch, walked from genesis.blob
   verify    BLS certificate, chain link, every digest, every output object
   execute   Move VM; effects, events and objects compared byte for byte
   store     one commit and one fsync per checkpoint; compressed segments
                       |
       sui.rpc.v2 gRPC (h2c, gRPC-web, TLS)    zui/1 native    metrics, admin
```

**Fetch.** Every source runs at once: Mysten's public checkpoint bucket, the requester-pays S3
archive, live SubscribeCheckpoints streams from other nodes, and p2p state sync from peers. The
first copy of a checkpoint to arrive wins. Sources are untrusted; a source that keeps serving bad
bytes for a sequence number stops the node, network and disk errors retry.

**Trust.** The genesis committee comes from `genesis.blob`. For each epoch the node verifies the
end-of-epoch checkpoint under that epoch's committee and takes the next committee from it. The
walk over all mainnet epochs takes seconds and is saved, so restarts do not repeat it.

**Verify.** A checkpoint is accepted only when the BLS quorum certificate verifies under its
epoch's committee, the summary links to the previous checkpoint, the contents digest matches the
summary, every transaction and effects digest matches the contents, and every output object
matches the effects. This is verify mode, the default. At the tip it costs 0.08 of a core.

**Execute.** In execute mode every transaction also runs in Deepwave's Move VM and executors, and a
checkpoint is accepted only when the computed effects, events and object bytes equal the certified
ones. Every execution version Sui has used is implemented, from the earliest epochs to protocol
142.

**Store.** Each checkpoint is one commit group, written with one write and made durable with one
fdatasync.

**Serve.** Readers see committed snapshots and never block the writer. The gRPC server renders
responses from stored BCS bytes; GetCheckpoint responses are cached pre-encoded.

## Parallel execution

- **Catch-up.** Transactions run across checkpoints on `--exec-threads` threads, each against the
  certified pre-state. A transaction whose result differs from what an in-order run would produce
  runs again in order before its verdict, so the stored bytes are always those of an in-order run.
- **At the tip.** Transactions inside a checkpoint are grouped into dependency levels from the
  certified effects, and each level runs on a thread pool. A checkpoint whose parallel result
  differs runs again in order.

## Formal snapshot restore

`--snapshot EPOCH` restores Mysten's formal snapshot itself: it walks trust to the snapshot's
epoch, fetches and decompresses partitions in parallel, checks every object's id, version and
digest against its reference entry, folds the references into an ECMH accumulator, and requires
the root to equal the commitment in the certified end-of-epoch checkpoint. A crash during the
restore makes the next start restore again. At every epoch end the node can also write snapshots
in Mysten's format (`--snapshot-write`).

## Storage engine

Storage formats are internal: only the bytes the node returns must equal Mysten's.

- **One append-only segment log per epoch.** A checkpoint's commit group holds the summary and
  contents, every transaction with effects and events, every object version and removal, then a
  commit record. Every record carries a checksum seeded with its location, so torn, rotten and
  misdirected writes are caught. Commit records chain the checksums of their group and the
  previous commit, so recovery finds the durable prefix exactly.
- **Compressed chunks.** Segments are stored as zstd-compressed chunks, with a decoded-chunk
  cache in memory.
- **Derived indexes, rebuilt from the logs when missing or damaged.** The live table maps each
  object id to its newest version in a checksummed, page-journaled hash table. Object versions,
  transactions and checkpoints go into a memtable that is sealed into immutable run files.
  Recovery loads the live table, checks the run chain and replays the log from the first position
  an index does not cover.
- **Pruning without compaction.** Retention follows sui-node's settings. Pruning drops whole
  segments after carrying forward the live objects they hold. With `--age-out`, superseded
  versions and old checkpoint data become holes in sealed segments and are freed by punching
  holes, without rewriting.
- **Readers.** A snapshot is a committed checkpoint number plus a read-side grace period. Reads
  are zero-copy views into the mapped segments after a checksum check.

**How the store is tested.**
- A deterministic simulator runs the engine on a simulated disk and clock and injects torn writes,
  lost unsynced writes, lost and resurrected files, latent sector errors, misdirected writes,
  failed reads and failed fsyncs. Every seed is checked against an in-memory model, and its trace
  must be accepted by a Lean 4 model of the recovery protocol.
- Crash tests kill the node with `kill -9` at random points while it follows mainnet, then
  compare every stored byte with its source; more than 500 kills have ended with 0 bad bytes.

## Indexes for RPC

- **StateService index** (owned objects, balances, dynamic fields, coin info): on disk under
  `DIR/state-index`, built once from the live set, then updated per checkpoint and replayed from
  its durable watermark after a restart.
- **Ledger history** (ListTransactions, ListEvents, ListCheckpoints): built from the store's
  checkpoint segments for the whole retained window, resumable.
- **RPC index** (package versions, past epochs): under `DIR/rpc`.

## Speed design

- **Zero-copy BCS.** Bytes are validated against a type's layout in one pass that records field
  offsets; digests are computed over byte ranges with no decode.
- **Runtime CPU dispatch.** Hot kernels (hashing, signature and BLS arithmetic) are compiled for
  several x86_64 tiers (baseline, AVX2, AVX-512 IFMA) and chosen by CPUID at startup.
- **Threads with bounded queues** for fetch, verify, execute, commit and serve; no allocation on
  the hot paths beyond per-stage arenas.
- **Metrics rendered on scrape** from counters, under sui-node's names where they mean the same.

## Source map

| directory | contents |
|---|---|
| `src/core/` | shared types, allocators, CPU dispatch |
| `src/bcs/`, `src/types/` | BCS encoding and Sui types |
| `src/crypto/` | hashes, signatures (Ed25519, secp256k1, secp256r1, multisig, passkey), BLS12-381, zkLogin |
| `src/move/` | Move binary format, verifier and VM |
| `src/natives/` | Sui and Move native functions |
| `src/protocol/` | protocol config tables, versions 1 to 142 |
| `src/exec/` | transaction execution, gas, system transactions |
| `src/checkpoint/`, `src/sync/` | checkpoint verification and state sync |
| `src/store/` | storage engine |
| `src/rt/`, `src/net/` | runtime, QUIC, TLS 1.3, anemo |
| `src/serve/`, `src/index/`, `src/history/` | gRPC server, renderers, indexes |
| `src/rpc_exec/` | ExecuteTransaction and SimulateTransaction |
| `src/node/` | the full node binary and `deepwave-tool` |
| `src/light/` | verify-only light client, also built for WebAssembly (`./zig build wasm-light`) |
| `src/harness/` | conformance harness and runner |
| `lean/` | Lean 4 models and proofs (BCS, gas, store recovery) |
| `tools/truth/`, `tools/dumper/` | Rust tools that produce ground truth from Mysten's code |
| `vendor/zstd/` | zstd 1.5.7, BSD license |

Each module may import only the modules listed before it in `build.zig`'s module table, which
keeps the dependency graph layered and lets one module's tests build without the rest.
