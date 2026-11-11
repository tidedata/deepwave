# Performance and correctness

Deepwave measured against Mysten's sui-node 1.83.1 (`6a567faf`). Unless a row says otherwise, both
nodes ran on the same machine with the same real mainnet inputs, and every compared output matched
byte for byte. Measured November 2026.

**Machine.** Mysten's recommended full-node hardware specification: 8 cores / 16 vCPU (x86_64,
Ice Lake), 128 GiB RAM, one local NVMe drive. Both binaries were built on the machine; sui-node in
its release profile, Deepwave in ReleaseFast.

**Modes.** Verify mode (the default) checks certificates, digests and output objects and executes
nothing. Execute mode also runs every transaction and compares the results with the certified
effects. Each row says which mode was measured.

## Headline

| | Deepwave | sui-node | |
|---|---|---|---|
| Move VM execution, per instruction | 15.8 ns | 78 ns | 5.0x faster |
| Catch-up, both executing every transaction | 11,871 tx/s | 2,427 tx/s | 4.9x faster |
| CPU per GetCheckpoint | 238 us | 6,817 us | 28x less |
| RAM during catch-up (Deepwave in verify mode, sui-node executing) | 961 MB | 12,781 MB | 13x less |
| Disk at sui-node's retention (Deepwave projected, sui-node measured) | about 300 GB | 335 GB | about 10% less |
| gRPC responses compared with sui-node | 4,722,443 | | 0 differences |

## Whole node

The same 100,000 mainnet checkpoints for both nodes, read from Mysten's checkpoint archive with 64
requests in flight per node. Each process sampled from /proc every second.

| what | Deepwave | sui-node | |
|---|---|---|---|
| Catch-up, both executing every transaction | 11,871 tx/s | 2,427 tx/s | 4.9x faster |
| Catch-up, checkpoints per second (same range) | 453.7 | 95.3 | 4.8x faster |
| CPU per transaction in catch-up | 797 us | 2,862 us | 3.6x less |
| RAM during catch-up, Deepwave in verify mode, sui-node executing (steady RSS) | 961 MB | 12,781 MB | 13x less |
| Private memory, execute-mode catch-up with the full live set, 8 threads | about 2.1 GB | 12.8 GB RSS | |
| CPU per GetCheckpoint | 238 us | 6,817 us | 28x less |
| CPU per GetObject | 10.1 us | 289 us | 28x less |
| Disk at sui-node's retention (Deepwave projected from its restore size plus measured growth; sui-node measured) | about 300 GB | 335 GB | about 10% less |
| Bytes written to disk over the 100,000 checkpoints (Deepwave in verify mode) | 38.1 GB | 63.4 GB | 1.7x less |
| Formal snapshot restore, epoch 1303 (sui-node: `sui-tool download-formal-snapshot`) | 1,393 s | 3,588 s | 2.6x faster |

In the execute-mode catch-up rows Deepwave used 8 executor threads (9.46 cores) and sui-node 6.94
cores. Over every execute-mode catch-up window, 5,141,720 transactions were executed with 0
mismatches. On later windows with 6 to 12 threads Deepwave ran 12,263 to 14,641 tx/s.

## RPC

Both nodes idle at the end of the range. A gRPC load generator on 4 pinned vCPUs, the node on the
other 12; 30 s per call, concurrency 64 over 8 connections. CPU per request is the node's CPU over
the run divided by successful responses.

| call | Deepwave | sui-node 1.83.1 |
|---|---|---|
| GetCheckpoint, 2,000 checkpoints, BCS mask | 5,922 req/s, p50 7.3 ms, p99 21.4 ms, 1.41 cores | 1,722 req/s, p50 33.8 ms, p99 81.4 ms, 11.73 cores |
| GetObject (latest), 2,910 objects | 29,784 req/s, p50 0.83 ms, p99 10.9 ms, 0.29 cores | 21,267 req/s, p50 1.62 ms, p99 6.62 ms, 5.95 cores |

sui-node was CPU bound on GetCheckpoint; Deepwave was not, so its request rate here is bounded by
the client.

## At the tip

Both nodes following mainnet at the same time for 10 minutes (2,468 checkpoints), Deepwave in
verify mode:

| | Deepwave | sui-node 1.83.1 |
|---|---|---|
| cores on average | 0.081 | 0.553 |
| CPU per checkpoint | 16.6 ms | 134 ms |
| median RSS | 633 MB | 7,436 MB |
| written per checkpoint | 429 KB | 1,240 KB |

**Tip latency over p2p, execute mode.** Once a second, the age of the last executed checkpoint on
each node, over 40 minutes, on different machines. Every one of the 8,739 checkpoints Deepwave
applied came from p2p and was built by executing all of its transactions (331,774 transactions,
all byte-equal to the certified effects).

| | p50 | p90 | p99 | max |
|---|---|---|---|---|
| sui-node 1.83.1 | 655 ms | 961 ms | 1,322 ms | 2,338 ms |
| Deepwave, p2p | 632 ms | 871 ms | 1,182 ms | 1,690 ms |

Deepwave applied a checkpoint about 35 ms after its summary arrived and used 0.27 of a core.

## Components against Mysten's code

Mysten's own Rust code called directly, against Deepwave doing the same work on the same items.
One machine, no network, median time per item; ratios carry about 10% noise.

| stage | Deepwave | Mysten | Deepwave faster |
|---|---|---|---|
| Move VM, per instruction | 15.8 ns | 78 ns | 5.0x |
| Execution (Move VM and gas), 3,958 calls, 16,555 of 16,555 outputs equal | 132 us | 653 us | 4.1 to 4.9x |
| Signature intake, 4 threads, batched, 25,663 mainnet transactions | 117k/s | 50k/s | 2.4x |

Signature checks by scheme, one thread, every user transaction checked as at intake:

| scheme | Deepwave | Mysten | Deepwave faster |
|---|---|---|---|
| secp256r1 | 55.4 us | 144.1 us | 2.4x |
| Passkey | 57.3 us | 121.2 us | 2.1x |
| zkLogin, cached | 41.4 us | 69.6 us | 1.8x |
| Ed25519 | 42.0 us | 66.6 us | 1.6x |
| Multisig | 88.9 us | 135.5 us | 1.6x |
| secp256k1 | 80.8 us | 115.0 us | 1.4x |

Single-thread component benchmarks on the same inputs (`./zig build bench -Dsuite=<suite>
-Doptimize=fast`, on an Apple M-series machine):

| component | Rust | Deepwave | ratio |
|---|---|---|---|
| GetCheckpoint render, 28,399 transactions | 45,203 ns/tx | 4,504 ns/tx | 10.0x |
| GetDatatype / GetFunction, warm package cache | 913 ns | 167 ns | 5.5x |
| SimulateTransaction, warm package cache, 20,087 transactions | 1,538,531 ns/tx | 321,509 ns/tx | 4.8x |
| Move-call PTB execution to effects, 1,420 PTBs | 702,225 ns/tx | 177,954 ns/tx | 4.0x |
| Whole checkpoint verification (decode, BLS certificate, digests) | 44,279 ns/tx | 27,778 ns/tx | 1.6x |

## Correctness

What Deepwave was checked against, byte for byte:

| check | items | result |
|---|---|---|
| Mainnet transactions re-executed (`exec-replay`) | 988,204 | 0 diffs |
| Real mainnet signatures verified | 3,435,641 | 0 diffs |
| gRPC responses against sui-node (`grpc-v2`) | 4,722,443 | 0 diffs |
| Stored byte strings read back (`store-replay`) | 21,745,272 | 0 diffs |
| System transactions (`exec-system`) | 96,372 | 0 diffs |
| Store crash and corruption simulations (`store-dst`) | 4,736 | all pass |
| Test suites in the release gate | 52 | 52 pass |

**Live mainnet.** From a formal snapshot to the tip and one hour there in execute mode: about 5.9
million transactions, 0 mismatches, 0 rejected checkpoints.

**Crash tests.** More than 500 `kill -9` restarts while following mainnet (on macOS and Linux,
from archive and local sources, many within a few checkpoints of an epoch change), each
followed by a byte-for-byte check of everything stored: 0 bad bytes, 0 rejected checkpoints.

How the suites work is in [testing.md](testing.md).
