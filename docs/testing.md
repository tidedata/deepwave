# Testing

Deepwave is tested at three levels: unit tests that need nothing but the repository, conformance
suites that compare Deepwave with Mysten's own code on real mainnet data, and Lean 4 proofs of the
encodings, gas charging and store recovery.

## Unit tests

```
./zig build test                      # every module
./zig build test -Doptimize=ReleaseSafe
```

Unit tests are self-contained: test vectors live next to the code (`testdata/`, `vectors/`
directories under `src/`).

## Conformance suites

The truth is whatever Mysten's Rust code at `mainnet-v1.83.1` produces on real mainnet data, never
a specification or a reading of the code. A suite compares Deepwave's bytes, digests, verdicts,
error codes and gas with that truth, item by item. A suite counts as passing only at 100% of its
corpus, with no skips, limits or filters.

```
export ZUI_CORPUS=$HOME/zui-corpus
./zig build test-conformance -Dsuite=list                          # every suite and what it needs
./zig build test-conformance -Dsuite=grpc-v2 -Doptimize=ReleaseFast
./zig build test-conformance -Dsuite=exec-replay,store-dst -Doptimize=ReleaseFast -Djobs=8
./zig build test-conformance -Dsuite=bls-cert -Dlimit=100          # smoke run, never counts as done
```

`-Dsuite` takes suite names, comma separated, or `all`. A selection whose suites live in one module
builds a runner with only that module (`deepwave-conformance-<module>`), so it compiles only the
code those suites reach. Each suite prints one summary line with items, passed, failed and skipped.

`./zig build bench -Dsuite=NAME -Doptimize=fast` times the same items against the Rust baseline.

### The corpus

The suites read a corpus at `$ZUI_CORPUS`: real mainnet checkpoints and transactions across every
epoch and protocol version, plus truth files produced by Rust tools that link Mysten's crates at
the pinned revision, plus official vectors (fastcrypto, Wycheproof, RFC and NIST). The corpus is
not distributed with the source.

To produce truth yourself:

```
export ZUI_SUI_SRC=/path/to/sui            # a checkout of Mysten's sui at mainnet-v1.83.1
tools/setup-sui.sh                         # links it at tools/sui for the truth tools
cargo build --release --manifest-path tools/dumper/Cargo.toml
cargo build --release --manifest-path tools/truth/<area>/Cargo.toml
```

`tools/dumper` converts mainnet checkpoint files into the corpus format with Mysten's types;
`tools/truth/*` hold one Rust tool per area (BCS types, hashing, signatures, BLS, zkLogin, Move
format and VM, natives, execution, state sync, serving, RPC execution, indexes) that writes the
expected outputs. All Rust builds share one target directory (`$CARGO_TARGET_DIR`, set by
`tools/env.sh`).

### Suites in the release gate

`tools/ci.sh` runs the unit tests and then every suite below at 100% of the corpus.

| area | suites |
|---|---|
| corpus integrity | `corpus` (every blob against its truth, digests re-hashed), `corpus-chain` (adjacent checkpoints link) |
| protocol config | `protocol-config`, `protocol-config-getters`, `gas-tables` |
| encoding | `bcs-codec`, `bcs`, `bcs-checkpoint`, `digests`, `bcs-format`, `hash` |
| proofs | `lean-bcs`, `lean-gas`, `lean-store` |
| signatures | `sig-vectors`, `sig-corpus` (every mainnet user signature), `ecmh`, `ecvrf`, `poseidon`, `zklogin` |
| BLS | `bls12381`, `bls-cert` (every mainnet checkpoint certificate, 8 cases each), `bls-group-ops` |
| Move | `move-binary`, `move-verify`, `move-vm-gas`, `move-vm-trace`, `move-vm-load`, `move-vm-gas-cuts`, `move-vm-trace-cuts` |
| natives and framework | `natives`, `natives-cuts`, `framework` |
| networking | `anemo-wire`, `sync-rpc-codec`, `anemo-interop` (a Mysten anemo peer on loopback) |
| storage | `store-dst` (deterministic fault simulation), `store-replay` (every stored byte string) |
| sync and checkpoints | `sync-follow`, `committee`, `checkpoint-verify` (every corpus checkpoint plus mutants) |
| execution | `exec-state-hash`, `exec-system`, `exec-move-synth`, `exec-replay` (mainnet transactions re-executed) |
| serving | `grpc-v2`, `verifysig`, `render-json`, `epoch-pkg`, `index-parity`, `index-feed` |
| node | `node-execute` (the `deepwave` binary in execute mode over 10,000 checkpoints), `node-convert` |

Recorded results for the largest suites:

| suite | result |
|---|---|
| `exec-replay` | 988,204 mainnet transactions, 0 failures |
| `grpc-v2` | 4,722,443 of 4,722,443 responses byte-equal to sui-node |
| `store-replay` | 21,745,272 of 21,745,272 |
| `exec-system` | 96,372 of 96,372 |
| `bls-cert` | 38,701 mainnet certificates |
| `index-parity` | 19,030 of 19,030 |

## Store fault simulation

`store-dst` runs the storage engine on a simulated disk and clock driven by a seeded PRNG. It
injects torn writes, lost unsynced writes on crash, lost and resurrected files, latent sector
errors, misdirected writes, slow I/O, failed reads, partial writes and failed fsyncs. Workloads
are synthetic seeds, real mainnet checkpoints and long steady-state runs with pruning at every
epoch change. Every seed is checked against an in-memory model, and its trace must be accepted by
the Lean model of the recovery protocol.

## Crash tests

`src/node/crash-test.sh` follows a window of checkpoints, kills the node with `kill -9` after a
random delay, restarts it on the same directory and repeats. When the node reaches the end it runs
`deepwave check` over the whole window, which compares every stored certificate, transaction,
effects, event and object version with the files it came from. Settings come from
`ZUI_CRASH_DIR`, `ZUI_CRASH_WORKERS` (default 3) and `ZUI_CRASH_SYNC` (default `data`).

## Lean proofs

```
./zig build lean
```

builds the Lean 4 specifications and proofs in `lean/` and rejects any `sorry`. They cover BCS
round trips and canonical encoding, gas charging, and the store's crash-recovery protocol. The
`lean-*` suites run the same models as oracles against Deepwave's outputs.
