# zui-truth-exec

Ground truth for the exec lane, computed by Mysten's code at mainnet-v1.83.1 (`sui-core`,
`sui-types`, `sui-protocol-config` from the `tools/sui` tree, fastcrypto `da61cd4`). The tool
never re-implements what it checks.

```
source tools/env.sh
(cd tools/truth/exec && cargo build --release)          # first build ~4 min (sui-core), shared target dir
T=$CARGO_TARGET_DIR/release/zui-truth-exec
$T state-hash $ZUI_CORPUS $ZUI_CORPUS/vectors/exec-state-hash/truth.jsonl.zst   # ~12 s on 16 threads
$T state-hash-history $ZUI_CORPUS $ZUI_CORPUS/vectors/exec-state-hash/history.jsonl.zst  # ~2 s
$T packages $ZUI_CORPUS <archive gRPC url>                # packages/ part (non-system packages + linkage closure)
$T objects $ZUI_CORPUS <archive gRPC url> $ZUI_CORPUS/vectors/exec-replay/objects.bin.zst  # inputs outside the corpus
$T bench state-hash --iters N --list <file>             # harness baseline
$T bench exec --iters N --list <file>                   # harness baseline
```

## state-hash (`vectors/exec-state-hash/truth.jsonl.zst`)

One line per corpus checkpoint, in sequence order:

```
{"seq":N,"epoch":E,"pv":P,"path":"v1"|"v2"|"v3","txs":T,"acc":hex32|null,"digest":hex32|null,
 "lookups":["<id hex>:<version>",...],"missing":["<id hex>:<version>",...]}
```

- `acc` is `bcs::to_bytes` of the `GlobalStateHash` returned by
  `sui_core::global_state_hasher::accumulate_effects(store, effects, ProtocolConfig(P, Mainnet))`
  over the checkpoint's effects; `digest` is `acc.digest()` (SHA-256 of the point).
- `path` is the branch `accumulate_effects` takes: `v3` = `enable_effects_v2`, `v2` =
  `simplified_unwrap_then_delete`, else `v1`.
- The store holds exactly the checkpoint's input and output objects (all transactions), keyed by
  (id, version). `missing` lists the keys Rust asked for that it does not hold (sorted); Rust then
  panics and `acc`/`digest` are null. On corpus v1 no checkpoint has missing keys.
- `lookups` lists every `get_object_ref_prior_to_key_deprecated(id, version)` call (sorted). That
  call reads history outside the checkpoint (the wrapped tombstone of an object unwrapped in the
  v1 path); the store answers `None`, so `acc` is the checkpoint-local accumulator. 30 checkpoints
  on corpus v1 make such lookups (all before protocol `simplified_unwrap_then_delete`).

## state-hash-history (`vectors/exec-state-hash/history.jsonl.zst`)

The v1-path history lookups answered `Some(ref)`. For each of the 30 corpus checkpoints whose
v1 accumulation makes lookups, for each answer source and each protocol version, one line:

```
{"seq":N,"answers":"wrapped"|"plain"|"corpus","pv":P,"fixed":bool,
 "history":["<key id>:<key ver>:<id>:<ver>:<digest>" | "<key id>:<key ver>:none",...],
 "acc":hex32|null,"digest":hex32|null}
```

- `wrapped`: every lookup answers `(id, key version - 1, OBJECT_DIGEST_WRAPPED)`.
- `plain`: every lookup answers `(id, key version - 1, [0x11; 32])`, a live-object digest.
- `corpus`: the newest ref of the id below the key version that any corpus effects name
  (written, wrapped, deleted, unwrapped-then-deleted), else `None`. On corpus v1 none exists, so
  these lines equal the `None` answers.
- `pv` is the epoch's own version (`loaded_child_objects_fixed` on) and 2 (flag off, still the
  v1 path). `fixed` is the flag. Rust's `assert!(!fixed || digest.is_wrapped())` panics on
  `plain` at the epoch's version: `acc` is null (30 lines).
- 180 lines; deepwave finishes each lookup with `state_hash.applyHistory` using the same answers.

## bench

`bench state-hash`: `accumulate_effects` per checkpoint on decoded effects with a prebuilt store
(decode and store building untimed), one thread, one warm-up pass, median of `--iters` passes,
unit `tx`.

`bench exec`: Mysten's executor (`sui_execution::executor(cfg, true)` then
`execute_transaction_to_effects`) on the coin PTBs and consensus commit prologues the deepwave
exec-replay bench selects. The store serves the checkpoint's input objects, the `packages/` part
and the system packages written by checkpoint 0 and each epoch's last checkpoint (the same
sources as `src/exec/packages.zig`). The warm-up pass prints any transaction whose effects differ
from the certified ones; one thread, median of `--iters` passes, unit `tx`.

## packages (`packages/<id hex>.obj`)

Every package id the corpus transactions name (inputs, MoveCall targets, type arguments), plus
the linkage closure, fetched as raw BCS `Object` from the archive gRPC endpoint and checked
against the reported digest. System packages are not fetched (they come from corpus writes).

## objects (`vectors/exec-replay/objects.bin.zst`)

Input objects the inputs diagnostic could not find in the corpus (shared and owned inputs at the
version the transaction read), fetched from the archive gRPC endpoint. Format: repeated
`u32 LE length` + BCS `Object`. The client decode limit is 256 MiB; each request retries up to 8
times.
