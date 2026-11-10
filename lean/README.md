# lean: specs, proofs and oracles

Lean 4 (v4.35.0, core only, no Mathlib). `./zig build lean` runs `lean/check.sh`: it rejects
`sorry`/`admit`, builds everything and audits every headline theorem with `#print axioms`
(only `propext`, `Classical.choice` and `Quot.sound` are allowed). About 5 s on the Mac.

## Modules

| module | what |
|---|---|
| `Zui.Bcs.Basic` | BCS model: formats (serde-reflection shapes), values, encoder, decoder with every bcs 0.1.6 check |
| `Zui.Bcs.Uleb` | ULEB128 (bcs `parse_u32_from_uleb128`): round trip, canonicity, minimality |
| `Zui.Bcs.Roundtrip` | well-typed values `WT` and `dec_encode` |
| `Zui.Bcs.Canonical` | `dec_canonical`, `decodeFull_iff`, `encoding_unique` |
| `Zui.Bcs.Json`, `Zui.Bcs.Gen` | registry JSON, vector generator (edge cases, random registry values, mutations) |
| `Zui.Gas.Model` | gas model 15 (`gas_v3.rs` on the Move `GasStatus` of `tables.rs`, cost table v5) |
| `Zui.Gas.Theorems` | budget, rebate, meter and batching theorems |
| `Zui.Gas.Vectors` | gas op-script vectors |
| `Zui.Store.Model` | storage crash-recovery protocol (`src/store/store.zig`) |
| `Zui.Store.Theorems` | recovery theorems |
| `Zui.Store.Trace` | trace checker and trace generator |

## Theorems

BCS (decoder at depth limit 500, sequence limit 2^31-1, sorted map keys on encoded bytes,
UTF-8 per Unicode Table 3-7, trailing input rejected):
- `dec_encode`: every well-typed value decodes from its encoding, with any suffix left over.
- `dec_canonical`: anything the decoder accepts is the encoding of a well-typed value.
- `decodeFull_iff`: `decodeFull R f bs = ok v ↔ WT R 500 f v ∧ bs = encode v`. So decoding is
  a bijection between well-typed values and accepted bytes, and `encoding_unique` follows.
- `readUleb32_uleb`, `readUleb32_canonical`, `uleb_last_nonzero`: the only accepted ULEB128 for
  `n` is the minimal one.

Gas (model 15):
- `charge_le_budget`: when `chargeStorage` succeeds, computation plus storage cost is at most
  the budget plus the sender rebate. `computation_le_budget`, `senderRebate_le` (rebate at most
  the storage rebate), `outOfGas_summary` (out of gas charges exactly the budget).
- `charge_gasLeft_le`, `used_le`: the meter only goes down.
- `le_halfDigits`: bucket rounding never charges less.
- `chargeList_batch`: a run of Move charges that crosses no tier boundary and pops nothing
  below zero can be charged as one batch with the same result and the same meter. This is the
  licence for batching in the move-vm lane, with two limits the theorem does not lift:
  - it is about the meter only. Rust charges each instruction before running it, so when
    instruction `i` of a block aborts (arithmetic, bounds, native abort) Rust has charged
    exactly `ops[0..i]`. A batched VM must then leave the meter at `chargeList ops[0..i]`
    (that prefix is also quiet, so one batch of the prefix totals does it), not at the whole
    block;
  - on `OUT_OF_GAS` the error and `gasLeft` (0) agree, but Rust would have run the instructions
    before the failing charge. Batch only when the block's cost fits `gasLeft`, otherwise fall
    back to per-instruction charging, so no instruction's side effect or abort is skipped.

Store (model below):
- `recover_crash`: if the first `s` checkpoints were synced (acknowledged) and the crash left
  anything at all after them, recovery yields `G.take k` for one `k` with `s ≤ k ≤ |G|`, and
  the index, loaded from a snapshot after `j ≤ s` checkpoints with `meta` naming replay position
  `a ≤ j`, equals `stateAt G k`. No acknowledged checkpoint is lost and none is partly visible.
- `replay_idem`, `replay_from_snapshot`: replaying groups already in the index changes nothing
  (the higher version wins, ties keep the existing entry), so replay from any older position
  converges.
- `recover_idem`: recovering a recovered log changes nothing.

### Store model and its assumptions

- The log is a list of entries, each a commit group (one checkpoint, its writes) or junk.
- Recovery scans from the start and keeps the longest run of groups whose sequence numbers go
  0, 1, 2, ... (the hash chain: a group is valid only in its own place).
- A crash keeps the synced prefix. After it, the tail may hold any mix of junk (torn, zeroed,
  misdirected or rotted bytes) and groups of the history in any order (unsynced groups that
  survived, reordered writes, stale copies). This is `Garbage`.
- The one assumption is the checksum chain: nothing except `G[i]` passes validation in place
  `i`.

The model allows many unsynced groups at once (catch-up batching). The Zig store's recovery
refuses with `error.Corrupt` when it finds a valid commit after a broken tail
(`store.zig` around line 465). That rule is sound only while at most one group is unsynced at
a time, as the store does today with one `fdatasync` per group. If groups are ever written
several to one sync, a legal crash (group `i` torn, group `i+1` persisted) would be refused.

## Oracles (`.lake/build/bin/zui-spec`, NDJSON in and out, last line is a JSON summary)

```
zui-spec bcs-gen <registry.json> <out.jsonl> [seed] [fuzz]   export BCS vectors with the model's verdicts
zui-spec bcs <registry.json> <vectors.jsonl>                re-check vectors: verdict, and encode(decode(b)) == b
zui-spec bcs-chk <registry.json> <Type> <file>...           decode whole corpus blobs (0x01 tag + BCS) as <Type>
zui-spec gas-gen <gas-config.json> <out.jsonl> [seed] [n]    export gas op scripts with the model's results
zui-spec gas <vectors.jsonl>                                re-check gas vectors against the model
zui-spec store-gen <dir> [seed] [n]                         write n example traces from the store model
zui-spec store-trace <trace.jsonl>...                       check storage traces against the store model
```

### BCS vectors (`$ZUI_CORPUS/vectors/lean-bcs/vectors.jsonl`, 249,983 lines)

`{"id","types"?,"fmt","hex","expect"}`. `fmt` is a serde-reflection format in the registry's
JSON shape (`"U64"`, `{"SEQ":...}`, `{"TYPENAME":"Object"}`, ...). `types` adds containers for
this vector only (depth and map tests). `expect` is `ok` or the bcs 0.1.6 error name:
`Eof`, `ExceededMaxLen`, `ExceededContainerDepthLimit`, `ExpectedBoolean`, `ExpectedOption`,
`NonCanonicalMap`, `Custom` (unknown variant), `RemainingInput`, `Utf8`, `NonCanonicalUleb128Encoding`,
`IntegerOverflowDuringUleb128Decoding`. The registry is `lean/data/sui-format-1.83.1.json` (a copy is beside the
vectors).

### Gas vectors (`$ZUI_CORPUS/vectors/lean-gas/vectors.jsonl`, 20,000 lines)

`{"id","pv","cfg","budget","price","rgp","ops","expect"}`. `ops` are run in order on one
`SuiGasStatus`: `["charge",instr,pushes,pops,incr,0]`, `["deduct",n]`, `["read",bytes]`,
`["pkgread",bytes]`, `["publish",bytes]`, `["mutate",size,rebate]`, `["bucketize",abort]`,
`["storage"]`, `["oog"]`, `["reset"]`. `expect` is
`{"res":[...],"summary":[computation,storage,rebate,non_refundable],"used","left"}` or
`{"new":"<error>"}` when the status cannot be created.

### Store traces (`$ZUI_CORPUS/vectors/lean-store/trace-*.jsonl`, 1,000 traces, 201k events)

```
{"op":"commit","writes":[[key,version,value],...]}   one checkpoint's group, sequence implicit
{"op":"ack"}                                         every commit so far is durable
{"op":"read","state":[[key,version,value],...]}      the live index, no crash
{"op":"recover","k":n,"state":[[key,version,value],...]}
```

`state` lists every key with an entry, sorted, with its newest (version, value). The checker
requires acknowledged `≤ k ≤` started and `state = stateAt G k` at each `recover`, then
continues from `G.take k`. For the storage lane: replay the `commit`/`ack` events through the
real store under DST crashes and emit your own `recover` lines (key = object id index,
version = object version, value = a digest prefix); `store-trace` then checks them.

## Ground truth

`tools/truth/lean` (README there) runs the exported inputs through Mysten's Rust at 1.83.1.
Results on 2026-11-07: 249,983 / 249,983 BCS vectors agree with bcs 0.1.6; 20,000 / 20,000
gas scripts agree with `SuiGasStatus` over protocol 138 to 141; every corpus v1 blob
(38,701, 9.0 GB) decodes as `CheckpointData` in the model and re-encodes byte for byte.

Findings:
- sui's `Cargo.lock` pins bcs 0.1.6, not 0.1.4 as ARCHITECTURE.md says.
- `spec/sui-format-1.83.1.yaml.snap` has no `Passkey` variant (index 4) in `PublicKey` and
  `CompressedSignature`; the registry here adds it from a fresh serde-reflection trace of the
  real types. Code generated from the snapshot alone would reject those variants.
