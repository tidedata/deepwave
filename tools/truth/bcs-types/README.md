# tools/truth/bcs-types

Ground truth for the bcs-types lane, built from crates.io `bcs` 0.1.6 (the exact codec
Mysten's sui-types links; CONTRACTS.md names 0.1.4, the dumper's lock resolves 0.1.6).

```
source tools/env.sh
cargo build --release --manifest-path tools/truth/bcs-types/Cargo.toml
$CARGO_TARGET_DIR/release/zui-truth-bcs-types vectors $ZUI_CORPUS/vectors/bcs-codec/vectors.jsonl
./zig build test-conformance -Dsuite=bcs-codec
```

`vectors.jsonl`, one object per line:

| field | meaning |
|---|---|
| `id` | `<type>/<case>`, stable |
| `type` | probe type name; the Zig side maps it to its own type (src/bcs/conformance.zig) |
| `in` | input bytes, hex |
| `ok` | present when `bcs::from_bytes` succeeded: hex of `bcs::to_bytes` of the decoded value |
| `err` | present on failure: deepwave's `bcs.Error` name for the `bcs::Error` (see `kind()` in main.rs) |

Probe types: `bool u8 u16 u32 u64 u128 opt_u32 unit unit_struct array4 tuple_u8_bool bytes
string vec_u32 vec_vec_u8 vec_opt_u8 enum struct map_u8_u8 map_str_u8 nest newtype_nest
wrapper_nest`. Cases: valid values, every truncation, trailing bytes, single-byte corruptions,
a ULEB128 edge table in every length position, UTF-8 edge cases, map key order, and container
depth around the limit of 500.

## Unseen registry variants

`zui-dumper coverage` lists the 89 registry variants no corpus checkpoint contains
(`$ZUI_CORPUS/truth/checkpoint/_unseen.json`). Round 1 covers them with the generic type walk
(the `bcs-format` suite proves their shape against the registry); synthetic vectors per
variant from Rust are a round 2 item.

## edge/: hand-written Deserialize rules (reviewer, round 1)

`edge/` is a second standalone workspace that links Mysten's sui-types 1.83.1 (through
`tools/sui`, sharing the dumper's lock and the shared target dir). It probes the values whose
Rust `Deserialize` checks more than the serde shape and writes `src/types/testdata/rust_edge.txt`,
which `src/types/edge_test.zig` replays (accept/reject and re-encoding):

- `Owner::Party`: ObjectPermissions bits, members strictly sorted and unique, not the
  ConsensusAddressOwner shape;
- std `Duration`: `secs + nanos / 1e9` overflow is rejected, nanos are normalized;
- zkLogin BN254 decimal strings: any length, no leading zero; values at or above the modulus are
  accepted (ark-ff reduces them);
- `SenderSignedTransaction`: intent must be (TransactionData, V0, Sui), checked after the struct.

```
cargo build --release --manifest-path tools/truth/bcs-types/edge/Cargo.toml
$CARGO_TARGET_DIR/release/zui-truth-bcs-edge > src/types/testdata/rust_edge.txt
```
