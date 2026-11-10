# zui-lean-truth

Ground truth for the Lean specs, from Mysten's own Rust at sui 1.83.1. It never reimplements a
rule: BCS verdicts come from crates.io `bcs` 0.1.6 (the version sui's `Cargo.lock` pins),
driven by a format-directed `DeserializeSeed` so every check is the crate's own; gas comes from
`sui-types`' `SuiGasStatus` with `ProtocolConfig::get_for_version(pv, Mainnet)`.

Build (shared target dir from `tools/env.sh`):

```
source tools/env.sh
cargo build --release --manifest-path tools/truth/lean/Cargo.toml
B=$CARGO_TARGET_DIR/release/zui-lean-truth
```

Commands:

```
$B registry spec/sui-format-1.83.1.yaml.snap lean/data/sui-format-1.83.1.json
$B bcs-check lean/data/sui-format-1.83.1.json $ZUI_CORPUS/vectors/lean-bcs/vectors.jsonl
$B gas-config lean/data/gas-config-mainnet.json
$B gas-check $ZUI_CORPUS/vectors/lean-gas/vectors.jsonl
```

`registry` strips the insta header, converts the snapshot to JSON and adds the enum variants the
snapshot lacks (found by tracing `PublicKey` and `CompressedSignature` with serde-reflection).
`gas-check` also requires each vector's config row to equal Rust's for that protocol version.
Formats are in `lean/README.md`. The checkers print `FAIL` lines and a JSON summary; a corrupted
`expect` makes them fail (checked).

`edge/` holds reviewer edge cases written from the Rust source for paths the generated vectors
do not reach (meter u64 overflows, the 10M instruction and 100M size tiers, exact tier starts,
storage tracking overflow, the u128 package-read path, price and rounding boundaries, depth
through unit and tuple structs). Their `expect` comes from Rust (`edge/gen.py` explains how);
both `zui-spec` and this tool must pass on them. Suites `lean-bcs` and `lean-gas` run them.
