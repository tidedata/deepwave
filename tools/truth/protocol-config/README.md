# zui-pc-truth

Truth tool of the protocol-config lane. Links Mysten's `sui-protocol-config` and
`sui-types::gas_model` at mainnet-v1.83.1 and writes into `$ZUI_CORPUS/vectors/protocol-config/`:

- `yaml/<Chain>_<v>.yaml` (Chain = Unknown, Mainnet, Testnet; v = 1..141): the insta YAML body of
  `ProtocolConfig::get_for_version(v, chain)` produced by the same insta serializer Mysten's
  snapshot test uses. The tool aborts unless it equals the checked-in `.snap` body.
- `dump.jsonl`: `{"chain","v","cfg"}` per line, `cfg` = serde_json of the real config (field order
  preserved). Input of the Zig generator `src/protocol/gen/gen.zig`.
- `getters.jsonl`: per (chain, version) the hand-written getters (`{"panic":true}` where Rust
  panics), `verifier_config` and `binary_config` with each argument shape, `feature_map()` and
  `lookup_feature` on names that are not bool flags.
- `gas.json`: `tables.<name>` = {table, probes, tiers} for zero/unit/v1..v5 (tier lookups for
  instruction, stack_height, stack_size at probe points), `cost_table_for_version[gm]` for gm 0..40
  and `predicates` (gas_predicates.rs).

    tools/truth/protocol-config/run.sh      # builds into the shared target-swarm and dumps
