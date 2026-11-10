# tools/truth/state-sync

Ground truth for the `state-sync` lane. One Rust binary, `zui-sync-truth`, built into the shared target dir
(`~/.cache/zui/target-swarm/release/zui-sync-truth`). It links Mysten's `sui-types` (mainnet-v1.83.1) and
fastcrypto; every verdict comes from Mysten's code (`CertifiedCheckpointSummary::verify_authority_signatures`,
`CheckpointContents::digest`, `TransactionEffects::digest/all_changed_objects/deleted/wrapped/unwrapped_then_deleted`,
`Object::compute_object_reference`). Committees come from `$ZUI_CORPUS/vectors/bls-cert/<epoch>.jsonl` (first line).

```
cd tools/truth/state-sync && source ../../env.sh && cargo build --release
V=$ZUI_CORPUS/vectors/sync-follow
zui-sync-truth follow  342446161 342456160 $V/dense      # dense.cp.jsonl, dense.state.jsonl, dense.summary.json
zui-sync-truth scan    $V/all.scan.jsonl                  # every corpus checkpoint, no chain
zui-sync-truth mutants 342446161 342456160 150 $V/dense.mutants.jsonl
zui-sync-truth mutants 0 330000000 600 $V/sparse.mutants.jsonl
zui-sync-truth edge    342446161 342456160 $V/edge         # hand-made edge blobs + edge.jsonl
zui-sync-truth detail  <seq>                              # puts and removes of one checkpoint
zui-sync-truth bench apply-check --iters N --list FILE    # harness baseline protocol
```

Formats are in CONTRACTS.md section 6.5.1. Verdict classes, in the order they are checked:
`decode`, `contents`, `tx_count`, `tx`, `effects`, `events`, `objects`, then the certificate (`epoch`, `bitmap`,
`stake`, `signature`), then `chain`. A mutation that Mysten's decoder rejects (including a BLS signature that is not
a valid curve point) is `decode`; whatever it accepts is checked, even when it would re-serialise differently (a
run-container signer bitmap is a valid certificate to sui-node). Not checked, by design: user signatures of the transactions (exec lane).
