# zui-truth-checkpoint

Ground truth for the checkpoint-verify lane, computed only with Mysten's own code: `sui-types` and
`shared-crypto` from `tools/sui` (mainnet-v1.83.1) and fastcrypto `da61cd46`. It builds into the
shared target dir (`source tools/env.sh`, then `cargo build --release` here); the binary is
`$CARGO_TARGET_DIR/release/zui-truth-checkpoint`.

```
zui-truth-checkpoint committees <out_dir> <genesis.blob> <chk_dir>
zui-truth-checkpoint synth      <out_file>
zui-truth-checkpoint verify     <out_dir> <genesis.blob> <chk_dir>
zui-truth-checkpoint bench verify-cert|verify-data|committee-prepare --iters N --list <file>
```

Regenerate everything (about 3.5 minutes on the dev Mac; the corpus is `$ZUI_CORPUS`):

```
B=$CARGO_TARGET_DIR/release/zui-truth-checkpoint
O=$ZUI_CORPUS/vectors/checkpoint-verify
G=$ZUI_CORPUS/vectors/bls-cert/upstream/genesis.blob
$B committees $O $G $ZUI_CORPUS/chk
$B synth      $O/synth.jsonl
$B verify     $O $G $ZUI_CORPUS/chk
```

Everything is deterministic (mutation choices come from `splitmix64` of the sequence number).

## `committees`: suite `committee`

`committees.jsonl`, one line per epoch (1,305 on corpus v1):
`{"epoch","keys":[hex 96-byte BLS key],"stakes":[...],"total","quorum","validity","src","eoe_seq"}`.
Keys are in committee index order (`Committee::voting_rights`, sorted by `AuthorityName`). Epoch 0
comes from the genesis system state in `genesis.blob` (`get_sui_system_state(..)
.get_current_epoch_committee()`), epoch E+1 from `next_epoch_committee` of epoch E's end-of-epoch
checkpoint through `Committee::new`; `eoe_seq` is that checkpoint. The command also asserts that
every one of the 38,701 corpus certificates verifies with Mysten's `verify_authority_signatures`
under its epoch's committee.

## `synth`: suite `committee`

`synth.jsonl`: `Committee::new` on inputs the chain never produced, built from the genesis
validators' real keys: reversed order, a repeated name (last stake wins), totals 9,999 and 10,001,
empty, all-zero stakes, a zero-stake member, one member holding everything, undecodable keys, epoch
`u64::MAX - 1`, two members, and stakes whose sum wraps (`stake-wrap`: `u64::MAX` and 10,001 build,
because sui-node's release build has no overflow checks and `.sum()` wraps to 10,000;
`stake-wrap-off` panics). Line: `{"id","epoch","rights":[[hex key, stake]],"verdict":"ok"|"panic"}`
plus the committee fields when `ok`. A `panic` is one of `Committee::new`'s assertions or the
"validator pubkey is always verified on-chain" expect. Stakes past `i64::MAX` are plain JSON integers.

`cert-*` lines (13) add `"cert":{"summary","sig","verdict"}`: three fixed test keys (secret scalars
`0x2a..01` to `0x2a..03`), a minimal epoch-3 summary, aggregate signatures over signer subsets, and the
verdict of `verify_authority_signatures` under the line's committee. `cert-wrap` and `cert-wrap-last`
give one member `2^64 - 5,000`, so the quorum weight (`weight += voting_rights`) wraps: a pair that
includes that member and sums to 2,000 after the wrap is `insufficient_stake`. 30 lines in all.

## `verify`: suite `checkpoint-verify`

`verify/<epoch>.jsonl`, one line per case:
`{"seq","case","mut":{xor|splice|drop_last_tx},"committee"?,"prev"?,"verdict","what"?,"index"?}`.
A case takes the blob of `seq`, applies the mutation, and runs the verification path under the
epoch's committee (or `committee`, another epoch's) with the previous checkpoint `prev` when given:

1. decode as `CheckpointData` (any failure: `decode`; this includes the aggregate signature being a
   curve point and every `GenericSignature` parsing, zkLogin and MultiSig included);
2. the chain step of `sui_storage::verify_checkpoint_with_committee` when `prev` is given
   (`chain_break`);
3. `CertifiedCheckpointSummary::verify_authority_signatures`: `epoch_mismatch`, `bad_bitmap`
   (signer index outside the committee), `insufficient_stake`, `bad_signature`;
4. contents digest against the summary (`digest_mismatch`, what `contents`), transaction count
   (`tx_count`), then per transaction the transaction digest (`transaction`), the effects'
   transaction digest (`effects_tx`), the effects digest (`effects`) and the events digest
   (`events`).

The user signatures pinned in the contents are not compared with the transactions' own: mainnet's
first epochs pin none for system transactions that carry a zero signature (checkpoint 9769, tx 1),
and no Mysten path compares them.

`mut`: `xor` is a list of `[offset, mask]`, `splice` is `[offset, bytes to delete, hex to insert]`
applied after the xors (it rewrites the signature info), `drop_last_tx` removes the last
transaction and fixes the count. `prev` is `{"digest","seq","epoch","eoe"}`.

Cases per checkpoint (about 44, 1,706,674 lines on corpus v1; every `real` and every `obj-real` verifies):

| case | mutation |
|---|---|
| `real` | none |
| `epoch-summary`, `epoch-sig`, `epoch-both` | epoch bit flipped in the summary, the signature info, both |
| `committee-prev`, `committee-next` | the real checkpoint under the previous or next epoch's committee |
| `seq-bit`, `summary-bit` | a bit of the summary (sequence number, anywhere) |
| `sig-bit`, `bitmap-bit` | a bit of the aggregate signature, of the signer bitmap |
| `signers-minimal`, `signers-short` | the signer set cut to the smallest quorum, and one signer fewer |
| `signers-none`, `signers-unknown`, `signers-unknown-far` | empty set, index = committee size, index + 1000 |
| `signers-add`, `signers-drop` | a non-signer added, a signer removed |
| `signers-run`, `signers-run-short`, `signers-run-unknown` | the real set, the short set and the set plus index = committee size, each `optimize()`d into run containers (about 97% of them come out as runs) |
| `contents-bit` | a bit of the contents |
| `tx-data`, `effects`, `effects-txdigest`, `events`, `usersig` | a bit of a transaction, its effects, the transaction digest inside the effects, its events, a user signature |
| `drop-last-tx` | last transaction removed |
| `obj-*` | apply mode, verdict of `verify_objects_blob` (below) instead of the path above: `obj-real`, `obj-out-bit` (a bit of an output object), `obj-drop-out` (first output object removed), `obj-effects-bit` (a bit of the effects), `obj-in-bit` (a bit of an input object, must not matter) |
| `byte-0..2` | a bit anywhere in the blob, tag byte included |
| `chain-*` | real checkpoint against a wrong or right predecessor: same, digest, sequence number, gap, epoch steps with and without end of epoch, epoch jump, epoch ahead |

Apply mode (`obj-*` cases, verdicts `digest_mismatch` with what `output_object` or `missing_output`):
for every transaction the set of output object references (id, version, digest) must equal
`TransactionEffectsAPI::all_changed_objects` (mutated, created, unwrapped). `output_object`: an
output object that is not a changed object (the check of sui-light-client's
`TransactionProof::verify_objects`); `missing_output`: a changed object without an output object.

## `bench`

`bench <name> --iters N --list <file>` prints the harness JSON line with `"impl":"rust"`:

- `verify-cert`: `verify_authority_signatures` on already decoded certificates (unit `cert`);
- `verify-data`: decode of the whole blob plus the whole verification path (unit `tx`);
- `committee-prepare`: `Committee::new` for every epoch's committee, decoding every key (unit `key`;
  it ignores `--list` and reads `vectors/checkpoint-verify/committees.jsonl`).
