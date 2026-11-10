# zui-truth-bls

Ground truth for the crypto-bls lane, computed only with Mysten's own code: fastcrypto `da61cd46`
(the rev sui mainnet-v1.83.1 pins) over blst 0.3.16, and `sui-types` / `shared-crypto` from
`tools/sui` (mainnet-v1.83.1). It builds into the shared target dir (`source tools/env.sh`, then
`cargo build --release` here); the binary is `$CARGO_TARGET_DIR/release/zui-truth-bls`.

```
zui-truth-bls certs <out_dir> <genesis.blob> <chk_dir>
zui-truth-bls synth <out_file>
zui-truth-bls vectors <out_file>
zui-truth-bls groupops <out_file>
zui-truth-bls bench cert-verify|committee-prepare --iters N --list <file>
```

Regenerate everything (about 40 s on the dev Mac):

```
B=$CARGO_TARGET_DIR/release/zui-truth-bls
$B certs    $ZUI_CORPUS/vectors/bls-cert $ZUI_CORPUS/vectors/bls-cert/upstream/genesis.blob $ZUI_CORPUS/chk
$B synth    $ZUI_CORPUS/vectors/bls-cert/synthetic.jsonl
$B vectors  $ZUI_CORPUS/vectors/bls12381/fastcrypto.jsonl
$B groupops $ZUI_CORPUS/vectors/bls-group-ops/fastcrypto.jsonl
```

All outputs are deterministic (fixed seeds; the only randomness fastcrypto adds, batch-verify
scalars, is 1 for a single certificate).

## `certs`: suite `bls-cert`

One file per epoch, `<out_dir>/<epoch>.jsonl`.

Line 1 is the committee: `{"epoch","keys":[hex 96-byte compressed G2, ...],"stakes":[...]}`. Keys are
in committee index order, which is `Committee::voting_rights` sorted by `AuthorityName`. Epoch 0
comes from the genesis system state (`genesis.blob` from MystenLabs/sui-genesis, sha256 in
`upstream/SOURCE`). Epoch E > 0 comes from the `next_epoch_committee` of epoch E-1's end-of-epoch
checkpoint in the corpus.

Every other line is one case:
`{"seq","case","signers":[u32...],"msg":hex,"sig":hex 48,"verdict"}`.

- `msg` is the exact signed message:
  `BCS(IntentMessage(Intent::sui_app(CheckpointSummary), summary)) ++ epoch as u64 LE`.
- `signers` are committee indices from the certificate's roaring bitmap.
- `verdict` comes from Mysten's own calls, as `AuthorityQuorumSignInfo` does for the BLS part:
  1. `AggregateAuthoritySignature::from_bytes` gives `"decode"` on failure.
  2. `add_aggregate` into the default obligation signature.
  3. Signer keys come from the committee; a duplicate index is skipped. An index outside the
     committee gives `"unknown-signer"` (`add_to_verification_obligation`'s `UnknownSigner`, before
     any pairing work). Real certificates never contain one; `synth` does.
  4. `VerificationObligation::verify_all` gives `"ok"` or `"invalid"`.

  Stake and epoch checks are not part of the verdict; they belong to checkpoint-verify.

The eight cases per checkpoint:

| case | mutation |
|---|---|
| `real` | none |
| `msg-bit` | one message bit flipped |
| `sig-swap` | another checkpoint's signature |
| `drop-signer` | one signer removed |
| `add-signer` | one non-signer added |
| `sig-bit` | one signature bit flipped, flag bits included |
| `sig-inf` | infinity signature |
| `sig-nonsub` | an on-curve G1 point outside the subgroup |

Mutation choices come from `splitmix(seq ^ 0x7a75692d626c7321)`.

Corpus v1 gives 1,305 files, 309,608 cases and 485 MB, built in 29 s. Every one of the 38,701
real certificates verifies with Mysten's code.

## `synth`: suite `bls-cert`, file `synthetic.jsonl`

Same line format and verdict path as `certs`, over a synthetic committee of 40 keys from a fixed
seed (uneven stakes summing to 10,000, as `Committee::new` requires). Mainnet certificates are
always signed by more than two thirds of the committee, so they never reach deepwave's direct-sum
branch for few signers, an unknown signer index or an empty signer set. Here signer sets of
0, 1, 2, 3, 5, 8, 13, 19, 20, 21, 27, 34, 39 and 40 members (three random sets per size) each get
`real` (the aggregate of the members' own signatures; key 0's signature when there are none),
`msg-bit`, `drop-signer`, `add-signer`, `unknown-signer` (index 40 appended),
`unknown-signer-max` (index 2^32 - 1 appended), `sig-inf` and `sig-nonsub`. 302 lines, 37 `ok`.

## `vectors`: suite `bls12381`

JSONL, one object per vector, with keys `op` and `id` plus the op's fields. Bytes are hex.

| op | fields | what |
|---|---|---|
| `hash_to_g1` | msg, dst, out | `blst::hash_to_g1`, compressed |
| `sk_to_pk` | sk, pk | `BLS12381KeyPair` from a 32-byte BE key |
| `sk_decode` | sk, decode | `BLS12381PrivateKey::from_bytes` accepts |
| `sign` | sk, msg, sig | `BLS12381KeyPair::sign` |
| `verify` | pk, msg, sig, verdict | `pk-decode`, `sig-decode`, `ok` or `invalid` (`BLS12381PublicKey::verify` after both decodes) |
| `sig_decode` | in, decode, bytes, g1 | `BLS12381Signature::from_bytes`; re-encoding; `G1Element::from_byte_array` (48-byte inputs) |
| `pk_decode` | in, decode, valid, bytes | `BLS12381PublicKey::from_bytes`, `validate()`, re-encoding |
| `aggregate` | sigs, out | `BLS12381AggregateSignature::aggregate` |
| `fast_aggregate_verify` | pks, msg, sig, ok | `BLS12381AggregateSignature::verify` |
| `aggregate_verify` | pks, msgs, sig, ok | `verify_different_msg` |

The edge cases include:
- infinity, non-subgroup and x = 0 points;
- every flag combination;
- coordinates at and above p;
- uncompressed (96/192-byte) encodings;
- the fastcrypto `test_sig_kat_min_sig` known answer.

The suite also runs the RFC 9380 vectors in `vectors/bls12381/upstream/`:
- hash_to_curve and encode_to_curve for G1 and G2, checking P, u, Q0 and Q1;
- expand_message_xmd for SHA-256, including the oversize-DST file.

The URLs and sha256 of these files are in `upstream/SOURCE`.

## `groupops`: suite `bls-group-ops`

These are the BLS12-381 arms of `sui-move-natives/src/crypto/group_ops.rs`. The tool replicates
each native's fastcrypto calls:
- the same `parse_trusted` / `parse_untrusted`;
- the same operand order (`b * a`, `b / a`);
- the same length checks and the same uncompressed-G1 paths.

Each line is `{"id","op","g","a","b","out"}`, where `out` is hex, or null where the native returns
its error. `g` is the native's group byte: 0 scalar, 1 G1, 2 G2, 3 GT, 4 uncompressed G1. Some ops
use other fields:
- `validate` has `ok` instead of `out`;
- `convert` adds `to`;
- `sum` has `terms` instead of `a`/`b`.

Inputs are the values Move code can hold: scalars below r, subgroup points, and GT values from
pairings. There are also rejects for `validate` and parse failures for each op. Gas, feature
flags and MSM/sum length limits are not covered; they stay with the natives lane.

## `bench`: Rust baselines for `zig build bench -Dsuite=bls-cert`

- `cert-verify`: every `real` case in the listed epoch files, through `bls_verdict`, which is
  the same path as above. The committee is already built. Unit: `cert`.
- `committee-prepare`: `Committee::new` over each listed epoch's keys and stakes, which decodes
  every key. Unit: `key`.

Both print one JSON line, `{"impl":"rust","bench","unit","units","iters","median_ns","min_ns","ns_per_unit"}`,
for the median of `--iters` passes after a warm-up. Both run single-threaded.
