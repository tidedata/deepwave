# tools/truth/checkpoints

Ground truth for val-checkpoints.

What already proves the builder, with no new Rust code: the corpus. Every `chk/<seq>.chk` is a
checkpoint Mysten's validators built and signed, with every transaction's effects, so the suite
`checkpoint-build` (src/validator/checkpoints/replay.zig) rebuilds each one from its effects, user
signatures and the previous summary and compares contents bytes, summary bytes (rolling gas, network
total, artifacts digest, version-specific data, end-of-epoch data) and the causal order.

`vectors/` (run.sh + zui_ckpt_vectors.rs): wire vectors from sui-types at mainnet-v1.83.1 with
fixed inputs and four generated BLS keys: CheckpointContents V1/V2, a protocol 141 summary and an
end-of-epoch summary (BCS and digests), each key's signature, SignedCheckpointSummary and
CheckpointSignatureV2 ConsensusTransaction (tracking id included), the strong quorum certificate
of 3 and of 4 signers, the CertifiedCheckpointSummary and roaring-rs bitmaps. The output is pasted
into src/validator/checkpoints/rust_vectors.zig, whose tests rebuild every vector with deepwave's code.

What needs a Rust run and is not written yet (loopback, generated keys only):

- `commit-build`: the localnet capture of tools/truth/consensus (`checkpoints/` next to the consensus
  dump) gives, per validator, the PendingCheckpoints it wrote (`pending_checkpoints` table of the
  epoch store: roots, details), the executed effects and the checkpoints it built. Replaying
  `queue.Queue` + `Builder` over the recorded commits must reproduce each pending checkpoint and each
  built checkpoint; the dump writes `pending.jsonl` (height, roots as digests, details) and the
  matching `checkpoints/<seq>.chk`.
- `aggregate`: the signatures sequenced in consensus (`ConsensusTransactionKind::CheckpointSignatureV2`
  from `consensus_txs.bin`) in commit order must certify each checkpoint at the same commit as the Rust
  aggregator, with an identical certificate (the signer bitmap and the aggregate signature depend only
  on the set of signers; Rust takes every signature received up to the one that reaches quorum, so the
  set can differ: compare the verified certificate, not the bytes, unless the same arrival order is
  replayed one by one, which the dump supports through the commit order).
- `artifacts`: fastcrypto `MerkleTree<Blake2b256>` roots for random object-state lists (a 30-line
  program over fastcrypto da61cd46) to pin `artifacts.merkleRoot` beyond the corpus epochs that carry
  the artifacts digest.
