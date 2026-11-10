# zui-truth-randomness

Ground truth for the validator randomness and JWK lane,
computed with Mysten's code at mainnet-v1.83.1 (sui 6a567faf, fastcrypto da61cd46).

`src/main.rs` is built as an example of the `sui-types` crate inside a scratch git worktree of the
sui checkout, so it compiles against Mysten's own Cargo.lock (a standalone crate would re-resolve
every dependency). `run.sh` does the worktree, the build and both commands:

    OUT_DIR=$ZUI_CORPUS/vectors tools/truth/randomness/run.sh

It writes `$OUT_DIR/dkg/fastcrypto.jsonl` and `$OUT_DIR/jwk/fastcrypto.jsonl`, which the validator
conformance runner reads from `$ZUI_CORPUS/vectors/{dkg,jwk}/fastcrypto.jsonl`:

    ./zig build validator-conformance-runner
    ZUI_CORPUS=... zig-out/bin/deepwave-conformance-validator --suite dkg-vectors
    ZUI_CORPUS=... zig-out/bin/deepwave-conformance-validator --suite jwk-vectors

(On macOS the build needs `SDKROOT` from `tools/env.sh`; the default 27.0 SDK fails to link.)
The output is deterministic (seeded StdRng), so regenerating gives the same files.

JSON lines, one object per line, `op` selects the record, `id` the case:

dkg (committee order and party ids exactly as `RandomnessManager::try_new`: a real `Committee`,
ids are authority indexes, `Nodes::new_reduced(nodes, validity_threshold, delta, lower_bound)`):
`committee` (sks, names = G2 public keys, stakes, reduction params, t after reduction, reduced
weights, total weight), `message` / `confirmation` (BCS of VersionedDkgMessage /
VersionedDkgConfirmation and `ctx`, the BCS ConsensusTransaction the party submits; zero weight
parties send no message but do confirm), `output` (VSS polynomial and each party's shares),
`round` (signature message, per party BCS partial signatures, full signature BCS) and `rsu`
(RandomnessStateUpdate TransactionData BCS and digest) for rounds 0, 1, 41 and 2^40.

jwk: `parse` (provider, Display name, iss, endpoint, document, `parse_jwks(.., true)` result),
`from_str` (a name `OIDCProvider::from_str` rejects), `from_iss`, `asu` (ActiveJwk order and the
AuthenticatorStateUpdate TransactionData and digest), `ctx_jwk` (BCS ConsensusTransaction).
