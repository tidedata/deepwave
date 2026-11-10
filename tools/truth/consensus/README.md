# tools/truth/consensus

Ground truth for the validator lanes (docs/VALIDATOR-DESIGN.md section 9). Owner: val-consensus-core;
every validator lane reads the vectors. Test machine only, loopback only, generated keys only: nothing here
talks to a real validator.

- `capture.sh` (skeleton): builds Mysten's `sui` at mainnet-v1.83.1 in the shared Rust target dir,
  makes a 4-validator localnet (`sui genesis`, loopback, fresh keys), runs it under load for
  `$MINUTES`, stops it cleanly, then runs `zui-consensus-dump` over the validators' consensus and
  epoch databases.
- `dump/` (to write, Cargo workspace like the other truth tools, linking `consensus-core`
  (`storage::rocksdb_store::RocksDBStore` is public), `typed-store` and `sui-core`): writes
  `vectors/`:
  - `committee.json` (authority index, stake, protocol/network/authority keys, addresses)
  - `blocks.bin`: records `u32 len ++ serialized SignedBlock ++ 32-byte digest` for every stored block
    of every validator (the digest is recomputed by Rust and equals the store key)
  - `commits.bin`: `u32 len ++ serialized Commit ++ digest`, plus commit info and finalized commits
    with rejected transactions
  - `consensus_txs.bin`: every ConsensusTransaction in committed blocks with its ConsensusTransactionKey
  - `subdags.json`: the CommittedSubDag sequence (leader, block refs in order, timestamp, rejects)
  - `checkpoints/`: the localnet's checkpoints (summary, contents, signatures) from a full node
- `tbls/` (val-randomness-jwk): DKG transcripts, confirmations, outputs and partial signatures from
  fastcrypto-tbls with fixed seeds.

Run on a test machine (after the dump tool exists):

    MINUTES=20 tools/truth/consensus/capture.sh /tmp/zui-consensus-capture

## committer-vectors (written, runs on a test machine)

`committer-vectors/zui_consensus_vectors.rs` is a test module for Mysten's `consensus-core` crate at
mainnet-v1.83.1; `committer-vectors/run.sh` drops it into a scratch git worktree of the sui checkout,
registers it in `lib.rs` and runs it. It builds seeded DAGs with Mysten's own `DagBuilder` (full
connectivity, 2f+1 random links, missing leader blocks, missing leader links, a 650 round run with two
leader schedule updates), replays them layer by layer through the components `Core::try_commit` uses
and writes blocks (serialized bytes), commits (digest, leader, timestamp, sub-dag block order), the final
leader swap table and stake-based leader elections:

    SUI_SRC=$ZUI_SUI_SRC OUT=$ZUI_CORPUS/consensus/replay.vec \
        tools/truth/consensus/committer-vectors/run.sh

deepwave side: `./zig build conformance-consensus && ZUI_CORPUS=... zig-out/bin/deepwave-conformance-consensus
--suite val-consensus-core` (suites `consensus-block`, `consensus-replay`).
The tool was written without a Rust toolchain run on the author's machine: expect to fix compile
errors on the first run (API names were read from the 1.83.1 sources).
