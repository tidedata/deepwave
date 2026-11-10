# tools/truth/authority

Ground truth for val-authority: what Mysten's validator at
mainnet-v1.83.1 decides for a recorded sequence of consensus commits. Test machine only, loopback only,
generated keys only; nothing here talks to a real validator.

Plan: reuse `tools/truth/consensus/capture.sh` (4-validator localnet under load, stopped cleanly),
then read the stopped validators' per-epoch databases with `dump/`:

| table (AuthorityEpochTables) | what it proves for deepwave |
|---|---|
| `owned_object_locked_transactions` | the lock holder of every ObjectRef (first in consensus order wins) |
| `consensus_message_processed` | the processed key set (dedup, dropped transactions included) |
| `shared_object_next_versions_v2`, `assigned_shared_object_versions_v3` | version assignment per transaction, cancelled sentinels, system object versions |
| `deferred_transactions_v2`, `deferred_transactions_with_aliases_v2` | deferral keys and their members |
| `congestion_control_object_debts`, `congestion_control_randomness_object_debts` | debts per object and round |
| `last_consensus_stats_v2` | ExecutionIndices per commit |
| `pending_checkpoints_v2` | roots per pending checkpoint (the split) |
| `execution_time_observations` | the estimator input |

and, from consensus's store, the committed sub-dags with rejects (shared with val-consensus-core:
`vectors/subdags.json`, `vectors/consensus_txs.bin`). The prologue bytes come from the checkpoints
(`checkpoints/`) of the full node.

Output (`vectors/authority/`): one line-oriented JSON file per table (`<table>.jsonl`, each line
`{"key": ..., "value": ...}` in Rust Debug-free BCS hex), and `commits.jsonl` joining every commit
index with the keys it processed. The Zig replay (`deepwave-validator-authority-replay`, to write after
the handler is wired to the localnet harness) feeds `subdags.json` through `authority.Handler` and
compares every table above line by line.

Run on a test machine after the dump source compiles (it is written against sui-core's public
`AuthorityEpochTables::open_readonly`; the first run will need small fixes):

    MINUTES=20 tools/truth/authority/capture.sh /tmp/zui-authority-capture
