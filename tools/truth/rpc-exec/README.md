# zui-truth-rpc-exec

Ground truth for the rpc-exec lane (sui.rpc.v2 `TransactionExecutionService.SimulateTransaction`),
computed by Mysten's code at mainnet-v1.83.1: the sui-rpc-api `RpcService` handler, with an
executor that calls `sui_core::transaction_simulation::simulate_transaction` (what
`AuthorityState::simulate_transaction` calls). The tool never re-implements what it checks.

```
source tools/env.sh
(cd tools/truth/rpc-exec && cargo build --release)       # shared target dir
T=$CARGO_TARGET_DIR/release/zui-truth-rpc-exec
$T gen $ZUI_CORPUS $ZUI_CORPUS/vectors/rpc-simulate [seq]   # every checkpoint at protocol >= 119
$T fetch-packages $ZUI_CORPUS https://archive.mainnet.sui.io:443 <ids file>  # into vectors/rpc-simulate-pkgs
$T bench simulate --iters N --list <file>                 # harness baseline (case 1, one thread)
```

`gen` writes `missing-packages.txt`: package ids execution asked for that neither `packages/` nor
`vectors/rpc-simulate-pkgs/` holds (original packages of upgraded ones: Rust's
`defining_ids_in_types` check resolves type defining ids against them and answers
InvariantViolation without them). `fetch-packages` gets them plus their linkage closure.
`ZUI_TRUTH_DEBUG=1` prints the execution error (with its source) behind every failed status.

## Records (`vectors/rpc-simulate/<seq>.rec.zst`)

zstd of repeated transaction blocks, little endian:

```
[tx index u32][epoch u64][pv u64][rgp u64][epoch start ms u64][committee size u32]
[n u32]{[len u32][BCS Object]}*n
[cases u8]{[case u8][req len u32][SimulateTransactionRequest]
           [code u8][msg len u32][message][details len u32][grpc-status-details-bin]
           [resp len u32][SimulateTransactionResponse][flags u8]}
```

- Objects are the pre-state the transaction saw: owned and immutable inputs, shared inputs at
  their assigned versions, receiving objects, every changed object's input version, the archive's
  `unchanged_loaded_runtime_objects`, and the system state (0x5 and its inner field) of the epoch
  start. Packages come from the corpus `packages/` and system-package writes.
- Flags: bit 0 Rust's simulated effects equal the certified effects (case 1); bit 1 the archive
  proto was available; bit 2 a pre-state key was missing from the archive object set.
- Cases (also `cases.txt`, masks in `masks.txt`): 1 BCS, checks enabled, `MASK_FULL` (every
  response field but `json`, `display`, `command_outputs`); 2 read_mask `transaction.effects`;
  3 gas payment emptied (mock gas coin); 4 checks disabled; 10 gas price rgp - 1; 11 budget
  `max_tx_gas` + 1; 12 gas coin version + 1; 13 gas coin digest flipped; 14 budget 1;
  15 truncated BCS; 16 invalid read_mask path; 17 no transaction (15-17 on the first user
  transaction of each checkpoint); 18 a system transaction.
- Gas selection (lane simulate-full): 5 gas payment emptied + `do_gas_selection`; 6 the same with
  budget `max_tx_gas` (the insufficient-balance quote); 7 the transaction as an unresolved proto
  (no `bcs`, no `gas_payment`) + `do_gas_selection` (budget estimation, then selection). The owner
  index is `Pre`'s `RpcIndexes`: the `object_by_owner` rows of the pre-state objects
  (AddressOwner and ConsensusAddressOwner, key order), so selection picks among the coins the
  transaction touched; the checkpoint's summary is the latest checkpoint. Answers that carry a
  server-made expiration (address-balance gas, gasless: random nonce) are not recorded
  (`dropped_nonce` in gen's summary).
- Command outputs: 19 MASK_FULL + `command_outputs`, checks on; 20 the same, checks off. Their
  `json` comes from the executor's layout resolver over the pre-state packages (sui-core
  `RestReadStore`); every other recorded mask still excludes `json`.

## Corpus v1 run (2026-11-07, PST)

14,646 checkpoints, 215,642 user transactions. With the 11 fetched packages (16:40), Rust's
simulated effects equal the certified effects for 212,884 (flag bit 0; the suite compares deepwave with
Rust's simulation either way), 0 package ids missing, 331 s on 8 threads. No S3 spend.
