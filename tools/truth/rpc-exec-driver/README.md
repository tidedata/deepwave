# zui-truth-rpc-exec-driver

Ground truth for deepwave's ExecuteTransaction (`src/rpc_exec/driver`, CONTRACTS 6.7), made only by
running Mysten's code at mainnet-v1.83.1 (`../../sui`). Nothing here talks to a network; no
validator is ever contacted.

```
source tools/env.sh
cd tools/truth/rpc-exec-driver && cargo build --release -j 6
$CARGO_TARGET_DIR/release/zui-truth-rpc-exec-driver gen $ZUI_CORPUS $ZUI_CORPUS/vectors/rpc-execute
$CARGO_TARGET_DIR/release/zui-truth-rpc-exec-driver errors $ZUI_CORPUS/vectors/rpc-execute
$CARGO_TARGET_DIR/release/zui-truth-rpc-exec-driver zcat <file.zst> > out.bin   # inspection helper
```

Produced 2026-11-07 (PST): 48 checkpoints, 783 user transactions (a checkpoint without user
transactions gives an empty record file), 5,967 handler cases (codes: 0 x4745, 3 x611, 8 x47,
9 x94, 10 x94, 13 x94, 14 x282); 191 SuiError records (66 UserInputError variants, 114 of the
115 SuiErrorKind variants: `SuiObjectResponseError` does not survive a BCS round trip, its serde
is internally tagged), 24 status records, 25 driver error records.

Conventions: integers are little endian. `str` and `blob` are `[len u32][bytes]` (`str` is UTF-8).
`objects` is `[n u32]{blob BCS Object}*n`. Category `u8` is the `ErrorCategory` order: Aborted 0,
InvalidTransaction 1, LockConflict 2, Internal 3, ValidatorOverloaded 4, Unavailable 5. gRPC codes
are tonic's numbers (0 OK, 3 INVALID_ARGUMENT, 9 FAILED_PRECONDITION, 10 ABORTED, 13 INTERNAL, ...).

## `gen <corpus> <out>`

Checkpoints: every `manifest.jsonl` checkpoint whose epoch is at protocol 119 or later (the rule
of tools/truth/rpc-exec), then 48 evenly spaced ones (`seqs[i * len / 48]`), listed in
`seqs.txt`. System transactions (`kind().is_system_tx()`) are skipped; every other transaction of
the checkpoint is a record, in checkpoint order.

### `wire/<seq>.rec.zst`

zstd of records `[tx index u32][count u8]{blob}*count`, count = 21, blobs in this order:

| # | content |
|---|---|
| 0 | `bcs::to_bytes(&transaction)`: the signed `Transaction` envelope (the bytes a validator receives) |
| 1 | `RawSubmitTxRequest` prost of `SubmitTxRequest::new_transaction(tx).into_raw()` |
| 2 | `RawSubmitTxRequest` prost of `SubmitTxRequest::new_ping().into_raw()` |
| 3 | BCS `ConsensusPosition { epoch: checkpoint epoch, block: BlockRef { round: seq as u32, author: AuthorityIndex(tx index % 4), digest: BlockDigest(tx digest bytes) }, index: tx index as u16 }` |
| 4 | `RawSubmitTxResponse` prost, one result `Submitted(blob 3)` |
| 5 | BCS `TransactionEffects` |
| 6 | BCS `TransactionEvents`, empty blob when the transaction has none |
| 7 | `objects`: the CheckpointTransaction `input_objects` |
| 8 | `objects`: the CheckpointTransaction `output_objects` |
| 9 | `RawSubmitTxResponse`, one result `Executed { effects_digest, details: Some(ExecutedData { effects, events, input_objects (7), output_objects (8) }) }` |
| 10 | `RawSubmitTxResponse`, one result `Rejected { error: UserInputError::ObjectVersionUnavailableForConsumption { provided_obj_ref: first gas payment ref, current_version: its version + 1 } }` |
| 11 | `RawWaitForEffectsRequest` of `{ transaction_digest: Some(tx digest), consensus_position: Some(blob 3), include_details: true, ping_type: None }` |
| 12 | `RawWaitForEffectsRequest` of `{ Some(tx digest), None, false, None }` |
| 13 | `RawWaitForEffectsRequest` of `{ None, Some(blob 3), false, Some(PingType::Consensus) }` |
| 14 | `RawWaitForEffectsResponse` `Executed { effects_digest, details: None }` |
| 15 | `RawWaitForEffectsResponse` `Executed { effects_digest, details: Some(ExecutedData as 9) }` |
| 16 | `RawWaitForEffectsResponse` `Rejected { error: Some(ObjectLockConflict { obj_ref: first gas ref, pending_transaction: tx digest }) }` |
| 17 | `RawWaitForEffectsResponse` `Rejected { error: None }` |
| 18 | `RawWaitForEffectsResponse` `Expired { epoch, round: Some(seq as u32) }` |
| 19 | `RawWaitForEffectsResponse` `Expired { epoch, round: None }` |
| 20 | the 32-byte effects digest |

A transaction without gas payment uses `(ObjectID::ZERO, 0, ObjectDigest([0; 32]))` as its gas ref.
All conversions are sui-types' own (`into_raw`, `TryFrom<...> for Raw...`), prost-encoded with
`encode_to_vec`.

### `handler/<seq>.rec.zst`

zstd of records, one per user transaction:

```
[tx index u32] blob(BCS TransactionData) [n sigs u32]{blob raw GenericSignature}*n
blob(BCS effects) blob(BCS events, empty = None) objects(input) objects(output)
[cases u8] { [case u8] blob(ExecuteTransactionRequest prost) [code u8] str(message)
             blob(grpc-status-details-bin) blob(ExecuteTransactionResponse prost) }*cases
```

Code 0: message and details are empty and the response is present; otherwise the response is
empty. Every reply is what `TransactionExecutionService::execute_transaction` of a real
`sui_rpc_api::RpcService` returns (`RpcService::new(reader)` + `with_executor`), converted by tonic
(`Status::code/message/details`). The reader holds nothing: chain id mainnet, `indexes()` None,
`get_struct_layout_with_overlay` Ok(None) (so no event/object `json`), no objects (so no `display`
and no clever errors).

The executor returns `ExecuteTransactionResponseV3 { effects: FinalizedEffects { effects,
QuorumExecuted(executed_epoch) }, events, input_objects, output_objects, auxiliary_data: None }`,
filtered like the orchestrator: events only when `include_events`, input objects only when
`include_input_objects` and non-empty, output objects only when `include_output_objects` and
non-empty (else None). Cases 20 and up make it return the listed `TransactionSubmissionError`.

Request: `transaction = Transaction { bcs: Bcs { name: "TransactionData", value } }`, one
`UserSignature { bcs: Bcs { value: raw signature } }` per signature, `read_mask` per case.
Cases (`cases.txt`): 1 to 6 for every user transaction, 10 and up only for the first user
transaction of each checkpoint:

| case | request |
|---|---|
| 1 | no read_mask (default `effects`) |
| 2 | read_mask `*` |
| 3 | `digest,transaction,signatures,events,balance_changes` |
| 4 | `objects,effects.status,effects.gas_used,effects.changed_objects` |
| 5 | `transaction.bcs,effects.bcs,events.bcs,signatures.bcs` |
| 6 | read_mask present with zero paths |
| 10 | transaction bcs truncated by one byte |
| 11 | three signatures (corpus signatures repeated) |
| 12 | two signatures, the second `00 01 02` |
| 13 | read_mask `effects.nope` |
| 14 | no transaction field |
| 15 | transaction bcs plus one `00` byte |
| 16 | one signature `09` ++ 64 zero bytes |
| 17 | one empty signature |
| 18 | one signature `00` ++ 96 zero bytes (a well-formed ed25519 shape) |
| 19 | transaction message with neither bcs nor version |
| 20 | executor `TransactionFailed { InvalidTransaction, "d-invalid" }` |
| 21 | `TimeoutBeforeFinality` |
| 22 | `TimeoutBeforeFinalityWithErrors { "last", 3, 90s }` |
| 23-27 | `TransactionFailed` Aborted "d-aborted", LockConflict "d-lock", ValidatorOverloaded "d-overload", Unavailable "d-unavail", Internal "d-internal" |
| 28 | `InvalidUserSignature(UserInputError::IncorrectUserSignature { "bad sig" })` |
| 29 | `InvalidUserSignature(InvalidSignature { "nope" })` |
| 30 | `TxAlreadyFinalizedWithDifferentUserSignatures` |
| 31 | `SystemOverload { 5000, [] }` |
| 32 | `TransactionDriverInternalError(Unknown("boom"))` |
| 33 | `SystemOverloadRetryAfter { 3400, [], 7 }` |
| 34 | `FailedWithTransientErrorAfterMaximumAttempts { 5 }` |
| 35 | `ObjectsDoubleUsed` with one conflicting transaction and two authorities |
| 36 | `NonRecoverableTransactionError` (TimeoutError 2500, GasBudgetTooHigh 5000, InvalidSignature 2500) |

Cases 20 and up use the default mask.

## `errors <out>`

`committee.txt`: `<index>\t<hex AuthorityName>` of `Committee::new_simple_test_committee()`
(4 members, deterministic keys, sorted by name, 2500 stake each). These names appear in the
records below.

### `sui_errors.rec`

Records `blob(bcs::to_bytes(&SuiError)) str(Display) str(request error text) [category u8]
[retryable u8] [categorized u8]`: request error text is `format_transaction_request_error` of
`RejectedAtValidator(e)` (the UserInputError's Display for a `UserInputError`, else the SuiError
Display); category is `categorize()`, retryable/categorized are `is_retryable()`. Every
`SuiErrorKind` variant and every `UserInputError` variant (wrapped in `SuiErrorKind::UserInputError`),
some more than once with different payloads (every `Owner` but `Party` for the owner-carrying
ones, Option Some/None, empty and two-element vectors, a string with quotes, backslash, newline,
tab, U+0001 and non-ASCII for the Debug-printed fields). Only values that survive a BCS round trip
are written; `sui_errors.txt` names each record (`<index>\t<variant>`). The program prints the
skipped ones.

### `status.rec`

`SuiError::from(tonic::Status)` (what a validator RPC error becomes): records `[code u8]
str(message) blob(details) blob(BCS resulting SuiError) str(its Display) [category u8]`. Inputs:
message "Too many requests" with two codes; every code 0..=16 with message `m<code>` and no
details; INTERNAL with the BCS of three SuiErrors; UNAVAILABLE with garbage details `01 02 03`;
INTERNAL with a valid SuiError plus one trailing byte.

### `driver_errors.rec`

`sui_core::transaction_driver::TransactionDriverError` values built by hand. The record starts
with the value:

```
spec = [variant u8] payload
  0 ClientInternal          str(error)
  1 ValidationFailed        str(error)
  2 Aborted                 agg(non_retriable) agg(retriable) digs(observed)
  3 RejectedByValidators    agg(non_retriable) agg(retriable)
  4 ForkedExecution         digs(observed) agg(non_retriable) agg(retriable)
  5 TimeoutWithLastRetriableError [has_last u8]{spec} [attempts u32] [timeout_ns u64]
agg  = [n u32]{ str(error) [m u32]{96-byte AuthorityName}*m [stake u64] [category u8] }*n [total_stake u64]
digs = [n u32]{ 32-byte effects digest [m u32]{96-byte AuthorityName}*m [stake u64] }*n
```

then the outputs: `str(Display) [category u8] [submission_retriable u8] [grpc code u8]
str(grpc message) blob(grpc-status-details-bin)`. The gRPC reply is the full node's path:
`submit_with_transaction_driver` maps `TimeoutWithLastRetriableError` to
`TimeoutBeforeFinalityWithErrors { last_error: e.to_string() or "", attempts, timeout }` and every
other error to `TransactionFailed { category, details: to_string() }`, then
`sui_rpc_api::RpcError::from`, then `tonic::Status::from`.

`AggregatedEffectsDigests` lives in a private module of sui-core and has no `Default`, so the tool
makes one empty value by transmuting a one-field mirror struct (same single `Vec` field) and then
fills the public `digests` field; `AggregatedRequestErrors` comes from `Default` and its public
fields. The Display, categorize and conversions that are recorded are Mysten's own.
