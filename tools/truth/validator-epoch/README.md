# zui-valepoch-truth

Truth tool of the val-epoch-api-keys lane. Links Mysten's `sui-types` and `sui-protocol-config` at
mainnet-v1.83.1 and writes into `$ZUI_CORPUS/vectors/validator-epoch/`:

- `protocol-digests.txt`: `<unknown|mainnet|testnet> <version> <hex>` for versions 1..=141, the
  `SupportedProtocolVersionsWithHashes::from_supported_versions` digest (Blake2b256 of the BCS of
  `ProtocolConfig`). deepwave's `epoch.capabilities.DigestTable` loads it, so a deepwave validator's
  CapabilityNotificationV2 matches Mysten's byte for byte.
- `sys-tx.jsonl`: `{"name","sender_signed_data","digest"}` for the end-of-epoch system transactions
  of `VerifiedTransaction::new_end_of_epoch_transaction` / `new_change_epoch` (cases listed in
  `src/main.rs`, rebuilt by name in `src/validator/epoch/vectors.zig`).
- `consensus-tx.jsonl`: `{"name","bcs"}` ConsensusTransactions the epoch lifecycle sends
  (EndOfPublish, CapabilityNotificationV2 with the digests above).
- `grpc-req.jsonl`: `{"name","bcs"}` Validator API request bodies (ObjectInfo latest and past,
  TransactionInfo, Checkpoint, CheckpointV2) and the prost `RawValidatorHealthResponse`.

Compare:

    tools/truth/validator-epoch/run.sh
    ./zig build validator && ./zig-out/bin/deepwave-validator vectors-check "$ZUI_CORPUS/vectors/validator-epoch"

Pass: every line `ok`, exit 0.

Written without a Rust toolchain on the authoring machine (the Mac has none); the first run
may need small compile fixes against the 1.83.1 API (the constructors used are the ones the
Rust code itself calls: see the sources named in `src/main.rs`).
