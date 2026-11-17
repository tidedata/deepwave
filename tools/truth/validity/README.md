# tools/truth/validity

Golden accept/reject vectors for the validator's signing-time checks (lane validity, docs/PARITY.md
G15-G21), computed by Mysten's own code at mainnet-v1.83.1. The tool never re-implements what it
checks: each suite calls the Mysten function (or the same sequence of Mysten functions sui-core
calls) and records Rust's verdict, with the exact `Display` text of the error.

```
source tools/env.sh
(cd tools/truth/validity && cargo build --release)           # shared target dir
$CARGO_TARGET_DIR/release/zui-truth-validity <suite> <out.txt.zst>
```

On another machine, run the same commands there and copy tools/truth/validity/out back.
The vector files are committed next to the Zig tests that embed them.

| suite | Mysten code | Zig test |
|---|---|---|
| `validity` | sui-types `SenderSignedData::validity_check` (signature-scheme flags, system kinds, size limits, `TransactionDataV1::validity_check`, `ProgrammableTransaction::validity_check`, `validate_gasless_transaction`) | src/validator/authority/validity_vectors_test.zig |
| `denycfg` | sui-core `evaluate_deny_configs` and `TransactionDenyConfigManager` (apply_updates, update_for_committee, restart over the same perpetual tables), sui-config `PeerDenySyncConfig::validate`, `check_transaction_for_signing` under the effective config | src/validator/authority/deny_vectors_test.zig |

File format (common.rs): zstd of tab-separated lines, `#` comments; the last field is `ok [value]` or
`err <Display>` with `\\`, `\t`, `\n` escaped.
