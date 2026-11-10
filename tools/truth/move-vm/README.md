# zui-truth-move-vm

Ground truth for the move-vm lane's suites, `move-vm-gas`, `move-vm-trace` and `move-vm-load`. It runs Mysten's
mainnet-v1.83.1 `move-vm-runtime` (the `latest` execution, built by
`sui_adapter_latest::adapter::new_move_runtime` with Sui natives and VM config), metered by
`SuiGasMeter` over `GasStatus` and traced by `move-trace-format`.

```
source tools/env.sh
cargo build --release --manifest-path tools/truth/move-vm/Cargo.toml
$CARGO_TARGET_DIR/release/zui-truth-move-vm build $ZUI_CORPUS $ZUI_CORPUS/vectors
$CARGO_TARGET_DIR/release/zui-truth-move-vm run $ZUI_CORPUS/vectors <id>        # one call: truth + trace
$CARGO_TARGET_DIR/release/zui-truth-move-vm bench call|instr --iters N --list <file>
$CARGO_TARGET_DIR/release/zui-truth-move-vm cut v0|v1|v2|v3 <pv> $ZUI_CORPUS/vectors  # older execution cut
```

`build` needs `ZUI_SUI_SRC` (the 1.83.1 tree), which is used for the framework snapshot 140.

## Inputs

- Package objects found in `$ZUI_CORPUS/chk/*.chk`. System packages are skipped: the snapshot is
  used for them instead.
- Framework snapshot 140: 0x1, 0x2, 0x3, 0xb and 0xdee9.
- The synthetic packages in `synth/out/`, built from `synth/` by `synth/build.sh`, which needs
  the `sui` CLI. They are published with `MovePackage::new_initial` and `new_upgraded` at
  protocol 141:
  - `zvm` at 0x5a7e..01.
  - `zvm2`, an upgrade of `zvm` stored at 0x5a7e..02, which adds `up`.
  - `zdep` at 0x5a7e..03, linked to zvm2.

  Every jump table of `zvm::mis` is rotated by one after compiling, so its variant unpacks meet
  the wrong tag.

## vectors/move-vm-gas/packages.bin

Little-endian.

- Header: `"ZUIMVPK1"`, then `u32 count`.
- Then, per package:
  - `version_id[32] original_id[32] u64 version`
  - `u32 n` x (`original[32] version_id[32]`): the linkage table, the package itself included.
  - `u32 n` x (`u32 len module, u32 len name, defining_id[32]`): the type origins.
  - `u32 n` x (`u32 len name, u32 len bytes`): the modules.

## vectors/move-vm-gas/calls.jsonl

One call per line. The truth comes from one `execute_function_bypass_visibility` at gas price 1.

```
{"id", "pv", "gm", "root": <version id hex>, "module": "<original id hex>::<name>", "fn", "fdef",
 "tys": [<display>], "tys_bcs": [<TypeTag BCS hex, defining ids>],
 "args": [["val"|"ref"|"mut", <BCS hex>]], "arg_tys": [<TypeTag hex>], "ret_tys": [<TypeTag hex>],
 "ret_kinds": ["val"|"ref"|"mut"], "budget": <gas units>,
 "truth": {"gas_left": <internal units>, "used": <gas units>, "ins", "hwm_h", "hwm_s", "cur_h", "cur_s",
           "natives", "st": "ok"|"err", "ret": [<hex>], "mut": [[<arg index>, <hex>]],
           "err": {"major", "sub", "loc": "module:<original id>::<name>"|"undefined", "off": [[fdef, pc]]},
           "rt": {"ok": {"writes": [[id, owner bcs, struct tag bcs, value bcs]], "events": [[struct tag bcs, value bcs]],
                         "acc": [[accumulator id, action, address, type bcs, kind, n]], "loaded": [[id, version, modified]],
                         "created": [id], "deleted": [id], "settle": [input sui, output sui]}}
                 | {"err": "<ExecutionErrorKind>"}}}
```

`ret_tys` holds the referent's tag for a returned reference, and `ret` its bytes (read through the
reference after the call). `rt` is `ObjectRuntime::finish` after the call, whatever its status, in
the sui-natives truth tool's format (all hex).

Draws:
- Corpus functions get 3 draws at protocol 141 and one at 119, 123, 124 or 137.
- Synthetic functions get 15 draws spread over all five versions.
- Each successful call is repeated with budgets of used/2 units, its whole used units, and 0 for every tenth call.
- Identical calls are kept once.

## vectors/move-vm-trace

`calls.jsonl` has the same lines, restricted to the traced calls. `trace/<id>.json.zst` is that
call's `MoveTrace` in its compressed JSON form. A call is traced only if it runs at most 20,000
instructions.

## vectors/move-vm-load

`packages.bin` (same format as above) holds every package the build saw, closed linkage or not.
`items.jsonl` has one line per package: `{"root": hex, "pv": 141, "src": "corpus"|"framework"|"synth",
"truth": {"st": "ok"} | {"st": "err", "err": {"major", "sub", "loc", "off"}}}`, where the truth is
`make_vm` over the root's linkage table with every package in the store (`loc` is `undefined`,
`package:<hex>` or `module:<hex>::<name>`; `off` is `[[fdef, offset], ...]`). Set `ZUI_TRUTH_DEBUG=1`
to print the original error under `expect_no_verification_errors`.

Calls (gas and trace) run with sui-adapter's `new_native_extensions` and the sui-natives DEFAULT_CTX
transaction context. The natives deepwave implements are parsed from `src/natives/table.zig` when the tool
is built (`include_str!`, so the list cannot go stale) and written to `vectors/move-vm-gas/natives.txt`
(sorted `addr::module::func` lines); functions reaching any other native are skipped. The deepwave suites
refuse vectors whose `natives.txt` differs from the table they run.

## bench

`bench call|instr` times every protocol-141 call that has the default budget, on one thread;
`call-interp`/`instr-interp` keep the calls whose truth has `natives == 0`, `call-native`/`instr-native`
the others. It
reports the median of N passes per call or per executed instruction, as CONTRACTS.md section 7
describes.

## cut: older execution cuts

`cut <vN> <pv> <vectors>` (src/cut.rs) re-runs the move-vm-gas calls that have protocol 141 and the
default budget (each distinct call once) on one of Mysten's older cuts: `move-vm-runtime-vN` and
`move-vm-types-vN` with `sui-adapter-vN` and `sui-move-natives-vN`, all four linked into this binary.
The VM is the cut's `new_move_vm` (with that cut's `all_natives`), one per call, run through a session
whose resolver relocates by the root's linkage table; gas is the cut's `SuiGasMeter` over
`GasStatus` with `cost_table_for_version(gas_model_version)` at protocol `pv`, mainnet. Used so far:
v0 at 17, v1 at 30, v2 at 37, v3 at 103. Needs `ZUI_SUI_SRC`.

The system packages 0x1, 0x2, 0x3, 0xb and 0xdee9 are replaced by the framework snapshot with the
largest number at or below `pv`; a system package that snapshot lacks (0xb before 103) is absent.

- `move-vm-gas/cuts/<vN>/packages.bin`: only those snapshot packages (ZUIMVPK1). Overlay them on
  `move-vm-gas/packages.bin` by version id, after removing every system package from it.
- `move-vm-gas/cuts/<vN>/calls.jsonl`: the same line format, with the source call's `id`, `pv` and
  `gm` of the cut, `fdef` in the old module, and a `TxContext` argument replaced by the bytes the
  adapter passes (`to_bcs_legacy_context` of the DEFAULT_CTX).
- `move-vm-trace/cuts/v3/{calls.jsonl,trace/<id>.json.zst}`: as the latest trace suite, for the
  calls in that suite that run at most 20,000 instructions. Only v3 has a move-trace-format tracer,
  so v0..v2 have no trace vectors. A call whose v3 trace fails (tracer assertion, a recorded
  "TRACING ERROR", or a crash; traces run in a `cut-trace` child process) keeps only its gas vector.

A call the cut cannot reach is dropped and counted by reason: its package or module is absent from
the old framework, the function is missing or reaches a native deepwave lacks, `load_type` or
`load_function` fails (binary format version, linking, verification), its signature or an argument
layout changed, or a native panics on it. Execution errors stay as `err` truth.

`rt` differences: `acc` is `[]` and `settle` is `[0, 0]` before v3. v0's `ObjectRuntime::finish`
reports write kinds instead of id sets: `created` holds the writes of kind Create, `deleted` the
deletions, and `loaded` children have `modified` false (v0 does not record it).
