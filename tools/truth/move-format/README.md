# zui-truth-move-format

Ground truth for the move-format lane. It links Mysten's crates at mainnet-v1.83.1
(move-binary-format, move-bytecode-verifier, move-bytecode-verifier-meter, sui-verifier-latest,
sui-protocol-config, sui-move-natives-latest) and records what they say. It never computes
truth with its own code.

Build with the shared target dir: `CARGO_TARGET_DIR=~/.cache/zui/target-swarm cargo build
--release` (after `source tools/env.sh`).

## Commands

- `zui-truth-move-format build <corpus> <vectors>` needs `ZUI_SUI_SRC` (the 1.83.1 tree). It
  collects every module from `chk/*.chk` (Publish and Upgrade commands, package objects), the
  framework bytecode snapshots and every `.mv` file in the tree. It dedups them by Blake2b256,
  adds deterministic mutants (`src/mutate.rs`: 8 byte-level and 24 structural per seed module),
  then shards everything into 128 packs.
  Mutants come in two rounds: the original one (salt 0, checked at protocol 141) and an
  extended one (salt 1: every opcode, enums and jump tables, stack-neutral borrow insertions,
  loop depth and definition limits, binary versions 1 to 5), whose mutants are also checked at
  their base module's protocol version. Modules in `regress/<pv>-<name>.mv` are added at `<pv>`
  and 141: inputs that once split deepwave from Rust.
- Differential fuzz into a scratch dir: `ZUI_MF_SALT=<n> ZUI_MF_SCALE=8 zui-truth-move-format
  build $ZUI_CORPUS <scratch>/vectors`, then `ZUI_CORPUS=<scratch> deepwave-conformance --suite
  move-binary` and `--suite move-verify`. A non-zero salt replaces both rounds with one extended
  round at that seed.
- `zui-truth-move-format trace <pv> <module.mv> [fdef]` prints the truth JSON for one module and
  every recording-meter call on stderr (plus the bytecode of function definition `fdef`), for
  diffing meter units against deepwave.
- `zui-truth-move-format bench <deserialize|serialize|verify> --iters N --list <file>` times
  Rust on the listed packs and prints one JSON line with `ns_per_unit` per module.

## Output

`vectors/move-binary/configs.jsonl`: one line per protocol version 1 to 141:
`{"pv", "binary": BinaryConfig, "verifier": VerifierConfig}`. The field names match
`move_binary_format::binary_config::BinaryConfig` (`table` is the 18 table-size limits in
`TableConfig` order) and `move_vm_config::verifier::VerifierConfig`. Optional limits are
`null`.

`vectors/move-binary/packs/pack-NNN.mvp`: modules back to back, each as a u32 LE length
followed by the module bytes.

`vectors/move-binary/truth/pack-NNN.jsonl`: line i describes module i of the pack.
`{"h": blake2b256 hex, "seq": first checkpoint or null, "src": [...], "items": [{"pv", "de"}]}`.
There is one item at the protocol version in force where the module first appeared (141 for
snapshot extras, tree modules and mutants) and, if that differs, one more at 141. `de` is one
of:
- `{"err": VMError}`, from `CompiledModule::deserialize_with_config`.
- `{"ok": {"ser": "same" | {"hex"} | {"err": text}, "shape": [...]}}`. `ser` is the result of
  `serialize_with_version(m.version)`. `shape` holds version, publishable, the self handle
  index, every table length in `CompiledModule` field order, then the total instruction count.

`VMError` is `{"major": status code, "sub": sub status or null, "loc": "undefined" |
"module:<name>", "idx": [[IndexKind, n], ...], "off": [[function def index, code offset], ...]}`.

`vectors/move-verify/truth/pack-NNN.jsonl` has the same lines and order as move-binary.
`items` lists `{"pv", "move", "sui", "units"}` for the same protocol versions, but only where
the module deserializes. Each item runs the publish path:
`verify_module_with_config_metered`, then `verify_module_function_signature_by_name`, then the
native check, then `sui_verify_module_metered` with the same recording meter.
- `move`: `"ok"` or `{"err": VMError}`.
- `sui`: `"ok"`, `{"err": {"kind": ExecutionErrorKind name, "msg": text or null}}`, or null
  when `move` failed.
- `units`: meter totals `{"mod", "fun_total", "fun_max", "adds"}` that the recording meter
  saw (module scope units, all function scope units, the largest single function, and the
  number of `add` calls).

`vectors/move-verify/natives/<pv>.txt`: the native function table for that protocol version.
One `addr64::module::function` per line.
