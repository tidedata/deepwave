//! zui-truth-move-format: ground truth for the move-format lane (CONTRACTS.md section 3.3).
//!
//! It runs Mysten's own Rust at mainnet-v1.83.1 (move-binary-format, move-bytecode-verifier,
//! sui-verifier-latest, sui-protocol-config, sui-move-natives-latest) over every Move module found
//! in the corpus and writes what it says. It never computes truth with its own reimplementation.
//!
//!   build <corpus_dir> <vectors_dir>     extract modules from every chk/*.chk, write
//!                                        <vectors_dir>/move-binary/{configs.jsonl,packs/,truth/}
//!                                        and <vectors_dir>/move-verify/{truth/,natives/}
//!   bench <name> --iters N --list <file> time Rust on the listed packs (deserialize|serialize|verify)
//!
//! Output formats: README.md next to this file.
use anyhow::{Context, Result, anyhow, bail};
use fastcrypto::hash::{Blake2b256, HashFunction};
use move_binary_format::CompiledModule;
use move_binary_format::errors::{Location, PartialVMError, VMError};
use move_bytecode_verifier_meter::{Meter, Scope};
use move_core_types::vm_status::StatusCode;
use move_vm_config::verifier::VerifierConfig;
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::transaction::{Command, TransactionDataAPI, TransactionKind};

#[cfg(not(feature = "sui_184"))]
const MAX_PV: u64 = 141;
#[cfg(feature = "sui_184")]
const MAX_PV: u64 = 142;
const PACKS: usize = 128;
const MUTANTS_BYTE: usize = 8;
const MUTANTS_STRUCT: usize = 24;

mod mutate;

/// `trace` command: print every meter call of the recording meter to stderr.
static TRACE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("build") => cmd_build(&args[2..]),
        Some("bench") => cmd_bench(&args[2..]),
        Some("trace") => {
            // trace <pv> <module.mv>: truth for one module, every meter call on stderr
            let pv: u64 = args[2].parse()?;
            let bytes = std::fs::read(&args[3])?;
            let env = env_for(pv)?;
            let (de, cm) = deserialize_truth(&bytes, &env);
            TRACE.store(true, std::sync::atomic::Ordering::Relaxed);
            if let (Some(f), Some(cm)) = (args.get(4), cm.as_ref()) {
                let f: usize = f.parse()?;
                let d = &cm.function_defs[f];
                let h = cm.function_handle_at(d.function);
                eprintln!("params {:?}\nreturn {:?}", cm.signature_at(h.parameters), cm.signature_at(h.return_));
                if let Some(code) = &d.code {
                    eprintln!("locals {:?}", cm.signature_at(code.locals));
                    for (i, b) in code.code.iter().enumerate() {
                        eprintln!("{i}: {b:?}");
                    }
                }
            }
            let v = cm.as_ref().map(|cm| verify_truth(cm, &env));
            println!("{}", serde_json::json!({"de": de, "verify": v}));
            Ok(())
        }
        _ => bail!("usage: zui-truth-move-format build <corpus> <vectors> | bench <name> --iters N --list <file>"),
    }
}

// ---------------------------------------------------------------------------------------------
// Extraction

#[derive(Clone)]
struct Found {
    bytes: Vec<u8>,
    pv: u64,
    src: &'static str,
    seq: u64,
}

fn load_epochs(corpus: &Path) -> Result<HashMap<u64, u64>> {
    let text = std::fs::read_to_string(corpus.join("epochs.jsonl"))?;
    let mut m = HashMap::new();
    for line in text.lines() {
        let v: serde_json::Value = serde_json::from_str(line)?;
        m.insert(
            v["epoch"].as_u64().ok_or_else(|| anyhow!("epoch"))?,
            v["pv"].as_u64().ok_or_else(|| anyhow!("pv"))?,
        );
    }
    Ok(m)
}

fn extract(path: &Path, epochs: &HashMap<u64, u64>) -> Result<Vec<Found>> {
    let raw = std::fs::read(path)?;
    if raw.first() != Some(&1) {
        bail!("{}: not a BCS blob", path.display());
    }
    let cp: CheckpointData =
        bcs::from_bytes(&raw[1..]).with_context(|| format!("decode {}", path.display()))?;
    let epoch = cp.checkpoint_summary.epoch;
    let seq = cp.checkpoint_summary.sequence_number;
    let pv = *epochs
        .get(&epoch)
        .ok_or_else(|| anyhow!("epoch {epoch} not in epochs.jsonl"))?;
    let mut out = vec![];
    for tx in &cp.transactions {
        if let TransactionKind::ProgrammableTransaction(pt) =
            tx.transaction.data().transaction_data().kind()
        {
            for c in &pt.commands {
                let (mods, src) = match c {
                    Command::Publish(m, _) => (m, "publish"),
                    Command::Upgrade(m, _, _, _) => (m, "upgrade"),
                    _ => continue,
                };
                for b in mods {
                    out.push(Found { bytes: b.clone(), pv, src, seq });
                }
            }
        }
        for obj in tx.input_objects.iter().chain(tx.output_objects.iter()) {
            if let Some(pkg) = obj.data.try_as_package() {
                for b in pkg.serialized_module_map().values() {
                    out.push(Found { bytes: b.clone(), pv, src: "package", seq });
                }
            }
        }
    }
    Ok(out)
}

fn blake(b: &[u8]) -> [u8; 32] {
    let mut h = Blake2b256::default();
    h.update(b);
    h.finalize().digest
}

// ---------------------------------------------------------------------------------------------
// Recording meter: unbounded, mirrors BoundMeter's scope arithmetic (f32 transfer) exactly and
// records what a bounded meter would have seen.

#[derive(Default)]
struct RecMeter {
    pkg: u128,
    module: u128,
    fun: u128,
    fun_total: u128,
    fun_max: u128,
    adds: u64,
}

impl Meter for RecMeter {
    fn enter_scope(&mut self, _name: &str, scope: Scope) {
        if TRACE.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!("enter {:?}", scope);
        }
        match scope {
            Scope::Package => self.pkg = 0,
            Scope::Module => self.module = 0,
            Scope::Function => self.fun = 0,
            Scope::Transaction => {}
        }
    }
    fn transfer(&mut self, from: Scope, to: Scope, factor: f32) -> move_binary_format::errors::PartialVMResult<()> {
        let units = match from {
            Scope::Package => self.pkg,
            Scope::Module => self.module,
            Scope::Function => self.fun,
            Scope::Transaction => 0,
        };
        let units = (units as f32 * factor) as u128;
        self.add(to, units)
    }
    fn add(&mut self, scope: Scope, units: u128) -> move_binary_format::errors::PartialVMResult<()> {
        self.adds += 1;
        if TRACE.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!("add {:?} {} fun={}", scope, units, self.fun);
        }
        match scope {
            Scope::Package => self.pkg = self.pkg.saturating_add(units),
            Scope::Module => self.module = self.module.saturating_add(units),
            Scope::Function => {
                self.fun = self.fun.saturating_add(units);
                self.fun_total = self.fun_total.saturating_add(units);
                self.fun_max = self.fun_max.max(self.fun);
            }
            Scope::Transaction => {}
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// JSON helpers

fn status_json(s: StatusCode) -> serde_json::Value {
    serde_json::json!(s as u64)
}

fn location_json(l: &Location) -> serde_json::Value {
    match l {
        Location::Undefined => serde_json::json!("undefined"),
        Location::Module(id) => serde_json::json!(format!("module:{}", id.name())),
        Location::Package(a) => serde_json::json!(format!("package:{}", a.to_hex())),
    }
}

fn vm_error_json(e: &VMError) -> serde_json::Value {
    serde_json::json!({
        "major": status_json(e.major_status()),
        "sub": e.sub_status(),
        "loc": location_json(e.location()),
        "idx": e.indices().iter().map(|(k, i)| serde_json::json!([format!("{k:?}"), i])).collect::<Vec<_>>(),
        "off": e.offsets().iter().map(|(f, o)| serde_json::json!([f.0, o])).collect::<Vec<_>>(),
    })
}

fn partial_error_json(e: PartialVMError) -> serde_json::Value {
    vm_error_json(&e.finish(Location::Undefined))
}

fn shape(m: &CompiledModule) -> serde_json::Value {
    serde_json::json!([
        m.version,
        m.publishable as u8,
        m.self_module_handle_idx.0,
        m.module_handles.len(),
        m.datatype_handles.len(),
        m.function_handles.len(),
        m.field_handles.len(),
        m.friend_decls.len(),
        m.struct_def_instantiations.len(),
        m.function_instantiations.len(),
        m.field_instantiations.len(),
        m.signatures.len(),
        m.identifiers.len(),
        m.address_identifiers.len(),
        m.constant_pool.len(),
        m.metadata.len(),
        m.struct_defs.len(),
        m.function_defs.len(),
        m.enum_defs.len(),
        m.enum_def_instantiations.len(),
        m.variant_handles.len(),
        m.variant_instantiation_handles.len(),
        m.function_defs.iter().map(|f| f.code.as_ref().map(|c| c.code.len()).unwrap_or(0)).sum::<usize>(),
    ])
}

fn binary_config_json(cfg: &ProtocolConfig) -> serde_json::Value {
    let b = cfg.binary_config(None);
    let t = &b.table_config;
    #[allow(unused_mut)]
    let mut v = serde_json::json!({
        "max_binary_format_version": b.max_binary_format_version,
        "min_binary_format_version": b.min_binary_format_version,
        "check_no_extraneous_bytes": b.check_no_extraneous_bytes,
        "deprecate_global_storage_ops": b.deprecate_global_storage_ops,
        "allow_unpublishable": b.allow_unpublishable(),
        "table": [t.module_handles, t.datatype_handles, t.function_handles, t.function_instantiations,
                  t.signatures, t.constant_pool, t.identifiers, t.address_identifiers, t.struct_defs,
                  t.struct_def_instantiations, t.function_defs, t.field_handles, t.field_instantiations,
                  t.friend_decls, t.enum_defs, t.enum_def_instantiations, t.variant_handles,
                  t.variant_instantiation_handles],
    });
    #[cfg(feature = "sui_184")]
    { v["type_parameter_index_max"] = serde_json::json!(b.binary_format_limits.type_parameter_index_max()); }
    v
}

fn verifier_config_json(v: &VerifierConfig) -> serde_json::Value {
    serde_json::json!({
        "max_loop_depth": v.max_loop_depth,
        "max_function_parameters": v.max_function_parameters,
        "max_generic_instantiation_length": v.max_generic_instantiation_length,
        "max_basic_blocks": v.max_basic_blocks,
        "max_value_stack_size": v.max_value_stack_size,
        "max_type_nodes": v.max_type_nodes,
        "max_push_size": v.max_push_size,
        "max_dependency_depth": v.max_dependency_depth,
        "max_data_definitions": v.max_data_definitions,
        "max_fields_in_struct": v.max_fields_in_struct,
        "max_function_definitions": v.max_function_definitions,
        "max_constant_vector_len": v.max_constant_vector_len,
        "max_back_edges_per_function": v.max_back_edges_per_function,
        "max_back_edges_per_module": v.max_back_edges_per_module,
        "max_basic_blocks_in_script": v.max_basic_blocks_in_script,
        "max_identifier_len": v.max_identifier_len,
        "disallow_self_identifier": v.disallow_self_identifier,
        "allow_receiving_object_id": v.allow_receiving_object_id,
        "reject_mutable_random_on_entry_functions": v.reject_mutable_random_on_entry_functions,
        "bytecode_version": v.bytecode_version,
        "max_variants_in_enum": v.max_variants_in_enum,
        "additional_borrow_checks": v.additional_borrow_checks,
        "better_loader_errors": v.better_loader_errors,
        "private_generics_verifier_v2": v.private_generics_verifier_v2,
        "sanity_check_with_regex_reference_safety": v.sanity_check_with_regex_reference_safety.map(|x| x as u64),
        "deprecate_global_storage_ops": v.deprecate_global_storage_ops,
        "disable_entry_point_signature_check": v.disable_entry_point_signature_check,
        "switch_to_regex_reference_safety": v.switch_to_regex_reference_safety,
        "framework_tx_context_mut_restrictions": v.framework_tx_context_mut_restrictions,
        "disallow_jump_orphans": v.disallow_jump_orphans,
        "max_generic_instantiation_type_nodes_per_function": v.max_generic_instantiation_type_nodes_per_function,
        "max_generic_instantiation_type_nodes_per_module": v.max_generic_instantiation_type_nodes_per_module,
        "include_function_signatures_in_instantiation_limits": v.include_function_signatures_in_instantiation_limits,
        "disable_id_leak_verifier": v.disable_id_leak_verifier,
    })
}

// ---------------------------------------------------------------------------------------------
// Truth per (module, protocol version)

struct Env {
    cfg: ProtocolConfig,
    natives: BTreeSet<(String, String, String)>,
}

fn env_for(pv: u64) -> Result<Env> {
    let cfg = std::panic::catch_unwind(|| {
        ProtocolConfig::get_for_version(ProtocolVersion::new(pv), Chain::Mainnet)
    })
    .map_err(|_| anyhow!("protocol config {pv} panics"))?;
    let natives = sui_move_natives_latest::all_natives(true, &cfg)
        .into_iter()
        .map(|(a, m, f, _)| (a.to_hex(), m.to_string(), f.to_string()))
        .collect();
    Ok(Env { cfg, natives })
}

fn deserialize_truth(bytes: &[u8], env: &Env) -> (serde_json::Value, Option<CompiledModule>) {
    let bc = env.cfg.binary_config(None);
    match CompiledModule::deserialize_with_config(bytes, &bc) {
        Err(e) => (serde_json::json!({ "err": partial_error_json(e) }), None),
        Ok(m) => {
            let mut out = vec![];
            let ser = match m.serialize_with_version(m.version, &mut out) {
                Err(e) => serde_json::json!({ "err": e.to_string() }),
                Ok(()) if out == bytes => serde_json::json!("same"),
                Ok(()) => serde_json::json!({ "hex": hex::encode(&out) }),
            };
            (serde_json::json!({ "ok": { "ser": ser, "shape": shape(&m) } }), Some(m))
        }
    }
}

/// What the latest adapter does to one module at publish (execution path, no signing limits):
/// `move_vm_runtime::validation::verification::translate::module` (bytecode verifier, function
/// signatures by name, natives), then `sui_verify_module_unmetered`. Units are what a meter sees.
fn verify_truth(m: &CompiledModule, env: &Env) -> serde_json::Value {
    let vcfg = env.cfg.verifier_config(None);
    let mut meter = RecMeter::default();
    meter.enter_scope(m.self_id().name().as_str(), Scope::Module);
    let mv = (|| -> Result<(), VMError> {
        move_bytecode_verifier::verify_module_with_config_metered(&vcfg, m, &mut meter)?;
        for function in m.function_defs() {
            let handle = m.function_handle_at(function.function);
            let name = m.identifier_at(handle.name);
            move_bytecode_verifier::script_signature::verify_module_function_signature_by_name(
                m,
                name,
                move_bytecode_verifier::no_additional_script_signature_checks,
            )?;
        }
        check_natives(m, &env.natives)
    })();
    let move_json = match &mv {
        Ok(()) => serde_json::json!("ok"),
        Err(e) => serde_json::json!({ "err": vm_error_json(e) }),
    };
    let sui_json = if mv.is_ok() {
        match sui_verifier_latest::verifier::sui_verify_module_metered(m, &BTreeMap::new(), &mut meter, &vcfg) {
            Ok(()) => serde_json::json!("ok"),
            Err(e) => serde_json::json!({ "err": {
                "kind": format!("{:?}", e.kind()),
                "msg": e.source().as_ref().map(|s| s.to_string()),
            }}),
        }
    } else {
        serde_json::Value::Null
    };
    serde_json::json!({
        "move": move_json,
        "sui": sui_json,
        "units": { "mod": meter.module as u64, "fun_total": meter.fun_total as u64, "fun_max": meter.fun_max as u64, "adds": meter.adds },
    })
}

/// move-vm-runtime `check_natives` with Sui's native table for the protocol version.
fn check_natives(m: &CompiledModule, natives: &BTreeSet<(String, String, String)>) -> Result<(), VMError> {
    use move_binary_format::{IndexKind, errors::verification_error, file_format::StructFieldInformation};
    let inner = || -> Result<(), PartialVMError> {
        for (idx, f) in m.function_defs().iter().filter(|f| f.is_native()).enumerate() {
            let fh = m.function_handle_at(f.function);
            let mh = m.module_handle_at(fh.module);
            let key = (
                m.address_identifier_at(mh.address).to_hex(),
                m.identifier_at(mh.name).to_string(),
                m.identifier_at(fh.name).to_string(),
            );
            if !natives.contains(&key) {
                return Err(verification_error(StatusCode::MISSING_DEPENDENCY, IndexKind::FunctionHandle, idx as u16));
            }
        }
        for (idx, s) in m.struct_defs().iter().enumerate() {
            if s.field_information == StructFieldInformation::Native {
                return Err(verification_error(StatusCode::MISSING_DEPENDENCY, IndexKind::FunctionHandle, idx as u16));
            }
        }
        Ok(())
    };
    inner().map_err(|e| e.finish(Location::Module(m.self_id())))
}

// ---------------------------------------------------------------------------------------------
// build

fn list_chk(corpus: &Path) -> Result<Vec<PathBuf>> {
    let mut v: Vec<(u64, PathBuf)> = vec![];
    for e in std::fs::read_dir(corpus.join("chk"))? {
        let p = e?.path();
        if p.extension().map(|x| x == "chk").unwrap_or(false) {
            let seq: u64 = p.file_stem().unwrap().to_str().unwrap().parse()?;
            v.push((seq, p));
        }
    }
    v.sort();
    Ok(v.into_iter().map(|x| x.1).collect())
}

struct Module {
    hash: [u8; 32],
    bytes: Vec<u8>,
    pv_first: u64,
    seq_first: u64,
    srcs: BTreeSet<&'static str>,
}

/// Protocol 142 (`binary_format_limits_profile = V1`): modules whose signature pool holds a
/// `TypeParameter(i)` (bare, and inside a `vector`) for i at the profile boundary. The serializer
/// writes the index as a u16 (at most 65535, uleb `ff ff 03`); 65536 and 65537 are the same bytes
/// patched to `80 80 04` and `81 80 04` (same length, so every table offset holds). LEGACY accepts
/// up to 65536 and then fails the u16 conversion (UNKNOWN_INVARIANT_VIOLATION_ERROR); V1 stops at
/// 65535 (MALFORMED). Each runs at 141 (LEGACY) and 142 (V1).
#[cfg(feature = "sui_184")]
fn tpidx_modules() -> Result<Vec<Vec<u8>>> {
    use move_binary_format::file_format::*;
    use move_core_types::account_address::AccountAddress;
    use move_core_types::identifier::Identifier;
    let id = |s: &str| Identifier::new(s).unwrap();
    let mut out = vec![];
    for (name, idx) in [("a", 0xFFFEu16), ("b", 0xFFFF)] {
        for wrap in [false, true] {
            let tok = if wrap { SignatureToken::Vector(Box::new(SignatureToken::TypeParameter(idx))) } else { SignatureToken::TypeParameter(idx) };
            let m = CompiledModule {
                version: 7,
                publishable: true,
                self_module_handle_idx: ModuleHandleIndex(0),
                module_handles: vec![ModuleHandle { address: AddressIdentifierIndex(0), name: IdentifierIndex(0) }],
                datatype_handles: vec![],
                function_handles: vec![FunctionHandle {
                    module: ModuleHandleIndex(0),
                    name: IdentifierIndex(1),
                    parameters: SignatureIndex(1),
                    return_: SignatureIndex(0),
                    type_parameters: vec![AbilitySet::EMPTY | Ability::Drop],
                }],
                field_handles: vec![],
                friend_decls: vec![],
                struct_def_instantiations: vec![],
                function_instantiations: vec![],
                field_instantiations: vec![],
                signatures: vec![Signature(vec![]), Signature(vec![tok])],
                identifiers: vec![id(&format!("tp{name}{}", wrap as u8)), id("f")],
                address_identifiers: vec![AccountAddress::ZERO],
                constant_pool: vec![],
                metadata: vec![],
                struct_defs: vec![],
                function_defs: vec![FunctionDefinition {
                    function: FunctionHandleIndex(0),
                    visibility: Visibility::Public,
                    is_entry: false,
                    acquires_global_resources: vec![],
                    code: Some(CodeUnit { locals: SignatureIndex(0), code: vec![Bytecode::Ret], jump_tables: vec![] }),
                }],
                enum_defs: vec![],
                enum_def_instantiations: vec![],
                variant_handles: vec![],
                variant_instantiation_handles: vec![],
            };
            let mut bytes = Vec::new();
            m.serialize_with_version(m.version, &mut bytes)?;
            out.push(bytes.clone());
            if idx == 0xFFFF {
                let at: Vec<usize> = (0..bytes.len().saturating_sub(2)).filter(|&i| bytes[i..i + 3] == [0xff, 0xff, 0x03]).collect();
                anyhow::ensure!(at.len() == 1, "type parameter index bytes found {} times", at.len());
                for patch in [[0x80, 0x80, 0x04], [0x81, 0x80, 0x04], [0x80, 0x80, 0x08]] {
                    let mut p = bytes.clone();
                    p[at[0]..at[0] + 3].copy_from_slice(&patch);
                    out.push(p);
                }
            }
        }
    }
    Ok(out)
}

fn cmd_build(args: &[String]) -> Result<()> {
    let corpus = PathBuf::from(args.first().ok_or_else(|| anyhow!("corpus dir"))?);
    let out = PathBuf::from(args.get(1).ok_or_else(|| anyhow!("vectors dir"))?);
    let t0 = Instant::now();
    let epochs = load_epochs(&corpus)?;
    let files = list_chk(&corpus)?;
    eprintln!("{} checkpoint blobs", files.len());
    let found: Mutex<HashMap<[u8; 32], Module>> = Mutex::new(HashMap::new());
    let total = std::sync::atomic::AtomicU64::new(0);
    files.par_iter().try_for_each(|p| -> Result<()> {
        let f = extract(p, &epochs)?;
        let mut local: Vec<([u8; 32], Found)> = f.into_iter().map(|x| (blake(&x.bytes), x)).collect();
        total.fetch_add(local.len() as u64, std::sync::atomic::Ordering::Relaxed);
        let mut g = found.lock().unwrap();
        for (h, x) in local.drain(..) {
            let e = g.entry(h).or_insert_with(|| Module {
                hash: h,
                bytes: x.bytes.clone(),
                pv_first: x.pv,
                seq_first: x.seq,
                srcs: BTreeSet::new(),
            });
            if (x.seq, x.pv) < (e.seq_first, e.pv_first) {
                e.seq_first = x.seq;
                e.pv_first = x.pv;
            }
            e.srcs.insert(x.src);
        }
        Ok(())
    })?;
    let mut found = found.into_inner().unwrap();
    let corpus_unique = found.len();
    // Framework bytecode snapshots (one dir per protocol version) and compiled modules in the tree.
    let sui = PathBuf::from(std::env::var("ZUI_SUI_SRC").map_err(|_| anyhow!("ZUI_SUI_SRC"))?);
    let mut extra: Vec<(Vec<u8>, u64, &'static str)> = vec![];
    let snap = sui.join("crates/sui-framework-snapshot/bytecode_snapshot");
    for e in std::fs::read_dir(&snap)? {
        let d = e?.path();
        let Some(pv) = d.file_name().and_then(|n| n.to_str()).and_then(|n| n.parse::<u64>().ok()) else { continue };
        for f in std::fs::read_dir(&d)? {
            let (_id, bytes, _deps): ([u8; 32], Vec<Vec<u8>>, Vec<[u8; 32]>) = bcs::from_bytes(&std::fs::read(f?.path())?)?;
            for b in bytes {
                extra.push((b, pv.min(MAX_PV), "snapshot"));
            }
        }
    }
    let mut stack = vec![sui.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d)? {
            let e = e?;
            let p = e.path();
            let ft = e.file_type()?;
            if ft.is_dir() && !ft.is_symlink() && p.file_name().map(|n| n != ".git" && n != "target").unwrap_or(true) {
                stack.push(p);
            } else if ft.is_file() && p.extension().map(|x| x == "mv").unwrap_or(false) {
                extra.push((std::fs::read(&p)?, MAX_PV, "tree"));
            }
        }
    }
    for (b, pv, src) in extra {
        let h = blake(&b);
        let e = found.entry(h).or_insert_with(|| Module { hash: h, bytes: b, pv_first: pv, seq_first: u64::MAX, srcs: BTreeSet::new() });
        if e.seq_first == u64::MAX && pv < e.pv_first {
            e.pv_first = pv;
        }
        e.srcs.insert(src);
    }
    let real_unique = found.len();
    // Deterministic mutants of every real module (negatives for both suites), checked at MAX_PV.
    let mut bases: Vec<&Module> = found.values().collect();
    bases.sort_by(|a, b| a.hash.cmp(&b.hash));
    // Mutant rounds (salt, scale). Salt 0 is the original round (checked at MAX_PV only). Salt
    // 1 adds the extended edits (every opcode, enums, jump tables, targeted reference-safety and
    // limit edits, old binary versions), each also checked at its base module's protocol
    // version so older verifier configs see invalid modules. ZUI_MF_SALT / ZUI_MF_SCALE replace
    // both rounds with one extended round for scratch differential fuzz runs.
    let env_u64 = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(d);
    let rounds: Vec<(u64, usize)> = match env_u64("ZUI_MF_SALT", 0) {
        0 => vec![(0, 1), (1, 1)],
        salt => vec![(salt, env_u64("ZUI_MF_SCALE", 1).max(1) as usize)],
    };
    let mut mutants: Vec<(Vec<u8>, &'static str, u64)> = vec![];
    for (salt, scale) in rounds {
        mutants.par_extend(bases.par_iter().flat_map_iter(|m| {
            let pv = if salt != 0 { m.pv_first } else { MAX_PV };
            mutate::mutants_ext(&m.bytes, &m.hash, MUTANTS_BYTE * scale, MUTANTS_STRUCT * scale, salt).into_iter().map(move |(b, s)| (b, s, pv))
        }));
    }
    for (b, src, pv) in mutants {
        let h = blake(&b);
        found.entry(h).or_insert_with(|| Module { hash: h, bytes: b, pv_first: pv, seq_first: u64::MAX, srcs: BTreeSet::from([src]) });
    }
    // Regression modules (regress/<pv>-<name>.mv): inputs that once split deepwave from Rust.
    let regress = Path::new(env!("CARGO_MANIFEST_DIR")).join("regress");
    if regress.is_dir() {
        for e in std::fs::read_dir(&regress)? {
            let p = e?.path();
            let Some(name) = p.file_name().and_then(|n| n.to_str()).filter(|n| n.ends_with(".mv")) else { continue };
            let pv: u64 = name.split('-').next().and_then(|x| x.parse().ok()).ok_or_else(|| anyhow!("regress file {name}: want <pv>-<name>.mv"))?;
            let b = std::fs::read(&p)?;
            let h = blake(&b);
            let e = found.entry(h).or_insert_with(|| Module { hash: h, bytes: b, pv_first: pv, seq_first: u64::MAX, srcs: BTreeSet::new() });
            e.srcs.insert("regress");
        }
    }
    #[cfg(feature = "sui_184")]
    for b in tpidx_modules()? {
        let h = blake(&b);
        let e = found.entry(h).or_insert_with(|| Module { hash: h, bytes: b, pv_first: 141, seq_first: u64::MAX, srcs: BTreeSet::new() });
        e.srcs.insert("tpidx142");
    }
    eprintln!("unique modules: {corpus_unique} corpus, {real_unique} with snapshots and tree, {} with mutants", found.len());
    let mut mods: Vec<Module> = found.into_values().collect();
    mods.sort_by(|a, b| a.hash.cmp(&b.hash));
    let bytes: usize = mods.iter().map(|m| m.bytes.len()).sum();
    eprintln!(
        "{} module occurrences, {} unique modules, {} bytes, extracted in {:.1}s",
        total.load(std::sync::atomic::Ordering::Relaxed),
        mods.len(),
        bytes,
        t0.elapsed().as_secs_f64()
    );

    // protocol environments
    let mut pvs: BTreeSet<u64> = mods.iter().map(|m| m.pv_first).collect();
    pvs.insert(MAX_PV);
    let mut envs: BTreeMap<u64, Env> = BTreeMap::new();
    for &pv in &pvs {
        envs.insert(pv, env_for(pv)?);
    }

    let bin_dir = out.join("move-binary");
    let ver_dir = out.join("move-verify");
    for d in [bin_dir.join("packs"), bin_dir.join("truth"), ver_dir.join("truth"), ver_dir.join("natives")] {
        std::fs::create_dir_all(&d)?;
    }
    {
        let mut f = std::fs::File::create(bin_dir.join("configs.jsonl"))?;
        for (pv, env) in &envs {
            let line = serde_json::json!({
                "pv": pv,
                "binary": binary_config_json(&env.cfg),
                "verifier": verifier_config_json(&env.cfg.verifier_config(None)),
            });
            writeln!(f, "{line}")?;
            let mut nf = std::fs::File::create(ver_dir.join("natives").join(format!("{pv}.txt")))?;
            for (a, m, fun) in &env.natives {
                writeln!(nf, "{a}::{m}::{fun}")?;
            }
        }
    }

    let per = mods.len().div_ceil(PACKS);
    let chunks: Vec<&[Module]> = mods.chunks(per.max(1)).collect();
    let counts = Mutex::new((0u64, 0u64, 0u64, 0u64)); // binary items, binary ok, verify items, verify ok
    chunks.par_iter().enumerate().try_for_each(|(i, chunk)| -> Result<()> {
        let mut pack = vec![];
        let mut bt = String::new();
        let mut vt = String::new();
        let (mut bi, mut bo, mut vi, mut vo) = (0, 0, 0, 0);
        for m in chunk.iter() {
            pack.extend_from_slice(&(m.bytes.len() as u32).to_le_bytes());
            pack.extend_from_slice(&m.bytes);
            let mut item_pvs = vec![m.pv_first];
            if m.pv_first != MAX_PV {
                item_pvs.push(MAX_PV);
            }
            let mut bitems = vec![];
            let mut vitems = vec![];
            for pv in item_pvs {
                let env = &envs[&pv];
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let (de, cm) = deserialize_truth(&m.bytes, env);
                    let ver = cm.as_ref().map(|cm| verify_truth(cm, env));
                    (de, ver)
                }));
                let (de, ver) = r.map_err(|_| anyhow!("panic on module {} at pv {pv}", hex::encode(m.hash)))?;
                bi += 1;
                if de.get("ok").is_some() {
                    bo += 1;
                }
                bitems.push(serde_json::json!({ "pv": pv, "de": de }));
                if let Some(v) = ver {
                    vi += 1;
                    if v["move"] == "ok" && v["sui"] == "ok" {
                        vo += 1;
                    }
                    let mut v = v;
                    v["pv"] = serde_json::json!(pv);
                    vitems.push(v);
                }
            }
            let line = serde_json::json!({
                "h": hex::encode(m.hash),
                "seq": if m.seq_first == u64::MAX { serde_json::Value::Null } else { serde_json::json!(m.seq_first) },
                "src": m.srcs.iter().collect::<Vec<_>>(),
                "items": bitems,
            });
            bt.push_str(&line.to_string());
            bt.push('\n');
            let line = serde_json::json!({ "h": hex::encode(m.hash), "items": vitems });
            vt.push_str(&line.to_string());
            vt.push('\n');
        }
        std::fs::write(bin_dir.join("packs").join(format!("pack-{i:03}.mvp")), &pack)?;
        std::fs::write(bin_dir.join("truth").join(format!("pack-{i:03}.jsonl")), bt)?;
        std::fs::write(ver_dir.join("truth").join(format!("pack-{i:03}.jsonl")), vt)?;
        let mut c = counts.lock().unwrap();
        c.0 += bi;
        c.1 += bo;
        c.2 += vi;
        c.3 += vo;
        Ok(())
    })?;
    let c = counts.into_inner().unwrap();
    eprintln!(
        "move-binary items {} ({} deserialize ok), move-verify items {} ({} verify ok), protocol versions {:?}, {:.1}s",
        c.0,
        c.1,
        c.2,
        c.3,
        pvs,
        t0.elapsed().as_secs_f64()
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// bench (CONTRACTS.md section 4.3 protocol)

fn read_pack(p: &Path) -> Result<Vec<Vec<u8>>> {
    let b = std::fs::read(p)?;
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        let n = u32::from_le_bytes(b[i..i + 4].try_into()?) as usize;
        out.push(b[i + 4..i + 4 + n].to_vec());
        i += 4 + n;
    }
    Ok(out)
}

fn cmd_bench(args: &[String]) -> Result<()> {
    let name = args.first().ok_or_else(|| anyhow!("bench name"))?.clone();
    let mut iters = 5usize;
    let mut list = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--iters" => {
                iters = args[i + 1].parse()?;
                i += 2;
            }
            "--list" => {
                list = Some(args[i + 1].clone());
                i += 2;
            }
            a => bail!("unknown arg {a}"),
        }
    }
    let list = list.ok_or_else(|| anyhow!("--list"))?;
    let mut modules = vec![];
    for line in std::fs::read_to_string(&list)?.lines() {
        if !line.is_empty() {
            modules.extend(read_pack(Path::new(line))?);
        }
    }
    let env = env_for(MAX_PV)?;
    let bc = env.cfg.binary_config(None);
    let vcfg = env.cfg.verifier_config(None);
    let compiled: Vec<CompiledModule> =
        modules.iter().filter_map(|b| CompiledModule::deserialize_with_config(b, &bc).ok()).collect();
    let run = |f: &mut dyn FnMut()| {
        f();
        let mut times = vec![];
        for _ in 0..iters {
            let t = Instant::now();
            f();
            times.push(t.elapsed().as_nanos());
        }
        times.sort();
        times[times.len() / 2]
    };
    let (units, ns) = match name.as_str() {
        "deserialize" => (
            modules.len(),
            run(&mut || {
                for b in &modules {
                    let _ = std::hint::black_box(CompiledModule::deserialize_with_config(b, &bc));
                }
            }),
        ),
        "serialize" => (
            compiled.len(),
            run(&mut || {
                for m in &compiled {
                    let mut out = vec![];
                    let _ = std::hint::black_box(m.serialize_with_version(m.version, &mut out));
                }
            }),
        ),
        "verify" => (
            compiled.len(),
            run(&mut || {
                for m in &compiled {
                    let r = move_bytecode_verifier::verify_module_with_config_unmetered(&vcfg, m);
                    if r.is_ok() {
                        let _ = std::hint::black_box(sui_verifier_latest::verifier::sui_verify_module_unmetered(
                            m,
                            &BTreeMap::new(),
                            &vcfg,
                        ));
                    }
                }
            }),
        ),
        n => bail!("unknown bench {n}"),
    };
    println!(
        "{}",
        serde_json::json!({ "impl": "rust", "bench": name, "unit": "module", "units": units, "ns_per_unit": ns as f64 / units.max(1) as f64 })
    );
    Ok(())
}
