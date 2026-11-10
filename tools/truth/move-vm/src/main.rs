//! zui-truth-move-vm: ground truth for the move-vm lane (CONTRACTS.md section 3.3, suites
//! `move-vm-gas` and `move-vm-trace`).
//!
//! It runs Mysten's own Rust at mainnet-v1.83.1: move-vm-runtime (the `latest` execution
//! version, in force on mainnet since protocol 119) built by `sui_adapter_latest::adapter::
//! new_move_runtime` with Sui's natives and VM config, metered by `SuiGasMeter` over sui-types
//! `GasStatus`, traced by `move-trace-format`. It never computes truth with its own code: the
//! only zui-made inputs are the calls (function, type arguments, BCS arguments, budget), drawn
//! by a deterministic generator.
//!
//!   build <corpus_dir> <vectors_dir>      write <vectors_dir>/move-vm-gas/{packages.bin,calls.jsonl}
//!                                         and <vectors_dir>/move-vm-trace/{calls.jsonl,trace/}
//!   run <vectors_dir> <id>                re-run one call and print its truth and trace (debug)
//!   bench <name> --iters N --list <file>  time Rust on the calls listed (one calls.jsonl path)
//!   cut <v0|v1|v2|v3> <pv> <vectors_dir>  re-run the protocol-141 calls on an older execution cut
//!                                         (src/cut.rs), writing under move-vm-{gas,trace}/cuts/<vN>/
//!
//! Output formats: README.md next to this file.
use anyhow::{Context, Result, anyhow, bail};
use indexmap::IndexMap;
use move_binary_format::CompiledModule;
use move_binary_format::errors::{Location, VMError};
use move_binary_format::file_format::{
    Ability, AbilitySet, Bytecode, Constant, DatatypeHandleIndex, SignatureToken, StructFieldInformation, Visibility,
};
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::{IdentStr, Identifier};
use move_core_types::language_storage::{ModuleId, StructTag, TypeTag};
use move_core_types::resolver::{IntraPackageName, ModuleResolver, SerializedPackage};
use move_core_types::runtime_value::{MoveEnumLayout, MoveStructLayout, MoveTypeLayout};
use move_trace_format::format::MoveTraceBuilder;
use move_vm_runtime::execution::interpreter::locals::BaseHeap;
use move_vm_runtime::execution::values::{Reference, Value};
use move_vm_runtime::runtime::MoveRuntime;
use move_vm_runtime::shared::linkage_context::LinkageContext;
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use sui_adapter_latest::gas_meter::SuiGasMeter;
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::gas_model::gas_predicates::cost_table_for_version;
use sui_types::gas_model::tables::GasStatus;
use sui_types::move_package::MovePackage;

/// Protocol versions run by the `latest` execution version (4) with distinct VM gas behaviour:
/// gas model 11 (119), 13 (123), 14 (124), 14 with abstract-size LdConst (137), 15 (141).
const PVS_1831: [u64; 5] = [119, 123, 124, 137, 141];
/// `v142` mode (cargo feature sui_184): the same calls at protocol 142 only, over the 142
/// framework snapshot, written under `move-vm-gas/v142` and `move-vm-trace/v142`.
static V142: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
fn v142() -> bool {
    V142.load(std::sync::atomic::Ordering::Relaxed)
}
fn pvs() -> &'static [u64] {
    if v142() { &[142] } else { &PVS_1831 }
}
fn top_pv() -> u64 {
    if v142() { 142 } else { 141 }
}
/// Framework snapshot used for system packages (0x1, 0x2, 0x3, 0xb, 0xdee9).
const FRAMEWORK_SNAPSHOT: u64 = 140;
/// Budget in gas units (gas price 1) for ordinary calls: 1M units = 1e9 internal units.
const BUDGET: u64 = 1_000_000;
const SEEDS_PER_FN: usize = 3;
/// Synthetic functions are small and aimed at edge cases: more draws, over every protocol version.
const SYNTH_SEEDS_PER_FN: usize = 15;
const TRACE_EVERY: usize = 7;
const TRACE_MAX_INS: u64 = 20_000;

mod cut;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("build") => cmd_build(&args[2..]),
        // 1.84: the build at protocol 142 only, 142 framework snapshot, into move-vm-gas/v142 and move-vm-trace/v142
        #[cfg(feature = "sui_184")]
        Some("build-v142") => {
            V142.store(true, std::sync::atomic::Ordering::Relaxed);
            cmd_build(&args[2..])
        }
        Some("run") => cmd_run(&args[2..]),
        Some("bench") => cmd_bench(&args[2..]),
        Some("cut") => cut::cmd_cut(&args[2..]),
        Some("cut-trace") => cut::cmd_cut_trace(&args[2..]),
        _ => bail!("usage: zui-truth-move-vm build <corpus> <vectors> | run <vectors> <id> | bench <name> --iters N --list <file> | cut <v0|v1|v2|v3> <pv> <vectors>"),
    }
}

// ---------------------------------------------------------------------------------------------
// Packages

#[derive(Clone)]
struct Pkg {
    sp: SerializedPackage,
    src: &'static str,
}

struct Store {
    by_version: BTreeMap<AccountAddress, Pkg>,
}

impl ModuleResolver for &Store {
    type Error = anyhow::Error;
    fn get_packages_static<const N: usize>(&self, ids: [AccountAddress; N]) -> Result<[Option<SerializedPackage>; N]> {
        Ok(ids.map(|id| self.by_version.get(&id).map(|p| p.sp.clone())))
    }
    fn get_packages<'a>(&self, ids: impl ExactSizeIterator<Item = &'a AccountAddress>) -> Result<Vec<Option<SerializedPackage>>> {
        Ok(ids.map(|id| self.by_version.get(id).map(|p| p.sp.clone())).collect())
    }
}

fn framework_packages(sui: &Path) -> Result<Vec<Pkg>> {
    Ok(framework_move_packages(sui)?
        .into_iter()
        .map(|mp| Ok(Pkg { sp: mp.into_serialized_move_package().map_err(|e| anyhow!("{e:?}"))?, src: "framework" }))
        .collect::<Result<_>>()?)
}

fn framework_move_packages(sui: &Path) -> Result<Vec<MovePackage>> {
    framework_move_packages_at(sui, if v142() { 142 } else { FRAMEWORK_SNAPSHOT })
}

fn framework_move_packages_at(sui: &Path, snapshot: u64) -> Result<Vec<MovePackage>> {
    let dir = sui.join(format!("crates/sui-framework-snapshot/bytecode_snapshot/{snapshot}"));
    let mut out = vec![];
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)?.map(|e| e.map(|e| e.path())).collect::<std::io::Result<_>>()?;
    files.sort();
    for f in files {
        let (_id, bytes, deps): ([u8; 32], Vec<Vec<u8>>, Vec<[u8; 32]>) = bcs::from_bytes(&std::fs::read(&f)?)?;
        let modules: Vec<CompiledModule> = bytes
            .iter()
            .map(|b| CompiledModule::deserialize_with_defaults(b).map_err(|e| anyhow!("{e:?}")))
            .collect::<Result<_>>()?;
        let mp = MovePackage::new_system(
            sui_types::base_types::SequenceNumber::from_u64(1),
            &modules,
            deps.into_iter().map(|d| sui_types::base_types::ObjectID::new(d)),
        );
        out.push(mp);
    }
    Ok(out)
}

/// The synthetic packages compiled by `synth/build.sh` (sources next to it): zvm at 0x5a7e..01,
/// its upgrade zvm2 stored at 0x5a7e..02, and zdep at 0x5a7e..03 linked against zvm2. They reach
/// what the corpus does not: every integer width and op, enums, deep generic types, recursion
/// limits, vector errors, upgraded linkage and type origins.
fn synth_packages(sui: &Path) -> Result<Vec<Pkg>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("synth/out");
    let read = |name: &str| -> Result<Vec<CompiledModule>> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir.join(name))?.map(|e| e.map(|e| e.path())).collect::<std::io::Result<_>>()?;
        files.sort();
        files
            .iter()
            .map(|f| {
                let mut m = CompiledModule::deserialize_with_defaults(&std::fs::read(f)?).map_err(|e| anyhow!("{e:?}"))?;
                if f.file_stem().is_some_and(|s| s == "mis") {
                    // Rotate every jump table by one: still verifies, but each arm unpacks the
                    // variant that precedes the one it receives.
                    for fd in m.function_defs.iter_mut() {
                        if let Some(code) = fd.code.as_mut() {
                            for jt in code.jump_tables.iter_mut() {
                                let move_binary_format::file_format::JumpTableInner::Full(v) = &mut jt.jump_table;
                                v.rotate_left(1);
                            }
                        }
                    }
                }
                Ok(m)
            })
            .collect()
    };
    let fw = framework_move_packages(sui)?;
    let deps: Vec<&MovePackage> = fw.iter().filter(|p| matches!(u16::from_be_bytes([p.id().to_vec()[30], p.id().to_vec()[31]]), 1 | 2)).collect();
    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(top_pv()), Chain::Mainnet);
    let v1 = MovePackage::new_initial(&read("zvm")?, &cfg, deps.iter().copied()).map_err(|e| anyhow!("{e:?}"))?;
    let mut sid = [0u8; 32];
    sid[0] = 0x5a;
    sid[1] = 0x7e;
    sid[31] = 2;
    let v2 = v1
        .new_upgraded(sui_types::base_types::ObjectID::new(sid), &read("zvm2")?, &cfg, deps.iter().copied())
        .map_err(|e| anyhow!("{e:?}"))?;
    let mut ddeps = deps.clone();
    ddeps.push(&v2);
    let dep = MovePackage::new_initial(&read("zdep")?, &cfg, ddeps.iter().copied()).map_err(|e| anyhow!("{e:?}"))?;

    // zbig at 0x5a7e..04: types at the JIT limit (128 nodes) that the verifier accepts (weighted
    // limit 256, datatypes weigh 4), plus a 128-node constant type. Copies go one node over:
    // 05 a field (W<vector^127<u8>>: 129 nodes, weight 132), 06 a function signature
    // (vector^128<u8>), 07 a constant type; Rust's JIT refuses them with VM_MAX_TYPE_NODES_REACHED
    // at the package. 09 carries an undecodable constant (the verifier refuses it). zbd (08)
    // links 05, so its make_vm fails with 05's error.
    let at = |n: u8| {
        let mut a = [0u8; 32];
        a[0] = 0x5a;
        a[1] = 0x7e;
        a[31] = n;
        AccountAddress::new(a)
    };
    let big = read("zbig")?;
    let relocate = |ms: &[CompiledModule], from: AccountAddress, to: AccountAddress| -> Vec<CompiledModule> {
        ms.iter()
            .cloned()
            .map(|mut m| {
                for a in m.address_identifiers.iter_mut() {
                    if *a == from {
                        *a = to;
                    }
                }
                m
            })
            .collect()
    };
    let wrap = |m: &CompiledModule, t: SignatureToken| -> SignatureToken {
        let w = m
            .datatype_handles
            .iter()
            .position(|h| m.identifier_at(h.name).as_str() == "W")
            .expect("W");
        SignatureToken::DatatypeInstantiation(Box::new((DatatypeHandleIndex(w as u16), vec![t])))
    };
    let nested_vec = |depth: usize| {
        let mut t = SignatureToken::U8;
        for _ in 0..depth {
            t = SignatureToken::Vector(Box::new(t));
        }
        t
    };
    let mut big_ok = big.clone();
    big_ok[0].constant_pool.push(Constant { type_: nested_vec(127), data: vec![0] });
    let mut big_field = relocate(&big, at(4), at(5));
    {
        let m = &mut big_field[0];
        let sd = m.struct_defs.iter().position(|d| m.identifier_at(m.datatype_handles[d.struct_handle.0 as usize].name).as_str() == "Big").expect("Big");
        let StructFieldInformation::Declared(fields) = &m.struct_defs[sd].field_information else { bail!("Big fields") };
        let t = wrap(m, fields[0].signature.0.clone());
        let StructFieldInformation::Declared(fields) = &mut m.struct_defs[sd].field_information else { bail!("Big fields") };
        fields[0].signature.0 = t;
    }
    let mut big_sig = relocate(&big, at(4), at(6));
    {
        let m = &mut big_sig[0];
        let h = m.function_handles.iter().find(|h| m.identifier_at(h.name).as_str() == "sig").expect("sig").parameters;
        let t = SignatureToken::Vector(Box::new(m.signatures[h.0 as usize].0[0].clone()));
        m.signatures[h.0 as usize].0[0] = t;
    }
    let mut big_const = relocate(&big, at(4), at(7));
    big_const[0].constant_pool.push(Constant { type_: nested_vec(128), data: vec![0] });
    let mut big_bad = relocate(&big, at(4), at(9));
    big_bad[0].constant_pool.push(Constant { type_: SignatureToken::U64, data: vec![1, 2, 3] });
    let bd = relocate(&read("zbd")?, at(4), at(5));
    let mk = |ms: &[CompiledModule]| MovePackage::new_initial(ms, &cfg, deps.iter().copied()).map_err(|e| anyhow!("{e:?}"));
    let p4 = mk(&big_ok)?;
    let p5 = mk(&big_field)?;
    let p6 = mk(&big_sig)?;
    let p7 = mk(&big_const)?;
    let p9 = mk(&big_bad)?;
    let mut bdeps = deps.clone();
    bdeps.push(&p5);
    let p8 = MovePackage::new_initial(&bd, &cfg, bdeps.iter().copied()).map_err(|e| anyhow!("{e:?}"))?;

    [v1.clone(), v2.clone(), dep, p4, p5, p6, p7, p8, p9]
        .into_iter()
        .map(|mp| Ok(Pkg { sp: mp.into_serialized_move_package().map_err(|e| anyhow!("{e:?}"))?, src: "synth" }))
        .collect()
}

fn corpus_packages(corpus: &Path) -> Result<Vec<Pkg>> {
    let mut files: Vec<(u64, PathBuf)> = vec![];
    for e in std::fs::read_dir(corpus.join("chk"))? {
        let p = e?.path();
        if p.extension().map(|x| x == "chk").unwrap_or(false) {
            files.push((p.file_stem().unwrap().to_str().unwrap().parse()?, p));
        }
    }
    files.sort();
    let found: std::sync::Mutex<BTreeMap<AccountAddress, Pkg>> = Default::default();
    files.par_iter().try_for_each(|(_, p)| -> Result<()> {
        let raw = std::fs::read(p)?;
        let cp: CheckpointData = bcs::from_bytes(&raw[1..]).with_context(|| format!("decode {}", p.display()))?;
        let mut local = vec![];
        for tx in &cp.transactions {
            for obj in tx.input_objects.iter().chain(tx.output_objects.iter()) {
                if let Some(pkg) = obj.data.try_as_package() {
                    let id: AccountAddress = pkg.id().into();
                    // System packages (0x1, 0x2, 0x3, 0xb, 0xdee9 and any id below 0x100) change
                    // in place under one id: the snapshot version is used instead. Keeping a corpus
                    // copy would make the result depend on which checkpoint a thread read first.
                    if id.to_vec()[..31].iter().all(|b| *b == 0) || is_system(&id) {
                        continue;
                    }
                    if let Ok(sp) = pkg.into_serialized_move_package() {
                        local.push(Pkg { sp, src: "corpus" });
                    }
                }
            }
        }
        let mut g = found.lock().unwrap();
        for p in local {
            g.entry(p.sp.version_id).or_insert(p);
        }
        Ok(())
    })?;
    Ok(found.into_inner().unwrap().into_values().collect())
}

fn is_system(a: &AccountAddress) -> bool {
    let v = a.to_vec();
    v[..30].iter().all(|b| *b == 0) && matches!(u16::from_be_bytes([v[30], v[31]]), 1 | 2 | 3 | 0xb | 0xdee9)
}

/// Keep packages whose whole linkage closure is present (system ids resolve to the snapshot).
fn closed_packages(all: Vec<Pkg>) -> BTreeMap<AccountAddress, Pkg> {
    let mut by: BTreeMap<AccountAddress, Pkg> = all.into_iter().map(|p| (p.sp.version_id, p)).collect();
    loop {
        let missing: Vec<AccountAddress> = by
            .iter()
            .filter(|(_, p)| p.sp.linkage_table.values().any(|v| !by.contains_key(v)))
            .map(|(k, _)| *k)
            .collect();
        if missing.is_empty() {
            return by;
        }
        for k in missing {
            by.remove(&k);
        }
    }
}

fn write_packages(path: &Path, pkgs: &[&Pkg]) -> Result<()> {
    let mut b: Vec<u8> = vec![];
    let u32le = |b: &mut Vec<u8>, x: usize| b.extend_from_slice(&(x as u32).to_le_bytes());
    let bytes = |b: &mut Vec<u8>, s: &[u8]| {
        b.extend_from_slice(&(s.len() as u32).to_le_bytes());
        b.extend_from_slice(s);
    };
    b.extend_from_slice(b"ZUIMVPK1");
    u32le(&mut b, pkgs.len());
    for p in pkgs {
        let sp = &p.sp;
        b.extend_from_slice(sp.version_id.as_ref());
        b.extend_from_slice(sp.original_id.as_ref());
        b.extend_from_slice(&sp.version.to_le_bytes());
        u32le(&mut b, sp.linkage_table.len());
        for (k, v) in &sp.linkage_table {
            b.extend_from_slice(k.as_ref());
            b.extend_from_slice(v.as_ref());
        }
        u32le(&mut b, sp.type_origin_table.len());
        for (k, v) in &sp.type_origin_table {
            bytes(&mut b, k.module_name.as_bytes());
            bytes(&mut b, k.type_name.as_bytes());
            b.extend_from_slice(v.as_ref());
        }
        u32le(&mut b, sp.modules.len());
        for (k, v) in &sp.modules {
            bytes(&mut b, k.as_bytes());
            bytes(&mut b, v);
        }
    }
    std::fs::write(path, b)?;
    Ok(())
}

fn read_packages(path: &Path) -> Result<Vec<Pkg>> {
    let b = std::fs::read(path)?;
    let mut i = 8usize;
    let mut take = |n: usize| -> &[u8] {
        let s = &b[i..i + n];
        i += n;
        s
    };
    let rd32 = |s: &[u8]| u32::from_le_bytes(s.try_into().unwrap()) as usize;
    let addr = |s: &[u8]| AccountAddress::new(s.try_into().unwrap());
    let n = rd32(take(4));
    let mut out = vec![];
    for _ in 0..n {
        let version_id = addr(take(32));
        let original_id = addr(take(32));
        let version = u64::from_le_bytes(take(8).try_into().unwrap());
        let nl = rd32(take(4));
        let mut linkage_table = BTreeMap::new();
        for _ in 0..nl {
            let k = addr(take(32));
            let v = addr(take(32));
            linkage_table.insert(k, v);
        }
        let nt = rd32(take(4));
        let mut type_origin_table = IndexMap::new();
        for _ in 0..nt {
            let l = rd32(take(4));
            let m = String::from_utf8(take(l).to_vec())?;
            let l = rd32(take(4));
            let t = String::from_utf8(take(l).to_vec())?;
            let a = addr(take(32));
            type_origin_table.insert(IntraPackageName { module_name: Identifier::new(m)?, type_name: Identifier::new(t)? }, a);
        }
        let nm = rd32(take(4));
        let mut modules = BTreeMap::new();
        for _ in 0..nm {
            let l = rd32(take(4));
            let name = String::from_utf8(take(l).to_vec())?;
            let l = rd32(take(4));
            modules.insert(Identifier::new(name)?, take(l).to_vec());
        }
        out.push(Pkg {
            sp: SerializedPackage { modules, version_id, original_id, linkage_table, type_origin_table, version },
            src: "file",
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Static analysis: which functions can run without natives, and their signatures as type tags

struct Loaded {
    store: Store,
    /// version id -> module name -> compiled module
    modules: BTreeMap<AccountAddress, BTreeMap<String, CompiledModule>>,
}

impl Loaded {
    fn module_for(&self, root: &Pkg, addr: &AccountAddress, name: &str) -> Option<(&Pkg, &CompiledModule)> {
        let ver = root.sp.linkage_table.get(addr)?;
        let pkg = self.store.by_version.get(ver)?;
        let m = self.modules.get(ver)?.get(name)?;
        Some((pkg, m))
    }
}

/// deepwave's native table, read when the tool is built: the list can never go stale.
const ZUI_NATIVE_TABLE: &str = include_str!("../../../../src/natives/table.zig");

/// The natives deepwave implements, "addr::module::function" with the short address, parsed from the
/// `entries` of src/natives/table.zig (`.{ .addr = N, .module = "m", .func = "f", ... }`).
fn zui_natives() -> &'static BTreeSet<String> {
    static SET: std::sync::OnceLock<BTreeSet<String>> = std::sync::OnceLock::new();
    SET.get_or_init(|| {
        let field = |l: &str, k: &str| -> Option<String> {
            let i = l.find(k)? + k.len();
            let r = &l[i..];
            if let Some(r) = r.strip_prefix('"') {
                Some(r[..r.find('"')?].to_string())
            } else {
                Some(r.chars().take_while(|c| c.is_ascii_digit()).collect())
            }
        };
        let mut out = BTreeSet::new();
        for l in ZUI_NATIVE_TABLE.lines() {
            let l = l.trim();
            if !l.starts_with(".{ .addr = ") {
                continue;
            }
            let (Some(a), Some(m), Some(f)) = (field(l, ".addr = "), field(l, ".module = "), field(l, ".func = ")) else { continue };
            out.insert(format!("{a}::{m}::{f}"));
        }
        assert!(out.len() > 50, "src/natives/table.zig: no entries parsed");
        out
    })
}

/// True if the function (or anything it can call) is a native deepwave does not implement, or a
/// callee cannot be resolved.
fn reaches_native(
    l: &Loaded,
    root: &Pkg,
    pkg: &Pkg,
    m: &CompiledModule,
    fdef: usize,
    memo: &mut HashMap<(AccountAddress, String, usize), bool>,
) -> bool {
    let key = (pkg.sp.version_id, m.self_id().name().to_string(), fdef);
    if let Some(v) = memo.get(&key) {
        return *v;
    }
    memo.insert(key.clone(), false); // recursion: assume clean while on the stack
    let d = &m.function_defs[fdef];
    let Some(code) = &d.code else {
        // Natives deepwave implements (src/natives/table.zig) are leaves; the others are skipped.
        let h = m.function_handle_at(d.function);
        let a = m.self_id().address().to_vec();
        let short = if a[..30].iter().all(|b| *b == 0) { Some(u16::from_be_bytes([a[30], a[31]])) } else { None };
        let name = short.map(|s| format!("{}::{}::{}", s, m.self_id().name(), m.identifier_at(h.name)));
        let bad = !name.is_some_and(|n| zui_natives().contains(&n));
        memo.insert(key, bad);
        return bad;
    };
    let mut bad = false;
    for b in &code.code {
        let fh = match b {
            Bytecode::Call(fh) => *fh,
            Bytecode::CallGeneric(fi) => m.function_instantiation_at(*fi).handle,
            _ => continue,
        };
        let h = m.function_handle_at(fh);
        let mh = m.module_handle_at(h.module);
        let addr = *m.address_identifier_at(mh.address);
        let mname = m.identifier_at(mh.name).as_str();
        let fname = m.identifier_at(h.name);
        let Some((cp, cm)) = l.module_for(root, &addr, mname) else {
            bad = true;
            break;
        };
        let Some(idx) = cm.function_defs.iter().position(|fd| cm.identifier_at(cm.function_handle_at(fd.function).name) == fname) else {
            bad = true;
            break;
        };
        if reaches_native(l, root, cp, cm, idx, memo) {
            bad = true;
            break;
        }
    }
    memo.insert(key, bad);
    bad
}

/// Defining id of a datatype named in module `m` of package `pkg` (resolved through `root`).
fn datatype_tag(l: &Loaded, root: &Pkg, m: &CompiledModule, dh: DatatypeHandleIndex, tys: Vec<TypeTag>) -> Option<StructTag> {
    let h = m.datatype_handle_at(dh);
    let mh = m.module_handle_at(h.module);
    let addr = *m.address_identifier_at(mh.address);
    let mname = m.identifier_at(mh.name).to_owned();
    let tname = m.identifier_at(h.name).to_owned();
    let (dp, _) = l.module_for(root, &addr, mname.as_str())?;
    let defining = *dp.sp.type_origin_table.get(&IntraPackageName { module_name: mname.clone(), type_name: tname.clone() })?;
    Some(StructTag { address: defining, module: mname, name: tname, type_params: tys })
}

fn token_tag(l: &Loaded, root: &Pkg, m: &CompiledModule, t: &SignatureToken, tys: &[TypeTag]) -> Option<TypeTag> {
    use SignatureToken as S;
    Some(match t {
        S::Bool => TypeTag::Bool,
        S::U8 => TypeTag::U8,
        S::U16 => TypeTag::U16,
        S::U32 => TypeTag::U32,
        S::U64 => TypeTag::U64,
        S::U128 => TypeTag::U128,
        S::U256 => TypeTag::U256,
        S::Address => TypeTag::Address,
        S::Signer => TypeTag::Signer,
        S::Vector(e) => TypeTag::Vector(Box::new(token_tag(l, root, m, e, tys)?)),
        S::Datatype(dh) => TypeTag::Struct(Box::new(datatype_tag(l, root, m, *dh, vec![])?)),
        S::DatatypeInstantiation(inst) => {
            let (dh, args) = &**inst;
            let args = args.iter().map(|a| token_tag(l, root, m, a, tys)).collect::<Option<Vec<_>>>()?;
            TypeTag::Struct(Box::new(datatype_tag(l, root, m, *dh, args)?))
        }
        S::TypeParameter(i) => tys.get(*i as usize)?.clone(),
        S::Reference(_) | S::MutableReference(_) => return None,
    })
}

// ---------------------------------------------------------------------------------------------
// Deterministic generator

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn fnv(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn gen_uint(r: &mut Rng, bits: u32) -> u128 {
    let max: u128 = if bits == 128 { u128::MAX } else { (1u128 << bits) - 1 };
    match r.below(10) {
        0 => 0,
        1 => 1,
        2 => max,
        3 => max - 1,
        4 => r.below(4) as u128 + 2,
        5 => (r.below(1000) as u128) & max,
        6 => (1u128 << r.below(bits as u64)) & max,
        _ => ((r.next() as u128) << 64 | r.next() as u128) & max,
    }
}

fn uleb(out: &mut Vec<u8>, mut x: u64) {
    loop {
        let b = (x & 0x7f) as u8;
        x >>= 7;
        if x == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn gen_value(r: &mut Rng, layout: &MoveTypeLayout, depth: usize, out: &mut Vec<u8>) {
    use MoveTypeLayout as L;
    match layout {
        L::Bool => out.push((r.below(2)) as u8),
        L::U8 => out.push(gen_uint(r, 8) as u8),
        L::U16 => out.extend_from_slice(&(gen_uint(r, 16) as u16).to_le_bytes()),
        L::U32 => out.extend_from_slice(&(gen_uint(r, 32) as u32).to_le_bytes()),
        L::U64 => out.extend_from_slice(&(gen_uint(r, 64) as u64).to_le_bytes()),
        L::U128 => out.extend_from_slice(&gen_uint(r, 128).to_le_bytes()),
        L::U256 => {
            let lo = gen_uint(r, 128);
            let hi = if r.below(3) == 0 { gen_uint(r, 128) } else { 0 };
            out.extend_from_slice(&lo.to_le_bytes());
            out.extend_from_slice(&hi.to_le_bytes());
        }
        L::Address | L::Signer => {
            let mut a = [0u8; 32];
            match r.below(4) {
                0 => {}
                1 => a[31] = (r.below(3) + 1) as u8,
                _ => {
                    for x in a.iter_mut() {
                        *x = r.next() as u8;
                    }
                }
            }
            out.extend_from_slice(&a);
        }
        L::Vector(e) => {
            let n = if depth > 3 {
                0
            } else {
                match r.below(8) {
                    0 => 0,
                    1..=4 => r.below(4) + 1,
                    5 | 6 => r.below(16) + 1,
                    _ => r.below(64) + 1,
                }
            };
            uleb(out, n);
            let ascii = matches!(**e, L::U8) && r.below(2) == 0;
            for _ in 0..n {
                if ascii {
                    const CH: &[u8] = b"0123456789abcdefABCDEF xyz_-:/.";
                    out.push(CH[r.below(CH.len() as u64) as usize]);
                } else {
                    gen_value(r, e, depth + 1, out);
                }
            }
        }
        L::Struct(s) => {
            let MoveStructLayout(fields) = &**s;
            for f in fields.iter() {
                gen_value(r, f, depth + 1, out);
            }
        }
        L::Enum(e) => {
            let MoveEnumLayout(vs) = &**e;
            let tag = r.below(vs.len() as u64);
            uleb(out, tag);
            for f in vs[tag as usize].iter() {
                gen_value(r, f, depth + 1, out);
            }
        }
    }
}

/// Candidate type arguments, in order, for a type parameter with the given constraints.
fn ty_candidates(c: AbilitySet) -> Vec<TypeTag> {
    let string = TypeTag::Struct(Box::new(StructTag {
        address: AccountAddress::ONE,
        module: Identifier::new("string").unwrap(),
        name: Identifier::new("String").unwrap(),
        type_params: vec![],
    }));
    let opt = TypeTag::Struct(Box::new(StructTag {
        address: AccountAddress::ONE,
        module: Identifier::new("option").unwrap(),
        name: Identifier::new("Option").unwrap(),
        type_params: vec![TypeTag::U64],
    }));
    let coin = TypeTag::Struct(Box::new(StructTag {
        address: AccountAddress::TWO,
        module: Identifier::new("coin").unwrap(),
        name: Identifier::new("Coin").unwrap(),
        type_params: vec![TypeTag::Struct(Box::new(StructTag {
            address: AccountAddress::TWO,
            module: Identifier::new("sui").unwrap(),
            name: Identifier::new("SUI").unwrap(),
            type_params: vec![],
        }))],
    }));
    if c.has_ability(Ability::Key) {
        return vec![coin];
    }
    vec![TypeTag::U64, TypeTag::U8, TypeTag::Bool, TypeTag::Address, TypeTag::Vector(Box::new(TypeTag::U8)), TypeTag::U128, string, opt]
}

// ---------------------------------------------------------------------------------------------
// Running one call

struct Env {
    pv: u64,
    gm: u64,
    cfg: ProtocolConfig,
    runtime: MoveRuntime,
}

/// The transaction context calls run under (the sui-natives truth tool's DEFAULT_CTX); deepwave's
/// move-vm conformance uses the same values.
fn native_extensions(cfg: &ProtocolConfig) -> Result<move_vm_runtime::natives::extensions::NativeExtensions<'_>> {
    struct NoBalances;
    impl sui_types::storage::ImplicitSystemObjectResolver for NoBalances {
        fn object_available_balance(&self, _: sui_types::base_types::SuiAddress, _: &TypeTag) -> sui_types::error::SuiResult<u128> {
            Ok(0)
        }
        // 1.84 `clock::borrow`: a fixed Clock (id 0x6, timestamp_ms 1_762_400_123_456)
        #[cfg(feature = "sui_184")]
        fn clock(&self) -> sui_types::error::SuiResult<sui_types::object::Object> {
            let mut id = [0u8; 32];
            id[31] = 6;
            let mut contents = id.to_vec();
            contents.extend_from_slice(&1_762_400_123_456u64.to_le_bytes());
            let ty: sui_types::base_types::MoveObjectType = move_core_types::language_storage::StructTag {
                address: AccountAddress::TWO,
                module: Identifier::new("clock").unwrap(),
                name: Identifier::new("Clock").unwrap(),
                type_params: vec![],
            }
            .into();
            let mo = unsafe { sui_types::object::MoveObject::new_from_execution_with_limit(ty, true, sui_types::base_types::SequenceNumber::from_u64(7), contents, 256_000) }.unwrap();
            Ok(sui_types::object::Object::new_move(
                mo,
                sui_types::object::Owner::Shared { initial_shared_version: sui_types::base_types::SequenceNumber::from_u64(1) },
                sui_types::digests::TransactionDigest::new([0x77; 32]),
            ))
        }
    }
    static EMPTY: std::sync::OnceLock<sui_types::in_memory_storage::InMemoryStorage> = std::sync::OnceLock::new();
    static METRICS: std::sync::OnceLock<Arc<sui_types::metrics::ExecutionMetrics>> = std::sync::OnceLock::new();
    let storage = EMPTY.get_or_init(|| sui_types::in_memory_storage::InMemoryStorage::new(vec![]));
    let metrics = METRICS.get_or_init(|| Arc::new(sui_types::metrics::ExecutionMetrics::new(&prometheus::Registry::new())));
    let tx = sui_types::base_types::TxContext::new_from_components(
        &sui_types::base_types::SuiAddress::from_bytes([0x5a; 32])?,
        &sui_types::digests::TransactionDigest::new([0xd1; 32]),
        &1304,
        1_762_400_000_000,
        538,
        750,
        50_000_000,
        None,
        cfg,
    );
    sui_adapter_latest::adapter::new_native_extensions(
        storage,
        &NoBalances,
        BTreeMap::new(),
        /* is_metered */ true,
        cfg,
        metrics.clone(),
        std::rc::Rc::new(std::cell::RefCell::new(tx)),
    )
    .map_err(|e| anyhow!("extensions: {e:?}"))
}

fn env_for(pv: u64) -> Result<Env> {
    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(pv), Chain::Mainnet);
    let natives = sui_move_natives_latest::all_natives(true, &cfg);
    let runtime = sui_adapter_latest::adapter::new_move_runtime(natives, &cfg).map_err(|e| anyhow!("{e:?}"))?;
    Ok(Env { pv, gm: cfg.gas_model_version(), cfg, runtime })
}

#[derive(Clone)]
struct Call {
    root: AccountAddress,
    module: ModuleId,
    function: Identifier,
    fdef: u16,
    tys: Vec<TypeTag>,
    /// (is_ref, is_mut, bcs) per parameter; for references the bytes are the referent.
    args: Vec<(bool, bool, Vec<u8>)>,
    /// Value type of each parameter (the referent for references), defining ids.
    arg_tags: Vec<TypeTag>,
    ret_tags: Vec<TypeTag>,
    /// 0 value, 1 `&`, 2 `&mut` per return; `ret_tags` holds the referent's tag.
    ret_kinds: Vec<u8>,
    budget: u64,
    pv: u64,
    /// cut mutants: arguments made malformed on purpose, run without the layout pre-check
    arg_error: bool,
}

struct Outcome {
    truth: serde_json::Value,
    trace: Option<Vec<u8>>,
    used: u64,
    ok: bool,
}

fn vm_error_json(e: &VMError) -> serde_json::Value {
    let loc = match e.location() {
        Location::Undefined => serde_json::json!("undefined"),
        Location::Module(id) => serde_json::json!(format!("module:{}::{}", id.address().to_hex(), id.name())),
        Location::Package(a) => serde_json::json!(format!("package:{}", a.to_hex())),
    };
    serde_json::json!({
        "major": e.major_status() as u64,
        "sub": e.sub_status(),
        "loc": loc,
        "off": e.offsets().iter().map(|(f, o)| vec![f.0 as u64, *o as u64]).collect::<Vec<_>>(),
    })
}

/// Re-runs a call with tracing when it is picked for the trace suite and short enough
/// (traces cost about 1 KB per instruction).
fn traced(store: &Store, env: &Env, c: &Call, o: Outcome, pick: bool) -> Result<Outcome> {
    if pick && o.truth["ins"].as_u64().unwrap_or(u64::MAX) <= TRACE_MAX_INS {
        run_call(store, env, c, true)
    } else {
        Ok(o)
    }
}

fn run_call(store: &Store, env: &Env, c: &Call, trace: bool) -> Result<Outcome> {
    let root = store.by_version.get(&c.root).ok_or_else(|| anyhow!("root package"))?;
    let link = LinkageContext::new(root.sp.linkage_table.clone().into_iter().collect()).map_err(|e| anyhow!("{e:?}"))?;
    let exts = native_extensions(&env.cfg)?;
    let mut vm = env.runtime.make_vm_with_native_extensions(store, link, exts.clone()).map_err(|e| anyhow!("make_vm: {e:?}"))?;
    let ty_args = c.tys.iter().map(|t| vm.load_type(t)).collect::<Result<Vec<_>, _>>().map_err(|e| anyhow!("load_type: {e:?}"))?;
    // Arguments: values by layout; references point into a heap the caller owns.
    let mut heap = BaseHeap::new();
    let mut args = vec![];
    let mut ref_slots = vec![];
    for (i, (is_ref, is_mut, bytes)) in c.args.iter().enumerate() {
        let tag = &c.arg_tags[i];
        let layout = vm.runtime_type_layout(tag).map_err(|e| anyhow!("layout: {e:?}"))?;
        let v = Value::simple_deserialize(bytes, &layout).ok_or_else(|| anyhow!("arg {i} does not deserialize"))?;
        if *is_ref {
            let slot = heap.allocate_value(v).map_err(|e| anyhow!("{e:?}"))?;
            args.push(heap.borrow_loc(slot).map_err(|e| anyhow!("{e:?}"))?);
            if *is_mut {
                ref_slots.push((i, slot, layout));
            }
        } else {
            args.push(v);
        }
    }
    let mut gs = GasStatus::new(cost_table_for_version(env.gm), c.budget, 1, env.gm);
    let mut tb = if trace { Some(MoveTraceBuilder::new()) } else { None };
    let res = vm.execute_function_bypass_visibility(&c.module, &c.function, ty_args, args, &mut SuiGasMeter(&mut gs), tb.as_mut());
    let gas_left: u64 = gs.gas_left.into();
    let mut j = serde_json::json!({
        "gas_left": gas_left,
        "used": gs.gas_used_pre_gas_price(),
        "ins": gs.instructions_executed(),
        "hwm_h": gs.stack_height_high_water_mark(),
        "hwm_s": gs.stack_size_high_water_mark(),
        "cur_h": gs.stack_height_current(),
        "cur_s": gs.stack_size_current(),
        "natives": gs.num_native_calls,
    });
    let ok = res.is_ok();
    match res {
        Ok(vals) => {
            let mut rets = vec![];
            if vals.len() != c.ret_tags.len() {
                bail!("return count");
            }
            for ((v, tag), kind) in vals.iter().zip(c.ret_tags.iter()).zip(c.ret_kinds.iter()) {
                let layout = vm.runtime_type_layout(tag).map_err(|e| anyhow!("{e:?}"))?;
                // A returned reference: its referent's bytes.
                let owned;
                let x = if *kind == 0 {
                    v
                } else {
                    let r: Reference = v.copy_value().value_as().map_err(|e| anyhow!("{e:?}"))?;
                    owned = r.read_ref().map_err(|e| anyhow!("{e:?}"))?;
                    &owned
                };
                rets.push(hex::encode(x.typed_serialize(&layout).ok_or_else(|| anyhow!("return serialize {}::{}", c.module, c.function))?));
            }
            let mut muts = vec![];
            for (i, slot, layout) in ref_slots {
                let v = heap.take_loc(slot).map_err(|e| anyhow!("{e:?}"))?;
                muts.push(serde_json::json!([i, hex::encode(v.typed_serialize(&layout).ok_or_else(|| anyhow!("mut serialize"))?)]));
            }
            j["st"] = "ok".into();
            j["ret"] = rets.into();
            j["mut"] = muts.into();
        }
        Err(e) => {
            j["st"] = "err".into();
            j["err"] = vm_error_json(&e);
        }
    }
    j["rt"] = finish_json(&vm, &exts)?;
    let trace = tb.map(|t| t.into_trace().into_compressed_json_bytes());
    Ok(Outcome { truth: j, trace, used: gs.gas_used_pre_gas_price(), ok })
}

/// `ObjectRuntime::finish` after the call (whatever its status), in the sui-natives truth
/// format (tools/truth/sui-natives/src/vm.rs `run_in`).
fn finish_json(vm: &move_vm_runtime::execution::vm::MoveVM, exts: &move_vm_runtime::natives::extensions::NativeExtensions<'_>) -> Result<serde_json::Value> {
    use sui_move_natives_latest::object_runtime::{MoveAccumulatorAction, MoveAccumulatorValue, ObjectRuntime};
    let ort = exts.borrow_mut().remove::<ObjectRuntime>().map_err(|e| anyhow!("{e:?}"))?;
    Ok(match ort.finish() {
        Err(e) => {
            let k = format!("{:?}", e.kind());
            let k = k.split(|c: char| c == ' ' || c == '{' || c == '(').next().unwrap_or("").to_string();
            serde_json::json!({"err": k})
        }
        Ok(r) => {
            let lay = |t: &TypeTag| -> Result<MoveTypeLayout> { vm.runtime_type_layout(t).map_err(|e| anyhow!("layout {t}: {e:?}")) };
            let mut writes = Vec::new();
            for (id, (owner, ty, v)) in &r.writes {
                let st: StructTag = ty.clone().into();
                let tt = TypeTag::Struct(Box::new(st.clone()));
                writes.push(serde_json::json!([hex::encode(id), hex::encode(bcs::to_bytes(owner)?), hex::encode(bcs::to_bytes(&st)?),
                    hex::encode(v.typed_serialize(&lay(&tt)?).context("write value")?)]));
            }
            let mut events = Vec::new();
            for (st, v) in &r.user_events {
                let tt = TypeTag::Struct(Box::new(st.clone()));
                events.push(serde_json::json!([hex::encode(bcs::to_bytes(st)?), hex::encode(v.typed_serialize(&lay(&tt)?).context("event value")?)]));
            }
            let acc: Vec<_> = r.accumulator_events.iter().map(|e| {
                let (k, n) = match e.value { MoveAccumulatorValue::U64(n) => (0, n), MoveAccumulatorValue::EventRef(n) => (1, n) };
                let a = match e.action { MoveAccumulatorAction::Merge => 0, MoveAccumulatorAction::Split => 1 };
                serde_json::json!([hex::encode(e.accumulator_id), a, hex::encode(e.target_addr), hex::encode(bcs::to_bytes(&e.target_ty).unwrap()), k, n])
            }).collect();
            let loaded: Vec<_> = r.loaded_child_objects.iter().map(|(id, l)| serde_json::json!([hex::encode(id), l.version.value(), l.is_modified])).collect();
            serde_json::json!({"ok": {
                "writes": writes, "events": events, "acc": acc, "loaded": loaded,
                "created": r.created_object_ids.iter().map(hex::encode).collect::<Vec<_>>(),
                "deleted": r.deleted_object_ids.iter().map(hex::encode).collect::<Vec<_>>(),
                "settle": [r.settlement_input_sui, r.settlement_output_sui],
            }})
        }
    })
}

fn call_json(c: &Call, id: usize, gm: u64) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "pv": c.pv,
        "gm": gm,
        "root": c.root.to_hex(),
        "module": format!("{}::{}", c.module.address().to_hex(), c.module.name()),
        "fn": c.function.as_str(),
        "fdef": c.fdef,
        "tys": c.tys.iter().map(|t| t.to_canonical_string(true)).collect::<Vec<_>>(),
        "tys_bcs": c.tys.iter().map(|t| hex::encode(bcs::to_bytes(t).unwrap())).collect::<Vec<_>>(),
        "args": c.args.iter().map(|(r, m, b)| serde_json::json!([if *m { "mut" } else if *r { "ref" } else { "val" }, hex::encode(b)])).collect::<Vec<_>>(),
        "arg_tys": c.arg_tags.iter().map(|t| hex::encode(bcs::to_bytes(t).unwrap())).collect::<Vec<_>>(),
        "ret_tys": c.ret_tags.iter().map(|t| hex::encode(bcs::to_bytes(t).unwrap())).collect::<Vec<_>>(),
        "ret_kinds": c.ret_kinds.iter().map(|k| ["val", "ref", "mut"][*k as usize]).collect::<Vec<_>>(),
        "budget": c.budget,
    })
}

fn parse_call(v: &serde_json::Value) -> Result<Call> {
    let s = |k: &str| v[k].as_str().ok_or_else(|| anyhow!("{k}"));
    let module = s("module")?;
    let (a, n) = module.split_once("::").ok_or_else(|| anyhow!("module"))?;
    Ok(Call {
        root: AccountAddress::from_hex(s("root")?)?,
        module: ModuleId::new(AccountAddress::from_hex(a)?, Identifier::new(n)?),
        function: Identifier::new(s("fn")?)?,
        fdef: v["fdef"].as_u64().unwrap_or(0) as u16,
        tys: v["tys_bcs"].as_array().unwrap().iter().map(|t| Ok(bcs::from_bytes(&hex::decode(t.as_str().unwrap())?)?)).collect::<Result<_>>()?,
        args: v["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                let k = a[0].as_str().unwrap();
                Ok((k != "val", k == "mut", hex::decode(a[1].as_str().unwrap())?))
            })
            .collect::<Result<_>>()?,
        arg_tags: v["arg_tys"].as_array().unwrap().iter().map(|t| Ok(bcs::from_bytes(&hex::decode(t.as_str().unwrap())?)?)).collect::<Result<_>>()?,
        ret_tags: v["ret_tys"].as_array().unwrap().iter().map(|t| Ok(bcs::from_bytes(&hex::decode(t.as_str().unwrap())?)?)).collect::<Result<_>>()?,
        ret_kinds: match v["ret_kinds"].as_array() {
            Some(a) => a.iter().map(|k| match k.as_str() { Some("ref") => 1, Some("mut") => 2, _ => 0 }).collect(),
            None => vec![0; v["ret_tys"].as_array().unwrap().len()],
        },
        budget: v["budget"].as_u64().unwrap(),
        pv: v["pv"].as_u64().unwrap(),
        arg_error: false,
    })
}

// ---------------------------------------------------------------------------------------------
// build

fn cmd_build(args: &[String]) -> Result<()> {
    let corpus = PathBuf::from(args.first().ok_or_else(|| anyhow!("corpus dir"))?);
    let out = PathBuf::from(args.get(1).ok_or_else(|| anyhow!("vectors dir"))?);
    let sui = PathBuf::from(std::env::var("ZUI_SUI_SRC").map_err(|_| anyhow!("ZUI_SUI_SRC"))?);
    let t0 = Instant::now();
    let mut all = framework_packages(&sui)?;
    let user = corpus_packages(&corpus)?;
    let synth = synth_packages(&sui)?;
    eprintln!("{} framework packages, {} corpus package objects, {} synthetic", all.len(), user.len(), synth.len());
    all.extend(user);
    all.extend(synth);
    let every: BTreeMap<AccountAddress, Pkg> = all.iter().map(|p| (p.sp.version_id, p.clone())).collect();
    let by = closed_packages(all);
    eprintln!("{} packages with a closed linkage", by.len());
    let store = Store { by_version: by };
    let envs: Vec<Env> = pvs().iter().map(|pv| env_for(*pv)).collect::<Result<_>>()?;
    let env141 = envs.last().unwrap();

    // Load every package once through the VM (verification + JIT); drop those that fail.
    let mut loadable = BTreeSet::new();
    for (vid, p) in &store.by_version {
        let link = LinkageContext::new(p.sp.linkage_table.clone().into_iter().collect());
        let ok = link.map(|l| env141.runtime.make_vm(&store, l).is_ok()).unwrap_or(false);
        if ok {
            loadable.insert(*vid);
        }
    }
    eprintln!("{} packages load in the VM", loadable.len());

    // move-vm-load: make_vm with every package (closed linkage or not) as the root.
    if !v142() {
        let every_store = Store { by_version: every.clone() };
        let dir = out.join("move-vm-load");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        let mut f = std::io::BufWriter::new(std::fs::File::create(dir.join("items.jsonl"))?);
        let (mut n_ok, mut n_err) = (0u64, 0u64);
        for (vid, p) in &every {
            let truth = match LinkageContext::new(p.sp.linkage_table.clone().into_iter().collect()) {
                Err(e) => serde_json::json!({"st": "err", "err": vm_error_json(&e)}),
                Ok(l) => match env141.runtime.make_vm(&every_store, l) {
                    Ok(_) => serde_json::json!({"st": "ok"}),
                    Err(e) => {
                        if std::env::var("ZUI_TRUTH_DEBUG").is_ok() {
                            eprintln!("load {}: {:?}", vid.to_hex(), e);
                        }
                        serde_json::json!({"st": "err", "err": vm_error_json(&e)})
                    }
                },
            };
            if truth["st"] == "ok" {
                n_ok += 1;
            } else {
                n_err += 1;
            }
            writeln!(f, "{}", serde_json::json!({"root": vid.to_hex(), "pv": top_pv(), "src": p.src, "truth": truth}))?;
        }
        f.flush()?;
        let pk: Vec<&Pkg> = every.values().collect();
        write_packages(&dir.join("packages.bin"), &pk)?;
        eprintln!("move-vm-load: {} roots ({} load, {} refused)", every.len(), n_ok, n_err);
    }
    let mut modules: BTreeMap<AccountAddress, BTreeMap<String, CompiledModule>> = BTreeMap::new();
    for (vid, p) in &store.by_version {
        let mut mm = BTreeMap::new();
        for (n, b) in &p.sp.modules {
            mm.insert(n.to_string(), CompiledModule::deserialize_with_defaults(b).map_err(|e| anyhow!("{e:?}"))?);
        }
        modules.insert(*vid, mm);
    }
    let l = Loaded { store, modules };

    // Calls: every non-native function of every loadable package that only reaches natives deepwave
    // implements.
    let mut calls: Vec<Call> = vec![];
    let mut skipped: BTreeMap<&'static str, u64> = BTreeMap::new();
    for vid in &loadable {
        let root = &l.store.by_version[vid];
        let mut memo = HashMap::new();
        for (mname, m) in &l.modules[vid] {
            for (fi, fd) in m.function_defs.iter().enumerate() {
                if fd.code.is_none() {
                    continue;
                }
                let h = m.function_handle_at(fd.function);
                let fname = m.identifier_at(h.name).to_owned();
                if reaches_native(&l, root, root, m, fi, &mut memo) {
                    *skipped.entry("reaches_unimplemented_native").or_default() += 1;
                    continue;
                }
                let ret = m.signature_at(h.return_);
                let params = m.signature_at(h.parameters);
                if params.0.iter().any(|t| matches!(t, SignatureToken::Signer)) {
                    *skipped.entry("signer_param").or_default() += 1;
                    continue;
                }
                let seed = fnv(&format!("{}::{}::{}", vid.to_hex(), mname, fname));
                let mut r = Rng(seed);
                let synth = root.src == "synth";
                let seeds = if synth { SYNTH_SEEDS_PER_FN } else { SEEDS_PER_FN + 1 };
                for s in 0..seeds {
                    // type arguments
                    let mut tys = vec![];
                    for c in &h.type_parameters {
                        let cands = ty_candidates(*c);
                        tys.push(cands[r.below(cands.len() as u64) as usize].clone());
                    }
                    let pv = if synth {
                        pvs()[s % pvs().len()]
                    } else if s < SEEDS_PER_FN {
                        top_pv()
                    } else {
                        pvs()[(seed % 4) as usize % pvs().len()]
                    };
                    let mut call = Call {
                        root: *vid,
                        module: ModuleId::new(root.sp.original_id, Identifier::new(mname.as_str())?),
                        function: fname.clone(),
                        fdef: fi as u16,
                        tys: tys.clone(),
                        args: vec![],
                        arg_tags: vec![],
                        ret_tags: vec![],
                        ret_kinds: vec![],
                        budget: BUDGET,
                        pv,
                        arg_error: false,
                    };
                    let mut good = true;
                    for p in &params.0 {
                        let (is_ref, is_mut, inner) = match p {
                            SignatureToken::Reference(t) => (true, false, &**t),
                            SignatureToken::MutableReference(t) => (true, true, &**t),
                            t => (false, false, t),
                        };
                        let Some(tag) = token_tag(&l, root, m, inner, &tys) else {
                            good = false;
                            break;
                        };
                        call.args.push((is_ref, is_mut, vec![]));
                        call.arg_tags.push(tag);
                    }
                    if !good {
                        *skipped.entry("param_type").or_default() += 1;
                        break;
                    }
                    for t in &ret.0 {
                        let (kind, inner) = match t {
                            SignatureToken::Reference(t) => (1u8, &**t),
                            SignatureToken::MutableReference(t) => (2u8, &**t),
                            t => (0u8, t),
                        };
                        match token_tag(&l, root, m, inner, &tys) {
                            Some(tag) => {
                                call.ret_tags.push(tag);
                                call.ret_kinds.push(kind);
                            }
                            None => good = false,
                        }
                    }
                    if !good {
                        *skipped.entry("ret_type").or_default() += 1;
                        break;
                    }
                    calls.push(call);
                }
            }
        }
    }
    eprintln!("{} call shapes; skipped {:?}", calls.len(), skipped);

    // Fill argument bytes from layouts (one VM per root package), then run and record truth.
    let calls: Vec<Call> = calls
        .par_iter()
        .filter_map(|c| {
            let root = &l.store.by_version[&c.root];
            let link = LinkageContext::new(root.sp.linkage_table.clone().into_iter().collect()).ok()?;
            let vm = env141.runtime.make_vm(&l.store, link).ok()?;
            let mut r = Rng(fnv(&format!("{}{}{}{}", c.root, c.module, c.function, c.pv)) ^ c.args.len() as u64 ^ (c.tys.len() as u64) << 7 ^ hashb(&c.args));
            let mut c2 = c.clone();
            for (a, tag) in c2.args.iter_mut().zip(c.arg_tags.iter()) {
                let layout = vm.runtime_type_layout(tag).ok()?;
                let mut b = vec![];
                gen_value(&mut r, &layout, 0, &mut b);
                a.2 = b;
            }
            Some(c2)
        })
        .collect();
    eprintln!("{} calls with arguments", calls.len());

    let env_of = |pv: u64| envs.iter().find(|e| e.pv == pv).unwrap();
    let harness_errs: std::sync::Mutex<BTreeMap<String, u64>> = Default::default();
    let results: Vec<Option<(Call, Outcome)>> = calls
        .par_iter()
        .enumerate()
        .map(|(i, c)| {
            let env = env_of(c.pv);
            match run_call(&l.store, env, c, false).and_then(|o| traced(&l.store, env, c, o, i % TRACE_EVERY == 0)) {
                Ok(o) => Some((c.clone(), o)),
                Err(e) => {
                    let m = format!("{e}");
                    *harness_errs.lock().unwrap().entry(m.chars().take(400).collect::<String>()).or_insert(0u64) += 1;
                    None
                }
            }
        })
        .collect();
    eprintln!("calls the harness could not set up: {:?}", harness_errs.lock().unwrap());
    // Out-of-gas variants: every successful call that used at least 2 units, rerun with half.
    let mut items: Vec<(Call, Outcome)> = vec![];
    let mut oog: Vec<Call> = vec![];
    // Also: the last partial unit (budget = whole units used, when the call used at least one)
    // and, for every tenth call, a zero budget (out of gas on the first charge).
    let mut seen_calls: BTreeSet<String> = BTreeSet::new();
    for (k, (c, o)) in results.into_iter().flatten().enumerate() {
        if !seen_calls.insert(call_json(&c, 0, 0).to_string()) {
            continue; // identical call already recorded (zero-argument functions, repeated seeds)
        }
        if o.ok {
            let internal = BUDGET * 1000 - o.truth["gas_left"].as_u64().unwrap_or(0);
            let mut budgets = BTreeSet::new();
            if o.used >= 2 {
                budgets.insert(o.used / 2);
            }
            if internal >= 1000 {
                budgets.insert(internal / 1000);
            }
            if k % 10 == 0 {
                budgets.insert(0);
            }
            for b in budgets {
                let mut c2 = c.clone();
                c2.budget = b;
                oog.push(c2);
            }
        }
        items.push((c, o));
    }
    let oog_res: Vec<Option<(Call, Outcome)>> = oog
        .par_iter()
        .enumerate()
        .map(|(i, c)| {
            let env = env_of(c.pv);
            run_call(&l.store, env, c, false).and_then(|o| traced(&l.store, env, c, o, i % TRACE_EVERY == 3)).ok().map(|o| (c.clone(), o))
        })
        .collect();
    items.extend(oog_res.into_iter().flatten());

    // Write.
    let (gas_dir, trace_dir) = if v142() { (out.join("move-vm-gas/v142"), out.join("move-vm-trace/v142")) } else { (out.join("move-vm-gas"), out.join("move-vm-trace")) };
    let _ = std::fs::remove_dir_all(&gas_dir);
    let _ = std::fs::remove_dir_all(&trace_dir);
    std::fs::create_dir_all(&gas_dir)?;
    std::fs::create_dir_all(trace_dir.join("trace"))?;
    // The native list these vectors were drawn with: the suites refuse vectors whose list
    // differs from src/natives/table.zig.
    let mut nl = String::new();
    for n in zui_natives() {
        nl.push_str(n);
        nl.push('\n');
    }
    std::fs::write(gas_dir.join("natives.txt"), &nl)?;
    let used_roots: BTreeSet<AccountAddress> = items.iter().map(|(c, _)| c.root).collect();
    let mut need: BTreeSet<AccountAddress> = BTreeSet::new();
    for r in &used_roots {
        for v in l.store.by_version[r].sp.linkage_table.values() {
            need.insert(*v);
        }
    }
    let pk: Vec<&Pkg> = need.iter().map(|v| &l.store.by_version[v]).collect();
    write_packages(&gas_dir.join("packages.bin"), &pk)?;
    let mut f = std::io::BufWriter::new(std::fs::File::create(gas_dir.join("calls.jsonl"))?);
    let mut ft = std::io::BufWriter::new(std::fs::File::create(trace_dir.join("calls.jsonl"))?);
    let (mut n_ok, mut n_err, mut n_trace) = (0u64, 0u64, 0u64);
    let mut majors: BTreeMap<u64, u64> = BTreeMap::new();
    for (id, (c, o)) in items.iter().enumerate() {
        let gm = env_of(c.pv).gm;
        let mut j = call_json(c, id, gm);
        j["truth"] = o.truth.clone();
        if o.ok {
            n_ok += 1;
        } else {
            n_err += 1;
            *majors.entry(o.truth["err"]["major"].as_u64().unwrap_or(0)).or_default() += 1;
        }
        writeln!(f, "{}", j)?;
        if let Some(t) = &o.trace {
            std::fs::write(trace_dir.join("trace").join(format!("{id}.json.zst")), t)?;
            writeln!(ft, "{}", j)?;
            n_trace += 1;
        }
    }
    f.flush()?;
    ft.flush()?;
    let pkg_src: BTreeMap<&str, usize> = pk.iter().fold(BTreeMap::new(), |mut m, p| {
        *m.entry(p.src).or_default() += 1;
        m
    });
    eprintln!(
        "{} items ({} ok, {} err {:?}), {} traced, {} packages {:?}, {:.1}s",
        items.len(),
        n_ok,
        n_err,
        majors,
        n_trace,
        pk.len(),
        pkg_src,
        t0.elapsed().as_secs_f64()
    );
    Ok(())
}

fn hashb(a: &[(bool, bool, Vec<u8>)]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for (_, _, b) in a {
        for x in b {
            h ^= *x as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    h
}

// ---------------------------------------------------------------------------------------------
// run / bench

fn load_vectors(dir: &Path) -> Result<(Store, Vec<serde_json::Value>)> {
    let pk = read_packages(&dir.join("move-vm-gas/packages.bin"))?;
    let store = Store { by_version: pk.into_iter().map(|p| (p.sp.version_id, p)).collect() };
    let text = std::fs::read_to_string(dir.join("move-vm-gas/calls.jsonl"))?;
    let lines = text.lines().map(serde_json::from_str).collect::<std::result::Result<Vec<serde_json::Value>, _>>()?;
    Ok((store, lines))
}

fn cmd_run(args: &[String]) -> Result<()> {
    let dir = PathBuf::from(args.first().ok_or_else(|| anyhow!("vectors dir"))?);
    let id: usize = args.get(1).ok_or_else(|| anyhow!("id"))?.parse()?;
    let (store, lines) = load_vectors(&dir)?;
    let v = &lines[id];
    let c = parse_call(v)?;
    let env = env_for(c.pv)?;
    let o = run_call(&store, &env, &c, true)?;
    println!("{}", o.truth);
    if let Some(t) = o.trace {
        let r = move_trace_format::format::MoveTraceReader::new(&t[..])?;
        for e in r {
            println!("{}", serde_json::to_string(&e?)?);
        }
    }
    Ok(())
}

/// `bench call --iters N --list <file>`: the list names calls.jsonl files (normally one); every
/// call is executed on one thread, per pass, and the median pass is reported per call.
/// `bench trace` / `bench trace-instr`: the move-vm-trace calls at protocol 141, each run with a
/// `MoveTraceBuilder` to its trace bytes (move-trace-format's only output form).
fn bench_trace(store: &Store, dir: &Path, name: &str, iters: usize) -> Result<()> {
    let text = std::fs::read_to_string(dir.join("move-vm-trace").join("calls.jsonl"))?;
    let mut calls = vec![];
    for l in text.lines().filter(|l| !l.is_empty()) {
        let v: serde_json::Value = serde_json::from_str(l)?;
        let c = parse_call(&v)?;
        if c.pv == 141 {
            calls.push(c);
        }
    }
    let env = env_for(141)?;
    let mut ins = 0u64;
    for c in &calls {
        let o = run_call(store, &env, c, true)?;
        ins += o.truth["ins"].as_u64().unwrap_or(0);
    }
    let mut passes = vec![];
    for _ in 0..iters {
        let t = Instant::now();
        for c in &calls {
            std::hint::black_box(run_call(store, &env, c, true)?.trace);
        }
        passes.push(t.elapsed().as_nanos() as f64);
    }
    passes.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let med = passes[passes.len() / 2];
    let (unit, units) = if name == "trace" { ("call", calls.len() as u64) } else { ("instr", ins) };
    println!(
        "{}",
        serde_json::json!({"impl": "rust", "bench": name, "unit": unit, "units": units, "ns_per_unit": med / units as f64, "min_ns": passes[0], "iters": iters})
    );
    Ok(())
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
                list = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            _ => bail!("unknown arg {}", args[i]),
        }
    }
    let list = std::fs::read_to_string(list.ok_or_else(|| anyhow!("--list"))?)?;
    let first = list.lines().next().ok_or_else(|| anyhow!("empty list"))?;
    let dir = Path::new(first).parent().and_then(|p| p.parent()).ok_or_else(|| anyhow!("list path"))?;
    let (store, lines) = load_vectors(dir)?;
    if name == "trace" || name == "trace-instr" {
        return bench_trace(&store, dir, &name, iters);
    }
    let calls: Vec<Call> = lines.iter().map(parse_call).collect::<Result<_>>()?;
    // `-interp` keeps calls that reach no native, `-native` the others.
    let (base, sel) = name.split_once('-').map(|(b, s)| (b.to_string(), s.to_string())).unwrap_or((name.clone(), String::new()));
    let calls: Vec<Call> = lines
        .iter()
        .zip(calls)
        .filter(|(l, c)| {
            let n = l["truth"]["natives"].as_u64().unwrap_or(0);
            c.pv == 141 && c.budget == BUDGET && match sel.as_str() { "interp" => n == 0, "native" => n > 0, _ => true }
        })
        .map(|(_, c)| c)
        .collect();
    let env = env_for(141)?;
    // warm-up (JIT and caches) and instruction count
    let mut ins = 0u64;
    for c in &calls {
        let o = run_call(&store, &env, c, false)?;
        ins += o.truth["ins"].as_u64().unwrap_or(0);
    }
    let mut passes = vec![];
    for _ in 0..iters {
        let t = Instant::now();
        for c in &calls {
            run_call(&store, &env, c, false)?;
        }
        passes.push(t.elapsed().as_nanos() as f64);
    }
    passes.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let med = passes[passes.len() / 2];
    let (unit, units) = match base.as_str() {
        "call" => ("call", calls.len() as u64),
        "instr" => ("instr", ins),
        _ => bail!("bench name: call | instr [-interp | -native]"),
    };
    println!(
        "{}",
        serde_json::json!({"impl": "rust", "bench": name, "unit": unit, "units": units, "ns_per_unit": med / units as f64, "iters": iters})
    );
    let _ = Arc::new(());
    let _ = IdentStr::new("x");
    let _ = Visibility::Public;
    Ok(())
}
