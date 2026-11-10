//! `cut <v0|v1|v2|v3> <pv> <vectors>`: the protocol-141 calls of move-vm-gas re-run on one of
//! Mysten's older execution cuts (sui-execution/historical-versions/vN with the Move VM of
//! external-crates/move/historical-versions/vN), at protocol `pv` on mainnet, over the framework
//! snapshot of that protocol version.
//!
//! The old cuts use the session API: `MoveVM::new_with_config` (sui-adapter-vN `new_move_vm`), a
//! session over a resolver that implements the cut's `LinkageResolver` (`View` below, the same
//! relocation rules as sui-adapter's `LinkageView`), `execute_function_bypass_visibility` with the
//! cut's `SuiGasMeter` over sui-types `GasStatus`, and the cut's `ObjectRuntime` from
//! `new_native_extensions`. Only v3 can trace (move-trace-format); v0..v2 have no tracer.
//!
//! A call the old cut cannot load (newer binary format, a function, type or native missing from
//! the old framework, a changed signature or argument layout) cannot happen on mainnet at that
//! protocol version: it is dropped and counted by reason. Errors raised while executing are truth.
use super::*;
use sui_types::base_types::ObjectID;
use sui_types::object::Owner;

pub(crate) enum Res {
    Drop(String),
    Done(Outcome),
}

/// The resolver a cut's session runs over: modules from the store, relocation through the root
/// package's linkage table, defining ids from the type origin tables (sui-adapter LinkageView).
pub(crate) struct View<'a> {
    store: &'a Store,
    storage_id: AccountAddress,
    runtime_id: AccountAddress,
    link: &'a BTreeMap<AccountAddress, AccountAddress>,
}

impl<'a> View<'a> {
    fn new(store: &'a Store, root: AccountAddress) -> Option<Self> {
        let p = store.by_version.get(&root)?;
        Some(View { store, storage_id: p.sp.version_id, runtime_id: p.sp.original_id, link: &p.sp.linkage_table })
    }
    fn relocate_(&self, m: &ModuleId) -> Result<ModuleId> {
        if *m.address() == self.runtime_id {
            return Ok(ModuleId::new(self.storage_id, m.name().to_owned()));
        }
        let to = self.link.get(m.address()).ok_or_else(|| anyhow!("missing linkage for {m} in context {}", self.storage_id))?;
        Ok(ModuleId::new(*to, m.name().to_owned()))
    }
    fn defining_(&self, m: &ModuleId, s: &IdentStr) -> Result<ModuleId> {
        let at = self.relocate_(m)?;
        let p = self.store.by_version.get(at.address()).ok_or_else(|| anyhow!("missing package {}", at.address()))?;
        let key = IntraPackageName { module_name: m.name().to_owned(), type_name: s.to_owned() };
        let d = p.sp.type_origin_table.get(&key).ok_or_else(|| anyhow!("{m}::{s} not in type origin table"))?;
        Ok(ModuleId::new(*d, m.name().to_owned()))
    }
}

impl ModuleResolver for View<'_> {
    type Error = anyhow::Error;
    fn get_packages_static<const N: usize>(&self, ids: [AccountAddress; N]) -> Result<[Option<SerializedPackage>; N]> {
        (&self.store).get_packages_static(ids)
    }
    fn get_packages<'b>(&self, ids: impl ExactSizeIterator<Item = &'b AccountAddress>) -> Result<Vec<Option<SerializedPackage>>> {
        (&self.store).get_packages(ids)
    }
}

macro_rules! linkage_resolver {
    ($types:ident) => {
        impl $types::data_store::LinkageResolver for View<'_> {
            type Error = anyhow::Error;
            fn link_context(&self) -> AccountAddress {
                self.storage_id
            }
            fn relocate(&self, m: &ModuleId) -> Result<ModuleId> {
                self.relocate_(m)
            }
            fn defining_module(&self, m: &ModuleId, s: &IdentStr) -> Result<ModuleId> {
                self.defining_(m, s)
            }
        }
    };
}
linkage_resolver!(move_vm_types_v0);
linkage_resolver!(move_vm_types_v1);
linkage_resolver!(move_vm_types_v2);
linkage_resolver!(move_vm_types_v3);

fn storage() -> &'static sui_types::in_memory_storage::InMemoryStorage {
    static EMPTY: std::sync::OnceLock<sui_types::in_memory_storage::InMemoryStorage> = std::sync::OnceLock::new();
    EMPTY.get_or_init(|| sui_types::in_memory_storage::InMemoryStorage::new(vec![]))
}

fn metrics() -> Arc<sui_types::metrics::ExecutionMetrics> {
    static METRICS: std::sync::OnceLock<Arc<sui_types::metrics::ExecutionMetrics>> = std::sync::OnceLock::new();
    METRICS.get_or_init(|| Arc::new(sui_types::metrics::ExecutionMetrics::new(&prometheus::Registry::new()))).clone()
}

/// The latest path's transaction context (DEFAULT_CTX). v0..v2 pass the context as a Move argument
/// (the call's own TxContext bytes), so only v3 uses this one.
fn tx_context(cfg: &ProtocolConfig) -> sui_types::base_types::TxContext {
    sui_types::base_types::TxContext::new_from_components(
        &sui_types::base_types::SuiAddress::from_bytes([0x5a; 32]).unwrap(),
        &sui_types::digests::TransactionDigest::new([0xd1; 32]),
        &EPOCH,
        1_762_400_000_000,
        538,
        750,
        50_000_000,
        None,
        cfg,
    )
}
const EPOCH: u64 = 1304;

/// The `rt` field (sui-natives truth format) from parts every cut can produce.
#[allow(clippy::too_many_arguments)]
fn rt_json(
    writes: Vec<(ObjectID, Owner, StructTag, Vec<u8>)>,
    events: Vec<(StructTag, Vec<u8>)>,
    acc: Vec<serde_json::Value>,
    loaded: Vec<(ObjectID, u64, bool)>,
    created: Vec<ObjectID>,
    deleted: Vec<ObjectID>,
    settle: [u64; 2],
) -> Result<serde_json::Value> {
    let mut w = vec![];
    for (id, owner, st, v) in writes {
        w.push(serde_json::json!([hex::encode(id), hex::encode(bcs::to_bytes(&owner)?), hex::encode(bcs::to_bytes(&st)?), hex::encode(v)]));
    }
    let mut e = vec![];
    for (st, v) in events {
        e.push(serde_json::json!([hex::encode(bcs::to_bytes(&st)?), hex::encode(v)]));
    }
    Ok(serde_json::json!({"ok": {
        "writes": w, "events": e, "acc": acc,
        "loaded": loaded.iter().map(|(id, v, m)| serde_json::json!([hex::encode(id), v, m])).collect::<Vec<_>>(),
        "created": created.iter().map(hex::encode).collect::<Vec<_>>(),
        "deleted": deleted.iter().map(hex::encode).collect::<Vec<_>>(),
        "settle": settle,
    }}))
}

fn rt_err(e: &sui_types::error::ExecutionError) -> serde_json::Value {
    let k = format!("{:?}", e.kind());
    let k = k.split(|c: char| c == ' ' || c == '{' || c == '(').next().unwrap_or("").to_string();
    serde_json::json!({"err": k})
}

/// Struct addresses in a tag rewritten from defining ids to runtime (original) ids: the old
/// sessions load types by runtime id under the root's linkage (Mysten's adapter does the same by
/// switching the link context to the defining package).
fn to_runtime(t: &TypeTag, orig: &HashMap<AccountAddress, AccountAddress>) -> TypeTag {
    match t {
        TypeTag::Vector(e) => TypeTag::Vector(Box::new(to_runtime(e, orig))),
        TypeTag::Struct(s) => {
            let mut s = (**s).clone();
            s.address = *orig.get(&s.address).unwrap_or(&s.address);
            s.type_params = s.type_params.iter().map(|x| to_runtime(x, orig)).collect();
            TypeTag::Struct(Box::new(s))
        }
        t => t.clone(),
    }
}

/// What every cut needs to run calls.
pub(crate) struct Ctx {
    pub cfg: ProtocolConfig,
    pub gm: u64,
    /// defining id -> original id, from every type origin table in the store
    pub orig: HashMap<AccountAddress, AccountAddress>,
    /// The TxContext argument the adapter passes (`to_bcs_legacy_context` of DEFAULT_CTX).
    pub tx_bytes: Vec<u8>,
}

fn status(e: &VMError) -> String {
    format!("{:?}", e.major_status())
}

/// The body shared by the four cuts. Expects in scope: `rt`, `types`, `new_vm`, `extensions`,
/// `execute`, `finish_json`.
macro_rules! cut_common {
    () => {
        use types::loaded_data::runtime_types::Type as T;
        type Session<'r, 'l, 'v> = rt::session::Session<'r, 'l, &'v View<'v>>;

        fn shape(s: &Session<'_, '_, '_>, list: &[T], tys: &[T]) -> Option<Vec<(u8, TypeTag)>> {
            list.iter()
                .map(|t| {
                    let t = t.subst(tys).ok()?;
                    let (k, inner) = match t {
                        T::Reference(b) => (1u8, *b),
                        T::MutableReference(b) => (2u8, *b),
                        x => (0u8, x),
                    };
                    Some((k, s.get_type_tag(&inner).ok()?))
                })
                .collect()
        }

        pub(crate) fn run(ctx: &Ctx, store: &Store, c: &Call, trace: bool) -> Result<Res> {
            let Some(view) = View::new(store, c.root) else { return Ok(Res::Drop("package_absent".into())) };
            let vm = new_vm(&ctx.cfg)?;
            let mut s = vm.new_session_with_extensions(&view, extensions(&ctx.cfg));
            let mut tys = vec![];
            for t in &c.tys {
                match s.load_type(&to_runtime(t, &ctx.orig)) {
                    Ok(x) => tys.push(x),
                    Err(e) => return Ok(Res::Drop(format!("load_type {}", status(&e)))),
                }
            }
            let inst = match s.load_function(&c.module, &c.function, &tys) {
                Ok(i) => i,
                Err(e) => return Ok(Res::Drop(format!("load_function {}", status(&e)))),
            };
            let kind = |r: bool, m: bool| if m { 2u8 } else if r { 1 } else { 0 };
            let want_p: Vec<(u8, TypeTag)> = c.args.iter().zip(&c.arg_tags).map(|((r, m, _), t)| (kind(*r, *m), t.clone())).collect();
            let want_r: Vec<(u8, TypeTag)> = c.ret_kinds.iter().copied().zip(c.ret_tags.iter().cloned()).collect();
            if shape(&s, &inst.parameters, &tys) != Some(want_p) || shape(&s, &inst.return_, &tys) != Some(want_r) {
                return Ok(Res::Drop("signature_changed".into()));
            }
            for (i, (_, _, b)) in c.args.iter().enumerate() {
                if c.arg_error {
                    break; // the malformed argument is the point: the VM reports it
                }
                let ok = s
                    .get_type_layout(&to_runtime(&c.arg_tags[i], &ctx.orig))
                    .ok()
                    .and_then(|l| types::values::Value::simple_deserialize(b, &l))
                    .is_some();
                if !ok {
                    return Ok(Res::Drop("arg_layout".into()));
                }
            }
            let mut gs = GasStatus::new(cost_table_for_version(ctx.gm), c.budget, 1, ctx.gm);
            let mut tb = if trace { Some(MoveTraceBuilder::new()) } else { None };
            let args: Vec<&[u8]> = c.args.iter().map(|a| a.2.as_slice()).collect();
            let res = execute(&mut s, &c.module, &c.function, tys, args, &mut gs, tb.as_mut());
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
                Ok(v) => {
                    j["st"] = "ok".into();
                    j["ret"] = v.return_values.iter().map(|(b, _)| hex::encode(b)).collect::<Vec<_>>().into();
                    j["mut"] = v
                        .mutable_reference_outputs
                        .iter()
                        .map(|(i, b, _)| serde_json::json!([*i as u64, hex::encode(b)]))
                        .collect::<Vec<_>>()
                        .into();
                }
                Err(e) => {
                    j["st"] = "err".into();
                    j["err"] = vm_error_json(&e);
                }
            }
            j["rt"] = finish_json(&mut s)?;
            let trace = tb.map(|t| t.into_trace().into_compressed_json_bytes());
            Ok(Res::Done(Outcome { truth: j, trace, used: gs.gas_used_pre_gas_price(), ok }))
        }
    };
}

/// v0..v2 runtime results: writes and events carry runtime types.
macro_rules! old_value_json {
    () => {
        fn value_bytes(s: &Session<'_, '_, '_>, ty: &T, v: &types::values::Value) -> Result<Vec<u8>> {
            let l = s.type_to_type_layout(ty).map_err(|e| anyhow!("layout: {e:?}"))?;
            v.simple_serialize(&l).ok_or_else(|| anyhow!("value serialize"))
        }
        fn struct_tag(s: &Session<'_, '_, '_>, ty: &T) -> Result<StructTag> {
            match s.get_type_tag(ty).map_err(|e| anyhow!("tag: {e:?}"))? {
                TypeTag::Struct(st) => Ok(*st),
                t => bail!("non-struct object type {t}"),
            }
        }
    };
}

pub(crate) mod v0 {
    use super::*;
    use move_vm_runtime_v0 as rt;
    use move_vm_types_v0 as types;
    use sui_adapter_v0 as adapter;
    use sui_move_natives_v0 as natives;
    pub(crate) const CAN_TRACE: bool = false;

    fn new_vm(cfg: &ProtocolConfig) -> Result<rt::move_vm::MoveVM> {
        adapter::adapter::new_move_vm(natives::all_natives(true), cfg).map_err(|e| anyhow!("{e:?}"))
    }
    fn extensions(cfg: &ProtocolConfig) -> rt::native_extensions::NativeContextExtensions<'static> {
        adapter::adapter::new_native_extensions(storage(), BTreeMap::new(), true, cfg, metrics())
    }
    fn execute(
        s: &mut Session<'_, '_, '_>,
        m: &ModuleId,
        f: &IdentStr,
        tys: Vec<T>,
        args: Vec<&[u8]>,
        gs: &mut GasStatus,
        _tb: Option<&mut MoveTraceBuilder>,
    ) -> move_binary_format::errors::VMResult<rt::session::SerializedReturnValues> {
        s.execute_function_bypass_visibility(m, f, tys, args, &mut adapter::gas_meter::SuiGasMeter(gs))
    }
    cut_common!();
    old_value_json!();
    fn finish_json(s: &mut Session<'_, '_, '_>) -> Result<serde_json::Value> {
        let ort: natives::object_runtime::ObjectRuntime = s.get_native_extensions().remove();
        let r = match ort.finish(BTreeSet::new(), BTreeSet::new()) {
            Err(e) => return Ok(rt_err(&e)),
            Ok(r) => r,
        };
        let mut writes = vec![];
        let mut created = vec![];
        for (id, (kind, owner, ty, v)) in &r.writes {
            if matches!(kind, sui_types::storage::WriteKind::Create) {
                created.push(*id);
            }
            writes.push((*id, owner.clone(), struct_tag(s, ty)?, value_bytes(s, ty, v)?));
        }
        let mut events = vec![];
        for (ty, st, v) in &r.user_events {
            events.push((st.clone(), value_bytes(s, ty, v)?));
        }
        // v0 records no modified flag for loaded children.
        let loaded = r.loaded_child_objects.iter().map(|(id, v)| (*id, v.value(), false)).collect();
        let deleted = r.deletions.keys().copied().collect();
        rt_json(writes, events, vec![], loaded, created, deleted, [0, 0])
    }
}

/// v1 and v2: same shapes, ObjectRuntime takes the epoch. `$ids` walks the id sets (v1 keeps them
/// in a LinkedHashMap, v2 in an IndexSet).
macro_rules! cut_v12 {
    ($m:ident, $rt:ident, $types:ident, $adapter:ident, $natives:ident, $ids:ident) => {
        pub(crate) mod $m {
            use super::*;
            use $adapter as adapter;
            use $natives as natives;
            use $rt as rt;
            use $types as types;
            pub(crate) const CAN_TRACE: bool = false;

            fn new_vm(cfg: &ProtocolConfig) -> Result<rt::move_vm::MoveVM> {
                adapter::adapter::new_move_vm(natives::all_natives(true), cfg).map_err(|e| anyhow!("{e:?}"))
            }
            fn extensions<'r>(cfg: &'r ProtocolConfig) -> rt::native_extensions::NativeContextExtensions<'r> {
                adapter::adapter::new_native_extensions(storage(), BTreeMap::new(), true, cfg, metrics(), EPOCH)
            }
            fn execute(
                s: &mut Session<'_, '_, '_>,
                m: &ModuleId,
                f: &IdentStr,
                tys: Vec<T>,
                args: Vec<&[u8]>,
                gs: &mut GasStatus,
                _tb: Option<&mut MoveTraceBuilder>,
            ) -> move_binary_format::errors::VMResult<rt::session::SerializedReturnValues> {
                s.execute_function_bypass_visibility(m, f, tys, args, &mut adapter::gas_meter::SuiGasMeter(gs))
            }
            cut_common!();
            old_value_json!();
            fn finish_json(s: &mut Session<'_, '_, '_>) -> Result<serde_json::Value> {
                let ort: natives::object_runtime::ObjectRuntime = s.get_native_extensions().remove();
                let r = match ort.finish() {
                    Err(e) => return Ok(rt_err(&e)),
                    Ok(r) => r,
                };
                let mut writes = vec![];
                for (id, (owner, ty, v)) in &r.writes {
                    writes.push((*id, owner.clone(), struct_tag(s, ty)?, value_bytes(s, ty, v)?));
                }
                let mut events = vec![];
                for (ty, st, v) in &r.user_events {
                    events.push((st.clone(), value_bytes(s, ty, v)?));
                }
                let loaded = r.loaded_child_objects.iter().map(|(id, l)| (*id, l.version.value(), l.is_modified)).collect();
                rt_json(
                    writes,
                    events,
                    vec![],
                    loaded,
                    r.created_object_ids.$ids().copied().collect(),
                    r.deleted_object_ids.$ids().copied().collect(),
                    [0, 0],
                )
            }
        }
    };
}
cut_v12!(v1, move_vm_runtime_v1, move_vm_types_v1, sui_adapter_v1, sui_move_natives_v1, keys);
cut_v12!(v2, move_vm_runtime_v2, move_vm_types_v2, sui_adapter_v2, sui_move_natives_v2, iter);

pub(crate) mod v3 {
    use super::*;
    use move_vm_runtime_v3 as rt;
    use move_vm_types_v3 as types;
    use sui_adapter_v3 as adapter;
    use sui_move_natives_v3 as natives;
    pub(crate) const CAN_TRACE: bool = true;

    fn new_vm(cfg: &ProtocolConfig) -> Result<rt::move_vm::MoveVM> {
        adapter::adapter::new_move_vm(natives::all_natives(true, cfg), cfg).map_err(|e| anyhow!("{e:?}"))
    }
    fn extensions<'r>(cfg: &'r ProtocolConfig) -> rt::native_extensions::NativeContextExtensions<'r> {
        let tx = std::rc::Rc::new(std::cell::RefCell::new(tx_context(cfg)));
        adapter::adapter::new_native_extensions(storage(), BTreeMap::new(), true, cfg, metrics(), tx)
    }
    fn execute(
        s: &mut Session<'_, '_, '_>,
        m: &ModuleId,
        f: &IdentStr,
        tys: Vec<T>,
        args: Vec<&[u8]>,
        gs: &mut GasStatus,
        tb: Option<&mut MoveTraceBuilder>,
    ) -> move_binary_format::errors::VMResult<rt::session::SerializedReturnValues> {
        s.execute_function_bypass_visibility(m, f, tys, args, &mut adapter::gas_meter::SuiGasMeter(gs), tb)
    }
    cut_common!();
    fn finish_json(s: &mut Session<'_, '_, '_>) -> Result<serde_json::Value> {
        use natives::object_runtime::{MoveAccumulatorAction, MoveAccumulatorValue, ObjectRuntime};
        let ort: ObjectRuntime = s.get_native_extensions().remove().map_err(|e| anyhow!("{e:?}"))?;
        let r = match ort.finish() {
            Err(e) => return Ok(rt_err(&e)),
            Ok(r) => r,
        };
        let lay = |t: &TypeTag| -> Result<move_core_types::runtime_value::MoveTypeLayout> {
            s.get_type_layout(t).map_err(|e| anyhow!("layout {t}: {e:?}"))
        };
        let mut writes = vec![];
        for (id, (owner, ty, v)) in &r.writes {
            let st: StructTag = ty.clone().into();
            let tt = TypeTag::Struct(Box::new(st.clone()));
            let b = v.typed_serialize(&lay(&tt)?).ok_or_else(|| anyhow!("write value"))?;
            writes.push((*id, owner.clone(), st, b));
        }
        let mut events = vec![];
        for (st, v) in &r.user_events {
            let tt = TypeTag::Struct(Box::new(st.clone()));
            events.push((st.clone(), v.typed_serialize(&lay(&tt)?).ok_or_else(|| anyhow!("event value"))?));
        }
        let acc = r
            .accumulator_events
            .iter()
            .map(|e| {
                let (k, n) = match e.value {
                    MoveAccumulatorValue::U64(n) => (0, n),
                    MoveAccumulatorValue::EventRef(n) => (1, n),
                };
                let a = match e.action {
                    MoveAccumulatorAction::Merge => 0,
                    MoveAccumulatorAction::Split => 1,
                };
                serde_json::json!([hex::encode(e.accumulator_id), a, hex::encode(e.target_addr), hex::encode(bcs::to_bytes(&e.target_ty).unwrap()), k, n])
            })
            .collect();
        let loaded = r.loaded_child_objects.iter().map(|(id, l)| (*id, l.version.value(), l.is_modified)).collect();
        rt_json(
            writes,
            events,
            acc,
            loaded,
            r.created_object_ids.iter().copied().collect(),
            r.deleted_object_ids.iter().copied().collect(),
            [r.settlement_input_sui, r.settlement_output_sui],
        )
    }
}

// ---------------------------------------------------------------------------------------------

type RunFn = fn(&Ctx, &Store, &Call, bool) -> Result<Res>;

/// Everything a cut run needs, shared by `cut` and its trace worker.
struct Setup {
    cut: String,
    pv: u64,
    dir: PathBuf,
    run: RunFn,
    can_trace: bool,
    snap: u64,
    overlay: Vec<Pkg>,
    l: Loaded,
    ctx: Ctx,
    /// (source id, call at 141), each distinct spec once
    calls: Vec<(u64, Call)>,
    /// spec keys of the latest trace suite's calls
    traced: BTreeSet<String>,
}

fn spec_key(c: &Call) -> String {
    call_json(c, 0, 0).to_string()
}

/// Ids of the argument-error mutants: source id plus this.
const ARG_ERROR_ID: u64 = 1_000_000_000;

fn setup(args: &[String]) -> Result<Setup> {
    let cut = args.first().ok_or_else(|| anyhow!("cut: v0|v1|v2|v3"))?.clone();
    let pv: u64 = args.get(1).ok_or_else(|| anyhow!("pv"))?.parse()?;
    let dir = PathBuf::from(args.get(2).ok_or_else(|| anyhow!("vectors dir"))?);
    let sui = PathBuf::from(std::env::var("ZUI_SUI_SRC").map_err(|_| anyhow!("ZUI_SUI_SRC"))?);
    let (run, can_trace): (RunFn, bool) = match cut.as_str() {
        "v0" => (v0::run, v0::CAN_TRACE),
        "v1" => (v1::run, v1::CAN_TRACE),
        "v2" => (v2::run, v2::CAN_TRACE),
        "v3" => (v3::run, v3::CAN_TRACE),
        _ => bail!("cut: v0|v1|v2|v3"),
    };

    // Framework snapshot: the largest one at or below pv.
    let snaps = sui.join("crates/sui-framework-snapshot/bytecode_snapshot");
    let snap = std::fs::read_dir(&snaps)?
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u64>().ok())
        .filter(|n| *n <= pv)
        .max()
        .ok_or_else(|| anyhow!("no framework snapshot <= {pv}"))?;
    let overlay: Vec<Pkg> = framework_move_packages_at(&sui, snap)?
        .into_iter()
        .map(|mp| Ok(Pkg { sp: mp.into_serialized_move_package().map_err(|e| anyhow!("{e:?}"))?, src: "framework" }))
        .collect::<Result<_>>()?;

    // Store: base packages, system packages replaced by the snapshot's (absent ones removed).
    let mut by: BTreeMap<AccountAddress, Pkg> =
        read_packages(&dir.join("move-vm-gas/packages.bin"))?.into_iter().map(|p| (p.sp.version_id, p)).collect();
    by.retain(|a, _| !is_system(a));
    for p in &overlay {
        by.insert(p.sp.version_id, p.clone());
    }
    let mut orig = HashMap::new();
    for p in by.values() {
        orig.insert(p.sp.version_id, p.sp.original_id);
        for d in p.sp.type_origin_table.values() {
            orig.insert(*d, p.sp.original_id);
        }
    }
    let mut modules: BTreeMap<AccountAddress, BTreeMap<String, CompiledModule>> = BTreeMap::new();
    for (vid, p) in &by {
        let mut mm = BTreeMap::new();
        for (n, b) in &p.sp.modules {
            if let Ok(m) = CompiledModule::deserialize_with_defaults(b) {
                mm.insert(n.to_string(), m);
            }
        }
        modules.insert(*vid, mm);
    }
    let l = Loaded { store: Store { by_version: by }, modules };
    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(pv), Chain::Mainnet);
    let tx_bytes = tx_context(&cfg).to_bcs_legacy_context();
    let ctx = Ctx { gm: cfg.gas_model_version(), cfg, orig, tx_bytes };

    // Calls: protocol 141, default budget, each distinct spec once (first id kept).
    let text = std::fs::read_to_string(dir.join("move-vm-gas/calls.jsonl"))?;
    let mut seen = BTreeSet::new();
    let mut calls: Vec<(u64, Call)> = vec![];
    for line in text.lines() {
        let v: serde_json::Value = serde_json::from_str(line)?;
        let c = parse_call(&v)?;
        if c.pv != 141 || c.budget != BUDGET || !seen.insert(spec_key(&c)) {
            continue;
        }
        calls.push((v["id"].as_u64().ok_or_else(|| anyhow!("id"))?, c));
    }
    // Argument-error mutants (old VMs deserialize arguments: FAILED_TO_DESERIALIZE_ARGUMENT,
    // Location::Undefined, nothing charged): one call in 16 with a non-TxContext argument gets
    // that argument with a byte appended, its last byte dropped, or its first byte set to 0xff.
    let txc_name = |t: &TypeTag| matches!(t, TypeTag::Struct(st) if st.address == AccountAddress::TWO && st.module.as_str() == "tx_context");
    let mut mutants = vec![];
    for (id, c) in &calls {
        if id % 16 != 0 {
            continue;
        }
        let Some(k) = c.arg_tags.iter().position(|t| !txc_name(t)) else { continue };
        let mut m = c.clone();
        m.arg_error = true;
        let b = &mut m.args[k].2;
        match (id / 16) % 3 {
            0 => b.push(0),
            1 if !b.is_empty() => {
                b.pop();
            }
            1 => b.push(0x80),
            _ if !b.is_empty() => b[0] = 0xff,
            _ => b.push(0xff),
        }
        mutants.push((id + ARG_ERROR_ID, m));
    }
    calls.extend(mutants);
    let traced: BTreeSet<String> = std::fs::read_to_string(dir.join("move-vm-trace/calls.jsonl"))?
        .lines()
        .map(|line| Ok(spec_key(&parse_call(&serde_json::from_str(line)?)?)))
        .collect::<Result<_>>()?;
    Ok(Setup { cut, pv, dir, run, can_trace, snap, overlay, l, ctx, calls, traced })
}

impl Setup {
    /// The call as the cut runs it (fdef in the old module, pv), or why it cannot run there.
    fn prepare(&self, c: &Call) -> std::result::Result<Call, &'static str> {
        let l = &self.l;
        let Some(root) = l.store.by_version.get(&c.root) else { return Err("package_absent") };
        if root.sp.linkage_table.values().any(|v| !l.store.by_version.contains_key(v)) {
            return Err("package_absent");
        }
        let Some((pkg, m)) = l.module_for(root, c.module.address(), c.module.name().as_str()) else {
            return Err("module_missing");
        };
        let Some(fdef) =
            m.function_defs.iter().position(|fd| m.identifier_at(m.function_handle_at(fd.function).name) == c.function.as_ident_str())
        else {
            return Err("function_missing");
        };
        if m.function_defs[fdef].code.is_none() {
            return Err("function_native");
        }
        if reaches_native(l, root, pkg, m, fdef, &mut HashMap::new()) {
            return Err("reaches_unimplemented_native");
        }
        let mut c = c.clone();
        c.fdef = fdef as u16;
        c.pv = self.pv;
        // On chain the adapter supplies the TxContext argument: the old natives (derive_id) and
        // the old framework read its fields, and panic on a digest that is not 32 bytes.
        let txc = TypeTag::Struct(Box::new(StructTag {
            address: AccountAddress::TWO,
            module: Identifier::new("tx_context").unwrap(),
            name: Identifier::new("TxContext").unwrap(),
            type_params: vec![],
        }));
        for (a, t) in c.args.iter_mut().zip(&c.arg_tags) {
            if *t == txc {
                a.2 = self.ctx.tx_bytes.clone();
            }
        }
        Ok(c)
    }
}

/// True if the tracer recorded its own failure ("!! TRACING ERROR !!") in the trace.
fn trace_has_error(t: &[u8]) -> Result<bool> {
    // A byte search: deep traces exceed serde_json's recursion limit, so no parse.
    let raw = zstd::stream::decode_all(t)?;
    Ok(raw.windows(13).any(|w| w == b"TRACING ERROR"))
}

/// `cut-trace <cut> <pv> <vectors> <out dir>`: the trace worker. Reads source ids on stdin, runs
/// each traced (one at a time) and writes `<out dir>/<id>.json.zst`; stdout gets `start <id>`
/// before each run, then `done <id> <truth>` or `skip <id> <reason>`. The v3 tracer can assert or
/// recurse without end (a stack overflow aborts the process), so `cut` runs it in this child and
/// counts the id in flight when it dies.
pub(crate) fn cmd_cut_trace(args: &[String]) -> Result<()> {
    // A big stack, so only unbounded tracer recursion (not deep values) kills the worker.
    let args = args.to_vec();
    std::thread::Builder::new().stack_size(256 << 20).spawn(move || cut_trace(&args))?.join().map_err(|_| anyhow!("cut-trace panicked"))?
}

fn cut_trace(args: &[String]) -> Result<()> {
    let s = setup(args)?;
    let out = PathBuf::from(args.get(3).ok_or_else(|| anyhow!("out dir"))?);
    if std::env::var("ZUI_TRUTH_DEBUG").is_err() {
        std::panic::set_hook(Box::new(|_| {}));
    }
    let by_id: HashMap<u64, &Call> = s.calls.iter().map(|(i, c)| (*i, c)).collect();
    let mut ids = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut ids)?;
    let mut so = std::io::stdout().lock();
    for id in ids.split_whitespace() {
        let id: u64 = id.parse()?;
        writeln!(so, "start {id}")?;
        so.flush()?;
        let c = s.prepare(by_id.get(&id).ok_or_else(|| anyhow!("id {id}"))?).map_err(|e| anyhow!("{e}"))?;
        let line = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (s.run)(&s.ctx, &s.l.store, &c, true))) {
            Err(_) => "skip tracer_panic".to_string(),
            Ok(Err(e)) => format!("skip harness:{}", format!("{e}").replace(char::is_whitespace, "_").chars().take(80).collect::<String>()),
            Ok(Ok(Res::Drop(_))) => "skip traced_run_dropped".to_string(),
            Ok(Ok(Res::Done(t))) => {
                let bytes = t.trace.unwrap_or_default();
                if trace_has_error(&bytes)? {
                    "skip tracer_error".to_string()
                } else {
                    std::fs::write(out.join(format!("{id}.json.zst")), &bytes)?;
                    format!("done {}", t.truth)
                }
            }
        };
        let (k, rest) = line.split_once(' ').unwrap();
        writeln!(so, "{k} {id} {rest}")?;
        so.flush()?;
    }
    Ok(())
}

pub(crate) fn cmd_cut(args: &[String]) -> Result<()> {
    let t0 = Instant::now();
    let s = setup(args)?;
    let (cut, pv) = (s.cut.clone(), s.pv);
    let only: Option<u64> = std::env::var("ZUI_CUT_ONLY").ok().and_then(|s| s.parse().ok());
    if std::env::var("ZUI_TRUTH_DEBUG").is_err() {
        // Panics are caught per call and counted; keep their messages off stderr.
        std::panic::set_hook(Box::new(|_| {}));
    }

    // Untraced runs, in parallel (big stacks: the old interpreters recurse on deep values).
    let pool = rayon::ThreadPoolBuilder::new().stack_size(64 << 20).build()?;
    let mut results: Vec<(u64, Call, std::result::Result<Outcome, String>)> = pool.install(|| {
        s.calls
            .par_iter()
            .filter(|(id, _)| only.is_none_or(|o| o == *id))
            .map(|(id, c)| {
                let r = match s.prepare(c) {
                    Err(why) => Err(why.to_string()),
                    Ok(c2) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (s.run)(&s.ctx, &s.l.store, &c2, false))) {
                        Err(_) => Err("vm_panic".to_string()),
                        Ok(Ok(Res::Drop(why))) => Err(why),
                        Ok(Ok(Res::Done(o))) => Ok(o),
                        Ok(Err(e)) => Err(format!("harness: {}", format!("{e}").chars().take(200).collect::<String>())),
                    },
                };
                let c2 = s.prepare(c).unwrap_or_else(|_| c.clone());
                (*id, c2, r)
            })
            .collect()
    });

    // Output dirs (only under cuts/).
    let gas_dir = s.dir.join("move-vm-gas/cuts").join(&cut);
    let trace_dir = s.dir.join("move-vm-trace/cuts").join(&cut);
    let _ = std::fs::remove_dir_all(&gas_dir);
    let _ = std::fs::remove_dir_all(&trace_dir);
    std::fs::create_dir_all(&gas_dir)?;

    // Traces: the picked calls short enough, through the worker process.
    let mut traced_ok: BTreeSet<u64> = BTreeSet::new();
    let mut trace_skips: BTreeMap<String, u64> = BTreeMap::new();
    if s.can_trace {
        std::fs::create_dir_all(trace_dir.join("trace"))?;
        let orig: HashMap<u64, &Call> = s.calls.iter().map(|(i, c)| (*i, c)).collect();
        let mut todo: Vec<u64> = results
            .iter()
            .filter(|(id, _, r)| {
                r.as_ref().is_ok_and(|o| o.truth["ins"].as_u64().unwrap_or(u64::MAX) <= TRACE_MAX_INS) && s.traced.contains(&spec_key(orig[id]))
            })
            .map(|(id, _, _)| *id)
            .collect();
        let truth_of: HashMap<u64, serde_json::Value> =
            results.iter().filter_map(|(id, _, r)| r.as_ref().ok().map(|o| (*id, o.truth.clone()))).collect();
        let exe = std::env::current_exe()?;
        while !todo.is_empty() {
            let mut child = std::process::Command::new(&exe)
                .arg("cut-trace")
                .args([&cut, &pv.to_string(), &s.dir.to_string_lossy().to_string(), &trace_dir.join("trace").to_string_lossy().to_string()])
                .env("RAYON_NUM_THREADS", "1")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()?;
            {
                let mut si = child.stdin.take().unwrap();
                writeln!(si, "{}", todo.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(" "))?;
            }
            let out = std::io::BufReader::new(child.stdout.take().unwrap());
            let mut in_flight = None;
            let mut finished: BTreeSet<u64> = BTreeSet::new();
            for line in std::io::BufRead::lines(out) {
                let line = line?;
                let mut it = line.splitn(3, ' ');
                let (k, id, rest) = (it.next().unwrap_or(""), it.next().unwrap_or("0").parse::<u64>()?, it.next().unwrap_or(""));
                match k {
                    "start" => in_flight = Some(id),
                    "skip" => {
                        *trace_skips.entry(rest.to_string()).or_default() += 1;
                        finished.insert(id);
                        in_flight = None;
                    }
                    "done" => {
                        let t: serde_json::Value = serde_json::from_str(rest)?;
                        if t == truth_of[&id] {
                            traced_ok.insert(id);
                        } else {
                            *trace_skips.entry("traced_truth_differs".into()).or_default() += 1;
                            let _ = std::fs::remove_file(trace_dir.join("trace").join(format!("{id}.json.zst")));
                        }
                        finished.insert(id);
                        in_flight = None;
                    }
                    _ => bail!("cut-trace: {line}"),
                }
            }
            let st = child.wait()?;
            if let Some(id) = in_flight {
                *trace_skips.entry("tracer_crash".into()).or_default() += 1;
                finished.insert(id);
            } else if !st.success() {
                bail!("cut-trace worker failed: {st}");
            }
            todo.retain(|i| !finished.contains(i));
        }
    }

    // Write.
    results.sort_by_key(|(id, _, _)| *id);
    write_packages(&gas_dir.join("packages.bin"), &s.overlay.iter().collect::<Vec<_>>())?;
    let mut f = std::io::BufWriter::new(std::fs::File::create(gas_dir.join("calls.jsonl"))?);
    let mut ft = if s.can_trace { Some(std::io::BufWriter::new(std::fs::File::create(trace_dir.join("calls.jsonl"))?)) } else { None };
    let (mut n_ok, mut n_err) = (0u64, 0u64);
    let mut drops: BTreeMap<String, u64> = BTreeMap::new();
    let mut majors: BTreeMap<u64, u64> = BTreeMap::new();
    for (id, c, r) in &results {
        let o = match r {
            Err(why) => {
                *drops.entry(why.clone()).or_default() += 1;
                continue;
            }
            Ok(o) => o,
        };
        let mut j = call_json(c, *id as usize, s.ctx.gm);
        j["truth"] = o.truth.clone();
        if o.ok {
            n_ok += 1;
        } else {
            n_err += 1;
            *majors.entry(o.truth["err"]["major"].as_u64().unwrap_or(0)).or_default() += 1;
        }
        writeln!(f, "{j}")?;
        if let Some(ft) = ft.as_mut() {
            if traced_ok.contains(id) {
                writeln!(ft, "{j}")?;
            }
        }
    }
    f.flush()?;
    if let Some(ft) = ft.as_mut() {
        ft.flush()?;
    }
    eprintln!(
        "cut {cut} pv {pv} (gm {}, framework snapshot {}, {} overlay packages): {} distinct calls, {} written ({} ok, {} err, majors {:?}), dropped {:?}, {}, {:.1}s",
        s.ctx.gm,
        s.snap,
        s.overlay.len(),
        results.len(),
        n_ok + n_err,
        n_ok,
        n_err,
        majors,
        drops,
        if s.can_trace {
            format!("{} traced (untraced {:?})", traced_ok.len(), trace_skips)
        } else {
            "no traces (this cut has no move-trace-format tracer)".into()
        },
        t0.elapsed().as_secs_f64()
    );
    Ok(())
}
