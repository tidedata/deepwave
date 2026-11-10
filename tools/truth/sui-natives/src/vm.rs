//! Runs native calls through Mysten's own move-vm-runtime (execution version 4, the "latest"
//! executor that mainnet uses from protocol 119) with the natives table and native extensions
//! that sui-adapter builds. Each native is the base invocation, so the only gas the meter sees is
//! the native's own `NativeResult.cost`, which is exactly what the deepwave suite compares.
//!
//! A vector is a script: one or more calls that share one set of native extensions (one
//! TxContext, one ObjectRuntime), so stateful natives (fresh_id after fresh_id) are covered.

use anyhow::{Context, Result, anyhow};
use move_binary_format::errors::VMError;
use move_core_types::gas_algebra::InternalGas;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::{ModuleId, TypeTag};
use move_core_types::runtime_value::MoveTypeLayout;
use move_core_types::vm_status::StatusCode;
use move_vm_runtime::execution::Type;
use move_vm_runtime::execution::interpreter::locals::BaseHeap;
use move_vm_runtime::execution::values::Value;
use move_vm_runtime::natives::functions::NativeFunctions;
use move_vm_runtime::runtime::MoveRuntime;
use move_vm_runtime::shared::gas::{GasMeter, SimpleInstruction};
use move_vm_runtime::shared::linkage_context::LinkageContext;
use move_vm_runtime::shared::views::ValueView;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use move_core_types::language_storage::StructTag;
use move_vm_runtime::execution::values::Reference;
use serde_json::json;
use sui_move_natives::object_runtime::{InputObject, MoveAccumulatorAction, MoveAccumulatorValue, ObjectRuntime};
use sui_types::base_types::{ObjectID, SequenceNumber, SuiAddress, TxContext};
use sui_types::object::{Object, Owner};
use sui_types::digests::TransactionDigest;
use sui_types::in_memory_storage::InMemoryStorage;
use sui_types::metrics::ExecutionMetrics;
use sui_types::storage::ImplicitSystemObjectResolver;

type PR<T> = move_binary_format::errors::PartialVMResult<T>;

/// Gas meter that records the native's charge. The base native invocation calls only
/// `charge_native_function_before_execution` and `charge_native_function`.
pub struct RecMeter {
    pub budget: u64,
    pub native: Vec<u64>,
}

impl GasMeter for RecMeter {
    fn charge_simple_instr(&mut self, _: SimpleInstruction) -> PR<()> { Ok(()) }
    fn charge_pop(&mut self, _: impl ValueView) -> PR<()> { Ok(()) }
    fn charge_call(&mut self, _: impl ExactSizeIterator<Item = impl ValueView>, _: u64) -> PR<()> { Ok(()) }
    fn charge_call_generic(&mut self, _: impl ExactSizeIterator<Item = impl ValueView>, _: u64) -> PR<()> { Ok(()) }
    fn charge_ld_const(&mut self, _: u64) -> PR<()> { Ok(()) }
    fn charge_ld_const_after_deserialization(&mut self, _: impl ValueView) -> PR<()> { Ok(()) }
    fn charge_copy_loc(&mut self, _: impl ValueView) -> PR<()> { Ok(()) }
    fn charge_move_loc(&mut self, _: impl ValueView) -> PR<()> { Ok(()) }
    fn charge_store_loc(&mut self, _: impl ValueView) -> PR<()> { Ok(()) }
    fn charge_pack(&mut self, _: bool, _: impl ExactSizeIterator<Item = impl ValueView>) -> PR<()> { Ok(()) }
    fn charge_unpack(&mut self, _: bool, _: impl ExactSizeIterator<Item = impl ValueView>) -> PR<()> { Ok(()) }
    fn charge_variant_switch(&mut self, _: impl ValueView) -> PR<()> { Ok(()) }
    fn charge_read_ref(&mut self, _: impl ValueView) -> PR<()> { Ok(()) }
    fn charge_write_ref(&mut self, _: impl ValueView, _: impl ValueView) -> PR<()> { Ok(()) }
    fn charge_eq(&mut self, _: impl ValueView, _: impl ValueView) -> PR<()> { Ok(()) }
    fn charge_neq(&mut self, _: impl ValueView, _: impl ValueView) -> PR<()> { Ok(()) }
    fn charge_vec_pack(&mut self, _: impl ExactSizeIterator<Item = impl ValueView>) -> PR<()> { Ok(()) }
    fn charge_vec_len(&mut self) -> PR<()> { Ok(()) }
    fn charge_vec_borrow(&mut self, _: bool, _: bool) -> PR<()> { Ok(()) }
    fn charge_vec_push_back(&mut self, _: impl ValueView) -> PR<()> { Ok(()) }
    fn charge_vec_pop_back(&mut self, _: Option<impl ValueView>) -> PR<()> { Ok(()) }
    fn charge_vec_unpack(&mut self, _: u64, _: impl ExactSizeIterator<Item = impl ValueView>) -> PR<()> { Ok(()) }
    fn charge_vec_swap(&mut self) -> PR<()> { Ok(()) }
    fn charge_native_function(
        &mut self,
        amount: InternalGas,
        _: Option<impl ExactSizeIterator<Item = impl ValueView>>,
    ) -> PR<()> {
        self.native.push(u64::from(amount));
        Ok(())
    }
    fn charge_native_function_before_execution(&mut self, _: impl ExactSizeIterator<Item = impl ValueView>) -> PR<()> { Ok(()) }
    fn charge_drop_frame(&mut self, _: impl Iterator<Item = impl ValueView>) -> PR<()> { Ok(()) }
    fn remaining_gas(&self) -> InternalGas { InternalGas::new(self.budget) }
}

struct Balances(Vec<(SuiAddress, TypeTag, u128)>, Option<sui_types::object::Object>);
impl ImplicitSystemObjectResolver for Balances {
    fn object_available_balance(&self, owner: SuiAddress, ty: &TypeTag) -> sui_types::error::SuiResult<u128> {
        Ok(self.0.iter().find(|(o, t, _)| *o == owner && t == ty).map(|x| x.2).unwrap_or(0))
    }
    // 1.84: `clock::borrow` reads the item's Clock (env.clock); an item without one is the
    // store failing to load it (an invariant violation).
    #[cfg(feature = "sui_184")]
    fn clock(&self) -> sui_types::error::SuiResult<sui_types::object::Object> {
        self.1.clone().ok_or_else(|| sui_types::error::SuiErrorKind::ExecutionInvariantViolation.into())
    }
}

/// The transaction context a vector runs under (tx_context natives read it).
#[derive(Clone)]
pub struct Ctx {
    pub sender: [u8; 32],
    pub digest: [u8; 32],
    pub epoch: u64,
    pub epoch_ts_ms: u64,
    pub rgp: u64,
    pub gas_price: u64,
    pub gas_budget: u64,
    pub sponsor: Option<[u8; 32]>,
}

pub const DEFAULT_CTX: Ctx = Ctx {
    sender: [0x5a; 32],
    digest: [0xd1; 32],
    epoch: 1304,
    epoch_ts_ms: 1_762_400_000_000,
    rgp: 538,
    gas_price: 750,
    gas_budget: 50_000_000,
    sponsor: None,
};

#[derive(Clone)]
pub struct Call {
    pub addr: u16,
    pub module: &'static str,
    pub func: &'static str,
    pub ty_args: Vec<TypeTag>,
    pub args: Vec<Vec<u8>>,
    pub budget: u64,
    /// After a successful call that returned a `&mut T`, write this value (BCS of T) through it,
    /// as Move code holding the reference would.
    pub write: Option<Vec<u8>>,
    /// Hand the type argument a stand-in shape instead of its layout (the real layout exceeds the
    /// VM's limits); `args` are decoded with the stand-in.
    pub shapes: Vec<Option<MoveTypeLayout>>,
}

/// The object world a vector runs in: storage contents, the transaction's input objects and
/// whether it is metered.
#[derive(Clone, Default)]
pub struct ObjEnv {
    pub unmetered: bool,
    pub inputs: Vec<(ObjectID, u64, Owner, Vec<ObjectID>)>,
    pub objects: Vec<Object>,
    /// object_available_balance per (owner, type)
    pub balances: Vec<(SuiAddress, TypeTag, u128)>,
    /// `ImplicitSystemObjectResolver::clock` (1.84): the Clock object `clock::borrow` loads
    pub clock: Option<Object>,
}

pub enum Outcome {
    Ok { rets: Vec<Vec<u8>>, muts: Vec<Vec<u8>> },
    Abort(u64),
    Err { status: StatusCode, sub: Option<u64> },
}

/// Everything the deepwave side needs to replay the call: the native's signature as runtime layouts
/// (instantiated), the type arguments with their layouts, and the outcome and charges.
pub struct Truth {
    pub params: Vec<(u8, Vec<u8>)>, // (0 value, 1 &, 2 &mut; BCS of MoveTypeLayout)
    pub rets: Vec<(u8, Vec<u8>)>,   // (kind as params; BCS of MoveTypeLayout of the value)
    pub tys: Vec<TyTruth>,
    pub outcome: Outcome,
    pub cost: Vec<u64>,
}

pub struct TyTruth {
    pub tag: Vec<u8>,
    pub layout: Option<Vec<u8>>,
    pub shape: Option<Vec<u8>>,
    pub annotated: Option<Vec<u8>>,
}

pub struct Env {
    pub pv: u64,
    pub cfg: ProtocolConfig,
    runtime: MoveRuntime,
    storage: InMemoryStorage,
    genesis: Vec<Object>,
    link: LinkageContext,
}

fn addr_of(a: u16) -> move_core_types::account_address::AccountAddress {
    let mut b = [0u8; 32];
    b[30] = (a >> 8) as u8;
    b[31] = a as u8;
    move_core_types::account_address::AccountAddress::new(b)
}

impl Env {
    pub fn new(pv: u64) -> Result<Self> {
        let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(pv), Chain::Mainnet);
        anyhow::ensure!(cfg.execution_version() == 4, "pv {pv} is not served by the latest executor");
        let natives = sui_move_natives::all_natives(/* silent */ true, &cfg);
        let runtime = MoveRuntime::new(
            NativeFunctions::new(natives).map_err(|e| anyhow!("natives: {e:?}"))?,
            sui_adapter::adapter::vm_config(&cfg),
        );
        let objects: Vec<_> = sui_framework::BuiltInFramework::genesis_objects().collect();
        let mut table = BTreeMap::new();
        for o in &objects {
            table.insert(o.id().into(), o.id().into());
        }
        let storage = InMemoryStorage::new(objects.clone());
        let link = LinkageContext::new(table).map_err(|e| anyhow!("linkage: {e:?}"))?;
        Ok(Env { pv, cfg, runtime, storage, genesis: objects, link })
    }

    pub fn run(&self, calls: &[Call], c: &Ctx) -> Result<Vec<Truth>> {
        Ok(self.run_env(calls, c, None)?.0)
    }

    /// Runs the calls; with an object world, also finishes the ObjectRuntime and returns its
    /// results as JSON.
    /// The storage an item runs on: genesis plus the item's objects.
    pub fn storage_for(&self, env: Option<&ObjEnv>) -> Option<InMemoryStorage> {
        match env {
            Some(e) if !e.objects.is_empty() => {
                let mut objs = self.genesis.clone();
                objs.extend(e.objects.iter().cloned());
                Some(InMemoryStorage::new(objs))
            }
            _ => None,
        }
    }

    pub fn run_env(&self, calls: &[Call], c: &Ctx, env: Option<&ObjEnv>) -> Result<(Vec<Truth>, Option<serde_json::Value>)> {
        let st = self.storage_for(env);
        self.run_in(calls, c, env, st.as_ref(), true)
    }

    /// `run_env` on a prebuilt storage (`storage_for`); without `results` the runtime still
    /// finishes but nothing is serialized (the bench path).
    pub fn run_in(&self, calls: &[Call], c: &Ctx, env: Option<&ObjEnv>, item_storage: Option<&InMemoryStorage>, results: bool) -> Result<(Vec<Truth>, Option<serde_json::Value>)> {
        let tx = TxContext::new_from_components(
            &SuiAddress::from_bytes(c.sender)?,
            &TransactionDigest::new(c.digest),
            &c.epoch,
            c.epoch_ts_ms,
            c.rgp,
            c.gas_price,
            c.gas_budget,
            c.sponsor.map(SuiAddress::from_bytes).transpose()?,
            &self.cfg,
        );
        let tx = Rc::new(RefCell::new(tx));
        let metrics = Arc::new(ExecutionMetrics::new(&prometheus::Registry::new()));
        let resolver = Balances(env.map(|e| e.balances.clone()).unwrap_or_default(), env.and_then(|e| e.clock.clone()));
        let storage = item_storage.unwrap_or(&self.storage);
        let mut inputs = BTreeMap::new();
        for (id, version, owner, uids) in env.map(|e| e.inputs.clone()).unwrap_or_default() {
            inputs.insert(id, InputObject { contained_uids: uids.into_iter().collect(), version: SequenceNumber::from_u64(version), owner });
        }
        let exts = sui_adapter::adapter::new_native_extensions(
            storage,
            &resolver,
            inputs,
            /* is_metered */ !env.map(|e| e.unmetered).unwrap_or(false),
            &self.cfg,
            metrics,
            tx,
        )
        .map_err(|e| anyhow!("extensions: {e:?}"))?;
        let mut vm = self
            .runtime
            .make_vm_with_native_extensions(storage, self.link.clone(), exts.clone())
            .map_err(|e| anyhow!("make_vm: {e:?}"))?;
        let mut out = Vec::new();
        for call in calls {
            out.push(self.one(&mut vm, call)?);
        }
        if env.is_none() {
            return Ok((out, None));
        }
        let ort = exts.borrow_mut().remove::<ObjectRuntime>().map_err(|e| anyhow!("{e:?}"))?;
        if !results {
            std::hint::black_box(ort.finish().is_ok());
            return Ok((out, None));
        }
        let res = match ort.finish() {
            Err(e) => {
                let k = format!("{:?}", e.kind());
                let k = k.split(|c: char| c == ' ' || c == '{' || c == '(').next().unwrap_or("").to_string();
                json!({"err": k})
            }
            Ok(r) => {
                let lay = |t: &TypeTag| -> Result<MoveTypeLayout> { vm.runtime_type_layout(t).map_err(|e| anyhow!("layout {t}: {e:?}")) };
                let mut writes = Vec::new();
                for (id, (owner, ty, v)) in &r.writes {
                    let st: StructTag = ty.clone().into();
                    let tt = TypeTag::Struct(Box::new(st.clone()));
                    writes.push(json!([hex::encode(id), hex::encode(bcs::to_bytes(owner)?), hex::encode(bcs::to_bytes(&st)?),
                        hex::encode(v.typed_serialize(&lay(&tt)?).context("write value")?)]));
                }
                let mut events = Vec::new();
                for (st, v) in &r.user_events {
                    let tt = TypeTag::Struct(Box::new(st.clone()));
                    events.push(json!([hex::encode(bcs::to_bytes(st)?), hex::encode(v.typed_serialize(&lay(&tt)?).context("event value")?)]));
                }
                let acc: Vec<_> = r.accumulator_events.iter().map(|e| {
                    let (k, n) = match e.value { MoveAccumulatorValue::U64(n) => (0, n), MoveAccumulatorValue::EventRef(n) => (1, n) };
                    let a = match e.action { MoveAccumulatorAction::Merge => 0, MoveAccumulatorAction::Split => 1 };
                    json!([hex::encode(e.accumulator_id), a, hex::encode(e.target_addr), hex::encode(bcs::to_bytes(&e.target_ty).unwrap()), k, n])
                }).collect();
                let loaded: Vec<_> = r.loaded_child_objects.iter().map(|(id, l)| json!([hex::encode(id), l.version.value(), l.is_modified])).collect();
                json!({"ok": {
                    "writes": writes, "events": events, "acc": acc, "loaded": loaded,
                    "created": r.created_object_ids.iter().map(hex::encode).collect::<Vec<_>>(),
                    "deleted": r.deleted_object_ids.iter().map(hex::encode).collect::<Vec<_>>(),
                    "settle": [r.settlement_input_sui, r.settlement_output_sui],
                }})
            }
        };
        Ok((out, Some(res)))
    }

    fn one(&self, vm: &mut move_vm_runtime::execution::vm::MoveVM, call: &Call) -> Result<Truth> {
        let module = ModuleId::new(addr_of(call.addr), Identifier::new(call.module)?);
        let ty_args: Vec<Type> = call
            .ty_args
            .iter()
            .map(|t| vm.load_type(t))
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow!("load_type: {e:?}"))?;
        let mut tys = Vec::new();
        for (i, t) in call.ty_args.iter().enumerate() {
            let lay = vm.runtime_type_layout(t).ok().map(|l| bcs::to_bytes(&l).unwrap());
            let ann = vm.annotated_type_layout(t).ok().map(|l| bcs::to_bytes(&l).unwrap());
            let shape = call.shapes.get(i).cloned().flatten().map(|l| bcs::to_bytes(&l).unwrap());
            tys.push(TyTruth { tag: bcs::to_bytes(t)?, layout: lay, shape, annotated: ann });
        }
        let fname = Identifier::new(call.func)?;
        let info = vm
            .function_information(&module, &fname, &ty_args)
            .map_err(|e| anyhow!("function_information {}::{}: {e:?}", module, call.func))?;
        anyhow::ensure!(info.is_native, "{}::{} is not native", module, call.func);
        anyhow::ensure!(info.parameters.len() == call.args.len(), "arity of {}::{}", module, call.func);

        let mut heap = BaseHeap::new();
        let mut args = Vec::new();
        let mut mut_slots = Vec::new();
        let mut params = Vec::new();
        for (ty, bytes) in info.parameters.iter().zip(&call.args) {
            let (inner, kind) = match ty {
                Type::Reference(t) => (subst(t, &ty_args), 1u8),
                Type::MutableReference(t) => (subst(t, &ty_args), 2u8),
                t => (subst(t, &ty_args), 0u8),
            };
            let layout = layout_or_shape(vm, &inner, &ty_args, call)?;
            params.push((kind, bcs::to_bytes(&layout)?));
            let v = Value::simple_deserialize(bytes, &layout)
                .with_context(|| format!("arg does not decode as {inner:?}"))?;
            if kind == 0 {
                args.push(v);
            } else {
                let (id, r) = heap.allocate_and_borrow_loc(v).map_err(|e| anyhow!("{e:?}"))?;
                args.push(r);
                if kind == 2 {
                    mut_slots.push((id, layout));
                }
            }
        }
        let mut rets = Vec::new();
        let mut ret_lays = Vec::new();
        for ty in &info.return_ {
            let (inner, kind) = match ty {
                Type::Reference(t) => (subst(t, &ty_args), 1u8),
                Type::MutableReference(t) => (subst(t, &ty_args), 2u8),
                t => (subst(t, &ty_args), 0u8),
            };
            let l = layout_or_shape(vm, &inner, &ty_args, call)?;
            rets.push((kind, bcs::to_bytes(&l)?));
            ret_lays.push((kind, l));
        }
        let mut meter = RecMeter { budget: call.budget, native: vec![] };
        let res = vm.execute_function_bypass_visibility(&module, &fname, ty_args.clone(), args, &mut meter, None);
        let outcome = match res {
            Ok(vals) => {
                let mut rv = Vec::new();
                for (v, (kind, layout)) in vals.iter().zip(&ret_lays) {
                    if *kind == 0 {
                        rv.push(v.typed_serialize(layout).context("serialize return")?);
                    } else {
                        let r: Reference = v.copy_value().value_as().map_err(|e| anyhow!("{e:?}"))?;
                        let x = r.read_ref().map_err(|e| anyhow!("{e:?}"))?;
                        rv.push(x.typed_serialize(layout).context("serialize ref return")?);
                    }
                }
                if let Some(w) = &call.write {
                    let (kind, layout) = &ret_lays[0];
                    anyhow::ensure!(*kind == 2, "write through a non-&mut return");
                    let nv = Value::simple_deserialize(w, layout).context("write value")?;
                    let r: Reference = vals[0].copy_value().value_as().map_err(|e| anyhow!("{e:?}"))?;
                    r.write_ref(nv).map_err(|e| anyhow!("{e:?}"))?;
                }
                drop(vals);
                let mut muts = Vec::new();
                for (id, layout) in mut_slots {
                    let v = heap.take_loc(id).map_err(|e| anyhow!("{e:?}"))?;
                    muts.push(v.typed_serialize(&layout).context("serialize mut ref")?);
                }
                Outcome::Ok { rets: rv, muts }
            }
            Err(e) => vm_err(&e),
        };
        Ok(Truth { params, rets, tys, outcome, cost: meter.native })
    }
}

fn vm_err(e: &VMError) -> Outcome {
    if e.major_status() == StatusCode::ABORTED {
        Outcome::Abort(e.sub_status().unwrap_or(0))
    } else {
        Outcome::Err { status: e.major_status(), sub: e.sub_status() }
    }
}

fn subst(t: &Type, ty_args: &[Type]) -> Type {
    match t {
        Type::TyParam(i) => ty_args[*i as usize].clone(),
        Type::Vector(e) => Type::Vector(Box::new(subst(e, ty_args))),
        Type::Reference(e) => Type::Reference(Box::new(subst(e, ty_args))),
        Type::MutableReference(e) => Type::MutableReference(Box::new(subst(e, ty_args))),
        Type::DatatypeInstantiation(b) => {
            let (k, args) = &**b;
            Type::DatatypeInstantiation(Box::new((k.clone(), args.iter().map(|a| subst(a, ty_args)).collect())))
        }
        other => other.clone(),
    }
}

/// The layout of `t`, or the stand-in shape when `t` is a type argument given one.
fn layout_or_shape(vm: &move_vm_runtime::execution::vm::MoveVM, t: &Type, ty_args: &[Type], call: &Call) -> Result<MoveTypeLayout> {
    for (i, a) in ty_args.iter().enumerate() {
        if a == t {
            if let Some(Some(s)) = call.shapes.get(i) {
                return Ok(s.clone());
            }
        }
    }
    layout_of(vm, t)
}

fn layout_of(vm: &move_vm_runtime::execution::vm::MoveVM, t: &Type) -> Result<MoveTypeLayout> {
    let tag = vm.type_tag_for_type_defining_ids(t).map_err(|e| anyhow!("type tag of {t:?}: {e:?}"))?;
    vm.runtime_type_layout(&tag).map_err(|e| anyhow!("layout of {tag}: {e:?}"))
}
