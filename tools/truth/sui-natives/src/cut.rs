//! `zui-truth-sui-natives cut <v0|v1|v2|v3> <pv> [corpus]`: the natives vectors again, through one
//! of Mysten's older execution cuts.
//!
//! Every script of `vectors/natives/<group>.jsonl` (same calls, type arguments, arguments, budgets,
//! ctx and object world) runs through that cut's Move VM (`move-vm-runtime-vN`, the old session
//! API over a module resolver), its natives (`sui-move-natives-vN::all_natives`) and its native
//! extensions (`sui-adapter-vN::adapter::new_native_extensions`: the cut's ObjectRuntime and
//! NativesCostTable, plus TransactionContext in v3), at protocol config `pv` (mainnet) and the
//! framework snapshot of that pv (`bytecode_snapshot/<largest dir <= pv>`). Each native is the
//! base invocation, so the only gas the meter sees is the native's own cost, as in `natives`.
//! Output: `vectors/natives/cuts/<dir>/<group>.jsonl`, the line format of `natives` with "pv" set
//! to `pv`; dir is `vN` at the cut's reference pv (v0 17, v1 30, v2 37, v3 103), else `vN-<pv>`.
//! Drops per group and reason go to stderr and `cuts/<dir>/drops.json`.
//!
//! Script rewrites so older frameworks are covered (the line records the call actually made):
//! - `type_name::with_defining_ids` / `with_original_ids` run as the old `get` /
//!   `get_with_original_ids` when the framework only declares those.
//! - `tx_context::fresh_id` (a native from execution version 4 on) runs as the old
//!   `tx_context::derive_id(ctx.digest, n)` for the script's n-th fresh id when the framework has no
//!   native `fresh_id`: same id, same ObjectRuntime record, the cost is derive_id's.
//! - A call with `write` (write a new value through the `&mut` that `borrow_child_object_mut`
//!   returns) runs as `0x2::dynamic_field::zui_write<K, V>` added to the snapshot's dynamic_field
//!   module: it calls `borrow_child_object_mut<Field<K, V>>` once, reads the old name and value
//!   and writes the new ones field by field (WriteRef, so the old VMs' dirty flag is set as by
//!   Move code). The old session API cannot hand out the reference itself.
//!
//! Results fields the old runtimes do not produce come out empty in the same shape: "acc" [] and
//! "settle" [0, 0] before v3; v0's loaded child objects have no modified flag (null), and its
//! created / deleted ids come from WriteKind::Create and DeleteKind::{Normal, UnwrapThenDelete}.

use anyhow::{Context, Result, anyhow, bail};
use move_binary_format::CompiledModule;
use move_binary_format::file_format::{
    AbilitySet, Bytecode, CodeUnit, FieldHandle, FieldInstantiation, FunctionDefinition, FunctionHandle,
    FunctionInstantiation, Signature, SignatureToken, Visibility,
};
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::{ModuleId, TypeTag};
use move_core_types::resolver::{ModuleResolver, SerializedPackage};
use move_core_types::runtime_value::{MoveTypeLayout, MoveValue};
use serde_json::{Value as J, json};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use sui_types::base_types::{SequenceNumber, SuiAddress, TxContext};
use sui_types::digests::TransactionDigest;
use sui_types::in_memory_storage::InMemoryStorage;
use sui_types::metrics::ExecutionMetrics;
use sui_types::object::Object;

use crate::vm::{Ctx, DEFAULT_CTX, ObjEnv};

/// The pv whose output goes to `cuts/vN` (others go to `cuts/vN-<pv>`).
const REF_PV: [u64; 4] = [17, 30, 37, 103];
const PATCH_FN: &str = "zui_write";

fn addr_of(a: u16) -> AccountAddress {
    let mut b = [0u8; 32];
    b[30] = (a >> 8) as u8;
    b[31] = a as u8;
    AccountAddress::new(b)
}
fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

/// One call of a script, as it will run in the cut.
#[derive(Clone)]
pub struct CCall {
    addr: u16,
    module: String,
    func: String,
    ty_args: Vec<TypeTag>,
    args: Vec<Vec<u8>>,
    budget: u64,
    write: Option<Vec<u8>>,
}

pub struct Script {
    ctx: Ctx,
    calls: Vec<CCall>,
    env: Option<ObjEnv>,
}

pub enum Out {
    Ok { rets: Vec<Vec<u8>>, muts: Vec<Vec<u8>> },
    Abort(u64),
    Err { status: u64, sub: Option<u64> },
}

pub struct CallTruth {
    params: Vec<(u8, Vec<u8>)>,
    rets: Vec<(u8, Vec<u8>)>,
    tys: Vec<(Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>)>, // tag, runtime layout, annotated layout
    out: Out,
    cost: Vec<u64>,
}

/// Why a script did not produce a line.
pub enum Skip {
    Drop(String),
    Fail(anyhow::Error),
}
impl From<anyhow::Error> for Skip {
    fn from(e: anyhow::Error) -> Self {
        Skip::Fail(e)
    }
}

/// The framework snapshot of a pv: package objects and the compiled modules.
pub struct Framework {
    objects: Vec<Object>,
    modules: BTreeMap<ModuleId, CompiledModule>,
    bytes: BTreeMap<ModuleId, Vec<u8>>,
    deps: BTreeMap<AccountAddress, Vec<AccountAddress>>,
}

impl Framework {
    fn load(pv: u64) -> Result<Self> {
        let pkgs = sui_framework_snapshot::load_bytecode_snapshot(pv)?;
        let mut fw = Framework { objects: vec![], modules: BTreeMap::new(), bytes: BTreeMap::new(), deps: BTreeMap::new() };
        for p in &pkgs {
            fw.objects.push(p.genesis_object());
            fw.deps.insert(p.id.into(), p.dependencies.iter().map(|d| (*d).into()).collect());
            for b in &p.bytes {
                let m = CompiledModule::deserialize_with_defaults(b).map_err(|e| anyhow!("snapshot module: {e:?}"))?;
                let id = m.self_id();
                fw.bytes.insert(id.clone(), b.clone());
                fw.modules.insert(id, m);
            }
        }
        Ok(fw)
    }

    /// Some(true) native, Some(false) Move code, None no such function.
    fn is_native(&self, addr: u16, module: &str, func: &str) -> Option<bool> {
        let m = self.modules.get(&ModuleId::new(addr_of(addr), Identifier::new(module).ok()?))?;
        m.function_defs
            .iter()
            .find(|d| m.identifier_at(m.function_handle_at(d.function).name).as_str() == func)
            .map(|d| d.is_native())
    }

    fn has_module(&self, addr: u16, module: &str) -> bool {
        Identifier::new(module).map(|m| self.modules.contains_key(&ModuleId::new(addr_of(addr), m))).unwrap_or(false)
    }
}

/// Module resolver over the snapshot (the old VMs only ask for modules by id).
pub struct Res {
    bytes: BTreeMap<ModuleId, Vec<u8>>,
    deps: BTreeMap<AccountAddress, Vec<AccountAddress>>,
}
#[derive(Debug)]
pub struct ResErr;

impl ModuleResolver for Res {
    type Error = ResErr;
    fn get_packages_static<const N: usize>(&self, ids: [AccountAddress; N]) -> Result<[Option<SerializedPackage>; N], ResErr> {
        Ok(ids.map(|a| self.package(&a)))
    }
    fn get_packages<'a>(&self, ids: impl ExactSizeIterator<Item = &'a AccountAddress>) -> Result<Vec<Option<SerializedPackage>>, ResErr> {
        Ok(ids.map(|a| self.package(a)).collect())
    }
    fn get_module(&self, id: &ModuleId) -> Result<Option<Vec<u8>>, ResErr> {
        Ok(self.bytes.get(id).cloned())
    }
}

impl Res {
    fn package(&self, a: &AccountAddress) -> Option<SerializedPackage> {
        let modules: BTreeMap<Identifier, Vec<u8>> =
            self.bytes.iter().filter(|(id, _)| id.address() == a).map(|(id, b)| (id.name().to_owned(), b.clone())).collect();
        if modules.is_empty() {
            return None;
        }
        let mut linkage: BTreeMap<AccountAddress, AccountAddress> = self.deps.get(a).into_iter().flatten().map(|d| (*d, *d)).collect();
        linkage.insert(*a, *a);
        Some(SerializedPackage { modules, version_id: *a, original_id: *a, linkage_table: linkage, type_origin_table: Default::default(), version: 1 })
    }
}

fn intern_sig(m: &mut CompiledModule, s: Vec<SignatureToken>) -> move_binary_format::file_format::SignatureIndex {
    let s = Signature(s);
    if let Some(i) = m.signatures.iter().position(|x| *x == s) {
        return move_binary_format::file_format::SignatureIndex(i as u16);
    }
    m.signatures.push(s);
    move_binary_format::file_format::SignatureIndex((m.signatures.len() - 1) as u16)
}

/// The snapshot's dynamic_field plus
/// `public fun zui_write<K: copy+drop+store, V: copy+drop+store>(o: &mut UID, id: address, k: K, v: V): (K, V)`
/// which borrows `Field<K, V>` mutably once, returns the old name and value and writes the new ones.
fn patch_dynamic_field(m: &CompiledModule) -> Result<Vec<u8>> {
    use move_binary_format::file_format::{
        FieldHandleIndex, FieldInstantiationIndex, FunctionHandleIndex, FunctionInstantiationIndex, IdentifierIndex,
        MemberCount, StructFieldInformation,
    };
    let mut m = m.clone();
    let fh = m
        .function_handles
        .iter()
        .position(|h| h.module == m.self_module_handle_idx && m.identifier_at(h.name).as_str() == "borrow_child_object_mut")
        .context("borrow_child_object_mut handle")?;
    let (sdi, sd) = m.find_struct_def_by_name("Field").context("Field")?;
    let field_dh = sd.struct_handle;
    let fields = match &sd.field_information {
        StructFieldInformation::Declared(f) => f.clone(),
        _ => bail!("Field is native"),
    };
    let pos = |n: &str| fields.iter().position(|f| m.identifier_at(f.name).as_str() == n).map(|i| i as MemberCount);
    let (fname, fval) = (pos("name").context("name")?, pos("value").context("value")?);
    let uid = match &m.signature_at(m.function_handles[fh].parameters).0[0] {
        SignatureToken::MutableReference(b) => (**b).clone(),
        t => bail!("first param {t:?}"),
    };
    let (t0, t1) = (SignatureToken::TypeParameter(0), SignatureToken::TypeParameter(1));
    let field_ty = SignatureToken::DatatypeInstantiation(Box::new((field_dh, vec![t0.clone(), t1.clone()])));
    let s_params = intern_sig(&mut m, vec![SignatureToken::MutableReference(Box::new(uid)), SignatureToken::Address, t0.clone(), t1.clone()]);
    let s_ret = intern_sig(&mut m, vec![t0.clone(), t1.clone()]);
    let s_locals = intern_sig(&mut m, vec![SignatureToken::MutableReference(Box::new(field_ty.clone()))]);
    let s_inst = intern_sig(&mut m, vec![field_ty]);
    let s_tps = intern_sig(&mut m, vec![t0, t1]);
    let finst = FunctionInstantiation { handle: FunctionHandleIndex(fh as u16), type_parameters: s_inst };
    let fi = match m.function_instantiations.iter().position(|x| *x == finst) {
        Some(i) => i,
        None => {
            m.function_instantiations.push(finst);
            m.function_instantiations.len() - 1
        }
    };
    let field_inst = |m: &mut CompiledModule, field: MemberCount| -> FieldInstantiationIndex {
        let h = FieldHandle { owner: sdi, field };
        let hi = match m.field_handles.iter().position(|x| *x == h) {
            Some(i) => i,
            None => {
                m.field_handles.push(h);
                m.field_handles.len() - 1
            }
        };
        let inst = FieldInstantiation { handle: FieldHandleIndex(hi as u16), type_parameters: s_tps };
        match m.field_instantiations.iter().position(|x| *x == inst) {
            Some(i) => FieldInstantiationIndex(i as u16),
            None => {
                m.field_instantiations.push(inst);
                FieldInstantiationIndex((m.field_instantiations.len() - 1) as u16)
            }
        }
    };
    let (fni, fvi) = (field_inst(&mut m, fname), field_inst(&mut m, fval));
    m.identifiers.push(Identifier::new(PATCH_FN)?);
    let name = IdentifierIndex((m.identifiers.len() - 1) as u16);
    m.function_handles.push(FunctionHandle {
        module: m.self_module_handle_idx,
        name,
        parameters: s_params,
        return_: s_ret,
        type_parameters: vec![AbilitySet::PRIMITIVES, AbilitySet::PRIMITIVES],
    });
    let handle = FunctionHandleIndex((m.function_handles.len() - 1) as u16);
    use Bytecode::*;
    let code = vec![
        MoveLoc(0),
        MoveLoc(1),
        CallGeneric(FunctionInstantiationIndex(fi as u16)),
        StLoc(4),
        CopyLoc(4),
        MutBorrowFieldGeneric(fni),
        ReadRef,
        CopyLoc(4),
        MutBorrowFieldGeneric(fvi),
        ReadRef,
        MoveLoc(2),
        CopyLoc(4),
        MutBorrowFieldGeneric(fni),
        WriteRef,
        MoveLoc(3),
        MoveLoc(4),
        MutBorrowFieldGeneric(fvi),
        WriteRef,
        Ret,
    ];
    m.function_defs.push(FunctionDefinition {
        function: handle,
        visibility: Visibility::Public,
        is_entry: false,
        acquires_global_resources: vec![],
        code: Some(CodeUnit { locals: s_locals, code, jump_tables: vec![] }),
    });
    let mut out = Vec::new();
    m.serialize_with_version(m.version, &mut out)?;
    Ok(out)
}

/// The write value (BCS of `Field<K, V>`) split into the BCS of its name and value.
fn split_field(write: &[u8], layout: &MoveTypeLayout) -> Result<(Vec<u8>, Vec<u8>)> {
    let MoveTypeLayout::Struct(st) = layout else { bail!("write type is not a struct") };
    let fl = st.fields();
    anyhow::ensure!(fl.len() == 3, "Field has {} fields", fl.len());
    let v = MoveValue::simple_deserialize(write, layout)?;
    let MoveValue::Struct(s) = v else { bail!("write value") };
    let f = s.into_fields();
    Ok((f[1].simple_serialize().context("name")?, f[2].simple_serialize().context("value")?))
}

fn tx_context(c: &Ctx, cfg: &ProtocolConfig) -> Result<Rc<RefCell<TxContext>>> {
    Ok(Rc::new(RefCell::new(TxContext::new_from_components(
        &SuiAddress::from_bytes(c.sender)?,
        &TransactionDigest::new(c.digest),
        &c.epoch,
        c.epoch_ts_ms,
        c.rgp,
        c.gas_price,
        c.gas_budget,
        c.sponsor.map(SuiAddress::from_bytes).transpose()?,
        cfg,
    ))))
}

/// One cut's VM over one framework snapshot.
pub trait CutVm {
    fn natives(&self) -> &BTreeSet<(AccountAddress, String, String)>;
    fn run(&self, s: &Script) -> Result<(Vec<CallTruth>, Option<J>), Skip>;
}

macro_rules! cut {
    ($m:ident, $vmrt:ident, $vmty:ident, $nat:ident, $adapter:ident,
     natives: |$ncfg:ident| $natives:expr,
     exts: |$res:ident, $inputs:ident, $metered:ident, $cfg:ident, $metrics:ident, $tx:ident| $exts:expr,
     exec: [$($extra:expr),*],
     results: |$sess:ident, $ort:ident| $results:block) => {
pub mod $m {
    use super::*;
    use $nat::object_runtime::{InputObject, ObjectRuntime};
    use $vmrt::move_vm::MoveVM;
    use $vmrt::session::Session;
    use $vmty::gas::{GasMeter, SimpleInstruction};
    use $vmty::loaded_data::runtime_types::Type;
    use $vmty::views::{TypeView, ValueView};
    use move_core_types::gas_algebra::InternalGas;
    use move_core_types::identifier::IdentStr;
    use move_core_types::language_storage::StructTag;
    use move_binary_format::errors::{PartialVMResult as PR, VMError};

    #[allow(unused_imports)]
    use $vmty::values::Value;

    /// Records the native's charge; the base native invocation charges nothing else that matters.
    struct RecMeter {
        budget: u64,
        native: Vec<u64>,
    }

    impl GasMeter for RecMeter {
        fn charge_simple_instr(&mut self, _: SimpleInstruction) -> PR<()> { Ok(()) }
        fn charge_pop(&mut self, _: impl ValueView) -> PR<()> { Ok(()) }
        fn charge_call(&mut self, _: &ModuleId, _: &str, _: impl IntoIterator<Item = impl ValueView>, _: u64) -> PR<()> { Ok(()) }
        fn charge_call_generic(&mut self, _: &ModuleId, _: &str, _: impl ExactSizeIterator<Item = impl TypeView>, _: impl ExactSizeIterator<Item = impl ValueView>, _: u64) -> PR<()> { Ok(()) }
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
        fn charge_vec_pack<'a>(&mut self, _: impl TypeView + 'a, _: impl ExactSizeIterator<Item = impl ValueView>) -> PR<()> { Ok(()) }
        fn charge_vec_len(&mut self, _: impl TypeView) -> PR<()> { Ok(()) }
        fn charge_vec_borrow(&mut self, _: bool, _: impl TypeView, _: bool) -> PR<()> { Ok(()) }
        fn charge_vec_push_back(&mut self, _: impl TypeView, _: impl ValueView) -> PR<()> { Ok(()) }
        fn charge_vec_pop_back(&mut self, _: impl TypeView, _: Option<impl ValueView>) -> PR<()> { Ok(()) }
        fn charge_vec_unpack(&mut self, _: impl TypeView, _: u64, _: impl ExactSizeIterator<Item = impl ValueView>) -> PR<()> { Ok(()) }
        fn charge_vec_swap(&mut self, _: impl TypeView) -> PR<()> { Ok(()) }
        fn charge_native_function(&mut self, amount: InternalGas, _: Option<impl ExactSizeIterator<Item = impl ValueView>>) -> PR<()> {
            self.native.push(u64::from(amount));
            Ok(())
        }
        fn charge_native_function_before_execution(&mut self, _: impl ExactSizeIterator<Item = impl TypeView>, _: impl ExactSizeIterator<Item = impl ValueView>) -> PR<()> { Ok(()) }
        fn charge_drop_frame(&mut self, _: impl Iterator<Item = impl ValueView>) -> PR<()> { Ok(()) }
        fn remaining_gas(&self) -> InternalGas { InternalGas::new(self.budget) }
    }

    impl $vmty::data_store::LinkageResolver for Res {
        type Error = ResErr;
    }

    pub struct Cut {
        cfg: ProtocolConfig,
        fw: Framework,
        res: Res,
        res_w: Res,
        vm: MoveVM,
        vm_w: MoveVM,
        natives: BTreeSet<(AccountAddress, String, String)>,
        metrics: Arc<ExecutionMetrics>,
    }

    fn mk_vm(cfg: &ProtocolConfig) -> Result<MoveVM> {
        let $ncfg = cfg;
        $adapter::adapter::new_move_vm($natives, cfg).map_err(|e| anyhow!("new_move_vm: {e:?}"))
    }

    impl Cut {
        pub fn new(pv: u64, fw: Framework) -> Result<Self> {
            let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(pv), Chain::Mainnet);
            let natives = {
                let $ncfg = &cfg;
                let t = $natives;
                t.iter().map(|(a, m, f, _)| (*a, m.to_string(), f.to_string())).collect()
            };
            let vm = mk_vm(&cfg)?;
            let vm_w = mk_vm(&cfg)?;
            let mut bytes_w = fw.bytes.clone();
            let df = ModuleId::new(addr_of(2), Identifier::new("dynamic_field")?);
            if let Some(m) = fw.modules.get(&df) {
                bytes_w.insert(df, patch_dynamic_field(m)?);
            }
            let res = Res { bytes: fw.bytes.clone(), deps: fw.deps.clone() };
            let res_w = Res { bytes: bytes_w, deps: fw.deps.clone() };
            let metrics = Arc::new(ExecutionMetrics::new(&prometheus::Registry::new()));
            Ok(Cut { cfg, fw, res, res_w, vm, vm_w, natives, metrics })
        }
    }

    fn vm_out(e: &VMError) -> Out {
        if e.major_status() == move_core_types::vm_status::StatusCode::ABORTED {
            Out::Abort(e.sub_status().unwrap_or(0))
        } else {
            Out::Err { status: e.major_status() as u64, sub: e.sub_status() }
        }
    }

    fn drop_err(what: String) -> Skip { Skip::Drop(what) }

    fn split_ref(t: &Type, ty_args: &[Type]) -> Result<(Type, u8), Skip> {
        let (inner, k) = match t {
            Type::Reference(i) => (&**i, 1u8),
            Type::MutableReference(i) => (&**i, 2u8),
            t => (t, 0u8),
        };
        Ok((inner.subst(ty_args).map_err(|e| anyhow!("subst: {e:?}"))?, k))
    }

    fn one(sess: &mut Session<'_, '_, &Res>, c: &CCall) -> Result<CallTruth, Skip> {
        let module = ModuleId::new(addr_of(c.addr), Identifier::new(c.module.as_str()).map_err(|e| anyhow!("{e}"))?);
        let fname = Identifier::new(c.func.as_str()).map_err(|e| anyhow!("{e}"))?;
        let mut ty_args = Vec::new();
        let mut tys = Vec::new();
        for t in &c.ty_args {
            let ty = sess.load_type(t).map_err(|e| drop_err(format!("type not in framework ({:?})", e.major_status())))?;
            ty_args.push(ty);
            let lay = sess.get_type_layout(t).ok().map(|l| bcs::to_bytes(&l).unwrap());
            let ann = sess.get_fully_annotated_type_layout(t).ok().map(|l| bcs::to_bytes(&l).unwrap());
            tys.push((bcs::to_bytes(t).map_err(|e| anyhow!("{e}"))?, lay, ann));
        }
        let inst = sess
            .load_function(&module, &fname, &ty_args)
            .map_err(|e| drop_err(format!("function does not load ({:?})", e.major_status())))?;
        if inst.parameters.len() != c.args.len() {
            return Err(drop_err(format!("arity differs in framework: {}::{}", module, c.func)));
        }
        let mut params = Vec::new();
        for (p, a) in inst.parameters.iter().zip(&c.args) {
            let (inner, k) = split_ref(p, &ty_args)?;
            let l = sess.type_to_type_layout(&inner).map_err(|e| drop_err(format!("param layout ({:?})", e.major_status())))?;
            if MoveValue::simple_deserialize(a, &l).is_err() {
                return Err(drop_err("arg does not decode under the framework's layout".into()));
            }
            params.push((k, bcs::to_bytes(&l).map_err(|e| anyhow!("{e}"))?));
        }
        let mut rets = Vec::new();
        let mut ret_lays = Vec::new();
        for r in &inst.return_ {
            let (inner, k) = split_ref(r, &ty_args)?;
            let l = sess.type_to_type_layout(&inner).map_err(|e| drop_err(format!("return layout ({:?})", e.major_status())))?;
            rets.push((k, bcs::to_bytes(&l).map_err(|e| anyhow!("{e}"))?));
            ret_lays.push(l);
        }
        let mut meter = RecMeter { budget: c.budget, native: vec![] };
        let out = if let Some(w) = &c.write {
            // borrow_child_object_mut<Field<K, V>> then write: through the patched helper
            let TypeTag::Struct(st) = &c.ty_args[0] else { return Err(drop_err("write on a non-struct type".into())) };
            if st.name.as_str() != "Field" || st.type_params.len() != 2 {
                return Err(drop_err("write on a type other than dynamic_field::Field".into()));
            }
            if ret_lays.len() != 1 {
                return Err(Skip::Fail(anyhow!("borrow_child_object_mut returns one value")));
            }
            let (k, v) = split_field(w, &ret_lays[0])?;
            let kv: Vec<Type> = st.type_params.iter().map(|t| sess.load_type(t)).collect::<Result<_, _>>().map_err(|e| anyhow!("{e:?}"))?;
            let args = vec![c.args[0].clone(), c.args[1].clone(), k, v];
            let helper = IdentStr::new(PATCH_FN).map_err(|e| anyhow!("{e}"))?;
            match sess.execute_function_bypass_visibility(&module, helper, kv, args, &mut meter $(, $extra)*) {
                Ok(r) => {
                    let mut field = c.args[1].clone(); // the child's UID is its id
                    for (b, _) in &r.return_values {
                        field.extend_from_slice(b);
                    }
                    Out::Ok { rets: vec![field], muts: r.mutable_reference_outputs.into_iter().map(|(_, b, _)| b).collect() }
                }
                Err(e) => vm_out(&e),
            }
        } else {
            match sess.execute_function_bypass_visibility(&module, &fname, ty_args, c.args.clone(), &mut meter $(, $extra)*) {
                Ok(r) => Out::Ok {
                    rets: r.return_values.into_iter().map(|(b, _)| b).collect(),
                    muts: r.mutable_reference_outputs.into_iter().map(|(_, b, _)| b).collect(),
                },
                Err(e) => vm_out(&e),
            }
        };
        Ok(CallTruth { params, rets, tys, out, cost: meter.native })
    }

    /// `NativeContextExtensions::remove` returns the extension before v3 and a Result in v3.
    trait TakeOrt<'a> {
        fn take(self) -> Result<ObjectRuntime<'a>>;
    }
    impl<'a> TakeOrt<'a> for ObjectRuntime<'a> {
        fn take(self) -> Result<ObjectRuntime<'a>> { Ok(self) }
    }
    impl<'a, E: std::fmt::Debug> TakeOrt<'a> for std::result::Result<ObjectRuntime<'a>, E> {
        fn take(self) -> Result<ObjectRuntime<'a>> { self.map_err(|e| anyhow!("object runtime: {e:?}")) }
    }

    #[allow(unused_variables, unused_mut)]
    fn results($sess: &Session<'_, '_, &Res>, $ort: ObjectRuntime<'_>) -> Result<J> $results

    impl CutVm for Cut {
        fn natives(&self) -> &BTreeSet<(AccountAddress, String, String)> {
            &self.natives
        }

        fn run(&self, s: &Script) -> Result<(Vec<CallTruth>, Option<J>), Skip> {
            let mut objs = self.fw.objects.clone();
            if let Some(e) = &s.env {
                objs.extend(e.objects.iter().cloned());
            }
            let storage = InMemoryStorage::new(objs);
            let mut inputs = BTreeMap::new();
            for (id, version, owner, uids) in s.env.as_ref().map(|e| e.inputs.clone()).unwrap_or_default() {
                inputs.insert(id, InputObject { contained_uids: uids.into_iter().collect(), version: SequenceNumber::from_u64(version), owner });
            }
            let $res = &storage;
            let $inputs = inputs;
            let $metered = !s.env.as_ref().map(|e| e.unmetered).unwrap_or(false);
            let $cfg = &self.cfg;
            let $metrics = self.metrics.clone();
            let $tx = tx_context(&s.ctx, &self.cfg)?;
            let exts = $exts;
            let write = s.calls.iter().any(|c| c.write.is_some());
            let (vm, res) = if write { (&self.vm_w, &self.res_w) } else { (&self.vm, &self.res) };
            let mut sess = vm.new_session_with_extensions(res, exts);
            let mut out = Vec::new();
            for c in &s.calls {
                out.push(one(&mut sess, c)?);
            }
            if s.env.is_none() {
                return Ok((out, None));
            }
            let ort = TakeOrt::take(sess.get_native_extensions().remove::<ObjectRuntime>())?;
            let r = results(&sess, ort)?;
            Ok((out, Some(r)))
        }
    }
}
    };
}

fn finish_err(e: &sui_types::error::ExecutionError) -> J {
    let k = format!("{:?}", e.kind());
    let k = k.split(|c: char| c == ' ' || c == '{' || c == '(').next().unwrap_or("").to_string();
    json!({"err": k})
}

cut!(v0, move_vm_runtime_v0, move_vm_types_v0, sui_move_natives_v0, sui_adapter_v0,
    natives: |cfg| { let _ = cfg; sui_move_natives_v0::all_natives(true) },
    exts: |res, inputs, metered, cfg, metrics, tx| { let _ = &tx; sui_adapter_v0::adapter::new_native_extensions(res, inputs, metered, cfg, metrics) },
    exec: [],
    results: |sess, ort| {
        use sui_types::storage::{DeleteKind, WriteKind};
        let r = match ort.finish(BTreeSet::new(), BTreeSet::new()) {
            Err(e) => return Ok(finish_err(&e)),
            Ok(r) => r,
        };
        let lay = |t: &Type| sess.type_to_type_layout(t).map_err(|e| anyhow!("layout: {e:?}"));
        let st_of = |t: &Type| -> Result<StructTag> {
            match sess.get_type_tag(t).map_err(|e| anyhow!("tag: {e:?}"))? {
                TypeTag::Struct(s) => Ok(*s),
                t => bail!("non-struct object type {t}"),
            }
        };
        let mut writes = Vec::new();
        let mut created = Vec::new();
        for (id, (kind, owner, ty, v)) in &r.writes {
            if matches!(kind, WriteKind::Create) { created.push(hx(id.as_ref())); }
            let st = st_of(ty)?;
            writes.push(json!([hx(id.as_ref()), hx(&bcs::to_bytes(owner)?), hx(&bcs::to_bytes(&st)?), hx(&v.simple_serialize(&lay(ty)?).context("write value")?)]));
        }
        let mut events = Vec::new();
        for (ty, st, v) in &r.user_events {
            events.push(json!([hx(&bcs::to_bytes(st)?), hx(&v.simple_serialize(&lay(ty)?).context("event value")?)]));
        }
        let deleted: Vec<_> = r.deletions.iter().filter(|(_, k)| matches!(k, DeleteKind::Normal | DeleteKind::UnwrapThenDelete)).map(|(id, _)| hx(id.as_ref())).collect();
        // no by-value inputs here: every Wrap deletion is a wrapped child
        let wrap: Vec<_> = r.deletions.iter().filter(|(_, k)| matches!(k, DeleteKind::Wrap)).map(|(id, _)| hx(id.as_ref())).collect();
        let loaded: Vec<_> = r.loaded_child_objects.iter().map(|(id, v)| json!([hx(id.as_ref()), v.value(), J::Null])).collect();
        Ok(json!({"ok": {"writes": writes, "events": events, "acc": [], "loaded": loaded, "created": created, "deleted": deleted, "v0_wrap": wrap, "settle": [0, 0]}}))
    }
);

/// v1 and v2 share RuntimeResults (writes with a runtime Type, events with Type and StructTag).
macro_rules! results_v12 {
    ($sess:ident, $ort:ident, $ids:ident) => {{
        let r = match $ort.finish() {
            Err(e) => return Ok(finish_err(&e)),
            Ok(r) => r,
        };
        let lay = |t: &Type| $sess.type_to_type_layout(t).map_err(|e| anyhow!("layout: {e:?}"));
        let st_of = |t: &Type| -> Result<StructTag> {
            match $sess.get_type_tag(t).map_err(|e| anyhow!("tag: {e:?}"))? {
                TypeTag::Struct(s) => Ok(*s),
                t => bail!("non-struct object type {t}"),
            }
        };
        let mut writes = Vec::new();
        for (id, (owner, ty, v)) in &r.writes {
            let st = st_of(ty)?;
            writes.push(json!([hx(id.as_ref()), hx(&bcs::to_bytes(owner)?), hx(&bcs::to_bytes(&st)?), hx(&v.simple_serialize(&lay(ty)?).context("write value")?)]));
        }
        let mut events = Vec::new();
        for (ty, st, v) in &r.user_events {
            events.push(json!([hx(&bcs::to_bytes(st)?), hx(&v.simple_serialize(&lay(ty)?).context("event value")?)]));
        }
        let loaded: Vec<_> = r.loaded_child_objects.iter().map(|(id, l)| json!([hx(id.as_ref()), l.version.value(), l.is_modified])).collect();
        Ok(json!({"ok": {
            "writes": writes, "events": events, "acc": [], "loaded": loaded,
            "created": r.created_object_ids.$ids().map(|x| hx(x.as_ref())).collect::<Vec<_>>(),
            "deleted": r.deleted_object_ids.$ids().map(|x| hx(x.as_ref())).collect::<Vec<_>>(),
            "settle": [0, 0],
        }}))
    }};
}

cut!(v1, move_vm_runtime_v1, move_vm_types_v1, sui_move_natives_v1, sui_adapter_v1,
    natives: |cfg| { let _ = cfg; sui_move_natives_v1::all_natives(true) },
    exts: |res, inputs, metered, cfg, metrics, tx| { let ep = tx.borrow().epoch(); sui_adapter_v1::adapter::new_native_extensions(res, inputs, metered, cfg, metrics, ep) },
    exec: [],
    results: |sess, ort| { results_v12!(sess, ort, keys) }
);

cut!(v2, move_vm_runtime_v2, move_vm_types_v2, sui_move_natives_v2, sui_adapter_v2,
    natives: |cfg| { let _ = cfg; sui_move_natives_v2::all_natives(true) },
    exts: |res, inputs, metered, cfg, metrics, tx| { let ep = tx.borrow().epoch(); sui_adapter_v2::adapter::new_native_extensions(res, inputs, metered, cfg, metrics, ep) },
    exec: [],
    results: |sess, ort| { results_v12!(sess, ort, iter) }
);

cut!(v3, move_vm_runtime_v3, move_vm_types_v3, sui_move_natives_v3, sui_adapter_v3,
    natives: |cfg| sui_move_natives_v3::all_natives(true, cfg),
    exts: |res, inputs, metered, cfg, metrics, tx| sui_adapter_v3::adapter::new_native_extensions(res, inputs, metered, cfg, metrics, tx),
    exec: [None],
    results: |sess, ort| {
        use sui_move_natives_v3::object_runtime::{MoveAccumulatorAction, MoveAccumulatorValue};
        let r = match ort.finish() {
            Err(e) => return Ok(finish_err(&e)),
            Ok(r) => r,
        };
        let lay = |t: &TypeTag| sess.get_type_layout(t).map_err(|e| anyhow!("layout {t}: {e:?}"));
        let mut writes = Vec::new();
        for (id, (owner, ty, v)) in &r.writes {
            let st: StructTag = ty.clone().into();
            let tt = TypeTag::Struct(Box::new(st.clone()));
            writes.push(json!([hx(id.as_ref()), hx(&bcs::to_bytes(owner)?), hx(&bcs::to_bytes(&st)?), hx(&v.typed_serialize(&lay(&tt)?).context("write value")?)]));
        }
        let mut events = Vec::new();
        for (st, v) in &r.user_events {
            let tt = TypeTag::Struct(Box::new(st.clone()));
            events.push(json!([hx(&bcs::to_bytes(st)?), hx(&v.typed_serialize(&lay(&tt)?).context("event value")?)]));
        }
        let acc: Vec<_> = r.accumulator_events.iter().map(|e| {
            let (k, n) = match e.value { MoveAccumulatorValue::U64(n) => (0, n), MoveAccumulatorValue::EventRef(n) => (1, n) };
            let a = match e.action { MoveAccumulatorAction::Merge => 0, MoveAccumulatorAction::Split => 1 };
            json!([hx(e.accumulator_id.as_ref()), a, hx(e.target_addr.as_ref()), hx(&bcs::to_bytes(&e.target_ty).unwrap()), k, n])
        }).collect();
        let loaded: Vec<_> = r.loaded_child_objects.iter().map(|(id, l)| json!([hx(id.as_ref()), l.version.value(), l.is_modified])).collect();
        Ok(json!({"ok": {
            "writes": writes, "events": events, "acc": acc, "loaded": loaded,
            "created": r.created_object_ids.iter().map(|x| hx(x.as_ref())).collect::<Vec<_>>(),
            "deleted": r.deleted_object_ids.iter().map(|x| hx(x.as_ref())).collect::<Vec<_>>(),
            "settle": [r.settlement_input_sui, r.settlement_output_sui],
        }}))
    }
);

/// A line of `vectors/natives/<group>.jsonl` back into its script.
pub fn parse_line(d: &J) -> Result<(Option<Ctx>, Vec<CCall>, Option<ObjEnv>, bool)> {
    let hexd = |s: &str| hex::decode(s).map_err(|e| anyhow!("{e}"));
    let ctx = match &d["ctx"] {
        J::Object(o) => Some(Ctx {
            sender: hexd(o["sender"].as_str().context("sender")?)?.try_into().map_err(|_| anyhow!("sender"))?,
            digest: hexd(o["digest"].as_str().context("digest")?)?.try_into().map_err(|_| anyhow!("digest"))?,
            epoch: o["epoch"].as_u64().context("epoch")?,
            epoch_ts_ms: o["epoch_ts_ms"].as_u64().context("ts")?,
            rgp: o["rgp"].as_u64().context("rgp")?,
            gas_price: o["gas_price"].as_u64().context("gas_price")?,
            gas_budget: o["gas_budget"].as_u64().context("gas_budget")?,
            sponsor: match o["sponsor"].as_str() {
                Some(s) => Some(hexd(s)?.try_into().map_err(|_| anyhow!("sponsor"))?),
                None => None,
            },
        }),
        _ => None,
    };
    let mut calls = Vec::new();
    let mut shaped = false;
    for c in d["calls"].as_array().context("calls")? {
        let tys = c["tys"].as_array().context("tys")?;
        shaped |= tys.iter().any(|t| t.get("shape").is_some());
        calls.push(CCall {
            addr: c["addr"].as_u64().context("addr")? as u16,
            module: c["module"].as_str().context("module")?.to_string(),
            func: c["func"].as_str().context("func")?.to_string(),
            ty_args: tys.iter().map(|t| Ok(bcs::from_bytes(&hexd(t["tag"].as_str().context("tag")?)?)?)).collect::<Result<_>>()?,
            args: c["args"].as_array().context("args")?.iter().map(|a| hexd(a.as_str().unwrap_or_default())).collect::<Result<_>>()?,
            budget: c["budget"].as_u64().context("budget")?,
            write: c["write"].as_str().map(hexd).transpose()?,
        });
    }
    let env = match &d["env"] {
        J::Object(e) => Some(crate::objrt::env_from_json(e)?),
        _ => None,
    };
    Ok((ctx, calls, env, shaped))
}

/// Maps the latest script's calls to the cut: Ok(calls as they run) or Err(drop reason).
fn map_calls(calls: &[CCall], fw: &Framework, natives: &BTreeSet<(AccountAddress, String, String)>, digest: [u8; 32]) -> Result<Vec<CCall>, String> {
    let mut out = Vec::new();
    let mut fresh = 0u64;
    let ok = |c: &CCall| fw.is_native(c.addr, &c.module, &c.func) == Some(true) && natives.contains(&(addr_of(c.addr), c.module.clone(), c.func.clone()));
    for c in calls {
        let name = format!("0x{:x}::{}::{}", c.addr, c.module, c.func);
        if !fw.has_module(c.addr, &c.module) {
            return Err(format!("module not in framework: 0x{:x}::{}", c.addr, c.module));
        }
        if ok(c) {
            out.push(c.clone());
            continue;
        }
        let mut m = c.clone();
        let mapped = match (c.addr, c.module.as_str(), c.func.as_str()) {
            (1, "type_name", "with_defining_ids") => {
                m.func = "get".into();
                true
            }
            (1, "type_name", "with_original_ids") => {
                m.func = "get_with_original_ids".into();
                true
            }
            (2, "tx_context", "fresh_id") => {
                m.func = "derive_id".into();
                m.args = vec![bcs::to_bytes(&digest.to_vec()).unwrap(), fresh.to_le_bytes().to_vec()];
                fresh += 1;
                true
            }
            _ => false,
        };
        if mapped && ok(&m) {
            out.push(m);
            continue;
        }
        return Err(match fw.is_native(c.addr, &c.module, &c.func) {
            None => format!("function not in framework: {name}"),
            Some(false) => format!("not native in framework: {name}"),
            Some(true) => format!("native not in cut: {name}"),
        });
    }
    Ok(out)
}

fn line_json(d: &J, pv: u64, calls: &[CCall], truths: &[CallTruth], results: Option<J>) -> J {
    let has_env = d.get("env").map(|e| !e.is_null()).unwrap_or(false);
    let mut cj = Vec::new();
    for (c, t) in calls.iter().zip(truths) {
        let out = match &t.out {
            Out::Ok { rets, muts } => json!({"ok": {"rets": rets.iter().map(|r| hx(r)).collect::<Vec<_>>(), "muts": muts.iter().map(|r| hx(r)).collect::<Vec<_>>()}}),
            Out::Abort(code) => json!({"abort": code}),
            Out::Err { status, sub } => json!({"err": {"status": status, "sub": sub}}),
        };
        let mut o = json!({
            "addr": c.addr, "module": c.module, "func": c.func,
            "tys": t.tys.iter().map(|(tag, lay, ann)| {
                let mut o = json!({"tag": hx(tag), "layout": lay.as_ref().map(|l| hx(l))});
                if has_env { o["ann"] = json!(ann.as_ref().map(|l| hx(l))); }
                o
            }).collect::<Vec<_>>(),
            "params": t.params.iter().map(|(k, l)| json!([k, hx(l)])).collect::<Vec<_>>(),
            "rets": t.rets.iter().map(|(_, l)| hx(l)).collect::<Vec<_>>(),
            "args": c.args.iter().map(|a| hx(a)).collect::<Vec<_>>(),
            "budget": c.budget, "out": out, "cost": t.cost,
        });
        if t.rets.iter().any(|(k, _)| *k != 0) { o["ret_ref"] = json!(true); }
        if let Some(w) = &c.write { o["write"] = json!(hx(w)); }
        cj.push(o);
    }
    let mut line = json!({"id": d["id"].clone(), "pv": pv, "ctx": d["ctx"].clone(), "calls": cj});
    if has_env {
        line["env"] = d["env"].clone();
        line["results"] = results.unwrap_or(J::Null);
    }
    line
}

pub fn run_cut(cut: &str, pv: u64, corpus: &Path) -> Result<()> {
    let n: u64 = match cut {
        "v0" => 0,
        "v1" => 1,
        "v2" => 2,
        "v3" => 3,
        _ => bail!("cut must be v0, v1, v2 or v3"),
    };
    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(pv), Chain::Mainnet);
    let ev = cfg.execution_version_as_option().unwrap_or(0);
    anyhow::ensure!(ev == n, "pv {pv} runs execution version {ev}, not {cut}");
    let fw = Framework::load(pv)?;
    let vm: Box<dyn CutVm> = match n {
        0 => Box::new(v0::Cut::new(pv, fw)?),
        1 => Box::new(v1::Cut::new(pv, fw)?),
        2 => Box::new(v2::Cut::new(pv, fw)?),
        _ => Box::new(v3::Cut::new(pv, fw)?),
    };
    // Framework is moved into the cut; keep a second copy for the static checks.
    let fw = Framework::load(pv)?;
    let dir_name = if REF_PV[n as usize] == pv { cut.to_string() } else { format!("{cut}-{pv}") };
    let in_dir = corpus.join("vectors/natives");
    let out_dir = in_dir.join("cuts").join(&dir_name);
    std::fs::create_dir_all(&out_dir)?;
    let mut groups: Vec<_> = std::fs::read_dir(&in_dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("jsonl"))
        .collect();
    groups.sort();
    std::panic::set_hook(Box::new(|_| {}));
    let mut summary = serde_json::Map::new();
    let (mut tw, mut td) = (0usize, 0usize);
    for path in groups {
        let grp = path.file_stem().unwrap().to_str().unwrap().to_string();
        let text = std::fs::read_to_string(&path)?;
        let mut f = std::io::BufWriter::new(std::fs::File::create(out_dir.join(format!("{grp}.jsonl")))?);
        let mut seen: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        let mut drops: BTreeMap<String, usize> = BTreeMap::new();
        let mut written = 0usize;
        let mut fails = 0usize;
        for l in text.lines().filter(|l| !l.is_empty()) {
            let d: J = serde_json::from_str(l)?;
            let id = d["id"].as_str().unwrap_or("?").to_string();
            let (ctx, calls, env, shaped) = parse_line(&d).with_context(|| format!("parse {id}"))?;
            let ctx = ctx.unwrap_or(DEFAULT_CTX);
            if shaped {
                *drops.entry("stand-in type shape (old session API decodes with the real layout)".into()).or_default() += 1;
                continue;
            }
            let mapped = match map_calls(&calls, &fw, vm.natives(), ctx.digest) {
                Ok(m) => m,
                Err(r) => {
                    *drops.entry(r).or_default() += 1;
                    continue;
                }
            };
            // the pv-sweep groups repeat one script at many pvs: at one pv they are the same
            let key = json!([
                mapped.iter().map(|c| json!([c.addr, c.module, c.func, c.ty_args.iter().map(|t| hx(&bcs::to_bytes(t).unwrap())).collect::<Vec<_>>(),
                    c.args.iter().map(|a| hx(a)).collect::<Vec<_>>(), c.budget, c.write.as_ref().map(|w| hx(w))])).collect::<Vec<_>>(),
                d["ctx"], d.get("env").cloned().unwrap_or(J::Null)
            ])
            .to_string();
            // (identical scripts at the same pv stay, as in the latest file)
            let line_pv = d["pv"].as_u64().unwrap_or(0);
            let first_pv = *seen.entry(script_key(&key)).or_insert(line_pv);
            if first_pv != line_pv {
                *drops.entry("same script as an earlier line (pv sweep)".into()).or_default() += 1;
                continue;
            }
            let script = Script { ctx, calls: mapped.clone(), env };
            let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| vm.run(&script)));
            let run = match run {
                Ok(r) => r,
                Err(p) => {
                    // an old native that trusts its Move caller's guards (e.g. string::sub_string
                    // range checks): unreachable from a transaction
                    let msg = p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
                    let f = mapped.first().map(|c| format!("0x{:x}::{}::{}", c.addr, c.module, c.func)).unwrap_or_default();
                    if fails < 5 {
                        eprintln!("{grp}/{id}: native panicked: {msg}");
                    }
                    *drops.entry(format!("native panics on input its Move caller rules out: {f}")).or_default() += 1;
                    continue;
                }
            };
            match run {
                Ok((truths, results)) => {
                    writeln!(f, "{}", line_json(&d, pv, &mapped, &truths, results))?;
                    written += 1;
                }
                Err(Skip::Drop(r)) => *drops.entry(r).or_default() += 1,
                Err(Skip::Fail(e)) => {
                    if fails < 5 {
                        eprintln!("{grp}/{id}: {e:#}");
                    }
                    fails += 1;
                    *drops.entry("runner error".into()).or_default() += 1;
                }
            }
        }
        f.flush()?;
        let dropped: usize = drops.values().sum();
        eprintln!("{grp}: {written} written, {dropped} dropped");
        for (r, k) in &drops {
            eprintln!("    {k:6}  {r}");
        }
        tw += written;
        td += dropped;
        summary.insert(grp, json!({"written": written, "dropped": drops}));
    }
    let mut sf = std::fs::File::create(out_dir.join("drops.json"))?;
    writeln!(sf, "{}", serde_json::to_string_pretty(&json!({"cut": cut, "pv": pv, "written": tw, "dropped": td, "groups": summary}))?)?;
    eprintln!("cut {cut} pv {pv}: {tw} written, {td} dropped -> {}", out_dir.display());
    Ok(())
}

fn script_key(s: &str) -> [u8; 32] {
    use fastcrypto::hash::{Blake2b256, HashFunction};
    Blake2b256::digest(s.as_bytes()).digest
}
