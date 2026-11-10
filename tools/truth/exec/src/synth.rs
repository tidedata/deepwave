//! `synth <corpus> <out dir>`: synthetic execution vectors for paths the corpus never hits,
//! each produced by Mysten's executor (`sui_execution::executor`, `execute_transaction_to_effects`).
//!
//! A vector is a real corpus transaction (or one crafted from its inputs) run against the
//! corpus objects plus a few synthetic "latest" objects. Output `<out>/vectors.jsonl.zst`, one
//! line per vector:
//! `{"name","pv","epoch","rgp","start_ms","tx":hex TransactionData,"objects":[hex Object],
//!   "latest":[hex Object],"effects":hex,"events":hex|null,"written":[hex Object]}`.
//! `objects` are the input objects at their versions; `latest` the objects the executor read
//! through `get_object` outside the inputs (deny list v2 state). `events` is BCS
//! `TransactionEvents` when the transaction emitted any.
//!
//! Deny list vectors (`deny/...`): coin-only programmable transactions of execution version 4
//! that write a regulated `Coin<T>` (a 0x403 per-type config exists for T in the corpus deny
//! snapshot at the epoch), with synthetic `Setting<bool>` fields for the receiving address and
//! the global pause, epoch-gated both ways; and a crafted `0x2::coin::send_funds<T>` call so the
//! regulated owner comes from a `Balance<T>` accumulator event.
use crate::{ExecEnv, ExecStore, decode, is_reservation, list_chk, load_exec_env};
use anyhow::{Context, Result};
use move_core_types::language_storage::{StructTag, TypeTag};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use sui_types::base_types::{ObjectID, SequenceNumber, SuiAddress};
use sui_types::digests::TransactionDigest;
use sui_types::effects::{TransactionEffects, TransactionEffectsAPI};
use sui_types::object::{MoveObject, Object, Owner};
use sui_types::storage::ObjectStore;
use sui_types::transaction::{
    Argument, CallArg, Command, InputObjectKind, ObjectArg, ObjectReadResult, ObjectReadResultKind, ProgrammableMoveCall,
    ProgrammableTransaction, TransactionData, TransactionDataAPI, TransactionKind,
};

/// `deny/objects.bin.zst`: id -> [(write epoch, object)] in version order.
pub(crate) fn load_deny(corpus: &Path) -> Result<HashMap<ObjectID, Vec<(u64, Object)>>> {
    let mut raw = Vec::new();
    zstd::Decoder::new(std::fs::File::open(corpus.join("deny/objects.bin.zst")).context("deny/objects.bin.zst (run deny-snapshot)")?)?.read_to_end(&mut raw)?;
    let mut out: HashMap<ObjectID, Vec<(u64, Object)>> = HashMap::new();
    let mut at = 0;
    while at < raw.len() {
        let n = u32::from_le_bytes(raw[at..at + 4].try_into()?) as usize;
        at += 4;
        let epoch = u64::from_le_bytes(raw[at..at + 8].try_into()?);
        let o: Object = bcs::from_bytes(&raw[at + 8..at + n])?;
        at += n;
        out.entry(o.id()).or_default().push((epoch, o));
    }
    for v in out.values_mut() {
        v.sort_by_key(|(_, o)| o.version());
    }
    Ok(out)
}

/// The newest version of each deny object written at `epoch` or before.
pub(crate) fn deny_at(deny: &HashMap<ObjectID, Vec<(u64, Object)>>, epoch: u64) -> HashMap<ObjectID, Object> {
    deny.iter()
        .filter_map(|(id, l)| l.iter().filter(|(e, _)| *e <= epoch).last().map(|(_, o)| (*id, o.clone())))
        .collect()
}

struct MapStore<'a>(&'a HashMap<ObjectID, Object>);
impl ObjectStore for MapStore<'_> {
    fn get_object(&self, id: &ObjectID) -> Option<Object> {
        self.0.get(id).cloned()
    }
    fn get_object_by_key(&self, id: &ObjectID, v: SequenceNumber) -> Option<Object> {
        self.0.get(id).filter(|o| o.version() == v).cloned()
    }
}

fn fw(module: &str, name: &str, params: Vec<TypeTag>) -> StructTag {
    StructTag {
        address: move_core_types::account_address::AccountAddress::TWO,
        module: move_core_types::identifier::Identifier::new(module).unwrap(),
        name: move_core_types::identifier::Identifier::new(name).unwrap(),
        type_params: params,
    }
}

/// `Field<K, Setting<bool>>` under `config` with the given key, as the store holds it.
fn setting_object(config: ObjectID, key_name: &str, key: &[u8], newer_epoch: u64, newer: Option<bool>, older: Option<bool>) -> Result<Object> {
    let key_tag = TypeTag::Struct(Box::new(fw("deny_list", key_name, vec![])));
    let id = sui_types::dynamic_field::derive_dynamic_field_id(config, &key_tag, key)?;
    let mut contents = id.to_vec();
    contents.extend_from_slice(key);
    contents.push(1); // Option<SettingData>: Some
    contents.extend_from_slice(&newer_epoch.to_le_bytes());
    contents.extend(bcs::to_bytes(&newer)?);
    contents.extend(bcs::to_bytes(&older)?);
    let setting = TypeTag::Struct(Box::new(fw("config", "Setting", vec![TypeTag::Bool])));
    let field = fw("dynamic_field", "Field", vec![key_tag, setting]);
    let mo = unsafe { MoveObject::new_from_execution_with_limit(field.into(), false, SequenceNumber::from_u64(7), contents, 512)? };
    Ok(Object::new_move(mo, Owner::ObjectOwner(config.into()), TransactionDigest::new([0x5a; 32])))
}

struct Run {
    effects: TransactionEffects,
    events: Option<Vec<u8>>,
    written: Vec<Object>,
    /// Runtime-loaded objects (id, version) the transaction did not write: the archive's
    /// `unchanged_loaded_runtime_objects`.
    loaded: Vec<(ObjectID, u64)>,
}

struct Ctx<'a> {
    env: &'a ExecEnv,
    cfg: ProtocolConfig,
    ex: Arc<dyn sui_execution::Executor + Send + Sync>,
    metrics: Arc<sui_types::metrics::ExecutionMetrics>,
    epoch: u64,
}

impl Ctx<'_> {
    fn run(&self, data: &TransactionData, inputs: &HashMap<ObjectID, Object>, latest: &HashMap<ObjectID, Object>) -> Result<Run> {
        self.run_with(data, inputs, latest, None)
    }

    /// `run` with the transaction digest the executor is given (default: the data's digest).
    fn run_with(&self, data: &TransactionData, inputs: &HashMap<ObjectID, Object>, latest: &HashMap<ObjectID, Object>, digest: Option<TransactionDigest>) -> Result<Run> {
        self.run_sys(data, inputs, latest, digest, sui_types::base_types::SystemObjectVersions::empty())
    }

    /// `run_with` and the pinned versions of the implicitly read system objects (the Clock for
    /// `clock::borrow`, protocol 142).
    fn run_sys(&self, data: &TransactionData, inputs: &HashMap<ObjectID, Object>, latest: &HashMap<ObjectID, Object>, digest: Option<TransactionDigest>, sysv: sui_types::base_types::SystemObjectVersions) -> Result<Run> {
        let ep = self.env.epochs[self.epoch as usize];
        let store = ExecStore { inputs, packages: &self.env.packages, system: &self.env.system, epoch: self.epoch, latest: Some(latest) };
        let mut reads = Vec::new();
        for k in data.input_objects()? {
            if matches!(k, InputObjectKind::MovePackage(_)) {
                // the packages the commands name are input objects (effects dependencies before
                // `disable_effects_tx_dependencies`); a package the store lacks would fail
                // input loading on a node, the executor runs without it
                if let Some(p) = store.package(&k.object_id()) {
                    reads.push(ObjectReadResult::new(k, ObjectReadResultKind::Object(p)));
                }
                continue;
            }
            let o = inputs.get(&k.object_id()).context("input object")?;
            reads.push(ObjectReadResult::new(k, ObjectReadResultKind::Object(o.clone())));
        }
        let gas_status = sui_types::gas::SuiGasStatus::new(data.gas_data().budget, data.gas_data().price, ep.1, &self.cfg)?;
        let (inner, _, fx, _, _) = self.ex.execute_transaction_to_effects(
            &store,
            &self.cfg,
            self.metrics.clone(),
            false,
            sui_types::execution_params::ExecutionOrEarlyError::ok(None),
            &self.epoch,
            ep.2,
            sui_types::transaction::CheckedInputObjects::new_for_replay(sui_types::transaction::InputObjects::new(reads)),
            sysv,
            &sui_types::accumulator_root::EmptyUnsettledObjectFunds,
            data.gas_data().clone(),
            gas_status,
            data.kind().clone(),
            None,
            data.sender(),
            digest.unwrap_or_else(|| data.digest()),
            &mut None,
        );
        let events = if inner.events.data.is_empty() { None } else { Some(bcs::to_bytes(&inner.events)?) };
        let loaded = inner.loaded_runtime_objects.iter().filter(|(id, _)| !inner.written.contains_key(id)).map(|(id, m)| (*id, m.version.value())).collect();
        Ok(Run { effects: fx, events, written: inner.written.values().cloned().collect(), loaded })
    }
}

/// The deny objects a check over `types_owners` reads (config fields, pause and owner settings),
/// as they exist in `latest`.
fn deny_reads(latest: &HashMap<ObjectID, Object>, types_owners: &[(String, Vec<SuiAddress>)]) -> Result<Vec<Object>> {
    let store = MapStore(latest);
    let mut out = Vec::new();
    let deny = sui_types::SUI_DENY_LIST_OBJECT_ID;
    for (ty, owners) in types_owners {
        // Wrapper<ConfigKey { 0, ty }>
        let mut key = 0u64.to_le_bytes().to_vec();
        key.extend(bcs::to_bytes(&ty.as_bytes().to_vec())?);
        let wrapper = TypeTag::Struct(Box::new(fw("dynamic_object_field", "Wrapper", vec![TypeTag::Struct(Box::new(fw("deny_list", "ConfigKey", vec![])))])));
        let fid = sui_types::dynamic_field::derive_dynamic_field_id(deny, &wrapper, &key)?;
        let Some(field) = store.get_object(&fid) else { continue };
        out.push(field.clone());
        let Some(cfg) = sui_types::deny_list_v2::get_per_type_coin_deny_list_v2(ty, &store) else { continue };
        let cid = *cfg.id.object_id();
        let mut ids = vec![sui_types::dynamic_field::derive_dynamic_field_id(cid, &TypeTag::Struct(Box::new(fw("deny_list", "GlobalPauseKey", vec![]))), &[0])?];
        for o in owners {
            ids.push(sui_types::dynamic_field::derive_dynamic_field_id(cid, &TypeTag::Struct(Box::new(fw("deny_list", "AddressKey", vec![]))), &o.to_vec())?);
        }
        for id in ids {
            if let Some(o) = latest.get(&id) {
                out.push(o.clone());
            }
        }
    }
    Ok(out)
}

fn hexs(v: &[Object]) -> Result<Vec<String>> {
    v.iter().map(|o| Ok(hex::encode(bcs::to_bytes(o)?))).collect()
}

pub fn cmd_synth(corpus: &Path, out: &Path) -> Result<()> {
    let env = load_exec_env(corpus)?;
    let deny = load_deny(corpus).unwrap_or_else(|e| {
        eprintln!("synth: {e:#}; deny vectors skipped");
        HashMap::new()
    });
    let mut seqs = list_chk(corpus)?;
    seqs.sort();
    seqs.reverse();
    let registry = prometheus::Registry::new();
    let metrics = Arc::new(sui_types::metrics::ExecutionMetrics::new(&registry));
    let mut lines: Vec<String> = Vec::new();
    let mut coin_cases = 0;
    let mut send_cases = 0;
    let mut scanned = 0;
    let mut deny_obj: Option<Object> = None;
    let mut regulated: Option<(TypeTag, ObjectID, SuiAddress)> = None;
    let mut base: Option<(u64, TransactionData, Object)> = None;
    for seq in seqs {
        if coin_cases >= 2 && send_cases >= 2 && deny_obj.is_some() && base.is_some() {
            break;
        }
        let cp = decode(&corpus.join(format!("chk/{seq}.chk")))?;
        let epoch = cp.checkpoint_summary.epoch;
        // checkpoints of an epoch past the corpus epoch table (a later live window)
        let Some(&ep) = env.epochs.get(epoch as usize) else { continue };
        let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(ep.0), Chain::Mainnet);
        if cfg.execution_version_as_option() != Some(4) {
            continue;
        }
        scanned += 1;
        let latest = deny_at(&deny, epoch);
        let store = MapStore(&latest);
        let ctx = Ctx { env: &env, ex: sui_execution::executor(&cfg, true)?, cfg, metrics: metrics.clone(), epoch };
        for t in &cp.transactions {
            let data = t.transaction.data().transaction_data().clone();
            if deny_obj.is_none() {
                deny_obj = t.input_objects.iter().find(|o| o.id() == sui_types::SUI_DENY_LIST_OBJECT_ID).cloned();
            }
            // the crafted transactions' base: a sender paying with one owned gas coin, reproduced
            if base.is_none() && t.effects.status().is_ok() && data.gas_data().payment.len() == 1 && !is_reservation(&data.gas_data().payment[0].2) {
                if let TransactionKind::ProgrammableTransaction(_) = data.kind() {
                    let gas = t.input_objects.iter().find(|o| o.id() == data.gas_data().payment[0].0 && o.version() == data.gas_data().payment[0].1);
                    if let Some(g) = gas {
                        let inputs: HashMap<ObjectID, Object> = t.input_objects.iter().map(|o| (o.id(), o.clone())).collect();
                        let complete = data.input_objects().map(|ks| ks.iter().all(|k| matches!(k, InputObjectKind::MovePackage(_)) || inputs.contains_key(&k.object_id()))).unwrap_or(false);
                        if complete && ctx.run(&data, &inputs, &latest).map(|r| r.effects == t.effects).unwrap_or(false) {
                            base = Some((epoch, data.clone(), g.clone()));
                        }
                    }
                }
            }
            let TransactionKind::ProgrammableTransaction(pt) = data.kind() else { continue };
            if !pt.commands.iter().all(|c| matches!(c, Command::SplitCoins(..) | Command::MergeCoins(..) | Command::TransferObjects(..))) {
                continue;
            }
            if data.gas_data().payment.is_empty() || data.gas_data().payment.iter().any(|r| is_reservation(&r.2)) {
                continue;
            }
            if !t.effects.status().is_ok() {
                continue;
            }
            // a regulated Coin<T> written to an address owner
            let mut hit: Option<(TypeTag, String, SuiAddress, ObjectID)> = None;
            for o in &t.output_objects {
                let (Some(ty), Owner::AddressOwner(a)) = (o.coin_type_maybe(), &o.owner) else { continue };
                if sui_types::gas_coin::GAS::is_gas_type(&ty) {
                    continue;
                }
                let s = ty.to_canonical_string(false);
                if let Some(cfgobj) = sui_types::deny_list_v2::get_per_type_coin_deny_list_v2(&s, &store) {
                    hit = Some((ty, s, *a, *cfgobj.id.object_id()));
                    break;
                }
            }
            let Some((ty, tys, owner, config)) = hit else { continue };
            if regulated.is_none() {
                regulated = Some((ty.clone(), config, owner));
            }
            if coin_cases >= 2 && send_cases >= 2 {
                continue;
            }
            let inputs: HashMap<ObjectID, Object> = t.input_objects.iter().map(|o| (o.id(), o.clone())).collect();
            let ok_inputs = data.input_objects().map(|ks| ks.iter().all(|k| matches!(k, InputObjectKind::MovePackage(_)) || inputs.get(&k.object_id()).map(|o| Some(o.version()) == k.version()).unwrap_or(false)));
            if ok_inputs.ok() != Some(true) {
                continue;
            }
            // control: Rust reproduces the certified effects with the snapshot store
            let base = ctx.run(&data, &inputs, &latest)?;
            if base.effects != t.effects {
                eprintln!("synth: {} does not reproduce, skipped", t.transaction.digest());
                continue;
            }
            let mut variants: Vec<(String, TransactionData, Vec<Object>)> = Vec::new();
            let tag = format!("{}", t.transaction.digest());
            if coin_cases < 2 {
                variants.push((format!("deny/coin/{tag}/control"), data.clone(), vec![]));
                variants.push((format!("deny/coin/{tag}/address"), data.clone(), vec![setting_object(config, "AddressKey", &owner.to_vec(), epoch - 1, Some(true), None)?]));
                variants.push((format!("deny/coin/{tag}/address-next-epoch"), data.clone(), vec![setting_object(config, "AddressKey", &owner.to_vec(), epoch, Some(true), None)?]));
                variants.push((format!("deny/coin/{tag}/address-older"), data.clone(), vec![setting_object(config, "AddressKey", &owner.to_vec(), epoch, Some(false), Some(true))?]));
                variants.push((format!("deny/coin/{tag}/pause"), data.clone(), vec![setting_object(config, "GlobalPauseKey", &[0], epoch - 1, Some(true), None)?]));
                variants.push((
                    format!("deny/coin/{tag}/pause-and-address"),
                    data.clone(),
                    vec![setting_object(config, "GlobalPauseKey", &[0], epoch - 1, Some(true), None)?, setting_object(config, "AddressKey", &owner.to_vec(), epoch - 1, Some(true), None)?],
                ));
                variants.push((format!("deny/coin/{tag}/pause-none"), data.clone(), vec![setting_object(config, "GlobalPauseKey", &[0], epoch - 1, None, Some(true))?]));
                // out of gas at the deny-list charge: the smallest budget (in gas units) at which
                // 0x403 is recorded as a loaded per-epoch config (check_coin_deny_list runs before
                // charge_coin_transfers, so it stays when that charge fails)
                let with_budget = |units: u64| {
                    let mut g = data.gas_data().clone();
                    g.budget = units * g.price;
                    TransactionData::new_with_gas_data(data.kind().clone(), data.sender(), g)
                };
                let has_deny = |r: &Run| r.effects.unchanged_consensus_objects().iter().any(|(id, _)| *id == sui_types::SUI_DENY_LIST_OBJECT_ID);
                let (mut lo, mut hi) = (1u64, data.gas_data().budget / data.gas_data().price);
                if !has_deny(&ctx.run(&with_budget(lo), &inputs, &latest)?) && has_deny(&ctx.run(&with_budget(hi), &inputs, &latest)?) {
                    while hi - lo > 1 {
                        let mid = lo + (hi - lo) / 2;
                        if has_deny(&ctx.run(&with_budget(mid), &inputs, &latest)?) { hi = mid } else { lo = mid }
                    }
                    let oog = with_budget(hi);
                    let r = ctx.run(&oog, &inputs, &latest)?;
                    if matches!(r.effects.status(), sui_types::execution_status::ExecutionStatus::Failure(f) if matches!(f.error, sui_types::execution_status::ExecutionErrorKind::InsufficientGas)) {
                        variants.push((format!("deny/coin/{tag}/out-of-gas"), oog, vec![]));
                    } else {
                        eprintln!("synth: {tag}: smallest budget with 0x403 loaded ({hi} units) does not run out of gas: {:?}", r.effects.status());
                    }
                }
                coin_cases += 1;
            }
            // crafted: coin::send_funds<T>(the sender's input Coin<T>, owner)
            if send_cases < 2 {
                let coin_in = pt.inputs.iter().find_map(|a| match a {
                    CallArg::Object(ObjectArg::ImmOrOwnedObject(r)) => {
                        let o = inputs.get(&r.0)?;
                        (o.coin_type_maybe().as_ref() == Some(&ty) && matches!(o.owner, Owner::AddressOwner(a) if a == data.sender())).then_some(*r)
                    }
                    _ => None,
                });
                if let Some(r) = coin_in {
                    let crafted = ProgrammableTransaction {
                        inputs: vec![CallArg::Object(ObjectArg::ImmOrOwnedObject(r)), CallArg::Pure(bcs::to_bytes(&owner)?)],
                        commands: vec![Command::MoveCall(Box::new(ProgrammableMoveCall {
                            package: sui_types::SUI_FRAMEWORK_PACKAGE_ID,
                            module: "coin".into(),
                            function: "send_funds".into(),
                            type_arguments: vec![ty.clone().into()],
                            arguments: vec![Argument::Input(0), Argument::Input(1)],
                        }))],
                    };
                    let cdata = TransactionData::new_with_gas_data(TransactionKind::ProgrammableTransaction(crafted), data.sender(), data.gas_data().clone());
                    variants.push((format!("deny/send-funds/{tag}/control"), cdata.clone(), vec![]));
                    variants.push((format!("deny/send-funds/{tag}/address"), cdata.clone(), vec![setting_object(config, "AddressKey", &owner.to_vec(), epoch - 1, Some(true), None)?]));
                    variants.push((format!("deny/send-funds/{tag}/pause"), cdata, vec![setting_object(config, "GlobalPauseKey", &[0], epoch - 1, Some(true), None)?]));
                    send_cases += 1;
                }
            }
            for (name, vdata, synthetic) in variants {
                let mut lat = latest.clone();
                for o in &synthetic {
                    lat.insert(o.id(), o.clone());
                }
                let r = ctx.run(&vdata, &inputs, &lat)?;
                // the regulated (type, owners) pairs: every written non-SUI coin and Balance<T> event owner
                let mut pairs: std::collections::BTreeMap<String, Vec<SuiAddress>> = Default::default();
                pairs.entry(tys.clone()).or_default().push(owner);
                for o in vdata.input_objects()?.iter().filter_map(|k| inputs.get(&k.object_id())) {
                    if let (Some(t2), Ok(a)) = (o.coin_type_maybe(), o.owner.get_owner_address()) {
                        if !sui_types::gas_coin::GAS::is_gas_type(&t2) {
                            pairs.entry(t2.to_canonical_string(false)).or_default().push(a);
                        }
                    }
                }
                for o in &r.written {
                    if let (Some(t2), Ok(a)) = (o.coin_type_maybe(), o.owner.get_owner_address()) {
                        if !sui_types::gas_coin::GAS::is_gas_type(&t2) {
                            pairs.entry(t2.to_canonical_string(false)).or_default().push(a);
                        }
                    }
                }
                let reads = deny_reads(&lat, &pairs.into_iter().collect::<Vec<_>>())?;
                let objs: Vec<Object> = vdata
                    .input_objects()?
                    .iter()
                    .filter(|k| !matches!(k, InputObjectKind::MovePackage(_)))
                    .map(|k| inputs[&k.object_id()].clone())
                    .collect();
                eprintln!("synth: {name}: {:?}", r.effects.status());
                let line = serde_json::json!({
                    "name": name,
                    "pv": ep.0,
                    "epoch": epoch,
                    "rgp": ep.1,
                    "start_ms": ep.2,
                    "tx": hex::encode(bcs::to_bytes(&vdata)?),
                    "objects": hexs(&objs)?,
                    "latest": hexs(&reads)?,
                    "effects": hex::encode(bcs::to_bytes(&r.effects)?),
                    "events": r.events.as_ref().map(hex::encode),
                    "written": hexs(&r.written)?,
                });
                lines.push(line.to_string());
            }
        }
    }
    eprintln!("synth: {} vectors from {scanned} checkpoints ({coin_cases} coin cases, {send_cases} send_funds cases)", lines.len());
    if deny_obj.is_none() {
        // no corpus transaction takes the DenyList (0x403) as an input: its live version (the
        // object holds only the v1 lists; the v2 state is in the config fields)
        deny_obj = fetch_live(sui_types::SUI_DENY_LIST_OBJECT_ID).map_err(|e| eprintln!("synth: 0x403: {e:#}")).ok();
    }
    match base {
        Some((epoch, data, gas)) => craft(&env, &deny, &metrics, epoch, &data, &gas, deny_obj.as_ref(), regulated.as_ref(), &mut lines)?,
        None => eprintln!("synth: no base transaction for the crafted vectors"),
    }
    std::fs::create_dir_all(out)?;
    let f = std::fs::File::create(out.join("vectors.jsonl.zst"))?;
    let mut z = zstd::Encoder::new(f, 9)?;
    for l in &lines {
        z.write_all(l.as_bytes())?;
        z.write_all(b"\n")?;
    }
    z.finish()?;
    Ok(())
}

fn call(package: ObjectID, module: &str, function: &str, ty: Vec<TypeTag>, arguments: Vec<Argument>) -> Command {
    Command::MoveCall(Box::new(ProgrammableMoveCall {
        package,
        module: module.into(),
        function: function.into(),
        type_arguments: ty.into_iter().map(Into::into).collect(),
        arguments,
    }))
}

fn sui_tag() -> TypeTag {
    TypeTag::Struct(Box::new(fw("sui", "SUI", vec![])))
}

/// Crafted transactions over a base sender and gas coin, each run by Mysten's executor:
/// - `ref/...`: calls returning references (not allowed in PTBs on mainnet): the typing meter
///   (scope_references, live and returned reference counts and limits, the cubic live charge)
///   then InvalidPublicFunctionReturnType from move_functions;
/// - `config/...`: per-epoch config reads (`config::read_setting` through the coin deny list v2
///   queries) of synthetic settings, the result made observable by a `bcs::peel_vec_u8` abort.
#[allow(clippy::too_many_arguments)]
fn craft(
    env: &ExecEnv,
    deny: &HashMap<ObjectID, Vec<(u64, Object)>>,
    metrics: &Arc<sui_types::metrics::ExecutionMetrics>,
    epoch: u64,
    base: &TransactionData,
    gas: &Object,
    deny_obj: Option<&Object>,
    regulated: Option<&(TypeTag, ObjectID, SuiAddress)>,
    lines: &mut Vec<String>,
) -> Result<()> {
    let ep = env.epochs[epoch as usize];
    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(ep.0), Chain::Mainnet);
    let ctx = Ctx { env, ex: sui_execution::executor(&cfg, true)?, cfg, metrics: metrics.clone(), epoch };
    let latest = deny_at(deny, epoch);
    let one = sui_types::MOVE_STDLIB_PACKAGE_ID;
    let two = sui_types::SUI_FRAMEWORK_PACKAGE_ID;
    let u64t = TypeTag::U64;
    let vec_in = CallArg::Pure(bcs::to_bytes(&vec![5u64, 6u64])?);
    let zero_in = CallArg::Pure(bcs::to_bytes(&0u64)?);
    let borrow = |m: bool| call(one, "vector", if m { "borrow_mut" } else { "borrow" }, vec![TypeTag::U64], vec![Argument::Input(0), Argument::Input(1)]);
    let mut cases: Vec<(String, Vec<CallArg>, Vec<Command>, Vec<Object>)> = Vec::new();
    cases.push(("ref/return".into(), vec![], vec![call(two, "coin", "balance", vec![sui_tag()], vec![Argument::GasCoin])], vec![]));
    cases.push((
        "ref/return-used".into(),
        vec![],
        vec![call(two, "coin", "balance", vec![sui_tag()], vec![Argument::GasCoin]), call(two, "balance", "value", vec![sui_tag()], vec![Argument::Result(0)])],
        vec![],
    ));
    cases.push(("ref/read".into(), vec![vec_in.clone(), zero_in.clone()], vec![borrow(false), call(one, "u64", "max", vec![], vec![Argument::Result(0), Argument::Input(1)])], vec![]));
    cases.push(("ref/freeze".into(), vec![vec_in.clone(), zero_in.clone()], vec![borrow(true), call(one, "bcs", "to_bytes", vec![u64t.clone()], vec![Argument::Result(0)])], vec![]));
    cases.push((
        "ref/read-twice".into(),
        vec![vec_in.clone(), zero_in.clone()],
        vec![borrow(false), call(one, "u64", "max", vec![], vec![Argument::Result(0), Argument::Result(0)]), call(one, "u64", "max", vec![], vec![Argument::Result(0), Argument::Input(1)])],
        vec![],
    ));
    for (name, n) in [("ref/live-20", 20usize), ("ref/live-65", 65)] {
        let mut cmds: Vec<Command> = (0..n).map(|_| borrow(false)).collect();
        for i in 0..n {
            cmds.push(call(one, "u64", "max", vec![], vec![Argument::Result(i as u16), Argument::Input(1)]));
        }
        cases.push((name.into(), vec![vec_in.clone(), zero_in.clone()], cmds, vec![]));
    }
    cases.push(("ref/returned-257".into(), vec![vec_in.clone(), zero_in.clone()], (0..257).map(|_| borrow(false)).collect(), vec![]));
    // a corpus function taking two `&mut Balance<T>` (`scan-refs`): one location borrowed twice
    let utils = ObjectID::from_hex_literal("0xda1644f58a955833a15abae24f8cc65b5bd8152ce013fde8be0a6a3dcf51fe36")?;
    if env.packages.contains_key(&utils) {
        let one_in = CallArg::Pure(bcs::to_bytes(&1u64)?);
        cases.push(("borrow/twice-gas".into(), vec![], vec![call(utils, "utils", "join_balance", vec![sui_tag()], vec![Argument::GasCoin, Argument::GasCoin])], vec![]));
        cases.push((
            "borrow/twice-balance".into(),
            vec![one_in.clone()],
            vec![
                Command::SplitCoins(Argument::GasCoin, vec![Argument::Input(0)]),
                call(two, "coin", "into_balance", vec![sui_tag()], vec![Argument::NestedResult(0, 0)]),
                call(utils, "utils", "join_balance", vec![sui_tag()], vec![Argument::Result(1), Argument::Result(1)]),
            ],
            vec![],
        ));
        cases.push((
            "borrow/distinct-balances".into(),
            vec![one_in.clone(), CallArg::Pure(bcs::to_bytes(&base.sender())?)],
            vec![
                Command::SplitCoins(Argument::GasCoin, vec![Argument::Input(0), Argument::Input(0)]),
                call(two, "coin", "into_balance", vec![sui_tag()], vec![Argument::NestedResult(0, 0)]),
                call(two, "coin", "into_balance", vec![sui_tag()], vec![Argument::NestedResult(0, 1)]),
                call(utils, "utils", "join_balance", vec![sui_tag()], vec![Argument::Result(1), Argument::Result(2)]),
                call(two, "coin", "from_balance", vec![sui_tag()], vec![Argument::Result(1)]),
                call(two, "coin", "from_balance", vec![sui_tag()], vec![Argument::Result(2)]),
                Command::TransferObjects(vec![Argument::Result(4), Argument::Result(5)], Argument::Input(1)),
            ],
            vec![],
        ));
    }
    // Publish of a hand-assembled module whose `init` emits `n` events: the publish path end to
    // end, and the event count limit (`max_num_event_emit`) hit inside `init`
    for (name, n) in [("publish/events-3", 3u64), ("publish/events-over-limit", cfg_max_events(&ctx.cfg) + 1)] {
        let module = event_module("m", n)?;
        let pt = ProgrammableTransaction {
            inputs: vec![CallArg::Pure(bcs::to_bytes(&base.sender())?)],
            commands: vec![
                Command::Publish(vec![module], vec![one, two]),
                Command::TransferObjects(vec![Argument::Result(0)], Argument::Input(0)),
            ],
        };
        cases.push((name.into(), pt.inputs, pt.commands, vec![]));
    }
    cases.extend(upgrade_cases(&ctx, base, gas)?);
    // review round 4: the in-transaction package store and missing packages; a case may run at
    // another protocol version and with a chosen transaction digest
    let (more, mut overrides) = intx_cases(&ctx, base, gas)?;
    cases.extend(more);
    // protocol 142: the implicit Clock (`clock::borrow`); version pinned per case
    let mut clock_ver: HashMap<String, u64> = HashMap::new();
    #[cfg(feature = "sui_184")]
    {
        let (more, ov, cv) = clock_cases(&ctx, base, gas)?;
        cases.extend(more);
        overrides.extend(ov);
        clock_ver.extend(cv);
    }
    let sys_versions = |name: &str| -> sui_types::base_types::SystemObjectVersions {
        match clock_ver.get(name) {
            Some(v) => sui_types::base_types::SystemObjectVersions::from_map(std::collections::BTreeMap::from([(
                sui_types::SUI_CLOCK_OBJECT_ID,
                sui_types::base_types::ConsensusObjectVersion { initial_shared_version: SequenceNumber::from_u64(1), version: SequenceNumber::from_u64(*v) },
            )])),
            None => sui_types::base_types::SystemObjectVersions::empty(),
        }
    };
    let mut synthetic: HashMap<String, Vec<Object>> = HashMap::new();
    if let (Some(d), Some((ty, config, owner))) = (deny_obj, regulated) {
        let Owner::Shared { initial_shared_version } = d.owner else { anyhow::bail!("deny list not shared") };
        // the per-type Config object (a dynamic object field's value): Move loads it at runtime
        let config_obj = fetch_live(*config)?;
        let dl = CallArg::Object(ObjectArg::SharedObject { id: d.id(), initial_shared_version, mutability: sui_types::transaction::SharedObjectMutability::Immutable });
        let addr = CallArg::Pure(bcs::to_bytes(owner)?);
        // bool -> abort iff true: bcs::peel_vec_u8 of bcs::to_bytes(b) needs a byte after length 1
        let observe = |q: Command| vec![q, call(one, "bcs", "to_bytes", vec![TypeTag::Bool], vec![Argument::Result(0)]), call(two, "bcs", "new", vec![], vec![Argument::Result(1)]), call(two, "bcs", "peel_vec_u8", vec![], vec![Argument::Result(2)])];
        let addr_q = |f: &str| call(two, "coin", f, vec![ty.clone()], vec![Argument::Input(0), Argument::Input(1)]);
        let pause_q = |f: &str| call(two, "coin", f, vec![ty.clone()], vec![Argument::Input(0)]);
        let set_addr = |newer_epoch: u64, newer: Option<bool>, older: Option<bool>| setting_object(*config, "AddressKey", &owner.to_vec(), newer_epoch, newer, older);
        let set_pause = |newer_epoch: u64, newer: Option<bool>, older: Option<bool>| setting_object(*config, "GlobalPauseKey", &[0], newer_epoch, newer, older);
        let variants: Vec<(&str, Command, bool, Vec<Object>)> = vec![
            ("config/address-current/none", addr_q("deny_list_v2_contains_current_epoch"), true, vec![]),
            ("config/address-current/denied", addr_q("deny_list_v2_contains_current_epoch"), true, vec![set_addr(epoch - 1, Some(true), None)?]),
            ("config/address-current/this-epoch", addr_q("deny_list_v2_contains_current_epoch"), true, vec![set_addr(epoch, Some(true), Some(false))?]),
            ("config/address-next/denied", addr_q("deny_list_v2_contains_next_epoch"), true, vec![set_addr(epoch, Some(true), None)?]),
            ("config/pause-current/on", pause_q("deny_list_v2_is_global_pause_enabled_current_epoch"), false, vec![set_pause(epoch - 1, Some(true), None)?]),
            ("config/pause-next/on", pause_q("deny_list_v2_is_global_pause_enabled_next_epoch"), false, vec![set_pause(epoch, Some(true), None)?]),
        ];
        for (name, q, with_addr, objs) in variants {
            let inputs = if with_addr { vec![dl.clone(), addr.clone()] } else { vec![dl.clone()] };
            synthetic.insert(name.into(), objs.clone());
            cases.push((name.into(), inputs, observe(q), vec![d.clone(), config_obj.clone()]));
        }
    } else {
        eprintln!("synth: no deny list input or regulated coin in the scanned checkpoints, config vectors skipped");
    }
    for (name, inputs, commands, extra) in cases {
        let pt = ProgrammableTransaction { inputs, commands };
        let vdata = TransactionData::new_with_gas_data(TransactionKind::ProgrammableTransaction(pt), base.sender(), base.gas_data().clone());
        let mut objs: HashMap<ObjectID, Object> = HashMap::new();
        objs.insert(gas.id(), gas.clone());
        for o in &extra {
            objs.insert(o.id(), o.clone());
        }
        let mut lat = latest.clone();
        let syn = synthetic.remove(&name).unwrap_or_default();
        for o in &syn {
            lat.insert(o.id(), o.clone());
        }
        let ov = overrides.get(&name).cloned();
        let pv = ov.and_then(|o| o.0).unwrap_or(ep.0);
        let digest = ov.and_then(|o| o.1);
        let r = if pv == ep.0 {
            ctx.run_sys(&vdata, &objs, &lat, digest, sys_versions(&name))?
        } else {
            let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(pv), Chain::Mainnet);
            let c2 = Ctx { env, ex: sui_execution::executor(&cfg, true)?, cfg, metrics: metrics.clone(), epoch };
            c2.run_sys(&vdata, &objs, &lat, digest, sys_versions(&name))?
        };
        eprintln!("synth: {name}: {:?}", r.effects.status());
        // the latest objects a config read can reach: the per-type config field and its settings
        let reads = match regulated {
            Some((ty, _, owner)) if name.starts_with("config/") => deny_reads(&lat, &[(ty.to_canonical_string(false), vec![*owner])])?,
            _ => vec![],
        };
        let mut inputs_list = vec![gas.clone()];
        inputs_list.extend(extra);
        // every runtime-loaded object's bytes (the config field comes from the latest set)
        for (id, v) in &r.loaded {
            if inputs_list.iter().any(|o| o.id() == *id && o.version().value() == *v) {
                continue;
            }
            if let Some(o) = objs.get(id).or_else(|| lat.get(id)).filter(|o| o.version().value() == *v) {
                inputs_list.push(o.clone());
            }
        }
        let loaded: Vec<serde_json::Value> = r.loaded.iter().map(|(id, v)| serde_json::json!({"id": hex::encode(id), "version": v})).collect();
        let mut line = serde_json::json!({
                "name": name,
                "pv": pv,
                "epoch": epoch,
                "rgp": ep.1,
                "start_ms": ep.2,
                "tx": hex::encode(bcs::to_bytes(&vdata)?),
                "objects": hexs(&inputs_list)?,
                "latest": hexs(&reads)?,
                "effects": hex::encode(bcs::to_bytes(&r.effects)?),
                "events": r.events.as_ref().map(hex::encode),
                "written": hexs(&r.written)?,
                "loaded": loaded,
            });
        if let Some(d) = digest {
            line["digest"] = serde_json::Value::String(hex::encode(d.inner()));
        }
        lines.push(line.to_string());
    }
    Ok(())
}

/// `scan-refs <corpus>`: public functions of corpus packages taking two references to the same
/// type, one mutable (a location borrowed twice in one command).
pub fn cmd_scan_refs(corpus: &Path) -> Result<()> {
    use move_binary_format::file_format::{SignatureToken, Visibility};
    let env = load_exec_env(corpus)?;
    let mut hits = 0;
    for (id, o) in &env.packages {
        let Some(p) = o.data.try_as_package() else { continue };
        for (name, bytes) in p.serialized_module_map() {
            let Ok(m) = move_binary_format::CompiledModule::deserialize_with_defaults(bytes) else { continue };
            for fd in &m.function_defs {
                if fd.visibility != Visibility::Public && !fd.is_entry {
                    continue;
                }
                let h = &m.function_handles[fd.function.0 as usize];
                let params = &m.signatures[h.parameters.0 as usize].0;
                let mut found = false;
                for (i, a) in params.iter().enumerate() {
                    for b in &params[i + 1..] {
                        let (am, ai) = match a {
                            SignatureToken::Reference(t) => (false, t),
                            SignatureToken::MutableReference(t) => (true, t),
                            _ => continue,
                        };
                        let (bm, bi) = match b {
                            SignatureToken::Reference(t) => (false, t),
                            SignatureToken::MutableReference(t) => (true, t),
                            _ => continue,
                        };
                        if (am || bm) && ai == bi {
                            found = true;
                        }
                    }
                }
                if found {
                    hits += 1;
                    if hits <= 40 {
                        println!("{id}::{name}::{} {:?}", m.identifier_at(h.name), params);
                    }
                }
            }
        }
    }
    println!("{hits} functions");
    Ok(())
}

/// One object at its latest version from the public fullnode (gRPC `GetObject`).
fn fetch_live(id: ObjectID) -> Result<Object> {
    use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
    let rt = tokio::runtime::Runtime::new()?;
    let _guard = rt.enter();
    let mut c = sui_rpc::Client::new("https://fullnode.mainnet.sui.io:443".to_string())?;
    let mut req = GetObjectRequest::default();
    req.object_id = Some(id.to_hex_literal());
    req.read_mask = Some(prost_types::FieldMask { paths: vec!["bcs".into()] });
    let resp = rt.block_on(async { c.ledger_client().get_object(req).await })?.into_inner();
    let raw = resp.object.and_then(|o| o.bcs).and_then(|b| b.value).context("no bcs")?;
    Ok(bcs::from_bytes(&raw)?)
}

fn cfg_max_events(cfg: &ProtocolConfig) -> u64 {
    cfg.max_num_event_emit()
}

/// `module 0x0::m { struct E has copy, drop { x: u64 }
///   fun init(ctx: &mut TxContext) { let i = 0; while (i < n) { event::emit(E { x: i }); i = i + 1 } } }`
fn event_module(name: &str, n: u64) -> Result<Vec<u8>> {
    use move_binary_format::file_format::*;
    use move_core_types::account_address::AccountAddress;
    use move_core_types::identifier::Identifier;
    let id = |s: &str| Identifier::new(s).unwrap();
    let m = CompiledModule {
        version: 7,
        publishable: true,
        self_module_handle_idx: ModuleHandleIndex(0),
        module_handles: vec![
            ModuleHandle { address: AddressIdentifierIndex(0), name: IdentifierIndex(0) },
            ModuleHandle { address: AddressIdentifierIndex(1), name: IdentifierIndex(4) },
            ModuleHandle { address: AddressIdentifierIndex(1), name: IdentifierIndex(6) },
        ],
        datatype_handles: vec![
            DatatypeHandle { module: ModuleHandleIndex(0), name: IdentifierIndex(1), abilities: AbilitySet::EMPTY | Ability::Copy | Ability::Drop, type_parameters: vec![] },
            DatatypeHandle { module: ModuleHandleIndex(2), name: IdentifierIndex(7), abilities: AbilitySet::EMPTY | Ability::Drop, type_parameters: vec![] },
        ],
        function_handles: vec![
            FunctionHandle { module: ModuleHandleIndex(0), name: IdentifierIndex(3), parameters: SignatureIndex(1), return_: SignatureIndex(0), type_parameters: vec![] },
            FunctionHandle { module: ModuleHandleIndex(1), name: IdentifierIndex(5), parameters: SignatureIndex(2), return_: SignatureIndex(0), type_parameters: vec![AbilitySet::EMPTY | Ability::Copy | Ability::Drop] },
        ],
        field_handles: vec![],
        friend_decls: vec![],
        struct_def_instantiations: vec![],
        function_instantiations: vec![FunctionInstantiation { handle: FunctionHandleIndex(1), type_parameters: SignatureIndex(3) }],
        field_instantiations: vec![],
        signatures: vec![
            Signature(vec![]),
            Signature(vec![SignatureToken::MutableReference(Box::new(SignatureToken::Datatype(DatatypeHandleIndex(1))))]),
            Signature(vec![SignatureToken::TypeParameter(0)]),
            Signature(vec![SignatureToken::Datatype(DatatypeHandleIndex(0))]),
            Signature(vec![SignatureToken::U64]),
        ],
        identifiers: vec![id(name), id("E"), id("x"), id("init"), id("event"), id("emit"), id("tx_context"), id("TxContext")],
        address_identifiers: vec![AccountAddress::ZERO, AccountAddress::TWO],
        constant_pool: vec![],
        metadata: vec![],
        struct_defs: vec![StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition { name: IdentifierIndex(2), signature: TypeSignature(SignatureToken::U64) }]),
        }],
        function_defs: vec![FunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(CodeUnit {
                locals: SignatureIndex(4),
                code: vec![
                    Bytecode::LdU64(0),
                    Bytecode::StLoc(1),
                    Bytecode::CopyLoc(1),
                    Bytecode::LdU64(n),
                    Bytecode::Lt,
                    Bytecode::BrFalse(14),
                    Bytecode::CopyLoc(1),
                    Bytecode::Pack(StructDefinitionIndex(0)),
                    Bytecode::CallGeneric(FunctionInstantiationIndex(0)),
                    Bytecode::MoveLoc(1),
                    Bytecode::LdU64(1),
                    Bytecode::Add,
                    Bytecode::StLoc(1),
                    Bytecode::Branch(2),
                    Bytecode::MoveLoc(0),
                    Bytecode::Pop,
                    Bytecode::Ret,
                ],
                jump_tables: vec![],
            }),
        }],
        enum_defs: vec![],
        enum_def_instantiations: vec![],
        variant_handles: vec![],
        variant_instantiation_handles: vec![],
    };
    let mut out = Vec::new();
    m.serialize_with_version(m.version, &mut out)?;
    Ok(out)
}

type Case = (String, Vec<CallArg>, Vec<Command>, Vec<Object>);

/// One module `m` of a synthetic package: `struct S has <abilities> { x: <field> }`, a public
/// `fun <name>(): u64 { <k> }` per entry of `funs`, and with `init` a private
/// `fun init(_: &mut TxContext) {}` (then the module depends on 0x2); with `dep` a handle to
/// module `<dep>::m`, which makes that package an immediate dependency.
fn upg_module(field: move_binary_format::file_format::SignatureToken, abilities: move_binary_format::file_format::AbilitySet, funs: &[(&str, u64)], init: bool, dep: Option<ObjectID>) -> Result<Vec<u8>> {
    let funs: Vec<UFun> = funs.iter().map(|(name, k)| UFun { name, k: *k, vis: move_binary_format::file_format::Visibility::Public, entry: false, param: false }).collect();
    upg_module_full("m", field, abilities, &funs, init, dep)
}

/// A function of `upg_module_full`: `<vis> [entry] fun <name>([_: u64]): u64 { <k> }`.
struct UFun<'a> {
    name: &'a str,
    k: u64,
    vis: move_binary_format::file_format::Visibility,
    entry: bool,
    param: bool,
}

/// `upg_module` with the module name and each function's visibility, entry flag and parameter.
fn upg_module_full(mname: &str, field: move_binary_format::file_format::SignatureToken, abilities: move_binary_format::file_format::AbilitySet, funs: &[UFun], init: bool, dep: Option<ObjectID>) -> Result<Vec<u8>> {
    use move_binary_format::file_format::*;
    use move_core_types::account_address::AccountAddress;
    use move_core_types::identifier::Identifier;
    let id = |s: &str| Identifier::new(s).unwrap();
    let mut identifiers = vec![id(mname), id("S"), id("x")];
    let mut function_handles = vec![];
    let mut function_defs = vec![];
    for f in funs {
        // a `u64` parameter shares the return type's signature (index 1)
        function_handles.push(FunctionHandle { module: ModuleHandleIndex(0), name: IdentifierIndex(identifiers.len() as u16), parameters: SignatureIndex(if f.param { 1 } else { 0 }), return_: SignatureIndex(1), type_parameters: vec![] });
        identifiers.push(id(f.name));
        let code = if f.param { vec![Bytecode::MoveLoc(0), Bytecode::Pop, Bytecode::LdU64(f.k), Bytecode::Ret] } else { vec![Bytecode::LdU64(f.k), Bytecode::Ret] };
        function_defs.push(FunctionDefinition {
            function: FunctionHandleIndex(function_defs.len() as u16),
            visibility: f.vis,
            is_entry: f.entry,
            acquires_global_resources: vec![],
            code: Some(CodeUnit { locals: SignatureIndex(0), code, jump_tables: vec![] }),
        });
    }
    let mut module_handles = vec![ModuleHandle { address: AddressIdentifierIndex(0), name: IdentifierIndex(0) }];
    let mut datatype_handles = vec![DatatypeHandle { module: ModuleHandleIndex(0), name: IdentifierIndex(1), abilities, type_parameters: vec![] }];
    let mut signatures = vec![Signature(vec![]), Signature(vec![SignatureToken::U64])];
    let mut address_identifiers = vec![AccountAddress::ZERO];
    if init {
        let base = identifiers.len() as u16;
        identifiers.extend([id("init"), id("tx_context"), id("TxContext")]);
        address_identifiers.push(AccountAddress::TWO);
        module_handles.push(ModuleHandle { address: AddressIdentifierIndex(1), name: IdentifierIndex(base + 1) });
        datatype_handles.push(DatatypeHandle { module: ModuleHandleIndex(1), name: IdentifierIndex(base + 2), abilities: AbilitySet::EMPTY | Ability::Drop, type_parameters: vec![] });
        signatures.push(Signature(vec![SignatureToken::MutableReference(Box::new(SignatureToken::Datatype(DatatypeHandleIndex(1))))]));
        function_handles.push(FunctionHandle { module: ModuleHandleIndex(0), name: IdentifierIndex(base), parameters: SignatureIndex(2), return_: SignatureIndex(0), type_parameters: vec![] });
        function_defs.push(FunctionDefinition {
            function: FunctionHandleIndex(function_defs.len() as u16),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(CodeUnit { locals: SignatureIndex(0), code: vec![Bytecode::MoveLoc(0), Bytecode::Pop, Bytecode::Ret], jump_tables: vec![] }),
        });
    }
    if let Some(d) = dep {
        address_identifiers.push(AccountAddress::from(d));
        module_handles.push(ModuleHandle { address: AddressIdentifierIndex(address_identifiers.len() as u16 - 1), name: IdentifierIndex(0) });
    }
    let m = CompiledModule {
        version: 7,
        publishable: true,
        self_module_handle_idx: ModuleHandleIndex(0),
        module_handles,
        datatype_handles,
        function_handles,
        field_handles: vec![],
        friend_decls: vec![],
        struct_def_instantiations: vec![],
        function_instantiations: vec![],
        field_instantiations: vec![],
        signatures,
        identifiers,
        address_identifiers,
        constant_pool: vec![],
        metadata: vec![],
        struct_defs: vec![StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition { name: IdentifierIndex(2), signature: TypeSignature(field) }]),
        }],
        function_defs,
        enum_defs: vec![],
        enum_def_instantiations: vec![],
        variant_handles: vec![],
        variant_instantiation_handles: vec![],
    };
    let mut out = Vec::new();
    m.serialize_with_version(m.version, &mut out)?;
    Ok(out)
}

/// `upgrade/...`: Upgrade commands (`authorize_upgrade`, Upgrade, `commit_upgrade`) of synthetic
/// packages published (and upgraded) by Mysten's executor first, over the base sender and gas:
/// each policy (compatible 0, additive 128, dep-only 192) accepting and refusing, an unknown
/// policy, a wrong digest, a ticket for another package, init on a new module (events) and on an
/// existing one, a missing dependency, a dependency downgrade against an immediate dependency's
/// linkage (`build_linkage_table` (2)), an older dependency than the previous version had (allowed),
/// a dependency upgraded or dropped.
fn upgrade_cases(ctx: &Ctx, base: &TransactionData, gas: &Object) -> Result<Vec<Case>> {
    use move_binary_format::file_format::{Ability, AbilitySet, SignatureToken};
    use sui_types::move_package::MovePackage;
    let one = sui_types::MOVE_STDLIB_PACKAGE_ID;
    let two = sui_types::SUI_FRAMEWORK_PACKAGE_ID;
    let sender = base.sender();
    let store_ab = AbilitySet::EMPTY | Ability::Store;
    let m1 = upg_module(SignatureToken::U64, store_ab, &[("f", 1)], false, None)?;
    let run = |cmds: Vec<Command>, inputs: Vec<CallArg>, extra: &[Object]| -> Result<Run> {
        let pt = ProgrammableTransaction { inputs, commands: cmds };
        let vdata = TransactionData::new_with_gas_data(TransactionKind::ProgrammableTransaction(pt), sender, base.gas_data().clone());
        let mut objs: HashMap<ObjectID, Object> = HashMap::new();
        objs.insert(gas.id(), gas.clone());
        for o in extra {
            objs.insert(o.id(), o.clone());
        }
        ctx.run(&vdata, &objs, &HashMap::new())
    };
    let is_cap = |o: &Object| o.struct_tag().is_some_and(|t| t.address == *two && t.module.as_str() == "package" && t.name.as_str() == "UpgradeCap");
    let pick = |r: &Run| -> Result<(Object, Object)> {
        anyhow::ensure!(r.effects.status().is_ok(), "setup failed: {:?}", r.effects.status());
        let p = r.written.iter().find(|o| o.is_package() && !sui_types::is_system_package(o.id())).context("no package")?.clone();
        let c = r.written.iter().find(|o| is_cap(o)).context("no cap")?.clone();
        Ok((p, c))
    };
    let publish = |modules: Vec<Vec<u8>>, deps: Vec<ObjectID>, extra: &[Object]| -> Result<(Object, Object)> {
        let r = run(vec![Command::Publish(modules, deps), Command::TransferObjects(vec![Argument::Result(0)], Argument::Input(0))], vec![CallArg::Pure(bcs::to_bytes(&sender)?)], extra)?;
        pick(&r)
    };
    let upgrade = |cap: &Object, pkg: ObjectID, modules: Vec<Vec<u8>>, deps: Vec<ObjectID>, policy: u8, digest: Option<Vec<u8>>| -> Result<(Vec<CallArg>, Vec<Command>)> {
        let d = digest.unwrap_or_else(|| MovePackage::compute_digest_for_modules_and_deps(&modules, &deps, true).to_vec());
        let inputs = vec![
            CallArg::Object(ObjectArg::ImmOrOwnedObject(cap.compute_object_reference())),
            CallArg::Pure(bcs::to_bytes(&policy)?),
            CallArg::Pure(bcs::to_bytes(&d)?),
        ];
        let cmds = vec![
            call(two, "package", "authorize_upgrade", vec![], vec![Argument::Input(0), Argument::Input(1), Argument::Input(2)]),
            Command::Upgrade(modules, deps, pkg, Argument::Result(0)),
            call(two, "package", "commit_upgrade", vec![], vec![Argument::Input(0), Argument::Result(1)]),
        ];
        Ok((inputs, cmds))
    };
    // A1, then A2 (A1 plus `g`): B depends on A2, C on A1
    let (a1, cap_a1) = publish(vec![m1.clone()], vec![one, two], &[])?;
    let a = a1.id();
    let m_fg = upg_module(SignatureToken::U64, store_ab, &[("f", 1), ("g", 7)], false, None)?;
    let (ins, cmds) = upgrade(&cap_a1, a, vec![m_fg.clone()], vec![one, two], 0, None)?;
    let (a2, _) = pick(&run(cmds, ins, &[cap_a1.clone(), a1.clone()])?)?;
    let (b1, cap_b1) = publish(vec![m1.clone()], vec![one, two, a2.id()], &[a1.clone(), a2.clone()])?;
    let (c1, cap_c1) = publish(vec![m1.clone()], vec![one, two, a], &[a1.clone()])?;
    // D depends on A2 (its linkage has A at version 2); C's upgrade makes D an immediate dependency
    let (d1, _) = publish(vec![m1.clone()], vec![one, two, a2.id()], &[a1.clone(), a2.clone()])?;
    let m_d = upg_module(SignatureToken::U64, store_ab, &[("f", 1)], false, Some(d1.id()))?;
    let pkgs = vec![a1.clone(), a2.clone(), b1.clone(), c1.clone(), d1.clone()];
    let with = |cap: &Object| -> Vec<Object> {
        let mut v = vec![cap.clone()];
        v.extend(pkgs.iter().cloned());
        v
    };
    let ev_n = event_module("n", 3)?;
    let mut out: Vec<Case> = Vec::new();
    let mut add = |name: &str, cap: &Object, pkg: ObjectID, modules: Vec<Vec<u8>>, deps: Vec<ObjectID>, policy: u8, digest: Option<Vec<u8>>| -> Result<()> {
        let (ins, cmds) = upgrade(cap, pkg, modules, deps, policy, digest)?;
        out.push((format!("upgrade/{name}"), ins, cmds, with(cap)));
        Ok(())
    };
    let std_deps = vec![one, two];
    add("compatible-add-fun", &cap_a1, a, vec![m_fg.clone()], std_deps.clone(), 0, None)?;
    add("compatible-body", &cap_a1, a, vec![upg_module(SignatureToken::U64, store_ab, &[("f", 2)], false, None)?], std_deps.clone(), 0, None)?;
    add("compatible-new-module-init", &cap_a1, a, vec![m1.clone(), ev_n.clone()], std_deps.clone(), 0, None)?;
    add("compatible-remove-fun", &cap_a1, a, vec![upg_module(SignatureToken::U64, store_ab, &[("g", 7)], false, None)?], std_deps.clone(), 0, None)?;
    add("compatible-field-type", &cap_a1, a, vec![upg_module(SignatureToken::U128, store_ab, &[("f", 1)], false, None)?], std_deps.clone(), 0, None)?;
    add("compatible-new-ability", &cap_a1, a, vec![upg_module(SignatureToken::U64, store_ab | Ability::Copy, &[("f", 1)], false, None)?], std_deps.clone(), 0, None)?;
    add("compatible-existing-module-init", &cap_a1, a, vec![upg_module(SignatureToken::U64, store_ab, &[("f", 1)], true, None)?], std_deps.clone(), 0, None)?;
    add("additive-add-fun", &cap_a1, a, vec![m_fg.clone()], std_deps.clone(), 128, None)?;
    add("additive-new-module", &cap_a1, a, vec![m1.clone(), ev_n.clone()], std_deps.clone(), 128, None)?;
    add("additive-body", &cap_a1, a, vec![upg_module(SignatureToken::U64, store_ab, &[("f", 2)], false, None)?], std_deps.clone(), 128, None)?;
    add("dep-only-same", &cap_a1, a, vec![m1.clone()], std_deps.clone(), 192, None)?;
    add("dep-only-add-fun", &cap_a1, a, vec![m_fg.clone()], std_deps.clone(), 192, None)?;
    add("dep-only-new-module", &cap_a1, a, vec![m1.clone(), ev_n.clone()], std_deps.clone(), 192, None)?;
    add("unknown-policy", &cap_a1, a, vec![m1.clone()], std_deps.clone(), 50, None)?;
    add("wrong-digest", &cap_a1, a, vec![m1.clone()], std_deps.clone(), 0, Some(vec![0u8; 32]))?;
    add("wrong-package", &cap_a1, b1.id(), vec![m1.clone()], std_deps.clone(), 0, None)?;
    add("missing-dependency", &cap_a1, a, vec![m1.clone(), ev_n.clone()], vec![one], 0, None)?;
    add("dep-older-than-previous", &cap_b1, b1.id(), vec![m1.clone()], vec![one, two, a], 0, None)?;
    add("dep-downgrade", &cap_c1, c1.id(), vec![m_d.clone()], vec![one, two, a, d1.id()], 0, None)?;
    add("dep-superseded", &cap_c1, c1.id(), vec![m_d.clone()], vec![one, two, a2.id(), d1.id()], 0, None)?;
    add("dep-transitive-missing", &cap_c1, c1.id(), vec![m_d.clone()], vec![one, two, d1.id()], 0, None)?;
    add("dep-upgrade", &cap_c1, c1.id(), vec![m1.clone()], vec![one, two, a2.id()], 0, None)?;
    add("dep-dropped", &cap_c1, c1.id(), vec![m1.clone()], std_deps.clone(), 0, None)?;
    // review round 3: compatibility edges from compatibility.rs (ExecutionCompatibilityMode and
    // InclusionCheckExecutionMode) that the corpus has no upgrade for
    use move_binary_format::file_format::Visibility::{Private, Public};
    let uf = |name, k, vis, entry, param| UFun { name, k, vis, entry, param };
    add("compatible-lost-public", &cap_a1, a, vec![upg_module_full("m", SignatureToken::U64, store_ab, &[uf("f", 1, Private, false, false)], false, None)?], std_deps.clone(), 0, None)?;
    add("compatible-public-signature", &cap_a1, a, vec![upg_module_full("m", SignatureToken::U64, store_ab, &[uf("f", 1, Public, false, true)], false, None)?], std_deps.clone(), 0, None)?;
    add("compatible-ability-removed", &cap_a1, a, vec![upg_module(SignatureToken::U64, AbilitySet::EMPTY, &[("f", 1)], false, None)?], std_deps.clone(), 0, None)?;
    add("additive-field-type", &cap_a1, a, vec![upg_module(SignatureToken::U128, store_ab, &[("f", 1)], false, None)?], std_deps.clone(), 128, None)?;
    // E1: public f, private p, private entry e; M1: modules m and n
    let e_funs = [uf("f", 1, Public, false, false), uf("p", 2, Private, false, false), uf("e", 3, Private, true, false)];
    let (e1, cap_e1) = publish(vec![upg_module_full("m", SignatureToken::U64, store_ab, &e_funs, false, None)?], std_deps.clone(), &[])?;
    let n1 = upg_module_full("n", SignatureToken::U64, store_ab, &[uf("f", 1, Public, false, false)], false, None)?;
    let (mm1, cap_mm1) = publish(vec![m1.clone(), n1.clone()], std_deps.clone(), &[])?;
    let with2 = |cap: &Object, p: &Object| -> Vec<Object> { vec![cap.clone(), p.clone()] };
    let mut add2 = |name: &str, cap: &Object, pkg: &Object, modules: Vec<Vec<u8>>, policy: u8| -> Result<()> {
        let (ins, cmds) = upgrade(cap, pkg.id(), modules, std_deps.clone(), policy, None)?;
        out.push((format!("upgrade/{name}"), ins, cmds, with2(cap, pkg)));
        Ok(())
    };
    let only_f = upg_module_full("m", SignatureToken::U64, store_ab, &[uf("f", 1, Public, false, false)], false, None)?;
    add2("compatible-drop-private-and-entry", &cap_e1, &e1, vec![only_f.clone()], 0)?;
    add2("compatible-entry-signature", &cap_e1, &e1, vec![upg_module_full("m", SignatureToken::U64, store_ab, &[uf("f", 1, Public, false, false), uf("p", 2, Private, false, false), uf("e", 3, Private, true, true)], false, None)?], 0)?;
    add2("compatible-private-to-public", &cap_e1, &e1, vec![upg_module_full("m", SignatureToken::U64, store_ab, &[uf("f", 1, Public, false, false), uf("p", 2, Public, false, false), uf("e", 3, Private, true, false)], false, None)?], 0)?;
    add2("additive-drop-private", &cap_e1, &e1, vec![upg_module_full("m", SignatureToken::U64, store_ab, &[uf("f", 1, Public, false, false), uf("e", 3, Private, true, false)], false, None)?], 128)?;
    add2("additive-entry-flag", &cap_e1, &e1, vec![upg_module_full("m", SignatureToken::U64, store_ab, &[uf("f", 1, Public, false, false), uf("p", 2, Private, true, false), uf("e", 3, Private, true, false)], false, None)?], 128)?;
    add2("compatible-module-removed", &cap_mm1, &mm1, vec![m1.clone()], 0)?;
    add2("dep-only-module-removed", &cap_mm1, &mm1, vec![m1.clone()], 192)?;
    add2("dep-only-same-two-modules", &cap_mm1, &mm1, vec![m1.clone(), n1.clone()], 192)?;
    add2("additive-module-order", &cap_mm1, &mm1, vec![n1.clone(), m1.clone()], 128)?;
    Ok(out)
}

/// Per-case overrides of `intx_cases`: the protocol version and the transaction digest.
type Overrides = HashMap<String, (Option<u64>, Option<TransactionDigest>)>;

/// `upg_module` bytes changed in place (an enum, a friend declaration).
fn tweak(bytes: &[u8], f: impl FnOnce(&mut move_binary_format::file_format::CompiledModule)) -> Result<Vec<u8>> {
    let mut m = move_binary_format::file_format::CompiledModule::deserialize_with_defaults(bytes)?;
    f(&mut m);
    let mut out = Vec::new();
    m.serialize_with_version(m.version, &mut out)?;
    Ok(out)
}

/// `upg_module` plus `enum E has copy, drop, store { <variants> }`.
fn enum_module(variants: &[&str]) -> Result<Vec<u8>> {
    use move_binary_format::file_format::*;
    use move_core_types::identifier::Identifier;
    let base = upg_module(SignatureToken::U64, AbilitySet::EMPTY | Ability::Store, &[("f", 1)], false, None)?;
    tweak(&base, |m| {
        let e = m.identifiers.len() as u16;
        m.identifiers.push(Identifier::new("E").unwrap());
        let h = m.datatype_handles.len() as u16;
        m.datatype_handles.push(DatatypeHandle { module: ModuleHandleIndex(0), name: IdentifierIndex(e), abilities: AbilitySet::EMPTY | Ability::Copy | Ability::Drop | Ability::Store, type_parameters: vec![] });
        let mut vs = vec![];
        for v in variants {
            let i = m.identifiers.len() as u16;
            m.identifiers.push(Identifier::new(*v).unwrap());
            vs.push(VariantDefinition { variant_name: IdentifierIndex(i), fields: vec![] });
        }
        m.enum_defs.push(EnumDefinition { enum_handle: DatatypeHandleIndex(h), variants: vs });
    })
}

/// Review round 4 cases:
/// - `intx/...`: a package published earlier in the same transaction as a later Upgrade's
///   current package (fetched from the transaction's package store at execution; at protocol
///   129, before `enable_init_on_upgrade`, the loader never looks it up, later the upgrade
///   linkage analysis does and finds no package) and as a later Publish's dependency (the
///   loader's `compute_publication_linkage`). The commands name the package id the Publish
///   creates, `derive_id(digest, 0)`, so these run with a chosen transaction digest.
/// - `linkage/...`: a Move call, a publish dependency and a type argument naming a package that
///   does not exist.
/// - `upgrade/...`: an enum gaining a variant under the compatible policy, and a friend
///   declaration added under dep-only.
fn intx_cases(ctx: &Ctx, base: &TransactionData, gas: &Object) -> Result<(Vec<Case>, Overrides)> {
    use move_binary_format::file_format::{Ability, AbilitySet, SignatureToken};
    use sui_types::move_package::MovePackage;
    let one = sui_types::MOVE_STDLIB_PACKAGE_ID;
    let two = sui_types::SUI_FRAMEWORK_PACKAGE_ID;
    let sender = base.sender();
    let store_ab = AbilitySet::EMPTY | Ability::Store;
    let std_deps = vec![one, two];
    let m1 = upg_module(SignatureToken::U64, store_ab, &[("f", 1)], false, None)?;
    let m_fg = upg_module(SignatureToken::U64, store_ab, &[("f", 1), ("g", 7)], false, None)?;
    let mut out: Vec<Case> = Vec::new();
    let mut ov: Overrides = HashMap::new();
    let sender_in = CallArg::Pure(bcs::to_bytes(&sender)?);
    // publish then upgrade it in one transaction
    let digest = TransactionDigest::new([0x5a; 32]);
    let fresh = ObjectID::derive_id(digest, 0);
    let d = MovePackage::compute_digest_for_modules_and_deps(&[m_fg.clone()], &std_deps, true).to_vec();
    let pub_upg = vec![
        Command::Publish(vec![m1.clone()], std_deps.clone()),
        call(two, "package", "authorize_upgrade", vec![], vec![Argument::Result(0), Argument::Input(1), Argument::Input(2)]),
        Command::Upgrade(vec![m_fg.clone()], std_deps.clone(), fresh, Argument::Result(1)),
        call(two, "package", "commit_upgrade", vec![], vec![Argument::Result(0), Argument::Result(2)]),
        Command::TransferObjects(vec![Argument::Result(0)], Argument::Input(0)),
    ];
    let pub_upg_in = vec![sender_in.clone(), CallArg::Pure(bcs::to_bytes(&0u8)?), CallArg::Pure(bcs::to_bytes(&d)?)];
    out.push(("intx/publish-then-upgrade".into(), pub_upg_in.clone(), pub_upg.clone(), vec![]));
    ov.insert("intx/publish-then-upgrade".into(), (None, Some(digest)));
    out.push(("intx/publish-then-upgrade-pv129".into(), pub_upg_in.clone(), pub_upg.clone(), vec![]));
    ov.insert("intx/publish-then-upgrade-pv129".into(), (Some(129), Some(digest)));
    // the upgrade in turn upgraded again: its current package is the first upgrade's storage id
    // (fresh ids: the package 0, its UpgradeCap 1, the first upgrade's storage id 2)
    let up1 = ObjectID::derive_id(digest, 2);
    let m_fgh = upg_module(SignatureToken::U64, store_ab, &[("f", 1), ("g", 7), ("h", 9)], false, None)?;
    let d2 = MovePackage::compute_digest_for_modules_and_deps(&[m_fgh.clone()], &std_deps, true).to_vec();
    let mut twice = pub_upg[..4].to_vec();
    twice.extend([
        call(two, "package", "authorize_upgrade", vec![], vec![Argument::Result(0), Argument::Input(1), Argument::Input(3)]),
        Command::Upgrade(vec![m_fgh.clone()], std_deps.clone(), up1, Argument::Result(4)),
        call(two, "package", "commit_upgrade", vec![], vec![Argument::Result(0), Argument::Result(5)]),
        Command::TransferObjects(vec![Argument::Result(0)], Argument::Input(0)),
    ]);
    let mut twice_in = pub_upg_in.clone();
    twice_in.push(CallArg::Pure(bcs::to_bytes(&d2)?));
    out.push(("intx/publish-upgrade-upgrade-pv129".into(), twice_in, twice, vec![]));
    ov.insert("intx/publish-upgrade-upgrade-pv129".into(), (Some(129), Some(digest)));
    // publish, then a second publish depending on the first
    let m_dep = upg_module(SignatureToken::U64, store_ab, &[("f", 1)], false, Some(fresh))?;
    let pub_pub = vec![
        Command::Publish(vec![m1.clone()], std_deps.clone()),
        Command::Publish(vec![m_dep.clone()], vec![one, two, fresh]),
        Command::TransferObjects(vec![Argument::Result(0), Argument::Result(1)], Argument::Input(0)),
    ];
    out.push(("intx/publish-then-publish-dep".into(), vec![sender_in.clone()], pub_pub.clone(), vec![]));
    ov.insert("intx/publish-then-publish-dep".into(), (None, Some(digest)));
    out.push(("intx/publish-then-publish-dep-pv129".into(), vec![sender_in.clone()], pub_pub, vec![]));
    ov.insert("intx/publish-then-publish-dep-pv129".into(), (Some(129), Some(digest)));
    // packages that do not exist
    let nowhere = ObjectID::from_hex_literal("0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0bad")?;
    out.push(("linkage/missing-call-package".into(), vec![], vec![call(nowhere, "m", "f", vec![], vec![])], vec![]));
    let s_ty = TypeTag::Struct(Box::new(StructTag { address: (*nowhere).into(), module: "m".parse()?, name: "S".parse()?, type_params: vec![] }));
    out.push(("linkage/missing-type-arg-package".into(), vec![], vec![call(one, "vector", "empty", vec![s_ty.clone()], vec![])], vec![]));
    out.push(("linkage/missing-make-vec-package".into(), vec![], vec![Command::MakeMoveVec(Some(s_ty.into()), vec![])], vec![]));
    out.push((
        "linkage/missing-publish-dep".into(),
        vec![sender_in.clone()],
        vec![Command::Publish(vec![m1.clone()], vec![one, two, nowhere]), Command::TransferObjects(vec![Argument::Result(0)], Argument::Input(0))],
        vec![],
    ));
    // upgrades: an enum gaining a variant, a friend added under dep-only
    let run = |cmds: Vec<Command>, inputs: Vec<CallArg>| -> Result<Run> {
        let pt = ProgrammableTransaction { inputs, commands: cmds };
        let vdata = TransactionData::new_with_gas_data(TransactionKind::ProgrammableTransaction(pt), sender, base.gas_data().clone());
        let mut objs: HashMap<ObjectID, Object> = HashMap::new();
        objs.insert(gas.id(), gas.clone());
        ctx.run(&vdata, &objs, &HashMap::new())
    };
    let is_cap = |o: &Object| o.struct_tag().is_some_and(|t| t.address == *two && t.module.as_str() == "package" && t.name.as_str() == "UpgradeCap");
    let publish = |modules: Vec<Vec<u8>>| -> Result<(Object, Object)> {
        let r = run(vec![Command::Publish(modules, std_deps.clone()), Command::TransferObjects(vec![Argument::Result(0)], Argument::Input(0))], vec![sender_in.clone()])?;
        anyhow::ensure!(r.effects.status().is_ok(), "setup failed: {:?}", r.effects.status());
        let p = r.written.iter().find(|o| o.is_package() && !sui_types::is_system_package(o.id())).context("no package")?.clone();
        let c = r.written.iter().find(|o| is_cap(o)).context("no cap")?.clone();
        Ok((p, c))
    };
    let mut upg = |name: &str, cap: &Object, pkg: &Object, modules: Vec<Vec<u8>>, policy: u8| -> Result<()> {
        let d = MovePackage::compute_digest_for_modules_and_deps(&modules, &std_deps, true).to_vec();
        let inputs = vec![CallArg::Object(ObjectArg::ImmOrOwnedObject(cap.compute_object_reference())), CallArg::Pure(bcs::to_bytes(&policy)?), CallArg::Pure(bcs::to_bytes(&d)?)];
        let cmds = vec![
            call(two, "package", "authorize_upgrade", vec![], vec![Argument::Input(0), Argument::Input(1), Argument::Input(2)]),
            Command::Upgrade(modules, std_deps.clone(), pkg.id(), Argument::Result(0)),
            call(two, "package", "commit_upgrade", vec![], vec![Argument::Input(0), Argument::Result(1)]),
        ];
        out.push((format!("upgrade/{name}"), inputs, cmds, vec![cap.clone(), pkg.clone()]));
        Ok(())
    };
    let e_a = enum_module(&["A"])?;
    let (ep1, cap_ep1) = publish(vec![e_a.clone()])?;
    upg("compatible-enum-same", &cap_ep1, &ep1, vec![e_a.clone()], 0)?;
    upg("compatible-enum-new-variant", &cap_ep1, &ep1, vec![enum_module(&["A", "B"])?], 0)?;
    upg("compatible-enum-variant-renamed", &cap_ep1, &ep1, vec![enum_module(&["B"])?], 0)?;
    let n1 = upg_module_full("n", SignatureToken::U64, store_ab, &[UFun { name: "f", k: 1, vis: move_binary_format::file_format::Visibility::Public, entry: false, param: false }], false, None)?;
    let (fp1, cap_fp1) = publish(vec![m1.clone(), n1.clone()])?;
    let m_friend = tweak(&m1, |m| {
        use move_binary_format::file_format::*;
        let i = m.identifiers.len() as u16;
        m.identifiers.push(move_core_types::identifier::Identifier::new("n").unwrap());
        m.friend_decls.push(ModuleHandle { address: AddressIdentifierIndex(0), name: IdentifierIndex(i) });
    })?;
    upg("dep-only-friend-added", &cap_fp1, &fp1, vec![m_friend.clone(), n1.clone()], 192)?;
    upg("additive-friend-added", &cap_fp1, &fp1, vec![m_friend.clone(), n1.clone()], 128)?;
    upg("compatible-friend-added", &cap_fp1, &fp1, vec![m_friend, n1.clone()], 0)?;
    Ok((out, ov))
}

/// The implicit Clock (protocol 142, `clock::borrow`): a published module `clk` with
/// `read(): u64 = clock::timestamp_ms(clock::borrow())` and `both(c: &Clock): u64` (the declared
/// Clock plus the implicit one), run at 142 over the 1.84 built-in framework (which travels in the
/// vector's objects: the corpus's system packages are 141's) with the Clock pinned at version
/// `ver` through `SystemObjectVersions`. Effects must carry the Clock as a ReadOnlyRoot (a
/// declared input wins over the implicit read).
#[cfg(feature = "sui_184")]
fn clock_cases(ctx: &Ctx, base: &TransactionData, gas: &Object) -> Result<(Vec<Case>, Overrides, HashMap<String, u64>)> {
    use move_binary_format::file_format::*;
    use move_core_types::account_address::AccountAddress;
    use move_core_types::identifier::Identifier;
    let one = sui_types::MOVE_STDLIB_PACKAGE_ID;
    let two = sui_types::SUI_FRAMEWORK_PACKAGE_ID;
    let sender = base.sender();
    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(142), Chain::Mainnet);
    let c142 = Ctx { env: ctx.env, ex: sui_execution::executor(&cfg, true)?, cfg, metrics: ctx.metrics.clone(), epoch: ctx.epoch };
    let fw: Vec<Object> = sui_framework::BuiltInFramework::genesis_objects().collect();
    let id = |s: &str| Identifier::new(s).unwrap();
    let m = CompiledModule {
        version: 7,
        publishable: true,
        self_module_handle_idx: ModuleHandleIndex(0),
        module_handles: vec![
            ModuleHandle { address: AddressIdentifierIndex(0), name: IdentifierIndex(0) },
            ModuleHandle { address: AddressIdentifierIndex(1), name: IdentifierIndex(2) },
        ],
        datatype_handles: vec![DatatypeHandle { module: ModuleHandleIndex(1), name: IdentifierIndex(5), abilities: AbilitySet::EMPTY | Ability::Key, type_parameters: vec![] }],
        function_handles: vec![
            FunctionHandle { module: ModuleHandleIndex(0), name: IdentifierIndex(1), parameters: SignatureIndex(0), return_: SignatureIndex(1), type_parameters: vec![] },
            FunctionHandle { module: ModuleHandleIndex(1), name: IdentifierIndex(3), parameters: SignatureIndex(0), return_: SignatureIndex(2), type_parameters: vec![] },
            FunctionHandle { module: ModuleHandleIndex(1), name: IdentifierIndex(4), parameters: SignatureIndex(2), return_: SignatureIndex(1), type_parameters: vec![] },
            FunctionHandle { module: ModuleHandleIndex(0), name: IdentifierIndex(6), parameters: SignatureIndex(2), return_: SignatureIndex(1), type_parameters: vec![] },
        ],
        field_handles: vec![],
        friend_decls: vec![],
        struct_def_instantiations: vec![],
        function_instantiations: vec![],
        field_instantiations: vec![],
        signatures: vec![
            Signature(vec![]),
            Signature(vec![SignatureToken::U64]),
            Signature(vec![SignatureToken::Reference(Box::new(SignatureToken::Datatype(DatatypeHandleIndex(0))))]),
        ],
        identifiers: vec![id("clk"), id("read"), id("clock"), id("borrow"), id("timestamp_ms"), id("Clock"), id("both")],
        address_identifiers: vec![AccountAddress::ZERO, AccountAddress::TWO],
        constant_pool: vec![],
        metadata: vec![],
        struct_defs: vec![],
        function_defs: vec![
            FunctionDefinition {
                function: FunctionHandleIndex(0),
                visibility: Visibility::Public,
                is_entry: false,
                acquires_global_resources: vec![],
                code: Some(CodeUnit { locals: SignatureIndex(0), code: vec![Bytecode::Call(FunctionHandleIndex(1)), Bytecode::Call(FunctionHandleIndex(2)), Bytecode::Ret], jump_tables: vec![] }),
            },
            FunctionDefinition {
                function: FunctionHandleIndex(3),
                visibility: Visibility::Public,
                is_entry: false,
                acquires_global_resources: vec![],
                code: Some(CodeUnit {
                    locals: SignatureIndex(0),
                    code: vec![
                        Bytecode::CopyLoc(0),
                        Bytecode::Call(FunctionHandleIndex(2)),
                        Bytecode::Call(FunctionHandleIndex(1)),
                        Bytecode::Call(FunctionHandleIndex(2)),
                        Bytecode::Add,
                        Bytecode::Ret,
                    ],
                    jump_tables: vec![],
                }),
            },
        ],
        enum_defs: vec![],
        enum_def_instantiations: vec![],
        variant_handles: vec![],
        variant_instantiation_handles: vec![],
    };
    let mut module = Vec::new();
    m.serialize_with_version(m.version, &mut module)?;
    // publish it at 142
    let pt = ProgrammableTransaction {
        inputs: vec![CallArg::Pure(bcs::to_bytes(&sender)?)],
        commands: vec![Command::Publish(vec![module], vec![one, two]), Command::TransferObjects(vec![Argument::Result(0)], Argument::Input(0))],
    };
    let vdata = TransactionData::new_with_gas_data(TransactionKind::ProgrammableTransaction(pt), sender, base.gas_data().clone());
    let mut objs: HashMap<ObjectID, Object> = HashMap::new();
    objs.insert(gas.id(), gas.clone());
    for o in &fw {
        objs.insert(o.id(), o.clone());
    }
    let r = c142.run(&vdata, &objs, &HashMap::new())?;
    anyhow::ensure!(r.effects.status().is_ok(), "clock module publish: {:?}", r.effects.status());
    let pkg = r.written.iter().find(|o| o.is_package() && !sui_types::is_system_package(o.id())).context("no package")?.clone();
    // the Clock: { id: 0x6, timestamp_ms }, shared since version 1, at version 100
    let ver = 100u64;
    let mut contents = sui_types::SUI_CLOCK_OBJECT_ID.to_vec();
    contents.extend_from_slice(&1_762_400_123_456u64.to_le_bytes());
    let mo = unsafe {
        MoveObject::new_from_execution_with_limit(sui_types::clock::Clock::type_().into(), true, SequenceNumber::from_u64(ver), contents, 256_000)
    }?;
    let clock = Object::new_move(mo, Owner::Shared { initial_shared_version: SequenceNumber::from_u64(1) }, TransactionDigest::new([0x66; 32]));
    let mut extra = fw.clone();
    extra.push(pkg.clone());
    let mut with_clock = extra.clone();
    with_clock.push(clock.clone());
    let read = || call(pkg.id(), "clk", "read", vec![], vec![]);
    let decl = CallArg::Object(ObjectArg::SharedObject { id: sui_types::SUI_CLOCK_OBJECT_ID, initial_shared_version: SequenceNumber::from_u64(1), mutability: sui_types::transaction::SharedObjectMutability::Immutable });
    let mut cases: Vec<Case> = vec![];
    let mut ov: Overrides = HashMap::new();
    let mut cv: HashMap<String, u64> = HashMap::new();
    let mut add = |name: &str, inputs: Vec<CallArg>, cmds: Vec<Command>, extra: Vec<Object>, with: bool| {
        cases.push((name.into(), inputs, cmds, extra));
        ov.insert(name.into(), (Some(142), None));
        if with {
            cv.insert(name.into(), ver);
        }
    };
    add("clock/borrow", vec![], vec![read()], with_clock.clone(), true);
    add("clock/borrow-twice", vec![], vec![read(), read()], with_clock.clone(), true);
    add("clock/declared", vec![decl.clone()], vec![call(pkg.id(), "clk", "both", vec![], vec![Argument::Input(0)])], with_clock.clone(), true);
    add("clock/declared-then-borrow", vec![decl], vec![call(pkg.id(), "clk", "both", vec![], vec![Argument::Input(0)]), read()], with_clock.clone(), true);
    // review: a failed transaction keeps the implicit read (`loaded_system_objects` survives
    // `drop_writes`), and a transaction that fails before the borrow runs reads nothing.
    // borrow-then-fail: the split coin is left unused (UnusedValueWithoutDrop after every command
    // ran); fail-then-borrow: a function `clk` does not have, so `read()` never runs.
    let one_mist = CallArg::Pure(bcs::to_bytes(&1u64)?);
    let split = || Command::SplitCoins(Argument::GasCoin, vec![Argument::Input(0)]);
    add("clock/borrow-then-fail", vec![one_mist], vec![read(), split()], with_clock.clone(), true);
    add("clock/fail-then-borrow", vec![], vec![call(pkg.id(), "clk", "nope", vec![], vec![]), read()], with_clock, true);
    // (a store without the Clock is a VMInvariantViolation in Rust; the scheduler always assigns the
    // version, so deepwave reports "clock version not assigned" and no vector keeps a permanent skip)
    let _ = extra;
    Ok((cases, ov, cv))
}
