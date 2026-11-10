//! `deny-order <corpus> <out.jsonl>`: coin deny list v2 vectors that carry the executor's store
//! reads in call order (`src/exec/testdata/deny_order.jsonl`).
//!
//! Every object is synthetic: a sender, its gas coin and `Coin<T>` objects whose `T` is a struct
//! of a system package (so the executor needs the corpus only for the system packages of the
//! epoch), the 0x403 per-type config fields and the configs' `Setting<bool>` fields. Each vector
//! is one coin-only programmable transaction run by `sui_execution::executor` at the newest
//! epoch of the corpus epoch table. One line per vector:
//! `{"name","pv","epoch","rgp","start_ms","tx":hex TransactionData,"objects":[hex Object],
//!   "system":[{"seq","epoch"}],"latest":[hex Object],"reads":[{"id":hex,"hit":bool,"what":label}],
//!   "status":Debug,"effects":hex,"written":[hex Object]}`.
//! `system` names the corpus checkpoints whose end-of-epoch transaction wrote the system
//! packages the executor loaded (`seq`), each with the first epoch that sees them.
//! `reads` is every `ObjectStore::get_object` call on the backing store, in call order: the
//! reads of `check_coin_deny_list_v2_during_execution` (the executor makes no other such call
//! for these transactions; the tool fails if it sees one it cannot name).
use crate::synth::{fw, setting_object};
use crate::{ExecStore, load_exec_env};
use anyhow::{Context, Result, bail};
use move_core_types::language_storage::TypeTag;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use sui_types::base_types::{ObjectID, SequenceNumber, SuiAddress};
use sui_types::digests::TransactionDigest;
use sui_types::effects::{TransactionEffects, TransactionEffectsAPI};
use sui_types::execution_status::{ExecutionErrorKind, ExecutionStatus};
use sui_types::object::{MoveObject, Object, Owner};
use sui_types::transaction::{
    Argument, CallArg, Command, GasData, InputObjectKind, ObjectArg, ObjectReadResult, ObjectReadResultKind, ProgrammableTransaction, TransactionData,
    TransactionDataAPI, TransactionKind,
};

fn addr(b: u8) -> SuiAddress {
    SuiAddress::from(ObjectID::new([b; 32]))
}

fn oid(a: u8, b: u8) -> ObjectID {
    let mut x = [0u8; 32];
    x[0] = a;
    x[31] = b;
    ObjectID::new(x)
}

fn with_rebate(o: Object, rebate: u64) -> Object {
    let mut inner = o.into_inner();
    inner.storage_rebate = rebate;
    inner.into()
}

/// The 0x403 dynamic object field of a coin type: `Field<Wrapper<ConfigKey>, ID>` naming `config`.
fn config_field(ty: &str, config: ObjectID) -> Result<Object> {
    let key_tag = TypeTag::Struct(Box::new(fw("dynamic_object_field", "Wrapper", vec![TypeTag::Struct(Box::new(fw("deny_list", "ConfigKey", vec![])))])));
    let mut key = 0u64.to_le_bytes().to_vec();
    key.extend(bcs::to_bytes(&ty.as_bytes().to_vec())?);
    let id = sui_types::dynamic_field::derive_dynamic_field_id(sui_types::SUI_DENY_LIST_OBJECT_ID, &key_tag, &key)?;
    let mut contents = id.to_vec();
    contents.extend_from_slice(&key);
    contents.extend_from_slice(config.as_ref());
    let field = fw("dynamic_field", "Field", vec![key_tag, TypeTag::Struct(Box::new(fw("object", "ID", vec![])))]);
    let mo = unsafe { MoveObject::new_from_execution_with_limit(field.into(), false, SequenceNumber::from_u64(5), contents, 512)? };
    Ok(Object::new_move(mo, Owner::ObjectOwner(sui_types::SUI_DENY_LIST_OBJECT_ID.into()), TransactionDigest::new([0x5b; 32])))
}

fn config_field_id(ty: &str) -> Result<ObjectID> {
    Ok(config_field(ty, ObjectID::ZERO)?.id())
}

fn setting_id(config: ObjectID, key_name: &str, key: &[u8]) -> Result<ObjectID> {
    Ok(sui_types::dynamic_field::derive_dynamic_field_id(config, &TypeTag::Struct(Box::new(fw("deny_list", key_name, vec![]))), key)?)
}

struct Case {
    name: &'static str,
    data: TransactionData,
    /// The store's latest objects outside the inputs.
    latest: Vec<Object>,
}

pub fn cmd_deny_order(corpus: &Path, out: &Path) -> Result<()> {
    let env = load_exec_env(corpus)?;
    let epoch = env.epochs.len() as u64 - 1;
    let ep = env.epochs[epoch as usize];
    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(ep.0), Chain::Mainnet);
    if cfg.execution_version_as_option() != Some(4) {
        bail!("epoch {epoch} (protocol {}) is not on execution version 4", ep.0);
    }
    let ex = sui_execution::executor(&cfg, true)?;
    let registry = prometheus::Registry::new();
    let metrics = Arc::new(sui_types::metrics::ExecutionMetrics::new(&registry));

    // the sender sorts between the two recipients
    let sender = addr(0x55);
    let hi = addr(0x99);
    let lo = addr(0x11);
    // coin types: structs of the system packages, in canonical string order ta < tb
    let ta = TypeTag::Struct(Box::new(move_core_types::language_storage::StructTag {
        address: move_core_types::account_address::AccountAddress::ONE,
        module: move_core_types::identifier::Identifier::new("ascii").unwrap(),
        name: move_core_types::identifier::Identifier::new("String").unwrap(),
        type_params: vec![],
    }));
    let tb = TypeTag::Struct(Box::new(fw("clock", "Clock", vec![])));
    let (sa, sb) = (ta.to_canonical_string(false), tb.to_canonical_string(false));
    anyhow::ensure!(sa < sb, "coin type order");
    let (ca, cb) = (oid(0xc0, 1), oid(0xc0, 2));

    let prev = TransactionDigest::new([0x5a; 32]);
    let gas = with_rebate(Object::new_move(MoveObject::new_gas_coin(SequenceNumber::from_u64(10), oid(0x6a, 1), 10_000_000_000), Owner::AddressOwner(sender), prev), 988_000);
    let coin_a = with_rebate(Object::new_move(MoveObject::new_coin(ta.clone(), SequenceNumber::from_u64(11), oid(0x6a, 2), 1_000), Owner::AddressOwner(sender), prev), 1_520_000);
    let coin_b = with_rebate(Object::new_move(MoveObject::new_coin(tb.clone(), SequenceNumber::from_u64(12), oid(0x6a, 3), 500), Owner::AddressOwner(sender), prev), 1_504_800);
    let mut inputs: HashMap<ObjectID, Object> = HashMap::new();
    for o in [&gas, &coin_a, &coin_b] {
        inputs.insert(o.id(), o.clone());
    }
    let gas_data = |budget: u64| GasData { payment: vec![gas.compute_object_reference()], owner: sender, price: ep.1, budget };
    let budget = 50_000_000u64;
    let tx = |pt: ProgrammableTransaction, budget: u64| TransactionData::new_with_gas_data(TransactionKind::ProgrammableTransaction(pt), sender, gas_data(budget));
    // split 100 off Coin<ta> to `to`: the rest stays with the sender (two owners of ta)
    let split_send = |to: SuiAddress| -> Result<ProgrammableTransaction> {
        Ok(ProgrammableTransaction {
            inputs: vec![
                CallArg::Object(ObjectArg::ImmOrOwnedObject(coin_a.compute_object_reference())),
                CallArg::Pure(bcs::to_bytes(&100u64)?),
                CallArg::Pure(bcs::to_bytes(&to)?),
            ],
            commands: vec![Command::SplitCoins(Argument::Input(0), vec![Argument::Input(1)]), Command::TransferObjects(vec![Argument::Result(0)], Argument::Input(2))],
        })
    };
    // Coin<ta> and Coin<tb> to `hi`: one owner of each type
    let two = ProgrammableTransaction {
        inputs: vec![
            CallArg::Object(ObjectArg::ImmOrOwnedObject(coin_a.compute_object_reference())),
            CallArg::Object(ObjectArg::ImmOrOwnedObject(coin_b.compute_object_reference())),
            CallArg::Pure(bcs::to_bytes(&hi)?),
        ],
        commands: vec![Command::TransferObjects(vec![Argument::Input(0), Argument::Input(1)], Argument::Input(2))],
    };

    let fa = config_field(&sa, ca)?;
    let fb = config_field(&sb, cb)?;
    // a setting in force now (written in an earlier epoch), one that takes effect next epoch,
    // and one in force now that is lifted next epoch
    let now = |c: ObjectID, k: &str, key: &[u8]| setting_object(c, k, key, epoch - 1, Some(true), None);
    let next = |c: ObjectID, k: &str, key: &[u8]| setting_object(c, k, key, epoch, Some(true), None);
    let lifted = |c: ObjectID, k: &str, key: &[u8]| setting_object(c, k, key, epoch, Some(false), Some(true));
    let a = "AddressKey";
    let p = "GlobalPauseKey";
    let (s, h, l) = (sender.to_vec(), hi.to_vec(), lo.to_vec());

    let mut cases: Vec<Case> = Vec::new();
    let mut add = |name: &'static str, pt: &ProgrammableTransaction, latest: Vec<Object>| cases.push(Case { name, data: tx(pt.clone(), budget), latest });
    let to_hi = split_send(hi)?;
    let to_lo = split_send(lo)?;
    // (c) no config object
    add("none/two-types", &two, vec![]);
    add("none/first-type-only", &two, vec![fb.clone()]);
    // configs without settings
    add("control/two-types", &two, vec![fa.clone(), fb.clone()]);
    add("control/split", &to_hi, vec![fa.clone()]);
    // (b) two regulated types
    add("two/first-address-denied", &two, vec![fa.clone(), fb.clone(), now(ca, a, &h)?]);
    add("two/first-paused", &two, vec![fa.clone(), fb.clone(), now(ca, p, &[0])?]);
    add("two/second-address-denied", &two, vec![fa.clone(), fb.clone(), now(cb, a, &h)?]);
    add("two/second-paused", &two, vec![fa.clone(), fb.clone(), now(cb, p, &[0])?]);
    add("two/both-denied", &two, vec![fa.clone(), fb.clone(), now(ca, a, &h)?, now(cb, p, &[0])?]);
    add("two/first-no-config-second-paused", &two, vec![fb.clone(), now(cb, p, &[0])?]);
    // (d) the global pause, by epoch
    add("pause/now", &to_hi, vec![fa.clone(), now(ca, p, &[0])?]);
    add("pause/next-epoch", &to_hi, vec![fa.clone(), next(ca, p, &[0])?]);
    add("pause/lifted-next-epoch", &to_hi, vec![fa.clone(), lifted(ca, p, &[0])?]);
    add("pause/now-and-addresses", &to_hi, vec![fa.clone(), now(ca, p, &[0])?, now(ca, a, &s)?, now(ca, a, &h)?]);
    // (e) the sender (keeps the rest of the coin) against the recipient, by epoch
    add("address/sender-now", &to_hi, vec![fa.clone(), now(ca, a, &s)?]);
    add("address/recipient-now", &to_hi, vec![fa.clone(), now(ca, a, &h)?]);
    add("address/both-now", &to_hi, vec![fa.clone(), now(ca, a, &s)?, now(ca, a, &h)?]);
    add("address/both-now-recipient-sorts-first", &to_lo, vec![fa.clone(), now(ca, a, &s)?, now(ca, a, &l)?]);
    add("address/sender-next-epoch", &to_hi, vec![fa.clone(), next(ca, a, &s)?]);
    add("address/recipient-next-epoch", &to_hi, vec![fa.clone(), next(ca, a, &h)?]);
    add("address/sender-now-recipient-next-epoch", &to_hi, vec![fa.clone(), now(ca, a, &s)?, next(ca, a, &h)?]);
    add("address/sender-next-epoch-recipient-now", &to_hi, vec![fa.clone(), next(ca, a, &s)?, now(ca, a, &h)?]);
    add("address/sender-lifted-next-epoch", &to_hi, vec![fa.clone(), lifted(ca, a, &s)?]);
    add("address/recipient-lifted-next-epoch", &to_hi, vec![fa.clone(), lifted(ca, a, &h)?]);

    // names of the reads
    let mut what: HashMap<ObjectID, String> = HashMap::new();
    for (t, ts, c) in [("a", &sa, ca), ("b", &sb, cb)] {
        what.insert(config_field_id(ts)?, format!("config({t})"));
        what.insert(setting_id(c, p, &[0])?, format!("pause({t})"));
        for (n, o) in [("sender", &s), ("hi", &h), ("lo", &l)] {
            what.insert(setting_id(c, a, o)?, format!("address({t},{n})"));
        }
    }

    let run = |data: &TransactionData, latest: &[Object]| -> Result<(TransactionEffects, Vec<Object>, Vec<(ObjectID, bool)>)> {
        let lat: HashMap<ObjectID, Object> = latest.iter().map(|o| (o.id(), o.clone())).collect();
        let log = Mutex::new(Vec::new());
        let store = ExecStore { inputs: &inputs, packages: &env.packages, system: &env.system, epoch, latest: Some(&lat), reads: Some(&log) };
        let mut reads = Vec::new();
        for k in data.input_objects()? {
            if matches!(k, InputObjectKind::MovePackage(_)) {
                continue;
            }
            let o = inputs.get(&k.object_id()).context("input object")?;
            reads.push(ObjectReadResult::new(k, ObjectReadResultKind::Object(o.clone())));
        }
        let gas_status = sui_types::gas::SuiGasStatus::new(data.gas_data().budget, data.gas_data().price, ep.1, &cfg)?;
        let (inner, _, fx, _, _) = ex.execute_transaction_to_effects(
            &store,
            &cfg,
            metrics.clone(),
            false,
            sui_types::execution_params::ExecutionOrEarlyError::ok(None),
            &epoch,
            ep.2,
            sui_types::transaction::CheckedInputObjects::new_for_replay(sui_types::transaction::InputObjects::new(reads)),
            sui_types::base_types::SystemObjectVersions::empty(),
            &sui_types::accumulator_root::EmptyUnsettledObjectFunds,
            data.gas_data().clone(),
            gas_status,
            data.kind().clone(),
            None,
            data.sender(),
            data.digest(),
            &mut None,
        );
        anyhow::ensure!(inner.events.data.is_empty(), "events");
        Ok((fx, inner.written.values().cloned().collect(), log.into_inner().unwrap()))
    };

    // (a) out of gas at the deny-list charge (the split, one coin type with two owners): the
    // smallest budget (in gas units) at which check_coin_deny_list runs (0x403 is then a loaded
    // per-epoch config object), which leaves too little for charge_coin_transfers
    let has_deny = |fx: &TransactionEffects| fx.unchanged_consensus_objects().iter().any(|(id, _)| *id == sui_types::SUI_DENY_LIST_OBJECT_ID);
    let oog_budget = {
        let all = vec![fa.clone()];
        let (mut lo_u, mut hi_u) = (1u64, budget / ep.1);
        anyhow::ensure!(!has_deny(&run(&tx(to_hi.clone(), lo_u * ep.1), &all)?.0) && has_deny(&run(&tx(to_hi.clone(), hi_u * ep.1), &all)?.0), "budget search bounds");
        while hi_u - lo_u > 1 {
            let mid = lo_u + (hi_u - lo_u) / 2;
            if has_deny(&run(&tx(to_hi.clone(), mid * ep.1), &all)?.0) { hi_u = mid } else { lo_u = mid }
        }
        eprintln!("deny-order: the deny list check is reached from a budget of {hi_u} gas units; one unit less runs out of gas before it");
        hi_u * ep.1
    };
    for (name, latest) in [
        ("out-of-gas/charge", vec![fa.clone()]),
        ("out-of-gas/charge-sender-denied", vec![fa.clone(), now(ca, a, &s)?]),
        ("out-of-gas/charge-recipient-denied", vec![fa.clone(), now(ca, a, &h)?]),
        ("out-of-gas/charge-paused", vec![fa.clone(), now(ca, p, &[0])?]),
        ("out-of-gas/charge-no-config", vec![]),
    ] {
        cases.push(Case { name, data: tx(to_hi.clone(), oog_budget), latest });
    }
    // one unit less: out of gas before context::finish, the check never runs
    cases.push(Case { name: "out-of-gas/before-finish", data: tx(to_hi.clone(), oog_budget - ep.1), latest: vec![fa.clone(), now(ca, a, &s)?] });

    // where the corpus holds the system packages the executor loaded: for each one, the
    // checkpoint that wrote the version this epoch sees and the first epoch that sees it
    let mut system: Vec<(u64, u64)> = Vec::new();
    for list in env.system.values() {
        let Some((visible, _)) = list.iter().filter(|(e, _)| *e <= epoch).last() else { continue };
        let seq = if *visible == 0 { 0 } else { env.epochs[*visible as usize - 1].3.context("epoch without a last checkpoint")? };
        if !system.contains(&(seq, *visible)) {
            system.push((seq, *visible));
        }
    }
    system.sort();
    let system: Vec<serde_json::Value> = system.iter().map(|(seq, visible)| serde_json::json!({"seq": seq, "epoch": visible})).collect();

    let mut f = std::fs::File::create(out)?;
    for c in &cases {
        let (fx, written, reads) = run(&c.data, &c.latest)?;
        if c.name.starts_with("out-of-gas/") && !matches!(fx.status(), ExecutionStatus::Failure(e) if matches!(e.error, ExecutionErrorKind::InsufficientGas)) {
            bail!("{}: expected InsufficientGas, got {:?}", c.name, fx.status());
        }
        let mut rl = Vec::new();
        for (id, hit) in &reads {
            let Some(w) = what.get(id) else { bail!("{}: get_object({id}) is not a deny list read", c.name) };
            rl.push(serde_json::json!({"id": hex::encode(id), "hit": hit, "what": w}));
        }
        let status = format!("{:?}", fx.status());
        eprintln!("deny-order: {}: {status}; gas {:?}; reads {}", c.name, fx.gas_cost_summary(), reads.iter().map(|(id, hit)| format!("{}{}", what[id], if *hit { "" } else { "?" })).collect::<Vec<_>>().join(" "));
        let objs: Vec<Object> = c.data.input_objects()?.iter().filter(|k| !matches!(k, InputObjectKind::MovePackage(_))).map(|k| inputs[&k.object_id()].clone()).collect();
        let hexs = |v: &[Object]| -> Result<Vec<String>> { v.iter().map(|o| Ok(hex::encode(bcs::to_bytes(o)?))).collect() };
        let line = serde_json::json!({
            "name": c.name,
            "pv": ep.0,
            "epoch": epoch,
            "rgp": ep.1,
            "start_ms": ep.2,
            "tx": hex::encode(bcs::to_bytes(&c.data)?),
            "objects": hexs(&objs)?,
            "system": system,
            "latest": hexs(&c.latest)?,
            "reads": rl,
            "status": status,
            "effects": hex::encode(bcs::to_bytes(&fx)?),
            "written": hexs(&written)?,
        });
        writeln!(f, "{line}")?;
    }
    eprintln!("deny-order: {} vectors at epoch {epoch} (protocol {})", cases.len(), ep.0);
    Ok(())
}
