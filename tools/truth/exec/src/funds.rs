//! `funds-sched <corpus> <out.jsonl>`: funds withdraw scheduling vectors for the validator's
//! certified execution path (deepwave `validator-funds` suite).
//!
//! Each scenario is a run of certified transactions with funds withdrawals, grouped by the
//! accumulator version consensus assigned them, in commit order. Mysten's own funds withdraw
//! scheduler (sui-core `execution_scheduler/funds_withdraw_scheduler`, the default `Eager` kind,
//! compiled from its sources: the module is `pub(crate)`) decides each transaction against an
//! `AccountFundsRead` that answers the account balances at the group's accumulator version
//! (settlements in between go through `settle_funds`). Each transaction then runs through
//! `sui_execution::executor` with `ExecutionOrEarlyError::failed(InsufficientFundsForWithdraw)`
//! for an `InsufficientFunds` status and the accumulator root version in its
//! `SystemObjectVersions`, as `AuthorityState::execute_certificate` does. Object withdrawals
//! (`vault::withdraw`, move/vault) read through sui-core's `UnsettledObjectWithdrawals`, which
//! records every successful execution's net object withdrawals at its accumulator version.
//!
//! Line: `{"name","pv","epoch","rgp","start_ms","objects":[hex Object],
//!         "txs":[{"tx":hex TransactionData,"acc":V,"status":"SufficientFunds"|"InsufficientFunds",
//!                 "effects":hex,"events":hex|null}]}`
//! `objects` is the whole store before the first transaction (gas coins, the accumulator root at
//! every version a group reads, the account fields at the versions their settlements wrote).
//! System packages come from the corpus (newest epoch).
use crate::execution_scheduler::funds_withdraw_scheduler::{FundsSettlement, FundsWithdrawSchedulerType, ScheduleStatus, TxFundsWithdraw, WithdrawReservations, scheduler::FundsWithdrawScheduler};
use crate::{ExecStore, load_exec_env};
use anyhow::{Context, Result};
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::{StructTag, TypeTag};
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use sui_core::accumulators::funds_read::AccountFundsRead;
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use sui_types::accumulator_root::{AccumulatorObjId, AccumulatorValue};
use sui_types::base_types::{ObjectID, SequenceNumber, SuiAddress};
use sui_types::digests::TransactionDigest;
use sui_types::effects::TransactionEffectsAPI;
use sui_types::execution_status::ExecutionErrorKind;
use sui_types::gas_coin::GAS;
use sui_types::object::{MoveObject, Object, Owner};
use sui_types::transaction::{
    Argument, CallArg, Command, FundsWithdrawalArg, ObjectArg, GasData, InputObjectKind, ObjectReadResult, ObjectReadResultKind, ProgrammableMoveCall,
    ProgrammableTransaction, TransactionData, TransactionDataAPI, TransactionExpiration, TransactionKind,
};

/// Balances as of the scheduler's current accumulator version.
struct Funds(Mutex<HashMap<AccumulatorObjId, (u128, SequenceNumber)>>);

impl AccountFundsRead for Funds {
    fn get_latest_account_amount(&self, id: &AccumulatorObjId) -> u128 {
        self.0.lock().unwrap().get(id).map(|x| x.0).unwrap_or(0)
    }
    fn get_consistent_latest_account_amount_and_version(&self, id: &AccumulatorObjId) -> (u128, SequenceNumber) {
        self.0.lock().unwrap().get(id).copied().unwrap_or((0, SequenceNumber::MIN))
    }
    fn get_account_amount_at_version(&self, id: &AccumulatorObjId, _v: SequenceNumber) -> u128 {
        self.get_latest_account_amount(id)
    }
}

fn addr(b: u8) -> SuiAddress {
    SuiAddress::from(ObjectID::from_single_byte(b))
}

fn fw2(module: &str, name: &str, params: Vec<TypeTag>) -> StructTag {
    crate::synth::fw(module, name, params)
}

fn balance_of(t: TypeTag) -> TypeTag {
    TypeTag::Struct(Box::new(fw2("balance", "Balance", vec![t])))
}

/// A second coin type for the multi-account cases (never executed: those transactions are short).
fn other_coin() -> TypeTag {
    TypeTag::Struct(Box::new(StructTag {
        address: move_core_types::account_address::AccountAddress::ONE,
        module: Identifier::new("string").unwrap(),
        name: Identifier::new("String").unwrap(),
        type_params: vec![],
    }))
}

/// `Field<Key<Balance<T>>, U128>` of `owner` holding `amount`, at `version`.
fn account(owner: SuiAddress, coin: TypeTag, amount: u64, version: u64) -> Object {
    let mut o = AccumulatorValue::create_for_testing(owner, balance_of(coin), amount);
    o.data.try_as_move_mut().unwrap().increment_version_to(SequenceNumber::from_u64(version));
    o
}

fn account_id(owner: SuiAddress, coin: TypeTag) -> AccumulatorObjId {
    AccumulatorValue::get_field_id(owner, &balance_of(coin)).unwrap()
}

/// `0x2::accumulator::AccumulatorRoot { id }`, shared, at `version`.
fn root(version: u64) -> Result<Object> {
    let id = sui_types::SUI_ACCUMULATOR_ROOT_OBJECT_ID;
    let tag = fw2("accumulator", "AccumulatorRoot", vec![]);
    let mo = unsafe { MoveObject::new_from_execution_with_limit(tag.into(), false, SequenceNumber::from_u64(version), id.to_vec(), 512)? };
    Ok(Object::new_move(mo, Owner::Shared { initial_shared_version: SequenceNumber::from_u64(3) }, TransactionDigest::new([0x3c; 32])))
}

fn gas_coin(n: u8, owner: SuiAddress) -> Object {
    let mut o = Object::with_id_owner_gas_for_testing(ObjectID::from_single_byte(0xc0 + n), owner, 10_000_000_000);
    o.data.try_as_move_mut().unwrap().increment_version_to(SequenceNumber::from_u64(7));
    o
}

/// One transaction of a scenario: `withdraws` are (coin, amount) from the sender; `ab_gas` pays
/// gas from the gas owner's address balance; `price` 0 makes it gasless.
struct Tx {
    sender: SuiAddress,
    sponsor: Option<SuiAddress>,
    withdraws: Vec<(TypeTag, u64)>,
    gas: Option<u8>,
    budget: u64,
    price: Option<u64>,
    group: usize,
    /// Withdraws this amount of SUI from the vault object's balance at runtime
    /// (`vault::withdraw` -> `balance::withdraw_funds_from_object`) instead of `withdraws`.
    vault: Option<u64>,
}

fn build(t: &Tx, epoch: u64, rgp: u64, nonce: u32, vault: Option<&Object>) -> TransactionData {
    let mut inputs = Vec::new();
    let mut commands = Vec::new();
    let recipient = addr(0x99);
    inputs.push(CallArg::Pure(bcs::to_bytes(&recipient).unwrap()));
    if let (Some(amount), Some(v)) = (t.vault, vault) {
        inputs.push(CallArg::Object(ObjectArg::ImmOrOwnedObject(v.compute_object_reference())));
        inputs.push(CallArg::Pure(bcs::to_bytes(&amount).unwrap()));
        commands.push(Command::MoveCall(Box::new(ProgrammableMoveCall {
            package: vault_pkg(),
            module: "vault".into(),
            function: "withdraw".into(),
            type_arguments: vec![sui().into()],
            arguments: vec![Argument::Input(1), Argument::Input(2), Argument::Input(0)],
        })));
    }
    for (coin, amount) in &t.withdraws {
        let i = inputs.len() as u16;
        inputs.push(CallArg::FundsWithdrawal(FundsWithdrawalArg::balance_from_sender(*amount, coin.clone())));
        let r = commands.len() as u16;
        commands.push(Command::MoveCall(Box::new(ProgrammableMoveCall {
            package: ObjectID::from_single_byte(2),
            module: "balance".into(),
            function: "redeem_funds".into(),
            type_arguments: vec![coin.clone().into()],
            arguments: vec![Argument::Input(i)],
        })));
        commands.push(Command::MoveCall(Box::new(ProgrammableMoveCall {
            package: ObjectID::from_single_byte(2),
            module: "balance".into(),
            function: "send_funds".into(),
            type_arguments: vec![coin.clone().into()],
            arguments: vec![Argument::Result(r), Argument::Input(0)],
        })));
    }
    let pt = ProgrammableTransaction { inputs, commands };
    let owner = t.sponsor.unwrap_or(t.sender);
    let payment = match t.gas {
        Some(n) => {
            let g = gas_coin(n, owner);
            vec![g.compute_object_reference()]
        }
        None => vec![],
    };
    let gas_data = GasData { payment, owner, price: t.price.unwrap_or(rgp), budget: t.budget };
    let expiration = if t.gas.is_none() {
        TransactionExpiration::ValidDuring {
            min_epoch: Some(epoch),
            max_epoch: Some(epoch + 1),
            min_timestamp: None,
            max_timestamp: None,
            chain: sui_types::digests::get_mainnet_chain_identifier(),
            nonce,
        }
    } else {
        TransactionExpiration::None
    };
    TransactionData::new_with_gas_data_and_expiration(TransactionKind::ProgrammableTransaction(pt), t.sender, gas_data, expiration)
}

/// The vault package (tools/truth/exec/move/vault, built by Mysten's `sui_move_build` as
/// sui-core's tests build theirs), published at this id.
fn vault_pkg() -> ObjectID {
    ObjectID::from_single_byte(0x7a)
}

fn vault_id() -> ObjectID {
    ObjectID::from_single_byte(0x7b)
}

/// The vault package object: the built module with its self address set to `vault_pkg()`,
/// linked against the corpus framework.
fn vault_package(env: &crate::ExecEnv, cfg: &ProtocolConfig, epoch: u64) -> Result<Object> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("move/vault");
    let built = sui_move_build::BuildConfig::new_for_testing().build(&path).with_context(|| format!("sui move build {}", path.display()))?;
    let mut m = built.get_modules().find(|m| m.self_id().name().as_str() == "vault").context("vault module")?.clone();
    let self_addr = m.module_handles[m.self_handle_idx().0 as usize].address;
    m.address_identifiers[self_addr.0 as usize] = vault_pkg().into();
    let mut deps = Vec::new();
    for id in [ObjectID::from_single_byte(1), ObjectID::from_single_byte(2)] {
        let list = env.system.get(&id).context("system package")?;
        let o = list.iter().filter(|(e, _)| *e <= epoch).last().context("system package at epoch")?.1.clone();
        deps.push(o.data.try_as_package().context("package")?.clone());
    }
    Ok(Object::new_package(&[m], TransactionDigest::new([0x7a; 32]), cfg, &deps)?)
}

/// `vault::vault::Vault { id }` owned by `owner`.
fn vault_object(owner: SuiAddress) -> Result<Object> {
    let tag = StructTag {
        address: vault_pkg().into(),
        module: Identifier::new("vault").unwrap(),
        name: Identifier::new("Vault").unwrap(),
        type_params: vec![],
    };
    let mo = unsafe { MoveObject::new_from_execution_with_limit(tag.into(), true, SequenceNumber::from_u64(7), vault_id().to_vec(), 512)? };
    Ok(Object::new_move(mo, Owner::AddressOwner(owner), TransactionDigest::new([0x7b; 32])))
}

struct Scenario {
    name: &'static str,
    /// (owner, coin, amount at the first group's version) for every funded account.
    funded: Vec<(SuiAddress, TypeTag, u64)>,
    txs: Vec<Tx>,
}

fn sui() -> TypeTag {
    GAS::type_tag()
}

fn scenarios() -> Vec<Scenario> {
    let a = addr(0xa1);
    let b = addr(0xb2);
    let s = addr(0x5b);
    let w = |sender, withdraws: Vec<(TypeTag, u64)>, gas: Option<u8>, group| Tx { sender, sponsor: None, withdraws, gas, budget: 5_000_000, price: None, group, vault: None };
    let vault = SuiAddress::from(vault_id());
    let ov = |amount, gas: u8, group| Tx { sender: a, sponsor: None, withdraws: vec![], gas: Some(gas), budget: 5_000_000, price: None, group, vault: Some(amount) };
    vec![
        Scenario {
            name: "enough-then-exact",
            funded: vec![(a, sui(), 1_000)],
            txs: vec![w(a, vec![(sui(), 400)], Some(1), 0), w(a, vec![(sui(), 600)], Some(2), 0)],
        },
        Scenario {
            name: "second-overdrawn",
            funded: vec![(a, sui(), 1_000)],
            txs: vec![w(a, vec![(sui(), 600)], Some(1), 0), w(a, vec![(sui(), 600)], Some(2), 0), w(a, vec![(sui(), 400)], Some(3), 0)],
        },
        Scenario {
            name: "unfunded",
            funded: vec![],
            txs: vec![w(b, vec![(sui(), 1)], Some(1), 0)],
        },
        Scenario {
            // non-atomic: the short transaction keeps its reservation on the account it covered
            name: "partial-reservation-sticks",
            funded: vec![(a, sui(), 1_000), (a, other_coin(), 10)],
            txs: vec![w(a, vec![(sui(), 300), (other_coin(), 11)], Some(1), 0), w(a, vec![(sui(), 800)], Some(2), 0)],
        },
        Scenario {
            // address-balance gas: the budget is reserved with the withdrawals
            name: "address-gas",
            funded: vec![(a, sui(), 12_000_000)],
            txs: vec![
                Tx { sender: a, sponsor: None, withdraws: vec![(sui(), 1_000)], gas: None, budget: 5_000_000, price: None, group: 0, vault: None },
                Tx { sender: a, sponsor: None, withdraws: vec![(sui(), 1_000)], gas: None, budget: 5_000_000, price: None, group: 0, vault: None },
                Tx { sender: a, sponsor: None, withdraws: vec![(sui(), 2_000_000)], gas: None, budget: 5_000_000, price: None, group: 0, vault: None },
            ],
        },
        Scenario {
            // a sponsor's address balance pays the gas; the sender's withdrawal is the sender's
            name: "sponsor-gas",
            funded: vec![(a, sui(), 500), (s, sui(), 6_000_000)],
            txs: vec![
                Tx { sender: a, sponsor: Some(s), withdraws: vec![(sui(), 500)], gas: None, budget: 5_000_000, price: None, group: 0, vault: None },
                Tx { sender: b, sponsor: Some(s), withdraws: vec![], gas: None, budget: 5_000_000, price: None, group: 0, vault: None },
            ],
        },
        Scenario {
            // gasless (price 0, no payment): only the declared withdrawals are reserved
            name: "gasless",
            funded: vec![(a, sui(), 100)],
            txs: vec![
                Tx { sender: a, sponsor: None, withdraws: vec![(sui(), 100)], gas: None, budget: 0, price: Some(0), group: 0, vault: None },
                Tx { sender: a, sponsor: None, withdraws: vec![(sui(), 1)], gas: None, budget: 0, price: Some(0), group: 0, vault: None },
            ],
        },
        Scenario {
            // the second group reads the balance its settlement left (1000 - 700), not the first one's
            name: "next-version-reads-settled",
            funded: vec![(a, sui(), 1_000)],
            txs: vec![w(a, vec![(sui(), 700)], Some(1), 0), w(a, vec![(sui(), 400)], Some(2), 1), w(a, vec![(sui(), 300)], Some(3), 1)],
        },
        Scenario {
            // G5: object withdrawals read at one accumulator version see the earlier ones as
            // unsettled (150: 100 succeeds, 100 more aborts, the exact 50 left succeeds); the next
            // version reads the settled 0
            name: "object-withdraws-unsettled",
            funded: vec![(vault, sui(), 150)],
            txs: vec![ov(100, 1, 0), ov(100, 2, 0), ov(50, 3, 0), ov(1, 4, 1)],
        },
        Scenario {
            // an address reservation and an object withdrawal in one group are separate accounts
            name: "object-and-address",
            funded: vec![(vault, sui(), 40), (a, sui(), 1_000)],
            txs: vec![w(a, vec![(sui(), 600)], Some(1), 0), ov(30, 2, 0), ov(30, 3, 0), w(a, vec![(sui(), 400)], Some(4), 0)],
        },
    ]
}

pub fn cmd_funds_sched(corpus: &Path, out: &Path) -> Result<()> {
    let env = load_exec_env(corpus)?;
    let epoch = (env.epochs.len() - 1) as u64;
    let (pv, rgp, start_ms, _) = env.epochs[epoch as usize];
    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(pv), Chain::Mainnet);
    let ex = sui_execution::executor(&cfg, true)?;
    let registry = prometheus::Registry::new();
    let metrics = Arc::new(sui_types::metrics::ExecutionMetrics::new(&registry));
    let uow_metrics = Arc::new(sui_core::accumulators::object_funds_checker::metrics::ObjectFundsCheckerMetrics::new(&registry));
    let sched_metrics = Arc::new(crate::execution_scheduler::funds_withdraw_scheduler::AddressFundsSchedulerMetrics::new(&registry));
    // built before the runtime is entered (the package loader blocks on its own)
    let vault_pkg_obj = vault_package(&env, &cfg, epoch)?;
    let rt = tokio::runtime::Runtime::new()?;
    // FundsWithdrawScheduler::new spawns its withdraw and settlement tasks
    let _rt_guard = rt.enter();
    let base_v: u64 = 100;
    let mut f = std::fs::File::create(out)?;
    for sc in scenarios() {
        let groups = sc.txs.iter().map(|t| t.group).max().unwrap_or(0) + 1;
        // store: gas coins, the root at each group's version, the funded accounts at base_v - 10
        let mut objects: Vec<Object> = Vec::new();
        let mut latest: HashMap<ObjectID, Object> = HashMap::new();
        let mut balances: HashMap<AccumulatorObjId, (u128, SequenceNumber)> = HashMap::new();
        for (owner, coin, amount) in &sc.funded {
            let o = account(*owner, coin.clone(), *amount, base_v - 10);
            balances.insert(account_id(*owner, coin.clone()), (*amount as u128, SequenceNumber::from_u64(base_v - 10)));
            latest.insert(o.id(), o.clone());
            objects.push(o);
        }
        objects.push(root(base_v)?);
        // the vault package and object (object withdrawals)
        let mut fixed: HashMap<ObjectID, Object> = HashMap::new();
        let mut cur_vault: Option<Object> = None;
        if sc.txs.iter().any(|t| t.vault.is_some()) {
            let p = vault_pkg_obj.clone();
            fixed.insert(p.id(), p.clone());
            objects.push(p);
            let v = vault_object(addr(0xa1))?;
            objects.push(v.clone());
            cur_vault = Some(v);
        }
        let unsettled = sui_core::accumulators::unsettled_object_withdrawals::UnsettledObjectWithdrawals::new(uow_metrics.clone());
        let funds = Arc::new(Funds(Mutex::new(balances)));
        let scheduler = FundsWithdrawScheduler::new(funds.clone(), SequenceNumber::from_u64(base_v), FundsWithdrawSchedulerType::Eager, sched_metrics.clone());
        let mut lines = Vec::new();
        for g in 0..groups {
            let v = base_v + g as u64;
            // the root at the group's version, as the store holds it once the previous settlement
            // ran (`object_available_balance` loads it as an implicitly read system object)
            latest.insert(sui_types::SUI_ACCUMULATOR_ROOT_OBJECT_ID, root(v)?);
            let txs: Vec<(usize, &Tx, TransactionData)> = sc.txs.iter().enumerate().filter(|(_, t)| t.group == g).map(|(i, t)| (i, t, build(t, epoch, rgp, i as u32, None))).collect();
            // collect_withdraw_reservations + schedule_withdraws (one call per accumulator version)
            let withdraws: Vec<TxFundsWithdraw> = txs
                .iter()
                .filter(|(_, t, d)| t.vault.is_none() && d.has_funds_withdrawals())
                .map(|(_, _, d)| TxFundsWithdraw { tx_digest: d.digest(), reservations: d.process_funds_withdrawals_for_execution(sui_types::digests::get_mainnet_chain_identifier()) })
                .collect();
            let mut status: HashMap<TransactionDigest, ScheduleStatus> = HashMap::new();
            if !withdraws.is_empty() {
                let receivers = scheduler.schedule_withdraws(WithdrawReservations { accumulator_version: SequenceNumber::from_u64(v), withdraws });
                let got: Vec<_> = rt.block_on(async {
                    use futures::StreamExt;
                    receivers.collect::<Vec<_>>().await
                });
                for r in got {
                    let (d, s) = r?;
                    status.insert(d, s);
                }
            }
            let mut changes: BTreeMap<AccumulatorObjId, i128> = BTreeMap::new();
            for (i, t, data) in &txs {
                // a vault transaction takes the vault as the previous one left it
                let data = &if t.vault.is_some() { build(t, epoch, rgp, *i as u32, cur_vault.as_ref()) } else { data.clone() };
                let st = status.get(&data.digest()).copied().unwrap_or(ScheduleStatus::SufficientFunds);
                let mut inputs: HashMap<ObjectID, Object> = fixed.clone();
                if t.vault.is_some() {
                    let v = cur_vault.clone().context("vault")?;
                    inputs.insert(v.id(), v);
                }
                if let Some(n) = t.gas {
                    let g = gas_coin(n, t.sponsor.unwrap_or(t.sender));
                    inputs.insert(g.id(), g.clone());
                    objects.push(g);
                }
                let run = run_one(&env, &cfg, &ex, &metrics, epoch, start_ms, data, &inputs, &latest, v, st == ScheduleStatus::InsufficientFunds, &unsettled)?;
                // AuthorityState::execute_certificate after a successful execution
                if run.0.status().is_ok() {
                    unsettled.record_object_funds_withdraws(data, &run.0, &run.2.accumulator_running_max_withdraws, SequenceNumber::from_u64(v), sui_types::digests::get_mainnet_chain_identifier());
                }
                if let Some(nv) = run.2.written.get(&vault_id()) {
                    cur_vault = Some(nv.clone());
                }
                // the settlement's funds changes: the effects' accumulator events
                for ev in run.0.accumulator_events() {
                    let amt = match ev.write.value {
                        sui_types::effects::AccumulatorValue::Integer(x) => x as i128,
                        _ => continue,
                    };
                    let signed = match ev.write.operation {
                        sui_types::effects::AccumulatorOperation::Merge => amt,
                        sui_types::effects::AccumulatorOperation::Split => -amt,
                    };
                    *changes.entry(ev.accumulator_obj).or_default() += signed;
                }
                lines.push(serde_json::json!({
                    "tx": hex::encode(bcs::to_bytes(data)?),
                    "acc": v,
                    "status": format!("{st:?}"),
                    "effects": hex::encode(bcs::to_bytes(&run.0)?),
                    "events": run.1.map(hex::encode),
                }));
            }
            if g + 1 < groups {
                // the settlement: account fields and the root move to v + 1
                let next = v + 1;
                {
                    let mut b = funds.0.lock().unwrap();
                    for (id, ch) in &changes {
                        let e = b.entry(*id).or_insert((0, SequenceNumber::MIN));
                        e.0 = (e.0 as i128 + ch) as u128;
                        e.1 = SequenceNumber::from_u64(next);
                    }
                }
                for (owner, coin, _) in &sc.funded {
                    let id = account_id(*owner, coin.clone());
                    if let Some(ch) = changes.get(&id) {
                        let _ = ch;
                        let amount = funds.0.lock().unwrap().get(&id).context("funded account")?.0 as u64;
                        let o = account(*owner, coin.clone(), amount, next);
                        latest.insert(o.id(), o.clone());
                        objects.push(o);
                    }
                }
                objects.push(root(next)?);
                scheduler.settle_funds(FundsSettlement { next_accumulator_version: SequenceNumber::from_u64(next), funds_changes: changes });
            }
        }
        let line = serde_json::json!({
            "name": sc.name, "pv": pv, "epoch": epoch, "rgp": rgp, "start_ms": start_ms,
            "objects": objects.iter().map(|o| bcs::to_bytes(o).map(hex::encode)).collect::<Result<Vec<_>, _>>()?,
            "txs": lines,
        });
        writeln!(f, "{line}")?;
        eprintln!("funds-sched: {} ({} txs)", sc.name, sc.txs.len());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_one(
    env: &crate::ExecEnv,
    cfg: &ProtocolConfig,
    ex: &Arc<dyn sui_execution::Executor + Send + Sync>,
    metrics: &Arc<sui_types::metrics::ExecutionMetrics>,
    epoch: u64,
    start_ms: u64,
    data: &TransactionData,
    inputs: &HashMap<ObjectID, Object>,
    latest: &HashMap<ObjectID, Object>,
    acc_version: u64,
    insufficient: bool,
    unsettled: &dyn sui_types::accumulator_root::UnsettledObjectFundsRead,
) -> Result<(sui_types::effects::TransactionEffects, Option<Vec<u8>>, sui_types::inner_temporary_store::InnerTemporaryStore)> {
    let ep = env.epochs[epoch as usize];
    let store = ExecStore { inputs, packages: &env.packages, system: &env.system, epoch, latest: Some(latest), reads: None };
    let mut reads = Vec::new();
    for k in data.input_objects()? {
        if matches!(k, InputObjectKind::MovePackage(_)) {
            if let Some(p) = store.package(&k.object_id()) {
                reads.push(ObjectReadResult::new(k, ObjectReadResultKind::Object(p)));
            }
            continue;
        }
        let o = inputs.get(&k.object_id()).context("input object")?;
        reads.push(ObjectReadResult::new(k, ObjectReadResultKind::Object(o.clone())));
    }
    let gas_status = if data.is_gasless_transaction() {
        sui_types::gas::SuiGasStatus::new(cfg.gasless_max_computation_units() * ep.1, ep.1, ep.1, cfg)?
    } else {
        sui_types::gas::SuiGasStatus::new(data.gas_data().budget, data.gas_data().price, ep.1, cfg)?
    };
    let acc = Some(SequenceNumber::from_u64(acc_version));
    let params = if insufficient {
        sui_types::execution_params::ExecutionOrEarlyError::failed(nonempty::nonempty![ExecutionErrorKind::InsufficientFundsForWithdraw], acc)
    } else {
        sui_types::execution_params::ExecutionOrEarlyError::ok(acc)
    };
    let (inner, _, fx, _, res) = ex.execute_transaction_to_effects(
        &store,
        cfg,
        metrics.clone(),
        false,
        params,
        &epoch,
        start_ms,
        sui_types::transaction::CheckedInputObjects::new_for_replay(sui_types::transaction::InputObjects::new(reads)),
        sui_types::base_types::SystemObjectVersions::new(acc.map(|version| sui_types::base_types::ConsensusObjectVersion { initial_shared_version: SequenceNumber::from_u64(3), version }), None),
        unsettled,
        data.gas_data().clone(),
        gas_status,
        data.kind().clone(),
        None,
        data.sender(),
        data.digest(),
        &mut None,
    );
    if let Err(e) = &res {
        eprintln!("funds-sched: {} failed: {e:?}", data.digest());
    }
    let events = if inner.events.data.is_empty() { None } else { Some(bcs::to_bytes(&inner.events)?) };
    Ok((fx, events, inner))
}
