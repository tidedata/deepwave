//! settle-vectors: accumulator settlement truth for deepwave's validator settlement builder
//! (src/validator/run/ckpt_env.zig `buildSettlements`, `barrierTx`) and its execution.
//!
//! Each case is a list of synthetic root-transaction effects whose changed objects carry
//! `AccumulatorWriteV1` outputs (authenticated event streams: `EventDigest`; balances:
//! `Integer`; one `IntegerTuple` case). Mysten's own code builds the settlement transactions:
//! `sui_core::mock_checkpoint_builder::MockCheckpointBuilder::get_settlement_txns` (the
//! crate-private `AccumulatorSettlementTxBuilder::new(None, effects, seq, 0)` + `build_tx(cfg,
//! epoch, 1, height, seq)` with height = seq = previous checkpoint + 1), then Mysten's executor
//! runs each settlement over a store holding the accumulator root (version `root_version`) and
//! the case's existing children, and the barrier (`get_barrier_tx` over the settlement effects)
//! runs last. A case may start from the objects a previous case wrote (`chained`: existing
//! event stream heads, whose MMR the new roots extend).
//!
//! One JSON line per case: name, pv, epoch, seq, height, root_effects (BCS hex), objects (BCS
//! hex, the store before the settlement), settlements [{data, digest, effects}], barrier {data,
//! digest, effects}; or `panic` with Rust's panic message when the builder panics.
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
use sui_core::mock_checkpoint_builder::MockCheckpointBuilder;
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use sui_types::accumulator_root::{AccumulatorValue as RootValue, EventStreamHead, derive_event_stream_head_object_id};
use sui_types::base_types::{ObjectID, ObjectRef, SequenceNumber, SuiAddress, TransactionDigest, VersionNumber};
use sui_types::committee::{Committee, EpochId};
use sui_types::crypto::AuthorityKeyPair;
use sui_types::digests::Digest;
use sui_types::effects::{
    AccumulatorAddress, AccumulatorOperation, AccumulatorValue, AccumulatorWriteV1, EffectsObjectChange, TransactionEffects,
    TransactionEffectsAPI,
};
use sui_types::error::SuiResult;
use sui_types::execution_status::ExecutionStatus;
use sui_types::gas::GasCostSummary;
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointSummary, VerifiedCheckpoint};
use sui_types::object::{MoveObject, Object, Owner};
use sui_types::storage::ObjectStore;
use sui_types::transaction::{InputObjectKind, ObjectReadResult, ObjectReadResultKind, Transaction, TransactionDataAPI};
use sui_types::{MoveTypeTagTrait, SUI_ACCUMULATOR_ROOT_OBJECT_ID, SUI_FRAMEWORK_ADDRESS, TypeTag};

/// Protocol version: 141, or `ZUI_SETTLE_PV` (142 when built against the 1.84 tree).
fn pv() -> u64 {
    std::env::var("ZUI_SETTLE_PV").ok().and_then(|v| v.parse().ok()).unwrap_or(141)
}
const EPOCH: u64 = 7;
const EPOCH_START_MS: u64 = 1_700_000_000_000;

struct Keys {
    committee: Committee,
    keys: Vec<AuthorityKeyPair>,
}

fn prev_checkpoint(keys: &Keys, seq: u64) -> VerifiedCheckpoint {
    let summary = CheckpointSummary {
        epoch: EPOCH,
        sequence_number: seq,
        network_total_transactions: 1000,
        content_digest: sui_types::digests::CheckpointContentsDigest::new([0; 32]),
        previous_digest: None,
        epoch_rolling_gas_cost_summary: GasCostSummary::default(),
        timestamp_ms: EPOCH_START_MS,
        checkpoint_commitments: vec![],
        end_of_epoch_data: None,
        version_specific_data: vec![],
    };
    let cert = CertifiedCheckpointSummary::new_from_keypairs_for_testing(summary, &keys.keys, &keys.committee);
    VerifiedCheckpoint::new_unchecked(cert)
}

/// Deterministic 32 bytes for test value `n`.
fn bytes32(tag: u8, n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut x = (n.wrapping_add(1)).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (tag as u64) << 56;
    for b in out.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
    out
}

fn addr(tag: u8, n: u64) -> SuiAddress {
    SuiAddress::from_bytes(bytes32(tag, n)).unwrap()
}

fn struct_tag(a: SuiAddress, module: &str, name: &str, params: Vec<TypeTag>) -> TypeTag {
    TypeTag::Struct(Box::new(move_core_types::language_storage::StructTag {
        address: a.into(),
        module: move_core_types::identifier::Identifier::new(module).unwrap(),
        name: move_core_types::identifier::Identifier::new(name).unwrap(),
        type_params: params,
    }))
}

fn balance_of(coin: TypeTag) -> TypeTag {
    struct_tag(SUI_FRAMEWORK_ADDRESS.into(), "balance", "Balance", vec![coin])
}

fn sui_coin() -> TypeTag {
    struct_tag(SUI_FRAMEWORK_ADDRESS.into(), "sui", "SUI", vec![])
}

/// A second balance type whose package is in the store (settle_u128's type argument package is
/// a transaction input): `0x2::bag::Bag`; nothing checks that `T` is a coin.
fn foo_coin() -> TypeTag {
    struct_tag(SUI_FRAMEWORK_ADDRESS.into(), "bag", "Bag", vec![])
}

/// One accumulator write of a root transaction.
enum W {
    /// stream, [(event index in the transaction, digest seed)]
    Events(SuiAddress, Vec<(u64, u64)>),
    /// owner, coin type, merge?, amount
    Bal(SuiAddress, TypeTag, bool, u64),
    /// owner, coin type, value
    Tuple(SuiAddress, TypeTag, u64, u64),
}

fn write_of(w: &W) -> (ObjectID, AccumulatorWriteV1) {
    match w {
        W::Events(stream, evs) => {
            let id = derive_event_stream_head_object_id(*stream).unwrap();
            let digests: Vec<(u64, Digest)> = evs.iter().map(|(i, s)| (*i, Digest::new(bytes32(1, *s)))).collect();
            let value = AccumulatorValue::EventDigest(nonempty::NonEmpty::from_vec(digests).unwrap());
            (id, AccumulatorWriteV1 { address: AccumulatorAddress::new(*stream, EventStreamHead::get_type_tag()), operation: AccumulatorOperation::Merge, value })
        }
        W::Bal(owner, coin, merge, amount) => {
            let ty = balance_of(coin.clone());
            let id = *RootValue::get_field_id(*owner, &ty).unwrap().inner();
            let op = if *merge { AccumulatorOperation::Merge } else { AccumulatorOperation::Split };
            (id, AccumulatorWriteV1 { address: AccumulatorAddress::new(*owner, ty), operation: op, value: AccumulatorValue::Integer(*amount) })
        }
        W::Tuple(owner, coin, a, b) => {
            let ty = balance_of(coin.clone());
            let id = *RootValue::get_field_id(*owner, &ty).unwrap().inner();
            (id, AccumulatorWriteV1 { address: AccumulatorAddress::new(*owner, ty), operation: AccumulatorOperation::Merge, value: AccumulatorValue::IntegerTuple(*a, *b) })
        }
    }
}

fn root_effects(i: u64, writes: &[W]) -> TransactionEffects {
    let mut changed = BTreeMap::new();
    for w in writes {
        let (id, write) = write_of(w);
        if changed.insert(id, EffectsObjectChange::new_from_accumulator_write(write)).is_some() {
            panic!("one write per accumulator object and transaction");
        }
    }
    TransactionEffects::new_from_execution_v2(
        ExecutionStatus::Success,
        EPOCH,
        GasCostSummary::default(),
        vec![],
        TransactionDigest::new(bytes32(2, i)),
        SequenceNumber::from_u64(100 + i),
        changed,
        None,
        None,
        vec![],
    )
}

/// The accumulator root object `0x2::accumulator::AccumulatorRoot` at `version`, shared since 1.
fn root_object(cfg: &ProtocolConfig, version: u64) -> Object {
    let ty = sui_types::base_types::MoveObjectType::from(move_core_types::language_storage::StructTag {
        address: SUI_FRAMEWORK_ADDRESS,
        module: sui_types::accumulator_root::ACCUMULATOR_ROOT_MODULE.to_owned(),
        name: sui_types::accumulator_root::ACCUMULATOR_ROOT_STRUCT.to_owned(),
        type_params: vec![],
    });
    let mo = unsafe { MoveObject::new_from_execution(ty, false, SequenceNumber::from_u64(version), SUI_ACCUMULATOR_ROOT_OBJECT_ID.to_vec(), cfg, true).unwrap() };
    Object::new_move(mo, Owner::Shared { initial_shared_version: SequenceNumber::from_u64(1) }, TransactionDigest::genesis_marker())
}

struct Store {
    objects: HashMap<ObjectID, Object>,
    packages: HashMap<ObjectID, Object>,
}

impl sui_types::storage::BackingPackageStore for Store {
    fn get_package_object(&self, id: &ObjectID) -> SuiResult<Option<sui_types::storage::PackageObject>> {
        Ok(self.packages.get(id).cloned().map(sui_types::storage::PackageObject::new))
    }
}

impl sui_types::storage::RuntimeObjectResolver for Store {
    fn read_child_object(&self, _parent: &ObjectID, child: &ObjectID, bound: SequenceNumber) -> SuiResult<Option<Object>> {
        Ok(self.objects.get(child).filter(|o| o.version() <= bound).cloned())
    }
    fn get_object_received_at_version(&self, _o: &ObjectID, _r: &ObjectID, _v: SequenceNumber, _e: EpochId) -> SuiResult<Option<Object>> {
        Ok(None)
    }
}

impl sui_types::storage::ParentSync for Store {
    fn get_latest_parent_entry_ref_deprecated(&self, _id: ObjectID) -> Option<ObjectRef> {
        None
    }
}

impl ObjectStore for Store {
    fn get_object(&self, id: &ObjectID) -> Option<Object> {
        self.objects.get(id).cloned().or_else(|| self.packages.get(id).cloned())
    }
    fn get_object_by_key(&self, id: &ObjectID, version: VersionNumber) -> Option<Object> {
        self.get_object(id).filter(|o| o.version() == version)
    }
}

struct Ctx {
    cfg: ProtocolConfig,
    ex: Arc<dyn sui_execution::Executor + Send + Sync>,
    metrics: Arc<sui_types::metrics::ExecutionMetrics>,
    packages: HashMap<ObjectID, Object>,
    keys: Keys,
}

fn run(ctx: &Ctx, objects: &HashMap<ObjectID, Object>, tx: &Transaction) -> Result<(TransactionEffects, BTreeMap<ObjectID, Object>)> {
    let (fx, written, res) = run_any(ctx, objects, tx)?;
    if let Err(e) = res {
        bail!("settlement execution failed: {e:?}");
    }
    Ok((fx, written))
}

fn run_any(ctx: &Ctx, objects: &HashMap<ObjectID, Object>, tx: &Transaction) -> Result<(TransactionEffects, BTreeMap<ObjectID, Object>, Result<(), String>)> {
    let data = tx.data().transaction_data().clone();
    let store = Store { objects: objects.clone(), packages: ctx.packages.clone() };
    let mut reads = vec![];
    for k in data.input_objects()? {
        let o = match k {
            InputObjectKind::SharedMoveObject { id, .. } => objects.get(&id).cloned().context("shared input")?,
            InputObjectKind::MovePackage(id) => ctx.packages.get(&id).cloned().context("package input")?,
            _ => bail!("unexpected input {k:?}"),
        };
        reads.push(ObjectReadResult::new(k, ObjectReadResultKind::Object(o)));
    }
    let (inner, _, fx, _, res) = ctx.ex.execute_transaction_to_effects(
        &store,
        &ctx.cfg,
        ctx.metrics.clone(),
        false,
        sui_types::execution_params::ExecutionOrEarlyError::ok(None),
        &EPOCH,
        EPOCH_START_MS,
        sui_types::transaction::CheckedInputObjects::new_for_replay(sui_types::transaction::InputObjects::new(reads)),
        sui_types::base_types::SystemObjectVersions::empty(),
        &sui_types::accumulator_root::EmptyUnsettledObjectFunds,
        data.gas_data().clone(),
        sui_types::gas::SuiGasStatus::new_unmetered(&ctx.cfg),
        data.kind().clone(),
        None,
        data.sender(),
        *tx.digest(),
        &mut None,
    );
    Ok((fx, inner.written, res.map_err(|e| format!("{e:?}"))))
}

fn hexb<T: serde::Serialize>(v: &T) -> String {
    hex::encode(bcs::to_bytes(v).unwrap())
}

fn tx_json(tx: &Transaction, fx: &TransactionEffects) -> serde_json::Value {
    serde_json::json!({
        "data": hexb(tx.data().transaction_data()),
        "digest": hex::encode(tx.digest().inner()),
        "effects": hexb(fx),
    })
}

/// Builds and executes one case; returns its JSON and the store after the barrier.
fn case(ctx: &Ctx, name: &str, prev_seq: u64, objects: HashMap<ObjectID, Object>, txs: &[Vec<W>]) -> Result<(serde_json::Value, HashMap<ObjectID, Object>)> {
    let mut b = MockCheckpointBuilder::new(prev_checkpoint(&ctx.keys, prev_seq));
    let effects: Vec<TransactionEffects> = txs.iter().enumerate().map(|(i, w)| root_effects(prev_seq * 1000 + i as u64, w)).collect();
    let dummy = sui_types::transaction::VerifiedTransaction::new_system_transaction(sui_types::transaction::TransactionKind::ProgrammableSystemTransaction(
        sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder::new().finish(),
    ));
    for fx in &effects {
        b.push_transaction(dummy.clone(), fx.clone());
    }
    let mut objs: Vec<&Object> = objects.values().collect();
    objs.sort_by_key(|o| o.id());
    let mut out = serde_json::json!({
        "name": name,
        "pv": pv(),
        "epoch": EPOCH,
        "seq": prev_seq + 1,
        "height": prev_seq + 1,
        "tx_index_offset": 0,
        "root_effects": effects.iter().map(hexb).collect::<Vec<_>>(),
        "objects": objs.iter().map(|o| hexb(*o)).collect::<Vec<_>>(),
    });
    let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| b.get_settlement_txns(&ctx.cfg)));
    let (txns, height) = match built {
        Ok(x) => x,
        Err(p) => {
            let msg = p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
            out["panic"] = serde_json::Value::String(msg);
            return Ok((out, objects));
        }
    };
    let mut after = objects.clone();
    let mut settlements = vec![];
    let mut sfx = vec![];
    for tx in &txns {
        let (fx, written) = run(ctx, &objects, tx)?;
        settlements.push(tx_json(tx, &fx));
        for (id, o) in written {
            if id != SUI_ACCUMULATOR_ROOT_OBJECT_ID {
                after.insert(id, o);
            }
        }
        sfx.push(fx);
    }
    // the barrier reads the root at the settlements' version and the children they wrote
    let barrier = b.get_barrier_tx(height, &sfx);
    let mut bstore = after.clone();
    bstore.insert(SUI_ACCUMULATOR_ROOT_OBJECT_ID, objects[&SUI_ACCUMULATOR_ROOT_OBJECT_ID].clone());
    let (bfx, written) = run(ctx, &bstore, &barrier)?;
    for (id, o) in written {
        after.insert(id, o);
    }
    for fx in sfx.iter().chain(std::iter::once(&bfx)) {
        if !fx.status().is_ok() {
            bail!("{name}: settlement status {:?}", fx.status());
        }
    }
    out["settlements"] = serde_json::Value::Array(settlements);
    out["barrier"] = tx_json(&barrier, &bfx);
    // deleted children leave the store
    for ((id, _, _), _) in bfx.all_removed_objects() {
        after.remove(&id);
    }
    for fx in &sfx {
        for ((id, _, _), _) in fx.all_removed_objects() {
            after.remove(&id);
        }
    }
    Ok((out, after))
}

fn new_ctx() -> Result<Ctx> {
    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(pv()), Chain::Mainnet);
    let registry = prometheus::Registry::new();
    let (committee, keys) = Committee::new_simple_test_committee_of_size(1);
    Ok(Ctx {
        ex: sui_execution::executor(&cfg, true)?,
        cfg,
        metrics: Arc::new(sui_types::metrics::ExecutionMetrics::new(&registry)),
        packages: sui_framework::BuiltInFramework::genesis_objects().map(|o| (o.id(), o)).collect(),
        keys: Keys { committee, keys },
    })
}

fn move_object(cfg: &ProtocolConfig, tag: move_core_types::language_storage::StructTag, version: u64, contents: Vec<u8>, owner: Owner) -> Object {
    let mo = unsafe { MoveObject::new_from_execution(sui_types::base_types::MoveObjectType::from(tag), false, SequenceNumber::from_u64(version), contents, cfg, true).unwrap() };
    Object::new_move(mo, owner, TransactionDigest::genesis_marker())
}

fn tag_of(t: TypeTag) -> move_core_types::language_storage::StructTag {
    match t {
        TypeTag::Struct(s) => *s,
        _ => unreachable!(),
    }
}

/// G9: a system Move call that fails with a VM error other than ABORTED. A
/// RandomnessStateUpdate over a `Random` whose inner `randomness_round` is u64::MAX:
/// `new_round == inner.randomness_round + 1` overflows (ARITHMETIC_ERROR), which
/// `setup_randomness_state_update` returns as an execution error and the engine turns into a
/// `MovePrimitiveRuntimeError` failure (convert_vm_error), not a panic.
pub fn cmd_system_fail_vectors(out: &Path) -> Result<()> {
    let ctx = new_ctx()?;
    let fw = SUI_FRAMEWORK_ADDRESS;
    let random_id = ObjectID::from_single_byte(8);
    let versioned_id = ObjectID::from_bytes(bytes32(6, 0))?;
    let isv = 3u64;
    let mut random_c = random_id.to_vec();
    random_c.extend(versioned_id.to_vec());
    random_c.extend(1u64.to_le_bytes());
    let random = move_object(&ctx.cfg, tag_of(struct_tag(fw.into(), "random", "Random", vec![])), 20, random_c, Owner::Shared { initial_shared_version: SequenceNumber::from_u64(isv) });
    let field_id = sui_types::dynamic_field::derive_dynamic_field_id(versioned_id, &TypeTag::U64, &bcs::to_bytes(&1u64)?)?;
    let mut field_c = field_id.to_vec();
    field_c.extend(bcs::to_bytes(&1u64)?);
    field_c.extend(bcs::to_bytes(&(1u64, EPOCH, u64::MAX, vec![7u8; 32]))?);
    let inner_ty = struct_tag(fw.into(), "random", "RandomInner", vec![]);
    let field = move_object(&ctx.cfg, tag_of(struct_tag(fw.into(), "dynamic_field", "Field", vec![TypeTag::U64, inner_ty])), 19, field_c, Owner::ObjectOwner(versioned_id.into()));
    let objects: HashMap<ObjectID, Object> = [(random_id, random), (field_id, field)].into_iter().collect();
    let mut lines = vec![];
    for (name, round) in [("randomness-round-overflow", 5u64), ("randomness-round-overflow-zero", 0u64)] {
        let kind = sui_types::transaction::TransactionKind::RandomnessStateUpdate(sui_types::transaction::RandomnessStateUpdate {
            epoch: EPOCH,
            randomness_round: sui_types::crypto::RandomnessRound(round),
            random_bytes: vec![9u8; 32],
            randomness_obj_initial_shared_version: SequenceNumber::from_u64(isv),
        });
        let tx = sui_types::transaction::VerifiedTransaction::new_system_transaction(kind).into_inner();
        let (fx, _, res) = run_any(&ctx, &objects, &tx)?;
        let mut objs: Vec<&Object> = objects.values().collect();
        objs.sort_by_key(|o| o.id());
        eprintln!("{name}: {:?} / {:?}", fx.status(), res.as_ref().err());
        lines.push(serde_json::json!({
            "name": name,
            "pv": pv(),
            "epoch": EPOCH,
            "epoch_start_ms": EPOCH_START_MS,
            "objects": objs.iter().map(|o| hexb(*o)).collect::<Vec<_>>(),
            "data": hexb(tx.data().transaction_data()),
            "digest": hex::encode(tx.digest().inner()),
            "effects": hexb(&fx),
        }));
    }
    let mut text = String::new();
    for l in &lines {
        text.push_str(&serde_json::to_string(l)?);
        text.push('\n');
    }
    std::fs::write(out, text)?;
    Ok(())
}

pub fn cmd_settle_vectors(out: &Path) -> Result<()> {
    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(pv()), Chain::Mainnet);
    if !cfg.enable_authenticated_event_streams() {
        bail!("authenticated event streams off at {}", pv());
    }
    drop(cfg);
    let ctx = new_ctx()?;
    let s = |n: u64| addr(3, n);
    let a = addr(4, 1);
    let b = addr(4, 2);
    let c = addr(4, 3);
    let mut lines = vec![];

    let base: HashMap<ObjectID, Object> = [(SUI_ACCUMULATOR_ROOT_OBJECT_ID, root_object(&ctx.cfg, 5))].into_iter().collect();

    // one stream, one event: the merkle root is the leaf hash
    let (j, _) = case(&ctx, "single-event", 0, base.clone(), &[vec![W::Events(s(0), vec![(0, 1)])]])?;
    lines.push(j);

    // several streams, several events per stream and transaction, mixed with balances (SUI and a
    // user coin, a net-zero SUI owner whose address stays an input)
    let mixed = vec![
        vec![W::Events(s(1), vec![(0, 10), (2, 11)]), W::Bal(a, sui_coin(), true, 500), W::Bal(c, sui_coin(), true, 1000)],
        vec![W::Events(s(2), vec![(1, 12)]), W::Events(s(1), vec![(0, 13), (1, 14), (3, 15)]), W::Bal(a, sui_coin(), false, 200), W::Bal(b, foo_coin(), true, 7)],
        vec![W::Events(s(3), vec![(0, 16)]), W::Events(s(2), vec![(4, 17), (5, 18)]), W::Bal(a, sui_coin(), false, 300), W::Bal(b, foo_coin(), false, 3)],
    ];
    let (j, after) = case(&ctx, "mixed", 41, base.clone(), &mixed)?;
    lines.push(j);

    // the next checkpoint over the heads the previous one wrote: the new roots extend each MMR
    let chained = vec![
        vec![W::Events(s(1), vec![(0, 20), (1, 21), (2, 22)]), W::Events(s(4), vec![(0, 23)])],
        vec![W::Events(s(2), vec![(0, 24)]), W::Bal(c, sui_coin(), false, 400)],
        vec![W::Events(s(1), vec![(7, 25)]), W::Events(s(3), vec![(0, 26), (1, 27), (2, 28), (3, 29), (4, 30)])],
    ];
    let (j, after2) = case(&ctx, "chained", 42, after, &chained)?;
    lines.push(j);
    let (j, _) = case(&ctx, "chained-again", 43, after2, &[vec![W::Events(s(1), vec![(0, 40)])], vec![W::Events(s(1), vec![(0, 41), (1, 42)])]])?;
    lines.push(j);

    // more updates than max_updates_per_settlement_txn (100): two settlement transactions
    let mut big = vec![];
    for t in 0..3u64 {
        let mut ws = vec![];
        for k in 0..35u64 {
            let n = 100 + t * 35 + k;
            let evs: Vec<(u64, u64)> = (0..(1 + (n % 4))).map(|e| (e * 2, n * 10 + e)).collect();
            ws.push(W::Events(s(n), evs));
        }
        ws.push(W::Bal(addr(5, t), sui_coin(), true, 1 + t));
        big.push(ws);
    }
    let (j, _) = case(&ctx, "chunked", 99, base.clone(), &big)?;
    lines.push(j);

    // IntegerTuple (SumU128U128): no execution path produces it; the builder panics (todo!)
    let (j, _) = case(&ctx, "integer-tuple", 9, base.clone(), &[vec![W::Tuple(a, foo_coin(), 1, 2)]])?;
    lines.push(j);

    let mut text = String::new();
    for l in &lines {
        text.push_str(&serde_json::to_string(l)?);
        text.push('\n');
    }
    std::fs::write(out, text)?;
    eprintln!("settle-vectors: {} cases -> {}", lines.len(), out.display());
    Ok(())
}
