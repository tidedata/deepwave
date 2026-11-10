//! zui-truth-exec: ground truth for the exec lane, computed by Mysten's own code.
//!
//! state-hash: for every corpus checkpoint, `sui_core::global_state_hasher::accumulate_effects`
//! over the checkpoint's effects with the protocol config of its epoch, against a store that
//! holds exactly the checkpoint's own input and output objects (CheckpointData). The v1 path's
//! history lookup (`get_object_ref_prior_to_key_deprecated`, unwrapped objects before effects v2
//! and simplified_unwrap_then_delete) cannot be answered from one checkpoint: the store answers
//! `None` and the tool records each lookup key, so the truth is the checkpoint-local accumulator
//! plus the exact list of history lookups Rust made.
use anyhow::{Context, Result, bail};
use fastcrypto::hash::MultisetHash;
use rayon::prelude::*;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use sui_core::authority::authority_store_tables::LiveObject;
use sui_core::global_state_hasher::{GlobalStateHashStore, accumulate_effects};
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use sui_types::base_types::{ObjectID, ObjectRef, SequenceNumber, VersionNumber};
use sui_types::committee::EpochId;
use sui_types::effects::{TransactionEffects, TransactionEffectsAPI};
use sui_types::error::SuiResult;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::global_state_hash::GlobalStateHash;
use sui_types::messages_checkpoint::CheckpointSequenceNumber;
use sui_types::object::Object;
use sui_types::storage::ObjectStore;

mod synth;

struct CheckpointStore {
    objects: HashMap<(ObjectID, SequenceNumber), Object>,
    lookups: Mutex<Vec<(ObjectID, SequenceNumber)>>,
    missing: Mutex<Vec<(ObjectID, SequenceNumber)>>,
    /// History answers for `get_object_ref_prior_to_key_deprecated` (state-hash-history);
    /// a key absent here is answered `None`.
    history: HashMap<(ObjectID, SequenceNumber), ObjectRef>,
}

impl CheckpointStore {
    fn new(cp: &CheckpointData) -> Self {
        let mut objects = HashMap::new();
        for tx in &cp.transactions {
            for o in tx.input_objects.iter().chain(tx.output_objects.iter()) {
                objects.insert((o.id(), o.version()), o.clone());
            }
        }
        Self { objects, lookups: Mutex::new(Vec::new()), missing: Mutex::new(Vec::new()), history: HashMap::new() }
    }
}

impl ObjectStore for CheckpointStore {
    fn get_object(&self, _object_id: &ObjectID) -> Option<Object> {
        unreachable!("state hasher reads objects by key only")
    }
    fn get_object_by_key(&self, object_id: &ObjectID, version: VersionNumber) -> Option<Object> {
        let o = self.objects.get(&(*object_id, version)).cloned();
        if o.is_none() {
            self.missing.lock().unwrap().push((*object_id, version));
        }
        o
    }
}

impl GlobalStateHashStore for CheckpointStore {
    fn get_object_ref_prior_to_key_deprecated(
        &self,
        object_id: &ObjectID,
        version: VersionNumber,
    ) -> SuiResult<Option<ObjectRef>> {
        self.lookups.lock().unwrap().push((*object_id, version));
        Ok(self.history.get(&(*object_id, version)).copied())
    }
    fn get_root_state_hash_for_epoch(
        &self,
        _epoch: EpochId,
    ) -> SuiResult<Option<(CheckpointSequenceNumber, GlobalStateHash)>> {
        unreachable!()
    }
    fn insert_state_hash_for_epoch(
        &self,
        _epoch: EpochId,
        _checkpoint_seq_num: &CheckpointSequenceNumber,
        _acc: &GlobalStateHash,
    ) -> SuiResult {
        unreachable!()
    }
    fn iter_live_object_set(
        &self,
        _include_wrapped_tombstone: bool,
    ) -> Box<dyn Iterator<Item = LiveObject> + '_> {
        unreachable!()
    }
}

#[derive(serde::Deserialize)]
struct EpochLine {
    epoch: u64,
    pv: u64,
}

fn load_pv(corpus: &Path) -> Result<Vec<u64>> {
    let text = std::fs::read_to_string(corpus.join("epochs.jsonl"))?;
    let mut v = Vec::new();
    for l in text.lines().filter(|l| !l.is_empty()) {
        let e: EpochLine = serde_json::from_str(l)?;
        if e.epoch as usize != v.len() {
            bail!("epochs.jsonl not contiguous at {}", e.epoch);
        }
        v.push(e.pv);
    }
    Ok(v)
}

pub(crate) fn decode(path: &Path) -> Result<CheckpointData> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if raw.first() != Some(&1) {
        bail!("{}: bad blob tag", path.display());
    }
    bcs::from_bytes(&raw[1..]).with_context(|| format!("decode {}", path.display()))
}

fn path_name(cfg: &ProtocolConfig) -> &'static str {
    if cfg.enable_effects_v2() {
        "v3"
    } else if cfg.simplified_unwrap_then_delete() {
        "v2"
    } else {
        "v1"
    }
}

fn keys_json(v: &[(ObjectID, SequenceNumber)]) -> String {
    let items: Vec<String> = v
        .iter()
        .map(|(id, ver)| format!("\"{}:{}\"", hex::encode(id.as_ref()), ver.value()))
        .collect();
    format!("[{}]", items.join(","))
}

fn state_hash_line(seq: u64, cp: &CheckpointData, pvs: &[u64]) -> Result<String> {
    let epoch = cp.checkpoint_summary.epoch;
    let pv = *pvs.get(epoch as usize).with_context(|| format!("no protocol version for epoch {epoch}"))?;
    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(pv), Chain::Mainnet);
    let effects: Vec<TransactionEffects> = cp.transactions.iter().map(|t| t.effects.clone()).collect();
    let store = CheckpointStore::new(cp);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        accumulate_effects(&store, &effects, &cfg)
    }));
    let mut lookups = store.lookups.lock().unwrap().clone();
    lookups.sort();
    let mut missing = store.missing.lock().unwrap().clone();
    missing.sort();
    let (acc, digest) = match res {
        Ok(acc) => (
            format!("\"{}\"", hex::encode(bcs::to_bytes(&acc)?)),
            format!("\"{}\"", hex::encode(acc.digest().digest)),
        ),
        Err(_) => ("null".to_string(), "null".to_string()),
    };
    Ok(format!(
        "{{\"seq\":{seq},\"epoch\":{epoch},\"pv\":{pv},\"path\":\"{}\",\"txs\":{},\"acc\":{acc},\"digest\":{digest},\"lookups\":{},\"missing\":{}}}",
        path_name(&cfg),
        effects.len(),
        keys_json(&lookups),
        keys_json(&missing),
    ))
}

pub(crate) fn list_chk(corpus: &Path) -> Result<Vec<u64>> {
    let mut v: Vec<u64> = std::fs::read_dir(corpus.join("chk"))?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_suffix(".chk")).and_then(|n| n.parse().ok()))
        .collect();
    v.sort();
    Ok(v)
}

fn cmd_state_hash(corpus: &Path, out: &Path) -> Result<()> {
    std::panic::set_hook(Box::new(|_| {}));
    let pvs = load_pv(corpus)?;
    let seqs = list_chk(corpus)?;
    let t = Instant::now();
    let lines: Vec<Result<String>> = seqs
        .par_iter()
        .map(|seq| {
            let cp = decode(&corpus.join(format!("chk/{seq}.chk")))?;
            state_hash_line(*seq, &cp, &pvs)
        })
        .collect();
    let f = std::fs::File::create(out)?;
    let mut z = zstd::Encoder::new(f, 19)?;
    let (mut n, mut with_lookups, mut with_missing, mut panics) = (0u64, 0u64, 0u64, 0u64);
    for l in lines {
        let l = l?;
        if !l.contains("\"lookups\":[]") {
            with_lookups += 1;
        }
        if !l.contains("\"missing\":[]") {
            with_missing += 1;
        }
        if l.contains("\"acc\":null") {
            panics += 1;
        }
        z.write_all(l.as_bytes())?;
        z.write_all(b"\n")?;
        n += 1;
    }
    z.finish()?;
    eprintln!(
        "state-hash: {n} checkpoints, {with_lookups} with history lookups, {with_missing} with missing objects, {panics} panicked, {:.1} s",
        t.elapsed().as_secs_f64()
    );
    Ok(())
}

/// `bench state-hash --iters N --list <file>`: accumulate_effects per checkpoint on decoded
/// effects with a prebuilt store (decode and store building untimed), one thread, median pass.
fn cmd_bench(args: &[String]) -> Result<()> {
    let name = args.first().context("bench name")?.clone();
    let mut iters = 5usize;
    let mut list: Option<PathBuf> = None;
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
            _ => bail!("unknown bench arg {}", args[i]),
        }
    }
    let list = list.context("--list")?;
    let files: Vec<PathBuf> = std::fs::read_to_string(&list)?
        .lines()
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .collect();
    match name.as_str() {
        "state-hash" => {
            // the corpus root is two levels above chk/<seq>.chk
            let corpus = files.first().context("empty list")?.parent().and_then(|p| p.parent()).context("corpus root")?;
            let pvs = load_pv(corpus)?;
            let mut work = Vec::new();
            let mut units = 0u64;
            for f in &files {
                let cp = decode(f)?;
                let pv = pvs[cp.checkpoint_summary.epoch as usize];
                let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(pv), Chain::Mainnet);
                let effects: Vec<TransactionEffects> = cp.transactions.iter().map(|t| t.effects.clone()).collect();
                let store = CheckpointStore::new(&cp);
                units += effects.len() as u64;
                work.push((cfg, effects, store));
            }
            let pass = |work: &Vec<(ProtocolConfig, Vec<TransactionEffects>, CheckpointStore)>| {
                let mut sink = 0u8;
                for (cfg, effects, store) in work {
                    let acc = accumulate_effects(store, effects, cfg);
                    sink ^= acc.digest().digest[0];
                }
                std::hint::black_box(sink);
            };
            pass(&work);
            let mut times = Vec::new();
            for _ in 0..iters {
                let t = Instant::now();
                pass(&work);
                times.push(t.elapsed().as_nanos() as u64);
            }
            times.sort();
            let med = times[times.len() / 2];
            println!(
                "{{\"impl\":\"rust\",\"bench\":\"{name}\",\"unit\":\"tx\",\"units\":{units},\"iters\":{iters},\"median_ns\":{med},\"min_ns\":{},\"ns_per_unit\":{:.2}}}",
                times[0],
                med as f64 / units.max(1) as f64
            );
        }
        "exec" => bench_exec(&files, iters, false)?,
        "exec-move" => bench_exec(&files, iters, true)?,
        _ => bail!("unknown bench {name}"),
    }
    Ok(())
}

/// Package and object store for executing corpus transactions with `sui_execution`: the
/// transaction's input objects, the corpus `packages/` part and the system packages its epoch
/// sees (genesis and end-of-epoch writes, as deepwave's packages.zig).
pub(crate) struct ExecStore<'a> {
    pub inputs: &'a HashMap<ObjectID, Object>,
    pub packages: &'a HashMap<ObjectID, Object>,
    pub system: &'a HashMap<ObjectID, Vec<(u64, Object)>>,
    pub epoch: u64,
    /// Latest objects outside the inputs (`get_object`): the deny list v2 state (synth).
    pub latest: Option<&'a HashMap<ObjectID, Object>>,
}

impl ExecStore<'_> {
    fn package(&self, id: &ObjectID) -> Option<Object> {
        // synth at a newer protocol: the vector's own system packages (the newer framework) win
        if let Some(o) = self.inputs.get(id).filter(|o| o.is_package()) {
            return Some(o.clone());
        }
        if let Some(list) = self.system.get(id) {
            return list.iter().filter(|(e, _)| *e <= self.epoch).last().map(|(_, o)| o.clone());
        }
        // synth: packages a vector publishes first (upgrade vectors) travel with its inputs
        self.packages.get(id).cloned().or_else(|| self.inputs.get(id).filter(|o| o.is_package()).cloned())
    }
}

impl sui_types::storage::BackingPackageStore for ExecStore<'_> {
    fn get_package_object(&self, id: &ObjectID) -> SuiResult<Option<sui_types::storage::PackageObject>> {
        Ok(self.package(id).map(sui_types::storage::PackageObject::new))
    }
}

/// Debugging aid: log the store's misses (bench mismatch re-runs).
static LOG_MISSES: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn log_miss(what: &str, id: &ObjectID, v: Option<SequenceNumber>, have: Option<&Object>) {
    if LOG_MISSES.load(std::sync::atomic::Ordering::Relaxed) {
        eprintln!("  store miss {what} {id} bound {v:?} have {:?}", have.map(|o| o.version()));
    }
}

impl sui_types::storage::RuntimeObjectResolver for ExecStore<'_> {
    /// Children the checkpoint carries (the transaction modified them); read-only children are
    /// not in the checkpoint, so a transaction that reads one does not reproduce and is dropped.
    fn read_child_object(&self, _p: &ObjectID, c: &ObjectID, v: SequenceNumber) -> SuiResult<Option<Object>> {
        // synth: the store's latest objects (deny list config fields and settings) are children too
        let have = self.inputs.get(c).or_else(|| self.latest.and_then(|l| l.get(c)));
        let r = have.filter(|o| o.version() <= v).cloned();
        if r.is_none() {
            log_miss("child", c, Some(v), have);
        }
        Ok(r)
    }
    fn get_object_received_at_version(&self, _o: &ObjectID, _r: &ObjectID, _v: SequenceNumber, _e: EpochId) -> SuiResult<Option<Object>> {
        Ok(None)
    }
}

impl sui_types::storage::ParentSync for ExecStore<'_> {
    fn get_latest_parent_entry_ref_deprecated(&self, _id: ObjectID) -> Option<ObjectRef> {
        None
    }
}

impl ObjectStore for ExecStore<'_> {
    fn get_object(&self, id: &ObjectID) -> Option<Object> {
        let r = self.inputs.get(id).cloned().or_else(|| self.latest.and_then(|l| l.get(id).cloned())).or_else(|| self.package(id));
        if r.is_none() {
            log_miss("object", id, None, None);
        }
        r
    }
    fn get_object_by_key(&self, id: &ObjectID, version: VersionNumber) -> Option<Object> {
        self.get_object(id).filter(|o| o.version() == version)
    }
}

pub(crate) fn is_reservation(d: &sui_types::digests::ObjectDigest) -> bool {
    sui_types::coin_reservation::ParsedDigest::is_coin_reservation_digest(d)
}

/// Coin-only programmable transactions and consensus commit prologues (the classes deepwave's
/// exec executes) whose inputs the checkpoint carries, prepared for `sui_execution`; with
/// `move_calls`, programmable transactions with a MoveCall (no Publish/Upgrade, no funds
/// withdrawals) on execution version 4 instead, timed only where Rust reproduces the certified
/// effects from the checkpoint's objects alone.
struct ExecItem {
    pv: u64,
    epoch: u64,
    start_ms: u64,
    rgp: u64,
    data: sui_types::transaction::TransactionData,
    digest: sui_types::digests::TransactionDigest,
    reads: Vec<sui_types::transaction::ObjectReadResult>,
    inputs: HashMap<ObjectID, Object>,
    want: TransactionEffects,
}

/// Epochs (pv, rgp, start ms, last checkpoint), the corpus `packages/` part and the system
/// packages by the first epoch that sees them.
pub(crate) struct ExecEnv {
    pub epochs: Vec<(u64, u64, u64, Option<u64>)>,
    pub packages: HashMap<ObjectID, Object>,
    pub system: HashMap<ObjectID, Vec<(u64, Object)>>,
}

pub(crate) fn load_exec_env(corpus: &Path) -> Result<ExecEnv> {
    // epochs: pv, rgp, start, last checkpoint
    let mut epochs: Vec<(u64, u64, u64, Option<u64>)> = Vec::new();
    for line in std::fs::read_to_string(corpus.join("epochs.jsonl"))?.lines() {
        let v: serde_json::Value = serde_json::from_str(line)?;
        let e = v["epoch"].as_u64().context("epoch")? as usize;
        if epochs.len() <= e {
            epochs.resize(e + 1, (0, 0, 0, None));
        }
        epochs[e] = (v["pv"].as_u64().unwrap_or(0), v["rgp"].as_u64().unwrap_or(0), v["start_ms"].as_u64().unwrap_or(0), v["last"].as_u64());
    }
    let mut packages = HashMap::new();
    for ent in std::fs::read_dir(corpus.join("packages"))? {
        let p = ent?.path();
        if p.extension().and_then(|x| x.to_str()) != Some("obj") {
            continue;
        }
        let o: Object = bcs::from_bytes(&std::fs::read(&p)?)?;
        packages.insert(o.id(), o);
    }
    let mut writes: Vec<(u64, u64)> = vec![(0, 0)];
    for (e, ep) in epochs.iter().enumerate() {
        if let Some(last) = ep.3 {
            writes.push((last, e as u64 + 1));
        }
    }
    let sys: Vec<Vec<(u64, Object)>> = writes
        .par_iter()
        .map(|(seq, visible)| {
            let p = corpus.join(format!("chk/{seq}.chk"));
            let Ok(cp) = decode(&p) else { return vec![] };
            let mut out = vec![];
            for t in &cp.transactions {
                for o in &t.output_objects {
                    if o.is_package() && sui_types::is_system_package(o.id()) {
                        out.push((*visible, o.clone()));
                    }
                }
            }
            out
        })
        .collect();
    let mut system: HashMap<ObjectID, Vec<(u64, Object)>> = HashMap::new();
    for list in sys {
        for (e, o) in list {
            system.entry(o.id()).or_default().push((e, o));
        }
    }
    for v in system.values_mut() {
        v.sort_by_key(|(e, _)| *e);
    }

    Ok(ExecEnv { epochs, packages, system })
}

fn bench_exec(files: &[PathBuf], iters: usize, move_calls: bool) -> Result<()> {
    use sui_types::transaction::{CallArg, Command, InputObjectKind, ObjectReadResult, ObjectReadResultKind, TransactionDataAPI, TransactionKind};
    let corpus = files.first().context("empty list")?.parent().and_then(|p| p.parent()).context("corpus root")?;
    let ExecEnv { epochs, packages, system } = load_exec_env(corpus)?;
    // deepwave's `bench/exec-move.pack`: the transactions to run and the objects each reads beyond
    // the checkpoint's input objects (tx digest, u32 count, u32 length + BCS Object each).
    let mut pack: HashMap<sui_types::digests::TransactionDigest, Vec<Object>> = HashMap::new();
    if move_calls {
        let raw = std::fs::read(corpus.join("bench/exec-move.pack")).context("bench/exec-move.pack (run the zui side first)")?;
        let mut at = 0usize;
        let u32_at = |at: &mut usize| -> usize {
            let v = u32::from_le_bytes(raw[*at..*at + 4].try_into().unwrap()) as usize;
            *at += 4;
            v
        };
        while at < raw.len() {
            let d = sui_types::digests::TransactionDigest::new(raw[at..at + 32].try_into().unwrap());
            at += 32;
            let n = u32_at(&mut at);
            let mut objs = Vec::with_capacity(n);
            for _ in 0..n {
                let len = u32_at(&mut at);
                objs.push(bcs::from_bytes::<Object>(&raw[at..at + len])?);
                at += len;
            }
            pack.insert(d, objs);
        }
    }
    let mut items = Vec::new();
    for f in files {
        let cp = decode(f)?;
        let epoch = cp.checkpoint_summary.epoch;
        let ep = epochs[epoch as usize];
        for t in &cp.transactions {
            let data = t.transaction.data().transaction_data().clone();
            let keep = match data.kind() {
                TransactionKind::ProgrammableTransaction(pt) if move_calls => {
                    let ev4 = ProtocolConfig::get_for_version(ProtocolVersion::new(ep.0), Chain::Mainnet).execution_version_as_option() == Some(4);
                    ev4 && pt.commands.iter().any(|c| matches!(c, Command::MoveCall(..)))
                        && !pt.commands.iter().any(|c| matches!(c, Command::Publish(..) | Command::Upgrade(..)))
                        && !pt.inputs.iter().any(|a| matches!(a, CallArg::FundsWithdrawal(..) | CallArg::Object(sui_types::transaction::ObjectArg::Receiving(..))))
                }
                _ if move_calls => false,
                TransactionKind::ProgrammableTransaction(pt) => pt.commands.iter().all(|c| matches!(c, Command::SplitCoins(..) | Command::MergeCoins(..) | Command::TransferObjects(..))),
                TransactionKind::ConsensusCommitPrologue(_)
                | TransactionKind::ConsensusCommitPrologueV2(_)
                | TransactionKind::ConsensusCommitPrologueV3(_)
                | TransactionKind::ConsensusCommitPrologueV4(_) => true,
                _ => false,
            };
            if !keep || data.gas_data().payment.iter().any(|r| is_reservation(&r.2)) {
                continue;
            }
            if !data.kind().is_system_tx() && data.gas_data().payment.is_empty() {
                continue;
            }
            let Ok(kinds) = data.input_objects() else { continue };
            let extra: &[Object] = if move_calls {
                match pack.get(t.transaction.digest()) {
                    Some(v) => v,
                    None => continue,
                }
            } else {
                &[]
            };
            let by_id: HashMap<ObjectID, &Object> = t.input_objects.iter().chain(extra.iter()).map(|o| (o.id(), o)).collect();
            let mut reads = Vec::new();
            let mut inputs = HashMap::new();
            let mut ok = true;
            for k in kinds {
                if matches!(k, InputObjectKind::MovePackage(_)) {
                    continue; // from the package store
                }
                let id = k.object_id();
                let Some(o) = by_id.get(&id) else {
                    ok = false;
                    break;
                };
                if let InputObjectKind::ImmOrOwnedMoveObject(r) = k {
                    if is_reservation(&r.2) || o.version() != r.1 {
                        ok = false;
                        break;
                    }
                }
                reads.push(ObjectReadResult::new(k, ObjectReadResultKind::Object((*o).clone())));
                inputs.insert(id, (*o).clone());
            }
            // Runtime loads (children, read-only or modified) are served from the same set.
            for o in t.input_objects.iter().chain(extra.iter()) {
                inputs.entry(o.id()).or_insert_with(|| o.clone());
            }
            if !ok {
                continue;
            }
            items.push(ExecItem {
                pv: ep.0,
                epoch,
                start_ms: ep.2,
                rgp: ep.1,
                digest: *t.transaction.digest(),
                data,
                reads,
                inputs,
                want: t.effects.clone(),
            });
        }
    }
    let registry = prometheus::Registry::new();
    let metrics = Arc::new(sui_types::metrics::ExecutionMetrics::new(&registry));
    let mut execs: HashMap<u64, (ProtocolConfig, Arc<dyn sui_execution::Executor + Send + Sync>)> = HashMap::new();
    for it in &items {
        if !execs.contains_key(&it.pv) {
            let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(it.pv), Chain::Mainnet);
            let ex = sui_execution::executor(&cfg, true)?;
            execs.insert(it.pv, (cfg, ex));
        }
    }
    // the coin deny list v2 state (corpus snapshot) per epoch, as the deepwave side reads it
    let deny = if move_calls { synth::load_deny(corpus).ok() } else { None };
    let mut deny_by_epoch: HashMap<u64, HashMap<ObjectID, Object>> = HashMap::new();
    if let Some(d) = &deny {
        for it in &items {
            deny_by_epoch.entry(it.epoch).or_insert_with(|| synth::deny_at(d, it.epoch));
        }
    }
    let run = |it: &ExecItem, reads: Vec<sui_types::transaction::ObjectReadResult>| -> TransactionEffects {
        let (cfg, ex) = &execs[&it.pv];
        let store = ExecStore { inputs: &it.inputs, packages: &packages, system: &system, epoch: it.epoch, latest: deny_by_epoch.get(&it.epoch) };
        let gas_status = if it.data.kind().is_system_tx() {
            sui_types::gas::SuiGasStatus::new_unmetered(cfg)
        } else {
            sui_types::gas::SuiGasStatus::new(it.data.gas_data().budget, it.data.gas_data().price, it.rgp, cfg).expect("gas status")
        };
        let (_, _, fx, _, _) = ex.execute_transaction_to_effects(
            &store,
            cfg,
            metrics.clone(),
            false,
            sui_types::execution_params::ExecutionOrEarlyError::ok(None),
            &it.epoch,
            it.start_ms,
            sui_types::transaction::CheckedInputObjects::new_for_replay(sui_types::transaction::InputObjects::new(reads)),
            sui_types::base_types::SystemObjectVersions::empty(),
            &sui_types::accumulator_root::EmptyUnsettledObjectFunds,
            it.data.gas_data().clone(),
            gas_status,
            it.data.kind().clone(),
            None,
            it.data.sender(),
            it.digest,
            &mut None,
        );
        fx
    };
    // Warm-up pass, which also checks Rust reproduces the certified effects.
    let mut equal = 0usize;
    let mut same = Vec::with_capacity(items.len());
    for it in &items {
        let fx = run(it, it.reads.clone());
        same.push(fx == it.want);
        if fx == it.want {
            equal += 1;
        } else {
            eprintln!("exec bench: {} (epoch {}, pv {}) differs from the certified effects: {:?} vs {:?}", it.digest, it.epoch, it.pv, fx.status(), it.want.status());
            if move_calls {
                eprintln!("  gas {:?} vs {:?}", fx.gas_cost_summary(), it.want.gas_cost_summary());
                LOG_MISSES.store(true, std::sync::atomic::Ordering::Relaxed);
                let _ = run(it, it.reads.clone());
                LOG_MISSES.store(false, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
    let timed: Vec<&ExecItem> = items.iter().zip(&same).filter(|(_, s)| !move_calls || **s).map(|(it, _)| it).collect();
    let mut times = Vec::new();
    for _ in 0..iters {
        let prepared: Vec<_> = timed.iter().map(|it| it.reads.clone()).collect();
        let t = Instant::now();
        for (it, reads) in timed.iter().zip(prepared) {
            std::hint::black_box(run(it, reads));
        }
        times.push(t.elapsed().as_nanos() as u64);
    }
    times.sort();
    let med = times[times.len() / 2];
    let units = timed.len() as u64;
    let name = if move_calls { "exec-move" } else { "exec" };
    let selected = items.len();
    println!(
        "{{\"impl\":\"rust\",\"bench\":\"{name}\",\"unit\":\"tx\",\"units\":{units},\"selected\":{selected},\"effects_equal\":{equal},\"iters\":{iters},\"median_ns\":{med},\"min_ns\":{},\"ns_per_unit\":{:.2}}}",
        times[0],
        med as f64 / units.max(1) as f64
    );
    Ok(())
}

/// History refs known from the corpus: every (id, version, digest) that corpus effects name as
/// written, wrapped or deleted (all_changed_objects, wrapped, deleted, unwrapped_then_deleted),
/// sorted per id by version.
fn corpus_history(corpus: &Path, seqs: &[u64]) -> Result<HashMap<ObjectID, Vec<ObjectRef>>> {
    let parts: Vec<Result<Vec<ObjectRef>>> = seqs
        .par_iter()
        .map(|seq| {
            let cp = decode(&corpus.join(format!("chk/{seq}.chk")))?;
            let mut v = Vec::new();
            for t in &cp.transactions {
                let fx = &t.effects;
                v.extend(fx.all_changed_objects().into_iter().map(|(r, _, _)| r));
                v.extend(fx.wrapped());
                v.extend(fx.deleted());
                v.extend(fx.unwrapped_then_deleted());
            }
            Ok(v)
        })
        .collect();
    let mut m: HashMap<ObjectID, Vec<ObjectRef>> = HashMap::new();
    for p in parts {
        for r in p? {
            m.entry(r.0).or_default().push(r);
        }
    }
    for v in m.values_mut() {
        v.sort();
        v.dedup();
    }
    Ok(m)
}

/// state-hash-history: the v1-path history lookups answered `Some(ref)`. For every corpus
/// checkpoint whose v1 accumulation makes lookups, and for each answer source and protocol
/// version below, run `accumulate_effects` with a store that answers each lookup key:
///   answers "wrapped": (id, version - 1, OBJECT_DIGEST_WRAPPED)
///   answers "plain":   (id, version - 1, [0x11; 32]) (a live-object digest)
///   answers "corpus":  the newest corpus ref of the id below the key version, else None
///   pv: the epoch's own (loaded_child_objects_fixed) and 2 (v1 path, flag off)
/// Rust asserts `!loaded_child_objects_fixed || digest.is_wrapped()`; a panic gives acc null.
fn cmd_state_hash_history(corpus: &Path, out: &Path) -> Result<()> {
    std::panic::set_hook(Box::new(|_| {}));
    let pvs = load_pv(corpus)?;
    let seqs = list_chk(corpus)?;
    // Checkpoints whose v1 accumulation makes lookups.
    let with_lookups: Vec<(u64, CheckpointData, Vec<(ObjectID, SequenceNumber)>)> = seqs
        .par_iter()
        .filter_map(|seq| {
            let cp = decode(&corpus.join(format!("chk/{seq}.chk"))).ok()?;
            let pv = pvs[cp.checkpoint_summary.epoch as usize];
            let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(pv), Chain::Mainnet);
            if path_name(&cfg) != "v1" {
                return None;
            }
            let effects: Vec<TransactionEffects> = cp.transactions.iter().map(|t| t.effects.clone()).collect();
            let store = CheckpointStore::new(&cp);
            let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| accumulate_effects(&store, &effects, &cfg))).is_ok();
            let mut l = store.lookups.lock().unwrap().clone();
            if !ok || l.is_empty() {
                return None;
            }
            l.sort();
            l.dedup();
            Some((*seq, cp, l))
        })
        .collect();
    let v1_seqs: Vec<u64> = seqs
        .iter()
        .copied()
        .filter(|s| {
            // history from every checkpoint at or below the newest lookup checkpoint
            with_lookups.last().is_some_and(|(m, _, _)| s <= m)
        })
        .collect();
    let hist = corpus_history(corpus, &v1_seqs)?;
    let plain = sui_types::digests::ObjectDigest::new([0x11; 32]);
    let wrapped = sui_types::digests::ObjectDigest::OBJECT_DIGEST_WRAPPED;
    let f = std::fs::File::create(out)?;
    let mut z = zstd::Encoder::new(f, 19)?;
    let (mut n, mut panics, mut corpus_some) = (0u64, 0u64, 0u64);
    for (seq, cp, keys) in &with_lookups {
        let real_pv = pvs[cp.checkpoint_summary.epoch as usize];
        for answers in ["wrapped", "plain", "corpus"] {
            let mut map: HashMap<(ObjectID, SequenceNumber), ObjectRef> = HashMap::new();
            for (id, ver) in keys {
                let r = match answers {
                    "wrapped" | "plain" => {
                        let prior = SequenceNumber::from_u64(ver.value().saturating_sub(1));
                        Some((*id, prior, if answers == "wrapped" { wrapped } else { plain }))
                    }
                    _ => hist.get(id).and_then(|v| v.iter().rev().find(|r| r.1 < *ver).copied()),
                };
                if let Some(r) = r {
                    if answers == "corpus" {
                        corpus_some += 1;
                    }
                    map.insert((*id, *ver), r);
                }
            }
            for pv in [real_pv, 2] {
                let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(pv), Chain::Mainnet);
                let effects: Vec<TransactionEffects> = cp.transactions.iter().map(|t| t.effects.clone()).collect();
                let mut store = CheckpointStore::new(cp);
                store.history = map.clone();
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| accumulate_effects(&store, &effects, &cfg)));
                let (acc, digest) = match res {
                    Ok(acc) => (
                        format!("\"{}\"", hex::encode(bcs::to_bytes(&acc)?)),
                        format!("\"{}\"", hex::encode(acc.digest().digest)),
                    ),
                    Err(_) => {
                        panics += 1;
                        ("null".to_string(), "null".to_string())
                    }
                };
                let mut ans: Vec<String> = keys
                    .iter()
                    .map(|k| match map.get(k) {
                        Some(r) => format!("\"{}:{}:{}:{}:{}\"", hex::encode(k.0.as_ref()), k.1.value(), hex::encode(r.0.as_ref()), r.1.value(), hex::encode(r.2.inner())),
                        None => format!("\"{}:{}:none\"", hex::encode(k.0.as_ref()), k.1.value()),
                    })
                    .collect();
                ans.sort();
                writeln!(
                    z,
                    "{{\"seq\":{seq},\"answers\":\"{answers}\",\"pv\":{pv},\"fixed\":{},\"history\":[{}],\"acc\":{acc},\"digest\":{digest}}}",
                    cfg.loaded_child_objects_fixed(),
                    ans.join(","),
                )?;
                n += 1;
            }
        }
    }
    z.finish()?;
    eprintln!(
        "state-hash-history: {} checkpoints with lookups, {n} items, {panics} panicked, {corpus_some} lookups answered from corpus history",
        with_lookups.len()
    );
    Ok(())
}

fn type_addrs(t: &move_core_types::language_storage::TypeTag, out: &mut std::collections::BTreeSet<ObjectID>) {
    use move_core_types::language_storage::TypeTag;
    match t {
        TypeTag::Vector(e) => type_addrs(e, out),
        TypeTag::Struct(s) => struct_addrs(s, out),
        _ => {}
    }
}

fn struct_addrs(s: &move_core_types::language_storage::StructTag, out: &mut std::collections::BTreeSet<ObjectID>) {
    out.insert(ObjectID::from(s.address));
    for p in &s.type_params {
        type_addrs(p, out);
    }
}

/// Package ids a corpus transaction may load: MoveCall packages and type arguments,
/// Publish/Upgrade dependencies and the upgraded package, and every address in the types of
/// its input and output objects. System packages are excluded (framework snapshots and the
/// corpus's own end-of-epoch writes supply them).
fn corpus_package_roots(corpus: &Path, seqs: &[u64]) -> Result<std::collections::BTreeSet<ObjectID>> {
    use sui_types::transaction::{Command, TransactionDataAPI, TransactionKind};
    let parts: Vec<Result<std::collections::BTreeSet<ObjectID>>> = seqs
        .par_iter()
        .map(|seq| {
            let cp = decode(&corpus.join(format!("chk/{seq}.chk")))?;
            let mut s = std::collections::BTreeSet::new();
            for t in &cp.transactions {
                let data = t.transaction.data().transaction_data();
                if let TransactionKind::ProgrammableTransaction(pt) = data.kind() {
                    for c in &pt.commands {
                        match c {
                            Command::MoveCall(mc) => {
                                s.insert(mc.package);
                                for ta in &mc.type_arguments {
                                    if let Ok(tag) = ta.to_type_tag() {
                                        type_addrs(&tag, &mut s);
                                    }
                                }
                            }
                            Command::MakeMoveVec(Some(ta), _) => {
                                if let Ok(tag) = ta.to_type_tag() {
                                    type_addrs(&tag, &mut s);
                                }
                            }
                            Command::Publish(_, deps) => s.extend(deps.iter().copied()),
                            Command::Upgrade(_, deps, pkg, _) => {
                                s.extend(deps.iter().copied());
                                s.insert(*pkg);
                            }
                            _ => {}
                        }
                    }
                }
                for o in t.input_objects.iter().chain(t.output_objects.iter()) {
                    if let Some(ty) = o.type_() {
                        struct_addrs(&move_core_types::language_storage::StructTag::from(ty.clone()), &mut s);
                    }
                }
            }
            s.retain(|id| !sui_types::is_system_package(*id));
            Ok(s)
        })
        .collect();
    let mut all = std::collections::BTreeSet::new();
    for p in parts {
        all.extend(p?);
    }
    Ok(all)
}

/// `packages <corpus> <grpc url>`: fetch every non-system package a corpus transaction loads,
/// plus the closure of their linkage tables, into `<corpus>/packages/<id>.obj` (raw BCS
/// `Object`) and `<corpus>/packages/index.jsonl`. BatchGetObjects of 50 ids, at most 10 batches
/// per second. Ids already on disk are not fetched again. Each object is checked: it decodes as
/// a package with the requested id, and its digest equals the digest the service reports.
/// `extra`: a file of more root ids (hex, one per line), for packages a replay loads that the
/// corpus scan does not name (runtime-loaded object types).
fn cmd_packages(corpus: &Path, url: &str, extra: Option<&Path>) -> Result<()> {
    use sui_rpc::proto::sui::rpc::v2::{BatchGetObjectsRequest, GetObjectRequest, get_object_result};
    let seqs = list_chk(corpus)?;
    let mut roots = corpus_package_roots(corpus, &seqs)?;
    if let Some(p) = extra {
        for line in std::fs::read_to_string(p)?.lines().map(str::trim).filter(|l| !l.is_empty()) {
            roots.insert(ObjectID::from_hex_literal(&format!("0x{}", line.trim_start_matches("0x")))?);
        }
    }
    let dir = corpus.join("packages");
    std::fs::create_dir_all(&dir)?;
    eprintln!("packages: {} root ids", roots.len());
    let mut queue: std::collections::VecDeque<ObjectID> = roots.iter().copied().collect();
    let mut seen: std::collections::BTreeSet<ObjectID> = roots.clone();
    let mut index: std::collections::BTreeMap<ObjectID, String> = std::collections::BTreeMap::new();
    let mut not_found: Vec<ObjectID> = Vec::new();
    let mut requests = 0u64;
    let rt = tokio::runtime::Runtime::new()?;
    let _guard = rt.enter();
    let mut client = sui_rpc::Client::new(url.to_string())?;
    let line_for = |obj: &Object, source: &str| -> Result<(String, Vec<ObjectID>)> {
        let pkg = obj.data.try_as_package().context("not a package")?;
        let links: Vec<ObjectID> = pkg.linkage_table().values().map(|u| u.upgraded_id).collect();
        let l = format!(
            "{{\"id\":\"{}\",\"version\":{},\"digest\":\"{}\",\"source\":\"{source}\",\"linkage\":[{}]}}",
            hex::encode(obj.id().as_ref()),
            obj.version().value(),
            hex::encode(obj.digest().inner()),
            links.iter().map(|l| format!("\"{}\"", hex::encode(l.as_ref()))).collect::<Vec<_>>().join(",")
        );
        Ok((l, links))
    };
    while !queue.is_empty() {
        let mut batch = Vec::new();
        while batch.len() < 50 {
            let Some(id) = queue.pop_front() else { break };
            let path = dir.join(format!("{}.obj", hex::encode(id.as_ref())));
            if let Ok(raw) = std::fs::read(&path) {
                let obj: Object = bcs::from_bytes(&raw)?;
                let (l, links) = line_for(&obj, "grpc")?;
                index.insert(id, l);
                for x in links {
                    if !sui_types::is_system_package(x) && seen.insert(x) {
                        queue.push_back(x);
                    }
                }
                continue;
            }
            batch.push(id);
        }
        if batch.is_empty() {
            continue;
        }
        let mut req = BatchGetObjectsRequest::default();
        req.requests = batch
            .iter()
            .map(|id| {
                let mut r = GetObjectRequest::default();
                r.object_id = Some(id.to_hex_literal());
                r
            })
            .collect();
        req.read_mask = Some(prost_types::FieldMask { paths: vec!["bcs".into(), "digest".into()] });
        let resp = rt.block_on(async { client.ledger_client().batch_get_objects(req).await })?.into_inner();
        requests += 1;
        std::thread::sleep(std::time::Duration::from_millis(100));
        if resp.objects.len() != batch.len() {
            bail!("batch of {} answered {}", batch.len(), resp.objects.len());
        }
        for (id, res) in batch.iter().zip(resp.objects) {
            match res.result {
                Some(get_object_result::Result::Object(o)) => {
                    let raw = o.bcs.and_then(|b| b.value).context("no bcs")?.to_vec();
                    let obj: Object = bcs::from_bytes(&raw).with_context(|| format!("decode {id}"))?;
                    if obj.id() != *id {
                        bail!("asked {id}, got {}", obj.id());
                    }
                    let want = o.digest.context("no digest")?;
                    if obj.digest().to_string() != want {
                        bail!("{id}: digest {} != reported {want}", obj.digest());
                    }
                    std::fs::write(dir.join(format!("{}.obj", hex::encode(id.as_ref()))), &raw)?;
                    let (l, links) = line_for(&obj, "grpc")?;
                    index.insert(*id, l);
                    for x in links {
                        if !sui_types::is_system_package(x) && seen.insert(x) {
                            queue.push_back(x);
                        }
                    }
                }
                _ => not_found.push(*id),
            }
        }
        if requests % 20 == 0 {
            eprintln!("packages: {requests} requests, {} stored, {} queued, {} not found", index.len(), queue.len(), not_found.len());
        }
    }
    let mut f = std::fs::File::create(dir.join("index.jsonl"))?;
    for l in index.values() {
        writeln!(f, "{l}")?;
    }
    not_found.sort();
    let mut nf = std::fs::File::create(dir.join("not_found.txt"))?;
    for id in &not_found {
        writeln!(nf, "{}", hex::encode(id.as_ref()))?;
    }
    eprintln!(
        "packages: {} roots, {} with linkage closure stored, {} ids not packages or not found, {requests} batch requests",
        roots.len(),
        index.len(),
        not_found.len()
    );
    Ok(())
}

/// `objects <corpus> <grpc url> <out>`: the input objects corpus transactions read that their
/// checkpoint does not carry. `CheckpointData` holds the objects a transaction changed, so
/// read-only consensus inputs (`accessed_consensus_objects` ReadOnly) and owned or immutable
/// inputs passed by reference that stay unchanged are absent. Each such ref (id, version,
/// digest) is fetched by BatchGetObjects (50 per request, at most 10 requests per second) and
/// kept only if the object's digest equals the ref's. Output: zstd of records
/// `u32 LE length ++ BCS Object`, in (id, version) order.
fn cmd_objects(corpus: &Path, url: &str, out: &Path) -> Result<()> {
    use sui_rpc::proto::sui::rpc::v2::{BatchGetObjectsRequest, GetObjectRequest, get_object_result};
    use sui_types::effects::InputConsensusObject;
    use sui_types::transaction::{InputObjectKind, TransactionDataAPI};
    let seqs = list_chk(corpus)?;
    let parts: Vec<Result<Vec<ObjectRef>>> = seqs
        .par_iter()
        .map(|seq| {
            let cp = decode(&corpus.join(format!("chk/{seq}.chk")))?;
            let mut have = std::collections::HashSet::new();
            for t in &cp.transactions {
                for o in t.input_objects.iter().chain(t.output_objects.iter()) {
                    have.insert((o.id(), o.version()));
                }
            }
            let mut need = Vec::new();
            for t in &cp.transactions {
                let data = t.transaction.data().transaction_data();
                let mut refs: Vec<ObjectRef> = Vec::new();
                if let Ok(kinds) = data.input_objects() {
                    for k in kinds {
                        if let InputObjectKind::ImmOrOwnedMoveObject(r) = k {
                            refs.push(r);
                        }
                    }
                }
                for c in t.effects.accessed_consensus_objects() {
                    if let InputConsensusObject::ReadOnly(r) = c {
                        refs.push(r);
                    }
                }
                for r in refs {
                    if !have.contains(&(r.0, r.1)) {
                        need.push(r);
                    }
                }
            }
            Ok(need)
        })
        .collect();
    let mut need: Vec<ObjectRef> = Vec::new();
    for p in parts {
        need.extend(p?);
    }
    need.sort();
    need.dedup();
    eprintln!("objects: {} refs not carried by their checkpoint", need.len());
    let rt = tokio::runtime::Runtime::new()?;
    let _guard = rt.enter();
    // Some batches (large objects) exceed tonic's default 4 MiB decode limit.
    let mut client = sui_rpc::Client::new(url.to_string())?.with_max_decoding_message_size(256 << 20);
    let mut records: Vec<Vec<u8>> = Vec::new();
    let (mut requests, mut missing, mut bad_digest) = (0u64, 0u64, 0u64);
    for chunk in need.chunks(50) {
        let mut req = BatchGetObjectsRequest::default();
        req.requests = chunk
            .iter()
            .map(|r| {
                let mut g = GetObjectRequest::default();
                g.object_id = Some(r.0.to_hex_literal());
                g.version = Some(r.1.value());
                g
            })
            .collect();
        req.read_mask = Some(prost_types::FieldMask { paths: vec!["bcs".into()] });
        let mut tries = 0;
        let resp = loop {
            match rt.block_on(async { client.ledger_client().batch_get_objects(req.clone()).await }) {
                Ok(r) => break r.into_inner(),
                Err(e) => {
                    tries += 1;
                    if tries == 8 {
                        bail!("objects: batch failed 8 times: {e}");
                    }
                    eprintln!("objects: retry after {e}");
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
            }
        };
        requests += 1;
        std::thread::sleep(std::time::Duration::from_millis(100));
        if resp.objects.len() != chunk.len() {
            bail!("batch of {} answered {}", chunk.len(), resp.objects.len());
        }
        for (r, res) in chunk.iter().zip(resp.objects) {
            match res.result {
                Some(get_object_result::Result::Object(o)) => {
                    let raw = o.bcs.and_then(|b| b.value).context("no bcs")?.to_vec();
                    let obj: Object = bcs::from_bytes(&raw)?;
                    if obj.compute_object_reference() != *r {
                        bad_digest += 1;
                        continue;
                    }
                    records.push(raw);
                }
                _ => missing += 1,
            }
        }
        if requests % 200 == 0 {
            eprintln!("objects: {requests} requests, {} stored, {missing} missing, {bad_digest} digest mismatches", records.len());
        }
    }
    let f = std::fs::File::create(out)?;
    let mut z = zstd::Encoder::new(f, 9)?;
    for r in &records {
        z.write_all(&(r.len() as u32).to_le_bytes())?;
        z.write_all(r)?;
    }
    z.finish()?;
    eprintln!(
        "objects: {} refs, {} stored, {missing} not served, {bad_digest} digest mismatches, {requests} batch requests",
        need.len(),
        records.len()
    );
    Ok(())
}

/// `deny-snapshot <corpus> <fullnode url> <archive url>`: every version of the coin deny list
/// v2 objects (`check_coin_deny_list_v2_during_execution` reads them with `get_object`, the
/// store's latest version, outside the transaction's inputs). The per-type config fields are the
/// dynamic object fields of 0x403 (`Field<Wrapper<ConfigKey>, ID>`); each config's settings are
/// its dynamic fields (`Field<AddressKey | GlobalPauseKey, Setting<bool>>`). Each object is
/// walked back to its creation through its previous transaction's effects
/// (`modified_at_versions`), the older versions read from the archive. Output:
/// `<corpus>/deny/objects.bin.zst`, records `u32 LE length ++ u64 LE write epoch ++ BCS Object`
/// (the length counts the epoch and the object).
/// Retries a gRPC call (public endpoints rate-limit): 8 tries, 1 s, 2 s, 4 s ... backoff.
async fn retry<T, E, F, Fut>(what: &str, mut f: F) -> Result<T>
where
    E: std::fmt::Display,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, E>>,
{
    let mut wait = 1u64;
    let mut last = String::new();
    for _ in 0..8 {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                last = e.to_string();
                tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                wait = (wait * 2).min(30);
            }
        }
    }
    bail!("{what}: gave up after 8 tries: {last}")
}

/// `deny-snapshot <corpus> <fullnode> <archive>`: every coin deny list v2 object (the 0x403
/// per-type config fields and every setting field under each config) at every version, each
/// with the epoch that wrote it, into `<corpus>/deny/objects.bin.zst`. 16 requests in flight.
fn cmd_deny_snapshot(corpus: &Path, fullnode: &str, archive: &str) -> Result<()> {
    use sui_rpc::proto::sui::rpc::v2::{GetObjectRequest, GetTransactionRequest, ListDynamicFieldsRequest};
    let rt = tokio::runtime::Runtime::new()?;
    let _guard = rt.enter();
    let live = sui_rpc::Client::new(fullnode.to_string())?.with_max_decoding_message_size(64 << 20);
    let arch = sui_rpc::Client::new(archive.to_string())?.with_max_decoding_message_size(64 << 20);
    let requests = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let list = {
        let live = live.clone();
        let requests = requests.clone();
        move |parent: ObjectID| {
            let live = live.clone();
            let requests = requests.clone();
            async move {
                let mut out = Vec::new();
                let mut token: Option<prost::bytes::Bytes> = None;
                loop {
                    let mut req = ListDynamicFieldsRequest::default();
                    req.parent = Some(parent.to_hex_literal());
                    req.page_size = Some(1000);
                    req.page_token = token.clone();
                    req.read_mask = Some(prost_types::FieldMask { paths: vec!["field_id".into()] });
                    let resp = retry("list_dynamic_fields", || {
                        let mut c = live.clone();
                        let req = req.clone();
                        async move { c.state_client().list_dynamic_fields(req).await }
                    })
                    .await?
                    .into_inner();
                    requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    for f in resp.dynamic_fields {
                        out.push(ObjectID::from_hex_literal(f.field_id.as_deref().context("field_id")?)?);
                    }
                    match resp.next_page_token {
                        Some(t) if !t.is_empty() => token = Some(t),
                        _ => break,
                    }
                }
                anyhow::Ok(out)
            }
        }
    };
    let get = {
        let live = live.clone();
        let arch = arch.clone();
        let requests = requests.clone();
        move |id: ObjectID, version: Option<u64>| {
            let client = if version.is_some() { arch.clone() } else { live.clone() };
            let requests = requests.clone();
            async move {
                let mut req = GetObjectRequest::default();
                req.object_id = Some(id.to_hex_literal());
                req.version = version;
                req.read_mask = Some(prost_types::FieldMask { paths: vec!["bcs".into()] });
                let resp = retry(&format!("get_object {id} {version:?}"), || {
                    let mut c = client.clone();
                    let req = req.clone();
                    async move { c.ledger_client().get_object(req).await }
                })
                .await?
                .into_inner();
                requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let raw = resp.object.and_then(|o| o.bcs).and_then(|b| b.value).context("no bcs")?;
                anyhow::Ok(bcs::from_bytes::<Object>(&raw)?)
            }
        }
    };
    let effects = {
        let arch = arch.clone();
        let requests = requests.clone();
        move |digest: sui_types::digests::TransactionDigest| {
            let arch = arch.clone();
            let requests = requests.clone();
            async move {
                let mut req = GetTransactionRequest::default();
                req.digest = Some(digest.to_string());
                req.read_mask = Some(prost_types::FieldMask { paths: vec!["effects.bcs".into()] });
                let resp = retry(&format!("get_transaction {digest}"), || {
                    let mut c = arch.clone();
                    let req = req.clone();
                    async move { c.ledger_client().get_transaction(req).await }
                })
                .await?
                .into_inner();
                requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let raw = resp.transaction.and_then(|t| t.effects).and_then(|e| e.bcs).and_then(|b| b.value).context("no effects bcs")?;
                anyhow::Ok(bcs::from_bytes::<TransactionEffects>(&raw)?)
            }
        }
    };
    let deny = ObjectID::from_hex_literal("0x403")?;
    let records: Vec<Vec<u8>> = rt.block_on(async {
        let sem = Arc::new(tokio::sync::Semaphore::new(16));
        let configs = list(deny).await?;
        eprintln!("deny-snapshot: {} per-type config fields", configs.len());
        // settings under each config
        let mut set = tokio::task::JoinSet::new();
        for c in configs.clone() {
            let (sem, get, list) = (sem.clone(), get.clone(), list.clone());
            set.spawn(async move {
                let _p = sem.acquire_owned().await?;
                let field = get(c, None).await?;
                // Field<Wrapper<ConfigKey>, ID>: the value (last 32 bytes) is the Config object's id
                let contents = field.data.try_as_move().context("config field")?.contents().to_vec();
                let cfg_id = ObjectID::from_bytes(&contents[contents.len() - 32..])?;
                list(cfg_id).await
            });
        }
        let mut roots: Vec<ObjectID> = configs;
        while let Some(r) = set.join_next().await {
            roots.extend(r??);
        }
        eprintln!("deny-snapshot: {} objects (config fields and settings)", roots.len());
        // every version of each, newest first through the effects' modified_at_versions
        let mut set = tokio::task::JoinSet::new();
        for id in roots {
            let (sem, get, effects) = (sem.clone(), get.clone(), effects.clone());
            set.spawn(async move {
                let _p = sem.acquire_owned().await?;
                let mut out = Vec::new();
                let mut obj = get(id, None).await?;
                loop {
                    let fx = effects(obj.previous_transaction).await?;
                    // the epoch that wrote this version: settings read with `read_value(Some(epoch))`
                    // give the same answer for any version current during one epoch
                    let mut rec = fx.executed_epoch().to_le_bytes().to_vec();
                    rec.extend(bcs::to_bytes(&obj)?);
                    out.push(rec);
                    let Some((_, prev)) = fx.modified_at_versions().into_iter().find(|(i, _)| *i == id) else { break };
                    obj = get(id, Some(prev.value())).await?;
                }
                anyhow::Ok(out)
            });
        }
        let mut records = Vec::new();
        let mut done = 0usize;
        while let Some(r) = set.join_next().await {
            records.extend(r??);
            done += 1;
            if done % 1000 == 0 {
                eprintln!("deny-snapshot: {done} objects walked, {} versions", records.len());
            }
        }
        anyhow::Ok(records)
    })?;
    let dir = corpus.join("deny");
    std::fs::create_dir_all(&dir)?;
    let tmp = dir.join("objects.bin.zst.tmp");
    let f = std::fs::File::create(&tmp)?;
    let mut z = zstd::Encoder::new(f, 9)?;
    for r in &records {
        z.write_all(&(r.len() as u32).to_le_bytes())?;
        z.write_all(r)?;
    }
    z.finish()?;
    std::fs::rename(&tmp, dir.join("objects.bin.zst"))?;
    eprintln!("deny-snapshot: {} object versions stored, {} requests", records.len(), requests.load(std::sync::atomic::Ordering::Relaxed));
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("state-hash") => cmd_state_hash(Path::new(&args[1]), Path::new(&args[2])),
        Some("state-hash-history") => cmd_state_hash_history(Path::new(&args[1]), Path::new(&args[2])),
        Some("packages") => cmd_packages(Path::new(&args[1]), &args[2], args.get(3).map(Path::new)),
        Some("objects") => cmd_objects(Path::new(&args[1]), &args[2], Path::new(&args[3])),
        Some("bench") => cmd_bench(&args[1..]),
        Some("show") => {
            // `show <corpus> <seq> <tx index>`: Debug print of one corpus transaction (debugging aid)
            let cp = decode(&Path::new(&args[1]).join(format!("chk/{}.chk", args[2])))?;
            let t = &cp.transactions[args[3].parse::<usize>()?];
            println!("{:#?}\n{:#?}\n{:#?}", t.transaction.data().transaction_data(), t.effects, t.events);
            for o in &t.output_objects {
                println!("OUT {} v{} {:?} {:?}", o.id(), o.version(), o.owner, o.type_());
            }
            Ok(())
        }
        Some("synth") => synth::cmd_synth(Path::new(&args[1]), Path::new(&args[2])),
        Some("scan-refs") => synth::cmd_scan_refs(Path::new(&args[1])),
        Some("deny-snapshot") => cmd_deny_snapshot(Path::new(&args[1]), &args[2], &args[3]),
        _ => bail!("usage: zui-truth-exec state-hash <corpus> <out.jsonl.zst> | bench <name> --iters N --list <file>"),
    }
}

#[allow(dead_code)]
fn _effects_api_used(fx: &TransactionEffects) -> usize {
    fx.modified_at_versions().len()
}
