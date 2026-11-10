//! zui-truth-exec-system: inputs and baselines for the exec-system lane, from Mysten's own code.
//!
//! children: every `read_child_object(parent, child, bound)` answer that corpus system
//! transactions need and their checkpoint does not carry (a child read without a change is not
//! in the checkpoint's input objects). The tool runs Mysten's executor
//! (`sui_execution::executor(cfg)` then `execute_transaction_to_effects`, unmetered) on every
//! corpus system transaction it covers, with a store holding the checkpoint's input objects, the
//! corpus packages and the answers found so far. Unanswered reads are fetched from Mysten's
//! GraphQL (`object(address: child, rootVersion: bound)`, the newest version at or below the
//! bound), each object checked against its id, its bound and the digest GraphQL reports, and the
//! transactions run again until no read is unanswered. The run then reports how many
//! transactions reproduce their certified effects (it must be all of them).
//!
//! bench system: the same executor on the bench checkpoints' system transactions (harness
//! baseline for exec-replay's system rows).
use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use sui_types::base_types::{ObjectID, ObjectRef, SequenceNumber, VersionNumber};
use sui_types::committee::EpochId;
use sui_types::effects::TransactionEffects;
use sui_types::error::SuiResult;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::object::Object;
use sui_types::storage::ObjectStore;
use sui_types::transaction::{InputObjectKind, ObjectReadResult, ObjectReadResultKind, TransactionDataAPI, TransactionKind};

type ChildKey = (ObjectID, ObjectID, u64);

fn decode(path: &Path) -> Result<CheckpointData> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if raw.first() != Some(&1) {
        bail!("{}: bad blob tag", path.display());
    }
    bcs::from_bytes(&raw[1..]).with_context(|| format!("decode {}", path.display()))
}

struct Epoch {
    pv: u64,
    start_ms: u64,
    last: Option<u64>,
}

fn load_epochs(corpus: &Path) -> Result<Vec<Epoch>> {
    let mut out: Vec<Epoch> = Vec::new();
    for line in std::fs::read_to_string(corpus.join("epochs.jsonl"))?.lines().filter(|l| !l.is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line)?;
        let e = v["epoch"].as_u64().context("epoch")? as usize;
        if e != out.len() {
            bail!("epochs.jsonl not contiguous at {e}");
        }
        out.push(Epoch { pv: v["pv"].as_u64().unwrap_or(0), start_ms: v["start_ms"].as_u64().unwrap_or(0), last: v["last"].as_u64() });
    }
    Ok(out)
}

/// Corpus packages: non-system by id, system per id with the epoch from which each write is
/// visible (genesis from 0, an end-of-epoch write from the next epoch), as src/exec/packages.zig.
struct Packages {
    user: HashMap<ObjectID, Object>,
    system: HashMap<ObjectID, Vec<(u64, Object)>>,
}

impl Packages {
    fn load(corpus: &Path, epochs: &[Epoch]) -> Result<Self> {
        let mut user = HashMap::new();
        for ent in std::fs::read_dir(corpus.join("packages"))? {
            let p = ent?.path();
            if p.extension().and_then(|x| x.to_str()) != Some("obj") {
                continue;
            }
            let o: Object = bcs::from_bytes(&std::fs::read(&p)?)?;
            user.insert(o.id(), o);
        }
        let mut writes: Vec<(u64, u64)> = vec![(0, 0)];
        for (e, ep) in epochs.iter().enumerate() {
            if let Some(last) = ep.last {
                writes.push((last, e as u64 + 1));
            }
        }
        let lists: Vec<Vec<(u64, Object)>> = writes
            .par_iter()
            .map(|(seq, visible)| {
                let Ok(cp) = decode(&corpus.join(format!("chk/{seq}.chk"))) else { return vec![] };
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
        for list in lists {
            for (e, o) in list {
                system.entry(o.id()).or_default().push((e, o));
            }
        }
        for v in system.values_mut() {
            v.sort_by_key(|(e, _)| *e);
        }
        Ok(Self { user, system })
    }

    fn get(&self, id: &ObjectID, epoch: u64) -> Option<Object> {
        if let Some(list) = self.system.get(id) {
            return list.iter().filter(|(e, _)| *e <= epoch).last().map(|(_, o)| o.clone());
        }
        self.user.get(id).cloned()
    }
}

struct Store<'a> {
    inputs: HashMap<ObjectID, Object>,
    packages: &'a Packages,
    epoch: u64,
    answers: &'a HashMap<ChildKey, Option<Object>>,
    missing: Mutex<Vec<ChildKey>>,
}

impl sui_types::storage::BackingPackageStore for Store<'_> {
    fn get_package_object(&self, id: &ObjectID) -> SuiResult<Option<sui_types::storage::PackageObject>> {
        Ok(self.packages.get(id, self.epoch).map(sui_types::storage::PackageObject::new))
    }
}

impl sui_types::storage::RuntimeObjectResolver for Store<'_> {
    fn read_child_object(&self, parent: &ObjectID, child: &ObjectID, bound: SequenceNumber) -> SuiResult<Option<Object>> {
        if let Some(o) = self.inputs.get(child) {
            if o.version() <= bound {
                return Ok(Some(o.clone()));
            }
        }
        let key = (*parent, *child, bound.value());
        match self.answers.get(&key) {
            Some(a) => Ok(a.clone()),
            None => {
                self.missing.lock().unwrap().push(key);
                Ok(None)
            }
        }
    }
    fn get_object_received_at_version(&self, _o: &ObjectID, _r: &ObjectID, _v: SequenceNumber, _e: EpochId) -> SuiResult<Option<Object>> {
        Ok(None)
    }
}

impl sui_types::storage::ParentSync for Store<'_> {
    fn get_latest_parent_entry_ref_deprecated(&self, _id: ObjectID) -> Option<ObjectRef> {
        None
    }
}

impl ObjectStore for Store<'_> {
    fn get_object(&self, id: &ObjectID) -> Option<Object> {
        self.inputs.get(id).cloned().or_else(|| self.packages.get(id, self.epoch))
    }
    fn get_object_by_key(&self, id: &ObjectID, version: VersionNumber) -> Option<Object> {
        self.get_object(id).filter(|o| o.version() == version)
    }
}

/// One corpus system transaction prepared for `sui_execution`.
struct Item {
    seq: u64,
    pv: u64,
    epoch: u64,
    start_ms: u64,
    data: sui_types::transaction::TransactionData,
    digest: sui_types::digests::TransactionDigest,
    /// Input objects: the checkpoint carries changed ones; a shared input read without a change
    /// (a non-exclusive write, a read-only root) is fetched at the version its certified effects
    /// report (`unchanged_consensus_objects`), digest checked: key (ZERO, id, version).
    kinds: Vec<(InputObjectKind, Option<Object>, Option<(u64, sui_types::digests::ObjectDigest)>)>,
    inputs: HashMap<ObjectID, Object>,
    want: TransactionEffects,
}

impl Item {
    fn pending(&self) -> impl Iterator<Item = ChildKey> + '_ {
        self.kinds.iter().filter_map(|(k, o, at)| match (o, at) {
            (None, Some((v, _))) => Some((ObjectID::ZERO, k.object_id(), *v)),
            _ => None,
        })
    }

    /// The reads and the input map with fetched inputs filled in; None while one is missing.
    fn resolve(&self, answers: &HashMap<ChildKey, Option<Object>>) -> Result<Option<(Vec<ObjectReadResult>, HashMap<ObjectID, Object>)>> {
        let mut reads = Vec::with_capacity(self.kinds.len());
        let mut inputs = self.inputs.clone();
        for (k, o, at) in &self.kinds {
            let o = match (o, at) {
                (Some(o), _) => o.clone(),
                (None, Some((v, d))) => {
                    let Some(Some(o)) = answers.get(&(ObjectID::ZERO, k.object_id(), *v)) else { return Ok(None) };
                    if o.digest() != *d {
                        bail!("fetched input {} at {v} has digest {}, effects say {d}", k.object_id(), o.digest());
                    }
                    inputs.insert(o.id(), o.clone());
                    o.clone()
                }
                (None, None) => bail!("input {} has no source", k.object_id()),
            };
            reads.push(ObjectReadResult::new(*k, ObjectReadResultKind::Object(o)));
        }
        Ok(Some((reads, inputs)))
    }
}

/// The system transaction kinds this tool covers (the ones deepwave's exec-system runs).
/// The kinds deepwave's `system.execute` runs (exec-system round 1); the bench times these at
/// protocol 119 and later.
fn handled(kind: &TransactionKind) -> bool {
    matches!(
        kind,
        TransactionKind::ProgrammableSystemTransaction(_)
            | TransactionKind::RandomnessStateUpdate(_)
            | TransactionKind::AuthenticatorStateUpdate(_)
            | TransactionKind::EndOfEpochTransaction(_)
    )
}

/// The kinds the children part answers for: the handled ones plus end of epoch (the next
/// executor), at every protocol version.
const COVERED: &[&str] = &[
    "ProgrammableSystemTransaction",
    "RandomnessStateUpdate",
    "AuthenticatorStateUpdate",
    "EndOfEpochTransaction",
    "ChangeEpoch",
];

fn covered(kind: &TransactionKind) -> bool {
    handled(kind) || matches!(kind, TransactionKind::EndOfEpochTransaction(_) | TransactionKind::ChangeEpoch(_))
}

fn items_of(cp: &CheckpointData, epochs: &[Epoch], packages: &Packages, kinds: fn(&TransactionKind) -> bool, min_pv: u64) -> Vec<Item> {
    let epoch = cp.checkpoint_summary.epoch;
    let ep = &epochs[epoch as usize];
    if ep.pv < min_pv {
        return vec![];
    }
    let mut out = vec![];
    for t in &cp.transactions {
        let data = t.transaction.data().transaction_data().clone();
        if !kinds(data.kind()) {
            continue;
        }
        let Ok(kinds) = data.input_objects() else { continue };
        let by_id: HashMap<ObjectID, &Object> = t.input_objects.iter().map(|o| (o.id(), o)).collect();
        use sui_types::effects::{TransactionEffectsAPI, UnchangedConsensusKind};
        let unchanged: HashMap<ObjectID, (u64, sui_types::digests::ObjectDigest)> = t
            .effects
            .unchanged_consensus_objects()
            .into_iter()
            .filter_map(|(id, k)| match k {
                UnchangedConsensusKind::ReadOnlyRoot((v, d)) => Some((id, (v.value(), d))),
                _ => None,
            })
            .collect();
        let mut list = Vec::new();
        let mut ok = true;
        for k in kinds {
            let id = k.object_id();
            let o = match k {
                InputObjectKind::MovePackage(_) => packages.get(&id, epoch),
                _ => by_id.get(&id).map(|o| (*o).clone()),
            };
            let at = if o.is_none() { unchanged.get(&id).copied() } else { None };
            if o.is_none() && at.is_none() {
                eprintln!("{}: {} input object {id} missing ({:?})", cp.checkpoint_summary.sequence_number, t.transaction.digest(), k);
                ok = false;
                break;
            }
            list.push((k, o, at));
        }
        if !ok {
            continue;
        }
        out.push(Item {
            seq: cp.checkpoint_summary.sequence_number,
            pv: ep.pv,
            epoch,
            start_ms: ep.start_ms,
            digest: *t.transaction.digest(),
            data,
            kinds: list,
            inputs: t.input_objects.iter().map(|o| (o.id(), o.clone())).collect(),
            want: t.effects.clone(),
        });
    }
    out
}

struct Exec {
    metrics: Arc<sui_types::metrics::ExecutionMetrics>,
    by_pv: HashMap<u64, (ProtocolConfig, Arc<dyn sui_execution::Executor + Send + Sync>)>,
}

impl Exec {
    fn new(items: &[Item]) -> Result<Self> {
        let registry = prometheus::Registry::new();
        let metrics = Arc::new(sui_types::metrics::ExecutionMetrics::new(&registry));
        let mut by_pv = HashMap::new();
        for it in items {
            if !by_pv.contains_key(&it.pv) {
                let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(it.pv), Chain::Mainnet);
                let ex = sui_execution::executor(&cfg, true)?;
                by_pv.insert(it.pv, (cfg, ex));
            }
        }
        Ok(Self { metrics, by_pv })
    }

    fn run(&self, it: &Item, store: &Store, reads: Vec<ObjectReadResult>) -> TransactionEffects {
        let (cfg, ex) = &self.by_pv[&it.pv];
        let (_, _, fx, _, _) = ex.execute_transaction_to_effects(
            store,
            cfg,
            self.metrics.clone(),
            false,
            sui_types::execution_params::ExecutionOrEarlyError::ok(None),
            &it.epoch,
            it.start_ms,
            sui_types::transaction::CheckedInputObjects::new_for_replay(sui_types::transaction::InputObjects::new(reads)),
            sui_types::base_types::SystemObjectVersions::empty(),
            &sui_types::accumulator_root::EmptyUnsettledObjectFunds,
            it.data.gas_data().clone(),
            sui_types::gas::SuiGasStatus::new_unmetered(cfg),
            it.data.kind().clone(),
            None,
            it.data.sender(),
            it.digest,
            &mut None,
        );
        fx
    }
}

fn manifest_seqs(corpus: &Path, kinds: &[&str]) -> Result<Vec<u64>> {
    let mut out = vec![];
    for line in std::fs::read_to_string(corpus.join("manifest.jsonl"))?.lines().filter(|l| !l.is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line)?;
        let has = v["kinds"].as_array().map(|a| a.iter().any(|k| kinds.contains(&k.as_str().unwrap_or("")))).unwrap_or(false);
        if has {
            out.push(v["seq"].as_u64().context("seq")?);
        }
    }
    Ok(out)
}

/// GraphQL `object(address, rootVersion)` for a batch of keys; each answer checked.
fn fetch(url: &str, keys: &[ChildKey], tmp: &Path) -> Result<Vec<Option<Object>>> {
    use base64::Engine;
    let mut q = String::from("{");
    for (i, (parent, child, bound)) in keys.iter().enumerate() {
        let at = if *parent == ObjectID::ZERO { "version" } else { "rootVersion" };
        q.push_str(&format!(" q{i}: object(address: \"{child}\", {at}: {bound}) {{ version digest objectBcs }}"));
    }
    q.push_str(" }");
    let body = serde_json::json!({ "query": q }).to_string();
    std::fs::write(tmp, body)?;
    let mut tries = 0;
    let v: serde_json::Value = loop {
        let out = std::process::Command::new("curl")
            .args(["-s", "-m", "60", "-H", "content-type: application/json", "--data-binary"])
            .arg(format!("@{}", tmp.display()))
            .arg(url)
            .output()?;
        let parsed: Option<serde_json::Value> = serde_json::from_slice(&out.stdout).ok();
        match parsed {
            Some(v) if v.get("data").is_some() && v.get("errors").is_none() => break v,
            other => {
                tries += 1;
                if tries >= 5 {
                    bail!("graphql failed: {:?}", other.map(|v| v.to_string()).unwrap_or_else(|| String::from_utf8_lossy(&out.stdout).into_owned()));
                }
                std::thread::sleep(std::time::Duration::from_secs(2 * tries));
            }
        }
    };
    let mut out = Vec::with_capacity(keys.len());
    for (i, (parent, child, bound)) in keys.iter().enumerate() {
        let a = &v["data"][format!("q{i}")];
        if a.is_null() {
            out.push(None);
            continue;
        }
        let bytes = base64::engine::general_purpose::STANDARD.decode(a["objectBcs"].as_str().context("objectBcs")?)?;
        let o: Object = bcs::from_bytes(&bytes)?;
        let digest: sui_types::digests::ObjectDigest = a["digest"].as_str().context("digest")?.parse().map_err(|e| anyhow::anyhow!("digest: {e:?}"))?;
        if o.id() != *child || o.version().value() > *bound || (*parent == ObjectID::ZERO && o.version().value() != *bound) || o.digest() != digest || o.version().value() != a["version"].as_u64().context("version")? {
            bail!("graphql answer for {child} at {bound} does not check out");
        }
        out.push(Some(o));
    }
    Ok(out)
}

fn cmd_children(corpus: &Path, url: &str, out: &Path) -> Result<()> {
    let epochs = load_epochs(corpus)?;
    let packages = Packages::load(corpus, &epochs)?;
    let seqs = manifest_seqs(corpus, COVERED)?;
    eprintln!("children: {} checkpoints with covered system transactions", seqs.len());
    let items: Vec<Item> = seqs
        .par_iter()
        .map(|seq| decode(&corpus.join(format!("chk/{seq}.chk"))).map(|cp| items_of(&cp, &epochs, &packages, covered, 0)))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    eprintln!("children: {} transactions", items.len());
    let exec = Exec::new(&items)?;
    // Answers already fetched (an earlier run's output) are kept: a rerun fetches only new reads.
    let mut answers: HashMap<ChildKey, Option<Object>> = load_children(out)?;
    eprintln!("children: {} answers from {}", answers.len(), out.display());
    let tmp = std::env::temp_dir().join(format!("zui-children-{}.json", std::process::id()));
    let mut round = 0;
    let (equal, differ) = loop {
        round += 1;
        let results: Vec<(bool, Vec<ChildKey>)> = items
            .par_iter()
            .map(|it| -> Result<(bool, Vec<ChildKey>)> {
                let Some((reads, inputs)) = it.resolve(&answers)? else {
                    return Ok((false, it.pending().filter(|k| !answers.contains_key(k)).collect()));
                };
                let store = Store { inputs, packages: &packages, epoch: it.epoch, answers: &answers, missing: Mutex::new(vec![]) };
                let fx = exec.run(it, &store, reads);
                Ok((fx == it.want, store.missing.into_inner().unwrap()))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut need: Vec<ChildKey> = results.iter().flat_map(|(_, m)| m.iter().copied()).collect();
        need.sort();
        need.dedup();
        let equal = results.iter().filter(|(e, _)| *e).count();
        eprintln!("children round {round}: {equal} of {} reproduce the certified effects, {} reads to fetch", items.len(), need.len());
        if need.is_empty() {
            let differ: Vec<String> = items.iter().zip(&results).filter(|(_, (e, _))| !*e).map(|(it, _)| format!("{}/{}", it.seq, it.digest)).collect();
            break (equal, differ);
        }
        // Six requests in flight, 25 objects each (the endpoint caps a query at 5,000 bytes).
        let pool = rayon::ThreadPoolBuilder::new().num_threads(6).build()?;
        for (g, group) in need.chunks(25 * 6 * 20).enumerate() {
            let got: Vec<Vec<(ChildKey, Option<Object>)>> = pool.install(|| {
                group
                    .par_chunks(25)
                    .enumerate()
                    .map(|(k, chunk)| {
                        let t = tmp.with_extension(format!("{g}-{k}.json"));
                        let r = fetch(url, chunk, &t);
                        let _ = std::fs::remove_file(&t);
                        Ok(chunk.iter().copied().zip(r?).collect())
                    })
                    .collect::<Result<Vec<_>>>()
            })?;
            for (key, o) in got.into_iter().flatten() {
                answers.insert(key, o);
            }
            write_children(out, &answers)?;
            eprintln!("  fetched {} of {}", ((g + 1) * 25 * 6 * 20).min(need.len()), need.len());
        }
        if round > 8 {
            bail!("children: reads did not converge");
        }
    };
    let _ = std::fs::remove_file(&tmp);
    for d in differ.iter().take(20) {
        eprintln!("  differs from the certified effects: {d}");
    }
    let (n, present) = write_children(out, &answers)?;
    eprintln!("children: {} answers ({} present), {} of {} transactions reproduce their certified effects, {} differ", n, present, equal, items.len(), differ.len());
    if !differ.is_empty() {
        bail!("{} transactions do not reproduce their certified effects", differ.len());
    }
    Ok(())
}

/// Records sorted by key: parent, child, bound, present, [len, Object BCS].
fn write_children(out: &Path, answers: &HashMap<ChildKey, Option<Object>>) -> Result<(usize, usize)> {
    let sorted: BTreeMap<&ChildKey, &Option<Object>> = answers.iter().collect();
    let mut raw = Vec::new();
    let mut present = 0usize;
    for ((parent, child, bound), o) in &sorted {
        raw.extend_from_slice(parent.as_ref());
        raw.extend_from_slice(child.as_ref());
        raw.extend_from_slice(&bound.to_le_bytes());
        match o {
            None => raw.push(0),
            Some(o) => {
                present += 1;
                raw.push(1);
                let b = bcs::to_bytes(o)?;
                raw.extend_from_slice(&(b.len() as u32).to_le_bytes());
                raw.extend_from_slice(&b);
            }
        }
    }
    let tmp = out.with_extension("tmp");
    std::fs::write(&tmp, zstd::encode_all(&raw[..], 19)?)?;
    std::fs::rename(&tmp, out)?;
    Ok((sorted.len(), present))
}

fn load_children(path: &Path) -> Result<HashMap<ChildKey, Option<Object>>> {
    let mut out = HashMap::new();
    let Ok(z) = std::fs::read(path) else { return Ok(out) };
    let raw = zstd::decode_all(&z[..])?;
    let mut at = 0usize;
    while at < raw.len() {
        let parent = ObjectID::from_bytes(&raw[at..at + 32])?;
        let child = ObjectID::from_bytes(&raw[at + 32..at + 64])?;
        let bound = u64::from_le_bytes(raw[at + 64..at + 72].try_into()?);
        let present = raw[at + 72];
        at += 73;
        let o = if present == 0 {
            None
        } else {
            let n = u32::from_le_bytes(raw[at..at + 4].try_into()?) as usize;
            at += 4;
            let o: Object = bcs::from_bytes(&raw[at..at + n])?;
            at += n;
            Some(o)
        };
        out.insert((parent, child, bound), o);
    }
    Ok(out)
}

/// `bench system --iters N --list <file>`: Mysten's executor on the covered system
/// transactions of the listed checkpoints (inputs prepared outside the timed region).
fn cmd_bench(args: &[String]) -> Result<()> {
    let name = args.first().context("bench name")?.clone();
    if name != "system" {
        bail!("unknown bench {name}");
    }
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
    let files: Vec<PathBuf> = std::fs::read_to_string(list.context("--list")?)?.lines().filter(|l| !l.is_empty()).map(PathBuf::from).collect();
    let corpus = files.first().context("empty list")?.parent().and_then(|p| p.parent()).context("corpus root")?.to_path_buf();
    let epochs = load_epochs(&corpus)?;
    let packages = Packages::load(&corpus, &epochs)?;
    let answers = load_children(&corpus.join("vectors/exec-replay/children-system.bin.zst"))?;
    let mut items = vec![];
    for f in &files {
        items.extend(items_of(&decode(f)?, &epochs, &packages, handled, 119));
    }
    let exec = Exec::new(&items)?;
    let mut resolved = Vec::new();
    for it in &items {
        let (reads, inputs) = it.resolve(&answers)?.context("bench input not in the children part: run `children` first")?;
        resolved.push((reads, Store { inputs, packages: &packages, epoch: it.epoch, answers: &answers, missing: Mutex::new(vec![]) }));
    }
    let mut equal = 0usize;
    for (it, (reads, st)) in items.iter().zip(&resolved) {
        if exec.run(it, st, reads.clone()) == it.want {
            equal += 1;
        }
    }
    let stores: Vec<&Store> = resolved.iter().map(|(_, s)| s).collect();
    let mut times = Vec::new();
    for _ in 0..iters {
        let prepared: Vec<_> = resolved.iter().map(|(r, _)| r.clone()).collect();
        let t = Instant::now();
        for ((it, st), reads) in items.iter().zip(&stores).zip(prepared) {
            std::hint::black_box(exec.run(it, st, reads));
        }
        times.push(t.elapsed().as_nanos() as u64);
    }
    times.sort();
    let med = times[times.len() / 2];
    let units = items.len() as u64;
    println!(
        "{{\"impl\":\"rust\",\"bench\":\"system\",\"unit\":\"tx\",\"units\":{units},\"effects_equal\":{equal},\"iters\":{iters},\"median_ns\":{med},\"min_ns\":{},\"ns_per_unit\":{:.2}}}",
        times[0],
        med as f64 / units.max(1) as f64
    );
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("children") => cmd_children(Path::new(&args[1]), &args[2], Path::new(&args[3])),
        Some("bench") => cmd_bench(&args[1..]),
        _ => bail!("usage: zui-truth-exec-system children <corpus> <graphql url> <out.bin.zst> | bench system --iters N --list <file>"),
    }
}
