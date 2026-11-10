//! zui-store-truth: ground truth and the RocksDB baseline for the deepwave storage lane.
//!
//! Truth is computed only with Mysten's own code at mainnet-v1.83.1 (sui-types): byte ranges are
//! checked by re-encoding every value, object refs come from `Object`, removals from
//! `TransactionEffectsAPI::{deleted, wrapped, unwrapped_then_deleted}` and the live set from
//! `CheckpointData::{latest_live_output_objects, eventually_removed_object_refs_post_version}`.
//! Formats: README.md.
//!
//! Commands:
//!   build <corpus_dir>                         chk/*.chk -> vectors/store-replay/ops/<seq>.ops,
//!                                              vectors/store-replay/live.bin, summary.json
//!   bench <name> --iters N --list <file>       RocksDB as sui-node 1.83.1 configures it (typed-store,
//!                                              AuthorityPerpetualTables options), harness protocol
//!                                              (CONTRACTS.md section 7). Names: ingest, ingest-sync,
//!                                              get-live, get-version, get-tx.

use anyhow::{Context, Result, anyhow, bail};
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use sui_types::base_types::{ObjectID, SequenceNumber};
use sui_types::digests::{ObjectDigest, TransactionDigest, TransactionEffectsDigest};
use sui_types::effects::TransactionEffectsAPI;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::message_envelope::Message;
use sui_types::storage::ObjectKey;
use typed_store::Map;
use typed_store::rocks::{DBMap, DBOptions, MetricConf, ReadWriteOptions, default_db_options, open_cf_opts};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        bail!("usage: zui-store-truth build <corpus_dir> | bench <name> --iters N --list <file>");
    }
    match args[1].as_str() {
        "build" => cmd_build(&args[2..]),
        "bench" => cmd_bench(&args[2..]),
        c => bail!("unknown command {c}"),
    }
}

fn decode_blob(raw: &[u8], what: &dyn std::fmt::Display) -> Result<CheckpointData> {
    if raw.first() != Some(&1) {
        bail!("{what}: not a BCS blob");
    }
    let cp: CheckpointData = bcs::from_bytes(&raw[1..]).with_context(|| format!("decode {what}"))?;
    Ok(cp)
}

fn read_uleb(raw: &[u8], pos: &mut usize) -> Result<u64> {
    let mut v: u64 = 0;
    let mut shift = 0;
    loop {
        let b = *raw.get(*pos).ok_or_else(|| anyhow!("uleb past end"))?;
        *pos += 1;
        v |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(v);
        }
        shift += 7;
        if shift > 63 {
            bail!("uleb too long");
        }
    }
}

type Range = (u32, u32);

struct TxRanges {
    tx: Range,
    effects: Range,
    events: Option<Range>,
    outs: Vec<Range>,
}

struct Ranges {
    summary: Range,
    contents: Range,
    txs: Vec<TxRanges>,
}

/// Exact byte ranges of every stored value in the blob: each one is the re-encoding of the value
/// Mysten's decoder produced, compared with the raw bytes at the cursor.
fn ranges(raw: &[u8], cp: &CheckpointData) -> Result<Ranges> {
    fn take<T: serde::Serialize>(raw: &[u8], pos: &mut usize, v: &T) -> Result<Range> {
        let b = bcs::to_bytes(v)?;
        let end = *pos + b.len();
        if end > raw.len() || raw[*pos..end] != b[..] {
            bail!("re-encoding differs at {}", *pos);
        }
        let r = (*pos as u32, b.len() as u32);
        *pos = end;
        Ok(r)
    }
    let mut pos = 1usize;
    let summary = take(raw, &mut pos, &cp.checkpoint_summary)?;
    let contents = take(raw, &mut pos, &cp.checkpoint_contents)?;
    if read_uleb(raw, &mut pos)? as usize != cp.transactions.len() {
        bail!("tx count");
    }
    let mut txs = Vec::with_capacity(cp.transactions.len());
    for t in &cp.transactions {
        let tx = take(raw, &mut pos, &t.transaction)?;
        let effects = take(raw, &mut pos, &t.effects)?;
        let tag = raw[pos];
        pos += 1;
        let events = match (tag, &t.events) {
            (0, None) => None,
            (1, Some(ev)) => Some(take(raw, &mut pos, ev)?),
            _ => bail!("events option tag"),
        };
        if read_uleb(raw, &mut pos)? as usize != t.input_objects.len() {
            bail!("input count");
        }
        for o in &t.input_objects {
            take(raw, &mut pos, o)?;
        }
        if read_uleb(raw, &mut pos)? as usize != t.output_objects.len() {
            bail!("output count");
        }
        let mut outs = Vec::with_capacity(t.output_objects.len());
        for o in &t.output_objects {
            outs.push(take(raw, &mut pos, o)?);
        }
        txs.push(TxRanges { tx, effects, events, outs });
    }
    if pos != raw.len() {
        bail!("trailing bytes");
    }
    Ok(Ranges { summary, contents, txs })
}

const OPS_MAGIC: &[u8; 4] = b"ZSOP";
const OPS_VERSION: u32 = 1;

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_range(out: &mut Vec<u8>, r: Range) {
    put_u32(out, r.0);
    put_u32(out, r.1);
}

/// The ops file of one checkpoint (README.md): what a store must hold after applying it.
fn ops_file(raw: &[u8], cp: &CheckpointData) -> Result<Vec<u8>> {
    let r = ranges(raw, cp)?;
    let s = cp.checkpoint_summary.data();
    let mut out = Vec::with_capacity(256 + cp.transactions.len() * 256);
    out.extend_from_slice(OPS_MAGIC);
    put_u32(&mut out, OPS_VERSION);
    put_u64(&mut out, s.sequence_number);
    put_u64(&mut out, s.epoch);
    put_range(&mut out, r.summary);
    put_range(&mut out, r.contents);
    put_u32(&mut out, cp.transactions.len() as u32);
    for (t, tr) in cp.transactions.iter().zip(&r.txs) {
        out.extend_from_slice(t.transaction.digest().inner());
        out.extend_from_slice(t.effects.digest().inner());
        put_range(&mut out, tr.tx);
        put_range(&mut out, tr.effects);
        match tr.events {
            Some(ev) => {
                out.push(1);
                put_range(&mut out, ev);
            }
            None => {
                out.push(0);
                put_range(&mut out, (0, 0));
            }
        }
        let deleted = t.effects.deleted();
        let wrapped = t.effects.wrapped();
        let utd = t.effects.unwrapped_then_deleted();
        // Mysten's removed_object_refs_post_version order: deleted, wrapped, unwrapped_then_deleted.
        let removed: Vec<_> = t.removed_object_refs_post_version().collect();
        if removed.len() != deleted.len() + wrapped.len() + utd.len() {
            bail!("removed refs count");
        }
        put_u32(&mut out, t.output_objects.len() as u32);
        put_u32(&mut out, removed.len() as u32);
        for (o, range) in t.output_objects.iter().zip(&tr.outs) {
            out.extend_from_slice(o.id().as_ref());
            put_u64(&mut out, o.version().value());
            out.extend_from_slice(o.digest().inner());
            put_range(&mut out, *range);
        }
        for (i, (id, v, d)) in removed.iter().enumerate() {
            let kind: u8 = if i < deleted.len() {
                0
            } else if i < deleted.len() + wrapped.len() {
                1
            } else {
                2
            };
            out.extend_from_slice(id.as_ref());
            put_u64(&mut out, v.value());
            out.extend_from_slice(d.inner());
            out.push(kind);
        }
    }
    Ok(out)
}

fn list_chk(dir: &Path) -> Result<Vec<(u64, PathBuf)>> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().to_string();
        if let Some(stem) = name.strip_suffix(".chk") {
            if let Ok(seq) = stem.parse::<u64>() {
                v.push((seq, e.path()));
            }
        }
    }
    v.sort();
    Ok(v)
}

type LiveDelta = (Vec<(ObjectID, SequenceNumber, ObjectDigest)>, Vec<ObjectID>);

fn cmd_build(args: &[String]) -> Result<()> {
    if args.len() != 1 {
        bail!("build <corpus_dir>");
    }
    let corpus = PathBuf::from(&args[0]);
    let out_dir = corpus.join("vectors/store-replay");
    let ops_dir = out_dir.join("ops");
    std::fs::create_dir_all(&ops_dir)?;
    let blobs = list_chk(&corpus.join("chk"))?;
    let t0 = Instant::now();
    let mut live: BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)> = BTreeMap::new();
    let (mut puts, mut removes, mut txs) = (0u64, 0u64, 0u64);
    for chunk in blobs.chunks(1024) {
        let deltas: Vec<Result<(LiveDelta, u64, u64, u64)>> = chunk
            .par_iter()
            .map(|(seq, path)| {
                let raw = std::fs::read(path)?;
                let cp = decode_blob(&raw, &path.display())?;
                if cp.checkpoint_summary.data().sequence_number != *seq {
                    bail!("{}: sequence mismatch", path.display());
                }
                let ops = ops_file(&raw, &cp).with_context(|| format!("{}", path.display()))?;
                let tmp = ops_dir.join(format!(".{seq}.ops.part"));
                std::fs::write(&tmp, &ops)?;
                std::fs::rename(&tmp, ops_dir.join(format!("{seq}.ops")))?;
                let p: u64 = cp.transactions.iter().map(|t| t.output_objects.len() as u64).sum();
                let r: u64 = cp.transactions.iter().map(|t| t.removed_object_refs_post_version().count() as u64).sum();
                let ins = cp
                    .latest_live_output_objects()
                    .into_iter()
                    .map(|o| (o.id(), o.version(), o.digest()))
                    .collect();
                let rem = cp.eventually_removed_object_refs_post_version().into_iter().map(|r| r.0).collect();
                Ok(((ins, rem), p, r, cp.transactions.len() as u64))
            })
            .collect();
        // Fold in sequence order, as a node applying these checkpoints in order would.
        for d in deltas {
            let ((ins, rem), p, r, t) = d?;
            for (id, v, dg) in ins {
                live.insert(id, (v, dg));
            }
            for id in rem {
                live.remove(&id);
            }
            puts += p;
            removes += r;
            txs += t;
        }
    }
    let mut lb = Vec::with_capacity(live.len() * 72);
    for (id, (v, d)) in &live {
        lb.extend_from_slice(id.as_ref());
        lb.extend_from_slice(&v.value().to_le_bytes());
        lb.extend_from_slice(d.inner());
    }
    std::fs::write(out_dir.join("live.bin"), &lb)?;
    let first = blobs.first().map(|b| b.0).unwrap_or(0);
    let last = blobs.last().map(|b| b.0).unwrap_or(0);
    let summary = format!(
        "{{\"checkpoints\":{},\"first\":{},\"last\":{},\"txs\":{},\"puts\":{},\"removes\":{},\"live\":{}}}\n",
        blobs.len(),
        first,
        last,
        txs,
        puts,
        removes,
        live.len()
    );
    std::fs::write(out_dir.join("summary.json"), &summary)?;
    print!("{summary}");
    eprintln!("built in {:.1}s", t0.elapsed().as_secs_f64());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Bench: RocksDB through typed-store with the options sui-node 1.83.1 uses for its perpetual
// tables (crates/sui-core/src/authority/authority_store_tables.rs, non-tidehunter build).

const ENV_VAR_OBJECTS_BLOCK_CACHE_SIZE: &str = "OBJECTS_BLOCK_CACHE_MB";
const ENV_VAR_TRANSACTIONS_BLOCK_CACHE_SIZE: &str = "TRANSACTIONS_BLOCK_CACHE_MB";
const ENV_VAR_EFFECTS_BLOCK_CACHE_SIZE: &str = "EFFECTS_BLOCK_CACHE_MB";

fn objects_table_config(db_options: DBOptions) -> DBOptions {
    db_options
        .optimize_for_write_throughput()
        .optimize_for_read(typed_store::rocks::read_size_from_env(ENV_VAR_OBJECTS_BLOCK_CACHE_SIZE).unwrap_or(5 * 1024))
}
fn transactions_table_config(db_options: DBOptions) -> DBOptions {
    db_options
        .optimize_for_write_throughput()
        .optimize_for_point_lookup(typed_store::rocks::read_size_from_env(ENV_VAR_TRANSACTIONS_BLOCK_CACHE_SIZE).unwrap_or(512))
}
fn effects_table_config(db_options: DBOptions) -> DBOptions {
    db_options
        .optimize_for_write_throughput()
        .optimize_for_point_lookup(typed_store::rocks::read_size_from_env(ENV_VAR_EFFECTS_BLOCK_CACHE_SIZE).unwrap_or(1024))
}

/// Value of the objects table: kind byte (0 object, 1 deleted, 2 wrapped) then the object BCS.
/// sui-node stores `StoreObjectWrapper` (Value | Deleted | Wrapped) in the same table.
struct Tables {
    _dir: tempfile::TempDir,
    objects: DBMap<ObjectKey, Vec<u8>>,
    transactions: DBMap<TransactionDigest, Vec<u8>>,
    effects: DBMap<TransactionEffectsDigest, Vec<u8>>,
    events: DBMap<TransactionDigest, Vec<u8>>,
    checkpoints: DBMap<u64, Vec<u8>>,
}

fn open_tables() -> Result<Tables> {
    let base = std::env::var("ZUI_STORE_BENCH_DIR").unwrap_or_else(|_| std::env::temp_dir().display().to_string());
    std::fs::create_dir_all(&base)?;
    let dir = tempfile::Builder::new().prefix("zui-rocks-").tempdir_in(base)?;
    let db_options = default_db_options().optimize_db_for_write_throughput(4, false);
    let cfs: Vec<(&str, typed_store::rocksdb::Options)> = vec![
        ("objects", objects_table_config(db_options.clone()).options),
        ("transactions", transactions_table_config(db_options.clone()).options),
        ("effects", effects_table_config(db_options.clone()).options),
        ("events_2", db_options.options.clone()),
        ("certified_checkpoints", db_options.options.clone()),
    ];
    let db = open_cf_opts(dir.path(), Some(db_options.options.clone()), MetricConf::new("zui-bench"), &cfs)?;
    let rw = ReadWriteOptions::default();
    Ok(Tables {
        objects: DBMap::reopen(&db, Some("objects"), &rw, false)?,
        transactions: DBMap::reopen(&db, Some("transactions"), &rw, false)?,
        effects: DBMap::reopen(&db, Some("effects"), &rw, false)?,
        events: DBMap::reopen(&db, Some("events_2"), &rw, false)?,
        checkpoints: DBMap::reopen(&db, Some("certified_checkpoints"), &rw, false)?,
        _dir: dir,
    })
}

struct BenchTx {
    digest: TransactionDigest,
    effects_digest: TransactionEffectsDigest,
    tx: Vec<u8>,
    effects: Vec<u8>,
    events: Option<Vec<u8>>,
    puts: Vec<(ObjectKey, Vec<u8>)>,
    removes: Vec<(ObjectKey, u8)>,
}

struct BenchCp {
    seq: u64,
    summary_contents: Vec<u8>,
    txs: Vec<BenchTx>,
}

/// Inputs are decoded into plain byte strings before timing, so both sides time only the store.
fn load_inputs(list: &Path) -> Result<Vec<BenchCp>> {
    let text = std::fs::read_to_string(list)?;
    let paths: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    paths
        .par_iter()
        .map(|p| {
            let raw = std::fs::read(p)?;
            let cp = decode_blob(&raw, p)?;
            let r = ranges(&raw, &cp)?;
            let sl = |x: Range| raw[x.0 as usize..(x.0 + x.1) as usize].to_vec();
            let mut summary_contents = sl(r.summary);
            summary_contents.extend_from_slice(&sl(r.contents));
            let mut txs = Vec::new();
            for (t, tr) in cp.transactions.iter().zip(&r.txs) {
                let deleted = t.effects.deleted().len();
                let wrapped = t.effects.wrapped().len();
                txs.push(BenchTx {
                    digest: *t.transaction.digest(),
                    effects_digest: t.effects.digest(),
                    tx: sl(tr.tx),
                    effects: sl(tr.effects),
                    events: tr.events.map(sl),
                    puts: t
                        .output_objects
                        .iter()
                        .zip(&tr.outs)
                        .map(|(o, x)| (ObjectKey(o.id(), o.version()), sl(*x)))
                        .collect(),
                    removes: t
                        .removed_object_refs_post_version()
                        .enumerate()
                        .map(|(i, (id, v, _))| (ObjectKey(id, v), if i >= deleted && i < deleted + wrapped { 2 } else { 1 }))
                        .collect(),
                });
            }
            Ok(BenchCp { seq: cp.checkpoint_summary.data().sequence_number, summary_contents, txs })
        })
        .collect()
}

fn ingest(t: &Tables, cps: &[BenchCp], sync: bool) -> Result<()> {
    for cp in cps {
        let mut b = t.objects.batch();
        b.insert_batch(&t.checkpoints, std::iter::once((cp.seq, &cp.summary_contents)))?;
        for tx in &cp.txs {
            b.insert_batch(&t.transactions, std::iter::once((tx.digest, &tx.tx)))?;
            b.insert_batch(&t.effects, std::iter::once((tx.effects_digest, &tx.effects)))?;
            if let Some(ev) = &tx.events {
                b.insert_batch(&t.events, std::iter::once((tx.digest, ev)))?;
            }
            let mut vals: Vec<(ObjectKey, Vec<u8>)> = Vec::with_capacity(tx.puts.len() + tx.removes.len());
            for (k, bytes) in &tx.puts {
                let mut v = Vec::with_capacity(bytes.len() + 1);
                v.push(0);
                v.extend_from_slice(bytes);
                vals.push((*k, v));
            }
            for (k, kind) in &tx.removes {
                vals.push((*k, vec![*kind]));
            }
            b.insert_batch(&t.objects, vals.into_iter())?;
        }
        if sync {
            let mut wo = typed_store::rocksdb::WriteOptions::default();
            wo.set_sync(true);
            b.write_opt(wo)?;
        } else {
            b.write()?;
        }
    }
    Ok(())
}

/// Deterministic read order shared with the Zig bench: by bytes 16..24 of the key (little-endian
/// u64), then the full key. Unrelated to the stores' key order, so reads are random for both.
fn order_key(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[16..24].try_into().unwrap())
}

/// sui-node's `get_latest_object_or_tombstone`: reverse iterator bounded to the object id.
fn latest(t: &Tables, id: ObjectID) -> Result<Option<(ObjectKey, Vec<u8>)>> {
    let mut it = t.objects.reversed_safe_iter_with_bounds(Some(ObjectKey::min_for_id(&id)), Some(ObjectKey::max_for_id(&id)))?;
    if let Some(Ok((k, v))) = it.next() {
        if k.0 == id {
            return Ok(Some((k, v)));
        }
    }
    Ok(None)
}

struct BenchOut {
    name: String,
    unit: &'static str,
    units: u64,
    passes: Vec<u128>,
}

impl BenchOut {
    fn print(&mut self) {
        self.passes.sort();
        let med = self.passes[self.passes.len() / 2];
        println!(
            "{{\"impl\":\"rust\",\"bench\":\"{}\",\"unit\":\"{}\",\"units\":{},\"iters\":{},\"median_ns\":{},\"min_ns\":{},\"ns_per_unit\":{:.2}}}",
            self.name,
            self.unit,
            self.units,
            self.passes.len(),
            med,
            self.passes[0],
            med as f64 / self.units.max(1) as f64
        );
        std::io::stdout().flush().ok();
    }
}

fn cmd_bench(args: &[String]) -> Result<()> {
    let name = args.first().ok_or_else(|| anyhow!("bench <name> --iters N --list <file>"))?.clone();
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
            a => bail!("unknown arg {a}"),
        }
    }
    let list = list.ok_or_else(|| anyhow!("--list required"))?;
    // typed-store's metrics spawn onto a Tokio runtime, as inside sui-node.
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build()?;
    let _guard = rt.enter();
    let cps = load_inputs(&list)?;
    let mut out = match name.as_str() {
        "ingest" | "ingest-sync" => {
            let sync = name == "ingest-sync";
            let mut passes = Vec::new();
            for pass in 0..=iters {
                let t = open_tables()?;
                let t0 = Instant::now();
                ingest(&t, &cps, sync)?;
                let ns = t0.elapsed().as_nanos();
                if pass > 0 {
                    passes.push(ns);
                }
                drop(t);
            }
            BenchOut { name, unit: "checkpoint", units: cps.len() as u64, passes }
        }
        "get-live" | "get-version" | "get-tx" => {
            let t = open_tables()?;
            ingest(&t, &cps, false)?;
            let t = Arc::new(t);
            let mut passes = Vec::new();
            let units;
            match name.as_str() {
                "get-live" => {
                    let mut ids: Vec<ObjectID> = cps
                        .iter()
                        .flat_map(|c| c.txs.iter())
                        .flat_map(|t| t.puts.iter().map(|p| p.0.0).chain(t.removes.iter().map(|r| r.0.0)))
                        .collect();
                    ids.sort_by(|a, b| (order_key(a.as_ref()), a).cmp(&(order_key(b.as_ref()), b)));
                    ids.dedup();
                    units = ids.len() as u64;
                    for pass in 0..=iters {
                        let t0 = Instant::now();
                        let mut acc = 0u64;
                        for id in &ids {
                            let (k, v) = latest(&t, *id)?.ok_or_else(|| anyhow!("missing {id}"))?;
                            acc = acc.wrapping_add(k.1.value() ^ v.len() as u64);
                        }
                        std::hint::black_box(acc);
                        if pass > 0 {
                            passes.push(t0.elapsed().as_nanos());
                        }
                    }
                }
                "get-version" => {
                    let mut keys: Vec<ObjectKey> =
                        cps.iter().flat_map(|c| c.txs.iter()).flat_map(|t| t.puts.iter().map(|p| p.0)).collect();
                    keys.sort_by(|a, b| (order_key(a.0.as_ref()), a).cmp(&(order_key(b.0.as_ref()), b)));
                    keys.dedup();
                    units = keys.len() as u64;
                    for pass in 0..=iters {
                        let t0 = Instant::now();
                        let mut acc = 0u64;
                        for k in &keys {
                            let v = t.objects.get(k)?.ok_or_else(|| anyhow!("missing {k:?}"))?;
                            acc = acc.wrapping_add(v.len() as u64);
                        }
                        std::hint::black_box(acc);
                        if pass > 0 {
                            passes.push(t0.elapsed().as_nanos());
                        }
                    }
                }
                _ => {
                    let mut ds: Vec<TransactionDigest> = cps.iter().flat_map(|c| c.txs.iter().map(|t| t.digest)).collect();
                    ds.sort_by(|a, b| (order_key(a.inner()), a).cmp(&(order_key(b.inner()), b)));
                    ds.dedup();
                    units = ds.len() as u64;
                    for pass in 0..=iters {
                        let t0 = Instant::now();
                        let mut acc = 0u64;
                        for d in &ds {
                            let v = t.transactions.get(d)?.ok_or_else(|| anyhow!("missing {d}"))?;
                            acc = acc.wrapping_add(v.len() as u64);
                        }
                        std::hint::black_box(acc);
                        if pass > 0 {
                            passes.push(t0.elapsed().as_nanos());
                        }
                    }
                }
            }
            BenchOut { name, unit: "read", units, passes }
        }
        n => bail!("unknown bench {n}"),
    };
    out.print();
    Ok(())
}
