// deepwave validator speed bench, Mysten side (docs/VALIDATOR-SPEED.md): stages 1, 5 and 6 on real
// mainnet checkpoints from the corpus, with sui 1.83.1's own crates. In process, no network.
//
//   zui-val-bench intake   --list L --out D [--reps N]   user transaction signature verification
//   zui-val-bench ckpt     --list L --out D [--reps N]   checkpoint contents + summary building
//   zui-val-bench versions --list L --out D [--reps N]   shared-object versions + congestion control
//
// L: corpus .chk paths, one per line (the corpus root is two levels above them). D: output dir,
// gets rust-<stage>.jsonl (timing lines, also on stdout) and rust-<stage>.out (the canonical
// output lines deepwave must reproduce byte for byte; their Blake2b-256 is the "out" field).
//
// What each stage times (inputs are decoded and prepared outside the timed region):
//   intake    `verify_sender_signed_data_message_signatures` (what SignatureVerifier::verify_tx
//             runs for a user transaction at intake), per transaction. cold: a fresh zkLogin
//             inputs cache per transaction; warm: one shared cache, after a warm-up pass; 4
//             threads: the item list split in 4 contiguous parts. VerifyParams and JWKs from the
//             checkpoint's sig-corpus header (the validators' state at that checkpoint).
//   ckpt      what CheckpointBuilder::create_checkpoints does once the effects are in memory:
//             CausalOrder::order_for_checkpoint per commit group (sui-core's own file, compiled
//             here through #[path] because the module is pub(crate)), CheckpointContents
//             (V2 when address_aliases is on), rolling gas, randomness rounds, artifacts digest,
//             CheckpointSummary::new, BCS of both and their digests; per checkpoint.
//   versions  per checkpoint as one consensus commit: SharedObjVerManager::
//             assign_versions_for_certificate for every schedulable (consensus commit prologue,
//             user and system transactions with shared inputs) against the next-version map, as
//             assign_versions_from_consensus does after get_or_init (here: a map standing in for
//             the epoch table, objects start at their initial shared version); every 97th
//             shared-object transaction is cancelled for congestion on its first shared input and
//             every 211th for a failed DKG. Then congestion control over the same commit:
//             ExecutionTimeEstimator::get_estimate (no observations: default durations),
//             compute_tx_start_at_cost, the deferral test and bump_object_execution_cost, then the
//             commit's accumulated debts, which seed the next commit's tracker. (ConsensusCommitInfo
//             is pub(crate), so the budget arithmetic of should_defer/finish_commit is restated
//             in `defer_test`/`debts`.)

#[path = "../../sui-core/src/checkpoints/causal_order.rs"]
#[allow(dead_code, unused_imports)]
mod causal_order;

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use fastcrypto::hash::{Blake2b256, HashFunction};
use fastcrypto_zkp::bn254::zk_login::{JWK, JwkId, OIDCProvider};
use fastcrypto_zkp::bn254::zk_login_api::ZkLoginEnv;
use nonempty::NonEmpty;
use serde_json::Value;
use sui_core::authority::authority_per_epoch_store::{AuthorityPerEpochStore, CancelConsensusCertificateReason};
use sui_core::authority::execution_time_estimator::ExecutionTimeEstimator;
use sui_core::authority::shared_object_congestion_tracker::SharedObjectCongestionTracker;
use sui_core::authority::shared_object_version_manager::{AssignedVersions, Schedulable, SharedObjVerManager};
use sui_core::authority::test_authority_builder::TestAuthorityBuilder;
use sui_protocol_config::{Chain, PerObjectCongestionControlMode, ProtocolConfig, ProtocolVersion};
use sui_types::base_types::{ObjectID, SequenceNumber, SuiAddress, TransactionDigest};
use sui_types::committee::Committee;
use sui_types::digests::ZKLoginInputsDigest;
use sui_types::effects::{TransactionEffects, TransactionEffectsAPI};
use sui_types::executable_transaction::{CertificateProof, ExecutableTransaction, VerifiedExecutableTransaction};
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::gas::GasCostSummary;
use sui_types::message_envelope::Message;
use sui_types::messages_checkpoint::{CheckpointArtifacts, CheckpointContents, CheckpointSummary};
use sui_types::signature::{GenericSignature, VerifyParams};
use sui_types::signature_verification::{VerifiedDigestCache, verify_sender_signed_data_message_signatures};
use sui_types::transaction::{SenderSignedData, TransactionDataAPI, TransactionKind};
use sui_types::{SUI_ACCUMULATOR_ROOT_OBJECT_ID, SUI_FORWARDING_ADDRESS_REGISTRY_OBJECT_ID};

// ------------------------------------------------------------------------------------- common

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        write!(s, "{:02x}", x).unwrap();
    }
    s
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        bail!("odd hex");
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!(e))).collect()
}

fn digest_hex(text: &str) -> String {
    hex(&Blake2b256::digest(text.as_bytes()).digest)
}

fn pct(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let k = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[k.clamp(1, sorted.len()) - 1]
}

struct Args {
    list: PathBuf,
    out: PathBuf,
    reps: usize,
}

fn args(rest: &[String]) -> Result<Args> {
    let mut list = None;
    let mut out = None;
    let mut reps = 3usize;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--list" => list = Some(PathBuf::from(&rest[i + 1])),
            "--out" => out = Some(PathBuf::from(&rest[i + 1])),
            "--reps" => reps = rest[i + 1].parse()?,
            o => bail!("unknown argument {o}"),
        }
        i += 2;
    }
    Ok(Args { list: list.ok_or_else(|| anyhow!("--list"))?, out: out.ok_or_else(|| anyhow!("--out"))?, reps })
}

fn read_list(p: &Path) -> Result<Vec<PathBuf>> {
    let t = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
    Ok(t.lines().filter(|l| !l.trim().is_empty()).map(PathBuf::from).collect())
}

fn seq_of(p: &Path) -> Result<u64> {
    Ok(p.file_stem().and_then(|s| s.to_str()).ok_or_else(|| anyhow!("name"))?.parse()?)
}

fn load_chk(p: &Path) -> Result<CheckpointData> {
    let raw = std::fs::read(p).with_context(|| format!("read {}", p.display()))?;
    if raw.first() != Some(&1) {
        bail!("{}: not a version-1 .chk blob", p.display());
    }
    Ok(bcs::from_bytes(&raw[1..])?)
}

fn corpus_root(files: &[PathBuf]) -> Result<PathBuf> {
    files.first().and_then(|f| f.parent()).and_then(|p| p.parent()).map(Path::to_path_buf).ok_or_else(|| anyhow!("empty list"))
}

/// Protocol version per epoch, from $ZUI_CORPUS/epochs.jsonl.
fn load_pv(root: &Path) -> Result<Vec<u64>> {
    let text = std::fs::read_to_string(root.join("epochs.jsonl"))?;
    let mut v = Vec::new();
    for l in text.lines().filter(|l| !l.is_empty()) {
        let e: Value = serde_json::from_str(l)?;
        let ep = e["epoch"].as_u64().ok_or_else(|| anyhow!("epoch"))? as usize;
        if ep != v.len() {
            bail!("epochs.jsonl not contiguous at {ep}");
        }
        v.push(e["pv"].as_u64().ok_or_else(|| anyhow!("pv"))?);
    }
    Ok(v)
}

/// One timing record. `items` are per-item ns (may be empty for wall-only parallel runs).
struct Rec<'a> {
    stage: &'a str,
    case: &'a str,
    mode: &'a str,
    threads: usize,
    unit: &'a str,
    items: Vec<u64>,
    count: u64,
    wall_ns: u64,
    out: &'a str,
}

fn emit(log: &mut String, r: Rec) {
    let mut t = r.items.clone();
    t.sort_unstable();
    let sum: u64 = t.iter().sum();
    let mean = if t.is_empty() { r.wall_ns as f64 / r.count.max(1) as f64 } else { sum as f64 / t.len() as f64 };
    let per_s = if r.wall_ns > 0 { r.count as f64 * 1e9 / r.wall_ns as f64 } else { 0.0 };
    let s = format!(
        "{{\"impl\":\"rust\",\"stage\":\"{}\",\"case\":\"{}\",\"mode\":\"{}\",\"threads\":{},\"unit\":\"{}\",\"items\":{},\"p50_ns\":{},\"p99_ns\":{},\"mean_ns\":{:.1},\"per_s\":{:.1},\"out\":\"{}\"}}",
        r.stage, r.case, r.mode, r.threads, r.unit, r.count, pct(&t, 50.0), pct(&t, 99.0), mean, per_s, r.out
    );
    println!("{s}");
    log.push_str(&s);
    log.push('\n');
}

/// Runs `f` over `n` items split in `threads` contiguous parts; best wall time of `reps`.
fn par_wall<F: Fn(usize) + Sync>(n: usize, threads: usize, reps: usize, f: F) -> u64 {
    let mut best = u64::MAX;
    for _ in 0..reps.max(1) {
        let chunk = n.div_ceil(threads).max(1);
        let t0 = Instant::now();
        std::thread::scope(|s| {
            let mut start = 0;
            while start < n {
                let end = (start + chunk).min(n);
                let f = &f;
                s.spawn(move || {
                    for i in start..end {
                        f(i);
                    }
                });
                start = end;
            }
        });
        best = best.min(t0.elapsed().as_nanos() as u64);
    }
    best
}

fn write_outputs(out: &Path, stage: &str, log: &str, lines: &str) -> Result<()> {
    std::fs::create_dir_all(out)?;
    std::fs::write(out.join(format!("rust-{stage}.jsonl")), log)?;
    std::fs::write(out.join(format!("rust-{stage}.out")), lines)?;
    Ok(())
}

// ------------------------------------------------------------------------------- 1. intake

struct Header {
    epoch: u64,
    params: Arc<VerifyParams>,
    /// tx index -> pinned aliases
    aliases: HashMap<u32, Vec<(SuiAddress, NonEmpty<SuiAddress>)>>,
}

fn addr(s: &str) -> Result<SuiAddress> {
    let b = unhex(s)?;
    Ok(SuiAddress::from_bytes(b).map_err(|e| anyhow!("{e}"))?)
}

/// The checkpoint's sig-corpus truth: epoch, verify flags, the validators' JWKs, pinned aliases.
fn load_header(root: &Path, seq: u64) -> Result<Header> {
    let p = root.join("vectors/sig-corpus").join(format!("{seq}.jsonl.zst"));
    let mut text = String::new();
    zstd::stream::read::Decoder::new(std::fs::File::open(&p).with_context(|| format!("open {}", p.display()))?)?.read_to_string(&mut text)?;
    let mut lines = text.lines();
    let h: Value = serde_json::from_str(lines.next().ok_or_else(|| anyhow!("empty sig-corpus"))?)?;
    let f = &h["flags"];
    let b = |k: &str| f[k].as_bool().unwrap_or(false);
    let mut jwks = imbl::HashMap::new();
    if let Some(list) = h["jwks"].as_array() {
        for j in list {
            let s = |k: &str| j[k].as_str().unwrap_or("").to_string();
            jwks.insert(JwkId::new(s("iss"), s("kid")), JWK { kty: s("kty"), e: s("e"), n: s("n"), alg: s("alg") });
        }
    }
    let params = VerifyParams {
        oidc_provider_jwks: jwks,
        supported_providers: f["zklogin_supported_providers"]
            .as_array()
            .map(|a| a.iter().map(|s| <OIDCProvider as std::str::FromStr>::from_str(s.as_str().unwrap()).expect("provider")).collect())
            .unwrap_or_default(),
        zk_login_env: ZkLoginEnv::Prod,
        zklogin_circuit_mode: f["zklogin_circuit_mode"].as_u64().unwrap_or(0),
        verify_legacy_zklogin_address: b("verify_legacy_zklogin_address"),
        accept_zklogin_in_multisig: b("accept_zklogin_in_multisig"),
        accept_passkey_in_multisig: b("accept_passkey_in_multisig"),
        accept_mldsa65_in_multisig: b("accept_mldsa65_in_multisig"),
        zklogin_max_epoch_upper_bound_delta: f["zklogin_max_epoch_upper_bound_delta"].as_u64(),
        additional_multisig_checks: b("additional_multisig_checks"),
        validate_zklogin_public_identifier: b("validate_zklogin_public_identifier"),
    };
    let mut aliases = HashMap::new();
    for l in lines {
        if !l.starts_with("{\"k\":\"tx\"") {
            continue;
        }
        let v: Value = serde_json::from_str(l)?;
        let Some(list) = v["aliases"].as_array() else { continue };
        let mut out = vec![];
        for pair in list {
            let signer = addr(pair[0].as_str().unwrap())?;
            let al: Vec<SuiAddress> = pair[1].as_array().unwrap().iter().map(|x| addr(x.as_str().unwrap())).collect::<Result<_>>()?;
            out.push((signer, NonEmpty::from_vec(al).ok_or_else(|| anyhow!("empty alias set"))?));
        }
        aliases.insert(v["tx"].as_u64().unwrap() as u32, out);
    }
    Ok(Header { epoch: h["epoch"].as_u64().ok_or_else(|| anyhow!("epoch"))?, params: Arc::new(params), aliases })
}

/// Class of a transaction: its most expensive signature scheme (by flag byte).
pub fn sig_class(sigs: &[GenericSignature]) -> &'static str {
    let rank = |f: u8| match f {
        0x05 => 5, // zkLogin
        0x03 => 4, // multisig
        0x06 => 3, // passkey
        0x02 => 2, // secp256r1
        0x01 => 1, // secp256k1
        _ => 0,    // ed25519 (0x00), others
    };
    let mut best = 0;
    for s in sigs {
        let b: &[u8] = s.as_ref();
        best = best.max(rank(b[0]));
    }
    match best {
        5 => "zklogin",
        4 => "multisig",
        3 => "passkey",
        2 => "secp256r1",
        1 => "secp256k1",
        _ => "ed25519",
    }
}

struct Item {
    seq: u64,
    tx: u32,
    ssd: SenderSignedData,
    epoch: u64,
    params: Arc<VerifyParams>,
    aliases: Vec<(SuiAddress, NonEmpty<SuiAddress>)>,
    class: &'static str,
}

/// The timed call: Mysten's verify path only, no output formatting.
fn verify_timed(it: &Item, cache: Arc<VerifiedDigestCache<ZKLoginInputsDigest>>) -> bool {
    verify_sender_signed_data_message_signatures(&it.ssd, it.epoch, &it.params, cache, it.aliases.clone()).is_ok()
}

fn verify_item(it: &Item, cache: Arc<VerifiedDigestCache<ZKLoginInputsDigest>>) -> String {
    match verify_sender_signed_data_message_signatures(&it.ssd, it.epoch, &it.params, cache, it.aliases.clone()) {
        Ok(idx) => format!("{} {} ok {}", it.seq, it.tx, idx.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",")),
        Err(_) => format!("{} {} err", it.seq, it.tx),
    }
}

fn intake(a: &Args) -> Result<()> {
    let files = read_list(&a.list)?;
    let root = corpus_root(&files)?;
    let mut items = vec![];
    for f in &files {
        let seq = seq_of(f)?;
        let cp = load_chk(f)?;
        let h = load_header(&root, seq)?;
        for (i, t) in cp.transactions.iter().enumerate() {
            let ssd = t.transaction.data();
            if ssd.intent_message().value.is_system_tx() {
                continue;
            }
            items.push(Item {
                seq,
                tx: i as u32,
                class: sig_class(ssd.tx_signatures()),
                ssd: ssd.clone(),
                epoch: h.epoch,
                params: h.params.clone(),
                aliases: h.aliases.get(&(i as u32)).cloned().unwrap_or_default(),
            });
        }
    }
    eprintln!("intake: {} user transactions from {} checkpoints", items.len(), files.len());
    let mut log = String::new();
    // reference outputs (cold path)
    let outs: Vec<String> = items.iter().map(|it| verify_item(it, Arc::new(VerifiedDigestCache::new_empty()))).collect();
    let mut lines = String::new();
    for o in &outs {
        lines.push_str(o);
        lines.push('\n');
    }
    let out_digest = digest_hex(&lines);
    let classes = ["all", "ed25519", "secp256k1", "secp256r1", "multisig", "zklogin", "passkey"];

    // cold, 1 thread: a fresh zkLogin cache per transaction
    let mut best_cold: Vec<u64> = vec![u64::MAX; items.len()];
    for _ in 0..a.reps.max(1) {
        for (k, it) in items.iter().enumerate() {
            let cache = Arc::new(VerifiedDigestCache::new_empty());
            let t0 = Instant::now();
            std::hint::black_box(verify_timed(it, cache));
            best_cold[k] = best_cold[k].min(t0.elapsed().as_nanos() as u64);
        }
    }
    // warm, 1 thread: one cache shared by every transaction, after a warm-up pass
    let cache = Arc::new(VerifiedDigestCache::new_empty());
    for it in &items {
        std::hint::black_box(verify_timed(it, cache.clone()));
    }
    let mut best_warm: Vec<u64> = vec![u64::MAX; items.len()];
    for _ in 0..a.reps.max(1) {
        for (k, it) in items.iter().enumerate() {
            let t0 = Instant::now();
            std::hint::black_box(verify_timed(it, cache.clone()));
            best_warm[k] = best_warm[k].min(t0.elapsed().as_nanos() as u64);
        }
    }
    for (mode, times) in [("cold", &best_cold), ("warm", &best_warm)] {
        for c in classes {
            let sel: Vec<u64> = items.iter().zip(times.iter()).filter(|(it, _)| c == "all" || it.class == c).map(|(_, t)| *t).collect();
            if sel.is_empty() {
                continue;
            }
            let n = sel.len() as u64;
            let wall: u64 = sel.iter().sum();
            emit(&mut log, Rec { stage: "intake", case: c, mode, threads: 1, unit: "tx", items: sel, count: n, wall_ns: wall, out: if c == "all" { &out_digest } else { "" } });
        }
    }
    // 4 threads (and 1 for the same harness): throughput, cold and warm
    for threads in [1usize, 4] {
        let w = par_wall(items.len(), threads, a.reps, |k| {
            std::hint::black_box(verify_timed(&items[k], Arc::new(VerifiedDigestCache::new_empty())));
        });
        emit(&mut log, Rec { stage: "intake", case: "all", mode: "cold-par", threads, unit: "tx", items: vec![], count: items.len() as u64, wall_ns: w, out: &out_digest });
        let w = par_wall(items.len(), threads, a.reps, |k| {
            std::hint::black_box(verify_timed(&items[k], cache.clone()));
        });
        emit(&mut log, Rec { stage: "intake", case: "all", mode: "warm-par", threads, unit: "tx", items: vec![], count: items.len() as u64, wall_ns: w, out: &out_digest });
    }
    let mut counts = BTreeMap::new();
    for it in &items {
        *counts.entry(it.class).or_insert(0u64) += 1;
    }
    eprintln!("intake classes: {counts:?}; errors: {}", outs.iter().filter(|o| o.ends_with("err")).count());
    write_outputs(&a.out, "intake", &log, &lines)
}

// --------------------------------------------------------------------------------- 5. ckpt

#[derive(PartialEq, Clone, Copy)]
enum Class {
    Prologue,
    Programmable,
    ProgrammableSystem,
    Randomness,
    Other,
}

fn class_of(k: &TransactionKind) -> Class {
    match k {
        TransactionKind::ConsensusCommitPrologue(_)
        | TransactionKind::ConsensusCommitPrologueV2(_)
        | TransactionKind::ConsensusCommitPrologueV3(_)
        | TransactionKind::ConsensusCommitPrologueV4(_) => Class::Prologue,
        TransactionKind::ProgrammableTransaction(_) => Class::Programmable,
        TransactionKind::ProgrammableSystemTransaction(_) => Class::ProgrammableSystem,
        TransactionKind::RandomnessStateUpdate(_) => Class::Randomness,
        _ => Class::Other,
    }
}

struct Ckpt {
    seq: u64,
    cfg: ProtocolConfig,
    summary: CheckpointSummary,
    prev: CheckpointSummary,
    effects: Vec<TransactionEffects>,
    classes: Vec<Class>,
    sigs: Vec<Vec<(GenericSignature, Option<SequenceNumber>)>>,
    rounds: HashMap<TransactionDigest, sui_types::crypto::RandomnessRound>,
    want_contents: Vec<u8>,
    want_summary: Vec<u8>,
}

/// Commit groups to causally order, as deepwave's replay: split at each prologue, settlement effects
/// at the end of a group excluded; none when the protocol skips the sort or randomness chunks
/// make the group boundaries unknown.
fn groups(c: &Ckpt) -> Vec<(usize, usize)> {
    let mut out = vec![];
    if c.cfg.disable_effects_tx_dependencies() {
        return out;
    }
    let has_random = c.classes.iter().any(|k| *k == Class::Randomness);
    let has_settlement = c.classes.iter().any(|k| *k == Class::ProgrammableSystem);
    if has_random && !has_settlement {
        return out;
    }
    let n = c.effects.len();
    let body_end = if c.summary.end_of_epoch_data.is_some() { n - 1 } else { n };
    let mut start = 0;
    let mut i = 0;
    while i <= body_end {
        let boundary = i == body_end || (i > start && c.classes[i] == Class::Prologue);
        if boundary {
            if i > start {
                let mut end = i;
                while end > start && c.classes[end - 1] == Class::ProgrammableSystem {
                    end -= 1;
                }
                out.push((start, end));
            }
            start = i;
        }
        i += 1;
    }
    out
}

/// Inputs of the causal sort per commit group: the group's effects fed reversed (the prologue kept
/// first), as owned vectors the way CausalOrder takes them. Built outside the clock: in the node
/// the effects are read from the store into owned values anyway.
type Groups = Vec<(usize, usize, Option<TransactionDigest>, Vec<TransactionEffects>)>;

fn prep_groups(c: &Ckpt) -> Groups {
    groups(c)
        .into_iter()
        .map(|(s, e)| {
            let g = &c.effects[s..e];
            let ccp = (c.classes[s] == Class::Prologue).then(|| *g[0].transaction_digest());
            let keep = ccp.is_some() as usize;
            let mut rev: Vec<TransactionEffects> = Vec::with_capacity(g.len());
            if keep == 1 {
                rev.push(g[0].clone());
            }
            rev.extend(g[keep..].iter().rev().cloned());
            (s, e, ccp, rev)
        })
        .collect()
}

/// The timed part: order, contents, summary, BCS and digests. Returns (output line, order ok).
fn build_ckpt(c: &Ckpt, groups: Groups) -> (String, bool, Vec<u8>, Vec<u8>) {
    // causal order per commit group
    let mut order_ok = true;
    for (s, e, ccp, rev) in groups {
        let g = &c.effects[s..e];
        let got = causal_order::CausalOrder::order_for_checkpoint(rev, ccp, &c.cfg);
        order_ok &= got.iter().zip(g.iter()).all(|(a, b)| a.transaction_digest() == b.transaction_digest());
    }
    let effects = &c.effects;
    let contents = if c.cfg.address_aliases() {
        CheckpointContents::new_v2(effects, c.sigs.clone())
    } else {
        CheckpointContents::new_with_digests_and_signatures(
            effects.iter().map(TransactionEffects::execution_digests),
            c.sigs.iter().map(|s| s.iter().map(|(g, _)| g.clone()).collect()).collect(),
        )
    };
    let n = effects.len();
    let eoe = c.summary.end_of_epoch_data.clone();
    let gas_effects = if eoe.is_some() { &effects[..n - 1] } else { &effects[..] };
    let cur = GasCostSummary::new_from_txn_effects(gas_effects.iter());
    let rolling = if c.prev.epoch == c.summary.epoch {
        let p = &c.prev.epoch_rolling_gas_cost_summary;
        GasCostSummary::new(
            p.computation_cost + cur.computation_cost,
            p.storage_cost + cur.storage_cost,
            p.storage_rebate + cur.storage_rebate,
            p.non_refundable_storage_fee + cur.non_refundable_storage_fee,
        )
    } else {
        cur
    };
    let network_total = c.prev.network_total_transactions + contents.size() as u64;
    let rounds: Vec<_> = effects.iter().filter_map(|e| c.rounds.get(e.transaction_digest())).copied().collect();
    let commitments = if c.cfg.include_checkpoint_artifacts_digest_in_summary() {
        vec![CheckpointArtifacts::from(&effects[..]).digest().expect("artifacts digest").into()]
    } else {
        vec![]
    };
    let summary = CheckpointSummary::new(
        &c.cfg,
        c.summary.epoch,
        c.seq,
        network_total,
        &contents,
        Some(c.prev.digest()),
        rolling,
        eoe,
        c.summary.timestamp_ms,
        rounds,
        commitments,
    );
    let cb = bcs::to_bytes(&contents).unwrap();
    let sb = bcs::to_bytes(&summary).unwrap();
    let line = format!("{} {} {} {}", c.seq, hex(contents.digest().inner()), hex(summary.digest().inner()), order_ok as u8);
    (line, order_ok, cb, sb)
}

fn ckpt(a: &Args) -> Result<()> {
    let files = read_list(&a.list)?;
    let root = corpus_root(&files)?;
    let pv = load_pv(&root)?;
    let mut cps = vec![];
    let mut skipped = 0;
    for f in &files {
        let seq = seq_of(f)?;
        let prev_path = f.with_file_name(format!("{}.chk", seq.saturating_sub(1)));
        if seq == 0 || !prev_path.exists() {
            skipped += 1;
            continue;
        }
        let cp = load_chk(f)?;
        let prev = load_chk(&prev_path)?;
        let summary = cp.checkpoint_summary.data().clone();
        let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(pv[summary.epoch as usize]), Chain::Mainnet);
        if !cfg.prepend_prologue_tx_in_consensus_commit_in_checkpoints() {
            skipped += 1;
            continue;
        }
        let n = cp.transactions.len();
        let mut rounds = HashMap::new();
        let mut classes = vec![];
        for t in &cp.transactions {
            let k = t.transaction.data().intent_message().value.kind();
            if let TransactionKind::RandomnessStateUpdate(r) = k {
                rounds.insert(*t.effects.transaction_digest(), r.randomness_round);
            }
            classes.push(class_of(k));
        }
        let sigs = (0..n).map(|i| cp.checkpoint_contents.inner().user_signatures(i).unwrap_or_default()).collect();
        cps.push(Ckpt {
            seq,
            cfg,
            want_contents: bcs::to_bytes(&cp.checkpoint_contents)?,
            want_summary: bcs::to_bytes(&summary)?,
            summary,
            prev: prev.checkpoint_summary.data().clone(),
            effects: cp.transactions.iter().map(|t| t.effects.clone()).collect(),
            classes,
            sigs,
            rounds,
        });
    }
    eprintln!("ckpt: {} checkpoints ({} skipped: no predecessor in the corpus or pre-prologue protocol)", cps.len(), skipped);
    let mut lines = String::new();
    let (mut bad_c, mut bad_s, mut bad_o) = (0, 0, 0);
    for c in &cps {
        let (l, ok, cb, sb) = build_ckpt(c, prep_groups(c));
        bad_o += (!ok) as u32;
        bad_c += (cb != c.want_contents) as u32;
        bad_s += (sb != c.want_summary) as u32;
        lines.push_str(&l);
        lines.push('\n');
    }
    eprintln!("ckpt: vs recorded mainnet bytes: contents differ {bad_c}, summary differ {bad_s}, order differ {bad_o}");
    let out_digest = digest_hex(&lines);
    let mut best: Vec<u64> = vec![u64::MAX; cps.len()];
    for _ in 0..a.reps.max(1) {
        for (k, c) in cps.iter().enumerate() {
            let g = prep_groups(c);
            let t0 = Instant::now();
            std::hint::black_box(build_ckpt(c, g));
            best[k] = best[k].min(t0.elapsed().as_nanos() as u64);
        }
    }
    let ntx: u64 = cps.iter().map(|c| c.effects.len() as u64).sum();
    let mut log = String::new();
    let wall: u64 = best.iter().sum();
    emit(&mut log, Rec { stage: "ckpt", case: "all", mode: "build", threads: 1, unit: "checkpoint", items: best, count: cps.len() as u64, wall_ns: wall, out: &out_digest });
    eprintln!("ckpt: {ntx} transactions, {:.1} ns/tx", wall as f64 / ntx.max(1) as f64);
    for threads in [1usize, 4] {
        // the group inputs of every checkpoint are made before each timed pass
        let mut w = u64::MAX;
        for _ in 0..a.reps.max(1) {
            let pre: Vec<std::sync::Mutex<Option<Groups>>> = cps.iter().map(|c| std::sync::Mutex::new(Some(prep_groups(c)))).collect();
            w = w.min(par_wall(cps.len(), threads, 1, |k| {
                let g = pre[k].lock().unwrap().take().unwrap_or_default();
                std::hint::black_box(build_ckpt(&cps[k], g));
            }));
        }
        emit(&mut log, Rec { stage: "ckpt", case: "all", mode: "build-par", threads, unit: "checkpoint", items: vec![], count: cps.len() as u64, wall_ns: w, out: &out_digest });
    }
    write_outputs(&a.out, "ckpt", &log, &lines)
}

// ----------------------------------------------------------------------------- 6. versions

struct Commit {
    seq: u64,
    scheds: Vec<Schedulable<VerifiedExecutableTransaction>>,
    cancelled: BTreeMap<TransactionDigest, CancelConsensusCertificateReason>,
    /// indices into `scheds` of user programmable transactions (congestion control input)
    user: Vec<usize>,
}

fn key_of(s: &Schedulable<VerifiedExecutableTransaction>) -> String {
    match s {
        Schedulable::Transaction(t) => hex(t.digest().inner()),
        Schedulable::ConsensusCommitPrologue(e, r, i) => format!("ccp:{e}:{r}:{i}"),
        Schedulable::RandomnessStateUpdate(e, r) => format!("rand:{e}:{}", r.0),
        Schedulable::AccumulatorSettlement(e, h) => format!("settle:{e}:{h}"),
    }
}

fn assigned_line(seq: u64, i: usize, key: &str, a: &AssignedVersions) -> String {
    let mut s = format!("{seq} {i} {key} s=");
    for (k, ((id, isv), v)) in a.shared_object_versions.iter().enumerate() {
        if k > 0 {
            s.push(',');
        }
        write!(s, "{}:{}:{}", hex(id.as_ref()), isv.value(), v.value()).unwrap();
    }
    let sv = |id| a.system_object_versions.get(&id).map(|v| format!("{}:{}", v.initial_shared_version.value(), v.version.value())).unwrap_or_else(|| "-".into());
    write!(s, " acc={} fwd={}", sv(SUI_ACCUMULATOR_ROOT_OBJECT_ID), sv(SUI_FORWARDING_ADDRESS_REGISTRY_OBJECT_ID)).unwrap();
    s
}

/// Version assignment for one commit (timed): get-or-init from the epoch map, then Mysten's
/// assign_versions_for_certificate per schedulable in order, then the new next versions.
fn assign_commit(
    es: &AuthorityPerEpochStore,
    implicit: &[(ObjectID, SequenceNumber)],
    epoch_map: &mut HashMap<(ObjectID, SequenceNumber), SequenceNumber>,
    c: &Commit,
) -> Vec<AssignedVersions> {
    let mut keys: Vec<(ObjectID, SequenceNumber)> =
        c.scheds.iter().flat_map(|s| s.shared_input_objects(es).map(|o| o.into_id_and_version()).collect::<Vec<_>>()).collect();
    keys.extend_from_slice(implicit);
    keys.sort();
    keys.dedup();
    let mut next: HashMap<(ObjectID, SequenceNumber), SequenceNumber> =
        keys.iter().map(|k| (*k, *epoch_map.get(k).unwrap_or(&k.1))).collect();
    let out: Vec<AssignedVersions> =
        c.scheds.iter().map(|s| SharedObjVerManager::assign_versions_for_certificate(es, s, &mut next, &c.cancelled)).collect();
    epoch_map.extend(next);
    out
}

/// `Params::commit_budget` (ConsensusCommitInfo is pub(crate)).
fn commit_budget(p: &sui_protocol_config::ExecutionTimeEstimateParams, period: Duration) -> u64 {
    (period.as_micros() as u64).saturating_mul(p.target_utilization) / 100
}

/// should_defer_due_to_object_congestion's test: start cost beyond budget + burst limit;
/// returns the congested objects (those at the start cost).
fn defer_test(
    t: &SharedObjectCongestionTracker,
    p: &sui_protocol_config::ExecutionTimeEstimateParams,
    period: Duration,
    cert: &VerifiedExecutableTransaction,
    debt_of: &dyn Fn(&ObjectID) -> u64,
) -> Option<Vec<ObjectID>> {
    let shared: Vec<_> = cert.shared_input_objects().collect();
    if shared.is_empty() {
        return None;
    }
    let start = t.compute_tx_start_at_cost(&shared);
    let limit = commit_budget(p, period).saturating_add(p.allowed_txn_cost_overage_burst_limit_us);
    if start <= limit {
        return None;
    }
    Some(shared.iter().filter(|o| debt_of(&o.id) == start).map(|o| o.id).collect())
}

/// Congestion control over one commit (timed). Returns the output line and the next debts.
fn congestion_commit(
    est: &ExecutionTimeEstimator,
    p: &sui_protocol_config::ExecutionTimeEstimateParams,
    period: Duration,
    debts: &[(ObjectID, u64)],
    c: &Commit,
    want: bool,
) -> (String, Vec<(ObjectID, u64)>) {
    let mut t = SharedObjectCongestionTracker::new(debts.iter().cloned(), p.clone(), false, false);
    // the tracker's object costs are private: mirror them to tell congested objects apart
    let mut cost: HashMap<ObjectID, u64> = debts.iter().cloned().collect();
    let mut line = if want { format!("{} cc", c.seq) } else { String::new() };
    for &k in &c.user {
        let Schedulable::Transaction(cert) = &c.scheds[k] else { continue };
        let shared: Vec<_> = cert.shared_input_objects().collect();
        if shared.is_empty() {
            continue;
        }
        let tx_cost: u64 = est.get_estimate(cert.transaction_data()).as_micros().try_into().unwrap_or(u64::MAX);
        if let Some(objs) = defer_test(&t, p, period, cert, &|id| *cost.get(id).unwrap_or(&0)) {
            if want { write!(line, " d{}:{}", k, objs.iter().map(|o| hex(o.as_ref())[..8].to_string()).collect::<Vec<_>>().join("+")).unwrap(); }
            continue;
        }
        let start = t.compute_tx_start_at_cost(&shared);
        t.bump_object_execution_cost(tx_cost, cert);
        for o in &shared {
            if o.is_accessed_exclusively() {
                cost.insert(o.id, start.saturating_add(tx_cost));
            }
        }
        if want { write!(line, " b{}:{}", k, tx_cost).unwrap(); }
    }
    // finish_commit: debts beyond the commit budget
    let budget = commit_budget(p, period);
    let mut next: Vec<(ObjectID, u64)> = cost.into_iter().filter_map(|(id, c)| {
        let r = c.saturating_sub(budget);
        (r > 0).then_some((id, r))
    }).collect();
    next.sort();
    if want {
        write!(line, " max={} debts={}", t.max_cost(), next.len()).unwrap();
        for (id, d) in &next {
            write!(line, " {}:{}", &hex(id.as_ref())[..8], d).unwrap();
        }
    }
    (line, next)
}

fn versions(a: &Args) -> Result<()> {
    let files = read_list(&a.list)?;
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    let state = rt.block_on(TestAuthorityBuilder::new().build());
    let es = state.epoch_store_for_testing().clone();
    let mut implicit = vec![];
    if es.accumulators_enabled() {
        implicit.push((SUI_ACCUMULATOR_ROOT_OBJECT_ID, es.epoch_start_config().accumulator_root_obj_initial_shared_version().unwrap()));
    }
    if es.protocol_config().enable_forwarding_addresses()
        && let Some(v) = es.epoch_start_config().forwarding_address_registry_obj_initial_shared_version()
    {
        implicit.push((SUI_FORWARDING_ADDRESS_REGISTRY_OBJECT_ID, v));
    }
    let root = corpus_root(&files)?;
    let pv = load_pv(&root)?;
    // congestion parameters of the newest protocol in the list
    let mut commits = vec![];
    let mut shared_tx_counter = 0u64;
    let mut last_pv = 0;
    for f in &files {
        let seq = seq_of(f)?;
        let cp = load_chk(f)?;
        let epoch = cp.checkpoint_summary.data().epoch;
        last_pv = last_pv.max(pv[epoch as usize]);
        let mut scheds = vec![];
        let mut user = vec![];
        let mut cancelled = BTreeMap::new();
        for t in &cp.transactions {
            let ssd = t.transaction.data().clone();
            let kind = ssd.intent_message().value.kind().clone();
            match class_of(&kind) {
                Class::ProgrammableSystem | Class::Other if !matches!(kind, TransactionKind::AuthenticatorStateUpdate(_)) => continue,
                _ => {}
            }
            let exe = VerifiedExecutableTransaction::new_unchecked(ExecutableTransaction::new_from_data_and_sig(ssd, CertificateProof::new_system(epoch)));
            let has_shared = exe.shared_input_objects().next().is_some();
            if class_of(&kind) == Class::Programmable && has_shared {
                shared_tx_counter += 1;
                if shared_tx_counter % 97 == 0 {
                    let first = exe.shared_input_objects().next().unwrap().id;
                    cancelled.insert(*exe.digest(), CancelConsensusCertificateReason::CongestionOnObjects(vec![first]));
                } else if shared_tx_counter % 211 == 0 {
                    cancelled.insert(*exe.digest(), CancelConsensusCertificateReason::DkgFailed);
                }
            }
            if class_of(&kind) == Class::Programmable {
                user.push(scheds.len());
            }
            scheds.push(Schedulable::Transaction(exe));
        }
        commits.push(Commit { seq, scheds, cancelled, user });
    }
    let nsched: usize = commits.iter().map(|c| c.scheds.len()).sum();
    eprintln!("versions: {} commits, {} schedulables, implicit {:?}", commits.len(), nsched, implicit);

    let mut lines = String::new();
    writeln!(lines, "implicit {}", implicit.iter().map(|(id, v)| format!("{}:{}", hex(id.as_ref()), v.value())).collect::<Vec<_>>().join(",")).unwrap();
    let mut epoch_map = HashMap::new();
    for c in &commits {
        let av = assign_commit(&es, &implicit, &mut epoch_map, c);
        for (i, (s, v)) in c.scheds.iter().zip(av.iter()).enumerate() {
            lines.push_str(&assigned_line(c.seq, i, &key_of(s), v));
            lines.push('\n');
        }
    }
    let mut final_map: Vec<_> = epoch_map.iter().collect();
    final_map.sort();
    for ((id, isv), v) in final_map {
        writeln!(lines, "next {}:{} {}", hex(id.as_ref()), isv.value(), v.value()).unwrap();
    }
    let v_digest = digest_hex(&lines);
    let mut log = String::new();
    let mut best: Vec<u64> = vec![u64::MAX; commits.len()];
    for _ in 0..a.reps.max(1) {
        let mut m = HashMap::new();
        for (k, c) in commits.iter().enumerate() {
            let t0 = Instant::now();
            std::hint::black_box(assign_commit(&es, &implicit, &mut m, c));
            best[k] = best[k].min(t0.elapsed().as_nanos() as u64);
        }
    }
    let wall: u64 = best.iter().sum();
    emit(&mut log, Rec { stage: "versions", case: "all", mode: "assign", threads: 1, unit: "commit", items: best, count: commits.len() as u64, wall_ns: wall, out: &v_digest });
    eprintln!("versions: {:.1} ns/schedulable", wall as f64 / nsched.max(1) as f64);

    // congestion control
    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(last_pv), Chain::Mainnet);
    let PerObjectCongestionControlMode::ExecutionTimeEstimate(params) = cfg.per_object_congestion_control_mode() else {
        bail!("protocol {last_pv}: congestion control is not ExecutionTimeEstimate");
    };
    let (committee, _) = Committee::new_simple_test_committee_of_size(1);
    let est = ExecutionTimeEstimator::new(Arc::new(committee), params.clone(), std::iter::empty());
    let period = Duration::from_millis(50);
    let mut cl = String::new();
    writeln!(cl, "params target={} burst={} max={} period_us={}", params.target_utilization, params.allowed_txn_cost_overage_burst_limit_us, params.max_estimate_us, period.as_micros()).unwrap();
    let mut debts = vec![];
    for c in &commits {
        let (l, d) = congestion_commit(&est, &params, period, &debts, c, true);
        cl.push_str(&l);
        cl.push('\n');
        debts = d;
    }
    let c_digest = digest_hex(&cl);
    let mut best: Vec<u64> = vec![u64::MAX; commits.len()];
    for _ in 0..a.reps.max(1) {
        let mut d = vec![];
        for (k, c) in commits.iter().enumerate() {
            let t0 = Instant::now();
            let (_, nd) = std::hint::black_box(congestion_commit(&est, &params, period, &d, c, false));
            best[k] = best[k].min(t0.elapsed().as_nanos() as u64);
            d = nd;
        }
    }
    let wall: u64 = best.iter().sum();
    emit(&mut log, Rec { stage: "congestion", case: "all", mode: "commit", threads: 1, unit: "commit", items: best, count: commits.len() as u64, wall_ns: wall, out: &c_digest });
    lines.push_str("--- congestion\n");
    lines.push_str(&cl);
    drop(es);
    drop(state);
    rt.shutdown_background();
    write_outputs(&a.out, "versions", &log, &lines)
}

fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().collect();
    let cmd = argv.get(1).map(String::as_str).unwrap_or("");
    let a = args(&argv[2.min(argv.len())..])?;
    match cmd {
        "intake" => intake(&a),
        "ckpt" => ckpt(&a),
        "versions" => versions(&a),
        _ => bail!("usage: zui-val-bench intake|ckpt|versions --list L --out D [--reps N]"),
    }
}
