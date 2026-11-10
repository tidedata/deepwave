//! zui-truth-checkpoint: ground truth for the checkpoint-verify lane, computed with Mysten's own
//! code (sui-types mainnet-v1.83.1, fastcrypto da61cd46). Formats: README.md.
//!
//! Commands:
//!   committees <out_dir> <genesis.blob> <chk_dir>   committee of every epoch (epoch 0 from the genesis
//!                                                   system state, epoch e+1 from epoch e's end-of-epoch
//!                                                   checkpoint) -> committees.jsonl; asserts that every
//!                                                   corpus certificate verifies with Mysten's code
//!   synth <out_file>                                Committee::new edge cases (bad totals, keys, duplicates)
//!   verify <out_dir> <genesis.blob> <chk_dir>       per epoch: every checkpoint, real and mutated, with the
//!                                                   verdict of the full verification path -> verify/<epoch>.jsonl
//!   bench <name> --iters N --list <file>            Rust baseline on the listed blobs (CONTRACTS.md 7)

use anyhow::{Context, Result, anyhow, bail};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;
use sui_types::base_types::AuthorityName;
use sui_types::committee::Committee;
use sui_types::effects::{TransactionEffects, TransactionEffectsAPI};
use sui_types::error::SuiErrorKind;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::message_envelope::Message;
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointContents};
use sui_types::object::Object;
use sui_types::sui_system_state::{SuiSystemStateTrait, get_sui_system_state};
use sui_types::transaction::Transaction;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("committees") => cmd_committees(&args[2..]),
        Some("synth") => cmd_synth(&args[2..]),
        Some("verify") => cmd_verify(&args[2..]),
        Some("bench") => cmd_bench(&args[2..]),
        _ => bail!("usage: zui-truth-checkpoint committees|synth|verify|bench ..."),
    }
}

fn splitmix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

#[derive(Deserialize)]
struct RawGenesis {
    #[allow(dead_code)]
    checkpoint: CertifiedCheckpointSummary,
    #[allow(dead_code)]
    checkpoint_contents: CheckpointContents,
    #[allow(dead_code)]
    transaction: Transaction,
    #[allow(dead_code)]
    effects: TransactionEffects,
    #[allow(dead_code)]
    events: sui_types::effects::TransactionEvents,
    objects: Vec<Object>,
}

fn genesis_committee(path: &str) -> Result<Committee> {
    let gbytes = std::fs::read(path)?;
    let inner: Vec<u8> = bcs::from_bytes(&gbytes).context("genesis outer bytes")?;
    let genesis: RawGenesis = bcs::from_bytes(&inner).context("genesis")?;
    let objs: &[Object] = &genesis.objects;
    let sys = get_sui_system_state(&objs).map_err(|e| anyhow!("system state: {e}"))?;
    let c = sys.get_current_epoch_committee().committee().clone();
    if c.epoch != 0 {
        bail!("genesis committee epoch {}", c.epoch);
    }
    Ok(c)
}

fn blob_files(chk_dir: &str) -> Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(chk_dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "chk"))
        .collect();
    files.sort();
    Ok(files)
}

fn decode_blob(raw: &[u8]) -> Result<CheckpointData> {
    if raw.first() != Some(&1) {
        bail!("not a BCS blob");
    }
    Ok(bcs::from_bytes(&raw[1..])?)
}

/// What one checkpoint contributes to the chain.
struct Rec {
    seq: u64,
    epoch: u64,
    digest: [u8; 32],
    eoe: bool,
    next_committee: Option<BTreeMap<AuthorityName, u64>>,
    path: PathBuf,
}

fn scan(chk_dir: &str) -> Result<Vec<Rec>> {
    let files = blob_files(chk_dir)?;
    let t0 = Instant::now();
    let mut recs: Vec<Rec> = files
        .par_iter()
        .map(|f| -> Result<Rec> {
            let raw = std::fs::read(f)?;
            let cp = decode_blob(&raw).with_context(|| format!("{}", f.display()))?;
            let cert = &cp.checkpoint_summary;
            let s = cert.data();
            Ok(Rec {
                seq: s.sequence_number,
                epoch: s.epoch,
                digest: cert.digest().into_inner(),
                eoe: s.end_of_epoch_data.is_some(),
                next_committee: s
                    .end_of_epoch_data
                    .as_ref()
                    .map(|e| e.next_epoch_committee.iter().cloned().collect()),
                path: f.clone(),
            })
        })
        .collect::<Result<_>>()?;
    recs.sort_by_key(|r| r.seq);
    eprintln!("scan: {} blobs in {:.1}s", recs.len(), t0.elapsed().as_secs_f64());
    Ok(recs)
}

fn committee_chain(genesis: &str, recs: &[Rec]) -> Result<BTreeMap<u64, Committee>> {
    let mut committees: BTreeMap<u64, Committee> = BTreeMap::new();
    committees.insert(0, genesis_committee(genesis)?);
    for r in recs {
        if let Some(nc) = &r.next_committee {
            committees.insert(r.epoch + 1, Committee::new(r.epoch + 1, nc.clone()));
        }
    }
    Ok(committees)
}

fn committee_json(c: &Committee) -> Value {
    let keys: Vec<String> = c.voting_rights.iter().map(|(n, _)| hex::encode(n.as_ref())).collect();
    let stakes: Vec<u64> = c.voting_rights.iter().map(|(_, s)| *s).collect();
    json!({"epoch": c.epoch, "keys": keys, "stakes": stakes, "total": c.total_votes(),
           "quorum": c.quorum_threshold(), "validity": c.validity_threshold()})
}

// ---------------------------------------------------------------------------------------------
// committees

fn cmd_committees(args: &[String]) -> Result<()> {
    let [out_dir, genesis, chk_dir] = args else { bail!("committees <out_dir> <genesis.blob> <chk_dir>") };
    std::fs::create_dir_all(out_dir)?;
    let recs = scan(chk_dir)?;
    let committees = committee_chain(genesis, &recs)?;
    // every certificate in the corpus must verify with Mysten's code under its epoch's committee
    let t0 = Instant::now();
    let bad: usize = recs
        .par_iter()
        .map(|r| -> Result<usize> {
            let cp = decode_blob(&std::fs::read(&r.path)?)?;
            let c = committees.get(&r.epoch).ok_or_else(|| anyhow!("no committee for epoch {}", r.epoch))?;
            Ok(cp.checkpoint_summary.verify_authority_signatures(c).is_err() as usize)
        })
        .try_reduce(|| 0, |a, b| Ok(a + b))?;
    eprintln!("committees: verified {} certificates in {:.1}s, {} bad", recs.len(), t0.elapsed().as_secs_f64(), bad);
    if bad != 0 {
        bail!("{bad} real certificates did not verify");
    }
    let mut out = Vec::new();
    let eoe_seq: BTreeMap<u64, u64> = recs.iter().filter(|r| r.eoe).map(|r| (r.epoch + 1, r.seq)).collect();
    for (e, c) in &committees {
        let mut v = committee_json(c);
        v["src"] = json!(if *e == 0 { "genesis" } else { "eoe" });
        v["eoe_seq"] = eoe_seq.get(e).map_or(Value::Null, |s| json!(s));
        writeln!(out, "{v}")?;
    }
    std::fs::write(Path::new(out_dir).join("committees.jsonl"), out)?;
    println!("{}", json!({"committees": committees.len(), "certs": recs.len()}));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// synth: Committee::new on inputs the chain never produced

fn cmd_synth(args: &[String]) -> Result<()> {
    let [out_file] = args else { bail!("synth <out_file>") };
    // real validator keys (genesis committee) are the only keys that decode, so reuse the first
    // eight from an existing committees.jsonl next to the output file
    let dir = Path::new(out_file).parent().unwrap_or(Path::new("."));
    let text = std::fs::read_to_string(dir.join("committees.jsonl")).context("run `committees` first")?;
    let first: Value = serde_json::from_str(text.lines().next().ok_or_else(|| anyhow!("empty committees.jsonl"))?)?;
    let keys: Vec<String> = first["keys"].as_array().unwrap().iter().map(|k| k.as_str().unwrap().to_string()).collect();
    let stakes: Vec<u64> = first["stakes"].as_array().unwrap().iter().map(|k| k.as_u64().unwrap()).collect();
    let n = keys.len();
    let mut cases: Vec<(String, u64, Vec<(String, u64)>)> = Vec::new();
    let real: Vec<(String, u64)> = keys.iter().cloned().zip(stakes.iter().cloned()).collect();
    cases.push(("genesis".into(), 7, real.clone()));
    // reversed order: Committee::new sorts
    let mut rev = real.clone();
    rev.reverse();
    cases.push(("reversed".into(), 7, rev.clone()));
    // duplicate name: the BTreeMap keeps the last stake
    let mut dup = real.clone();
    dup.push((real[0].0.clone(), real[0].1 + 5));
    dup[0].1 = real[0].1; // first listed stake differs from the last
    cases.push(("dup-last-wins".into(), 7, dup));
    // total 10,000 after the duplicate collapses (first copy had a different stake)
    let mut dup2 = real.clone();
    dup2.insert(0, (real[1].0.clone(), 1));
    cases.push(("dup-first-ignored".into(), 7, dup2));
    // total != 10,000
    let mut low = real.clone();
    low[0].1 -= 1;
    cases.push(("total-9999".into(), 7, low));
    let mut high = real.clone();
    high[0].1 += 1;
    cases.push(("total-10001".into(), 7, high));
    // empty and all-zero
    cases.push(("empty".into(), 7, vec![]));
    cases.push(("all-zero".into(), 7, real.iter().map(|(k, _)| (k.clone(), 0)).collect()));
    // a zero-stake member next to a valid total
    let mut zero = real.clone();
    let moved = zero[n - 1].1;
    zero[n - 1].1 = 0;
    zero[0].1 += moved;
    cases.push(("zero-member".into(), 7, zero));
    // one member holding everything
    cases.push(("single".into(), 7, vec![(real[0].0.clone(), 10_000)]));
    // an undecodable key (not on the curve: x with the infinity flag and junk)
    let mut badkey = real.clone();
    let mut bk = [0u8; 96];
    bk[0] = 0xc0;
    bk[95] = 1;
    badkey[0].0 = hex::encode(bk);
    cases.push(("bad-key-inf-junk".into(), 7, badkey));
    // an all-0xff key
    let mut ffkey = real.clone();
    ffkey[1].0 = hex::encode([0xffu8; 96]);
    cases.push(("bad-key-ff".into(), 7, ffkey));
    // epoch edge
    cases.push(("epoch-max-1".into(), u64::MAX - 1, real.clone()));
    // single member via the other genesis keys at different stake splits
    let mut two = vec![(real[0].0.clone(), 6_667), (real[1].0.clone(), 3_333)];
    cases.push(("two".into(), 9, two.clone()));
    two[0].1 = 3_333;
    two[1].1 = 6_667;
    cases.push(("two-swapped".into(), 9, two));
    // stakes whose sum wraps: sui-node is built without overflow checks, so `Committee::new`'s
    // `.sum()` wraps and a total of 10,000 mod 2^64 passes its assertion
    cases.push(("stake-wrap".into(), 7, vec![(real[0].0.clone(), u64::MAX), (real[1].0.clone(), 10_001)]));
    cases.push(("stake-wrap-off".into(), 7, vec![(real[0].0.clone(), u64::MAX), (real[1].0.clone(), 10_002)]));
    let mut out = Vec::new();
    for (id, epoch, rights) in &cases {
        let parsed: Option<BTreeMap<AuthorityName, u64>> = rights
            .iter()
            .map(|(k, s)| -> Option<(AuthorityName, u64)> {
                let b = hex::decode(k).ok()?;
                let arr: [u8; 96] = b.try_into().ok()?;
                Some((AuthorityName::new(arr), *s))
            })
            .collect();
        let rights_json: Vec<Value> = rights.iter().map(|(k, s)| json!([k, s])).collect();
        let line = match parsed {
            None => json!({"id": id, "epoch": epoch, "rights": rights_json, "verdict": "panic"}),
            Some(m) => {
                let r = std::panic::catch_unwind(|| Committee::new(*epoch, m));
                match r {
                    Ok(c) => {
                        let mut v = committee_json(&c);
                        v["id"] = json!(id);
                        v["rights"] = json!(rights_json);
                        v["verdict"] = json!("ok");
                        v
                    }
                    Err(_) => json!({"id": id, "epoch": epoch, "rights": rights_json, "verdict": "panic"}),
                }
            }
        };
        writeln!(out, "{line}")?;
    }
    let certs = synth_certs()?;
    for line in &certs {
        writeln!(out, "{line}")?;
    }
    std::fs::write(out_file, out)?;
    println!("{}", json!({"cases": cases.len() + certs.len()}));
    Ok(())
}

/// Certificates under committees with wrapping stakes, signed with fixed test keys: the quorum
/// weight in `add_to_verification_obligation` (`weight += voting_rights`) wraps the same way the
/// total does. Each line is a committee case plus `cert` {summary, sig, verdict}: the verdict of
/// `verify_authority_signatures` on that certificate under the line's committee.
fn synth_certs() -> Result<Vec<Value>> {
    use fastcrypto::bls12381::min_sig::{BLS12381KeyPair, BLS12381PrivateKey};
    use fastcrypto::traits::{AggregateAuthenticator, KeyPair as _, ToFromBytes};
    use shared_crypto::intent::{Intent, IntentScope};
    use sui_types::crypto::{AggregateAuthoritySignature, AuthorityQuorumSignInfo, AuthoritySignInfo};
    use sui_types::messages_checkpoint::CheckpointSummary;

    let epoch = 3u64;
    // a minimal CheckpointSummary (no previous digest, commitments or end-of-epoch data)
    let mut sb = Vec::new();
    sb.extend_from_slice(&epoch.to_le_bytes());
    sb.extend_from_slice(&42u64.to_le_bytes());
    sb.extend_from_slice(&0u64.to_le_bytes());
    sb.push(32);
    sb.extend_from_slice(&[7u8; 32]);
    sb.push(0);
    sb.extend_from_slice(&[0u8; 40]);
    sb.extend_from_slice(&[0, 0, 0]);
    let summary: CheckpointSummary = bcs::from_bytes(&sb)?;
    let mut kps: Vec<BLS12381KeyPair> = (1..=3u8)
        .map(|i| {
            let mut b = [0u8; 32];
            b[0] = 0x2a;
            b[31] = i;
            BLS12381KeyPair::from(BLS12381PrivateKey::from_bytes(&b).expect("scalar"))
        })
        .collect();
    kps.sort_by_key(|k| AuthorityName::from(k.public()));
    let names: Vec<AuthorityName> = kps.iter().map(|k| AuthorityName::from(k.public())).collect();
    let sigs: Vec<_> = kps
        .iter()
        .zip(&names)
        .map(|(k, n)| AuthoritySignInfo::new(epoch, &summary, Intent::sui_app(IntentScope::CheckpointSummary), *n, k).signature)
        .collect();
    // committees by sorted index: [stakes], and the signer sets to certify under each
    let big = u64::MAX - 4_999; // 2^64 - 5,000
    let plans: Vec<(&str, Vec<u64>, Vec<Vec<u32>>)> = vec![
        // total 2^64 + 10,000: {0,1} weighs 2,000 after the wrap, {0} and {1,2} pass
        ("cert-wrap", vec![big, 7_000, 8_000], vec![vec![0], vec![0, 1], vec![1, 2], vec![0, 1, 2], vec![1]]),
        // the big member last in index order
        ("cert-wrap-last", vec![7_000, 8_000, big], vec![vec![2], vec![1, 2], vec![0, 1], vec![0, 1, 2]]),
        ("cert-plain", vec![3_400, 3_300, 3_300], vec![vec![0, 1], vec![1, 2], vec![0], vec![0, 1, 2]]),
    ];
    let mut out = Vec::new();
    for (pid, stakes, sets) in plans {
        let rights: BTreeMap<AuthorityName, u64> = names.iter().cloned().zip(stakes.iter().cloned()).collect();
        let committee = Committee::new(epoch, rights);
        let rights_json: Vec<Value> = names.iter().zip(&stakes).map(|(n, s)| json!([hex::encode(n.as_ref()), s])).collect();
        for set in sets {
            let parts: Vec<_> = set.iter().map(|&i| sigs[i as usize].clone()).collect();
            let agg = AggregateAuthoritySignature::aggregate(&parts).map_err(|e| anyhow!("{e}"))?;
            let info = AuthorityQuorumSignInfo::<true> { epoch, signature: agg, signers_map: set.iter().cloned().collect() };
            let cert = CertifiedCheckpointSummary::new_from_data_and_sig(summary.clone(), info.clone());
            let verdict = match cert.verify_authority_signatures(&committee) {
                Ok(()) => "ok",
                Err(e) => match e.as_inner() {
                    SuiErrorKind::WrongEpoch { .. } => "epoch_mismatch",
                    SuiErrorKind::UnknownSigner { .. } => "bad_bitmap",
                    SuiErrorKind::CertificateRequiresQuorum => "insufficient_stake",
                    SuiErrorKind::InvalidSignature { .. } => "bad_signature",
                    other => panic!("unexpected certificate error {other:?}"),
                },
            };
            let id = format!("{pid}/{}", set.iter().map(|i| i.to_string()).collect::<Vec<_>>().join("-"));
            let mut v = committee_json(&committee);
            v["id"] = json!(id);
            v["rights"] = json!(rights_json);
            v["verdict"] = json!("ok");
            v["cert"] = json!({"summary": hex::encode(&sb), "sig": hex::encode(bcs::to_bytes(&info)?), "verdict": verdict});
            out.push(v);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// the verification path

#[derive(Clone, Debug, PartialEq, Eq)]
struct Verdict {
    v: &'static str,
    what: Option<&'static str>,
    index: Option<u32>,
}

fn vd(v: &'static str) -> Verdict {
    Verdict { v, what: None, index: None }
}
fn mism(what: &'static str, index: u32) -> Verdict {
    Verdict { v: "digest_mismatch", what: Some(what), index: Some(index) }
}

#[derive(Clone, Copy, Debug)]
struct Prev {
    digest: [u8; 32],
    seq: u64,
    epoch: u64,
    eoe: bool,
}

/// Verifies one blob the way a full node verifies a checkpoint it is given with its contents:
///  1. decode as CheckpointData (any failure: "decode");
///  2. the chain step of `sui_storage::verify_checkpoint_with_committee` when `prev` is given;
///  3. `CertifiedCheckpointSummary::verify_authority_signatures` (epoch, signer indices, quorum,
///     aggregate signature), errors mapped by kind;
///  4. the contents digest against the summary (`verify_with_contents`);
///  5. contents against the transactions: count, then per transaction the transaction digest,
///     the effects' transaction digest, the effects digest and the events digest (what
///     `VersionedFullCheckpointContents::verify_digests` and the checkpoint executor check). The
///     user signatures pinned in the contents are NOT compared with the transactions' own: on
///     mainnet the first epochs pin none for system transactions that carry a zero signature
///     (checkpoint 9769, tx 1), and no Mysten path compares them.
fn verify_blob(committee: &Committee, blob: &[u8], prev: Option<&Prev>) -> Verdict {
    let cp = match decode_blob(blob) {
        Ok(cp) => cp,
        Err(_) => return vd("decode"),
    };
    verify_data(committee, &cp, prev)
}

fn verify_data(committee: &Committee, cp: &CheckpointData, prev: Option<&Prev>) -> Verdict {
    let cert = &cp.checkpoint_summary;
    let s = cert.data();
    if let Some(p) = prev {
        // verify_checkpoint_with_committee asserts seq == prev + 1; deepwave reports it as a chain break
        if s.sequence_number != p.seq.wrapping_add(1) || p.seq == u64::MAX {
            return vd("chain_break");
        }
        if s.previous_digest.map(|d| d.into_inner()) != Some(p.digest) {
            return vd("chain_break");
        }
        if s.epoch != p.epoch && s.epoch != p.epoch.wrapping_add(1) {
            return vd("chain_break");
        }
        if s.epoch == p.epoch.wrapping_add(1) && !p.eoe {
            return vd("chain_break");
        }
    }
    if let Err(e) = cert.verify_authority_signatures(committee) {
        return match e.as_inner() {
            SuiErrorKind::WrongEpoch { .. } => vd("epoch_mismatch"),
            SuiErrorKind::UnknownSigner { .. } => vd("bad_bitmap"),
            SuiErrorKind::CertificateRequiresQuorum => vd("insufficient_stake"),
            SuiErrorKind::InvalidSignature { .. } => vd("bad_signature"),
            other => panic!("unexpected certificate error {other:?}"),
        };
    }
    let contents = &cp.checkpoint_contents;
    if *contents.digest() != s.content_digest {
        return mism("contents", 0);
    }
    if contents.size() != cp.transactions.len() {
        return mism("tx_count", cp.transactions.len().min(u32::MAX as usize) as u32);
    }
    let view = contents.inner();
    for (i, (tx, d)) in cp.transactions.iter().zip(view.digests_iter()).enumerate() {
        let i = i as u32;
        let tdig = *tx.transaction.digest();
        if tdig != d.transaction {
            return mism("transaction", i);
        }
        if *tx.effects.transaction_digest() != tdig {
            return mism("effects_tx", i);
        }
        if tx.effects.digest() != d.effects {
            return mism("effects", i);
        }
        let want = tx.effects.events_digest().copied();
        let have = tx.events.as_ref().map(|e| e.digest());
        if want != have {
            return mism("events", i);
        }
    }
    vd("ok")
}

/// Apply mode: the output objects of every transaction against its effects. Every output
/// object's reference (id, version, digest) must be one of `all_changed_objects` (the check of
/// sui-light-client's `TransactionProof::verify_objects`) and every changed object must have its
/// output object. Both are compared as sets.
fn verify_objects_blob(blob: &[u8]) -> Verdict {
    let cp = match decode_blob(blob) {
        Ok(cp) => cp,
        Err(_) => return vd("decode"),
    };
    for (i, tx) in cp.transactions.iter().enumerate() {
        let changed: std::collections::BTreeSet<_> = tx.effects.all_changed_objects().into_iter().map(|c| c.0).collect();
        let outs: std::collections::BTreeSet<_> = tx.output_objects.iter().map(|o| o.compute_object_reference()).collect();
        if !outs.is_subset(&changed) {
            return mism("output_object", i as u32);
        }
        if !changed.is_subset(&outs) {
            return mism("missing_output", i as u32);
        }
    }
    vd("ok")
}

// ---------------------------------------------------------------------------------------------
// mutations

#[derive(Clone, Default)]
struct Mutation {
    xor: Vec<(usize, u8)>,
    /// (offset, bytes to delete, bytes to insert): applied after the xors
    splice: Option<(usize, usize, Vec<u8>)>,
    drop_last_tx: bool,
}

fn uleb_len(mut n: usize) -> usize {
    let mut l = 1;
    while n >= 0x80 {
        n >>= 7;
        l += 1;
    }
    l
}

fn apply(blob: &[u8], m: &Mutation, last_tx_start: usize, count_off: usize, ntx: usize) -> Vec<u8> {
    let mut b = blob.to_vec();
    for &(o, x) in &m.xor {
        b[o] ^= x;
    }
    if let Some((o, del, ins)) = &m.splice {
        b.splice(*o..*o + *del, ins.iter().cloned());
    }
    if m.drop_last_tx {
        // the tx vector count is a ULEB128; the last transaction runs to the end of the blob
        let old_len = uleb_len(ntx);
        let mut newcount = Vec::new();
        let mut n = ntx - 1;
        loop {
            let byte = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                newcount.push(byte);
                break;
            }
            newcount.push(byte | 0x80);
        }
        let mut out = b[..count_off].to_vec();
        out.extend_from_slice(&newcount);
        out.extend_from_slice(&b[count_off + old_len..last_tx_start]);
        return out;
    }
    b
}

struct TxLayout {
    data: (usize, usize),
    sigs: (usize, usize),
    effects: (usize, usize),
    events: Option<(usize, usize)>,
    start: usize,
    /// input objects: (offset, len) of each
    ins: Vec<(usize, usize)>,
    /// offset of the output objects' count, and (offset, len) of each output object
    out_count_off: usize,
    outs: Vec<(usize, usize)>,
}

struct Layout {
    summary: (usize, usize),
    siginfo: (usize, usize),
    sig_epoch: usize,
    sig_bytes: usize,
    contents: (usize, usize),
    count_off: usize,
    txs: Vec<TxLayout>,
}

fn layout(blob: &[u8], cp: &CheckpointData) -> Result<Layout> {
    let cert = &cp.checkpoint_summary;
    let s = bcs::to_bytes(cert.data())?;
    let sg = bcs::to_bytes(cert.auth_sig())?;
    let summary = (1, s.len());
    let siginfo = (1 + s.len(), sg.len());
    if blob[summary.0..][..summary.1] != s[..] || blob[siginfo.0..][..siginfo.1] != sg[..] {
        bail!("summary/signature layout");
    }
    let sigpos = sg
        .windows(48)
        .position(|w| w == cert.auth_sig().signature.as_ref())
        .ok_or_else(|| anyhow!("signature bytes not found"))?;
    let c = bcs::to_bytes(&cp.checkpoint_contents)?;
    let contents = (siginfo.0 + siginfo.1, c.len());
    let count_off = contents.0 + contents.1;
    let n = cp.transactions.len();
    let mut pos = count_off + uleb_len(n);
    let mut txs = Vec::with_capacity(n);
    for tx in &cp.transactions {
        let start = pos;
        let t = bcs::to_bytes(&tx.transaction)?;
        let data = bcs::to_bytes(tx.transaction.data().transaction_data())?;
        let nsig = tx.transaction.data().tx_signatures().len();
        // SenderSignedData is a one element vec: 0x01, then the 3 intent bytes, then the data
        if t[0] != 1 || t[1..4] != [0, 0, 0] {
            bail!("transaction layout");
        }
        let data_off = pos + 4;
        let sigs_start = data_off + data.len() + uleb_len(nsig);
        let sigs = (sigs_start, pos + t.len() - sigs_start);
        pos += t.len();
        let e = bcs::to_bytes(&tx.effects)?;
        let effects = (pos, e.len());
        pos += e.len();
        let events = match &tx.events {
            None => {
                pos += 1;
                None
            }
            Some(ev) => {
                let l = bcs::to_bytes(ev)?.len();
                let r = (pos + 1, l);
                pos += 1 + l;
                Some(r)
            }
        };
        pos += uleb_len(tx.input_objects.len());
        let mut ins = Vec::new();
        for o in &tx.input_objects {
            let l = bcs::to_bytes(o)?.len();
            ins.push((pos, l));
            pos += l;
        }
        let out_count_off = pos;
        pos += uleb_len(tx.output_objects.len());
        let mut outs = Vec::new();
        for o in &tx.output_objects {
            let l = bcs::to_bytes(o)?.len();
            outs.push((pos, l));
            pos += l;
        }
        txs.push(TxLayout { data: (data_off, data.len()), sigs, effects, events, start, ins, out_count_off, outs });
    }
    if pos != blob.len() {
        bail!("layout ends at {pos}, blob is {}", blob.len());
    }
    Ok(Layout {
        summary,
        siginfo,
        sig_epoch: siginfo.0,
        sig_bytes: siginfo.0 + sigpos,
        contents,
        count_off,
        txs,
    })
}

fn rnd(seq: u64, k: u64) -> u64 {
    splitmix(seq ^ splitmix(k.wrapping_mul(0x2545_f491_4f6c_dd1d)))
}

fn bitmask(r: u64) -> u8 {
    1u8 << (r % 8)
}

struct Case {
    name: String,
    m: Mutation,
    prev: Option<Prev>,
    committee_epoch: u64,
}

fn plain(name: &str, epoch: u64, m: Mutation) -> Case {
    Case { name: name.to_string(), m, prev: None, committee_epoch: epoch }
}

fn xor1(o: usize, x: u8) -> Mutation {
    Mutation { xor: vec![(o, x)], ..Default::default() }
}

fn cases_for(rec: &Rec, cp: &CheckpointData, lay: &Layout, prev_rec: Option<&Rec>, committees: &BTreeMap<u64, Committee>) -> Vec<Case> {
    let seq = rec.seq;
    let epoch = rec.epoch;
    let s = cp.checkpoint_summary.data();
    let mut v: Vec<Case> = Vec::new();
    v.push(plain("real", epoch, Mutation::default()));
    // epochs
    v.push(plain("epoch-summary", epoch, xor1(lay.summary.0, 1)));
    v.push(plain("epoch-sig", epoch, xor1(lay.sig_epoch, 1)));
    v.push(Case {
        name: "epoch-both".into(),
        m: Mutation { xor: vec![(lay.summary.0, 1), (lay.sig_epoch, 1)], ..Default::default() },
        prev: None,
        committee_epoch: epoch,
    });
    if epoch > 0 {
        v.push(plain("committee-prev", epoch - 1, Mutation::default()));
    }
    if committees.contains_key(&(epoch + 1)) {
        v.push(plain("committee-next", epoch + 1, Mutation::default()));
    }
    // summary bytes (sequence number and the rest): the signature no longer matches
    v.push(plain("seq-bit", epoch, xor1(lay.summary.0 + 8, bitmask(rnd(seq, 1)))));
    let r = rnd(seq, 2);
    v.push(plain("summary-bit", epoch, xor1(lay.summary.0 + 8 + (r as usize >> 8) % (lay.summary.1 - 8), bitmask(r))));
    // signature and signer bitmap
    let r = rnd(seq, 3);
    v.push(plain("sig-bit", epoch, xor1(lay.sig_bytes + (r as usize >> 8) % 48, bitmask(r))));
    let bm_start = lay.sig_bytes + 48;
    let bm_end = lay.siginfo.0 + lay.siginfo.1;
    let r = rnd(seq, 4);
    v.push(plain("bitmap-bit", epoch, xor1(bm_start + (r as usize >> 8) % (bm_end - bm_start), bitmask(r))));
    // rebuilt signer sets (insufficient stake, just enough, unknown signer, none)
    if let Some(c) = committees.get(&epoch) {
        let signers: Vec<u32> = cp.checkpoint_summary.auth_sig().signers_map.iter().collect();
        let enc = |sel: &dyn Fn(&mut sui_types::crypto::AuthorityQuorumSignInfo<true>)| -> Vec<u8> {
            let mut info = cp.checkpoint_summary.auth_sig().clone();
            sel(&mut info);
            bcs::to_bytes(&info).expect("sig info")
        };
        let splice = |bytes: Vec<u8>| Mutation { splice: Some((lay.siginfo.0, lay.siginfo.1, bytes)), ..Default::default() };
        // minimal prefix of the signers that reaches the quorum; the same without its last member
        let mut w = 0u64;
        let mut k = 0usize;
        for (i, &sx) in signers.iter().enumerate() {
            w += c.stake_by_index(sx).unwrap_or(0);
            if w >= c.quorum_threshold() {
                k = i + 1;
                break;
            }
        }
        if k > 0 {
            let keep: Vec<u32> = signers[..k].to_vec();
            v.push(plain(
                "signers-minimal",
                epoch,
                splice(enc(&|i| {
                    i.signers_map = keep.iter().cloned().collect();
                })),
            ));
            let keep: Vec<u32> = signers[..k - 1].to_vec();
            v.push(plain(
                "signers-short",
                epoch,
                splice(enc(&|i| {
                    i.signers_map = keep.iter().cloned().collect();
                })),
            ));
        }
        v.push(plain(
            "signers-none",
            epoch,
            splice(enc(&|i| {
                i.signers_map.clear();
            })),
        ));
        let n = c.voting_rights.len() as u32;
        v.push(plain(
            "signers-unknown",
            epoch,
            splice(enc(&|i| {
                i.signers_map.insert(n);
            })),
        ));
        v.push(plain(
            "signers-unknown-far",
            epoch,
            splice(enc(&|i| {
                i.signers_map.insert(n + 1000);
            })),
        ));
        // a non-signer added: stake passes, the aggregate key no longer matches
        if let Some(non) = (0..n).find(|x| !signers.contains(x)) {
            v.push(plain(
                "signers-add",
                epoch,
                splice(enc(&|i| {
                    i.signers_map.insert(non);
                })),
            ));
        }
        // a signer dropped from a full-strength set: still above quorum, key mismatch
        // the signer sets as run containers (`optimize`): the run decode of the bitmap
        v.push(plain(
            "signers-run",
            epoch,
            splice(enc(&|i| {
                i.signers_map.optimize();
            })),
        ));
        if k > 0 {
            let keep: Vec<u32> = signers[..k - 1].to_vec();
            v.push(plain(
                "signers-run-short",
                epoch,
                splice(enc(&|i| {
                    i.signers_map = keep.iter().cloned().collect();
                    i.signers_map.optimize();
                })),
            ));
        }
        v.push(plain(
            "signers-run-unknown",
            epoch,
            splice(enc(&|i| {
                i.signers_map.insert(n);
                i.signers_map.optimize();
            })),
        ));
        if signers.len() > 1 {
            let victim = signers[(rnd(seq, 5) as usize) % signers.len()];
            v.push(plain(
                "signers-drop",
                epoch,
                splice(enc(&|i| {
                    i.signers_map.remove(victim);
                })),
            ));
        }
    }
    // contents
    let r = rnd(seq, 6);
    v.push(plain("contents-bit", epoch, xor1(lay.contents.0 + (r as usize >> 8) % lay.contents.1, bitmask(r))));
    // transactions
    let n = lay.txs.len();
    if n > 0 {
        let pick = |k: u64| -> usize { (rnd(seq, k) as usize >> 4) % n };
        let t = pick(7);
        let r = rnd(seq, 8);
        v.push(plain("tx-data", epoch, xor1(lay.txs[t].data.0 + (r as usize >> 8) % lay.txs[t].data.1, bitmask(r))));
        let t = pick(9);
        let r = rnd(seq, 10);
        v.push(plain("effects", epoch, xor1(lay.txs[t].effects.0 + (r as usize >> 8) % lay.txs[t].effects.1, bitmask(r))));
        // the transaction digest inside the effects: found by searching the effects bytes
        let t = pick(11);
        let _ = t;
        v.push(Case { name: "effects-txdigest".into(), m: Mutation { xor: vec![(usize::MAX, 0)], ..Default::default() }, prev: None, committee_epoch: epoch });
        let with_events: Vec<usize> = (0..n).filter(|&i| lay.txs[i].events.is_some()).collect();
        if !with_events.is_empty() {
            let t = with_events[(rnd(seq, 12) as usize >> 4) % with_events.len()];
            let (eo, el) = lay.txs[t].events.unwrap();
            let r = rnd(seq, 13);
            v.push(plain("events", epoch, xor1(eo + (r as usize >> 8) % el, bitmask(r))));
        }
        let with_sigs: Vec<usize> = (0..n).filter(|&i| lay.txs[i].sigs.1 > 0).collect();
        if !with_sigs.is_empty() {
            let t = with_sigs[(rnd(seq, 14) as usize >> 4) % with_sigs.len()];
            let (so, sl) = lay.txs[t].sigs;
            let r = rnd(seq, 15);
            v.push(plain("usersig", epoch, xor1(so + (r as usize >> 8) % sl, bitmask(r))));
        }
        v.push(plain("drop-last-tx", epoch, Mutation { drop_last_tx: true, ..Default::default() }));
    }
    // apply mode (objects against effects): verdict of `verify_objects_blob`
    v.push(plain("obj-real", epoch, Mutation::default()));
    let with_out: Vec<usize> = (0..lay.txs.len()).filter(|&i| !lay.txs[i].outs.is_empty()).collect();
    if !with_out.is_empty() {
        let t = with_out[(rnd(seq, 40) as usize >> 4) % with_out.len()];
        let outs = &lay.txs[t].outs;
        let (oo, ol) = outs[(rnd(seq, 41) as usize >> 4) % outs.len()];
        let r = rnd(seq, 42);
        v.push(plain("obj-out-bit", epoch, xor1(oo + (r as usize >> 8) % ol, bitmask(r))));
        // drop the first output object: the count and the object are adjacent, one splice
        let n = outs.len();
        let new_count = {
            let mut b = Vec::new();
            let mut x = n - 1;
            loop {
                let byte = (x & 0x7f) as u8;
                x >>= 7;
                if x == 0 {
                    b.push(byte);
                    break;
                }
                b.push(byte | 0x80);
            }
            b
        };
        v.push(plain(
            "obj-drop-out",
            epoch,
            Mutation { splice: Some((lay.txs[t].out_count_off, uleb_len(n) + outs[0].1, new_count)), ..Default::default() },
        ));
        // an effects bit: changed objects no longer match
        let (eo, el) = lay.txs[t].effects;
        let r = rnd(seq, 43);
        v.push(plain("obj-effects-bit", epoch, xor1(eo + (r as usize >> 8) % el, bitmask(r))));
    }
    let with_in: Vec<usize> = (0..lay.txs.len()).filter(|&i| !lay.txs[i].ins.is_empty()).collect();
    if !with_in.is_empty() {
        let t = with_in[(rnd(seq, 44) as usize >> 4) % with_in.len()];
        let ins = &lay.txs[t].ins;
        let (io, il) = ins[(rnd(seq, 45) as usize >> 4) % ins.len()];
        let r = rnd(seq, 46);
        v.push(plain("obj-in-bit", epoch, xor1(io + (r as usize >> 8) % il, bitmask(r))));
    }
    for k in 0..3u64 {
        let r = rnd(seq, 20 + k);
        // anywhere in the blob, the tag byte included
        v.push(Case {
            name: format!("byte-{k}"),
            m: Mutation { xor: vec![(usize::MAX - 1, bitmask(r))], ..Default::default() },
            prev: None,
            committee_epoch: epoch,
        });
    }
    // chain steps
    if let Some(prev_digest) = s.previous_digest {
        let pd = prev_digest.into_inner();
        if let Some(p) = prev_rec {
            v.push(Case {
                name: "chain-real".into(),
                m: Mutation::default(),
                prev: Some(Prev { digest: p.digest, seq: p.seq, epoch: p.epoch, eoe: p.eoe }),
                committee_epoch: epoch,
            });
        }
        let base = Prev { digest: pd, seq: seq.wrapping_sub(1), epoch, eoe: false };
        let mut flipped = pd;
        flipped[(rnd(seq, 30) as usize) % 32] ^= bitmask(rnd(seq, 31));
        let mk = |name: &str, p: Prev| Case { name: name.into(), m: Mutation::default(), prev: Some(p), committee_epoch: epoch };
        v.push(mk("chain-same", base));
        v.push(mk("chain-digest", Prev { digest: flipped, ..base }));
        v.push(mk("chain-seq", Prev { seq, ..base }));
        v.push(mk("chain-seq-gap", Prev { seq: seq.wrapping_sub(2), ..base }));
        v.push(mk("chain-eoe-same", Prev { eoe: true, ..base }));
        if epoch >= 1 {
            v.push(mk("chain-noeoe", Prev { epoch: epoch - 1, ..base }));
            v.push(mk("chain-eoe", Prev { epoch: epoch - 1, eoe: true, ..base }));
        }
        if epoch >= 2 {
            v.push(mk("chain-epoch-jump", Prev { epoch: epoch - 2, eoe: true, ..base }));
        }
        v.push(mk("chain-epoch-ahead", Prev { epoch: epoch + 1, eoe: true, ..base }));
    }
    v
}

fn mut_json(m: &Mutation) -> Value {
    let mut o = serde_json::Map::new();
    if !m.xor.is_empty() {
        o.insert("xor".into(), json!(m.xor.iter().map(|(a, b)| json!([a, b])).collect::<Vec<_>>()));
    }
    if let Some((a, b, c)) = &m.splice {
        o.insert("splice".into(), json!([a, b, hex::encode(c)]));
    }
    if m.drop_last_tx {
        o.insert("drop_last_tx".into(), json!(true));
    }
    Value::Object(o)
}

fn verdict_json(v: &Verdict) -> Value {
    let mut o = serde_json::Map::new();
    o.insert("verdict".into(), json!(v.v));
    if let Some(w) = v.what {
        o.insert("what".into(), json!(w));
    }
    if let Some(i) = v.index {
        o.insert("index".into(), json!(i));
    }
    Value::Object(o)
}

fn cmd_verify(args: &[String]) -> Result<()> {
    let [out_dir, genesis, chk_dir] = args else { bail!("verify <out_dir> <genesis.blob> <chk_dir>") };
    let out_dir = Path::new(out_dir).join("verify");
    std::fs::create_dir_all(&out_dir)?;
    let recs = scan(chk_dir)?;
    let committees = committee_chain(genesis, &recs)?;
    let by_seq: BTreeMap<u64, &Rec> = recs.iter().map(|r| (r.seq, r)).collect();
    let mut by_epoch: BTreeMap<u64, Vec<&Rec>> = BTreeMap::new();
    for r in &recs {
        by_epoch.entry(r.epoch).or_default().push(r);
    }
    let t0 = Instant::now();
    let results: Vec<(u64, usize, usize)> = by_epoch
        .par_iter()
        .map(|(&epoch, list)| -> Result<(u64, usize, usize)> {
            let mut out = Vec::new();
            let mut lines = 0usize;
            let mut real_ok = 0usize;
            for r in list {
                let raw = std::fs::read(&r.path)?;
                let cp = decode_blob(&raw)?;
                let lay = layout(&raw, &cp).with_context(|| format!("seq {}", r.seq))?;
                let prev_rec = if r.seq > 0 { by_seq.get(&(r.seq - 1)).copied() } else { None };
                let cases = cases_for(r, &cp, &lay, prev_rec, &committees);
                for mut c in cases {
                    // resolve placeholders that need the blob
                    if c.name == "effects-txdigest" {
                        // flip a bit of the transaction digest stored in tx t's effects
                        let n = lay.txs.len();
                        let t = (rnd(r.seq, 11) as usize >> 4) % n;
                        let td = cp.transactions[t].transaction.digest().into_inner();
                        let (eo, el) = lay.txs[t].effects;
                        let pos = raw[eo..eo + el].windows(32).position(|w| w == td).ok_or_else(|| anyhow!("tx digest not in effects"))?;
                        c.m = xor1(eo + pos + (rnd(r.seq, 16) as usize) % 32, bitmask(rnd(r.seq, 17)));
                    } else if c.name.starts_with("byte-") {
                        let k: u64 = c.name[5..].parse()?;
                        let rr = rnd(r.seq, 20 + k);
                        c.m = xor1((rr as usize >> 8) % raw.len(), bitmask(rr));
                    }
                    let last_start = lay.txs.last().map_or(0, |t| t.start);
                    let bytes = apply(&raw, &c.m, last_start, lay.count_off, lay.txs.len());
                    let committee = committees.get(&c.committee_epoch).ok_or_else(|| anyhow!("no committee {}", c.committee_epoch))?;
                    let verdict = if c.name.starts_with("obj-") { verify_objects_blob(&bytes) } else { verify_blob(committee, &bytes, c.prev.as_ref()) };
                    if (c.name == "real" || c.name == "obj-real") && verdict.v == "ok" {
                        real_ok += 1;
                    }
                    let mut line = json!({"seq": r.seq, "case": c.name, "mut": mut_json(&c.m)});
                    if c.committee_epoch != epoch {
                        line["committee"] = json!(c.committee_epoch);
                    }
                    if let Some(p) = &c.prev {
                        line["prev"] = json!({"digest": hex::encode(p.digest), "seq": p.seq, "epoch": p.epoch, "eoe": p.eoe});
                    }
                    for (k, val) in verdict_json(&verdict).as_object().unwrap() {
                        line[k] = val.clone();
                    }
                    writeln!(out, "{line}")?;
                    lines += 1;
                }
            }
            std::fs::write(out_dir.join(format!("{epoch}.jsonl")), out)?;
            Ok((epoch, lines, real_ok))
        })
        .collect::<Result<_>>()?;
    let lines: usize = results.iter().map(|r| r.1).sum();
    let real_ok: usize = results.iter().map(|r| r.2).sum();
    println!(
        "{}",
        json!({"epochs": results.len(), "checkpoints": recs.len(), "real_ok": real_ok, "lines": lines, "secs": t0.elapsed().as_secs_f64()})
    );
    if real_ok != 2 * recs.len() {
        bail!("{} real checkpoints did not verify", 2 * recs.len() - real_ok);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// bench

#[derive(Serialize)]
struct BenchOut<'a> {
    #[serde(rename = "impl")]
    imp: &'a str,
    bench: &'a str,
    unit: &'a str,
    units: u64,
    iters: usize,
    median_ns: u128,
    min_ns: u128,
    ns_per_unit: f64,
}

fn load_committees() -> Result<BTreeMap<u64, Committee>> {
    let corpus = std::env::var("ZUI_CORPUS").context("ZUI_CORPUS")?;
    let text = std::fs::read_to_string(Path::new(&corpus).join("vectors/checkpoint-verify/committees.jsonl"))?;
    let mut m = BTreeMap::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let v: Value = serde_json::from_str(line)?;
        let epoch = v["epoch"].as_u64().unwrap();
        let rights: BTreeMap<AuthorityName, u64> = v["keys"]
            .as_array()
            .unwrap()
            .iter()
            .zip(v["stakes"].as_array().unwrap())
            .map(|(k, s)| {
                let b: [u8; 96] = hex::decode(k.as_str().unwrap()).unwrap().try_into().unwrap();
                (AuthorityName::new(b), s.as_u64().unwrap())
            })
            .collect();
        m.insert(epoch, Committee::new(epoch, rights));
    }
    Ok(m)
}

fn cmd_bench(args: &[String]) -> Result<()> {
    let name = args.first().ok_or_else(|| anyhow!("bench <name> --iters N --list <file>"))?.clone();
    let mut iters = 5usize;
    let mut list: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--iters" => {
                iters = args.get(i + 1).ok_or_else(|| anyhow!("--iters N"))?.parse()?;
                i += 2;
            }
            "--list" => {
                list = Some(args.get(i + 1).ok_or_else(|| anyhow!("--list FILE"))?.clone());
                i += 2;
            }
            a => bail!("unknown bench argument {a}"),
        }
    }
    let list = list.ok_or_else(|| anyhow!("--list FILE is required"))?;
    let files: Vec<PathBuf> = std::fs::read_to_string(&list)?.lines().filter(|l| !l.is_empty()).map(PathBuf::from).collect();
    let committees = load_committees()?;
    let blobs: Vec<Vec<u8>> = files.iter().map(std::fs::read).collect::<std::io::Result<_>>()?;
    let iters = iters.max(1);
    let run = |f: &dyn Fn() -> Result<()>| -> Result<Vec<u128>> {
        f()?;
        let mut v = Vec::with_capacity(iters);
        for _ in 0..iters {
            let t = Instant::now();
            f()?;
            v.push(t.elapsed().as_nanos());
        }
        Ok(v)
    };
    let (passes, unit, units) = match name.as_str() {
        // the certificate check sui-node runs per checkpoint, on already-decoded certificates
        "verify-cert" => {
            let certs: Vec<(CertifiedCheckpointSummary, &Committee)> = blobs
                .iter()
                .map(|b| {
                    let cp = decode_blob(b)?;
                    let c = committees.get(&cp.checkpoint_summary.data().epoch).ok_or_else(|| anyhow!("committee"))?;
                    Ok((cp.checkpoint_summary, c))
                })
                .collect::<Result<_>>()?;
            let units = certs.len() as u64;
            let p = run(&|| {
                for (cert, c) in &certs {
                    if cert.verify_authority_signatures(c).is_err() {
                        bail!("bench cert did not verify");
                    }
                }
                Ok(())
            })?;
            (p, "cert", units)
        }
        // decode the whole blob and run the whole verification path
        "verify-data" => {
            let mut txs = 0u64;
            let epochs: Vec<u64> = blobs
                .iter()
                .map(|b| {
                    let cp = decode_blob(b)?;
                    txs += cp.transactions.len() as u64;
                    Ok(cp.checkpoint_summary.data().epoch)
                })
                .collect::<Result<_>>()?;
            let p = run(&|| {
                for (b, e) in blobs.iter().zip(&epochs) {
                    let v = verify_blob(&committees[e], b, None);
                    if v.v != "ok" {
                        bail!("bench blob did not verify: {}", v.v);
                    }
                }
                Ok(())
            })?;
            (p, "tx", txs)
        }
        // Committee::new for every epoch's committee (decodes every key)
        "committee-prepare" => {
            let raw: Vec<(u64, BTreeMap<AuthorityName, u64>)> =
                committees.iter().map(|(e, c)| (*e, c.voting_rights.iter().cloned().collect())).collect();
            let keys: u64 = raw.iter().map(|r| r.1.len() as u64).sum();
            let p = run(&|| {
                for (e, r) in &raw {
                    std::hint::black_box(Committee::new(*e, r.clone()));
                }
                Ok(())
            })?;
            (p, "key", keys)
        }
        n => bail!("unknown bench {n} (verify-cert, verify-data, committee-prepare)"),
    };
    let mut passes = passes;
    passes.sort();
    let med = passes[passes.len() / 2];
    let o = BenchOut {
        imp: "rust",
        bench: &name,
        unit,
        units,
        iters,
        median_ns: med,
        min_ns: passes[0],
        ns_per_unit: med as f64 / units.max(1) as f64,
    };
    println!("{}", serde_json::to_string(&o)?);
    Ok(())
}
