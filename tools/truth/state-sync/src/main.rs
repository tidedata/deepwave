//! zui-sync-truth: ground truth for the state-sync lane, computed with Mysten's own code
//! (sui-types mainnet-v1.83.1). Formats: README.md and CONTRACTS.md section 6.5.1.
//!
//!   follow <from> <to> <out_prefix>     per-checkpoint verify verdict + plan hash, window net state
//!   mutants <from> <to> <count> <out>   single-fault mutations of real blobs with Mysten's verdict
//!   detail <seq>                        plan lines of one checkpoint
//!   bench <name> --iters N --list FILE  Rust baseline (harness protocol)

use anyhow::{Context, Result, anyhow, bail};
use rayon::prelude::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;
use sui_types::base_types::AuthorityName;
use sui_types::committee::{Committee, CommitteeTrait};
use sui_types::digests::ObjectDigest;
use sui_types::effects::{TransactionEffectsAPI};
use sui_types::error::SuiErrorKind;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::message_envelope::Message;
use fastcrypto::hash::{Blake2b256, HashFunction};

fn corpus() -> PathBuf {
    PathBuf::from(std::env::var("ZUI_CORPUS").expect("ZUI_CORPUS"))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("follow") => cmd_follow(&args[2..]),
        Some("mutants") => cmd_mutants(&args[2..]),
        Some("detail") => cmd_detail(&args[2..]),
        Some("scan") => cmd_scan(&args[2..]),
        Some("bench") => cmd_bench(&args[2..]),
        Some("edge") => cmd_edge(&args[2..]),
        _ => bail!("usage: zui-sync-truth follow|scan|mutants|edge|detail|bench ..."),
    }
}

fn load_committee(epoch: u64) -> Result<Committee> {
    let p = corpus().join(format!("vectors/bls-cert/{epoch}.jsonl"));
    let text = std::fs::read_to_string(&p).with_context(|| format!("{}", p.display()))?;
    let v: Value = serde_json::from_str(text.lines().next().ok_or_else(|| anyhow!("empty"))?)?;
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
    Ok(Committee::new(epoch, rights))
}

fn decode_blob(raw: &[u8]) -> Result<CheckpointData> {
    if raw.first() != Some(&1) {
        bail!("not a BCS blob");
    }
    Ok(bcs::from_bytes(&raw[1..])?)
}

fn blob_path(seq: u64) -> PathBuf {
    corpus().join(format!("chk/{seq}.chk"))
}

type Id = [u8; 32];

#[derive(Clone)]
struct TxPlan {
    tx: [u8; 32],
    fx: [u8; 32],
    puts: Vec<(Id, u64, [u8; 32])>,
    removes: Vec<(Id, u64, u8)>,
}

/// The writes and removals the effects promise, from Mysten's effects API.
fn plan_of(cp: &CheckpointData) -> Vec<TxPlan> {
    cp.transactions
        .iter()
        .map(|t| {
            let e = &t.effects;
            let mut puts: Vec<(Id, u64, [u8; 32])> = e
                .all_changed_objects()
                .into_iter()
                .map(|((id, v, d), _, _)| (id.into_bytes(), v.value(), d.into_inner()))
                .collect();
            puts.sort_by(|a, b| a.0.cmp(&b.0));
            let mut removes: Vec<(Id, u64, u8)> = Vec::new();
            for (id, v, _) in e.deleted() {
                removes.push((id.into_bytes(), v.value(), 0));
            }
            for (id, v, _) in e.wrapped() {
                removes.push((id.into_bytes(), v.value(), 1));
            }
            for (id, v, _) in e.unwrapped_then_deleted() {
                removes.push((id.into_bytes(), v.value(), 2));
            }
            removes.sort_by(|a, b| a.0.cmp(&b.0));
            TxPlan { tx: t.transaction.digest().into_inner(), fx: e.digest().into_inner(), puts, removes }
        })
        .collect()
}

fn plan_hash(plan: &[TxPlan]) -> [u8; 32] {
    let mut h = Blake2b256::default();
    for t in plan {
        h.update(t.tx);
        h.update(t.fx);
        h.update((t.puts.len() as u32).to_le_bytes());
        for (id, v, d) in &t.puts {
            h.update(id);
            h.update(v.to_le_bytes());
            h.update(d);
        }
        h.update((t.removes.len() as u32).to_le_bytes());
        for (id, v, k) in &t.removes {
            h.update(id);
            h.update(v.to_le_bytes());
            h.update([*k]);
        }
    }
    h.finalize().digest
}

#[derive(Clone, Copy)]
struct Prev {
    digest: [u8; 32],
}

/// The verification order of deepwave's apply path: decode (by the caller), contents digest, per
/// transaction tx/effects/events digests and output objects, then the certificate, then the chain.
fn verify_data(committee: &Committee, cp: &CheckpointData, prev: Option<&Prev>) -> &'static str {
    let cert = &cp.checkpoint_summary;
    let s = cert.data();
    let contents = &cp.checkpoint_contents;
    if *contents.digest() != s.content_digest {
        return "contents";
    }
    if contents.size() != cp.transactions.len() {
        return "tx_count";
    }
    let view = contents.inner();
    for (tx, d) in cp.transactions.iter().zip(view.digests_iter()) {
        if *tx.transaction.digest() != d.transaction {
            return "tx";
        }
        if tx.effects.digest() != d.effects {
            return "effects";
        }
        let want = tx.effects.events_digest().copied();
        let have = tx.events.as_ref().map(|e| e.digest());
        if want != have {
            return "events";
        }
        // output objects against the promised set
        let mut promised: Vec<(Id, u64, [u8; 32])> = tx
            .effects
            .all_changed_objects()
            .into_iter()
            .map(|((id, v, d), _, _)| (id.into_bytes(), v.value(), d.into_inner()))
            .collect();
        promised.sort();
        let mut have: Vec<(Id, u64, [u8; 32])> = tx
            .output_objects
            .iter()
            .map(|o| {
                let r = o.compute_object_reference();
                (r.0.into_bytes(), r.1.value(), <ObjectDigest as Into<[u8; 32]>>::into(r.2))
            })
            .collect();
        have.sort();
        if promised != have {
            return "objects";
        }
    }
    if let Err(e) = cert.verify_authority_signatures(committee) {
        return match e.as_inner() {
            SuiErrorKind::WrongEpoch { .. } => "epoch",
            SuiErrorKind::UnknownSigner { .. } => "bitmap",
            SuiErrorKind::CertificateRequiresQuorum => "stake",
            SuiErrorKind::InvalidSignature { .. } => "signature",
            other => panic!("unexpected certificate error {other:?}"),
        };
    }
    if let Some(p) = prev {
        if s.previous_digest.map(|d| d.into_inner()) != Some(p.digest) {
            return "chain";
        }
    }
    "ok"
}

// ---------------------------------------------------------------------------------------------

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

fn cmd_follow(args: &[String]) -> Result<()> {
    let [from, to, prefix] = args else { bail!("follow <from> <to> <out_prefix>") };
    let (from, to): (u64, u64) = (from.parse()?, to.parse()?);
    let t0 = Instant::now();
    struct Out {
        seq: u64,
        epoch: u64,
        digest: [u8; 32],
        prev: Option<[u8; 32]>,
        verdict: &'static str,
        plan: Vec<TxPlan>,
        phash: [u8; 32],
    }
    let seqs: Vec<u64> = (from..=to).collect();
    let mut committees: BTreeMap<u64, Committee> = BTreeMap::new();
    let outs: Vec<Out> = seqs
        .par_iter()
        .map(|&seq| -> Result<Out> {
            let raw = std::fs::read(blob_path(seq))?;
            let cp = decode_blob(&raw)?;
            let s = cp.checkpoint_summary.data();
            let c = load_committee(s.epoch)?;
            let verdict = verify_data(&c, &cp, None);
            let plan = plan_of(&cp);
            let phash = plan_hash(&plan);
            Ok(Out {
                seq,
                epoch: s.epoch,
                digest: cp.checkpoint_summary.digest().into_inner(),
                prev: s.previous_digest.map(|d| d.into_inner()),
                verdict,
                plan,
                phash,
            })
        })
        .collect::<Result<_>>()?;
    let _ = &mut committees;
    let mut cpl = Vec::new();
    let mut state: BTreeMap<Id, (u64, Option<[u8; 32]>, u8)> = BTreeMap::new();
    let (mut ntx, mut nput, mut nrm) = (0u64, 0u64, 0u64);
    let mut epochs: Vec<u64> = vec![];
    for (i, o) in outs.iter().enumerate() {
        let mut verdict = o.verdict;
        if i > 0 && verdict == "ok" && o.prev != Some(outs[i - 1].digest) {
            verdict = "chain";
        }
        let (mut p, mut r) = (0, 0);
        for t in &o.plan {
            p += t.puts.len();
            r += t.removes.len();
            for (id, v, d) in &t.puts {
                state.insert(*id, (*v, Some(*d), 0));
            }
            for (id, v, k) in &t.removes {
                state.insert(*id, (*v, None, *k));
            }
        }
        ntx += o.plan.len() as u64;
        nput += p as u64;
        nrm += r as u64;
        if epochs.last() != Some(&o.epoch) {
            epochs.push(o.epoch);
        }
        writeln!(
            cpl,
            "{}",
            json!({"seq": o.seq, "epoch": o.epoch, "digest": hx(&o.digest), "txs": o.plan.len(), "puts": p, "removes": r, "plan": hx(&o.phash), "verify": verdict})
        )?;
    }
    std::fs::write(format!("{prefix}.cp.jsonl"), cpl)?;
    let mut st = Vec::new();
    let mut h = Blake2b256::default();
    for (id, (v, d, k)) in &state {
        match d {
            Some(d) => {
                writeln!(st, "{}", json!({"id": hx(id), "v": v, "d": hx(d)}))?;
                h.update(id);
                h.update(v.to_le_bytes());
                h.update([1]);
                h.update(d);
            }
            None => {
                writeln!(st, "{}", json!({"id": hx(id), "v": v, "rm": k}))?;
                h.update(id);
                h.update(v.to_le_bytes());
                h.update([0, *k]);
            }
        }
    }
    std::fs::write(format!("{prefix}.state.jsonl"), st)?;
    let sh = h.finalize().digest;
    let sum = json!({"from": from, "to": to, "checkpoints": outs.len(), "txs": ntx, "puts": nput, "removes": nrm,
        "state_count": state.len(), "state_hash": hx(&sh), "epochs": epochs});
    std::fs::write(format!("{prefix}.summary.json"), format!("{sum}\n"))?;
    eprintln!("follow: {} checkpoints in {:.1}s", outs.len(), t0.elapsed().as_secs_f64());
    println!("{sum}");
    Ok(())
}

/// Every checkpoint blob of the corpus: verdict without the chain link, counts and plan hash.
fn cmd_scan(args: &[String]) -> Result<()> {
    let [out] = args else { bail!("scan <out.jsonl>") };
    let seqs = existing_seqs(0, u64::MAX)?;
    let t0 = Instant::now();
    let lines: Vec<String> = seqs
        .par_iter()
        .map(|&seq| -> Result<String> {
            let cp = decode_blob(&std::fs::read(blob_path(seq))?)?;
            let s = cp.checkpoint_summary.data();
            let c = load_committee(s.epoch)?;
            let verdict = verify_data(&c, &cp, None);
            let plan = plan_of(&cp);
            let p: usize = plan.iter().map(|t| t.puts.len()).sum();
            let r: usize = plan.iter().map(|t| t.removes.len()).sum();
            Ok(json!({"seq": seq, "epoch": s.epoch, "digest": hx(&cp.checkpoint_summary.digest().into_inner()), "txs": plan.len(),
                "puts": p, "removes": r, "plan": hx(&plan_hash(&plan)), "verify": verdict})
            .to_string())
        })
        .collect::<Result<_>>()?;
    let mut w = Vec::new();
    for l in &lines {
        writeln!(w, "{l}")?;
    }
    std::fs::write(out, w)?;
    eprintln!("scan: {} checkpoints in {:.1}s", lines.len(), t0.elapsed().as_secs_f64());
    Ok(())
}

fn cmd_detail(args: &[String]) -> Result<()> {
    let [seq] = args else { bail!("detail <seq>") };
    let cp = decode_blob(&std::fs::read(blob_path(seq.parse()?))?)?;
    for (i, t) in plan_of(&cp).iter().enumerate() {
        println!("tx {i} {} fx {}", hx(&t.tx), hx(&t.fx));
        for (id, v, d) in &t.puts {
            println!("  put {} {v} {}", hx(id), hx(d));
        }
        for (id, v, k) in &t.removes {
            println!("  rm {} {v} {k}", hx(id));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// mutants

fn splitmix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay[from..].windows(needle.len()).position(|w| w == needle).map(|p| p + from)
}

fn classify(blob: &[u8], flips: &[(usize, u8)], committee: &Committee, prev: Option<&Prev>) -> &'static str {
    let mut b = blob.to_vec();
    for &(o, m) in flips {
        b[o] ^= m;
    }
    classify_bytes(&b, committee, prev)
}

/// Mysten's verdict for a raw blob: whatever its decoder accepts is checked, even when it does
/// not re-serialize to the same bytes (a run-container or trailing-byte signer bitmap is a valid
/// certificate to sui-node, so it must be one to deepwave too).
fn classify_bytes(b: &[u8], committee: &Committee, prev: Option<&Prev>) -> &'static str {
    match decode_blob(b) {
        Err(_) => "decode",
        Ok(cp) => verify_data(committee, &cp, prev),
    }
}

fn existing_seqs(from: u64, to: u64) -> Result<Vec<u64>> {
    let mut v: Vec<u64> = std::fs::read_dir(corpus().join("chk"))?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.path().file_stem().and_then(|s| s.to_str()).and_then(|s| s.parse::<u64>().ok()))
        .filter(|s| *s >= from && *s <= to)
        .collect();
    v.sort();
    Ok(v)
}

fn cmd_mutants(args: &[String]) -> Result<()> {
    let [from, to, count, out] = args else { bail!("mutants <from> <to> <count> <out>") };
    let (from, to, count): (u64, u64, u64) = (from.parse()?, to.parse()?, count.parse()?);
    let all = existing_seqs(from, to)?;
    let mut lines = Vec::new();
    for k in 0..count {
        let seq = all[(splitmix(k.wrapping_mul(0x51) ^ 0x7a11) % all.len() as u64) as usize];
        let path = blob_path(seq);
        let blob = std::fs::read(&path)?;
        let cp = decode_blob(&blob)?;
        let c = load_committee(cp.checkpoint_summary.data().epoch)?;
        let Some(pd) = cp.checkpoint_summary.data().previous_digest else { continue };
        let prev = Prev { digest: pd.into_inner() };
        if verify_data(&c, &cp, Some(&prev)) != "ok" {
            bail!("seq {seq} does not verify unmutated");
        }
        let s = bcs::to_bytes(cp.checkpoint_summary.data())?;
        let sg = bcs::to_bytes(cp.checkpoint_summary.auth_sig())?;
        let contents = bcs::to_bytes(&cp.checkpoint_contents)?;
        let mut cands: Vec<(String, usize, u8)> = vec![];
        cands.push(("summary-epoch".into(), 1, 1));
        cands.push(("summary-seq".into(), 9, 1));
        cands.push(("summary-timestamp".into(), 1 + s.len() - 20, 1));
        if let Some(p) = find(&blob, cp.checkpoint_summary.data().content_digest.as_ref(), 1) {
            cands.push(("summary-content-digest".into(), p + 5, 0x10));
        }
        if let Some(p) = find(&blob, cp.checkpoint_summary.auth_sig().signature.as_ref(), 1 + s.len()) {
            cands.push(("cert-signature".into(), p + 7, 0x04));
            cands.push(("cert-signature-first".into(), p, 0x01));
        }
        cands.push(("cert-epoch".into(), 1 + s.len(), 1));
        cands.push(("cert-bitmap-tail".into(), 1 + s.len() + sg.len() - 1, 0x01));
        cands.push(("cert-bitmap-mid".into(), 1 + s.len() + sg.len() - 6, 0x02));
        if let Some(p) = find(&blob, &contents, 1 + s.len()) {
            cands.push(("contents-first-digest".into(), p + 4, 0x08));
            cands.push(("contents-last".into(), p + contents.len() - 1, 0x01));
        }
        for (ti, t) in cp.transactions.iter().enumerate().take(4) {
            let tb = bcs::to_bytes(&t.transaction)?;
            if let Some(p) = find(&blob, &tb, 1) {
                cands.push((format!("tx{ti}-data"), p + tb.len() / 2, 0x20));
                cands.push((format!("tx{ti}-last"), p + tb.len() - 1, 0x01));
            }
            let eb = bcs::to_bytes(&t.effects)?;
            if let Some(p) = find(&blob, &eb, 1) {
                cands.push((format!("tx{ti}-effects"), p + eb.len() / 2, 0x01));
                cands.push((format!("tx{ti}-effects-status"), p + 2, 0x01));
            }
            if let Some(ev) = &t.events {
                let vb = bcs::to_bytes(ev)?;
                if let Some(p) = find(&blob, &vb, 1) {
                    cands.push((format!("tx{ti}-events"), p + vb.len() - 1, 0x01));
                }
            }
            for (oi, o) in t.output_objects.iter().enumerate().take(3) {
                let ob = bcs::to_bytes(o)?;
                if let Some(p) = find(&blob, &ob, 1) {
                    cands.push((format!("tx{ti}-obj{oi}-tail"), p + ob.len() - 1, 0x01));
                    cands.push((format!("tx{ti}-obj{oi}-mid"), p + ob.len() / 2, 0x40));
                }
            }
        }
        let pick = (splitmix(k ^ 0xabcdef) as usize) % cands.len();
        let mut chosen: Vec<usize> = vec![pick, (pick + 7) % cands.len(), (pick + 13) % cands.len()];
        chosen.dedup();
        for ci in chosen {
            let (name, off, mask) = &cands[ci];
            let class = classify(&blob, &[(*off, *mask)], &c, Some(&prev));
            lines.push(json!({"seq": seq, "mutation": name, "flips": [[off, mask]], "prev": hx(&prev.digest),
                "expect": if class == "ok" { "ok" } else { "reject" }, "class": class}));
        }
        // chain break
        let mut bad = prev.digest;
        bad[0] ^= 1;
        lines.push(json!({"seq": seq, "mutation": "chain-break", "flips": [], "prev": hx(&bad),
            "expect": "reject", "class": classify(&blob, &[], &c, Some(&Prev { digest: bad }))}));
        // wrong committee
        let e = cp.checkpoint_summary.data().epoch;
        if e > 0 {
            let wc = load_committee(e - 1)?;
            lines.push(json!({"seq": seq, "mutation": "wrong-committee", "flips": [], "prev": hx(&prev.digest), "committee_epoch": e - 1,
                "expect": "reject", "class": classify(&blob, &[], &wc, Some(&prev))}));
        }
    }
    let mut w = Vec::new();
    for l in &lines {
        writeln!(w, "{l}")?;
    }
    std::fs::write(out, w)?;
    println!("{}", json!({"mutants": lines.len()}));
    Ok(())
}

// ---------------------------------------------------------------------------------------------

fn cmd_bench(args: &[String]) -> Result<()> {
    let name = args.first().ok_or_else(|| anyhow!("bench <name> --iters N --list FILE"))?.clone();
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
                list = Some(args[i + 1].clone());
                i += 2;
            }
            a => bail!("unknown argument {a}"),
        }
    }
    let list = list.ok_or_else(|| anyhow!("--list required"))?;
    let files: Vec<PathBuf> = std::fs::read_to_string(&list)?.lines().filter(|l| !l.is_empty()).map(PathBuf::from).collect();
    let blobs: Vec<Vec<u8>> = files.iter().map(std::fs::read).collect::<std::io::Result<_>>()?;
    let mut txs = 0u64;
    let mut cpn = 0u64;
    for b in &blobs {
        let cp = decode_blob(b)?;
        txs += cp.transactions.len() as u64;
        cpn += 1;
    }
    let run = |f: &dyn Fn() -> Result<()>| -> Result<Vec<u128>> {
        f()?;
        (0..iters.max(1))
            .map(|_| {
                let t = Instant::now();
                f()?;
                Ok(t.elapsed().as_nanos())
            })
            .collect()
    };
    let (mut passes, unit, units) = match name.as_str() {
        // decode CheckpointData and run every digest/object check except the certificate
        "apply-check" => {
            let p = run(&|| {
                for b in &blobs {
                    let cp = decode_blob(b)?;
                    let c = cp.checkpoint_summary.data();
                    if *cp.checkpoint_contents.digest() != c.content_digest {
                        bail!("contents");
                    }
                    let plan = plan_of(&cp);
                    for (t, d) in cp.transactions.iter().zip(cp.checkpoint_contents.inner().digests_iter()) {
                        if *t.transaction.digest() != d.transaction || t.effects.digest() != d.effects {
                            bail!("digest");
                        }
                        if t.effects.events_digest().copied() != t.events.as_ref().map(|e| e.digest()) {
                            bail!("events");
                        }
                        for o in &t.output_objects {
                            let _ = o.compute_object_reference();
                        }
                    }
                    std::hint::black_box(&plan);
                }
                Ok(())
            })?;
            (p, "tx", txs)
        }
        _ => bail!("unknown bench {name}"),
    };
    passes.sort();
    let med = passes[passes.len() / 2];
    println!(
        "{}",
        json!({"impl": "rust", "bench": name, "unit": unit, "units": units, "ns_per_unit": med as f64 / units as f64, "checkpoints": cpn})
    );
    let _ = Path::new("");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// edge: hand-made cases the random mutants do not reach (signer bitmap encodings, quorum edges,
// output object and event sets, transaction lists). Each case is one blob; the verdict is
// Mysten's, from `classify_bytes` (no re-serialisation rule).

fn uleb(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn roaring_canonical(members: &[u32]) -> Vec<u8> {
    let rb: roaring::RoaringBitmap = members.iter().copied().collect();
    let mut v = Vec::new();
    rb.serialize_into(&mut v).unwrap();
    v
}

/// One run container (key 0) holding `runs` as (start, len-1) pairs.
fn roaring_runs(runs: &[(u16, u16)]) -> Vec<u8> {
    let card: u32 = runs.iter().map(|r| r.1 as u32 + 1).sum();
    let mut v = Vec::new();
    v.extend_from_slice(&12347u32.to_le_bytes()); // size 1, run cookie
    v.push(1); // run bitmap: container 0 is a run container
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&((card - 1) as u16).to_le_bytes());
    v.extend_from_slice(&(runs.len() as u16).to_le_bytes());
    for (s, l) in runs {
        v.extend_from_slice(&s.to_le_bytes());
        v.extend_from_slice(&l.to_le_bytes());
    }
    v
}

fn runs_of(members: &[u32]) -> Vec<(u16, u16)> {
    let mut out: Vec<(u16, u16)> = vec![];
    for &m in members {
        let m = m as u16;
        if let Some(last) = out.last_mut() {
            if last.0 + last.1 + 1 == m {
                last.1 += 1;
                continue;
            }
        }
        out.push((m, 0));
    }
    out
}

/// The blob with the certificate's signer bitmap replaced by `bitmap` (raw roaring bytes) and,
/// optionally, the aggregate signature and epoch replaced.
fn with_cert(blob: &[u8], cp: &CheckpointData, bitmap: &[u8], sig: Option<[u8; 48]>, epoch: Option<u64>) -> Result<Vec<u8>> {
    let s = bcs::to_bytes(cp.checkpoint_summary.data())?;
    let sg = bcs::to_bytes(cp.checkpoint_summary.auth_sig())?;
    let at = 1 + s.len();
    anyhow::ensure!(blob[at..at + sg.len()] == sg[..], "certificate bytes not found");
    let mut cert = Vec::new();
    cert.extend_from_slice(&epoch.unwrap_or(u64::from_le_bytes(sg[0..8].try_into()?)).to_le_bytes());
    match sig {
        Some(x) => cert.extend_from_slice(&x),
        None => cert.extend_from_slice(&sg[8..56]),
    }
    uleb(bitmap.len(), &mut cert);
    cert.extend_from_slice(bitmap);
    let mut out = blob[..at].to_vec();
    out.extend_from_slice(&cert);
    out.extend_from_slice(&blob[at + sg.len()..]);
    Ok(out)
}

fn reencode(cp: &CheckpointData) -> Result<Vec<u8>> {
    let mut out = vec![1u8];
    out.extend_from_slice(&bcs::to_bytes(cp)?);
    Ok(out)
}

fn cmd_edge(args: &[String]) -> Result<()> {
    let [from, to, out_dir] = args else { bail!("edge <from> <to> <out_dir>") };
    let (from, to): (u64, u64) = (from.parse()?, to.parse()?);
    // A checkpoint with a transaction that has events and 2+ outputs, one without events, and 2+ transactions.
    let mut pick = None;
    for seq in existing_seqs(from, to)? {
        let blob = std::fs::read(blob_path(seq))?;
        let cp = decode_blob(&blob)?;
        let with_ev = cp.transactions.iter().position(|t| t.events.is_some() && t.output_objects.len() >= 2);
        let without_ev = cp.transactions.iter().position(|t| t.events.is_none() && !t.output_objects.is_empty());
        if let (Some(a), Some(b)) = (with_ev, without_ev) {
            if cp.checkpoint_summary.data().previous_digest.is_some() {
                pick = Some((seq, blob, cp, a, b));
                break;
            }
        }
    }
    let (seq, blob, cp, tev, tnoev) = pick.ok_or_else(|| anyhow!("no suitable checkpoint in range"))?;
    let epoch = cp.checkpoint_summary.data().epoch;
    let committee = load_committee(epoch)?;
    let prev = Prev { digest: cp.checkpoint_summary.data().previous_digest.unwrap().into_inner() };
    let members: Vec<u32> = cp.checkpoint_summary.auth_sig().signers_map.iter().collect();
    let n = committee.num_members() as u32;
    let mut cases: Vec<(String, Vec<u8>)> = vec![];
    cases.push(("original".into(), blob.clone()));
    // signer bitmap encodings sui-node accepts
    cases.push(("bitmap-runs".into(), with_cert(&blob, &cp, &roaring_runs(&runs_of(&members)), None, None)?));
    let mut t = roaring_canonical(&members);
    t.extend_from_slice(&[0xab, 0xcd, 0xef]);
    cases.push(("bitmap-trailing-bytes".into(), with_cert(&blob, &cp, &t, None, None)?));
    let mut g = roaring_canonical(&members);
    g[12..16].copy_from_slice(&[0xff; 4]); // the one container's offset
    cases.push(("bitmap-offset-garbage".into(), with_cert(&blob, &cp, &g, None, None)?));
    // signer bitmap encodings it rejects while decoding
    let over: Vec<u32> = (0..151).collect();
    cases.push(("bitmap-over-cap".into(), with_cert(&blob, &cp, &roaring_canonical(&over), None, None)?));
    let mut uns = roaring_canonical(&members);
    let l = uns.len();
    uns.swap(l - 1, l - 3);
    uns.swap(l - 2, l - 4);
    cases.push(("bitmap-unsorted-array".into(), with_cert(&blob, &cp, &uns, None, None)?));
    cases.push(("bitmap-touching-runs".into(), with_cert(&blob, &cp, &roaring_runs(&[(0, 1), (2, 1)]), None, None)?));
    cases.push(("bitmap-zero-runs".into(), with_cert(&blob, &cp, &roaring_runs(&[]), None, None)?));
    cases.push(("bitmap-bad-cookie".into(), with_cert(&blob, &cp, &[0x39, 0x30, 0, 0, 0, 0, 0, 0], None, None)?));
    // quorum edges
    cases.push(("bitmap-empty".into(), with_cert(&blob, &cp, &roaring_canonical(&[]), None, None)?));
    let mut unknown = members.clone();
    unknown.push(n);
    cases.push(("bitmap-unknown-index".into(), with_cert(&blob, &cp, &roaring_canonical(&unknown), None, None)?));
    let mut far = members.clone();
    far.push(70_000);
    cases.push(("bitmap-unknown-high-container".into(), with_cert(&blob, &cp, &roaring_canonical(&far), None, None)?));
    let mut below = members.clone();
    let mut w: u64 = below.iter().map(|&i| committee.weight(committee.authority_by_index(i).unwrap())).sum();
    while w >= committee.quorum_threshold() {
        let i = below.pop().unwrap();
        w -= committee.weight(committee.authority_by_index(i).unwrap());
    }
    cases.push(("bitmap-below-quorum".into(), with_cert(&blob, &cp, &roaring_canonical(&below), None, None)?));
    let mut plus = below.clone();
    for i in 0..n {
        if !members.contains(&i) && !plus.contains(&i) {
            plus.push(i);
            break;
        }
    }
    plus.sort();
    cases.push(("bitmap-swap-signer".into(), with_cert(&blob, &cp, &roaring_canonical(&members[1..].iter().copied().chain(plus.iter().copied().filter(|i| !members.contains(i))).collect::<std::collections::BTreeSet<_>>().into_iter().collect::<Vec<_>>()), None, None)?));
    cases.push(("bitmap-drop-one".into(), with_cert(&blob, &cp, &roaring_canonical(&members[1..]), None, None)?));
    // aggregate signature bytes
    cases.push(("sig-not-a-point".into(), with_cert(&blob, &cp, &roaring_canonical(&members), Some([0xff; 48]), None)?));
    let mut inf = [0u8; 48];
    inf[0] = 0xc0;
    cases.push(("sig-infinity".into(), with_cert(&blob, &cp, &roaring_canonical(&members), Some(inf), None)?));
    cases.push(("sig-not-a-point-and-epoch".into(), with_cert(&blob, &cp, &roaring_canonical(&members), Some([0xff; 48]), Some(epoch + 1))?));
    cases.push(("sig-not-a-point-and-unknown-signer".into(), with_cert(&blob, &cp, &roaring_canonical(&unknown), Some([0xff; 48]), None)?));
    cases.push(("cert-epoch-and-below-quorum".into(), with_cert(&blob, &cp, &roaring_canonical(&below), None, Some(epoch + 1))?));
    // transactions, outputs, events
    let mut c = cp.clone();
    c.transactions[tev].output_objects.reverse();
    cases.push(("objects-reordered".into(), reencode(&c)?));
    let mut c = cp.clone();
    c.transactions[tev].output_objects.pop();
    cases.push(("objects-missing".into(), reencode(&c)?));
    let mut c = cp.clone();
    let o = c.transactions[tev].output_objects[0].clone();
    c.transactions[tev].output_objects.push(o);
    cases.push(("objects-duplicate".into(), reencode(&c)?));
    let mut c = cp.clone();
    let o = c.transactions[tev].output_objects[0].clone();
    c.transactions[tev].output_objects[1] = o;
    cases.push(("objects-duplicate-replaces".into(), reencode(&c)?));
    let mut c = cp.clone();
    let o = c.transactions[tev].output_objects.pop().unwrap();
    c.transactions[tnoev].output_objects.push(o);
    cases.push(("objects-moved-between-txs".into(), reencode(&c)?));
    let mut c = cp.clone();
    let o = c.transactions[tnoev].output_objects[0].clone();
    c.transactions[tev].output_objects.push(o);
    cases.push(("objects-extra-from-other-tx".into(), reencode(&c)?));
    let mut c = cp.clone();
    c.transactions[tev].input_objects.clear();
    cases.push(("inputs-cleared".into(), reencode(&c)?));
    let mut c = cp.clone();
    c.transactions[tev].events = None;
    cases.push(("events-dropped".into(), reencode(&c)?));
    let mut c = cp.clone();
    c.transactions[tnoev].events = Some(Default::default());
    cases.push(("events-added-empty".into(), reencode(&c)?));
    let mut c = cp.clone();
    c.transactions.pop();
    cases.push(("tx-dropped".into(), reencode(&c)?));
    let mut c = cp.clone();
    c.transactions.swap(tev, tnoev);
    cases.push(("tx-swapped".into(), reencode(&c)?));
    let mut c = cp.clone();
    let t = c.transactions[0].clone();
    c.transactions.push(t);
    cases.push(("tx-extra".into(), reencode(&c)?));

    std::fs::create_dir_all(out_dir)?;
    let mut lines = Vec::new();
    for (name, b) in &cases {
        let class = classify_bytes(b, &committee, Some(&prev));
        std::fs::write(Path::new(out_dir).join(format!("{name}.chk")), b)?;
        writeln!(lines, "{}", json!({"name": name, "seq": seq, "committee_epoch": epoch, "prev": hx(&prev.digest), "expect": if class == "ok" { "ok" } else { "reject" }, "class": class}))?;
    }
    std::fs::write(Path::new(out_dir).join("edge.jsonl"), lines)?;
    println!("{}", json!({"edge": cases.len(), "seq": seq}));
    Ok(())
}
