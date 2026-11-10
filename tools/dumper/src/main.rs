//! zui-dumper: ground truth for the deepwave conformance corpus, computed with Mysten's own
//! sui-types (mainnet-v1.83.1). Formats: docs/CONFORMANCE.md. Corpus builder: tools/corpus-build.sh.
//!
//! Commands:
//!   truth <out_dir> <file.chk|->...          .chk (0x01 ++ BCS(CheckpointData)) -> <out_dir>/<seq>.jsonl.zst;
//!                                            prints one manifest line per blob (header + "cov"), seq order
//!   head <file.chk|->...                     the same manifest lines without writing truth
//!   convert <out_dir> <file.binpb.zst|->...  sui.rpc.v2 Checkpoint proto -> <out_dir>/<seq>.chk (parallel)
//!   loaded <out.jsonl> <file.binpb.zst|->... each transaction's effects.unchanged_loaded_runtime_objects
//!                                            (what the .chk form drops) as JSON lines, seq order
//!   fetch-node <url> <out_dir> <seq>...      sui.rpc.v2 GetCheckpoint -> <out_dir>/<seq>.binpb.zst (50 ms apart)
//!   epochs <url> <from> <to>                 sui.rpc.v2 GetEpoch -> JSON lines (first/last checkpoint, protocol)
//!   plan <epochs.jsonl> <per_epoch> <seed>   C1 strata: first + last + per_epoch seeded picks of every epoch
//!   coverage <manifest.jsonl> <registry.yaml> <out_dir>
//!                                            _variants.json (checkpoints per Enum::Variant) + _unseen.json
//!   bench <name> --iters N --list <file>     Rust baseline on the listed blobs (harness protocol, CONTRACTS.md 7)
//!   bench <iters> <file.chk>...              legacy: decode and decode+digest summary line
//!   zcat <file.zst>...                       decompress truth files to stdout (no zstd CLI needed)
//!
//! Every command that reads blobs re-checks the blob tag and the whole-blob BCS round trip.

mod tree;

use anyhow::{Context, Result, anyhow, bail};
use fastcrypto::hash::{Blake2b256, HashFunction};
use prost::Message as _;
use rayon::prelude::*;
use serde::Serialize;
use shared_crypto::intent::{Intent, IntentMessage, IntentScope};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use sui_types::crypto::SuiSignature;
use sui_types::effects::TransactionEffectsAPI;
use sui_types::full_checkpoint_content::{Checkpoint, CheckpointData};
use sui_types::message_envelope::Message;
use sui_types::signature::GenericSignature;
use sui_types::transaction::TransactionDataAPI;
use tree::Coverage;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        bail!("usage: zui-dumper truth|head|convert|loaded|fetch-node|epochs|plan|coverage|bench|zcat ...");
    }
    match args[1].as_str() {
        "truth" => cmd_truth(&args[2..]),
        "head" => cmd_head(&args[2..]),
        "convert" => cmd_convert(&args[2..]),
        "loaded" => cmd_loaded(&args[2..]),
        "fetch-node" => cmd_fetch_node(&args[2..]),
        "epochs" => cmd_epochs(&args[2..]),
        "plan" => cmd_plan(&args[2..]),
        "coverage" => cmd_coverage(&args[2..]),
        "bench" => cmd_bench(&args[2..]),
        "zcat" => {
            let mut out = std::io::stdout().lock();
            for f in &args[2..] {
                out.write_all(&zstd::decode_all(&std::fs::read(f)?[..])?)?;
            }
            Ok(())
        }
        c => bail!("unknown command {c}"),
    }
}

fn decode_blob(raw: &[u8], what: &dyn std::fmt::Display) -> Result<CheckpointData> {
    if raw.first() != Some(&1) {
        bail!("{what}: not a BCS blob (first byte {:?})", raw.first());
    }
    bcs::from_bytes(&raw[1..]).with_context(|| format!("decode {what}"))
}

fn hex32(d: &[u8]) -> String {
    hex::encode(d)
}

fn blake(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2b256::default();
    for p in parts {
        h.update(p);
    }
    h.finalize().digest
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

struct Line {
    k: &'static str,
    p: String,
    o: usize,
    n: usize,
    d: Option<String>,
    sd: Option<String>,
    t: Option<String>,
}

impl Line {
    fn render(&self, out: &mut String) {
        out.push_str("{\"k\":");
        tree::push_json_str(out, self.k);
        out.push_str(",\"p\":");
        tree::push_json_str(out, &self.p);
        out.push_str(&format!(",\"o\":{},\"n\":{}", self.o, self.n));
        if let Some(d) = &self.d {
            out.push_str(&format!(",\"d\":\"{d}\""));
        }
        if let Some(sd) = &self.sd {
            out.push_str(&format!(",\"sd\":\"{sd}\""));
        }
        if let Some(t) = &self.t {
            out.push_str(",\"t\":");
            out.push_str(t);
        }
        out.push_str("}\n");
    }
}

struct Walker<'a> {
    raw: &'a [u8],
    pos: usize,
    lines: Vec<Line>,
    cov: Coverage,
}

impl<'a> Walker<'a> {
    /// Asserts that `v` re-encodes to exactly the bytes at the cursor and advances.
    fn take<T: Serialize>(&mut self, v: &T, what: &str) -> Result<(usize, usize)> {
        let b = bcs::to_bytes(v)?;
        let end = self.pos + b.len();
        if end > self.raw.len() || self.raw[self.pos..end] != b[..] {
            bail!("{what}: re-encoded bytes do not match raw at offset {}", self.pos);
        }
        let r = (self.pos, b.len());
        self.pos = end;
        Ok(r)
    }

    fn emit<T: Serialize>(
        &mut self,
        k: &'static str,
        p: String,
        v: &T,
        d: Option<String>,
        sd: Option<String>,
        with_tree: bool,
    ) -> Result<usize> {
        let (o, n) = self.take(v, &p)?;
        let t = if with_tree { Some(tree::to_text(v, &mut self.cov).map_err(|e| anyhow!("{p}: {e}"))?) } else { None };
        self.lines.push(Line { k, p, o, n, d, sd, t });
        Ok(n)
    }

    fn uleb(&mut self) -> Result<u64> {
        read_uleb(self.raw, &mut self.pos)
    }
    fn skip(&mut self, n: usize) {
        self.pos += n;
    }
}

/// Scheme name of a user signature, as recorded in the header's `sigs`.
fn sig_scheme(sig: &GenericSignature) -> String {
    match sig {
        GenericSignature::MultiSig(_) => "MultiSig".into(),
        GenericSignature::MultiSigLegacy(_) => "MultiSigLegacy".into(),
        GenericSignature::ZkLoginAuthenticator(_) => "ZkLoginAuthenticator".into(),
        GenericSignature::PasskeyAuthenticator(_) => "PasskeyAuthenticator".into(),
        GenericSignature::Signature(s) => format!("{:?}", s.scheme()),
    }
}

/// Signature inner structures: flag byte then BCS of the authenticator.
fn emit_sig_inner(w: &mut Walker, p: &str, sig: &GenericSignature, sig_off: usize) -> Result<()> {
    let bytes = sig.as_ref();
    // sig BCS = uleb(len) ++ bytes; inner starts after the length prefix and the flag byte.
    let mut q = sig_off;
    let len = read_uleb(w.raw, &mut q)? as usize;
    if len != bytes.len() {
        bail!("{p}: sig length mismatch");
    }
    let inner_off = q + 1;
    let inner = &bytes[1..];
    let (k, t): (&'static str, Option<String>) = match sig {
        GenericSignature::MultiSig(m) => ("MultiSig", Some(tree::to_text(m, &mut w.cov).map_err(|e| anyhow!("{e}"))?)),
        GenericSignature::MultiSigLegacy(m) => {
            ("MultiSigLegacy", Some(tree::to_text(m, &mut w.cov).map_err(|e| anyhow!("{e}"))?))
        }
        GenericSignature::ZkLoginAuthenticator(z) => {
            ("ZkLoginAuthenticator", Some(tree::to_text(z, &mut w.cov).map_err(|e| anyhow!("{e}"))?))
        }
        GenericSignature::PasskeyAuthenticator(_) => {
            let raw: sui_types::passkey_authenticator::RawPasskeyAuthenticator = bcs::from_bytes(inner)?;
            ("PasskeyAuthenticator", Some(tree::to_text(&raw, &mut w.cov).map_err(|e| anyhow!("{e}"))?))
        }
        GenericSignature::Signature(s) => {
            w.cov.variants.insert(format!("SignatureScheme::{:?}", s.scheme()));
            return Ok(());
        }
    };
    // inner BCS must be exactly the remaining bytes
    w.lines.push(Line { k, p: format!("{p}.inner"), o: inner_off, n: inner.len(), d: None, sd: None, t });
    Ok(())
}

struct TruthOut {
    seq: u64,
    /// Header line followed by one line per object (the truth file body).
    lines: String,
    /// Manifest line: the header plus "cov" (the Enum::Variant names this checkpoint contains).
    manifest: String,
}

fn json_str_list<'a, I: IntoIterator<Item = &'a String>>(it: I) -> String {
    let mut s = String::from("[");
    for (i, v) in it.into_iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        tree::push_json_str(&mut s, v);
    }
    s.push(']');
    s
}

fn truth_for(path: &Path) -> Result<TruthOut> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    truth_for_raw(&raw, &path.display())
}

fn truth_for_raw(raw: &[u8], what: &dyn std::fmt::Display) -> Result<TruthOut> {
    let cp = decode_blob(raw, what)?;
    let mut w = Walker { raw, pos: 1, lines: Vec::new(), cov: Coverage::default() };

    // Whole-checkpoint round trip.
    let whole = bcs::to_bytes(&cp)?;
    if whole[..] != raw[1..] {
        bail!("{what}: CheckpointData re-encode differs from raw");
    }

    let summary = cp.checkpoint_summary.data();
    let seq = summary.sequence_number;
    let sig = cp.checkpoint_summary.auth_sig();
    let cs_start = w.pos;
    let sd = {
        let im = IntentMessage::new(Intent::sui_app(IntentScope::CheckpointSummary), summary);
        let mut m = bcs::to_bytes(&im)?;
        m.extend_from_slice(&bcs::to_bytes(&sig.epoch)?);
        hex32(&blake(&[&m]))
    };
    w.emit("CheckpointSummary", "summary".into(), summary, Some(hex32(summary.digest().inner())), Some(sd), true)?;
    w.emit("AuthorityStrongQuorumSignInfo", "summary.sig".into(), sig, None, None, true)?;
    w.lines.push(Line {
        k: "CertifiedCheckpointSummary",
        p: "summary.cert".into(),
        o: cs_start,
        n: w.pos - cs_start,
        d: None,
        sd: None,
        t: None,
    });
    w.emit(
        "CheckpointContents",
        "contents".into(),
        &cp.checkpoint_contents,
        Some(hex32(cp.checkpoint_contents.digest().inner())),
        None,
        true,
    )?;
    let ntx = w.uleb()? as usize;
    if ntx != cp.transactions.len() {
        bail!("tx count mismatch");
    }
    let mut kinds: Vec<String> = Vec::new();
    let mut sigs: Vec<Vec<String>> = Vec::new();
    let mut failed: Vec<usize> = Vec::new();
    let mut big: usize = 0;
    for (i, tx) in cp.transactions.iter().enumerate() {
        let tx_start = w.pos;
        let ssd = tx.transaction.data();
        let n_one = w.uleb()?;
        if n_one != 1 {
            bail!("SenderSignedData len {n_one}");
        }
        let intent = &raw[w.pos..w.pos + 3];
        if intent != [0, 0, 0] {
            bail!("tx{i}: unexpected intent {:?}", intent);
        }
        w.skip(3);
        let td = ssd.transaction_data();
        let sdig = {
            let im = IntentMessage::new(Intent::sui_transaction(), td);
            hex32(&blake(&[&bcs::to_bytes(&im)?]))
        };
        w.emit("TransactionData", format!("tx[{i}].data"), td, Some(hex32(td.digest().inner())), Some(sdig), true)?;
        // kind name for the header, via the coverage tracer
        let mut kc = Coverage::default();
        let _ = tree::to_node(td.kind(), &mut kc);
        match kc.variants.iter().find(|v| v.starts_with("TransactionKind::")) {
            Some(k) => kinds.push(k.trim_start_matches("TransactionKind::").to_string()),
            None => bail!("tx{i}: no TransactionKind variant"),
        }
        let nsig = w.uleb()? as usize;
        if nsig != ssd.tx_signatures().len() {
            bail!("tx{i}: sig count mismatch");
        }
        let mut tx_sigs = Vec::new();
        for (j, s) in ssd.tx_signatures().iter().enumerate() {
            let off = w.pos;
            let p = format!("tx[{i}].sig[{j}]");
            w.emit("GenericSignature", p.clone(), s, None, None, false)?;
            emit_sig_inner(&mut w, &p, s, off)?;
            tx_sigs.push(sig_scheme(s));
        }
        sigs.push(tx_sigs);
        w.lines.push(Line {
            k: "Transaction",
            p: format!("tx[{i}].transaction"),
            o: tx_start,
            n: w.pos - tx_start,
            d: None,
            sd: None,
            t: None,
        });
        if td.digest() != *tx.effects.transaction_digest() {
            bail!("tx{i}: effects.transaction_digest mismatch");
        }
        if tx.effects.status().is_err() {
            failed.push(i);
        }
        w.emit("TransactionEffects", format!("tx[{i}].effects"), &tx.effects, Some(hex32(tx.effects.digest().inner())), None, true)?;
        let tag = *w.raw.get(w.pos).ok_or_else(|| anyhow!("tx{i}: events tag past end"))?;
        w.skip(1);
        match (&tx.events, tag) {
            (Some(ev), 1) => {
                w.emit("TransactionEvents", format!("tx[{i}].events"), ev, Some(hex32(&ev.digest().into_inner())), None, true)?;
            }
            (None, 0) => {}
            _ => bail!("tx{i}: events option tag mismatch"),
        }
        for (label, objs) in [("in", &tx.input_objects), ("out", &tx.output_objects)] {
            let n = w.uleb()? as usize;
            if n != objs.len() {
                bail!("tx{i}: {label} object count mismatch");
            }
            for (j, o) in objs.iter().enumerate() {
                let len = w.emit("Object", format!("tx[{i}].{label}[{j}]"), o, Some(hex32(o.digest().inner())), None, true)?;
                big = big.max(len);
            }
        }
    }
    if w.pos != raw.len() {
        bail!("trailing bytes: {} of {}", w.pos, raw.len());
    }

    let eoe = summary.end_of_epoch_data.as_ref();
    let header_body = format!(
        "\"k\":\"Header\",\"seq\":{},\"epoch\":{},\"len\":{},\"txs\":{},\"eoe\":{},\"next_pv\":{},\"ts\":{},\"kinds\":{},\"sigs\":[{}],\"fail\":[{}],\"big\":{}",
        seq,
        summary.epoch,
        raw.len(),
        cp.transactions.len(),
        eoe.is_some(),
        eoe.map(|e| e.next_epoch_protocol_version.as_u64().to_string()).unwrap_or("null".into()),
        summary.timestamp_ms,
        json_str_list(&kinds),
        sigs.iter().map(|s| json_str_list(s)).collect::<Vec<_>>().join(","),
        failed.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(","),
        big,
    );
    let mut lines = format!("{{{header_body}}}\n");
    for l in &w.lines {
        l.render(&mut lines);
    }
    let manifest = format!("{{{header_body},\"cov\":{}}}\n", json_str_list(&w.cov.variants));
    Ok(TruthOut { seq, lines, manifest })
}

/// Runs `f` over every input in parallel and prints the returned manifest lines in seq order.
fn for_each_blob(files: &[PathBuf], f: impl Fn(&Path) -> Result<TruthOut> + Sync) -> Result<()> {
    let done = AtomicUsize::new(0);
    let failed = AtomicUsize::new(0);
    let mut results: Vec<(u64, String)> = files
        .par_iter()
        .filter_map(|p| match f(p) {
            Ok(t) => {
                let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                if n % 1000 == 0 {
                    eprintln!("truth: {n}/{}", files.len());
                }
                Some((t.seq, t.manifest))
            }
            Err(e) => {
                failed.fetch_add(1, Ordering::Relaxed);
                eprintln!("FAIL {}: {e:#}", p.display());
                None
            }
        })
        .collect();
    results.sort_by_key(|r| r.0);
    let mut stdout = std::io::stdout().lock();
    for (_, m) in &results {
        stdout.write_all(m.as_bytes())?;
    }
    stdout.flush()?;
    eprintln!("truth: ok {} failed {}", done.load(Ordering::Relaxed), failed.load(Ordering::Relaxed));
    if failed.load(Ordering::Relaxed) > 0 {
        std::process::exit(2);
    }
    Ok(())
}

fn cmd_truth(args: &[String]) -> Result<()> {
    let out_dir = PathBuf::from(args.first().ok_or_else(|| anyhow!("truth <out_dir> files..."))?);
    std::fs::create_dir_all(&out_dir)?;
    let files = expand(&args[1..])?;
    for_each_blob(&files, |p| {
        let t = truth_for(p)?;
        let dst = out_dir.join(format!("{}.jsonl.zst", t.seq));
        let tmp = out_dir.join(format!(".{}.jsonl.zst.part", t.seq));
        let z = zstd::encode_all(t.lines.as_bytes(), 9)?;
        std::fs::write(&tmp, z)?;
        std::fs::rename(&tmp, &dst)?;
        Ok(t)
    })
}

fn cmd_head(args: &[String]) -> Result<()> {
    let files = expand(args)?;
    for_each_blob(&files, truth_for)
}

fn expand(args: &[String]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for a in args {
        if a == "-" {
            for line in std::io::stdin().lines() {
                let line = line?;
                if !line.trim().is_empty() {
                    out.push(PathBuf::from(line.trim()));
                }
            }
        } else {
            out.push(PathBuf::from(a));
        }
    }
    Ok(out)
}

fn proto_to_chk(bytes: &[u8]) -> Result<(u64, Vec<u8>)> {
    let dec = zstd::decode_all(bytes)?;
    let proto = sui_rpc::proto::sui::rpc::v2::Checkpoint::decode(&dec[..])?;
    let cp: Checkpoint = (&proto).try_into().map_err(|e| anyhow!("proto->Checkpoint: {e:?}"))?;
    let data: CheckpointData = cp.into();
    let seq = data.checkpoint_summary.data().sequence_number;
    let mut out = vec![1u8];
    out.extend(bcs::to_bytes(&data)?);
    Ok((seq, out))
}

fn cmd_convert(args: &[String]) -> Result<()> {
    let out_dir = PathBuf::from(args.first().ok_or_else(|| anyhow!("convert <out_dir> files..."))?);
    std::fs::create_dir_all(&out_dir)?;
    let files = expand(&args[1..])?;
    let failed = AtomicUsize::new(0);
    files.par_iter().for_each(|f| {
        let r = (|| -> Result<()> {
            let bytes = std::fs::read(f)?;
            let (seq, chk) = proto_to_chk(&bytes)?;
            let stem = f.file_name().and_then(|n| n.to_str()).and_then(|n| n.split('.').next()).unwrap_or("");
            if stem != seq.to_string() {
                bail!("file name says {stem}, checkpoint is {seq}");
            }
            let tmp = out_dir.join(format!(".{seq}.chk.part"));
            std::fs::write(&tmp, chk)?;
            std::fs::rename(&tmp, out_dir.join(format!("{seq}.chk")))?;
            Ok(())
        })();
        if let Err(e) = r {
            failed.fetch_add(1, Ordering::Relaxed);
            eprintln!("FAIL convert {}: {e:#}", f.display());
        }
    });
    if failed.load(Ordering::Relaxed) > 0 {
        std::process::exit(2);
    }
    Ok(())
}

/// `loaded <out.jsonl> <file.binpb.zst|->...`: one line per transaction whose effects name
/// unchanged_loaded_runtime_objects, `{"checkpoint":S,"tx":I,"loaded":[["0x<id>",V],...]}` (I is the
/// transaction's index in the checkpoint), in (S, I) order. The archive proto is the only source
/// of that list (it is not part of the certified effects, and the .chk form drops it); the
/// rpc-surface suites serve it from this file.
fn cmd_loaded(args: &[String]) -> Result<()> {
    let out = PathBuf::from(args.first().ok_or_else(|| anyhow!("loaded <out.jsonl> files..."))?);
    let files = expand(&args[1..])?;
    let mut rows: Vec<(u64, usize, String)> = Vec::new();
    for f in &files {
        let dec = zstd::decode_all(&std::fs::read(f).with_context(|| f.display().to_string())?[..])?;
        let proto = sui_rpc::proto::sui::rpc::v2::Checkpoint::decode(&dec[..])?;
        let cp: Checkpoint = (&proto).try_into().map_err(|e| anyhow!("{}: proto->Checkpoint: {e:?}", f.display()))?;
        let data: CheckpointData = cp.into();
        let seq = data.checkpoint_summary.data().sequence_number;
        for (i, t) in proto.transactions.iter().enumerate() {
            let Some(fx) = t.effects.as_ref() else { continue };
            if fx.unchanged_loaded_runtime_objects.is_empty() {
                continue;
            }
            let mut refs = Vec::with_capacity(fx.unchanged_loaded_runtime_objects.len());
            for r in &fx.unchanged_loaded_runtime_objects {
                let id = r.object_id.as_deref().ok_or_else(|| anyhow!("{}: tx {i}: loaded object without object_id", f.display()))?;
                let v = r.version.ok_or_else(|| anyhow!("{}: tx {i}: loaded object without version", f.display()))?;
                refs.push(format!("[\"{id}\",{v}]"));
            }
            rows.push((seq, i, format!("{{\"checkpoint\":{seq},\"tx\":{i},\"loaded\":[{}]}}\n", refs.join(","))));
        }
    }
    rows.sort_by_key(|r| (r.0, r.1));
    let tmp = out.with_extension("jsonl.part");
    std::fs::write(&tmp, rows.iter().map(|r| r.2.as_str()).collect::<String>())?;
    std::fs::rename(&tmp, &out)?;
    eprintln!("loaded: {} transactions with loaded runtime objects in {} checkpoints", rows.len(), files.len());
    Ok(())
}

fn cmd_fetch_node(args: &[String]) -> Result<()> {
    use sui_rpc::proto::sui::rpc::v2::GetCheckpointRequest;
    if args.len() < 3 {
        bail!("fetch-node <url> <out_dir> <seq>...");
    }
    let url = args[0].clone();
    let out_dir = PathBuf::from(&args[1]);
    std::fs::create_dir_all(&out_dir)?;
    let seqs: Vec<u64> = args[2..].iter().map(|s| s.parse()).collect::<Result<_, _>>()?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let mut client = sui_rpc::Client::new(url)?;
        for seq in seqs {
            let mut req = GetCheckpointRequest::default();
            req.checkpoint_id =
                Some(sui_rpc::proto::sui::rpc::v2::get_checkpoint_request::CheckpointId::SequenceNumber(seq));
            req.read_mask = Some(field_mask(&[
                "summary.bcs",
                "signature",
                "contents.bcs",
                "transactions.transaction.bcs",
                "transactions.effects.bcs",
                "transactions.effects.unchanged_loaded_runtime_objects",
                "transactions.events.bcs",
                "objects.objects.bcs",
            ]));
            let resp = client.ledger_client().get_checkpoint(req).await?.into_inner();
            let cp = resp.checkpoint.ok_or_else(|| anyhow!("no checkpoint"))?;
            let bytes = cp.encode_to_vec();
            let z = zstd::encode_all(&bytes[..], 3)?;
            std::fs::write(out_dir.join(format!("{seq}.binpb.zst")), z)?;
            // throttle: the node is production; keep this light
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
}

fn field_mask(paths: &[&str]) -> prost_types::FieldMask {
    prost_types::FieldMask { paths: paths.iter().map(|s| s.to_string()).collect() }
}

fn ts_ms(t: &Option<prost_types::Timestamp>) -> String {
    t.as_ref().map(|t| (t.seconds as i128 * 1000 + t.nanos as i128 / 1_000_000).to_string()).unwrap_or("null".into())
}

fn opt_u64(v: Option<u64>) -> String {
    v.map(|v| v.to_string()).unwrap_or("null".into())
}

fn cmd_epochs(args: &[String]) -> Result<()> {
    use sui_rpc::proto::sui::rpc::v2::GetEpochRequest;
    if args.len() != 3 {
        bail!("epochs <url> <from> <to>");
    }
    let url = args[0].clone();
    let from: u64 = args[1].parse()?;
    let to: u64 = args[2].parse()?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let mut client = sui_rpc::Client::new(url)?;
        let mut out = std::io::stdout().lock();
        for e in from..=to {
            let mut req = GetEpochRequest::default();
            req.epoch = Some(e);
            req.read_mask = Some(field_mask(&[
                "epoch",
                "first_checkpoint",
                "last_checkpoint",
                "start",
                "end",
                "reference_gas_price",
                "protocol_config.protocol_version",
            ]));
            let ep = client
                .ledger_client()
                .get_epoch(req)
                .await
                .with_context(|| format!("GetEpoch {e}"))?
                .into_inner()
                .epoch
                .ok_or_else(|| anyhow!("epoch {e}: empty response"))?;
            writeln!(
                out,
                "{{\"epoch\":{},\"first\":{},\"last\":{},\"pv\":{},\"rgp\":{},\"start_ms\":{},\"end_ms\":{}}}",
                e,
                opt_u64(ep.first_checkpoint),
                opt_u64(ep.last_checkpoint),
                opt_u64(ep.protocol_config.as_ref().and_then(|p| p.protocol_version)),
                opt_u64(ep.reference_gas_price),
                ts_ms(&ep.start),
                ts_ms(&ep.end),
            )?;
            out.flush()?;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
}

/// splitmix64: the fixed PRNG behind the strata picks (documented in CORPUS.md).
struct SplitMix(u64);
impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
}

fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn cmd_plan(args: &[String]) -> Result<()> {
    if args.len() != 3 {
        bail!("plan <epochs.jsonl> <per_epoch> <seed>");
    }
    let per: u64 = args[1].parse()?;
    let seed = fnv1a(&args[2]);
    let text = std::fs::read_to_string(&args[0])?;
    let mut out = std::io::stdout().lock();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line)?;
        let e = v["epoch"].as_u64().ok_or_else(|| anyhow!("epoch"))?;
        let (Some(first), Some(last)) = (v["first"].as_u64(), v["last"].as_u64()) else {
            continue; // the current epoch has no last checkpoint yet
        };
        let mut picks = std::collections::BTreeSet::new();
        picks.insert(first);
        picks.insert(last);
        let inner = last.saturating_sub(first).saturating_sub(1);
        if inner <= per {
            for s in first + 1..last {
                picks.insert(s);
            }
        } else {
            let mut rng = SplitMix(seed ^ e.wrapping_mul(0x9e3779b97f4a7c15));
            let mut n = 0;
            while n < per {
                if picks.insert(first + 1 + rng.next() % inner) {
                    n += 1;
                }
            }
        }
        for s in picks {
            writeln!(out, "{s}")?;
        }
    }
    Ok(())
}

/// Collects `Enum::Variant` names from the serde-reflection registry.
fn registry_variants(yaml: &str) -> Result<Vec<String>> {
    // insta snapshots carry a `---`-delimited metadata header before the registry document.
    let body = yaml.rsplit("\n---\n").next().unwrap_or(yaml);
    let reg: serde_yaml::Value = serde_yaml::from_str(body)?;
    let mut out = Vec::new();
    let map = reg.as_mapping().ok_or_else(|| anyhow!("registry is not a mapping"))?;
    for (name, fmt) in map {
        let name = name.as_str().unwrap_or_default();
        if let Some(variants) = fmt.get("ENUM").and_then(|e| e.as_mapping()) {
            for (_, var) in variants {
                if let Some(vm) = var.as_mapping() {
                    for (vname, _) in vm {
                        out.push(format!("{name}::{}", vname.as_str().unwrap_or_default()));
                    }
                }
            }
        }
    }
    out.sort();
    Ok(out)
}

fn cmd_coverage(args: &[String]) -> Result<()> {
    if args.len() != 3 {
        bail!("coverage <manifest.jsonl> <registry.yaml> <out_dir>");
    }
    let manifest = std::fs::read_to_string(&args[0])?;
    let mut counts = BTreeMap::<String, u64>::new();
    let mut seen_seq = std::collections::HashSet::new();
    for line in manifest.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line)?;
        let seq = v["seq"].as_u64().ok_or_else(|| anyhow!("manifest line without seq"))?;
        if !seen_seq.insert(seq) {
            bail!("manifest has seq {seq} twice");
        }
        for c in v["cov"].as_array().ok_or_else(|| anyhow!("seq {seq}: no cov"))? {
            *counts.entry(c.as_str().unwrap_or_default().to_string()).or_default() += 1;
        }
    }
    let registry = registry_variants(&std::fs::read_to_string(&args[1])?)?;
    let unseen: Vec<&String> = registry.iter().filter(|v| !counts.contains_key(*v)).collect();
    let out_dir = PathBuf::from(&args[2]);
    let mut s = String::from("{\n");
    for (i, (k, v)) in counts.iter().enumerate() {
        s.push_str("  ");
        tree::push_json_str(&mut s, k);
        s.push_str(&format!(": {v}{}\n", if i + 1 < counts.len() { "," } else { "" }));
    }
    s.push_str("}\n");
    std::fs::write(out_dir.join("_variants.json"), s)?;
    let mut u = String::from("[\n");
    for (i, k) in unseen.iter().enumerate() {
        u.push_str("  ");
        tree::push_json_str(&mut u, k);
        u.push_str(if i + 1 < unseen.len() { ",\n" } else { "\n" });
    }
    u.push_str("]\n");
    std::fs::write(out_dir.join("_unseen.json"), u)?;
    let reg_seen = registry.len() - unseen.len();
    println!(
        "{{\"checkpoints\":{},\"variants_seen\":{},\"registry_variants\":{},\"registry_seen\":{},\"registry_unseen\":{}}}",
        seen_seq.len(),
        counts.len(),
        registry.len(),
        reg_seen,
        unseen.len()
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Bench: the Rust side of `zig build bench` (CONTRACTS.md section 7). Inputs are read into memory
// first; each pass runs over every input once on one thread; the record carries the median pass.

struct BenchOut {
    name: String,
    unit: &'static str,
    units: u64,
    bytes: u64,
    passes: Vec<u128>,
}

impl BenchOut {
    fn print(&mut self) {
        self.passes.sort();
        let med = self.passes[self.passes.len() / 2];
        let min = self.passes[0];
        println!(
            "{{\"impl\":\"rust\",\"bench\":\"{}\",\"unit\":\"{}\",\"units\":{},\"bytes\":{},\"iters\":{},\"median_ns\":{},\"min_ns\":{},\"ns_per_unit\":{:.2}}}",
            self.name,
            self.unit,
            self.units,
            self.bytes,
            self.passes.len(),
            med,
            min,
            med as f64 / self.units.max(1) as f64
        );
    }
}

fn passes(iters: usize, mut f: impl FnMut() -> Result<()>) -> Result<Vec<u128>> {
    f()?; // warm-up, not timed
    let mut v = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        f()?;
        v.push(t.elapsed().as_nanos());
    }
    Ok(v)
}

fn all_digests(cp: &CheckpointData) -> u8 {
    let mut acc = cp.checkpoint_summary.data().digest().inner()[0];
    acc ^= cp.checkpoint_contents.digest().inner()[0];
    for tx in &cp.transactions {
        acc ^= tx.transaction.data().transaction_data().digest().inner()[0];
        acc ^= tx.effects.digest().inner()[0];
        if let Some(ev) = &tx.events {
            acc ^= ev.digest().into_inner()[0];
        }
        for o in tx.input_objects.iter().chain(tx.output_objects.iter()) {
            acc ^= o.digest().inner()[0];
        }
    }
    acc
}

fn cmd_bench(args: &[String]) -> Result<()> {
    if args.first().is_some_and(|a| a.parse::<usize>().is_ok()) {
        return cmd_bench_legacy(args);
    }
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
    let files: Vec<PathBuf> =
        std::fs::read_to_string(&list)?.lines().filter(|l| !l.is_empty()).map(PathBuf::from).collect();
    if files.is_empty() {
        bail!("empty input list");
    }
    let iters = iters.max(1);
    if name == "convert" {
        // node-convert: archive proto (sui.rpc.v2 Checkpoint, zstd) to the checkpoint blob, as
        // `convert` does it; decompression outside the timed region, like the Zig bench.
        let protos: Vec<Vec<u8>> =
            files.iter().map(|f| Ok(zstd::decode_all(&std::fs::read(f)?[..])?)).collect::<Result<_>>()?;
        let bytes: u64 = protos.iter().map(|b| b.len() as u64).sum();
        let p = passes(iters, || {
            for b in &protos {
                let proto = sui_rpc::proto::sui::rpc::v2::Checkpoint::decode(&b[..])?;
                let cp: Checkpoint = (&proto).try_into().map_err(|e| anyhow!("proto->Checkpoint: {e:?}"))?;
                let data: CheckpointData = cp.into();
                let mut out = vec![1u8];
                out.extend(bcs::to_bytes(&data)?);
                std::hint::black_box(out);
            }
            Ok(())
        })?;
        BenchOut { name, unit: "checkpoint", units: protos.len() as u64, bytes, passes: p }.print();
        return Ok(());
    }
    let blobs: Vec<Vec<u8>> = files.iter().map(std::fs::read).collect::<Result<_, _>>()?;
    let bytes: u64 = blobs.iter().map(|b| b.len() as u64).sum();
    let decoded: Vec<CheckpointData> =
        blobs.iter().zip(&files).map(|(b, f)| decode_blob(b, &f.display())).collect::<Result<_>>()?;
    let txs: u64 = decoded.iter().map(|c| c.transactions.len() as u64).sum();
    let objects: u64 = decoded
        .iter()
        .flat_map(|c| c.transactions.iter())
        .map(|t| (t.input_objects.len() + t.output_objects.len()) as u64)
        .sum();
    let out = |unit: &'static str, units: u64, p: Vec<u128>| {
        BenchOut { name: name.clone(), unit, units, bytes, passes: p }.print();
    };
    match name.as_str() {
        // owned decode, as sui-node does it
        "decode" => out("tx", txs, passes(iters, || {
            for b in &blobs {
                std::hint::black_box(bcs::from_bytes::<CheckpointData>(&b[1..])?);
            }
            Ok(())
        })?),
        // decode then re-encode
        "roundtrip" => out("tx", txs, passes(iters, || {
            for b in &blobs {
                let cp: CheckpointData = bcs::from_bytes(&b[1..])?;
                std::hint::black_box(bcs::to_bytes(&cp)?);
            }
            Ok(())
        })?),
        // every digest of already-decoded checkpoints: summary, contents, tx data, effects, events, objects
        "digests" => out("tx", txs, passes(iters, || {
            for cp in &decoded {
                std::hint::black_box(all_digests(cp));
            }
            Ok(())
        })?),
        // what checkpoint verification needs: decode plus every digest
        "decode-digests" => out("tx", txs, passes(iters, || {
            for b in &blobs {
                let cp: CheckpointData = bcs::from_bytes(&b[1..])?;
                std::hint::black_box(all_digests(&cp));
            }
            Ok(())
        })?),
        // object digests only (input + output), from decoded objects
        "object-digests" => out("object", objects, passes(iters, || {
            for cp in &decoded {
                for tx in &cp.transactions {
                    for o in tx.input_objects.iter().chain(tx.output_objects.iter()) {
                        std::hint::black_box(o.digest());
                    }
                }
            }
            Ok(())
        })?),
        // fastcrypto Blake2b256 over each whole blob (raw hashing throughput)
        "blob-blake2b" => out("byte", bytes, passes(iters, || {
            for b in &blobs {
                std::hint::black_box(Blake2b256::digest(b));
            }
            Ok(())
        })?),
        // the full truth pipeline (decode, walk, tree text, digests), no file output
        "truth" => out("tx", txs, passes(iters, || {
            for (b, f) in blobs.iter().zip(&files) {
                std::hint::black_box(truth_for_raw(b, &f.display())?);
            }
            Ok(())
        })?),
        n => bail!("unknown bench {n} (convert, decode, roundtrip, digests, decode-digests, object-digests, blob-blake2b, truth)"),
    }
    Ok(())
}

fn cmd_bench_legacy(args: &[String]) -> Result<()> {
    let iters: usize = args[0].parse()?;
    let files = expand(&args[1..])?;
    let blobs: Vec<Vec<u8>> = files.iter().map(std::fs::read).collect::<Result<_, _>>()?;
    let total: usize = blobs.iter().map(|b| b.len()).sum();
    let mut ntx = 0usize;
    for b in &blobs {
        let cp: CheckpointData = bcs::from_bytes(&b[1..])?;
        ntx += cp.transactions.len();
    }
    let t0 = Instant::now();
    for _ in 0..iters {
        for b in &blobs {
            let cp: CheckpointData = bcs::from_bytes(&b[1..])?;
            std::hint::black_box(&cp);
        }
    }
    let dt = t0.elapsed().as_secs_f64();
    let t1 = Instant::now();
    for _ in 0..iters {
        for b in &blobs {
            let cp: CheckpointData = bcs::from_bytes(&b[1..])?;
            std::hint::black_box(all_digests(&cp));
        }
    }
    let dt2 = t1.elapsed().as_secs_f64();
    let mb = (total * iters) as f64 / 1e6;
    println!(
        "{{\"impl\":\"rust-bcs\",\"files\":{},\"bytes\":{},\"txs\":{},\"iters\":{},\"decode_s\":{:.4},\"decode_mb_s\":{:.1},\"decode_ns_per_tx\":{:.0},\"decode_digest_s\":{:.4},\"decode_digest_ns_per_tx\":{:.0}}}",
        files.len(),
        total,
        ntx,
        iters,
        dt,
        mb / dt,
        dt * 1e9 / (ntx * iters) as f64,
        dt2,
        dt2 * 1e9 / (ntx * iters) as f64
    );
    Ok(())
}
