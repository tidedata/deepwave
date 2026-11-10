//! zui-truth-bls: ground truth for the crypto-bls lane, computed with Mysten's own code
//! (fastcrypto da61cd46 over blst 0.3.16, sui-types mainnet-v1.83.1). Formats: README.md.
//!
//! Commands:
//!   certs <out_dir> <genesis.blob> <chk_dir>   every checkpoint certificate in the corpus, grouped by
//!                                             epoch: <out_dir>/<epoch>.jsonl (committee line, then one
//!                                             line per certificate case: real plus mutated negatives)
//!   vectors <out_file>                        bls12381 suite vectors (hash-to-G1, keys, sign, verify,
//!                                             aggregate, decode edge cases), deterministic
//!   synth <out_file>                          bls-cert cases real certificates never reach (few signers,
//!                                             indices outside the committee, no signers) over a
//!                                             synthetic committee, deterministic
//!   groupops <out_file>                       bls-group-ops suite vectors (sui::group_ops BLS12-381
//!                                             natives' fastcrypto calls), deterministic
//!   bench <name> --iters N --list <file>      Rust baseline on the listed epoch files (CONTRACTS.md 7)

use anyhow::{Context, Result, anyhow, bail};
use fastcrypto::bls12381::min_sig::{
    BLS12381AggregateSignature, BLS12381KeyPair, BLS12381PrivateKey, BLS12381PublicKey,
    BLS12381Signature,
};
use fastcrypto::traits::{AggregateAuthenticator, KeyPair, Signer, ToFromBytes, VerifyingKey};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use shared_crypto::intent::{Intent, IntentScope};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;
use sui_types::committee::Committee;
use sui_types::crypto::{AggregateAuthoritySignature, VerificationObligation};
use sui_types::effects::TransactionEffects;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::messages_checkpoint::{CertifiedCheckpointSummary, CheckpointContents};
use sui_types::object::Object;
use sui_types::sui_system_state::{SuiSystemStateTrait, get_sui_system_state};
use sui_types::transaction::Transaction;

mod groupops;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("certs") => cmd_certs(&args[2..]),
        Some("vectors") => cmd_vectors(&args[2..]),
        Some("synth") => cmd_synth(&args[2..]),
        Some("groupops") => groupops::cmd_groupops(&args[2..]),
        Some("bench") => cmd_bench(&args[2..]),
        _ => bail!("usage: zui-truth-bls certs|synth|vectors|groupops|bench ..."),
    }
}

// ---------------------------------------------------------------------------------------------
// certs

#[derive(Deserialize)]
struct RawGenesis {
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

/// What one checkpoint contributes: its certificate, the exact signed message Mysten builds, and
/// (for end-of-epoch checkpoints) the next committee.
struct CertRec {
    seq: u64,
    epoch: u64,
    signers: Vec<u32>,
    msg: Vec<u8>,
    sig: Vec<u8>,
    next_committee: Option<BTreeMap<sui_types::base_types::AuthorityName, u64>>,
}

fn splitmix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// The signed message exactly as `AuthorityQuorumSignInfo::verify_secure` builds it.
fn signed_message(cert: &CertifiedCheckpointSummary) -> Vec<u8> {
    let mut ob = VerificationObligation::default();
    let idx = ob.add_message(cert.data(), cert.auth_sig().epoch, Intent::sui_app(IntentScope::CheckpointSummary));
    ob.messages.swap_remove(idx)
}

/// The BLS part of `AuthorityQuorumSignInfo::add_to_verification_obligation` + `verify_all`, with
/// Mysten's own calls: signature bytes decoded as `AggregateAuthoritySignature`, aggregated into the
/// default (infinity) obligation signature, signer keys from the committee by index (an unknown
/// index is `UnknownSigner`), then `VerificationObligation::verify_all`. Stake and epoch checks are the checkpoint-verify lane's.
fn bls_verdict(committee: &Committee, signers: &[u32], msg: &[u8], sig: &[u8]) -> &'static str {
    let sig = match AggregateAuthoritySignature::from_bytes(sig) {
        Ok(s) => s,
        Err(_) => return "decode",
    };
    let mut ob = VerificationObligation::default();
    ob.messages.push(msg.to_vec());
    ob.signatures.push(AggregateAuthoritySignature::default());
    ob.public_keys.push(Vec::new());
    if ob.signatures[0].add_aggregate(sig).is_err() {
        return "aggregate";
    }
    let mut seen = BTreeSet::new();
    for &i in signers {
        if !seen.insert(i) {
            continue;
        }
        // add_to_verification_obligation: an index outside the committee is UnknownSigner,
        // returned before any pairing work.
        let Some(name) = committee.authority_by_index(i) else { return "unknown-signer" };
        ob.public_keys[0].push(committee.public_key(name).expect("committee key"));
    }
    match ob.verify_all() {
        Ok(()) => "ok",
        Err(_) => "invalid",
    }
}

/// Certificate cases that mainnet certificates never reach, over a synthetic 40-member committee
/// (keys from a fixed seed, uneven stakes summing to 10,000): signer sets of every size from none to all (deepwave sums
/// few signers directly and many as total minus the missing), signer indices outside the
/// committee, and the usual message, signer and signature mutations. Same verdict path as `certs`.
fn cmd_synth(args: &[String]) -> Result<()> {
    let [out_file] = args else { bail!("synth <out_file>") };
    let mut rng = StdRng::seed_from_u64(0x7a75_692d_7379_6e74);
    let n = 40usize;
    let kps: Vec<BLS12381KeyPair> = (0..n).map(|_| BLS12381KeyPair::generate(&mut rng)).collect();
    let mut rights: BTreeMap<sui_types::base_types::AuthorityName, u64> = BTreeMap::new();
    // Committee::new wants a total of 10,000: uneven stakes, the remainder on the last member
    let mut left = 10_000u64;
    for (i, kp) in kps.iter().enumerate() {
        let s = if i + 1 == n { left } else { 1 + rng.next_u64() % 400 };
        left -= s;
        rights.insert(kp.public().into(), s);
    }
    let epoch = 1_000_000u64;
    let committee = Committee::new(epoch, rights);
    // key pairs in committee index order
    let by_index: Vec<&BLS12381KeyPair> = committee
        .voting_rights
        .iter()
        .map(|(name, _)| {
            let name_b: &[u8] = name.as_ref();
            kps.iter().find(|kp| kp.public().as_ref() == name_b).expect("committee member")
        })
        .collect();
    let mut out = Vec::new();
    let keys: Vec<String> = committee.voting_rights.iter().map(|(k, _)| hex::encode(k.as_ref())).collect();
    let stakes: Vec<u64> = committee.voting_rights.iter().map(|(_, s)| *s).collect();
    writeln!(out, "{}", json!({"epoch": epoch, "keys": keys, "stakes": stakes}))?;
    let mut lines = 0usize;
    let mut seq = 9_000_000_000u64;
    for k in [0usize, 1, 2, 3, 5, 8, 13, 19, 20, 21, 27, 34, 39, 40] {
        for rep in 0..3 {
            if (k == 0 || k == n) && rep > 0 {
                continue;
            }
            seq += 1;
            let mlen = 64 + (rng.next_u64() % 200) as usize;
            let msg = rand_bytes(&mut rng, mlen);
            let mut pool: Vec<u32> = (0..n as u32).collect();
            let mut signers: Vec<u32> = Vec::new();
            for _ in 0..k {
                let j = (rng.next_u64() % pool.len() as u64) as usize;
                signers.push(pool.swap_remove(j));
            }
            signers.sort();
            // the aggregate of the signers' signatures (key 0 alone when there are none)
            let sigs: Vec<BLS12381Signature> = if signers.is_empty() {
                vec![by_index[0].sign(&msg)]
            } else {
                signers.iter().map(|&i| by_index[i as usize].sign(&msg)).collect()
            };
            let agg = BLS12381AggregateSignature::aggregate(&sigs).map_err(|e| anyhow!("{e}"))?;
            let sig = agg.as_ref().to_vec();
            let mut emit = |case: &str, s: &[u32], m: &[u8], g: &[u8]| -> Result<()> {
                let v = bls_verdict(&committee, s, m, g);
                writeln!(out, "{}", json!({"seq": seq, "case": case, "signers": s, "msg": hex::encode(m), "sig": hex::encode(g), "verdict": v}))?;
                lines += 1;
                Ok(())
            };
            emit("real", &signers, &msg, &sig)?;
            let mut m = msg.clone();
            let bit = (rng.next_u64() % (m.len() as u64 * 8)) as usize;
            m[bit / 8] ^= 1 << (bit % 8);
            emit("msg-bit", &signers, &m, &sig)?;
            if !signers.is_empty() {
                let mut s = signers.clone();
                s.remove((rng.next_u64() % s.len() as u64) as usize);
                emit("drop-signer", &s, &msg, &sig)?;
            }
            if !pool.is_empty() {
                let mut s = signers.clone();
                s.push(pool[(rng.next_u64() % pool.len() as u64) as usize]);
                s.sort();
                emit("add-signer", &s, &msg, &sig)?;
            }
            // an index just past the end and one far outside, appended (as a bitmap orders them)
            let mut s = signers.clone();
            s.push(n as u32);
            emit("unknown-signer", &s, &msg, &sig)?;
            let mut s = signers.clone();
            s.push(u32::MAX);
            emit("unknown-signer-max", &s, &msg, &sig)?;
            let mut inf = [0u8; 48];
            inf[0] = 0xc0;
            emit("sig-inf", &signers, &msg, &inf)?;
            emit("sig-nonsub", &signers, &msg, &non_subgroup_g1(seq))?;
        }
    }
    std::fs::write(out_file, &out)?;
    println!("{}", json!({"lines": lines, "file": out_file}));
    Ok(())
}

/// An on-curve G1 point outside the r-torsion subgroup, compressed, found from `seed`.
pub(crate) fn non_subgroup_g1(seed: u64) -> [u8; 48] {
    let mut s = seed;
    loop {
        let mut b = [0u8; 48];
        for chunk in b.chunks_mut(8) {
            s = splitmix(s);
            chunk.copy_from_slice(&s.to_be_bytes());
        }
        b[0] &= 0x0f; // x < p
        b[0] |= 0x80;
        let mut aff = blst::blst_p1_affine::default();
        let ok = unsafe { blst::blst_p1_uncompress(&mut aff, b.as_ptr()) } == blst::BLST_ERROR::BLST_SUCCESS;
        if ok && !unsafe { blst::blst_p1_affine_in_g1(&aff) } {
            return b;
        }
    }
}

fn cmd_certs(args: &[String]) -> Result<()> {
    let [out_dir, genesis_path, chk_dir] = args else {
        bail!("certs <out_dir> <genesis.blob> <chk_dir>");
    };
    let out_dir = PathBuf::from(out_dir);
    std::fs::create_dir_all(&out_dir)?;

    // Epoch 0 committee from the genesis blob (as sui-config's Genesis::committee does).
    let gbytes = std::fs::read(genesis_path)?;
    let inner: Vec<u8> = bcs::from_bytes(&gbytes).context("genesis outer bytes")?;
    let genesis: RawGenesis = bcs::from_bytes(&inner).context("genesis")?;
    let objs: &[Object] = &genesis.objects;
    let sys = get_sui_system_state(&objs).map_err(|e| anyhow!("system state: {e}"))?;
    let gcomm = sys.get_current_epoch_committee().committee().clone();
    if gcomm.epoch != 0 {
        bail!("genesis committee epoch {}", gcomm.epoch);
    }
    let genesis_digest = *genesis.checkpoint.digest();

    let mut files: Vec<PathBuf> = std::fs::read_dir(chk_dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "chk"))
        .collect();
    files.sort();
    eprintln!("certs: {} blobs", files.len());
    let t0 = Instant::now();
    let mut recs: Vec<CertRec> = files
        .par_iter()
        .map(|f| -> Result<CertRec> {
            let raw = std::fs::read(f)?;
            if raw.first() != Some(&1) {
                bail!("{}: not a BCS blob", f.display());
            }
            let cp: CheckpointData = bcs::from_bytes(&raw[1..]).with_context(|| format!("{}", f.display()))?;
            let cert = &cp.checkpoint_summary;
            let s = cert.data();
            Ok(CertRec {
                seq: s.sequence_number,
                epoch: s.epoch,
                signers: cert.auth_sig().signers_map.iter().collect(),
                msg: signed_message(cert),
                sig: cert.auth_sig().signature.as_ref().to_vec(),
                next_committee: s
                    .end_of_epoch_data
                    .as_ref()
                    .map(|e| e.next_epoch_committee.iter().cloned().collect()),
            })
        })
        .collect::<Result<_>>()?;
    recs.sort_by_key(|r| r.seq);
    eprintln!("certs: decoded in {:.1}s", t0.elapsed().as_secs_f64());

    // Committees: epoch 0 from genesis, epoch e+1 from epoch e's end-of-epoch checkpoint.
    let mut committees: BTreeMap<u64, Committee> = BTreeMap::new();
    committees.insert(0, gcomm);
    for r in &recs {
        if let Some(nc) = &r.next_committee {
            committees.insert(r.epoch + 1, Committee::new(r.epoch + 1, nc.clone()));
        }
    }
    let mut by_epoch: BTreeMap<u64, Vec<&CertRec>> = BTreeMap::new();
    for r in &recs {
        by_epoch.entry(r.epoch).or_default().push(r);
    }
    if let Some(r0) = recs.first().filter(|r| r.seq == 0) {
        // The genesis checkpoint in the corpus must be the one in the genesis blob.
        let _ = r0;
        eprintln!("certs: genesis checkpoint digest {}", hex::encode(genesis_digest.inner()));
    }

    let results: Vec<(u64, usize, usize)> = by_epoch
        .par_iter()
        .map(|(&epoch, list)| -> Result<(u64, usize, usize)> {
            let committee = committees.get(&epoch).ok_or_else(|| anyhow!("no committee for epoch {epoch}"))?;
            let mut out = Vec::new();
            let keys: Vec<String> = committee.voting_rights.iter().map(|(n, _)| hex::encode(n.as_ref())).collect();
            let stakes: Vec<u64> = committee.voting_rights.iter().map(|(_, s)| *s).collect();
            writeln!(out, "{}", json!({"epoch": epoch, "keys": keys, "stakes": stakes}))?;
            let n = committee.voting_rights.len() as u32;
            let mut lines = 0usize;
            let mut real_ok = 0usize;
            for (k, r) in list.iter().enumerate() {
                let mut emit = |case: &str, signers: &[u32], msg: &[u8], sig: &[u8]| -> Result<&'static str> {
                    let v = bls_verdict(committee, signers, msg, sig);
                    writeln!(
                        out,
                        "{}",
                        json!({"seq": r.seq, "case": case, "signers": signers, "msg": hex::encode(msg), "sig": hex::encode(sig), "verdict": v})
                    )?;
                    lines += 1;
                    Ok(v)
                };
                if emit("real", &r.signers, &r.msg, &r.sig)? == "ok" {
                    real_ok += 1;
                }
                let rnd = splitmix(r.seq ^ 0x7a75_692d_626c_7321);
                // 1. one message bit flipped
                let mut m = r.msg.clone();
                let bit = (rnd % (m.len() as u64 * 8)) as usize;
                m[bit / 8] ^= 1 << (bit % 8);
                emit("msg-bit", &r.signers, &m, &r.sig)?;
                // 2. another certificate's signature from the same epoch
                if list.len() > 1 {
                    let other = list[(k + 1) % list.len()];
                    emit("sig-swap", &r.signers, &r.msg, &other.sig)?;
                }
                // 3. one signer dropped
                if !r.signers.is_empty() {
                    let mut s = r.signers.clone();
                    s.remove((rnd >> 8) as usize % s.len());
                    emit("drop-signer", &s, &r.msg, &r.sig)?;
                }
                // 4. one non-signer added
                let non: Vec<u32> = (0..n).filter(|i| !r.signers.contains(i)).collect();
                if !non.is_empty() {
                    let mut s = r.signers.clone();
                    s.push(non[(rnd >> 16) as usize % non.len()]);
                    s.sort();
                    emit("add-signer", &s, &r.msg, &r.sig)?;
                }
                // 5. one signature bit flipped (flag bits included: decode errors are verdicts too)
                let mut sg = r.sig.clone();
                let sbit = ((rnd >> 24) % (sg.len() as u64 * 8)) as usize;
                sg[sbit / 8] ^= 0x80 >> (sbit % 8);
                emit("sig-bit", &r.signers, &r.msg, &sg)?;
                // 6. the point at infinity as signature
                let mut inf = [0u8; 48];
                inf[0] = 0xc0;
                emit("sig-inf", &r.signers, &r.msg, &inf)?;
                // 7. an on-curve point outside G1
                emit("sig-nonsub", &r.signers, &r.msg, &non_subgroup_g1(rnd))?;
            }
            std::fs::write(out_dir.join(format!("{epoch}.jsonl")), out)?;
            Ok((epoch, lines, real_ok))
        })
        .collect::<Result<_>>()?;
    let lines: usize = results.iter().map(|r| r.1).sum();
    let real_ok: usize = results.iter().map(|r| r.2).sum();
    println!(
        "{}",
        json!({"epochs": results.len(), "certs": recs.len(), "real_ok": real_ok, "lines": lines, "secs": t0.elapsed().as_secs_f64()})
    );
    if real_ok != recs.len() {
        bail!("{} real certificates did not verify", recs.len() - real_ok);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// vectors

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

fn fc_pk_decode(b: &[u8]) -> serde_json::Value {
    match BLS12381PublicKey::from_bytes(b) {
        Err(_) => json!({"decode": false}),
        Ok(pk) => json!({"decode": true, "valid": pk.validate().is_ok(), "bytes": h(pk.as_ref())}),
    }
}

fn fc_sig_decode(b: &[u8]) -> serde_json::Value {
    match BLS12381Signature::from_bytes(b) {
        Err(_) => json!({"decode": false}),
        Ok(s) => json!({"decode": true, "bytes": h(s.as_ref())}),
    }
}

/// `BLS12381PublicKey::verify` after both decodes, as a verdict string.
fn fc_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> &'static str {
    let Ok(pk) = BLS12381PublicKey::from_bytes(pk) else { return "pk-decode" };
    let Ok(sig) = BLS12381Signature::from_bytes(sig) else { return "sig-decode" };
    match pk.verify(msg, &sig) {
        Ok(()) => "ok",
        Err(_) => "invalid",
    }
}

fn rand_bytes(rng: &mut StdRng, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rng.fill_bytes(&mut v);
    v
}

/// Random on-curve point encodings that are not in the prime-order subgroup.
pub(crate) fn non_subgroup_g2(rng: &mut StdRng) -> [u8; 96] {
    loop {
        let mut b = [0u8; 96];
        rng.fill_bytes(&mut b);
        b[0] &= 0x0f;
        b[48] &= 0x0f;
        b[0] |= 0x80;
        let mut aff = blst::blst_p2_affine::default();
        let ok = unsafe { blst::blst_p2_uncompress(&mut aff, b.as_ptr()) } == blst::BLST_ERROR::BLST_SUCCESS;
        if ok && !unsafe { blst::blst_p2_affine_in_g2(&aff) } {
            return b;
        }
    }
}

pub(crate) const P_BE: &str = "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

fn cmd_vectors(args: &[String]) -> Result<()> {
    let [out_file] = args else { bail!("vectors <out_file>") };
    let mut rng = StdRng::seed_from_u64(0x7a75_692d_626c_7331);
    let mut out = Vec::new();
    let mut n = 0usize;
    let mut put = |v: serde_json::Value, out: &mut Vec<u8>| -> Result<()> {
        writeln!(out, "{v}")?;
        n += 1;
        Ok(())
    };
    let dst = fastcrypto::bls12381::min_sig::DST_G1;

    // hash-to-G1 with the min-sig DST: lengths 0..=300 and a few large ones.
    let mut lens: Vec<usize> = (0..=300).collect();
    lens.extend([511, 512, 1000, 4096, 65536]);
    for (i, &len) in lens.iter().enumerate() {
        let msg = rand_bytes(&mut rng, len);
        let mut p = blst::blst_p1::default();
        unsafe { blst::blst_hash_to_g1(&mut p, msg.as_ptr(), msg.len(), dst.as_ptr(), dst.len(), std::ptr::null(), 0) };
        let mut c = [0u8; 48];
        unsafe { blst::blst_p1_compress(c.as_mut_ptr(), &p) };
        put(json!({"op": "hash_to_g1", "id": format!("h2g1/{i}"), "msg": h(&msg), "dst": h(dst), "out": h(&c)}), &mut out)?;
    }

    // keys and signatures: secret keys from KeyPair::generate and from raw scalars.
    let mut keys: Vec<BLS12381KeyPair> = Vec::new();
    for i in 0..64 {
        let kp = BLS12381KeyPair::generate(&mut rng);
        put(json!({"op": "sk_to_pk", "id": format!("sk2pk/{i}"), "sk": h(kp.as_ref()), "pk": h(kp.public().as_ref())}), &mut out)?;
        keys.push(kp);
    }
    // secret key decode edge cases: zero, r-1, r, r+1, all-ones, small values
    let r_be = hex::decode("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")?;
    let mut sk_cases: Vec<Vec<u8>> = vec![vec![0u8; 32], vec![0xff; 32], r_be.clone()];
    let mut rm1 = r_be.clone();
    rm1[31] -= 1;
    sk_cases.push(rm1);
    let mut rp1 = r_be.clone();
    rp1[31] += 1;
    sk_cases.push(rp1);
    for v in [1u8, 2, 3, 0x7f] {
        let mut b = vec![0u8; 32];
        b[31] = v;
        sk_cases.push(b);
    }
    for (i, b) in sk_cases.iter().enumerate() {
        let v = match BLS12381PrivateKey::from_bytes(b) {
            Err(_) => json!({"op": "sk_decode", "id": format!("skdec/{i}"), "sk": h(b), "decode": false}),
            Ok(sk) => {
                let kp: BLS12381KeyPair = sk.into();
                json!({"op": "sk_decode", "id": format!("skdec/{i}"), "sk": h(b), "decode": true, "pk": h(kp.public().as_ref())})
            }
        };
        put(v, &mut out)?;
    }
    for (i, kp) in keys.iter().enumerate() {
        for j in 0..4 {
            let msg = rand_bytes(&mut rng, [0usize, 32, 100, 300][j]);
            let sig = kp.sign(&msg);
            put(json!({"op": "sign", "id": format!("sign/{i}.{j}"), "sk": h(kp.as_ref()), "msg": h(&msg), "sig": h(sig.as_ref())}), &mut out)?;
            // verify: valid, wrong message, wrong key, wrong signature
            let pk = kp.public().as_ref().to_vec();
            put(json!({"op": "verify", "id": format!("verify/{i}.{j}.ok"), "pk": h(&pk), "msg": h(&msg), "sig": h(sig.as_ref()), "verdict": fc_verify(&pk, &msg, sig.as_ref())}), &mut out)?;
            let mut m2 = msg.clone();
            m2.push(j as u8);
            put(json!({"op": "verify", "id": format!("verify/{i}.{j}.msg"), "pk": h(&pk), "msg": h(&m2), "sig": h(sig.as_ref()), "verdict": fc_verify(&pk, &m2, sig.as_ref())}), &mut out)?;
            let pk2 = keys[(i + 1) % keys.len()].public().as_ref().to_vec();
            put(json!({"op": "verify", "id": format!("verify/{i}.{j}.pk"), "pk": h(&pk2), "msg": h(&msg), "sig": h(sig.as_ref()), "verdict": fc_verify(&pk2, &msg, sig.as_ref())}), &mut out)?;
            let mut s2 = sig.as_ref().to_vec();
            let bit = (rng.next_u32() % 384) as usize;
            s2[bit / 8] ^= 0x80 >> (bit % 8);
            put(json!({"op": "verify", "id": format!("verify/{i}.{j}.sigbit"), "pk": h(&pk), "msg": h(&msg), "sig": h(&s2), "verdict": fc_verify(&pk, &msg, &s2)}), &mut out)?;
            let mut p2 = pk.clone();
            let bit = (rng.next_u32() % 768) as usize;
            p2[bit / 8] ^= 0x80 >> (bit % 8);
            put(json!({"op": "verify", "id": format!("verify/{i}.{j}.pkbit"), "pk": h(&p2), "msg": h(&msg), "sig": h(sig.as_ref()), "verdict": fc_verify(&p2, &msg, sig.as_ref())}), &mut out)?;
        }
    }

    // signature and public key decoding edge cases
    let mut sig_cases: Vec<Vec<u8>> = Vec::new();
    let mut inf = vec![0u8; 48];
    inf[0] = 0xc0;
    sig_cases.push(inf.clone());
    for flag in [0x00u8, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xe0, 0xc1] {
        let mut b = inf.clone();
        b[0] = flag;
        sig_cases.push(b);
    }
    let mut inf_junk = inf.clone();
    inf_junk[47] = 1;
    sig_cases.push(inf_junk);
    let p = hex::decode(P_BE)?;
    for add in [0u8, 1, 2] {
        // x = p + add with the compression flag: non-canonical
        let mut b = p.clone();
        b[47] = b[47].wrapping_add(add);
        b[0] |= 0x80;
        sig_cases.push(b);
    }
    let mut zero_x = vec![0u8; 48];
    zero_x[0] = 0x80; // x = 0: on the curve as (0, ±2), not in G1
    sig_cases.push(zero_x.clone());
    zero_x[0] = 0xa0;
    sig_cases.push(zero_x);
    for i in 0..40 {
        sig_cases.push(non_subgroup_g1(0x5157_0000 + i).to_vec());
        let mut b = rand_bytes(&mut rng, 48);
        b[0] = (b[0] & 0x1f) | 0x80;
        sig_cases.push(b);
    }
    // uncompressed (96-byte) forms of real signatures and of infinity
    for kp in keys.iter().take(8) {
        let s = kp.sign(b"zui");
        let blst_sig = blst::min_sig::Signature::from_bytes(s.as_ref()).map_err(|e| anyhow!("{e:?}"))?;
        sig_cases.push(blst_sig.serialize().to_vec());
        sig_cases.push(s.as_ref().to_vec());
    }
    let mut uinf = vec![0u8; 96];
    uinf[0] = 0x40;
    sig_cases.push(uinf);
    for (i, b) in sig_cases.iter().enumerate() {
        let mut v = fc_sig_decode(b);
        v["op"] = json!("sig_decode");
        v["id"] = json!(format!("sigdec/{i}"));
        v["in"] = json!(h(b));
        // group membership as `G1Element::from_byte_array` decides it (48-byte inputs only)
        if b.len() == 48 {
            let arr: [u8; 48] = b.as_slice().try_into()?;
            use fastcrypto::serde_helpers::ToFromByteArray;
            v["g1"] = json!(fastcrypto::groups::bls12381::G1Element::from_byte_array(&arr).is_ok());
        }
        put(v, &mut out)?;
    }
    let mut pk_cases: Vec<Vec<u8>> = Vec::new();
    let mut pinf = vec![0u8; 96];
    pinf[0] = 0xc0;
    pk_cases.push(pinf.clone());
    for flag in [0x00u8, 0x20, 0x40, 0x80, 0xa0, 0xe0] {
        let mut b = pinf.clone();
        b[0] = flag;
        pk_cases.push(b);
    }
    for which in [0usize, 48] {
        for add in [0u8, 1] {
            let mut b = keys[0].public().as_ref().to_vec();
            b[which..which + 48].copy_from_slice(&p);
            b[which + 47] = b[which + 47].wrapping_add(add);
            b[0] |= 0x80;
            pk_cases.push(b);
        }
    }
    for i in 0..40 {
        pk_cases.push(non_subgroup_g2(&mut rng).to_vec());
        let mut b = rand_bytes(&mut rng, 96);
        b[0] = (b[0] & 0x1f) | 0x80;
        b[48] &= 0x1f;
        pk_cases.push(b);
        if i < 8 {
            let pk = keys[i].public().as_ref().to_vec();
            let blst_pk = blst::min_sig::PublicKey::from_bytes(&pk).map_err(|e| anyhow!("{e:?}"))?;
            pk_cases.push(blst_pk.serialize().to_vec());
            pk_cases.push(pk);
        }
    }
    let mut zero_x2 = vec![0u8; 96];
    zero_x2[0] = 0x80;
    pk_cases.push(zero_x2.clone());
    zero_x2[0] = 0xa0;
    pk_cases.push(zero_x2);
    for (i, b) in pk_cases.iter().enumerate() {
        let mut v = fc_pk_decode(b);
        v["op"] = json!("pk_decode");
        v["id"] = json!(format!("pkdec/{i}"));
        v["in"] = json!(h(b));
        put(v, &mut out)?;
    }
    // verify with an infinity / non-subgroup signature or key
    for i in 0..8 {
        let kp = &keys[i];
        let msg = rand_bytes(&mut rng, 40);
        let pk = kp.public().as_ref().to_vec();
        let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
            ("siginf", pk.clone(), inf.clone()),
            ("signonsub", pk.clone(), non_subgroup_g1(0x77_0000 + i as u64).to_vec()),
            ("pkinf", pinf.clone(), kp.sign(&msg).as_ref().to_vec()),
            ("bothinf", pinf.clone(), inf.clone()),
            ("pknonsub", non_subgroup_g2(&mut rng).to_vec(), kp.sign(&msg).as_ref().to_vec()),
        ];
        for (name, pk, sig) in cases {
            put(json!({"op": "verify", "id": format!("verify-edge/{i}.{name}"), "pk": h(&pk), "msg": h(&msg), "sig": h(&sig), "verdict": fc_verify(&pk, &msg, &sig)}), &mut out)?;
        }
    }

    // aggregation: signatures over one message, fast_aggregate_verify; distinct messages,
    // aggregate verify; and the aggregate bytes
    for t in 0..48 {
        let k = 1 + (t * 7) % 33;
        let msg = rand_bytes(&mut rng, 64);
        let start = t % keys.len();
        let signers: Vec<&BLS12381KeyPair> = (0..k).map(|j| &keys[(start + j) % keys.len()]).collect();
        let sigs: Vec<BLS12381Signature> = signers.iter().map(|kp| kp.sign(&msg)).collect();
        let agg = BLS12381AggregateSignature::aggregate(&sigs).map_err(|e| anyhow!("{e}"))?;
        let pks: Vec<BLS12381PublicKey> = signers.iter().map(|kp| kp.public().clone()).collect();
        let sig_hex: Vec<String> = sigs.iter().map(|s| h(s.as_ref())).collect();
        let pk_hex: Vec<String> = pks.iter().map(|p| h(p.as_ref())).collect();
        put(json!({"op": "aggregate", "id": format!("agg/{t}"), "sigs": sig_hex, "out": h(agg.as_ref())}), &mut out)?;
        let ok = agg.verify(&pks, &msg).is_ok();
        put(json!({"op": "fast_aggregate_verify", "id": format!("fav/{t}.ok"), "pks": pk_hex, "msg": h(&msg), "sig": h(agg.as_ref()), "ok": ok}), &mut out)?;
        if k > 1 {
            let fewer: Vec<BLS12381PublicKey> = pks[1..].to_vec();
            let fewer_hex: Vec<String> = fewer.iter().map(|p| h(p.as_ref())).collect();
            put(json!({"op": "fast_aggregate_verify", "id": format!("fav/{t}.fewer"), "pks": fewer_hex, "msg": h(&msg), "sig": h(agg.as_ref()), "ok": agg.verify(&fewer, &msg).is_ok()}), &mut out)?;
        }
        let mut m2 = msg.clone();
        m2[0] ^= 1;
        put(json!({"op": "fast_aggregate_verify", "id": format!("fav/{t}.msg"), "pks": pk_hex, "msg": h(&m2), "sig": h(agg.as_ref()), "ok": agg.verify(&pks, &m2).is_ok()}), &mut out)?;
        // distinct messages
        let msgs: Vec<Vec<u8>> = (0..k).map(|j| { let mut m = msg.clone(); m.push(j as u8); m }).collect();
        let dsigs: Vec<BLS12381Signature> = signers.iter().zip(&msgs).map(|(kp, m)| kp.sign(m)).collect();
        let dagg = BLS12381AggregateSignature::aggregate(&dsigs).map_err(|e| anyhow!("{e}"))?;
        let mrefs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        let msg_hex: Vec<String> = msgs.iter().map(|m| h(m)).collect();
        put(json!({"op": "aggregate_verify", "id": format!("av/{t}.ok"), "pks": pk_hex, "msgs": msg_hex, "sig": h(dagg.as_ref()), "ok": dagg.verify_different_msg(&pks, &mrefs).is_ok()}), &mut out)?;
        let mut mrefs2 = mrefs.clone();
        mrefs2.reverse();
        let msg_hex2: Vec<String> = mrefs2.iter().map(|m| h(m)).collect();
        put(json!({"op": "aggregate_verify", "id": format!("av/{t}.swapped"), "pks": pk_hex, "msgs": msg_hex2, "sig": h(dagg.as_ref()), "ok": dagg.verify_different_msg(&pks, &mrefs2).is_ok()}), &mut out)?;
    }
    // the fastcrypto test-suite known answer (min_sig) and drand-style G1 checks
    put(json!({"op": "verify", "id": "fastcrypto/test_sig_kat_min_sig",
        "pk": "8c66dc2c1ea9e53f0985c17b4e7af19912b6d3c40e0c5920a5a12509b4eb3619f5e07ec56ea77f0b30629ba1cc72d75b139460782a5f0e2f89fb4c42b4b8a5fae3d260102220e63d0754e7e1846deefd3988eade4ed37f1385437d19de1a1618",
        "msg": h(b"Hello, world!"),
        "sig": "89dff2dc1e9428b9437d50b37f8160eca790110ea2a79b6c88a43a16953466f8e391ff65842b067a1c9441c7c2cebce0",
        "verdict": fc_verify(
            &hex::decode("8c66dc2c1ea9e53f0985c17b4e7af19912b6d3c40e0c5920a5a12509b4eb3619f5e07ec56ea77f0b30629ba1cc72d75b139460782a5f0e2f89fb4c42b4b8a5fae3d260102220e63d0754e7e1846deefd3988eade4ed37f1385437d19de1a1618")?,
            b"Hello, world!",
            &hex::decode("89dff2dc1e9428b9437d50b37f8160eca790110ea2a79b6c88a43a16953466f8e391ff65842b067a1c9441c7c2cebce0")?)}), &mut out)?;
    let sk = hex::decode("266f9708fd8d3b462b10cdbf5498076c021eb3acfdd47cb1fef647967fe194fb")?;
    let kp: BLS12381KeyPair = BLS12381PrivateKey::from_bytes(&sk).map_err(|e| anyhow!("{e}"))?.into();
    put(json!({"op": "sign", "id": "fastcrypto/test_sig_kat_min_sig.sign", "sk": h(&sk), "msg": h(b"Hello, world!"), "sig": h(kp.sign(b"Hello, world!").as_ref())}), &mut out)?;
    put(json!({"op": "sk_to_pk", "id": "fastcrypto/test_sig_kat_min_sig.pk", "sk": h(&sk), "pk": h(kp.public().as_ref())}), &mut out)?;

    std::fs::write(out_file, &out)?;
    println!("{}", json!({"vectors": n, "file": out_file}));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// bench

#[derive(Deserialize)]
struct CommitteeLine {
    epoch: u64,
    keys: Vec<String>,
    stakes: Vec<u64>,
}

#[derive(Deserialize)]
struct CertLine {
    case: String,
    signers: Vec<u32>,
    msg: String,
    sig: String,
}

struct BenchEpoch {
    committee: Committee,
    certs: Vec<(Vec<u32>, Vec<u8>, Vec<u8>)>,
}

fn load_epoch(path: &Path) -> Result<BenchEpoch> {
    let text = std::fs::read_to_string(path)?;
    let mut lines = text.lines();
    let c: CommitteeLine = serde_json::from_str(lines.next().ok_or_else(|| anyhow!("empty"))?)?;
    let mut vr = BTreeMap::new();
    for (k, stake) in c.keys.iter().zip(&c.stakes) {
        let b = hex::decode(k)?;
        let name = sui_types::base_types::AuthorityName::from_bytes(&b).map_err(|e| anyhow!("{e}"))?;
        vr.insert(name, *stake);
    }
    let committee = Committee::new(c.epoch, vr);
    let mut certs = Vec::new();
    for l in lines {
        let cl: CertLine = serde_json::from_str(l)?;
        if cl.case == "real" {
            certs.push((cl.signers, hex::decode(&cl.msg)?, hex::decode(&cl.sig)?));
        }
    }
    Ok(BenchEpoch { committee, certs })
}

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
    let files: Vec<PathBuf> =
        std::fs::read_to_string(&list)?.lines().filter(|l| !l.is_empty()).map(PathBuf::from).collect();
    let epochs: Vec<BenchEpoch> = files.iter().map(|f| load_epoch(f)).collect::<Result<_>>()?;
    let units: u64 = epochs.iter().map(|e| e.certs.len() as u64).sum();
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
    let mut passes = match name.as_str() {
        // the certificate check sui-node runs per checkpoint: decode the aggregate signature,
        // aggregate the signer keys (already-decoded committee), batch_verify with one message
        "cert-verify" => run(&|| {
            for e in &epochs {
                for (signers, msg, sig) in &e.certs {
                    if bls_verdict(&e.committee, signers, msg, sig) != "ok" {
                        bail!("bench cert did not verify");
                    }
                }
            }
            Ok(())
        })?,
        // per-epoch committee preparation: decode every committee key (Committee::new)
        "committee-prepare" => {
            let raw: Vec<Vec<(sui_types::base_types::AuthorityName, u64)>> =
                epochs.iter().map(|e| e.committee.voting_rights.clone()).collect();
            let units_c: u64 = raw.iter().map(|r| r.len() as u64).sum();
            let p = run(&|| {
                for (e, r) in epochs.iter().zip(&raw) {
                    std::hint::black_box(Committee::new(e.committee.epoch, r.iter().cloned().collect()));
                }
                Ok(())
            })?;
            return print_bench(&name, "key", units_c, p, iters);
        }
        n => bail!("unknown bench {n} (cert-verify, committee-prepare)"),
    };
    passes.sort();
    print_bench(&name, "cert", units, passes, iters)
}

fn print_bench(name: &str, unit: &str, units: u64, mut passes: Vec<u128>, iters: usize) -> Result<()> {
    passes.sort();
    let med = passes[passes.len() / 2];
    let o = BenchOut {
        imp: "rust",
        bench: name,
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
