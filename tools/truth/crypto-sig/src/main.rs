//! zui-truth-sig: ground truth for the crypto-sig lane, computed only by Mysten's code
//! (fastcrypto at da61cd4, ed25519-consensus 2.1, sui-types at mainnet-v1.83.1).
//! Formats: README.md next to this file.
//!
//! Commands:
//!   vectors <wycheproof_dir> <out.jsonl>       primitive vectors: Wycheproof inputs, ZIP-215 small-order
//!                                              combinations, seeded random and mutated cases; every
//!                                              verdict and output comes from fastcrypto
//!   corpus <corpus_dir> <out_dir> [seq...]     per checkpoint: every user signature (and seeded
//!                                              mutations) through GenericSignature::verify_authenticator,
//!                                              plus every transaction through
//!                                              verify_sender_signed_data_message_signatures (with the
//!                                              pinned address aliases and the checkpoint's JWKs)
//!   uservec <out.jsonl>                        synthesized user signatures (MultiSig, MultiSigLegacy,
//!                                              Passkey, single keys in every encoding) and seeded
//!                                              mutations, through the same path as `corpus`
//!   bench <name> --iters N --list <file>       Rust baselines (harness protocol, CONTRACTS.md 7)
//!   zkvec <corpus_dir> <aux_src> <out_dir>     every mainnet zkLogin signature re-wrapped: as a
//!                                              MultiSig member (and beside an Ed25519 member) and at
//!                                              top level, under flag, epoch, provider and JWK variants
//!   scan <corpus_dir>                          survey: alias versions pinned by CheckpointContentsV2,
//!                                              transactions with zkLogin signatures
//!
//! Nothing here reimplements a check: inputs are generated, verdicts are whatever Mysten's code says.

use anyhow::{Context, Result, anyhow, bail};
use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature};
use fastcrypto::error::FastCryptoError;
use fastcrypto::hash::{Keccak256, Sha256};
use fastcrypto::secp256k1::recoverable::Secp256k1RecoverableSignature;
use fastcrypto::secp256k1::{Secp256k1KeyPair, Secp256k1PublicKey, Secp256k1Signature};
use fastcrypto::secp256r1::recoverable::Secp256r1RecoverableSignature;
use fastcrypto::secp256r1::{Secp256r1KeyPair, Secp256r1PublicKey, Secp256r1Signature};
use fastcrypto::traits::{
    KeyPair as _, RecoverableSignature, RecoverableSigner, Signer, ToFromBytes, VerifyingKey,
};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use serde::Serialize;
use serde_json::{Value, json};
use shared_crypto::intent::{Intent, IntentMessage};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use sui_types::base_types::SuiAddress;
use sui_types::crypto::{SignatureScheme, SuiSignature};
use sui_types::error::SuiError;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::multisig::MultiSig;
use sui_types::signature::{GenericSignature, VerifyParams};
use sui_types::signature_verification::{
    VerifiedDigestCache, verify_sender_signed_data_message_signatures,
};
use sui_types::transaction::TransactionDataAPI;
use fastcrypto_zkp::bn254::zk_login::{JWK, JwkId, OIDCProvider};
use nonempty::NonEmpty;
use std::collections::{BTreeMap, HashMap};
use sui_types::base_types::ObjectID;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("vectors") => cmd_vectors(&args[2..]),
        Some("corpus") => cmd_corpus(&args[2..]),
        Some("uservec") => cmd_uservec(&args[2..]),
        Some("bench") => cmd_bench(&args[2..]),
        Some("ecmh") => cmd_ecmh(&args[2..]),
        Some("ecvrf") => cmd_ecvrf(&args[2..]),
        Some("scan") => cmd_scan(&args[2..]),
        Some("zkvec") => cmd_zkvec(&args[2..]),
        _ => bail!("usage: zui-truth-sig vectors|uservec|corpus|zkvec|ecmh|ecvrf|bench ..."),
    }
}

// ---------------------------------------------------------------------------------------------
// Verdict names (README.md "Verdicts"): "ok", or "<stage>:<Rust error variant>".

fn fc_name(e: &FastCryptoError) -> String {
    let s = format!("{e:?}");
    s.split(['(', ' ', '{']).next().unwrap_or("").to_string()
}

fn sui_name(e: &SuiError) -> String {
    let s: &'static str = e.as_inner().into();
    s.to_string()
}

fn stage(st: &str, e: &FastCryptoError) -> String {
    format!("{st}:{}", fc_name(e))
}

fn ed25519_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> String {
    let pk = match Ed25519PublicKey::from_bytes(pk) {
        Ok(p) => p,
        Err(e) => return stage("pk", &e),
    };
    let sig = match Ed25519Signature::from_bytes(sig) {
        Ok(s) => s,
        Err(e) => return stage("sig", &e),
    };
    match pk.verify(msg, &sig) {
        Ok(()) => "ok".into(),
        Err(e) => stage("verify", &e),
    }
}

#[derive(Clone, Copy)]
enum H {
    Sha256,
    Keccak256,
}

impl H {
    fn name(self) -> &'static str {
        match self {
            H::Sha256 => "sha256",
            H::Keccak256 => "keccak256",
        }
    }
}

fn k1_verify(pk: &[u8], msg: &[u8], sig: &[u8], h: H) -> String {
    let pk = match Secp256k1PublicKey::from_bytes(pk) {
        Ok(p) => p,
        Err(e) => return stage("pk", &e),
    };
    let sig = match Secp256k1Signature::from_bytes(sig) {
        Ok(s) => s,
        Err(e) => return stage("sig", &e),
    };
    let r = match h {
        H::Sha256 => pk.verify_with_hash::<Sha256>(msg, &sig),
        H::Keccak256 => pk.verify_with_hash::<Keccak256>(msg, &sig),
    };
    match r {
        Ok(()) => "ok".into(),
        Err(e) => stage("verify", &e),
    }
}

fn r1_verify(pk: &[u8], msg: &[u8], sig: &[u8], h: H) -> String {
    let pk = match Secp256r1PublicKey::from_bytes(pk) {
        Ok(p) => p,
        Err(e) => return stage("pk", &e),
    };
    let sig = match Secp256r1Signature::from_bytes(sig) {
        Ok(s) => s,
        Err(e) => return stage("sig", &e),
    };
    let r = match h {
        H::Sha256 => pk.verify_with_hash::<Sha256>(msg, &sig),
        H::Keccak256 => pk.verify_with_hash::<Keccak256>(msg, &sig),
    };
    match r {
        Ok(()) => "ok".into(),
        Err(e) => stage("verify", &e),
    }
}

fn k1_recover(msg: &[u8], sig: &[u8], h: H) -> (String, Option<String>) {
    let sig = match Secp256k1RecoverableSignature::from_bytes(sig) {
        Ok(s) => s,
        Err(e) => return (stage("sig", &e), None),
    };
    let r = match h {
        H::Sha256 => sig.recover_with_hash::<Sha256>(msg),
        H::Keccak256 => sig.recover_with_hash::<Keccak256>(msg),
    };
    match r {
        Ok(pk) => ("ok".into(), Some(hex::encode(pk.as_ref()))),
        Err(e) => (stage("recover", &e), None),
    }
}

fn r1_recover(msg: &[u8], sig: &[u8], h: H) -> (String, Option<String>) {
    let sig = match Secp256r1RecoverableSignature::from_bytes(sig) {
        Ok(s) => s,
        Err(e) => return (stage("sig", &e), None),
    };
    let r = match h {
        H::Sha256 => sig.recover_with_hash::<Sha256>(msg),
        H::Keccak256 => sig.recover_with_hash::<Keccak256>(msg),
    };
    match r {
        Ok(pk) => ("ok".into(), Some(hex::encode(pk.as_ref()))),
        Err(e) => (stage("recover", &e), None),
    }
}

/// ed25519-consensus batch verification (the library fastcrypto wraps). Deterministic RNG: the
/// verdict of a batch does not depend on the coefficients except with negligible probability.
fn ed25519_batch(items: &[(Vec<u8>, Vec<u8>, Vec<u8>)], seed: u64) -> String {
    let mut batch = ed25519_consensus::batch::Verifier::new();
    for (pk, msg, sig) in items {
        let Ok(vk) = ed25519_consensus::VerificationKeyBytes::try_from(&pk[..]) else {
            return "pk:InvalidSliceLength".into();
        };
        let Ok(s) = ed25519_consensus::Signature::try_from(&sig[..]) else {
            return "sig:InvalidSliceLength".into();
        };
        batch.queue((vk, s, &msg[..]));
    }
    match batch.verify(ChaCha20Rng::seed_from_u64(seed)) {
        Ok(()) => "ok".into(),
        Err(e) => format!("verify:{e:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// vectors

struct Out {
    lines: Vec<Value>,
}

impl Out {
    fn push(&mut self, v: Value) {
        self.lines.push(v);
    }
}

fn ed_sign(kp: &Ed25519KeyPair, m: &[u8]) -> Ed25519Signature {
    Signer::<Ed25519Signature>::sign(kp, m)
}

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

fn cmd_vectors(args: &[String]) -> Result<()> {
    let [wy, out_path] = args else { bail!("vectors <wycheproof_dir> <out.jsonl>") };
    let wy = PathBuf::from(wy);
    let mut out = Out { lines: Vec::new() };
    wycheproof_ed25519(&wy.join("ed25519_test.json"), &mut out)?;
    wycheproof_ecdsa(&wy.join("ecdsa_secp256k1_sha256_p1363_test.json"), "secp256k1", &mut out)?;
    wycheproof_ecdsa(&wy.join("ecdsa_secp256r1_sha256_p1363_test.json"), "secp256r1", &mut out)?;
    zip215(&mut out);
    let mut rng = ChaCha20Rng::seed_from_u64(0x7a75_692d_7369_6731); // "zui-sig1"
    gen_ed25519(&mut rng, &mut out);
    gen_ecdsa(&mut rng, "secp256k1", &mut out);
    gen_ecdsa(&mut rng, "secp256r1", &mut out);
    gen_batches(&mut rng, &mut out);
    // fastcrypto's batch API rejects an empty batch (verify_batch_empty_fail*): the one case
    // where it differs from ed25519-consensus, whose empty batch is Ok.
    {
        let msgs: [&[u8]; 0] = [];
        let r = Ed25519PublicKey::verify_batch_empty_fail_different_msg(&msgs, &[], &[]);
        let v = match r {
            Ok(()) => "ok".to_string(),
            Err(e) => stage("verify", &e),
        };
        out.push(json!({ "id": "gen/ed25519/batch/empty", "op": "ed25519_batch", "items": [], "v": v }));
    }
    let mut f = std::io::BufWriter::new(std::fs::File::create(out_path)?);
    for l in &out.lines {
        serde_json::to_writer(&mut f, l)?;
        f.write_all(b"\n")?;
    }
    f.flush()?;
    eprintln!("{} vectors -> {out_path}", out.lines.len());
    Ok(())
}

fn wycheproof_ed25519(path: &Path, out: &mut Out) -> Result<()> {
    let d: Value = serde_json::from_slice(&std::fs::read(path).with_context(|| path.display().to_string())?)?;
    for g in d["testGroups"].as_array().unwrap() {
        let pk = unhex(g["publicKey"]["pk"].as_str().unwrap());
        for t in g["tests"].as_array().unwrap() {
            let msg = unhex(t["msg"].as_str().unwrap());
            let sig = unhex(t["sig"].as_str().unwrap());
            out.push(json!({
                "id": format!("wycheproof/ed25519/{}", t["tcId"]),
                "op": "ed25519_verify", "pk": h(&pk), "msg": h(&msg), "sig": h(&sig),
                "v": ed25519_verify(&pk, &msg, &sig), "wy": t["result"],
            }));
        }
    }
    Ok(())
}

fn wycheproof_ecdsa(path: &Path, curve: &str, out: &mut Out) -> Result<()> {
    let d: Value = serde_json::from_slice(&std::fs::read(path).with_context(|| path.display().to_string())?)?;
    for g in d["testGroups"].as_array().unwrap() {
        if g["sha"].as_str() != Some("SHA-256") {
            continue;
        }
        let unc = unhex(g["publicKey"]["uncompressed"].as_str().unwrap());
        // Sui public keys are 33-byte compressed SEC1: compress the Wycheproof key the way the
        // curve library itself serialises it (both libraries accept 65-byte input).
        let pk: Vec<u8> = if curve == "secp256k1" {
            match Secp256k1PublicKey::from_bytes(&unc) {
                Ok(p) => p.as_ref().to_vec(),
                Err(_) => continue,
            }
        } else {
            match Secp256r1PublicKey::from_bytes(&unc) {
                Ok(p) => p.as_ref().to_vec(),
                Err(_) => continue,
            }
        };
        for t in g["tests"].as_array().unwrap() {
            let msg = unhex(t["msg"].as_str().unwrap());
            let sig = unhex(t["sig"].as_str().unwrap());
            let v = if curve == "secp256k1" {
                k1_verify(&pk, &msg, &sig, H::Sha256)
            } else {
                r1_verify(&pk, &msg, &sig, H::Sha256)
            };
            out.push(json!({
                "id": format!("wycheproof/{curve}/{}", t["tcId"]),
                "op": format!("{curve}_verify"), "h": "sha256", "pk": h(&pk), "msg": h(&msg), "sig": h(&sig),
                "v": v, "wy": t["result"],
            }));
        }
    }
    Ok(())
}

/// ZIP-215 small-order cases: every combination of small-order encodings (canonical,
/// sign-flipped and y+p non-canonical) for A and R with s = 0, plus non-canonical s values.
fn zip215(out: &mut Out) {
    use curve25519_dalek::constants::EIGHT_TORSION;
    let p: [u8; 32] = {
        let mut b = [0xffu8; 32];
        b[0] = 0xed;
        b[31] = 0x7f;
        b
    };
    let mut encs: Vec<[u8; 32]> = Vec::new();
    for pt in EIGHT_TORSION.iter() {
        let c = pt.compress().to_bytes();
        for e in [c, { let mut x = c; x[31] ^= 0x80; x }] {
            if !encs.contains(&e) {
                encs.push(e);
            }
        }
    }
    // y + p for y in 0..19 (only y = 0 and y = 1 are small-order), both sign bits
    for y in 0u8..19 {
        let mut e = p;
        let (lo, c) = e[0].overflowing_add(y);
        e[0] = lo;
        if c {
            let mut i = 1;
            loop {
                let (v, c2) = e[i].overflowing_add(1);
                e[i] = v;
                if !c2 { break; }
                i += 1;
            }
        }
        for s in [e, { let mut x = e; x[31] ^= 0x80; x }] {
            if !encs.contains(&s) {
                encs.push(s);
            }
        }
    }
    let msg = b"Zcash".to_vec();
    let mut n = 0;
    for a in &encs {
        for r in &encs {
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(r);
            out.push(json!({
                "id": format!("zip215/{n}"), "op": "ed25519_verify", "pk": h(a), "msg": h(&msg),
                "sig": h(&sig), "v": ed25519_verify(a, &msg, &sig),
            }));
            n += 1;
        }
    }
    // s at and around the group order l, and with the top bits set
    let l: [u8; 32] = unhex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010").try_into().unwrap();
    let kp = Ed25519KeyPair::from_bytes(&[7u8; 32]).unwrap();
    let pk = kp.public().as_ref().to_vec();
    let good = ed_sign(&kp, &msg);
    let svals: Vec<[u8; 32]> = {
        let mut v = vec![l];
        let mut l1 = l;
        l1[0] += 1;
        v.push(l1);
        let mut lm1 = l;
        lm1[0] -= 1;
        v.push(lm1);
        let mut top = [0u8; 32];
        top[31] = 0x80;
        v.push(top);
        let mut ff = [0xffu8; 32];
        v.push(ff);
        ff[31] = 0x0f;
        v.push(ff);
        v
    };
    for (k, s) in svals.iter().enumerate() {
        let mut sig = good.as_ref().to_vec();
        sig[32..].copy_from_slice(s);
        out.push(json!({
            "id": format!("zip215/s/{k}"), "op": "ed25519_verify", "pk": h(&pk), "msg": h(&msg),
            "sig": h(&sig), "v": ed25519_verify(&pk, &msg, &sig),
        }));
        // the same s added to a real signature's s (s + l is the classic malleability)
    }
    let mut s_plus_l = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let v = good.as_ref()[32 + i] as u16 + l[i] as u16 + carry;
        s_plus_l[i] = v as u8;
        carry = v >> 8;
    }
    let mut sig = good.as_ref().to_vec();
    sig[32..].copy_from_slice(&s_plus_l);
    out.push(json!({
        "id": "zip215/s/plus_l", "op": "ed25519_verify", "pk": h(&pk), "msg": h(&msg),
        "sig": h(&sig), "v": ed25519_verify(&pk, &msg, &sig),
    }));
}

fn rand_msg(rng: &mut ChaCha20Rng) -> Vec<u8> {
    let len = match rng.gen_range(0..4) {
        0 => 0,
        1 => 32,
        2 => rng.gen_range(1..64),
        _ => rng.gen_range(64..400),
    };
    let mut m = vec![0u8; len];
    rng.fill_bytes(&mut m);
    m
}

fn flip(rng: &mut ChaCha20Rng, b: &mut [u8]) {
    if b.is_empty() {
        return;
    }
    let i = rng.gen_range(0..b.len());
    b[i] ^= 1 << rng.gen_range(0..8);
}

fn gen_ed25519(rng: &mut ChaCha20Rng, out: &mut Out) {
    for n in 0..1024 {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        let kp = Ed25519KeyPair::from_bytes(&sk).unwrap();
        let mut msg = rand_msg(rng);
        let sig = ed_sign(&kp, &msg);
        let mut pk = kp.public().as_ref().to_vec();
        let mut sigb = sig.as_ref().to_vec();
        out.push(json!({ "id": format!("gen/ed25519/sign/{n}"), "op": "ed25519_sign", "sk": h(&sk), "msg": h(&msg), "out": h(&sigb) }));
        if n % 2 == 0 {
            out.push(json!({ "id": format!("gen/ed25519/{n}"), "op": "ed25519_verify", "pk": h(&pk), "msg": h(&msg), "sig": h(&sigb), "v": ed25519_verify(&pk, &msg, &sigb) }));
        } else {
            match n % 6 {
                1 => flip(rng, &mut sigb),
                3 => flip(rng, &mut pk),
                _ => {
                    if msg.is_empty() {
                        msg.push(0)
                    } else {
                        flip(rng, &mut msg)
                    }
                }
            }
            out.push(json!({ "id": format!("gen/ed25519/mut/{n}"), "op": "ed25519_verify", "pk": h(&pk), "msg": h(&msg), "sig": h(&sigb), "v": ed25519_verify(&pk, &msg, &sigb) }));
        }
    }
    // random 32-byte strings as public keys (about half are not points)
    for n in 0..256 {
        let mut pk = [0u8; 32];
        rng.fill_bytes(&mut pk);
        let mut sig = [0u8; 64];
        rng.fill_bytes(&mut sig);
        sig[63] &= 0x0f;
        let msg = rand_msg(rng);
        out.push(json!({ "id": format!("gen/ed25519/randpk/{n}"), "op": "ed25519_verify", "pk": h(&pk), "msg": h(&msg), "sig": h(&sig), "v": ed25519_verify(&pk, &msg, &sig) }));
    }
}

const K1_N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
const K1_P: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const R1_N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
const R1_P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

fn be_sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut r = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let v = a[i] as i16 - b[i] as i16 - borrow;
        r[i] = v.rem_euclid(256) as u8;
        borrow = if v < 0 { 1 } else { 0 };
    }
    r
}

fn be_add_small(a: &[u8; 32], k: i64) -> [u8; 32] {
    let mut r = *a;
    if k >= 0 {
        let mut carry = k as u64;
        for i in (0..32).rev() {
            if carry == 0 {
                break;
            }
            let v = r[i] as u64 + (carry & 0xff);
            r[i] = v as u8;
            carry = (carry >> 8) + (v >> 8);
        }
    } else {
        let mut bb = [0u8; 32];
        bb[24..].copy_from_slice(&((-k) as u64).to_be_bytes());
        r = be_sub(&r, &bb);
    }
    r
}

fn arr(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

fn gen_ecdsa(rng: &mut ChaCha20Rng, curve: &str, out: &mut Out) {
    let k1 = curve == "secp256k1";
    let n = arr(if k1 { K1_N } else { R1_N });
    let p = arr(if k1 { K1_P } else { R1_P });
    let half = {
        // (n - 1) / 2: the largest low s
        let nm1 = be_add_small(&n, -1);
        let mut r = [0u8; 32];
        let mut carry = 0u8;
        for i in 0..32 {
            r[i] = (nm1[i] >> 1) | (carry << 7);
            carry = nm1[i] & 1;
        }
        r
    };
    let verify = |pk: &[u8], msg: &[u8], sig: &[u8], hh: H| if k1 { k1_verify(pk, msg, sig, hh) } else { r1_verify(pk, msg, sig, hh) };
    let recover = |msg: &[u8], sig: &[u8], hh: H| if k1 { k1_recover(msg, sig, hh) } else { r1_recover(msg, sig, hh) };
    let mut idx = 0usize;
    let mut push_v = |out: &mut Out, tag: &str, pk: &[u8], msg: &[u8], sig: &[u8], hh: H| {
        out.push(json!({ "id": format!("gen/{curve}/{tag}/{idx}"), "op": format!("{curve}_verify"), "h": hh.name(), "pk": h(pk), "msg": h(msg), "sig": h(sig), "v": verify(pk, msg, sig, hh) }));
        idx += 1;
    };
    let mut ridx = 0usize;
    let mut push_r = |out: &mut Out, tag: &str, msg: &[u8], sig: &[u8], hh: H| {
        let (v, pk) = recover(msg, sig, hh);
        out.push(json!({ "id": format!("gen/{curve}/rec/{tag}/{ridx}"), "op": format!("{curve}_recover"), "h": hh.name(), "msg": h(msg), "sig": h(sig), "v": v, "out": pk }));
        ridx += 1;
    };
    for i in 0..512 {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        let hh = if i % 2 == 0 { H::Sha256 } else { H::Keccak256 };
        let msg = rand_msg(rng);
        // recoverable signature: 64 bytes r||s (low s) + recovery id
        let (pk, rsig): (Vec<u8>, Vec<u8>) = if k1 {
            let kp = Secp256k1KeyPair::from_bytes(&sk).unwrap();
            let s = match hh {
                H::Sha256 => kp.sign_recoverable_with_hash::<Sha256>(&msg),
                H::Keccak256 => kp.sign_recoverable_with_hash::<Keccak256>(&msg),
            };
            (kp.public().as_ref().to_vec(), s.as_ref().to_vec())
        } else {
            let kp = Secp256r1KeyPair::from_bytes(&sk).unwrap();
            let s = match hh {
                H::Sha256 => kp.sign_recoverable_with_hash::<Sha256>(&msg),
                H::Keccak256 => kp.sign_recoverable_with_hash::<Keccak256>(&msg),
            };
            let pk = kp.public().as_ref().to_vec();
            (pk, s.as_ref().to_vec())
        };
        let sig = rsig[..64].to_vec();
        push_v(out, "ok", &pk, &msg, &sig, hh);
        push_r(out, "ok", &msg, &rsig, hh);
        // high s: n - s (valid curve-wise, rejected by low-s rules for verify; recover accepts)
        let s: [u8; 32] = sig[32..].try_into().unwrap();
        let hs = be_sub(&n, &s);
        let mut hsig = sig.clone();
        hsig[32..].copy_from_slice(&hs);
        push_v(out, "high_s", &pk, &msg, &hsig, hh);
        let mut hrsig = rsig.clone();
        hrsig[32..64].copy_from_slice(&hs);
        hrsig[64] ^= 1;
        push_r(out, "high_s", &msg, &hrsig, hh);
        // every recovery id and a few invalid ones
        for rid in [0u8, 1, 2, 3, 4, 27, 255] {
            if rid == rsig[64] {
                continue;
            }
            if i % 8 != 0 && rid > 3 {
                continue;
            }
            let mut x = rsig.clone();
            x[64] = rid;
            push_r(out, "rid", &msg, &x, hh);
        }
        // random mutations
        let mut m = sig.clone();
        flip(rng, &mut m);
        push_v(out, "mut_sig", &pk, &msg, &m, hh);
        let mut mp = pk.clone();
        flip(rng, &mut mp);
        push_v(out, "mut_pk", &pk_or(&mp), &msg, &sig, hh);
        let mut mm = msg.clone();
        if mm.is_empty() { mm.push(1) } else { flip(rng, &mut mm) }
        push_v(out, "mut_msg", &pk, &mm, &sig, hh);
        let mut mr = rsig.clone();
        let len = 64;
        let k = rng.gen_range(0..len);
        mr[k] ^= 1 << rng.gen_range(0..8);
        push_r(out, "mut", &msg, &mr, hh);
        // wrong hash function
        let other = if matches!(hh, H::Sha256) { H::Keccak256 } else { H::Sha256 };
        push_v(out, "wrong_hash", &pk, &msg, &sig, other);
        // boundary scalars for r and s
        if i < 16 {
            let zero = [0u8; 32];
            let one = be_add_small(&zero, 1);
            let vals = [zero, one, be_add_small(&n, -1), n, be_add_small(&n, 1), half, be_add_small(&half, 1), p, be_add_small(&p, -1), [0xffu8; 32]];
            for v in vals.iter() {
                let mut a = sig.clone();
                a[..32].copy_from_slice(v);
                push_v(out, "edge_r", &pk, &msg, &a, hh);
                let mut b = sig.clone();
                b[32..].copy_from_slice(v);
                push_v(out, "edge_s", &pk, &msg, &b, hh);
                for rid in 0u8..4 {
                    let mut c = rsig.clone();
                    c[..32].copy_from_slice(v);
                    c[64] = rid;
                    push_r(out, "edge_r", &msg, &c, hh);
                    let mut d = rsig.clone();
                    d[32..64].copy_from_slice(v);
                    d[64] = rid;
                    push_r(out, "edge_s", &msg, &d, hh);
                }
            }
            // public key encodings: other prefixes, x >= p, x = 0
            for (k, pre) in [0x00u8, 0x01, 0x04, 0x05, 0x06, 0x07, 0xff].iter().enumerate() {
                let mut q = pk.clone();
                q[0] = *pre;
                push_v(out, &format!("pk_prefix{k}"), &q, &msg, &sig, hh);
            }
            for x in [p, be_add_small(&p, 1), be_add_small(&p, -1), [0u8; 32], [0xffu8; 32]] {
                for pre in [2u8, 3] {
                    let mut q = vec![pre];
                    q.extend_from_slice(&x);
                    push_v(out, "pk_x", &q, &msg, &sig, hh);
                }
            }
        }
        // small r with recovery ids 2 and 3 (x = r + n), and r near n with 2/3 (overflow)
        if i < 64 {
            let mut small = [0u8; 32];
            rng.fill_bytes(&mut small[16..]);
            small[16] &= 0x3f;
            let big = be_sub(&n, &be_add_small(&[0u8; 32], rng.gen_range(1..1 << 30)));
            let mid = be_sub(&be_sub(&[0xffu8; 32], &n), &be_add_small(&[0u8; 32], -(rng.gen_range(0..1 << 30) as i64) ));
            for rv in [small, big, mid] {
                for rid in [2u8, 3] {
                    let mut c = rsig.clone();
                    c[..32].copy_from_slice(&rv);
                    c[64] = rid;
                    push_r(out, "x_reduced", &msg, &c, hh);
                }
            }
        }
    }
}

fn pk_or(b: &[u8]) -> Vec<u8> {
    b.to_vec()
}

fn gen_batches(rng: &mut ChaCha20Rng, out: &mut Out) {
    // valid triples to draw from, plus a pool of invalid ones (mutations and small-order cases)
    let mut good: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    for _ in 0..256 {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        let kp = Ed25519KeyPair::from_bytes(&sk).unwrap();
        let msg = rand_msg(rng);
        let sig = ed_sign(&kp, &msg).as_ref().to_vec();
        good.push((kp.public().as_ref().to_vec(), msg, sig));
    }
    let zip: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = out
        .lines
        .iter()
        .filter(|l| l["id"].as_str().unwrap_or("").starts_with("zip215/") && l["op"] == "ed25519_verify")
        .map(|l| (unhex(l["pk"].as_str().unwrap()), unhex(l["msg"].as_str().unwrap()), unhex(l["sig"].as_str().unwrap())))
        .collect();
    for n in 0..512 {
        let size = match n % 4 {
            0 => rng.gen_range(1..4),
            1 => rng.gen_range(4..32),
            2 => rng.gen_range(32..128),
            _ => rng.gen_range(1..300),
        };
        let mut items: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> =
            (0..size).map(|_| good[rng.gen_range(0..good.len())].clone()).collect();
        match n % 5 {
            0 => {}
            1 => {
                let k = rng.gen_range(0..items.len());
                flip(rng, &mut items[k].2);
            }
            2 => {
                let k = rng.gen_range(0..items.len());
                items[k] = zip[rng.gen_range(0..zip.len())].clone();
            }
            3 => {
                for _ in 0..rng.gen_range(1..4) {
                    let k = rng.gen_range(0..items.len());
                    items[k] = zip[rng.gen_range(0..zip.len())].clone();
                }
            }
            _ => {
                let k = rng.gen_range(0..items.len());
                flip(rng, &mut items[k].1);
            }
        }
        let v = ed25519_batch(&items, n as u64);
        let arr: Vec<Value> = items.iter().map(|(a, b, c)| json!([h(a), h(b), h(c)])).collect();
        out.push(json!({ "id": format!("gen/ed25519/batch/{n}"), "op": "ed25519_batch", "items": arr, "v": v }));
    }
}

// ---------------------------------------------------------------------------------------------
// corpus

/// Serialises as its raw bytes (a BCS tuple of u8), so `IntentMessage<Raw>` hashes exactly the
/// bytes given: lets a mutated message go through the same generic verify path.
struct Raw(Vec<u8>);

impl Serialize for Raw {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut t = s.serialize_tuple(self.0.len())?;
        for b in &self.0 {
            t.serialize_element(b)?;
        }
        t.end()
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

fn params_for(pv: u64) -> VerifyParams {
    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(pv), Chain::Mainnet);
    VerifyParams {
        zk_login_env: fastcrypto_zkp::bn254::zk_login_api::ZkLoginEnv::Prod,
        zklogin_circuit_mode: cfg.zklogin_circuit_mode(),
        verify_legacy_zklogin_address: cfg.verify_legacy_zklogin_address(),
        accept_zklogin_in_multisig: cfg.accept_zklogin_in_multisig(),
        accept_passkey_in_multisig: cfg.accept_passkey_in_multisig(),
        accept_mldsa65_in_multisig: cfg.mldsa65_auth(),
        zklogin_max_epoch_upper_bound_delta: cfg.zklogin_max_epoch_upper_bound_delta(),
        additional_multisig_checks: cfg.additional_multisig_checks(),
        validate_zklogin_public_identifier: cfg.validate_zklogin_public_identifier(),
        // exactly as AuthorityPerEpochStore builds the SignatureVerifier
        supported_providers: cfg
            .zklogin_supported_providers()
            .iter()
            .map(|s| <OIDCProvider as std::str::FromStr>::from_str(s).expect("provider"))
            .collect(),
        ..Default::default()
    }
}

/// Corpus-wide inputs that are not in the checkpoint itself: every AuthenticatorStateInner
/// version (its active JWKs) and every AddressAliases object version, from the input and output
/// objects of all corpus blobs plus the extra blobs in `aux_src` (CORPUS.md: checkpoints that
/// wrote an AddressAliases version a corpus transaction was verified against).
struct Pre {
    /// (checkpoint seq, active JWKs) in seq order
    states: Vec<(u64, Vec<(JwkId, JWK)>)>,
    aliases: HashMap<(ObjectID, u64), Vec<SuiAddress>>,
}

fn chk_list(dir: &Path) -> Result<Vec<(u64, PathBuf)>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut v: Vec<(u64, PathBuf)> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let p = e.path();
            let n = p.file_name()?.to_str()?.strip_suffix(".chk")?.parse::<u64>().ok()?;
            Some((n, p))
        })
        .collect();
    v.sort();
    Ok(v)
}

fn prescan(corpus: &Path, aux_src: &Path) -> Result<Pre> {
    let mut files = chk_list(&corpus.join("chk"))?;
    files.extend(chk_list(aux_src)?);
    type One = (Vec<(u64, Vec<(JwkId, JWK)>)>, Vec<((ObjectID, u64), Vec<SuiAddress>)>);
    let parts: Vec<One> = files
        .par_iter()
        .map(|(seq, path)| -> Result<One> {
            let raw = std::fs::read(path)?;
            let cp: CheckpointData = bcs::from_bytes(&raw[1..]).with_context(|| format!("decode {}", path.display()))?;
            let mut st = Vec::new();
            let mut al = Vec::new();
            for tx in &cp.transactions {
                for o in tx.output_objects.iter().chain(tx.input_objects.iter()) {
                    let Some(mo) = o.data.try_as_move() else { continue };
                    let t = mo.type_();
                    if t.address() == sui_types::SUI_FRAMEWORK_ADDRESS && t.module().as_str() == "address_alias" && t.name().as_str() == "AddressAliases" {
                        let a: sui_types::address_alias::AddressAliases = bcs::from_bytes(mo.contents()).context("AddressAliases")?;
                        al.push(((o.id(), o.version().value()), a.aliases.contents));
                    }
                }
                // the authenticator state after this transaction (output objects only)
                for o in tx.output_objects.iter() {
                    let Some(mo) = o.data.try_as_move() else { continue };
                    if mo.type_().to_string().contains("authenticator_state::AuthenticatorStateInner") {
                        #[derive(serde::Deserialize)]
                        struct Field {
                            _id: [u8; 32],
                            _name: u64,
                            value: sui_types::authenticator_state::AuthenticatorStateInner,
                        }
                        let f: Field = bcs::from_bytes(mo.contents()).context("AuthenticatorStateInner")?;
                        st.push((*seq, f.value.active_jwks.into_iter().map(|a| (a.jwk_id, a.jwk)).collect()));
                    }
                }
            }
            Ok((st, al))
        })
        .collect::<Result<_>>()?;
    let mut pre = Pre { states: Vec::new(), aliases: HashMap::new() };
    for (st, al) in parts {
        pre.states.extend(st);
        for (k, v) in al {
            if let Some(prev) = pre.aliases.insert(k, v.clone()) {
                if prev != v {
                    bail!("AddressAliases {} v{}: two different contents", k.0, k.1);
                }
            }
        }
    }
    pre.states.sort_by_key(|s| s.0);
    Ok(pre)
}

fn load_first_seqs(corpus: &Path) -> Result<Vec<u64>> {
    let text = std::fs::read_to_string(corpus.join("epochs.jsonl"))?;
    let mut v = Vec::new();
    for l in text.lines().filter(|l| !l.is_empty()) {
        let e: Value = serde_json::from_str(l)?;
        v.push(e["first"].as_u64().ok_or_else(|| anyhow!("epochs.jsonl: no first"))?);
    }
    Ok(v)
}

/// The JWK map a validator's SignatureVerifier holds while executing checkpoint `seq` of
/// `epoch` (sui-core AuthorityPerEpochStore): at epoch start every active JWK of the
/// authenticator state (the latest state written before the epoch's first checkpoint), then each
/// JWK the epoch adds (`update_authenticator_state` -> `insert_jwk`, first insertion wins; nothing
/// is removed inside an epoch). Here the additions are those visible in authenticator-state
/// versions written by corpus checkpoints of this epoch up to and including `seq`.
fn jwks_at(pre: &Pre, first_of: &[u64], epoch: u64, seq: u64) -> Vec<(JwkId, JWK)> {
    let first = first_of[epoch as usize];
    let mut map: BTreeMap<(String, String), (JwkId, JWK)> = BTreeMap::new();
    let mut add = |list: &Vec<(JwkId, JWK)>| {
        for (id, j) in list {
            map.entry((id.iss.clone(), id.kid.clone())).or_insert((id.clone(), j.clone()));
        }
    };
    if let Some(base) = pre.states.iter().rev().find(|s| s.0 < first) {
        add(&base.1);
    }
    for s in pre.states.iter().filter(|s| s.0 >= first && s.0 <= seq) {
        add(&s.1);
    }
    map.into_values().collect()
}

fn splitmix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

fn has_zklogin(sig: &GenericSignature) -> bool {
    match sig {
        GenericSignature::ZkLoginAuthenticator(_) => true,
        GenericSignature::MultiSig(m) => m.has_zklogin_sigs(),
        GenericSignature::MultiSigLegacy(m) => MultiSig::try_from(m.clone()).map(|m| m.has_zklogin_sigs()).unwrap_or(false),
        _ => false,
    }
}

/// One user-signature check exactly as `verify_sender_signed_data_message_signatures` does it
/// for one signature: parse the GenericSignature bytes, then `verify_authenticator`.
fn check_sig(sig_bytes: &[u8], intent_bytes: &[u8], author: SuiAddress, epoch: u64, params: &VerifyParams) -> (String, Value) {
    let sig = match <GenericSignature as ToFromBytes>::from_bytes(sig_bytes) {
        Ok(s) => s,
        Err(e) => return (format!("parse:{}", fc_name(&e)), Value::Null),
    };
    let addr = match SuiAddress::try_from(&sig) {
        Ok(a) => json!(h(a.as_ref())),
        Err(e) => json!(format!("err:{}", sui_name(&e))),
    };
    let msg = IntentMessage::new(Intent::sui_transaction(), Raw(intent_bytes[3..].to_vec()));
    debug_assert_eq!(&intent_bytes[..3], &bcs::to_bytes(&Intent::sui_transaction()).unwrap()[..]);
    let cache = Arc::new(VerifiedDigestCache::new_empty());
    match sig.verify_authenticator(&msg, author, epoch, params, cache) {
        Ok(()) => ("ok".into(), addr),
        Err(e) => (sui_name(&e), addr),
    }
}

fn cmd_corpus(args: &[String]) -> Result<()> {
    if args.len() < 2 {
        bail!("corpus <corpus_dir> <out_dir> [seq...]");
    }
    let corpus = PathBuf::from(&args[0]);
    let out_dir = PathBuf::from(&args[1]);
    std::fs::create_dir_all(&out_dir)?;
    let pvs = load_pv(&corpus)?;
    let seqs: Vec<u64> = if args.len() > 2 {
        args[2..].iter().map(|s| s.parse()).collect::<Result<_, _>>()?
    } else {
        let mut v: Vec<u64> = std::fs::read_dir(corpus.join("chk"))?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_suffix(".chk")).and_then(|n| n.parse().ok()))
            .collect();
        v.sort();
        v
    };
    let params: Vec<VerifyParams> = pvs.iter().map(|pv| params_for(*pv)).collect();
    let first_of = load_first_seqs(&corpus)?;
    let pre = prescan(&corpus, &out_dir.join("aux-src"))?;
    eprintln!("prescan: {} authenticator states, {} AddressAliases versions", pre.states.len(), pre.aliases.len());
    let done = std::sync::atomic::AtomicUsize::new(0);
    let totals: Vec<(u64, u64, u64)> = seqs
        .par_iter()
        .map(|seq| -> Result<(u64, u64, u64)> {
            let raw = std::fs::read(corpus.join(format!("chk/{seq}.chk")))?;
            if raw.first() != Some(&1) {
                bail!("{seq}: not a BCS blob");
            }
            let cp: CheckpointData = bcs::from_bytes(&raw[1..]).with_context(|| format!("decode {seq}"))?;
            let epoch = cp.checkpoint_summary.data().epoch;
            let pv = *pvs.get(epoch as usize).ok_or_else(|| anyhow!("no pv for epoch {epoch}"))?;
            // JWKs the validators held at this checkpoint (see jwks_at)
            let jwk_list = jwks_at(&pre, &first_of, epoch, *seq);
            let mut prm_owned = params[epoch as usize].clone();
            for (id, jwk) in &jwk_list {
                prm_owned.oidc_provider_jwks.insert(id.clone(), jwk.clone());
            }
            let prm = &prm_owned;
            let mut lines: Vec<String> = Vec::new();
            let (mut nsig, mut nmut, mut nzk) = (0u64, 0u64, 0u64);
            for (i, tx) in cp.transactions.iter().enumerate() {
                let ssd = tx.transaction.data();
                let intent = ssd.intent_message();
                let intent_bytes = bcs::to_bytes(intent)?;
                let sigs = ssd.tx_signatures();
                if sigs.iter().any(has_zklogin) {
                    nzk += 1;
                }
                // transaction level, with the address aliases the checkpoint pins for each
                // required signer (CheckpointContentsV2: the AddressAliases version used)
                let req = intent.value.required_signers();
                let signers: Vec<String> = req.iter().map(|a| h(a.as_ref())).collect();
                let pinned = cp.checkpoint_contents.inner().user_signatures(i).unwrap_or_default();
                let mut aliased: Vec<(SuiAddress, NonEmpty<SuiAddress>)> = Vec::new();
                let mut alias_json = Vec::new();
                for (k, signer) in req.iter().enumerate() {
                    match pinned.get(k).and_then(|p| p.1) {
                        None => aliased.push((*signer, NonEmpty::singleton(*signer))),
                        Some(ver) => {
                            let id = sui_types::address_alias::address_aliases_object_id(*signer)?;
                            let list = pre.aliases.get(&(id, ver.value())).ok_or_else(|| anyhow!("{seq} tx {i}: AddressAliases {id} v{} not in the corpus or aux-src", ver.value()))?;
                            // sui-core: an empty aliases field falls back to the signer itself
                            let ne = NonEmpty::from_vec(list.clone()).unwrap_or(NonEmpty::singleton(*signer));
                            alias_json.push(json!([h(signer.as_ref()), ne.iter().map(|a| h(a.as_ref())).collect::<Vec<_>>()]));
                            aliased.push((*signer, ne));
                        }
                    }
                }
                let cache = Arc::new(VerifiedDigestCache::new_empty());
                let tv = verify_sender_signed_data_message_signatures(tx.transaction.data(), epoch, prm, cache, aliased);
                let (v, idx) = match tv {
                    Ok(ix) => ("ok".to_string(), json!(ix)),
                    Err(e) => (sui_name(&e), Value::Null),
                };
                let mut tl = json!({ "k": "tx", "tx": i, "system": intent.value.is_system_tx(), "signers": signers, "v": v, "idx": idx });
                if !alias_json.is_empty() {
                    tl["aliases"] = json!(alias_json);
                }
                lines.push(tl.to_string());
                for (j, sig) in sigs.iter().enumerate() {
                    let bytes = sig.as_ref().to_vec();
                    let author = SuiAddress::try_from(sig).map_err(|e| anyhow!("{seq} tx {i} sig {j}: author: {e}"))?;
                    let (v, addr) = check_sig(&bytes, &intent_bytes, author, epoch, prm);
                    lines.push(json!({ "k": "sig", "tx": i, "sig": j, "scheme": scheme_name(sig), "m": Value::Null, "author": h(author.as_ref()), "addr": addr, "v": v }).to_string());
                    nsig += 1;
                    // seeded mutations: 1 for plain Ed25519, 12 for every other scheme
                    let is_ed = matches!(sig, GenericSignature::Signature(s) if s.scheme() == SignatureScheme::ED25519);
                    let count = if is_ed { 1 } else { 12 };
                    for k in 0..count {
                        let r = splitmix(seq.wrapping_mul(0x1000193) ^ ((i as u64) << 32) ^ ((j as u64) << 48) ^ k);
                        let kind = if is_ed { r % 3 } else if k < 8 { 0 } else if k < 11 { 1 } else { 2 };
                        let xor = (1u8 << ((r >> 8) % 8)) as u8;
                        let (target, off, mb, mi, ma) = match kind {
                            0 => {
                                let off = (((r >> 16) % (bytes.len() as u64 - 1)) + 1) as usize; // keep the flag
                                let mut b = bytes.clone();
                                b[off] ^= xor;
                                ("sig", off, b, intent_bytes.clone(), author)
                            }
                            1 => {
                                let off = ((r >> 16) % (intent_bytes.len() as u64 - 3)) as usize + 3;
                                let mut m = intent_bytes.clone();
                                m[off] ^= xor;
                                ("msg", off, bytes.clone(), m, author)
                            }
                            _ => {
                                let off = ((r >> 16) % 32) as usize;
                                let mut a: [u8; 32] = author.to_inner();
                                a[off] ^= xor;
                                ("author", off, bytes.clone(), intent_bytes.clone(), SuiAddress::from_bytes(a).unwrap())
                            }
                        };
                        let (v, addr) = check_sig(&mb, &mi, ma, epoch, prm);
                        lines.push(json!({ "k": "sig", "tx": i, "sig": j, "scheme": scheme_name(sig), "m": format!("{target}:{off}:{xor:02x}"), "author": h(ma.as_ref()), "addr": addr, "v": v }).to_string());
                        nmut += 1;
                    }
                }
            }
            let flags = json!({
                "accept_zklogin_in_multisig": prm.accept_zklogin_in_multisig,
                "accept_passkey_in_multisig": prm.accept_passkey_in_multisig,
                "accept_mldsa65_in_multisig": prm.accept_mldsa65_in_multisig,
                "additional_multisig_checks": prm.additional_multisig_checks,
                "validate_zklogin_public_identifier": prm.validate_zklogin_public_identifier,
                "verify_legacy_zklogin_address": prm.verify_legacy_zklogin_address,
                "zklogin_max_epoch_upper_bound_delta": prm.zklogin_max_epoch_upper_bound_delta,
                "zklogin_circuit_mode": prm.zklogin_circuit_mode,
                "zklogin_supported_providers": prm.supported_providers.iter().map(|p| format!("{p:?}")).collect::<Vec<_>>(),
            });
            let mut header = json!({ "k": "Header", "seq": seq, "epoch": epoch, "pv": pv, "flags": flags, "sigs": nsig, "mutations": nmut, "zklogin_txs": nzk });
            if nzk > 0 {
                header["jwks"] = json!(jwk_list.iter().map(|(id, j)| json!({ "iss": id.iss, "kid": id.kid, "kty": j.kty, "e": j.e, "n": j.n, "alg": j.alg })).collect::<Vec<_>>());
            }
            let mut text = header.to_string();
            text.push('\n');
            for l in &lines {
                text.push_str(l);
                text.push('\n');
            }
            let z = zstd::encode_all(text.as_bytes(), 9)?;
            let tmp = out_dir.join(format!(".{seq}.jsonl.zst.part"));
            std::fs::write(&tmp, z)?;
            std::fs::rename(&tmp, out_dir.join(format!("{seq}.jsonl.zst")))?;
            let d = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if d % 2000 == 0 {
                eprintln!("{d}/{}", seqs.len());
            }
            Ok((nsig, nmut, nzk))
        })
        .collect::<Result<_>>()?;
    let (s, m, z) = totals.iter().fold((0, 0, 0), |a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2));
    println!("{{\"checkpoints\":{},\"sigs\":{s},\"mutations\":{m},\"zklogin_txs\":{z}}}", seqs.len());
    Ok(())
}

fn scheme_name(sig: &GenericSignature) -> &'static str {
    match sig {
        GenericSignature::MultiSig(_) => "MultiSig",
        GenericSignature::MultiSigLegacy(_) => "MultiSigLegacy",
        GenericSignature::ZkLoginAuthenticator(_) => "ZkLoginAuthenticator",
        GenericSignature::PasskeyAuthenticator(_) => "PasskeyAuthenticator",
        GenericSignature::Signature(s) => match s.scheme() {
            SignatureScheme::ED25519 => "ED25519",
            SignatureScheme::Secp256k1 => "Secp256k1",
            SignatureScheme::Secp256r1 => "Secp256r1",
            SignatureScheme::MLDSA65 => "MLDSA65",
            _ => "other",
        },
    }
}

// ---------------------------------------------------------------------------------------------
// bench (harness protocol)

fn passes(iters: usize, mut f: impl FnMut() -> Result<()>) -> Result<Vec<u128>> {
    f()?;
    let mut v = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        f()?;
        v.push(t.elapsed().as_nanos());
    }
    Ok(v)
}

fn print_bench(name: &str, unit: &str, units: u64, mut p: Vec<u128>) {
    p.sort();
    let med = p[p.len() / 2];
    println!(
        "{{\"impl\":\"rust\",\"bench\":\"{name}\",\"unit\":\"{unit}\",\"units\":{units},\"iters\":{},\"median_ns\":{med},\"min_ns\":{},\"ns_per_unit\":{:.2}}}",
        p.len(),
        p[0],
        med as f64 / units.max(1) as f64
    );
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
                list = Some(args[i + 1].clone());
                i += 2;
            }
            a => bail!("unknown bench argument {a}"),
        }
    }
    let files: Vec<PathBuf> = std::fs::read_to_string(list.ok_or_else(|| anyhow!("--list FILE"))?)?
        .lines()
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .collect();
    let iters = iters.max(1);
    if name == "user-sig" {
        return bench_user_sig(&files, iters);
    }
    // primitive benches over the vectors file(s): the "ok" items of one op
    let mut items: Vec<Value> = Vec::new();
    for f in &files {
        for l in std::fs::read_to_string(f)?.lines().filter(|l| !l.is_empty()) {
            items.push(serde_json::from_str(l)?);
        }
    }
    let pick = |op: &str| -> Vec<&Value> { items.iter().filter(|v| v["op"] == op && v["v"] == "ok").collect() };
    let hk = |v: &Value| if v["h"] == "keccak256" { H::Keccak256 } else { H::Sha256 };
    match name.as_str() {
        "ed25519-verify" => {
            let xs: Vec<(Ed25519PublicKey, Vec<u8>, Ed25519Signature)> = pick("ed25519_verify")
                .iter()
                .map(|v| {
                    (
                        Ed25519PublicKey::from_bytes(&unhex(v["pk"].as_str().unwrap())).unwrap(),
                        unhex(v["msg"].as_str().unwrap()),
                        Ed25519Signature::from_bytes(&unhex(v["sig"].as_str().unwrap())).unwrap(),
                    )
                })
                .collect();
            print_bench(&name, "sig", xs.len() as u64, passes(iters, || {
                for (pk, m, s) in &xs {
                    std::hint::black_box(pk.verify(m, s).is_ok());
                }
                Ok(())
            })?);
        }
        // the full path from bytes, as Sui does per signature (parse key, parse sig, verify)
        "ed25519-verify-bytes" => {
            let xs: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = pick("ed25519_verify")
                .iter()
                .map(|v| (unhex(v["pk"].as_str().unwrap()), unhex(v["msg"].as_str().unwrap()), unhex(v["sig"].as_str().unwrap())))
                .collect();
            print_bench(&name, "sig", xs.len() as u64, passes(iters, || {
                for (pk, m, s) in &xs {
                    std::hint::black_box(ed25519_verify(pk, m, s));
                }
                Ok(())
            })?);
        }
        "ed25519-batch" => {
            let bs: Vec<Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>> = pick("ed25519_batch")
                .iter()
                .map(|v| {
                    v["items"].as_array().unwrap().iter().map(|t| (unhex(t[0].as_str().unwrap()), unhex(t[1].as_str().unwrap()), unhex(t[2].as_str().unwrap()))).collect()
                })
                .collect();
            let n: u64 = bs.iter().map(|b| b.len() as u64).sum();
            print_bench(&name, "sig", n, passes(iters, || {
                for (k, b) in bs.iter().enumerate() {
                    std::hint::black_box(ed25519_batch(b, k as u64));
                }
                Ok(())
            })?);
        }
        // fastcrypto EllipticCurveMultisetHash: insert every "i" item of the ecmh vectors, digest once
        "ecmh-insert" => {
            use fastcrypto::hash::{EllipticCurveMultisetHash, MultisetHash};
            let mut xs: Vec<Vec<u8>> = Vec::new();
            for v in items.iter().filter(|v| v["op"] == "ecmh") {
                for o in v["ops"].as_array().unwrap() {
                    if o[0] == "i" {
                        xs.push(unhex(o[1].as_str().unwrap()));
                    }
                }
            }
            print_bench(&name, "item", xs.len() as u64, passes(iters, || {
                let mut acc = EllipticCurveMultisetHash::default();
                for x in &xs {
                    acc.insert(x);
                }
                std::hint::black_box(acc.digest());
                Ok(())
            })?);
        }
        "ecvrf-prove" => {
            use fastcrypto::vrf::VRFKeyPair;
            use fastcrypto::vrf::ecvrf::{ECVRFKeyPair, ECVRFPrivateKey};
            let xs: Vec<(ECVRFKeyPair, Vec<u8>)> = items
                .iter()
                .filter(|v| v["op"] == "ecvrf_prove")
                .map(|v| {
                    let sk = bcs::from_bytes::<ECVRFPrivateKey>(&unhex(v["sk"].as_str().unwrap())).unwrap();
                    (ECVRFKeyPair::from(sk), unhex(v["alpha"].as_str().unwrap()))
                })
                .collect();
            print_bench(&name, "proof", xs.len() as u64, passes(iters, || {
                for (kp, a) in &xs {
                    std::hint::black_box(kp.output(a));
                }
                Ok(())
            })?);
        }
        // the sui::ecvrf::ecvrf_verify native path from bytes, valid proofs only
        "ecvrf-verify" => {
            let xs: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> = items
                .iter()
                .filter(|v| v["op"] == "ecvrf_verify" && v["v"] == "true")
                .map(|v| {
                    let g = |k: &str| unhex(v[k].as_str().unwrap());
                    (g("hash"), g("alpha"), g("pk"), g("proof"))
                })
                .collect();
            print_bench(&name, "proof", xs.len() as u64, passes(iters, || {
                for (hh, a, pk, pf) in &xs {
                    std::hint::black_box(ecvrf_native(hh, a, pk, pf));
                }
                Ok(())
            })?);
        }
        "ed25519-sign" => {
            let xs: Vec<(Ed25519KeyPair, Vec<u8>)> = items
                .iter()
                .filter(|v| v["op"] == "ed25519_sign")
                .map(|v| (Ed25519KeyPair::from_bytes(&unhex(v["sk"].as_str().unwrap())).unwrap(), unhex(v["msg"].as_str().unwrap())))
                .collect();
            print_bench(&name, "sig", xs.len() as u64, passes(iters, || {
                for (kp, m) in &xs {
                    std::hint::black_box(ed_sign(kp, m));
                }
                Ok(())
            })?);
        }
        "secp256k1-verify" | "secp256r1-verify" => {
            let op = if name == "secp256k1-verify" { "secp256k1_verify" } else { "secp256r1_verify" };
            let xs: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, H)> = pick(op)
                .iter()
                .map(|v| (unhex(v["pk"].as_str().unwrap()), unhex(v["msg"].as_str().unwrap()), unhex(v["sig"].as_str().unwrap()), hk(v)))
                .collect();
            let k1 = op == "secp256k1_verify";
            print_bench(&name, "sig", xs.len() as u64, passes(iters, || {
                for (pk, m, s, hh) in &xs {
                    std::hint::black_box(if k1 { k1_verify(pk, m, s, *hh) } else { r1_verify(pk, m, s, *hh) });
                }
                Ok(())
            })?);
        }
        "secp256k1-recover" | "secp256r1-recover" => {
            let op = if name == "secp256k1-recover" { "secp256k1_recover" } else { "secp256r1_recover" };
            let xs: Vec<(Vec<u8>, Vec<u8>, H)> =
                pick(op).iter().map(|v| (unhex(v["msg"].as_str().unwrap()), unhex(v["sig"].as_str().unwrap()), hk(v))).collect();
            let k1 = op == "secp256k1_recover";
            print_bench(&name, "sig", xs.len() as u64, passes(iters, || {
                for (m, s, hh) in &xs {
                    std::hint::black_box(if k1 { k1_recover(m, s, *hh) } else { r1_recover(m, s, *hh) });
                }
                Ok(())
            })?);
        }
        n => bail!("unknown bench {n}"),
    }
    Ok(())
}

/// Every non-zkLogin user signature of the listed blobs through verify_authenticator, decoded
/// and hashed outside the timed region except for what verify_authenticator does itself (it
/// hashes the intent message).
fn bench_user_sig(files: &[PathBuf], iters: usize) -> Result<()> {
    let mut work: Vec<(GenericSignature, IntentMessage<Raw>, SuiAddress, u64, usize)> = Vec::new();
    let pvs = {
        // the corpus root is two levels above chk/<seq>.chk
        let root = files.first().and_then(|f| f.parent()).and_then(|p| p.parent()).ok_or_else(|| anyhow!("empty list"))?;
        load_pv(root)?
    };
    let params: Vec<VerifyParams> = pvs.iter().map(|pv| params_for(*pv)).collect();
    for f in files {
        let raw = std::fs::read(f)?;
        let cp: CheckpointData = bcs::from_bytes(&raw[1..])?;
        let epoch = cp.checkpoint_summary.data().epoch;
        for tx in &cp.transactions {
            let ssd = tx.transaction.data();
            if ssd.intent_message().value.is_system_tx() {
                continue;
            }
            let ib = bcs::to_bytes(ssd.intent_message())?;
            for s in ssd.tx_signatures() {
                if has_zklogin(s) {
                    continue;
                }
                let a = SuiAddress::try_from(s)?;
                work.push((s.clone(), IntentMessage::new(Intent::sui_transaction(), Raw(ib[3..].to_vec())), a, epoch, epoch as usize));
            }
        }
    }
    let cache = Arc::new(VerifiedDigestCache::new_empty());
    print_bench("user-sig", "sig", work.len() as u64, passes(iters, || {
        for (s, m, a, e, pi) in &work {
            std::hint::black_box(s.verify_authenticator(m, *a, *e, &params[*pi], cache.clone()).is_ok());
        }
        Ok(())
    })?);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// uservec: synthesized user signatures. Inputs are built as raw bytes (so malformed shapes can be
// expressed); every verdict and address comes from `check_sig` (Mysten's code).

fn uleb(out: &mut Vec<u8>, mut n: u64) {
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

fn bcs_bytes(out: &mut Vec<u8>, b: &[u8]) {
    uleb(out, b.len() as u64);
    out.extend_from_slice(b);
}

fn b64url(b: &[u8]) -> String {
    use base64ct::Encoding;
    base64ct::Base64UrlUnpadded::encode_string(b)
}

fn b64std(b: &[u8]) -> String {
    use base64ct::Encoding;
    base64ct::Base64::encode_string(b)
}

enum Member {
    Ed(Ed25519KeyPair),
    K1(Secp256k1KeyPair),
    R1(Secp256r1KeyPair),
    Passkey(Secp256r1KeyPair),
    ZkLogin(Vec<u8>),
    Mldsa(Vec<u8>),
}

impl Clone for Member {
    fn clone(&self) -> Self {
        match self {
            Member::Ed(k) => Member::Ed(k.copy()),
            Member::K1(k) => Member::K1(k.copy()),
            Member::R1(k) => Member::R1(k.copy()),
            Member::Passkey(k) => Member::Passkey(k.copy()),
            Member::ZkLogin(b) => Member::ZkLogin(b.clone()),
            Member::Mldsa(b) => Member::Mldsa(b.clone()),
        }
    }
}

fn gen_kp<K: ToFromBytes>(rng: &mut ChaCha20Rng) -> K {
    loop {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        if let Ok(k) = K::from_bytes(&sk) {
            return k;
        }
    }
}

impl Member {
    fn tag(&self) -> u8 {
        match self {
            Member::Ed(_) => 0,
            Member::K1(_) => 1,
            Member::R1(_) => 2,
            Member::ZkLogin(_) => 3,
            Member::Passkey(_) => 4,
            Member::Mldsa(_) => 5,
        }
    }
    fn flag(&self) -> u8 {
        match self {
            Member::Ed(_) => 0,
            Member::K1(_) => 1,
            Member::R1(_) => 2,
            Member::ZkLogin(_) => 5,
            Member::Passkey(_) => 6,
            Member::Mldsa(_) => 7,
        }
    }
    fn pk(&self) -> Vec<u8> {
        match self {
            Member::Ed(k) => k.public().as_ref().to_vec(),
            Member::K1(k) => k.public().as_ref().to_vec(),
            Member::R1(k) | Member::Passkey(k) => k.public().as_ref().to_vec(),
            Member::ZkLogin(b) | Member::Mldsa(b) => b.clone(),
        }
    }
}

fn r1_uncompressed(k: &Secp256r1KeyPair) -> Vec<u8> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    k.public().pubkey.as_affine().to_encoded_point(false).as_bytes().to_vec()
}

fn k1_uncompressed(k: &Secp256k1KeyPair) -> Vec<u8> {
    k.public().pubkey.serialize_uncompressed().to_vec()
}

const CDJ_ORIGIN: &str = "https://www.sui.io";

/// clientDataJSON shapes around a challenge string `c` (WebAuthn, serde_json edge cases).
fn cdj_variants(c: &str) -> Vec<String> {
    let o = CDJ_ORIGIN;
    let mut v = vec![
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","crossOrigin":false}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}"}}"#),
        format!(" {{ \"challenge\" : \"{c}\" ,\t\"type\":\"webauthn.get\",\r\n\"origin\":\"{o}\"}}\n"),
        format!(r#"{{"type":{{"webauthn.get":null}},"challenge":"{c}","origin":"{o}"}}"#),
        format!(r#"{{"type":{{ "webauthn.get" : null }},"challenge":"{c}","origin":"{o}"}}"#),
        format!(r#"{{"type":{{"webauthn.get":0}},"challenge":"{c}","origin":"{o}"}}"#),
        format!(r#"{{"type":{{"webauthn.get":null,"x":1}},"challenge":"{c}","origin":"{o}"}}"#),
        format!(r#"{{"type":["webauthn.get"],"challenge":"{c}","origin":"{o}"}}"#),
        format!(r#"{{"type":"webauthn.create","challenge":"{c}","origin":"{o}"}}"#),
        format!(r#"{{"type":"payment.get","challenge":"{c}","origin":"{o}"}}"#),
        format!(r#"{{"type":"webauthn.Get","challenge":"{c}","origin":"{o}"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}"}}"#),
        format!(r#"{{"type":"webauthn.get","origin":"{o}"}}"#),
        format!(r#"{{"challenge":"{c}","origin":"{o}"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","crossOrigin":null}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","crossOrigin":true}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","crossOrigin":1}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","crossOrigin":false,"crossOrigin":false}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","type":"webauthn.get"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","challenge":"{c}","origin":"{o}"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","origin":"{o}"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","x":1,"x":"2"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":5}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":5,"origin":"{o}"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}",}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}"}} x"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}"}}{{}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}""#),
        format!(r#"{{"type":"webauthn.get" "challenge":"{c}","origin":"{o}"}}"#),
        format!(r#"{{"type"="webauthn.get","challenge":"{c}","origin":"{o}"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"😀"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"\ud83d"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"\ude00\ud83d"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"\ud83dA"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"😀\/\b\f\n\r\t\"\\"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"\x"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"\u12"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"\u12G4"}}"#),
        format!("{{\"type\":\"webauthn.get\",\"challenge\":\"{c}\",\"origin\":\"a\tb\"}}"),
        format!("{{\"type\":\"webauthn.get\",\"challenge\":\"{c}\",\"origin\":\"a\u{1}b\"}}"),
        format!("{{\"type\":\"webauthn.get\",\"challenge\":\"{c}\",\"origin\":\"a\u{7f}b\"}}"),
        format!("{{\"type\":\"webauthn.get\",\"challenge\":\"{c}\",\"origin\":\"h\u{e9}\u{1F600}\"}}"),
        format!("\u{feff}{{\"type\":\"webauthn.get\",\"challenge\":\"{c}\",\"origin\":\"{o}\"}}"),
        format!("{{\"type\":\"webauthn.get\",\"challenge\":\"{c}\",\"origin\":\"{o}\"}}\u{c}"),
        format!("{{\"type\":\"webauthn.get\",\"challenge\":\"{c}\",\"origin\":\"{o}\"}}\u{a0}"),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","x":"\u0000"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","x":[[[[1]]]],"y":{{"a":{{"b":null}}}},"z":[]}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","x":[1,]}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","x":{{"a":1,}}}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","x":{{1:2}}}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","x":true,"y":false,"z":null}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","x":tru}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","x":nul}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","x":True}}"#),
        String::new(),
        "{}".into(),
        "[]".into(),
        "null".into(),
        format!(r#"["webauthn.get","{c}","{o}",false]"#),
        format!(r#"{{"Type":"webauthn.get","challenge":"{c}","origin":"{o}"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}=","origin":"{o}"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}A","origin":"{o}"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{c}AA","origin":"{o}"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{}","origin":"{o}"}}"#, &c[..c.len() - 1]),
        format!(r#"{{"type":"webauthn.get","challenge":"{}","origin":"{o}"}}"#, &c[1..]),
        format!(r#"{{"type":"webauthn.get","challenge":" {c}","origin":"{o}"}}"#),
        format!(r#"{{"type":"webauthn.get","challenge":"{}","origin":"{o}"}}"#, c.replace('-', "+").replace('_', "/")),
        format!(r#"{{"type":"webauthn.get","challenge":"\u{:04x}{}","origin":"{o}"}}"#, c.as_bytes()[0], &c[1..]),
        format!(r#"{{"type":"webauthn.get","challenge":"{}\/","origin":"{o}"}}"#, &c[..c.len() - 1]),
    ];
    // nesting around serde_json's recursion limit (128)
    for depth in [126usize, 127, 128, 129] {
        let mut x = String::new();
        for _ in 0..depth {
            x.push('[');
        }
        for _ in 0..depth {
            x.push(']');
        }
        v.push(format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","x":{x}}}"#));
        let mut y = String::new();
        for _ in 0..depth {
            y.push_str("{\"a\":");
        }
        y.push('1');
        for _ in 0..depth {
            y.push('}');
        }
        v.push(format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","y":{y}}}"#));
    }
    // numbers (serde_json grammar, overflow to f64 and infinity)
    let zeros400 = "0".repeat(400);
    let digits = "123456789".repeat(40);
    for n in [
        "0", "-0", "01", "-01", "1.", ".5", "1e", "1e+", "1E+5", "1e-5", "-", "+1", "1.5e308", "1.7976931348623157e308", "1.7976931348623159e308",
        "1.8e308", "-1.8e308", "1e309", "1e-400", "2.4703282292062328e-324", "4.9e-324", "18446744073709551615", "18446744073709551616",
        "-9223372036854775808", "-9223372036854775809", "123456789e300", "0.000001e314", "1e00000000000000000000000000000308",
        "1e-0000000000000000000000000000000400", "0x10", "NaN", "Infinity", "-Infinity", "1_000",
    ] {
        v.push(format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","n":{n}}}"#));
    }
    for n in [format!("1{zeros400}"), format!("-1{zeros400}"), format!("0.{zeros400}1"), format!("1{zeros400}e-300"), format!("{digits}"), format!("{digits}.{digits}e-200"), format!("0.{digits}e310")] {
        v.push(format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{o}","n":{n}}}"#));
    }
    v
}

fn passkey_sig(kp: &Secp256r1KeyPair, digest: &[u8; 32], cdj: &str, ad: &[u8], user_sig_override: Option<Vec<u8>>) -> Vec<u8> {
    let mut msg = ad.to_vec();
    msg.extend_from_slice(&<Sha256 as fastcrypto::hash::HashFunction<32>>::digest(cdj.as_bytes()).digest);
    let sig: Secp256r1Signature = Signer::sign(kp, &msg);
    let user_sig = user_sig_override.unwrap_or_else(|| {
        let mut u = vec![2u8];
        u.extend_from_slice(sig.as_ref());
        u.extend_from_slice(kp.public().as_ref());
        u
    });
    let _ = digest;
    let mut out = vec![6u8];
    bcs_bytes(&mut out, ad);
    bcs_bytes(&mut out, cdj.as_bytes());
    bcs_bytes(&mut out, &user_sig);
    out
}

fn blake(b: &[u8]) -> [u8; 32] {
    <fastcrypto::hash::Blake2b256 as fastcrypto::hash::HashFunction<32>>::digest(b).digest
}

fn flag_set(rng: &mut ChaCha20Rng) -> (VerifyParams, Value) {
    let pk = rng.gen_bool(0.7);
    let amc = rng.gen_bool(0.6);
    let vzk = rng.gen_bool(0.6);
    let zk = rng.gen_bool(0.5);
    let p = VerifyParams {
        accept_passkey_in_multisig: pk,
        additional_multisig_checks: amc,
        validate_zklogin_public_identifier: vzk,
        accept_zklogin_in_multisig: zk,
        accept_mldsa65_in_multisig: false,
        ..params_for(1)
    };
    let f = json!({
        "accept_zklogin_in_multisig": zk,
        "accept_passkey_in_multisig": pk,
        "accept_mldsa65_in_multisig": false,
        "additional_multisig_checks": amc,
        "validate_zklogin_public_identifier": vzk,
        "verify_legacy_zklogin_address": p.verify_legacy_zklogin_address,
    });
    (p, f)
}

struct UserOut<'a> {
    lines: &'a mut Vec<Value>,
    n: usize,
}

impl UserOut<'_> {
    fn emit(&mut self, kind: &str, sig: &[u8], intent: &[u8], author: SuiAddress, prm: &VerifyParams, flags: &Value) {
        let (v, addr) = check_sig(sig, intent, author, 0, prm);
        self.lines.push(json!({
            "id": format!("user/{kind}/{}", self.n), "op": "user_sig", "flags": flags,
            "msg": h(intent), "sig": h(sig), "author": h(author.as_ref()), "v": v, "addr": addr,
        }));
        self.n += 1;
    }

    /// The case itself, then seeded mutations: byte flips past the flag, truncation, extension,
    /// and a wrong author.
    fn emit_mutated(&mut self, rng: &mut ChaCha20Rng, kind: &str, sig: &[u8], intent: &[u8], author: SuiAddress, prm: &VerifyParams, flags: &Value, n: usize) {
        self.emit(kind, sig, intent, author, prm, flags);
        for k in 0..n {
            let mut s = sig.to_vec();
            match k % 6 {
                0 | 1 | 2 => {
                    if s.len() > 1 {
                        let off = rng.gen_range(1..s.len());
                        s[off] ^= 1 << rng.gen_range(0..8);
                    }
                }
                3 => {
                    let l = rng.gen_range(0..s.len().max(1));
                    s.truncate(l);
                }
                4 => {
                    let extra = rng.gen_range(1..4);
                    for _ in 0..extra {
                        s.push(rng.r#gen());
                    }
                }
                _ => {
                    let mut a = author.to_inner();
                    a[rng.gen_range(0..32)] ^= 1 << rng.gen_range(0..8);
                    self.emit(&format!("{kind}-author"), &s, intent, SuiAddress::from_bytes(a).unwrap(), prm, flags);
                    continue;
                }
            }
            self.emit(&format!("{kind}-mut"), &s, intent, author, prm, flags);
        }
    }
}

fn author_of(sig: &[u8]) -> Option<SuiAddress> {
    let g = <GenericSignature as ToFromBytes>::from_bytes(sig).ok()?;
    SuiAddress::try_from(&g).ok()
}

fn rand_intent(rng: &mut ChaCha20Rng) -> Vec<u8> {
    let mut v = vec![0u8, 0, 0];
    let n = rng.gen_range(1..200);
    for _ in 0..n {
        v.push(rng.r#gen());
    }
    v
}

fn new_member(rng: &mut ChaCha20Rng, kind: u32) -> Member {
    match kind {
        0 => Member::Ed(gen_kp::<Ed25519KeyPair>(rng)),
        1 => Member::K1(gen_kp::<Secp256k1KeyPair>(rng)),
        2 => Member::R1(gen_kp::<Secp256r1KeyPair>(rng)),
        3 => Member::Passkey(gen_kp::<Secp256r1KeyPair>(rng)),
        4 => {
            // ZkLoginPublicIdentifier: iss_len || iss || address seed (sometimes malformed)
            let iss = ["https://accounts.google.com", "https://id.twitch.tv/oauth2", "x"][rng.gen_range(0..3)];
            let mut b = vec![iss.len() as u8];
            b.extend_from_slice(iss.as_bytes());
            let seed_len = [32usize, 31, 1, 33][rng.gen_range(0..4)];
            for _ in 0..seed_len {
                b.push(rng.r#gen());
            }
            match rng.gen_range(0..6) {
                0 => b[0] = b[0].wrapping_add(40),
                1 => b[1] = 0xff,
                2 => b.truncate(1),
                _ => {}
            }
            Member::ZkLogin(b)
        }
        _ => {
            let mut b = vec![0u8; 1952];
            rng.fill_bytes(&mut b);
            Member::Mldsa(b)
        }
    }
}

/// A member signature as a CompressedSignature (tag + payload bytes) over `digest`.
fn member_sig(rng: &mut ChaCha20Rng, m: &Member, digest: &[u8; 32], intent: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match m {
        Member::Ed(k) => {
            uleb(&mut out, 0);
            out.extend_from_slice(ed_sign(k, digest).as_ref());
        }
        Member::K1(k) => {
            uleb(&mut out, 1);
            let s: Secp256k1Signature = Signer::sign(k, digest);
            out.extend_from_slice(s.as_ref());
        }
        Member::R1(k) => {
            uleb(&mut out, 2);
            let s: Secp256r1Signature = Signer::sign(k, digest);
            out.extend_from_slice(s.as_ref());
        }
        Member::Passkey(k) => {
            uleb(&mut out, 4);
            let cdj = format!(r#"{{"type":"webauthn.get","challenge":"{}","origin":"{CDJ_ORIGIN}","crossOrigin":false}}"#, b64url(digest));
            let mut ad = vec![0u8; 37];
            rng.fill_bytes(&mut ad);
            bcs_bytes(&mut out, &passkey_sig(k, digest, &cdj, &ad, None));
        }
        _ => return None,
    }
    let _ = intent;
    Some(out)
}

fn ms_pk_bytes(members: &[Member], weights: &[u8], threshold: u16) -> Vec<u8> {
    let mut out = Vec::new();
    uleb(&mut out, members.len() as u64);
    for (m, w) in members.iter().zip(weights) {
        uleb(&mut out, m.tag() as u64);
        match m {
            Member::ZkLogin(b) => bcs_bytes(&mut out, b),
            _ => out.extend_from_slice(&m.pk()),
        }
        out.push(*w);
    }
    out.extend_from_slice(&threshold.to_le_bytes());
    out
}

fn ms_address(members: &[Member], weights: &[u8], threshold: u16) -> SuiAddress {
    let mut b = vec![3u8];
    b.extend_from_slice(&threshold.to_le_bytes());
    for (m, w) in members.iter().zip(weights) {
        b.push(m.flag());
        b.extend_from_slice(&m.pk());
        b.push(*w);
    }
    SuiAddress::from_bytes(blake(&b)).unwrap()
}

fn legacy_pk_string(rng: &mut ChaCha20Rng, m: &Member, deviate: bool) -> String {
    let mut raw = vec![m.flag()];
    let form = rng.gen_range(0..if deviate { 10 } else { 30 });
    match m {
        Member::K1(k) if form < 3 => {
            let mut u = k1_uncompressed(k);
            if form == 1 {
                u[0] = 6 + (u[64] & 1);
            } else if form == 2 {
                u[0] = 7 - (u[64] & 1);
            }
            raw.extend_from_slice(&u);
        }
        Member::R1(k) | Member::Passkey(k) if form < 2 => raw.extend_from_slice(&r1_uncompressed(k)),
        Member::R1(k) | Member::Passkey(k) if form == 2 => {
            let mut c = k.public().as_ref().to_vec();
            c[0] = 5;
            raw.extend_from_slice(&c);
        }
        _ => raw.extend_from_slice(&m.pk()),
    }
    let mut s = b64std(&raw);
    match rng.gen_range(0..if deviate { 6 } else { 1000 }) {
        0 => {
            // non-canonical trailing bits when there is padding
            if s.ends_with('=') {
                let i = s.trim_end_matches('=').len() - 1;
                let c = s.as_bytes()[i];
                let alt = if c == b'A' { 'B' } else { 'A' };
                s.replace_range(i..i + 1, &alt.to_string());
            }
        }
        1 => {
            s = s.trim_end_matches('=').to_string();
        }
        2 => s.push('='),
        3 => s = s.replace('+', "-").replace('/', "_"),
        _ => {}
    }
    s
}

/// Hand-made roaring bitmaps for indices `idx` (various container forms, and malformed ones).
fn roaring_bytes(rng: &mut ChaCha20Rng, idx: &[u32], deviate: bool) -> Vec<u8> {
    let mut rb = roaring::RoaringBitmap::new();
    for i in idx {
        rb.insert(*i);
    }
    let form = if deviate { rng.gen_range(0..10) } else { [0, 1, 10][rng.gen_range(0..3)] };
    let mut out = Vec::new();
    match form {
        0 | 1 => {
            rb.optimize();
            rb.serialize_into(&mut out).unwrap();
        }
        2 => {
            // array container with a duplicate or out of order value
            let mut vals: Vec<u16> = idx.iter().map(|x| *x as u16).collect();
            if vals.is_empty() {
                vals.push(0);
            }
            vals.push(vals[0]);
            out.extend_from_slice(&12346u32.to_le_bytes());
            out.extend_from_slice(&1u32.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&((vals.len() - 1) as u16).to_le_bytes());
            out.extend_from_slice(&8u32.to_le_bytes());
            for v in vals {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
        3 => {
            // a value >= 10, or a second container
            let mut r2 = rb.clone();
            r2.insert([10u32, 11, 15, 65536, 70000][rng.gen_range(0..5)]);
            r2.serialize_into(&mut out).unwrap();
        }
        4 => {
            // run container with too many values (cardinality > 150) or touching runs
            out.extend_from_slice(&(12347u32).to_le_bytes());
            out.push(1);
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            let (s1, l1, s2, l2) = [(0u16, 200u16, 300u16, 1u16), (0, 1, 2, 1), (0, 1, 3, 1), (5, 0, 1, 1), (0, 9, 20, 0)][rng.gen_range(0..5)];
            out.extend_from_slice(&2u16.to_le_bytes());
            for v in [s1, l1, s2, l2] {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
        5 => {
            rb.serialize_into(&mut out).unwrap();
            for _ in 0..rng.gen_range(1..5) {
                out.push(rng.r#gen());
            }
        }
        6 => {
            rb.serialize_into(&mut out).unwrap();
            let l = rng.gen_range(0..out.len());
            out.truncate(l);
        }
        7 => {
            // empty bitmap, or a bogus cookie
            if rng.gen_bool(0.5) {
                roaring::RoaringBitmap::new().serialize_into(&mut out).unwrap();
            } else {
                out.extend_from_slice(&12345u32.to_le_bytes());
            }
        }
        8 => {
            // run container with a single run [0, 9]: indices 0..9
            out.extend_from_slice(&(12347u32).to_le_bytes());
            out.push(1);
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&1u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&((rng.gen_range(0..12)) as u16).to_le_bytes());
        }
        9 => {
            // run cookie with offsets (>= 4 containers): keys 0..3
            let mut r2 = rb.clone();
            for k in 1..4u32 {
                r2.insert(k << 16);
            }
            r2.optimize();
            r2.serialize_into(&mut out).unwrap();
        }
        _ => rb.serialize_into(&mut out).unwrap(),
    }
    out
}

fn cmd_uservec(args: &[String]) -> Result<()> {
    let [out_path] = args else { bail!("uservec <out.jsonl>") };
    let mut rng = ChaCha20Rng::seed_from_u64(0x7a75_692d_7573_6572); // "zui-user"
    let mut lines = Vec::new();
    let mut out = UserOut { lines: &mut lines, n: 0 };

    // 1. single keys: every flag, lengths, r1 compact keys, high s, MLDSA65 shape
    for i in 0..600 {
        let (prm, flags) = flag_set(&mut rng);
        let intent = rand_intent(&mut rng);
        let d = blake(&intent);
        let mut sig = Vec::new();
        match i % 6 {
            0 => {
                let k = gen_kp::<Ed25519KeyPair>(&mut rng);
                sig.push(0);
                sig.extend_from_slice(ed_sign(&k, &d).as_ref());
                sig.extend_from_slice(k.public().as_ref());
            }
            1 => {
                let k = gen_kp::<Secp256k1KeyPair>(&mut rng);
                let s: Secp256k1Signature = Signer::sign(&k, &d);
                sig.push(1);
                sig.extend_from_slice(s.as_ref());
                sig.extend_from_slice(k.public().as_ref());
            }
            2 | 3 => {
                let k = gen_kp::<Secp256r1KeyPair>(&mut rng);
                let s: Secp256r1Signature = Signer::sign(&k, &d);
                sig.push(2);
                sig.extend_from_slice(s.as_ref());
                let mut pk = k.public().as_ref().to_vec();
                if i % 6 == 3 {
                    pk[0] = 5; // compact form: the key is right only when y is the smaller root
                }
                sig.extend_from_slice(&pk);
            }
            4 => {
                // high-s r1 / k1 (n - s)
                let k1 = rng.gen_bool(0.5);
                let n = if k1 { arr("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141") } else { arr("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551") };
                let (mut s, pk) = if k1 {
                    let k = gen_kp::<Secp256k1KeyPair>(&mut rng);
                    let s: Secp256k1Signature = Signer::sign(&k, &d);
                    (s.as_ref().to_vec(), k.public().as_ref().to_vec())
                } else {
                    let k = gen_kp::<Secp256r1KeyPair>(&mut rng);
                    let s: Secp256r1Signature = Signer::sign(&k, &d);
                    (s.as_ref().to_vec(), k.public().as_ref().to_vec())
                };
                let hs = be_sub(&n, s[32..64].try_into().unwrap());
                s[32..64].copy_from_slice(&hs);
                sig.push(if k1 { 1 } else { 2 });
                sig.extend_from_slice(&s);
                sig.extend_from_slice(&pk);
            }
            _ => {
                // other flags and lengths
                let f = [4u8, 7, 8, 0xff, 0, 1, 2, 7][rng.gen_range(0..8)];
                sig.push(f);
                let len = [0usize, 1, 95, 96, 97, 3309 + 1952, 3309 + 1952 + 1][rng.gen_range(0..7)];
                for _ in 0..len {
                    sig.push(rng.r#gen());
                }
            }
        }
        let author = author_of(&sig).unwrap_or_else(|| SuiAddress::from_bytes(blake(&sig)).unwrap());
        out.emit_mutated(&mut rng, "single", &sig, &intent, author, &prm, &flags, 4);
    }

    // 2. passkey: every clientDataJSON shape, user signature schemes and key forms
    for round in 0..6 {
        let kp = gen_kp::<Secp256r1KeyPair>(&mut rng);
        let intent = rand_intent(&mut rng);
        let d = blake(&intent);
        let c = b64url(&d);
        for (vi, cdj) in cdj_variants(&c).into_iter().enumerate() {
            let (prm, flags) = flag_set(&mut rng);
            let mut ad = vec![0u8; [0usize, 37, 37, 200][rng.gen_range(0..4)]];
            rng.fill_bytes(&mut ad);
            let sig = passkey_sig(&kp, &d, &cdj, &ad, None);
            let author = SuiAddress::from_bytes(blake(&[&[6u8][..], kp.public().as_ref()].concat())).unwrap();
            let n = if round == 0 && vi < 3 { 12 } else { 0 };
            out.emit_mutated(&mut rng, "passkey", &sig, &intent, author, &prm, &flags, n);
        }
        // user signature variants on a valid clientDataJSON
        let cdj = format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"{CDJ_ORIGIN}"}}"#);
        let mut msg = vec![1u8; 37];
        msg.extend_from_slice(&<Sha256 as fastcrypto::hash::HashFunction<32>>::digest(cdj.as_bytes()).digest);
        let good: Secp256r1Signature = Signer::sign(&kp, &msg);
        let n = arr("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        let mut variants: Vec<Vec<u8>> = Vec::new();
        let base = [&[2u8][..], good.as_ref(), kp.public().as_ref()].concat();
        variants.push(base.clone());
        let mut compact = base.clone();
        compact[65] = 5;
        variants.push(compact);
        let mut high = base.clone();
        let hs = be_sub(&n, high[33..65].try_into().unwrap());
        high[33..65].copy_from_slice(&hs);
        variants.push(high);
        let mut zero_r = base.clone();
        zero_r[1..33].fill(0);
        variants.push(zero_r);
        let mut big_s = base.clone();
        big_s[33..65].copy_from_slice(&n);
        variants.push(big_s);
        let mut bad_pk = base.clone();
        bad_pk[66..98].fill(0xff);
        variants.push(bad_pk);
        let mut flag0 = base.clone();
        flag0[0] = 0;
        variants.push(flag0);
        let mut flag1 = base.clone();
        flag1[0] = 1;
        variants.push(flag1);
        let ek = gen_kp::<Ed25519KeyPair>(&mut rng);
        variants.push([&[0u8][..], ed_sign(&ek, &msg).as_ref(), ek.public().as_ref()].concat());
        let mut short = base.clone();
        short.pop();
        variants.push(short);
        variants.push(vec![6u8; 98]);
        variants.push(Vec::new());
        for us in variants {
            let (prm, flags) = flag_set(&mut rng);
            let sig = passkey_sig(&kp, &d, &cdj, &[1u8; 37], Some(us));
            let author = SuiAddress::from_bytes(blake(&[&[6u8][..], kp.public().as_ref()].concat())).unwrap();
            out.emit(&format!("passkey-us{round}"), &sig, &intent, author, &prm, &flags);
        }
    }

    // 3. MultiSig and MultiSigLegacy
    for i in 0..3000 {
        let (prm, flags) = flag_set(&mut rng);
        let intent = rand_intent(&mut rng);
        let d = blake(&intent);
        let legacy = i % 3 == 2;
        let nm = match rng.gen_range(0..20) {
            0 => 0,
            1 => 11,
            _ => rng.gen_range(1..=10),
        };
        let mut members: Vec<Member> = Vec::new();
        for _ in 0..nm {
            let r = rng.gen_range(0..100);
            let mut kind = if r < 30 { 0 } else if r < 50 { 1 } else if r < 70 { 2 } else if r < 85 { 3 } else if r < 97 { 4 } else { 5 };
            if legacy && kind >= 4 && rng.gen_bool(0.9) {
                kind = 0; // a legacy zkLogin key never decodes; keep most legacy cases decodable
            }
            members.push(new_member(&mut rng, kind));
        }
        if nm >= 2 && rng.gen_bool(0.05) {
            let a = rng.gen_range(0..nm);
            let b = rng.gen_range(0..nm);
            members[b] = members[a].clone();
        }
        // a zkLogin member that is really an ed25519 key (32 bytes), signing as ed25519
        let mut fake_zk: Option<(usize, Ed25519KeyPair)> = None;
        if nm >= 1 && rng.gen_bool(0.05) {
            let k = gen_kp::<Ed25519KeyPair>(&mut rng);
            let at = rng.gen_range(0..nm);
            members[at] = Member::ZkLogin(k.public().as_ref().to_vec());
            fake_zk = Some((at, k));
        }
        let mut weights: Vec<u8> = (0..nm).map(|_| [1u8, 1, 1, 2, 3, 255][rng.gen_range(0..6)]).collect();
        if nm > 0 && rng.gen_bool(0.03) {
            let at = rng.gen_range(0..nm);
            weights[at] = 0;
        }
        let sum: u32 = weights.iter().map(|w| *w as u32).sum();
        let threshold: u16 = match rng.gen_range(0..20) {
            0 => 0,
            1 => (sum + 1).min(65535) as u16,
            _ => rng.gen_range(1..=sum.max(1)).min(65535) as u16,
        };
        // signers: a subset of signable members in index order
        let mut idx: Vec<u32> = Vec::new();
        let mut sigs: Vec<Vec<u8>> = Vec::new();
        for (j, m) in members.iter().enumerate() {
            if !rng.gen_bool(0.6) {
                continue;
            }
            if let Some((at, k)) = &fake_zk {
                if *at == j {
                    let mut s = Vec::new();
                    uleb(&mut s, 0);
                    s.extend_from_slice(ed_sign(k, &d).as_ref());
                    idx.push(j as u32);
                    sigs.push(s);
                    continue;
                }
            }
            if let Some(s) = member_sig(&mut rng, m, &d, &intent) {
                idx.push(j as u32);
                sigs.push(s);
            }
        }
        match rng.gen_range(0..25) {
            0 if sigs.len() >= 2 => sigs.swap(0, 1),
            1 if !sigs.is_empty() => {
                // signature kind that does not match its key
                let k = gen_kp::<Secp256k1KeyPair>(&mut rng);
                let s: Secp256k1Signature = Signer::sign(&k, &d);
                let mut b = Vec::new();
                uleb(&mut b, [0u64, 1, 2][rng.gen_range(0..3)]);
                b.extend_from_slice(s.as_ref());
                sigs[0] = b;
            }
            2 => {
                // a zkLogin or MLDSA65 member signature (bytes only)
                let mut b = Vec::new();
                if rng.gen_bool(0.5) {
                    uleb(&mut b, 3);
                    let mut z = vec![0u8; rng.gen_range(0..40)];
                    rng.fill_bytes(&mut z);
                    if !z.is_empty() {
                        z[0] = if rng.gen_bool(0.5) { 4 } else { 6 };
                    }
                    bcs_bytes(&mut b, &z);
                } else {
                    uleb(&mut b, 5);
                    let mut z = vec![0u8; 3309];
                    rng.fill_bytes(&mut z);
                    b.extend_from_slice(&z);
                }
                sigs.push(b);
                idx.push(rng.gen_range(0..10));
            }
            3 => sigs.clear(),
            _ => {}
        }
        let mut bitmap: u16 = idx.iter().fold(0u16, |a, i| a | (1 << (*i).min(15)));
        match rng.gen_range(0..20) {
            0 => bitmap |= 1 << rng.gen_range(0..10),
            1 => bitmap &= !(1 << rng.gen_range(0..10)),
            2 => bitmap |= 1 << rng.gen_range(10..16),
            _ => {}
        }
        let mut body = Vec::new();
        uleb(&mut body, sigs.len() as u64);
        for s in &sigs {
            body.extend_from_slice(s);
        }
        if legacy {
            let mut li: Vec<u32> = (0..16).filter(|b| bitmap & (1 << b) != 0).collect();
            if rng.gen_bool(0.05) {
                li.push(rng.gen_range(10..40));
            }
            let dev = rng.gen_range(0..3);
            bcs_bytes(&mut body, &roaring_bytes(&mut rng, &li, dev == 0));
            uleb(&mut body, members.len() as u64);
            let dev_at = if dev == 1 && !members.is_empty() { rng.gen_range(0..members.len()) } else { usize::MAX };
            for (j, (m, w)) in members.iter().zip(&weights).enumerate() {
                let s = legacy_pk_string(&mut rng, m, j == dev_at);
                bcs_bytes(&mut body, s.as_bytes());
                body.push(*w);
            }
            body.extend_from_slice(&threshold.to_le_bytes());
        } else {
            body.extend_from_slice(&bitmap.to_le_bytes());
            body.extend_from_slice(&ms_pk_bytes(&members, &weights, threshold));
        }
        let mut sig = vec![3u8];
        sig.extend_from_slice(&body);
        let author = author_of(&sig).unwrap_or_else(|| ms_address(&members, &weights, threshold));
        let n = if i % 4 == 0 { 6 } else { 0 };
        out.emit_mutated(&mut rng, if legacy { "legacy" } else { "multisig" }, &sig, &intent, author, &prm, &flags, n);
    }

    // 5. transaction level with address aliases (own seed: the cases above stay byte-identical)
    alias_vectors(&mut lines)?;

    let mut f = std::io::BufWriter::new(std::fs::File::create(out_path)?);
    for l in &lines {
        serde_json::to_writer(&mut f, l)?;
        f.write_all(b"\n")?;
    }
    f.flush()?;
    eprintln!("{} user-signature vectors -> {out_path}", lines.len());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// ecmh: fastcrypto EllipticCurveMultisetHash (the GlobalStateHasher accumulator).
//
// {"id","op":"ecmh","ops":[["i",hex]|["r",hex]|["u",[ops...]]...],"acc":hex,"digest":hex}
//   ops run in order on a fresh accumulator: insert, remove, union with an accumulator built
//   from the nested ops; acc = bcs::to_bytes(&acc) (the compressed Ristretto point).
// {"id","op":"ecmh_from_bytes","bytes":hex,"v":"ok"|"err","digest":hex|null,"acc":hex|null}
//   bcs::from_bytes::<EllipticCurveMultisetHash>, then digest and re-serialization.

fn ecmh_run(ops: &[Value]) -> fastcrypto::hash::EllipticCurveMultisetHash {
    use fastcrypto::hash::MultisetHash;
    let mut acc = fastcrypto::hash::EllipticCurveMultisetHash::default();
    for o in ops {
        let k = o[0].as_str().unwrap();
        match k {
            "i" => acc.insert(unhex(o[1].as_str().unwrap())),
            "r" => acc.remove(unhex(o[1].as_str().unwrap())),
            "u" => {
                let other = ecmh_run(o[1].as_array().unwrap());
                acc.union(&other);
            }
            _ => unreachable!(),
        }
    }
    acc
}

fn ecmh_item(rng: &mut ChaCha20Rng) -> Vec<u8> {
    let len = match rng.gen_range(0..6) {
        0 => 0,
        1 | 2 | 3 => 32, // object digests, as the state hasher inserts them
        4 => rng.gen_range(1..128),
        _ => rng.gen_range(128..600),
    };
    let mut m = vec![0u8; len];
    rng.fill_bytes(&mut m);
    m
}

fn cmd_ecmh(args: &[String]) -> Result<()> {
    use fastcrypto::hash::{EllipticCurveMultisetHash, MultisetHash};
    let [out_path] = args else { bail!("ecmh <out.jsonl>") };
    let mut rng = ChaCha20Rng::seed_from_u64(0x7a75_692d_6563_6d68); // "zui-ecmh"
    let mut out = Out { lines: Vec::new() };
    let emit = |out: &mut Out, id: String, ops: Vec<Value>| {
        let acc = ecmh_run(&ops);
        out.push(json!({ "id": id, "op": "ecmh", "ops": ops, "acc": h(&bcs::to_bytes(&acc).unwrap()),
            "digest": h(&acc.digest().digest) }));
    };
    emit(&mut out, "ecmh/empty".into(), vec![]);
    for n in 0..2000 {
        let it = ecmh_item(&mut rng);
        emit(&mut out, format!("ecmh/one/{n}"), vec![json!(["i", h(&it)])]);
    }
    for n in 0..300 {
        let it = ecmh_item(&mut rng);
        emit(&mut out, format!("ecmh/remove-only/{n}"), vec![json!(["r", h(&it)])]);
    }
    for n in 0..3000 {
        let pool: Vec<Vec<u8>> = (0..rng.gen_range(1..12)).map(|_| ecmh_item(&mut rng)).collect();
        let mut ops = Vec::new();
        for _ in 0..rng.gen_range(1..40) {
            let it = &pool[rng.gen_range(0..pool.len())];
            match rng.gen_range(0..10) {
                0..=5 => ops.push(json!(["i", h(it)])),
                6..=8 => ops.push(json!(["r", h(it)])),
                _ => {
                    let sub: Vec<Value> = (0..rng.gen_range(0..6))
                        .map(|_| {
                            let x = &pool[rng.gen_range(0..pool.len())];
                            if rng.gen_bool(0.7) { json!(["i", h(x)]) } else { json!(["r", h(x)]) }
                        })
                        .collect();
                    ops.push(json!(["u", sub]));
                }
            }
        }
        emit(&mut out, format!("ecmh/seq/{n}"), ops);
    }
    // insert then remove everything: back to the identity
    for n in 0..50 {
        let items: Vec<Vec<u8>> = (0..rng.gen_range(1..20)).map(|_| ecmh_item(&mut rng)).collect();
        let mut ops: Vec<Value> = items.iter().map(|x| json!(["i", h(x)])).collect();
        ops.extend(items.iter().rev().map(|x| json!(["r", h(x)])));
        emit(&mut out, format!("ecmh/cancel/{n}"), ops);
    }
    // deserialization: valid accumulators, random bytes, and encoding edges
    let mut cands: Vec<(String, Vec<u8>)> = Vec::new();
    for n in 0..500 {
        let mut a = EllipticCurveMultisetHash::default();
        a.insert(ecmh_item(&mut rng));
        let b = bcs::to_bytes(&a).unwrap();
        cands.push((format!("ecmh/bytes/valid/{n}"), b.clone()));
        let mut f = b.clone();
        flip(&mut rng, &mut f);
        cands.push((format!("ecmh/bytes/flip/{n}"), f));
    }
    for n in 0..1000 {
        let mut b = vec![0u8; 32];
        rng.fill_bytes(&mut b);
        if n % 2 == 0 {
            b[0] &= 0xfe; // nonnegative s
            b[31] &= 0x7f;
        }
        cands.push((format!("ecmh/bytes/random/{n}"), b));
    }
    let p: [u8; 32] = {
        let mut x = [0xffu8; 32];
        x[0] = 0xed;
        x[31] = 0x7f;
        x
    };
    let mut edges: Vec<Vec<u8>> = vec![vec![0u8; 32], p.to_vec()];
    for d in 0..40u8 {
        let mut x = p;
        x[0] = x[0].wrapping_add(d); // p + d (non-canonical) and around it
        edges.push(x.to_vec());
        let mut y = [0u8; 32];
        y[0] = d;
        edges.push(y.to_vec());
        let mut z = [0xffu8; 32];
        z[0] = d;
        edges.push(z.to_vec());
    }
    edges.push(vec![0u8; 31]);
    edges.push(vec![0u8; 33]);
    edges.push(vec![]);
    for (i, e) in edges.into_iter().enumerate() {
        cands.push((format!("ecmh/bytes/edge/{i}"), e));
    }
    for (id, b) in cands {
        let r = bcs::from_bytes::<EllipticCurveMultisetHash>(&b);
        let line = match r {
            Ok(a) => json!({ "id": id, "op": "ecmh_from_bytes", "bytes": h(&b), "v": "ok",
                "digest": h(&a.digest().digest), "acc": h(&bcs::to_bytes(&a).unwrap()) }),
            Err(_) => json!({ "id": id, "op": "ecmh_from_bytes", "bytes": h(&b), "v": "err", "digest": null, "acc": null }),
        };
        out.push(line);
    }
    let mut f = std::io::BufWriter::new(std::fs::File::create(out_path)?);
    for l in &out.lines {
        serde_json::to_writer(&mut f, l)?;
        f.write_all(b"\n")?;
    }
    eprintln!("ecmh: {} vectors", out.lines.len());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// ecvrf: fastcrypto vrf::ecvrf (ristretto255, "sui_vrf"), as the sui::ecvrf native uses it.
//
// {"id","op":"ecvrf_prove","sk":hex,"alpha":hex,"pk":hex,"proof":hex,"output":hex}
//   sk = bcs ECVRFPrivateKey (canonical scalar); pk, proof = bcs of the key pair's key and of
//   kp.output(alpha)'s proof; output = the 64-byte VRF output.
// {"id","op":"ecvrf_verify","hash":hex,"alpha":hex,"pk":hex,"proof":hex,"v":...}
//   exactly the native's sequence: hash must be 64 bytes ("err:hash"), bcs::from_bytes of the
//   key ("err:pk") and of the proof ("err:proof"), then proof.verify_output: "true" / "false".

fn ecvrf_native(hash: &[u8], alpha: &[u8], pk: &[u8], proof: &[u8]) -> &'static str {
    use fastcrypto::vrf::VRFProof;
    use fastcrypto::vrf::ecvrf::{ECVRFProof, ECVRFPublicKey};
    let Ok(hb): Result<[u8; 64], _> = hash.try_into() else { return "err:hash" };
    let Ok(pk) = bcs::from_bytes::<ECVRFPublicKey>(pk) else { return "err:pk" };
    let Ok(pf) = bcs::from_bytes::<ECVRFProof>(proof) else { return "err:proof" };
    if pf.verify_output(alpha, &pk, &hb).is_ok() { "true" } else { "false" }
}

fn cmd_ecvrf(args: &[String]) -> Result<()> {
    use fastcrypto::vrf::VRFKeyPair;
    use fastcrypto::vrf::ecvrf::{ECVRFKeyPair, ECVRFPrivateKey};
    let [out_path] = args else { bail!("ecvrf <out.jsonl>") };
    let mut rng = ChaCha20Rng::seed_from_u64(0x7a75_692d_7672_6631); // "zui-vrf1"
    let mut out = Out { lines: Vec::new() };
    let mut good: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new(); // hash, alpha, pk, proof
    for n in 0..1500 {
        // a canonical scalar: 32 random bytes with the top 4 bits cleared, rejection on >= l
        let sk_bytes = loop {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            if n % 7 == 0 {
                b[31] &= 0x0f;
            } else {
                b[31] &= 0x1f;
            }
            if bcs::from_bytes::<ECVRFPrivateKey>(&b).is_ok() {
                break b;
            }
        };
        let sk = bcs::from_bytes::<ECVRFPrivateKey>(&sk_bytes).unwrap();
        let kp = ECVRFKeyPair::from(sk);
        let alpha = rand_msg(&mut rng);
        let (output, proof) = kp.output(&alpha);
        let pk = bcs::to_bytes(&kp.pk).unwrap();
        let pf = bcs::to_bytes(&proof).unwrap();
        out.push(json!({ "id": format!("ecvrf/prove/{n}"), "op": "ecvrf_prove", "sk": h(&sk_bytes), "alpha": h(&alpha),
            "pk": h(&pk), "proof": h(&pf), "output": h(&output) }));
        good.push((output.to_vec(), alpha, pk, pf));
    }
    let mut cases: Vec<(String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    for (n, (hh, a, pk, pf)) in good.iter().enumerate() {
        cases.push((format!("ecvrf/verify/ok/{n}"), hh.clone(), a.clone(), pk.clone(), pf.clone()));
        let (mut hh2, mut a2, mut pk2, mut pf2) = (hh.clone(), a.clone(), pk.clone(), pf.clone());
        let kind = match n % 10 {
            0 | 1 => { flip(&mut rng, &mut pf2); "proof-flip" }
            2 => { flip(&mut rng, &mut pk2); "pk-flip" }
            3 => { flip(&mut rng, &mut hh2); "hash-flip" }
            4 => { a2.push(rng.r#gen()); "alpha-ext" }
            5 => { let j = rng.gen_range(0..good.len()); pk2 = good[j].2.clone(); "other-pk" }
            6 => {
                // s + l (non-canonical scalar) or a top-bit s
                let i = 48 + rng.gen_range(0..32);
                pf2[i] = pf2[i].wrapping_add(rng.gen_range(1..255));
                "s-byte"
            }
            7 => { let l = rng.gen_range(0..pf2.len()); pf2.truncate(l); "proof-trunc" }
            8 => { pf2.push(0); "proof-trailing" }
            _ => { hh2.truncate(rng.gen_range(0..64)); "hash-len" }
        };
        cases.push((format!("ecvrf/verify/{kind}/{n}"), hh2, a2, pk2, pf2));
    }
    // identity key (valid encoding, rejected by verify), zero proofs, edge encodings
    let (hh, a, _pk, pf) = good[0].clone();
    cases.push(("ecvrf/verify/identity-pk".into(), hh.clone(), a.clone(), vec![0u8; 32], pf.clone()));
    cases.push(("ecvrf/verify/zero-proof".into(), hh.clone(), a.clone(), good[0].2.clone(), vec![0u8; 80]));
    cases.push(("ecvrf/verify/pk-short".into(), hh.clone(), a.clone(), vec![0u8; 31], pf.clone()));
    cases.push(("ecvrf/verify/pk-long".into(), hh.clone(), a.clone(), [good[0].2.clone(), vec![0]].concat(), pf.clone()));
    for (id, hh, a, pk, pf) in cases {
        let v = ecvrf_native(&hh, &a, &pk, &pf);
        out.push(json!({ "id": id, "op": "ecvrf_verify", "hash": h(&hh), "alpha": h(&a), "pk": h(&pk), "proof": h(&pf), "v": v }));
    }
    let mut f = std::io::BufWriter::new(std::fs::File::create(out_path)?);
    for l in &out.lines {
        serde_json::to_writer(&mut f, l)?;
        f.write_all(b"\n")?;
    }
    eprintln!("ecvrf: {} vectors", out.lines.len());
    Ok(())
}

/// Survey: alias versions recorded in CheckpointContentsV2 and zkLogin transactions.
fn cmd_scan(args: &[String]) -> Result<()> {
    let corpus = PathBuf::from(&args[0]);
    let mut seqs: Vec<u64> = std::fs::read_dir(corpus.join("chk"))?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_suffix(".chk")).and_then(|n| n.parse().ok()))
        .collect();
    seqs.sort();
    let out: Vec<String> = seqs
        .par_iter()
        .map(|seq| -> Result<Vec<String>> {
            let raw = std::fs::read(corpus.join(format!("chk/{seq}.chk")))?;
            let cp: CheckpointData = bcs::from_bytes(&raw[1..])?;
            let mut v = Vec::new();
            for (i, tx) in cp.transactions.iter().enumerate() {
                let sigs = cp.checkpoint_contents.inner().user_signatures(i).unwrap_or_default();
                let signers = tx.transaction.data().intent_message().value.required_signers();
                for (k, (_, ver)) in sigs.iter().enumerate() {
                    if let Some(ver) = ver {
                        let s = signers.get(k).copied();
                        let id = s.map(|s| sui_types::address_alias::address_aliases_object_id(s).unwrap());
                        let mut found = None;
                        for o in cp.transactions.iter().flat_map(|t| t.output_objects.iter().chain(t.input_objects.iter())) {
                            if Some(o.id()) == id && o.version() == *ver { found = Some(o.digest()); }
                        }
                        v.push(format!("alias seq={seq} tx={i} k={k} signer={:?} ver={} obj={:?} in_corpus={}", s, ver.value(), id, found.is_some()));
                    }
                }
                if tx.transaction.data().tx_signatures().iter().any(has_zklogin) {
                    v.push(format!("zk seq={seq} tx={i}"));
                }
            }
            Ok(v)
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    for l in out { println!("{l}"); }
    Ok(())
}

/// `verify_sender_signed_data_message_signatures` with aliases over synthesized transactions:
/// sender (and sometimes a sponsor), an alias set for some signers, signatures from a key pool
/// (some over the wrong message, sometimes one too many or too few).
/// Line: {"id","op":"user_tx","flags","msg":<Intent ++ BCS(TransactionData)>,"sigs":[..],
///        "aliases":[[signer,[alias..]],..],"v","idx"}
fn alias_vectors(lines: &mut Vec<Value>) -> Result<()> {
    use sui_types::base_types::{ObjectDigest, SequenceNumber};
    use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
    use sui_types::transaction::{SenderSignedData, TransactionData};
    let mut rng = ChaCha20Rng::seed_from_u64(0x7a75_692d_616c_6961); // "zui-alia"
    enum K {
        Ed(Ed25519KeyPair),
        K1(Secp256k1KeyPair),
        R1(Secp256r1KeyPair),
    }
    let mut keys: Vec<K> = Vec::new();
    for i in 0..6 {
        keys.push(match i % 3 {
            0 => K::Ed(gen_kp(&mut rng)),
            1 => K::K1(gen_kp(&mut rng)),
            _ => K::R1(gen_kp(&mut rng)),
        });
    }
    let pk_bytes = |k: &K| -> (u8, Vec<u8>) {
        match k {
            K::Ed(k) => (0, k.public().as_ref().to_vec()),
            K::K1(k) => (1, k.public().as_ref().to_vec()),
            K::R1(k) => (2, k.public().as_ref().to_vec()),
        }
    };
    let addr_of = |k: &K| -> SuiAddress {
        let (f, pk) = pk_bytes(k);
        let mut b = vec![f];
        b.extend_from_slice(&pk);
        SuiAddress::from_bytes(blake(&b)).unwrap()
    };
    let sign = |k: &K, d: &[u8; 32]| -> Vec<u8> {
        let (f, pk) = pk_bytes(k);
        let mut out = vec![f];
        match k {
            K::Ed(k) => out.extend_from_slice(ed_sign(k, d).as_ref()),
            K::K1(k) => out.extend_from_slice(<Secp256k1KeyPair as Signer<Secp256k1Signature>>::sign(k, d).as_ref()),
            K::R1(k) => out.extend_from_slice(<Secp256r1KeyPair as Signer<Secp256r1Signature>>::sign(k, d).as_ref()),
        }
        out.extend_from_slice(&pk);
        out
    };
    let pool: Vec<SuiAddress> = keys.iter().map(addr_of).collect();
    let rand_addr = |rng: &mut ChaCha20Rng| -> SuiAddress {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        SuiAddress::from_bytes(b).unwrap()
    };
    let mut n = 0usize;
    // (category, sender key, sponsor key, alias sets as pool indices (usize::MAX = the signer
    // itself), signing keys); then seeded random cases
    type Case = (&'static str, usize, Option<usize>, Vec<Option<Vec<usize>>>, Vec<usize>);
    const SELF: usize = usize::MAX;
    let mut cases: Vec<Case> = vec![
        ("aliased", 0, None, vec![Some(vec![1])], vec![1]),
        ("aliased", 0, None, vec![Some(vec![2, 1])], vec![1]),
        ("aliased", 0, Some(3), vec![Some(vec![1]), None], vec![3, 1]),
        ("aliased", 0, Some(3), vec![Some(vec![1]), Some(vec![4])], vec![4, 1]),
        ("none-signed", 0, None, vec![Some(vec![1, 2])], vec![3]),
        ("none-signed", 0, None, vec![Some(vec![1])], vec![0]),
        ("none-signed", 0, Some(3), vec![Some(vec![1]), None], vec![0, 3]),
        ("both-signed", 0, None, vec![Some(vec![SELF, 1])], vec![0, 1]),
        ("both-signed", 0, None, vec![Some(vec![1, SELF])], vec![1, 0]),
        ("both-signed", 0, Some(3), vec![Some(vec![SELF, 1]), None], vec![0, 1]),
        ("both-signed", 0, Some(3), vec![Some(vec![1, SELF]), None], vec![1, 0]),
        ("both-signed", 0, Some(3), vec![Some(vec![SELF, 1]), Some(vec![SELF, 1])], vec![1, 3]),
        ("both-signed", 0, Some(3), vec![Some(vec![1, SELF]), Some(vec![1, SELF])], vec![0, 1]),
        ("self", 0, None, vec![Some(vec![SELF])], vec![0]),
    ];
    for _ in 0..1500 {
        let sender = rng.gen_range(0..keys.len());
        let sponsor = if rng.gen_bool(0.4) { Some(rng.gen_range(0..keys.len())) } else { None };
        let nreq = if sponsor.is_some_and(|s| s != sender) { 2 } else { 1 };
        let mut sets = Vec::new();
        for _ in 0..nreq {
            if rng.gen_bool(0.6) {
                let l = rng.gen_range(1..4);
                let mut v: Vec<usize> = Vec::new();
                while v.len() < l {
                    let x = if rng.gen_bool(0.25) { SELF } else { rng.gen_range(0..keys.len()) };
                    if !v.contains(&x) {
                        v.push(x);
                    }
                }
                sets.push(Some(v));
            } else {
                sets.push(None);
            }
        }
        let nsig = match rng.gen_range(0..10) {
            0 => nreq + 1,
            1 if nreq > 1 => nreq - 1,
            _ => nreq,
        };
        let signers: Vec<usize> = (0..nsig).map(|_| rng.gen_range(0..keys.len())).collect();
        cases.push(("random", sender, sponsor, sets, signers));
    }
    for (cat, sender, sponsor, sets, signers) in cases {
        let (prm, flags) = flag_set(&mut rng);
        let s_addr = pool[sender];
        let sp_addr = sponsor.map(|s| pool[s]).unwrap_or(s_addr);
        let mut pt = ProgrammableTransactionBuilder::new();
        pt.pure(rng.r#gen::<u64>())?;
        let gas = (rand_addr(&mut rng).into(), SequenceNumber::from_u64(rng.gen_range(1..1000)), ObjectDigest::new(rng.r#gen()));
        let td = TransactionData::new_programmable_allow_sponsor(s_addr, vec![gas], pt.finish(), 1_000_000, 1000, sp_addr);
        let intent = bcs::to_bytes(&IntentMessage::new(Intent::sui_transaction(), td.clone()))?;
        let d = blake(&intent);
        let mut wrong = d;
        wrong[0] ^= 1;
        let mut sig_bytes = Vec::new();
        for k in &signers {
            let bad = cat == "random" && rng.gen_bool(0.08);
            sig_bytes.push(sign(&keys[*k], if bad { &wrong } else { &d }));
        }
        let gsigs: Vec<GenericSignature> = sig_bytes.iter().map(|b| <GenericSignature as ToFromBytes>::from_bytes(b).unwrap()).collect();
        let req = td.required_signers();
        let mut aliased = Vec::new();
        let mut aj = Vec::new();
        for (signer, set) in req.iter().zip(&sets) {
            match set {
                None => aliased.push((*signer, NonEmpty::singleton(*signer))),
                Some(v) => {
                    let l: Vec<SuiAddress> = v.iter().map(|i| if *i == SELF { *signer } else { pool[*i] }).collect();
                    aj.push(json!([h(signer.as_ref()), l.iter().map(|a| h(a.as_ref())).collect::<Vec<_>>()]));
                    aliased.push((*signer, NonEmpty::from_vec(l).unwrap()));
                }
            }
        }
        let ssd = SenderSignedData::new(td, gsigs);
        let cache = Arc::new(VerifiedDigestCache::new_empty());
        let (v, idx) = match verify_sender_signed_data_message_signatures(&ssd, 0, &prm, cache, aliased) {
            Ok(ix) => ("ok".to_string(), json!(ix)),
            Err(e) => (sui_name(&e), Value::Null),
        };
        lines.push(json!({
            "id": format!("user/alias-{cat}/{n}"), "op": "user_tx", "flags": flags, "msg": h(&intent),
            "sigs": sig_bytes.iter().map(|b| h(b)).collect::<Vec<_>>(), "aliases": aj, "v": v, "idx": idx,
        }));
        n += 1;
    }
    Ok(())
}

/// `zkvec`: real mainnet zkLogin signatures through paths the chain corpus never takes. Mainnet
/// has no MultiSig with a zkLogin member signature in the corpus, so each zkLogin signature is
/// wrapped in MultiSigs whose member key is its own ZkLoginPublicIdentifier (the Groth16 proof
/// and ephemeral signature stay valid: they sign the same intent message), next to an Ed25519
/// member, behind a mismatched key, a wrong seed, an unpadded identifier, a disabled flag, an
/// expired or too-far epoch, a missing JWK, and byte flips. Top-level variants vary the provider
/// list, the legacy padded address and the epoch bounds. Every line carries the epoch, the full
/// flags and the JWKs (those with the signature's kid at that checkpoint) its verdict used.
/// Shards <out_dir>/NNN.jsonl.zst. Line: {"id":"zk/<seq>/<tx>/<sig>/<kind>","op":"user_sig","epoch","flags","jwks":[{iss,kid,n,e,kty,alg}],
///        "msg","sig","author","v","addr"}
fn cmd_zkvec(args: &[String]) -> Result<()> {
    use sui_types::crypto::{CompressedSignature, PublicKey, ZkLoginAuthenticatorAsBytes, ZkLoginPublicIdentifier};
    use sui_types::multisig::MultiSigPublicKey;
    let [corpus, aux, out_path] = args else { bail!("zkvec <corpus_dir> <aux_src> <out_dir>") };
    let corpus = PathBuf::from(corpus);
    let pvs = load_pv(&corpus)?;
    let first_of = load_first_seqs(&corpus)?;
    let pre = prescan(&corpus, Path::new(aux))?;
    let seqs: Vec<(u64, PathBuf)> = chk_list(&corpus.join("chk"))?;
    let providers = [OIDCProvider::Google, OIDCProvider::Facebook, OIDCProvider::Twitch, OIDCProvider::Apple, OIDCProvider::Kakao, OIDCProvider::Slack, OIDCProvider::Microsoft];
    let per_seq: Vec<Vec<Value>> = seqs
        .par_iter()
        .map(|(seq, path)| -> Result<Vec<Value>> {
            let raw = std::fs::read(path)?;
            let cp: CheckpointData = bcs::from_bytes(&raw[1..])?;
            let real_epoch = cp.checkpoint_summary.data().epoch;
            let pv = pvs[real_epoch as usize];
            let mut out = Vec::new();
            let mut jwk_list: Option<Vec<(JwkId, JWK)>> = None;
            for (i, tx) in cp.transactions.iter().enumerate() {
                let ssd = tx.transaction.data();
                let intent_bytes = bcs::to_bytes(ssd.intent_message())?;
                let d = blake(&intent_bytes);
                for (j, sig) in ssd.tx_signatures().iter().enumerate() {
                    let GenericSignature::ZkLoginAuthenticator(z) = sig else { continue };
                    let all = jwk_list.get_or_insert_with(|| jwks_at(&pre, &first_of, real_epoch, *seq));
                    let kid = z.inputs.get_kid().to_string();
                    let mine: Vec<(JwkId, JWK)> = all.iter().filter(|(id, _)| id.kid == kid).cloned().collect();
                    let zbytes = sig.as_ref().to_vec();
                    let iss = z.inputs.get_iss().to_string();
                    let seed = z.inputs.get_address_seed();
                    let max_epoch = z.get_max_epoch();
                    let id_of = |seed_bytes: &[u8]| -> PublicKey {
                        let mut b = vec![iss.len() as u8];
                        b.extend_from_slice(iss.as_bytes());
                        b.extend_from_slice(seed_bytes);
                        PublicKey::ZkLogin(ZkLoginPublicIdentifier(b))
                    };
                    let padded_id = id_of(seed.padded());
                    let unpadded_id = id_of(seed.unpadded());
                    let mut rng = ChaCha20Rng::seed_from_u64(splitmix(seq ^ ((i as u64) << 32) ^ ((j as u64) << 48) ^ 0x7a6b));
                    let ed = gen_kp::<Ed25519KeyPair>(&mut rng);
                    let ed_pk = PublicKey::Ed25519(ed.public().into());
                    let ed_sig = CompressedSignature::Ed25519((&ed_sign(&ed, &d)).into());
                    let zk_sig = |b: &[u8]| CompressedSignature::ZkLogin(ZkLoginAuthenticatorAsBytes(b.to_vec()));
                    let ms = |members: Vec<(PublicKey, u8)>, thr: u16, sigs: Vec<CompressedSignature>, bitmap: u16| -> (Vec<u8>, SuiAddress) {
                        let mpk = MultiSigPublicKey::insecure_new(members, thr);
                        let author = SuiAddress::from(&mpk);
                        let m = MultiSig::insecure_new(sigs, bitmap, mpk);
                        (GenericSignature::MultiSig(m).as_ref().to_vec(), author)
                    };
                    let base = params_for(pv);
                    // (kind, sig bytes, author, epoch, params, jwks)
                    let mut cases: Vec<(String, Vec<u8>, SuiAddress, u64, VerifyParams, Vec<(JwkId, JWK)>)> = Vec::new();
                    let accept = VerifyParams { accept_zklogin_in_multisig: true, ..base.clone() };
                    let e0 = real_epoch;
                    {
                        let (b, a) = ms(vec![(padded_id.clone(), 1)], 1, vec![zk_sig(&zbytes)], 1);
                        cases.push(("ms1".into(), b.clone(), a, e0, accept.clone(), mine.clone()));
                        cases.push(("ms1-noaccept".into(), b.clone(), a, e0, VerifyParams { accept_zklogin_in_multisig: false, ..base.clone() }, mine.clone()));
                        cases.push(("ms1-legacy-off".into(), b.clone(), a, e0, VerifyParams { verify_legacy_zklogin_address: false, ..accept.clone() }, mine.clone()));
                        cases.push(("ms1-legacy-on".into(), b.clone(), a, e0, VerifyParams { verify_legacy_zklogin_address: true, ..accept.clone() }, mine.clone()));
                        cases.push(("ms1-nojwk".into(), b.clone(), a, e0, accept.clone(), Vec::new()));
                        cases.push(("ms1-expired".into(), b.clone(), a, max_epoch.saturating_add(1), accept.clone(), mine.clone()));
                        cases.push(("ms1-last-epoch".into(), b.clone(), a, max_epoch, VerifyParams { zklogin_max_epoch_upper_bound_delta: Some(0), ..accept.clone() }, mine.clone()));
                        if max_epoch >= 2 {
                            let dlt = rng.gen_range(0..max_epoch.min(40));
                            cases.push(("ms1-too-far".into(), b.clone(), a, max_epoch - dlt - 1, VerifyParams { zklogin_max_epoch_upper_bound_delta: Some(dlt), ..accept.clone() }, mine.clone()));
                        }
                        let prov: Vec<OIDCProvider> = providers.iter().filter(|_| rng.gen_bool(0.5)).cloned().collect();
                        cases.push(("ms1-providers".into(), b.clone(), a, e0, VerifyParams { supported_providers: prov, ..accept.clone() }, mine.clone()));
                        for k in 0..3 {
                            let mut f = zbytes.clone();
                            let off = rng.gen_range(1..f.len());
                            f[off] ^= 1 << rng.gen_range(0..8);
                            let (b, a) = ms(vec![(padded_id.clone(), 1)], 1, vec![zk_sig(&f)], 1);
                            cases.push((format!("ms1-flip{k}"), b, a, e0, accept.clone(), mine.clone()));
                        }
                    }
                    {
                        let vzk = rng.gen_bool(0.5);
                        let (b, a) = ms(vec![(unpadded_id.clone(), 1)], 1, vec![zk_sig(&zbytes)], 1);
                        cases.push(("ms1-unpadded-id".into(), b, a, e0, VerifyParams { validate_zklogin_public_identifier: vzk, verify_legacy_zklogin_address: rng.gen_bool(0.5), ..accept.clone() }, mine.clone()));
                        let mut ws = seed.padded().to_vec();
                        let at = rng.gen_range(0..ws.len());
                        ws[at] ^= 1 << rng.gen_range(0..8);
                        let (b, a) = ms(vec![(id_of(&ws), 1)], 1, vec![zk_sig(&zbytes)], 1);
                        cases.push(("ms1-wrong-seed".into(), b, a, e0, accept.clone(), mine.clone()));
                        let (b, a) = ms(vec![(ed_pk.clone(), 1)], 1, vec![zk_sig(&zbytes)], 1);
                        cases.push(("ms1-ed-key".into(), b, a, e0, VerifyParams { additional_multisig_checks: rng.gen_bool(0.5), ..accept.clone() }, mine.clone()));
                        // the zkLogin member's key holds an Ed25519 signature (strict check on the key kind)
                        let (b, a) = ms(vec![(padded_id.clone(), 1)], 1, vec![ed_sig.clone()], 1);
                        cases.push(("ms1-ed-sig".into(), b, a, e0, VerifyParams { additional_multisig_checks: rng.gen_bool(0.5), ..accept.clone() }, mine.clone()));
                    }
                    {
                        // beside an Ed25519 member; both orders, weights and thresholds
                        let zk_first = rng.gen_bool(0.5);
                        let wz: u8 = [0u8, 1, 2][rng.gen_range(0..3)];
                        let we: u8 = [1u8, 2][rng.gen_range(0..2)];
                        let thr: u16 = rng.gen_range(1..=(wz as u16 + we as u16 + 1));
                        let (members, sigs) = if zk_first {
                            (vec![(padded_id.clone(), wz), (ed_pk.clone(), we)], vec![zk_sig(&zbytes), ed_sig.clone()])
                        } else {
                            (vec![(ed_pk.clone(), we), (padded_id.clone(), wz)], vec![ed_sig.clone(), zk_sig(&zbytes)])
                        };
                        let (b, a) = ms(members.clone(), thr, sigs, 0b11);
                        cases.push(("ms2".into(), b, a, e0, accept.clone(), mine.clone()));
                        // only the zkLogin member signs
                        let zbit: u16 = if zk_first { 0b01 } else { 0b10 };
                        let (b, a) = ms(members, 1, vec![zk_sig(&zbytes)], zbit);
                        cases.push(("ms2-zk-only".into(), b, a, e0, accept.clone(), mine.clone()));
                    }
                    {
                        // top level
                        let a_unp = SuiAddress::try_from_unpadded(&z.inputs)?;
                        let a_pad = SuiAddress::try_from_padded(&z.inputs)?;
                        let prov: Vec<OIDCProvider> = providers.iter().filter(|_| rng.gen_bool(0.5)).cloned().collect();
                        cases.push(("top-providers".into(), zbytes.clone(), a_unp, e0, VerifyParams { supported_providers: prov, ..base.clone() }, mine.clone()));
                        for leg in [false, true] {
                            cases.push((format!("top-padded-legacy-{leg}"), zbytes.clone(), a_pad, e0, VerifyParams { verify_legacy_zklogin_address: leg, ..base.clone() }, mine.clone()));
                        }
                        cases.push(("top-last-epoch".into(), zbytes.clone(), a_unp, max_epoch, VerifyParams { zklogin_max_epoch_upper_bound_delta: Some(0), ..base.clone() }, mine.clone()));
                        cases.push(("top-expired".into(), zbytes.clone(), a_unp, max_epoch.saturating_add(1), base.clone(), mine.clone()));
                        cases.push(("top-nojwk".into(), zbytes.clone(), a_unp, e0, base.clone(), Vec::new()));
                    }
                    for (kind, b, author, epoch, mut prm, jw) in cases {
                        prm.oidc_provider_jwks = Default::default();
                        for (id, jwk) in &jw {
                            prm.oidc_provider_jwks.insert(id.clone(), jwk.clone());
                        }
                        let (v, addr) = check_sig(&b, &intent_bytes, author, epoch, &prm);
                        let flags = json!({
                            "accept_zklogin_in_multisig": prm.accept_zklogin_in_multisig,
                            "accept_passkey_in_multisig": prm.accept_passkey_in_multisig,
                            "accept_mldsa65_in_multisig": prm.accept_mldsa65_in_multisig,
                            "additional_multisig_checks": prm.additional_multisig_checks,
                            "validate_zklogin_public_identifier": prm.validate_zklogin_public_identifier,
                            "verify_legacy_zklogin_address": prm.verify_legacy_zklogin_address,
                            "zklogin_max_epoch_upper_bound_delta": prm.zklogin_max_epoch_upper_bound_delta,
                            "zklogin_circuit_mode": prm.zklogin_circuit_mode,
                            "zklogin_supported_providers": prm.supported_providers.iter().map(|p| format!("{p:?}")).collect::<Vec<_>>(),
                        });
                        out.push(json!({
                            "id": format!("zk/{seq}/{i}/{j}/{kind}"), "op": "user_sig", "epoch": epoch, "flags": flags,
                            "jwks": jw.iter().map(|(id, j)| json!({ "iss": id.iss, "kid": id.kid, "kty": j.kty, "e": j.e, "n": j.n, "alg": j.alg })).collect::<Vec<_>>(),
                            "msg": h(&intent_bytes), "sig": h(&b), "author": h(author.as_ref()), "v": v, "addr": addr,
                        }));
                    }
                }
            }
            Ok(out)
        })
        .collect::<Result<_>>()?;
    // shards of whole checkpoints, about 1,000 lines each, in checkpoint order
    let out_dir = PathBuf::from(out_path);
    std::fs::create_dir_all(&out_dir)?;
    let mut n = 0usize;
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    let mut shard = String::new();
    let mut shard_no = 0usize;
    let mut in_shard = 0usize;
    let flush = |text: &mut String, no: &mut usize| -> Result<()> {
        if text.is_empty() {
            return Ok(());
        }
        std::fs::write(out_dir.join(format!("{:03}.jsonl.zst", *no)), zstd::encode_all(text.as_bytes(), 9)?)?;
        text.clear();
        *no += 1;
        Ok(())
    };
    for lines in &per_seq {
        for l in lines {
            shard.push_str(&l.to_string());
            shard.push('\n');
            n += 1;
            in_shard += 1;
            let kind = l["id"].as_str().unwrap().rsplit('/').next().unwrap().to_string();
            *tally.entry(format!("{kind} {}", l["v"].as_str().unwrap())).or_default() += 1;
        }
        if in_shard >= 1000 {
            flush(&mut shard, &mut shard_no)?;
            in_shard = 0;
        }
    }
    flush(&mut shard, &mut shard_no)?;
    for (k, c) in &tally {
        eprintln!("{c:6} {k}");
    }
    eprintln!("zkvec: {n} vectors");
    Ok(())
}
