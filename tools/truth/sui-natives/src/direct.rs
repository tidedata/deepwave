//! `bench-direct <group> --list <file> [--iters n]`: the native's own Rust body on the same
//! inputs, with no Move VM, extensions or NativeContext (NativeContext::new is pub(crate) in
//! move-vm-runtime, so a native cannot be called outside the VM). Each call's arguments are
//! decoded from BCS outside the timing; the body is what the native runs between its charges.
//! Groups: validator, nitro, ed25519, bls12381, hash.

use anyhow::{Context, Result, anyhow};
use fastcrypto::traits::{ToFromBytes, VerifyingKey};
use serde_json::{Value as J, json};

fn vec_arg(b: &[u8]) -> Vec<u8> {
    bcs::from_bytes::<Vec<u8>>(b).unwrap()
}

enum Op {
    Validator(Vec<u8>),
    Nitro(Vec<u8>, u64),
    Ed(Vec<u8>, Vec<u8>, Vec<u8>),
    MinSig(Vec<u8>, Vec<u8>, Vec<u8>),
    MinPk(Vec<u8>, Vec<u8>, Vec<u8>),
    Hash(&'static str, Vec<u8>),
    Hmac(Vec<u8>, Vec<u8>),
}

fn run(op: &Op) -> bool {
    use fastcrypto::hash::{Blake2b256, HashFunction, Keccak256, Sha256, Sha3_256};
    match op {
        Op::Validator(b) => match bcs::from_bytes::<sui_types::sui_system_state::sui_system_state_inner_v1::ValidatorMetadataV1>(b) {
            Ok(m) => m.verify(true).is_ok(),
            Err(_) => false,
        },
        Op::Nitro(b, ts) => match sui_types::nitro_attestation::parse_nitro_attestation(b, true, true, true) {
            Ok((sig, msg, doc)) => sui_types::nitro_attestation::verify_nitro_attestation(&sig, &msg, &doc, *ts).is_ok(),
            Err(_) => false,
        },
        Op::Ed(s, pk, m) => {
            use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
            match (Ed25519Signature::from_bytes(s), Ed25519PublicKey::from_bytes(pk)) {
                (Ok(s), Ok(pk)) => pk.verify(m, &s).is_ok(),
                _ => false,
            }
        }
        Op::MinSig(s, pk, m) => {
            use fastcrypto::bls12381::min_sig::{BLS12381PublicKey, BLS12381Signature};
            match (BLS12381Signature::from_bytes(s), BLS12381PublicKey::from_bytes(pk)) {
                (Ok(s), Ok(pk)) => pk.verify(m, &s).is_ok(),
                _ => false,
            }
        }
        Op::MinPk(s, pk, m) => {
            use fastcrypto::bls12381::min_pk::{BLS12381PublicKey, BLS12381Signature};
            match (BLS12381Signature::from_bytes(s), BLS12381PublicKey::from_bytes(pk)) {
                (Ok(s), Ok(pk)) => pk.verify(m, &s).is_ok(),
                _ => false,
            }
        }
        Op::Hash(f, d) => {
            let h: [u8; 32] = match *f {
                "sha2_256" => Sha256::digest(d).digest,
                "sha3_256" => Sha3_256::digest(d).digest,
                "blake2b256" => Blake2b256::digest(d).digest,
                _ => Keccak256::digest(d).digest,
            };
            h[0] & 1 == 1
        }
        Op::Hmac(k, d) => {
            let key = fastcrypto::hmac::HmacKey::from_bytes(k).unwrap();
            fastcrypto::hmac::hmac_sha3_256(&key, d).digest[0] & 1 == 1
        }
    }
}

pub fn run_bench_direct(args: &[String]) -> Result<()> {
    let group = args.get(2).context("bench-direct <group>")?.clone();
    let mut iters = 5usize;
    let mut list = None;
    let mut i = 3;
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
            _ => i += 1,
        }
    }
    let list = std::fs::read_to_string(list.context("--list")?)?;
    let mut ops = Vec::new();
    for path in list.lines().filter(|l| !l.is_empty()) {
        if std::path::Path::new(path).file_stem().and_then(|s| s.to_str()) != Some(group.as_str()) {
            continue;
        }
        for line in std::fs::read_to_string(path)?.lines().filter(|l| !l.is_empty()) {
            let d: J = serde_json::from_str(line)?;
            for c in d["calls"].as_array().unwrap() {
                let a: Vec<Vec<u8>> = c["args"].as_array().unwrap().iter().map(|x| hex::decode(x.as_str().unwrap()).unwrap()).collect();
                let f = c["func"].as_str().unwrap();
                let op = match f {
                    "validate_metadata_bcs" => Op::Validator(vec_arg(&a[0])),
                    "load_nitro_attestation_internal" => Op::Nitro(vec_arg(&a[0]), u64::from_le_bytes(a[1][..8].try_into().unwrap())),
                    "ed25519_verify" => Op::Ed(vec_arg(&a[0]), vec_arg(&a[1]), vec_arg(&a[2])),
                    "bls12381_min_sig_verify" => Op::MinSig(vec_arg(&a[0]), vec_arg(&a[1]), vec_arg(&a[2])),
                    "bls12381_min_pk_verify" => Op::MinPk(vec_arg(&a[0]), vec_arg(&a[1]), vec_arg(&a[2])),
                    "sha2_256" | "sha3_256" | "blake2b256" | "keccak256" => {
                        Op::Hash(Box::leak(f.to_string().into_boxed_str()), vec_arg(&a[0]))
                    }
                    "hmac_sha3_256" => Op::Hmac(vec_arg(&a[0]), vec_arg(&a[1])),
                    _ => return Err(anyhow!("bench-direct: no direct body for {f}")),
                };
                ops.push(op);
            }
        }
    }
    let pass = || {
        let mut n = 0u64;
        for op in &ops {
            n += std::hint::black_box(run(op)) as u64;
        }
        n
    };
    std::hint::black_box(pass());
    let mut times = Vec::new();
    for _ in 0..iters.max(1) {
        let t0 = std::time::Instant::now();
        std::hint::black_box(pass());
        times.push(t0.elapsed().as_nanos() as u64);
    }
    times.sort();
    let med = times[times.len() / 2];
    println!(
        "{}",
        json!({"impl": "rust-direct", "bench": format!("{group}-body"), "unit": "call", "units": ops.len(), "iters": times.len(),
               "median_ns": med, "min_ns": times[0], "ns_per_unit": med as f64 / ops.len().max(1) as f64})
    );
    Ok(())
}
