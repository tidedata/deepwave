//! zui-zk-truth: ground truth for the crypto-zk lane (CONTRACTS.md sections 3.3 and 4.3).
//!
//! Every verdict and every output byte below comes from Mysten's own code at the pinned revisions
//! (fastcrypto-zkp and sui-types of mainnet-v1.83.1). Nothing is recomputed here.
//!
//!   vectors <corpus_dir>                 writes $corpus/vectors/{groth16,poseidon,zklogin}/ (README.md)
//!   bench <name> --iters N --list FILE   Rust timing on the same vector files the Zig bench reads
//!   gen-poseidon <out.zig>               Poseidon round constants and MDS matrices as Zig limbs
use anyhow::{Context, Result, anyhow, bail};
use ark_ff::{BigInteger, Field, PrimeField, UniformRand};
use ark_groth16::Groth16;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::{Rng, SeedableRng, rngs::StdRng};
use fastcrypto::error::FastCryptoError;
use fastcrypto::traits::ToFromBytes;
use fastcrypto_zkp::bn254::FieldElement;
use fastcrypto_zkp::bn254::zk_login::{JWK, JwkId};
use fastcrypto_zkp::bn254::zk_login_api::{ZkLoginCircuitMode, ZkLoginEnv};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;
use sui_types::base_types::SuiAddress;
use sui_types::crypto::SuiSignature;
use ark_ec::AffineRepr;
use sui_types::full_checkpoint_content::CheckpointData;
use sui_types::signature::GenericSignature;
use sui_types::transaction::TransactionDataAPI;
use sui_types::zk_login_authenticator::ZkLoginAuthenticator;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("vectors") => cmd_vectors(&args[2..]),
        Some("bench") => cmd_bench(&args[2..]),
        Some("gen-poseidon") => cmd_gen_poseidon(&args[2..]),
        _ => bail!("usage: zui-zk-truth vectors <corpus> | bench <name> --iters N --list FILE | gen-poseidon <out.zig>"),
    }
}

/// Debug form of a fastcrypto error: the exact value deepwave mirrors.
fn ferr(e: &FastCryptoError) -> String {
    format!("{e:?}")
}

fn le32_fr(f: &ark_bn254::Fr) -> String {
    hex::encode(f.into_bigint().to_bytes_le())
}

struct Out {
    lines: Vec<String>,
}
impl Out {
    fn new() -> Self {
        Out { lines: Vec::new() }
    }
    fn push(&mut self, v: Value) {
        self.lines.push(serde_json::to_string(&v).unwrap());
    }
    fn write(&self, path: &Path) -> Result<()> {
        std::fs::create_dir_all(path.parent().unwrap())?;
        let mut f = std::fs::File::create(path)?;
        for l in &self.lines {
            f.write_all(l.as_bytes())?;
            f.write_all(b"\n")?;
        }
        eprintln!("{}: {} items", path.display(), self.lines.len());
        Ok(())
    }
}

fn cmd_vectors(args: &[String]) -> Result<()> {
    let corpus = PathBuf::from(args.first().ok_or_else(|| anyhow!("vectors <corpus_dir>"))?);
    let what: Vec<&str> = args[1..].iter().map(|s| s.as_str()).collect();
    let all = what.is_empty();
    if all || what.contains(&"poseidon") {
        poseidon_vectors(&corpus)?;
    }
    if all || what.contains(&"groth16") {
        groth16_vectors(&corpus)?;
    }
    if all || what.contains(&"zklogin") {
        zklogin_fn_vectors(&corpus)?;
        zklogin_corpus_vectors(&corpus)?;
    }
    if all || what.contains(&"zklogin") || what.contains(&"zklogin-edge") {
        zklogin_edge_vectors(&corpus)?;
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------
// Poseidon

fn rand_fr_le(rng: &mut StdRng) -> Vec<u8> {
    ark_bn254::Fr::rand(rng).into_bigint().to_bytes_le()
}

fn poseidon_vectors(corpus: &Path) -> Result<()> {
    use fastcrypto_zkp::bn254::poseidon::{poseidon_bytes, poseidon_merkle_tree};
    let mut out = Out::new();
    let mut rng = StdRng::seed_from_u64(0x5e1d_0001);
    let r_le = ark_bn254::Fr::MODULUS.to_bytes_le();
    let mut r_minus_1 = ark_bn254::Fr::MODULUS;
    r_minus_1.sub_with_borrow(&ark_ff::BigInt::from(1u64));
    let edge: Vec<Vec<u8>> = vec![
        vec![0u8; 32],
        {
            let mut v = vec![0u8; 32];
            v[0] = 1;
            v
        },
        r_minus_1.to_bytes_le(),
        r_le.clone(),      // = r: non-canonical
        vec![0xff; 32],    // > r
        vec![0u8; 31],     // short
        vec![0u8; 33],     // long
        {
            let mut v = r_le.clone();
            v[0] += 1;
            v
        },
    ];
    // poseidon_bytes: 0..=17 inputs, random canonical inputs, plus edge inputs at each position.
    for n in 0..=17usize {
        let reps = if n == 0 || n == 17 { 2 } else { 40 };
        for i in 0..reps {
            let inputs: Vec<Vec<u8>> = (0..n).map(|_| rand_fr_le(&mut rng)).collect();
            let res = poseidon_bytes(&inputs);
            out.push(json!({"id": format!("bytes/n{n}/r{i}"), "fn": "bytes",
                "in": inputs.iter().map(hex::encode).collect::<Vec<_>>(),
                "out": res.as_ref().ok().map(hex::encode), "err": res.as_ref().err().map(ferr)}));
        }
        if n >= 1 && n <= 16 {
            for (e, ev) in edge.iter().enumerate() {
                let mut inputs: Vec<Vec<u8>> = (0..n).map(|_| rand_fr_le(&mut rng)).collect();
                let pos = rng.gen_range(0..n);
                inputs[pos] = ev.clone();
                let res = poseidon_bytes(&inputs);
                out.push(json!({"id": format!("bytes/n{n}/edge{e}"), "fn": "bytes",
                    "in": inputs.iter().map(hex::encode).collect::<Vec<_>>(),
                    "out": res.as_ref().ok().map(hex::encode), "err": res.as_ref().err().map(ferr)}));
            }
        }
    }
    // Small values 1..16 (the fastcrypto unit-test shape).
    for n in 1..=16usize {
        let inputs: Vec<Vec<u8>> = (1..=n)
            .map(|v| {
                let mut b = vec![0u8; 32];
                b[0] = v as u8;
                b
            })
            .collect();
        let res = poseidon_bytes(&inputs);
        out.push(json!({"id": format!("bytes/small{n}"), "fn": "bytes",
            "in": inputs.iter().map(hex::encode).collect::<Vec<_>>(),
            "out": res.as_ref().ok().map(hex::encode), "err": res.as_ref().err().map(ferr)}));
    }
    // poseidon_merkle_tree (what poseidon_zk_login runs): 0..=80 field elements.
    for n in 0..=80usize {
        let reps = if n <= 33 || n % 8 == 0 { 6 } else { 2 };
        for i in 0..reps {
            let frs: Vec<ark_bn254::Fr> = (0..n).map(|_| ark_bn254::Fr::rand(&mut rng)).collect();
            let fes: Vec<FieldElement> = frs.iter().map(|f| FieldElement::from(*f)).collect();
            let res = poseidon_merkle_tree(&fes);
            out.push(json!({"id": format!("merkle/n{n}/r{i}"), "fn": "merkle",
                "in": frs.iter().map(le32_fr).collect::<Vec<_>>(),
                "out": res.as_ref().ok().map(|f| { let x: ark_bn254::Fr = f.clone().into(); le32_fr(&x) }),
                "err": res.as_ref().err().map(ferr)}));
        }
    }
    out.write(&corpus.join("vectors/poseidon/fastcrypto.jsonl"))?;
    write_readme(corpus, "poseidon")?;
    Ok(())
}

// ------------------------------------------------------------------------------------------------
// Groth16

/// A circuit with `k` public inputs: x_i * x_i = s_i for witnesses s_i, plus a*b = c.
#[derive(Clone)]
struct MultiInput<F: PrimeField> {
    xs: Vec<F>,
    a: F,
    b: F,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for MultiInput<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| Ok(self.a))?;
        let b = cs.new_witness_variable(|| Ok(self.b))?;
        let c = cs.new_witness_variable(|| Ok(self.a * self.b))?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        for x in &self.xs {
            let xv = cs.new_input_variable(|| Ok(*x))?;
            let s = cs.new_witness_variable(|| Ok(x.square()))?;
            cs.enforce_constraint(lc!() + xv, lc!() + xv, lc!() + s)?;
            cs.enforce_constraint(lc!() + xv + a, lc!() + Variable::One, lc!() + xv + a)?;
        }
        Ok(())
    }
}

fn ser<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
    let mut v = Vec::new();
    t.serialize_compressed(&mut v).unwrap();
    v
}

fn bool_res(r: &Result<bool, FastCryptoError>) -> Value {
    match r {
        Ok(b) => json!(b),
        Err(e) => json!(ferr(e)),
    }
}

/// Mutations of a byte string: bit flips at chosen spots, truncation, extension.
fn mutations(rng: &mut StdRng, b: &[u8], n: usize) -> Vec<(String, Vec<u8>)> {
    let mut v = Vec::new();
    if b.is_empty() {
        v.push(("ext".into(), vec![0u8]));
        return v;
    }
    for i in 0..n {
        let mut m = b.to_vec();
        let pos = rng.gen_range(0..m.len());
        let bit = rng.gen_range(0..8);
        m[pos] ^= 1 << bit;
        v.push((format!("flip{i}@{pos}.{bit}"), m));
    }
    let mut m = b.to_vec();
    let last = m.len() - 1;
    m[last] ^= 0x40; // infinity flag on the last element (arkworks SW flags live in the top bits)
    v.push(("flag40".into(), m));
    let mut m = b.to_vec();
    m[last] ^= 0x80;
    v.push(("flag80".into(), m));
    let mut m = b.to_vec();
    m[last] |= 0xc0;
    v.push(("flagc0".into(), m));
    v.push(("trunc1".into(), b[..b.len() - 1].to_vec()));
    let mut m = b.to_vec();
    m.push(0);
    v.push(("ext1".into(), m));
    let mut m = b.to_vec();
    m.extend_from_slice(&[0u8; 32]);
    v.push(("ext32".into(), m));
    v
}

fn groth16_vectors(corpus: &Path) -> Result<()> {
    use fastcrypto_zkp::bn254::api as bn;
    let mut out = Out::new();
    let mut rng = StdRng::seed_from_u64(0x9e07_0016);
    type E = ark_bn254::Bn254;
    type Fr = ark_bn254::Fr;
    for k in 0..=10usize {
        for rep in 0..3 {
            let xs: Vec<Fr> = (0..k).map(|_| Fr::rand(&mut rng)).collect();
            let circ = MultiInput { xs: xs.clone(), a: Fr::rand(&mut rng), b: Fr::rand(&mut rng) };
            let (pk, vk) = Groth16::<E>::circuit_specific_setup(circ.clone(), &mut rng).unwrap();
            let vk_bytes = ser(&vk);
            let id = format!("bn254/k{k}/v{rep}");
            let pvk = bn::prepare_pvk_bytes(&vk_bytes);
            let nin = bn::get_public_inputs_num(vk_bytes.len());
            out.push(json!({"id": format!("{id}/prepare"), "op": "prepare", "curve": "bn254", "vk": hex::encode(&vk_bytes),
                "pvk": pvk.as_ref().ok().map(|p| p.iter().map(hex::encode).collect::<Vec<_>>()),
                "err": pvk.as_ref().err().map(ferr),
                "nin": nin.as_ref().ok(), "nin_err": nin.as_ref().err().map(ferr)}));
            // Mutated verifying keys.
            for (mname, m) in mutations(&mut rng, &vk_bytes, if rep == 0 { 12 } else { 4 }) {
                let pvk_m = bn::prepare_pvk_bytes(&m);
                let nin_m = bn::get_public_inputs_num(m.len());
                out.push(json!({"id": format!("{id}/prepare-{mname}"), "op": "prepare", "curve": "bn254", "vk": hex::encode(&m),
                    "pvk": pvk_m.as_ref().ok().map(|p| p.iter().map(hex::encode).collect::<Vec<_>>()),
                    "err": pvk_m.as_ref().err().map(ferr),
                    "nin": nin_m.as_ref().ok(), "nin_err": nin_m.as_ref().err().map(ferr)}));
            }
            let pvk = pvk.unwrap();
            for prep in 0..2 {
                let proof = Groth16::<E>::prove(&pk, circ.clone(), &mut rng).unwrap();
                let mut pp = ser(&proof.a);
                pp.extend(ser(&proof.b));
                pp.extend(ser(&proof.c));
                let inputs: Vec<u8> = xs.iter().flat_map(|x| ser(x)).collect();
                let pid = format!("{id}/p{prep}");
                let mut push = |name: &str, pvk: &[Vec<u8>], inp: &[u8], prf: &[u8]| {
                    let r = bn::verify_groth16_in_bytes(&pvk[0], &pvk[1], &pvk[2], &pvk[3], inp, prf);
                    out.push(json!({"id": format!("{pid}/{name}"), "op": "verify", "curve": "bn254",
                        "pvk": pvk.iter().map(hex::encode).collect::<Vec<_>>(),
                        "inputs": hex::encode(inp), "proof": hex::encode(prf), "res": bool_res(&r)}));
                };
                push("valid", &pvk, &inputs, &pp);
                if prep == 1 {
                    continue;
                }
                // Wrong inputs, wrong counts, non-canonical scalars.
                if k > 0 {
                    let mut wrong = inputs.clone();
                    wrong[0] ^= 1;
                    push("input-flip", &pvk, &wrong, &pp);
                    push("input-short", &pvk, &inputs[32..], &pp);
                    let mut nc = inputs.clone();
                    nc[..32].copy_from_slice(&Fr::MODULUS.to_bytes_le());
                    push("input-noncanonical", &pvk, &nc, &pp);
                    let mut big = inputs.clone();
                    big[31] = 0xff;
                    push("input-big", &pvk, &big, &pp);
                    push("input-ragged", &pvk, &inputs[1..], &pp);
                }
                let mut more = inputs.clone();
                more.extend(ser(&Fr::rand(&mut rng)));
                push("input-extra", &pvk, &more, &pp);
                for (mname, m) in mutations(&mut rng, &pp, 6) {
                    push(&format!("proof-{mname}"), &pvk, &inputs, &m);
                }
                // Swap A and C, negate A.
                let mut sw = ser(&proof.c);
                sw.extend(ser(&proof.b));
                sw.extend(ser(&proof.a));
                push("proof-swap", &pvk, &inputs, &sw);
                let mut ng = ser(&(-proof.a));
                ng.extend(ser(&proof.b));
                ng.extend(ser(&proof.c));
                push("proof-nega", &pvk, &inputs, &ng);
                // Identity points in the proof.
                let mut inf = ser(&ark_bn254::G1Affine::identity());
                inf.extend(ser(&proof.b));
                inf.extend(ser(&proof.c));
                push("proof-a-inf", &pvk, &inputs, &inf);
                let mut infb = ser(&proof.a);
                infb.extend(ser(&ark_bn254::G2Affine::identity()));
                infb.extend(ser(&proof.c));
                push("proof-b-inf", &pvk, &inputs, &infb);
                // Mutated prepared key parts.
                for part in 0..4 {
                    for (mname, m) in mutations(&mut rng, &pvk[part], 2) {
                        let mut p2 = pvk.clone();
                        p2[part] = m;
                        push(&format!("pvk{part}-{mname}"), &p2, &inputs, &pp);
                    }
                }
            }
        }
    }
    // Points not in the G2 subgroup: on the twist, but not of order r.
    {
        let mut found = 0;
        let mut ctr = 0u64;
        while found < 8 {
            ctr += 1;
            let x = ark_bn254::Fq2::new(ark_bn254::Fq::from(ctr), ark_bn254::Fq::from(ctr * 7 + 3));
            if let Some(p) = ark_bn254::G2Affine::get_point_from_x_unchecked(x, ctr % 2 == 0) {
                if !p.is_in_correct_subgroup_assuming_on_curve() {
                    let b = ser(&p);
                    let mut rng2 = StdRng::seed_from_u64(ctr);
                    let xs: Vec<Fr> = vec![Fr::rand(&mut rng2)];
                    let circ = MultiInput { xs: xs.clone(), a: Fr::rand(&mut rng2), b: Fr::rand(&mut rng2) };
                    let (pk, vk) = Groth16::<E>::circuit_specific_setup(circ.clone(), &mut rng2).unwrap();
                    let proof = Groth16::<E>::prove(&pk, circ.clone(), &mut rng2).unwrap();
                    let pvk = bn::prepare_pvk_bytes(&ser(&vk)).unwrap();
                    let mut pp = ser(&proof.a);
                    pp.extend(&b);
                    pp.extend(ser(&proof.c));
                    let inputs: Vec<u8> = xs.iter().flat_map(|x| ser(x)).collect();
                    let r = bn::verify_groth16_in_bytes(&pvk[0], &pvk[1], &pvk[2], &pvk[3], &inputs, &pp);
                    out.push(json!({"id": format!("bn254/g2-nonsubgroup{found}/verify"), "op": "verify", "curve": "bn254",
                        "pvk": pvk.iter().map(hex::encode).collect::<Vec<_>>(),
                        "inputs": hex::encode(&inputs), "proof": hex::encode(&pp), "res": bool_res(&r)}));
                    // ... and as the vk's gamma (beta_g2 is at offset 32).
                    let mut vkb = ser(&vk);
                    vkb[32 + 64..32 + 128].copy_from_slice(&b);
                    let pv = bn::prepare_pvk_bytes(&vkb);
                    out.push(json!({"id": format!("bn254/g2-nonsubgroup{found}/prepare"), "op": "prepare", "curve": "bn254", "vk": hex::encode(&vkb),
                        "pvk": pv.as_ref().ok().map(|p| p.iter().map(hex::encode).collect::<Vec<_>>()),
                        "err": pv.as_ref().err().map(ferr),
                        "nin": bn::get_public_inputs_num(vkb.len()).ok(), "nin_err": Value::Null}));
                    found += 1;
                }
            }
        }
    }
    // Arbitrary lengths for get_public_inputs_num and prepare.
    for len in 0..=400usize {
        let nin = bn::get_public_inputs_num(len);
        let bytes = vec![0u8; len];
        let pvk = bn::prepare_pvk_bytes(&bytes);
        out.push(json!({"id": format!("bn254/len{len}/prepare"), "op": "prepare", "curve": "bn254", "vk": hex::encode(&bytes),
            "pvk": pvk.as_ref().ok().map(|p| p.iter().map(hex::encode).collect::<Vec<_>>()),
            "err": pvk.as_ref().err().map(ferr), "nin": nin.as_ref().ok(), "nin_err": nin.as_ref().err().map(ferr)}));
    }
    out.write(&corpus.join("vectors/groth16/bn254.jsonl"))?;

    // BLS12-381: fastcrypto (blst) verifier, arkworks prover.
    let mut out = Out::new();
    use fastcrypto_zkp::bls12381::api as bls;
    type E2 = ark_bls12_381::Bls12_381;
    type Fr2 = ark_bls12_381::Fr;
    for k in 0..=9usize {
        for rep in 0..2 {
            let xs: Vec<Fr2> = (0..k).map(|_| Fr2::rand(&mut rng)).collect();
            let circ = MultiInput { xs: xs.clone(), a: Fr2::rand(&mut rng), b: Fr2::rand(&mut rng) };
            let (pk, vk) = Groth16::<E2>::circuit_specific_setup(circ.clone(), &mut rng).unwrap();
            let vk_bytes = ser(&vk);
            let id = format!("bls12381/k{k}/v{rep}");
            let pvk = bls::prepare_pvk_bytes(&vk_bytes);
            let nin = bls::get_public_inputs_num(vk_bytes.len());
            out.push(json!({"id": format!("{id}/prepare"), "op": "prepare", "curve": "bls12381", "vk": hex::encode(&vk_bytes),
                "pvk": pvk.as_ref().ok().map(|p| p.iter().map(hex::encode).collect::<Vec<_>>()),
                "err": pvk.as_ref().err().map(ferr), "nin": nin.as_ref().ok(), "nin_err": nin.as_ref().err().map(ferr)}));
            for (mname, m) in mutations(&mut rng, &vk_bytes, 4) {
                let pv = bls::prepare_pvk_bytes(&m);
                let nn = bls::get_public_inputs_num(m.len());
                out.push(json!({"id": format!("{id}/prepare-{mname}"), "op": "prepare", "curve": "bls12381", "vk": hex::encode(&m),
                    "pvk": pv.as_ref().ok().map(|p| p.iter().map(hex::encode).collect::<Vec<_>>()),
                    "err": pv.as_ref().err().map(ferr), "nin": nn.as_ref().ok(), "nin_err": nn.as_ref().err().map(ferr)}));
            }
            let Ok(pvk) = pvk else { continue };
            let proof = Groth16::<E2>::prove(&pk, circ.clone(), &mut rng).unwrap();
            let mut pp = ser(&proof.a);
            pp.extend(ser(&proof.b));
            pp.extend(ser(&proof.c));
            let inputs: Vec<u8> = xs.iter().flat_map(|x| ser(x)).collect();
            let mut push = |name: &str, inp: &[u8], prf: &[u8]| {
                let r = bls::verify_groth16_in_bytes(&pvk[0], &pvk[1], &pvk[2], &pvk[3], inp, prf);
                out.push(json!({"id": format!("{id}/{name}"), "op": "verify", "curve": "bls12381",
                    "pvk": pvk.iter().map(hex::encode).collect::<Vec<_>>(),
                    "inputs": hex::encode(inp), "proof": hex::encode(prf), "res": bool_res(&r)}));
            };
            push("valid", &inputs, &pp);
            if k > 0 {
                let mut wrong = inputs.clone();
                wrong[0] ^= 1;
                push("input-flip", &wrong, &pp);
            }
            for (mname, m) in mutations(&mut rng, &pp, 3) {
                push(&format!("proof-{mname}"), &inputs, &m);
            }
        }
    }
    out.write(&corpus.join("vectors/groth16/bls12381.jsonl"))?;
    write_readme(corpus, "groth16")?;
    Ok(())
}

// ------------------------------------------------------------------------------------------------
// zkLogin helper functions (address, address seed, field hashing, Move natives)

fn zklogin_fn_vectors(corpus: &Path) -> Result<()> {
    use fastcrypto_zkp::bn254::utils::{gen_address_seed, get_nonce, get_zk_login_address};
    use fastcrypto_zkp::bn254::zk_login::hash_ascii_str_to_field;
    use fastcrypto_zkp::bn254::zk_login_api::{verify_zk_login_id, verify_zk_login_iss};
    use fastcrypto_zkp::zk_login_utils::Bn254FrElement;
    use std::str::FromStr;
    let mut out = Out::new();
    let mut rng = StdRng::seed_from_u64(0x21_0001);
    let strs: Vec<String> = vec![
        "".into(),
        "sub".into(),
        "https://accounts.google.com".into(),
        "a".repeat(32),
        "a".repeat(33),
        "x".repeat(115),
        "x".repeat(116),
        "y".repeat(145),
        "y".repeat(146),
        "é".into(),
        "\u{ff}".into(),
        "\u{100}".into(),
        "tab\there".into(),
        "\u{0}".into(),
    ];
    for (i, s) in strs.iter().enumerate() {
        for max in [0u16, 1, 10, 32, 115, 145, 248, 279, 224, 186, 300] {
            let r = hash_ascii_str_to_field(s, max);
            out.push(json!({"id": format!("ascii/s{i}/m{max}"), "fn": "ascii", "s": s, "max": max,
                "out": r.as_ref().ok().map(le32_fr), "err": r.as_ref().err().map(ferr)}));
        }
    }
    for i in 0..60 {
        let len = rng.gen_range(0..140);
        let s: String = (0..len).map(|_| rng.gen_range(0x20u8..0x7f) as char).collect();
        let max = rng.gen_range(0..200u16);
        let r = hash_ascii_str_to_field(&s, max);
        out.push(json!({"id": format!("ascii/rand{i}"), "fn": "ascii", "s": s, "max": max,
            "out": r.as_ref().ok().map(le32_fr), "err": r.as_ref().err().map(ferr)}));
    }
    // Decimal parsing as Bn254FrElement does it (radix 10, reduced mod r, no leading zero).
    let r_dec = ark_bn254::Fr::MODULUS.to_string();
    let q_dec = ark_bn254::Fq::MODULUS.to_string();
    let mut decs: Vec<String> = vec![
        "0".into(), "00".into(), "01".into(), "1".into(), "".into(), "-1".into(), "+1".into(), " 1".into(),
        "1 ".into(), "12a".into(), r_dec.clone(), q_dec.clone(),
        format!("{r_dec}0"), "1".repeat(100), "9".repeat(80), "٣".into(),
    ];
    for _ in 0..20 {
        let len = rng.gen_range(1..90);
        let mut s: String = (0..len).map(|_| (b'0' + rng.gen_range(0..10u8)) as char).collect();
        if s.starts_with('0') && s.len() > 1 {
            s.replace_range(0..1, "7");
        }
        decs.push(s);
    }
    for (i, s) in decs.iter().enumerate() {
        let fr = Bn254FrElement::from_str(s);
        let fq = fastcrypto_zkp::zk_login_utils::Bn254FqElement::from_str(s);
        out.push(json!({"id": format!("dec/{i}"), "fn": "dec", "s": s,
            "fr": fr.as_ref().ok().map(|f| hex::encode(f.padded())), "fr_err": fr.as_ref().err().map(ferr),
            "fq": fq.as_ref().ok().map(|f| f.to_string()), "fq_err": fq.as_ref().err().map(ferr)}));
    }
    // Address from (seed, iss), padded and unpadded.
    let isss = ["https://accounts.google.com", "https://id.twitch.tv/oauth2", "", "x", &"i".repeat(255), &"i".repeat(256), &"i".repeat(300)];
    for i in 0..40 {
        let seed = if i == 0 {
            "0".to_string()
        } else if i == 1 {
            "1".to_string()
        } else {
            let f = ark_bn254::Fr::rand(&mut rng);
            let mut s = f.to_string();
            if i % 5 == 0 {
                // small seeds exercise unpadded
                s = (rng.gen_range(1u64..u64::MAX) >> rng.gen_range(0..60)).max(1).to_string();
            }
            s
        };
        let iss = isss[i % isss.len()];
        let fr = Bn254FrElement::from_str(&seed).unwrap();
        let padded = get_zk_login_address(&fr, iss).unwrap();
        // unpadded as sui-types try_from_unpadded computes it
        let mut h = fastcrypto::hash::Blake2b256::default();
        use fastcrypto::hash::HashFunction;
        h.update([0x05u8]);
        h.update([iss.len() as u8]);
        h.update(iss.as_bytes());
        h.update(fr.unpadded());
        let unpadded = h.finalize().digest;
        out.push(json!({"id": format!("addr/{i}"), "fn": "addr", "seed": seed, "iss": iss,
            "padded": hex::encode(padded), "unpadded": hex::encode(unpadded)}));
    }
    // gen_address_seed and get_nonce.
    for i in 0..30 {
        let salt = ark_bn254::Fr::rand(&mut rng).to_string();
        let sub = format!("{}", rng.gen_range(0u64..u64::MAX));
        let aud = format!("{}.apps.googleusercontent.com", rng.gen_range(0u64..u64::MAX));
        let r = gen_address_seed(&salt, "sub", &sub, &aud);
        out.push(json!({"id": format!("seed/{i}"), "fn": "seed", "salt": salt, "name": "sub", "value": sub, "aud": aud,
            "out": r.as_ref().ok(), "err": r.as_ref().err().map(ferr)}));
        let pk_len = [32usize, 33, 34, 47, 48][i % 5];
        let pk: Vec<u8> = (0..pk_len).map(|_| rng.r#gen()).collect();
        let max_epoch: u64 = rng.gen_range(0..2000);
        let rnd = ark_bn254::Fr::rand(&mut rng).to_string();
        let n = get_nonce(&pk, max_epoch, &rnd);
        out.push(json!({"id": format!("nonce/{i}"), "fn": "nonce", "pk": hex::encode(&pk), "max_epoch": max_epoch, "rnd": rnd,
            "out": n.as_ref().ok(), "err": n.as_ref().err().map(ferr)}));
    }
    // Move natives check_zklogin_id / check_zklogin_issuer (fastcrypto side): Ok / InvalidProof / other.
    for i in 0..30 {
        let salt_hash = ark_bn254::Fr::rand(&mut rng).to_string();
        let sub = format!("{}", rng.gen_range(0u64..u64::MAX));
        let aud = "client".to_string();
        let iss = "https://accounts.google.com";
        let seed = fastcrypto_zkp::bn254::zk_login::hash_ascii_str_to_field("x", 1).unwrap(); // dummy
        let _ = seed;
        // Build the right address for half of them.
        let good_seed = {
            let a = hash_ascii_str_to_field("sub", 32).unwrap();
            let b = hash_ascii_str_to_field(&sub, 115).unwrap();
            let c = hash_ascii_str_to_field(&aud, 145).unwrap();
            let d: ark_bn254::Fr = (&Bn254FrElement::from_str(&salt_hash).unwrap()).into();
            let fes: Vec<FieldElement> = [a, b, c, d].into_iter().map(FieldElement::from).collect();
            let f: ark_bn254::Fr = fastcrypto_zkp::bn254::poseidon::poseidon_merkle_tree(&fes).unwrap().into();
            f.to_string()
        };
        let addr = get_zk_login_address(&Bn254FrElement::from_str(&good_seed).unwrap(), iss).unwrap();
        let mut addr2 = addr;
        if i % 2 == 1 {
            addr2[0] ^= 1;
        }
        let name = if i % 7 == 6 { "s".repeat(40) } else { "sub".into() };
        let r = verify_zk_login_id(&addr2, &name, &sub, &aud, iss, &salt_hash);
        out.push(json!({"id": format!("checkid/{i}"), "fn": "checkid", "addr": hex::encode(addr2), "name": name,
            "value": sub, "aud": aud, "iss": iss, "pin": salt_hash, "res": match &r { Ok(()) => json!(true), Err(e) => json!(ferr(e)) }}));
        let r2 = verify_zk_login_iss(&addr2, &good_seed, iss);
        out.push(json!({"id": format!("checkiss/{i}"), "fn": "checkiss", "addr": hex::encode(addr2), "seed": good_seed, "iss": iss,
            "res": match &r2 { Ok(()) => json!(true), Err(e) => json!(ferr(e)) }}));
    }
    out.write(&corpus.join("vectors/zklogin/fns.jsonl"))?;
    Ok(())
}

// ------------------------------------------------------------------------------------------------
// zkLogin authenticators from the corpus

/// serde mirror of ZkLoginAuthenticator's BCS, for building mutated variants.
#[derive(Serialize, Deserialize, Clone)]
struct MProof {
    a: Vec<String>,
    b: Vec<Vec<String>>,
    c: Vec<String>,
}
#[derive(Serialize, Deserialize, Clone)]
struct MClaim {
    value: String,
    index_mod_4: u8,
}
#[derive(Serialize, Deserialize, Clone)]
struct MInputs {
    proof_points: MProof,
    iss_base64_details: MClaim,
    header_base64: String,
    address_seed: String,
}
#[derive(Serialize, Deserialize, Clone)]
struct MAuth {
    inputs: MInputs,
    max_epoch: u64,
    #[serde(with = "serde_bytes_compat")]
    user_signature: Vec<u8>,
}
mod serde_bytes_compat {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        Vec::<u8>::deserialize(d)
    }
}

#[derive(Clone)]
struct Found {
    seq: u64,
    epoch: u64,
    id: String,
    sender: SuiAddress,
    auth: Vec<u8>, // BCS after the 0x05 flag
}

struct Scan {
    found: Vec<Found>,
    jwks: BTreeMap<JwkId, (JWK, u64)>, // jwk and the checkpoint seq it was last seen in
}

fn scan_blob(path: &Path) -> Result<Scan> {
    let raw = std::fs::read(path)?;
    if raw.first() != Some(&1) {
        bail!("{}: not a chk blob", path.display());
    }
    let cp: CheckpointData = bcs::from_bytes(&raw[1..]).with_context(|| format!("{}", path.display()))?;
    let seq = cp.checkpoint_summary.sequence_number;
    let epoch = cp.checkpoint_summary.epoch;
    let mut found = Vec::new();
    let mut jwks = BTreeMap::new();
    for (ti, tx) in cp.transactions.iter().enumerate() {
        let data = tx.transaction.data();
        let sender = data.transaction_data().sender();
        for (si, sig) in data.tx_signatures().iter().enumerate() {
            match sig {
                GenericSignature::ZkLoginAuthenticator(_) => {
                    let b = sig.as_ref();
                    found.push(Found { seq, epoch, id: format!("{seq}/tx[{ti}]/sig[{si}]"), sender, auth: b[1..].to_vec() });
                }
                GenericSignature::MultiSig(m) => {
                    for (mi, s) in m.get_sigs().iter().enumerate() {
                        if let sui_types::crypto::CompressedSignature::ZkLogin(z) = s {
                            let b: &[u8] = &z.0;
                            // CompressedSignature::ZkLogin holds the authenticator bytes (flag included).
                            let inner = if b.first() == Some(&0x05) { &b[1..] } else { b };
                            found.push(Found {
                                seq,
                                epoch,
                                id: format!("{seq}/tx[{ti}]/sig[{si}]/multisig[{mi}]"),
                                sender,
                                auth: inner.to_vec(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }
        for o in tx.input_objects.iter().chain(tx.output_objects.iter()) {
            if let Some(mo) = o.data.try_as_move() {
                let t = mo.type_().to_string();
                if t.contains("authenticator_state::AuthenticatorStateInner") {
                    #[derive(Deserialize)]
                    struct Field {
                        _id: [u8; 32],
                        _name: u64,
                        value: sui_types::authenticator_state::AuthenticatorStateInner,
                    }
                    let f: Field = bcs::from_bytes(mo.contents()).context("AuthenticatorStateInner")?;
                    for a in f.value.active_jwks {
                        let e = jwks.entry(a.jwk_id.clone()).or_insert((a.jwk.clone(), seq));
                        if seq >= e.1 {
                            *e = (a.jwk.clone(), seq);
                        }
                    }
                }
            }
        }
    }
    Ok(Scan { found, jwks })
}

fn chk_files(corpus: &Path) -> Result<Vec<PathBuf>> {
    let mut v: Vec<(u64, PathBuf)> = std::fs::read_dir(corpus.join("chk"))?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let p = e.path();
            let n = p.file_name()?.to_str()?.strip_suffix(".chk")?.parse::<u64>().ok()?;
            Some((n, p))
        })
        .collect();
    v.sort();
    Ok(v.into_iter().map(|x| x.1).collect())
}

fn epoch_pvs(corpus: &Path) -> Result<BTreeMap<u64, u64>> {
    let mut m = BTreeMap::new();
    for l in std::fs::read_to_string(corpus.join("epochs.jsonl"))?.lines() {
        let v: Value = serde_json::from_str(l)?;
        m.insert(v["epoch"].as_u64().unwrap(), v["pv"].as_u64().unwrap());
    }
    Ok(m)
}

fn verify_all(auth_bytes: &[u8], sender: SuiAddress, epoch: u64, delta: Option<u64>, jwks: &imbl::HashMap<JwkId, JWK>) -> Value {
    let mut full = vec![0x05u8];
    full.extend_from_slice(auth_bytes);
    let a = match ZkLoginAuthenticator::from_bytes(&full) {
        Ok(a) => a,
        Err(e) => return json!({"parse": ferr(&e)}),
    };
    let unpadded = SuiAddress::try_from_unpadded(&a.inputs).map(|x| hex::encode(x.to_inner()));
    let padded = SuiAddress::try_from_padded(&a.inputs).map(|x| hex::encode(x.to_inner()));
    let mut ext = vec![a.user_signature.scheme().flag()];
    ext.extend(a.user_signature.public_key_bytes());
    let modes = [("v1", ZkLoginCircuitMode::V1Only), ("both", ZkLoginCircuitMode::Both), ("v2", ZkLoginCircuitMode::V2Only)];
    let mut res = serde_json::Map::new();
    res.insert("parse".into(), json!("ok"));
    res.insert("iss".into(), json!(a.get_iss()));
    res.insert("kid".into(), json!(a.inputs.get_kid()));
    res.insert("max_epoch".into(), json!(a.get_max_epoch()));
    res.insert("eph".into(), json!(hex::encode(&ext)));
    res.insert("unpadded".into(), json!(unpadded.ok()));
    res.insert("padded".into(), json!(padded.ok()));
    res.insert("sender_match".into(), json!(unpadded_eq(&a, sender)));
    use sui_types::signature::AuthenticatorTrait;
    let ep = a.verify_user_authenticator_epoch(epoch, delta);
    res.insert("epoch_ok".into(), json!(ep.is_ok()));
    for (name, mode) in modes {
        let r = fastcrypto_zkp::bn254::zk_login_api::verify_zk_login(&a.inputs, a.get_max_epoch(), &ext, jwks, &ZkLoginEnv::Prod, mode);
        res.insert(name.into(), match r { Ok(()) => json!("ok"), Err(e) => json!(ferr(&e)) });
    }
    Value::Object(res)
}

fn unpadded_eq(a: &ZkLoginAuthenticator, sender: SuiAddress) -> &'static str {
    if SuiAddress::try_from_unpadded(&a.inputs).ok() == Some(sender) {
        "unpadded"
    } else if SuiAddress::try_from_padded(&a.inputs).ok() == Some(sender) {
        "padded"
    } else {
        "none"
    }
}

fn dec_add(s: &str, d: u64) -> String {
    let n = num_bigint::BigUint::parse_bytes(s.as_bytes(), 10).unwrap_or_default() + d;
    n.to_str_radix(10)
}

fn zklogin_corpus_vectors(corpus: &Path) -> Result<()> {
    let files = chk_files(corpus)?;
    eprintln!("zklogin: scanning {} blobs", files.len());
    let scans: Vec<Scan> = files.par_iter().map(|p| scan_blob(p)).collect::<Result<_>>()?;
    let mut jwks: BTreeMap<JwkId, (JWK, u64)> = BTreeMap::new();
    let mut found = Vec::new();
    for s in scans {
        found.extend(s.found);
        for (k, v) in s.jwks {
            let e = jwks.entry(k).or_insert(v.clone());
            if v.1 >= e.1 {
                *e = v;
            }
        }
    }
    eprintln!("zklogin: {} authenticators, {} distinct JWKs", found.len(), jwks.len());
    let map: imbl::HashMap<JwkId, JWK> = jwks.iter().map(|(k, v)| (k.clone(), v.0.clone())).collect();
    let empty: imbl::HashMap<JwkId, JWK> = imbl::HashMap::new();
    // JWK file.
    let mut jf = Out::new();
    for (k, (j, seq)) in &jwks {
        jf.push(json!({"iss": k.iss, "kid": k.kid, "kty": j.kty, "e": j.e, "n": j.n, "alg": j.alg, "seen": seq}));
    }
    jf.write(&corpus.join("vectors/zklogin/jwks.jsonld"))?;
    let pvs = epoch_pvs(corpus)?;
    let items: Vec<Vec<Value>> = found
        .par_iter()
        .map(|f| {
            let pv = *pvs.get(&f.epoch).unwrap_or(&141);
            let cfg = sui_protocol_config::ProtocolConfig::get_for_version(pv.into(), sui_protocol_config::Chain::Mainnet);
            let delta = cfg.zklogin_max_epoch_upper_bound_delta();
            let mode = cfg.zklogin_circuit_mode();
            let legacy = cfg.verify_legacy_zklogin_address();
            let mut v = Vec::new();
            let mut item = |name: &str, auth: &[u8], use_jwks: bool| {
                let r = verify_all(auth, f.sender, f.epoch, delta, if use_jwks { &map } else { &empty });
                v.push(json!({"id": format!("{}{}", f.id, name), "seq": f.seq, "epoch": f.epoch, "pv": pv, "delta": delta,
                    "mode": mode, "legacy": legacy, "jwks": use_jwks, "sender": hex::encode(f.sender.to_inner()),
                    "auth": hex::encode(auth), "res": r}));
            };
            item("", &f.auth, true);
            item("/nojwk", &f.auth, false);
            if let Ok(m) = bcs::from_bytes::<MAuth>(&f.auth) {
                let enc = |m: &MAuth| bcs::to_bytes(m).unwrap();
                let mut a = m.clone();
                a.max_epoch += 1;
                item("/maxepoch+1", &enc(&a), true);
                let mut a = m.clone();
                let l = a.user_signature.len();
                a.user_signature[l - 1] ^= 1;
                item("/ephpk", &enc(&a), true);
                let mut a = m.clone();
                a.inputs.address_seed = dec_add(&a.inputs.address_seed, 1);
                item("/seed+1", &enc(&a), true);
                let mut a = m.clone();
                a.inputs.proof_points.a[0] = dec_add(&a.inputs.proof_points.a[0], 1);
                item("/proofA", &enc(&a), true);
                let mut a = m.clone();
                a.inputs.proof_points.b[0][0] = dec_add(&a.inputs.proof_points.b[0][0], 1);
                item("/proofB", &enc(&a), true);
                let mut a = m.clone();
                a.inputs.proof_points.c[2] = "2".into();
                item("/proofCz", &enc(&a), true);
                let mut a = m.clone();
                a.inputs.iss_base64_details.index_mod_4 = (a.inputs.iss_base64_details.index_mod_4 + 1) % 4;
                item("/imod4", &enc(&a), true);
                let mut a = m.clone();
                a.inputs.header_base64.push('A');
                item("/hdr+A", &enc(&a), true);
                let mut a = m.clone();
                a.inputs.address_seed = format!("0{}", a.inputs.address_seed);
                item("/seed0", &enc(&a), true);
            }
            v
        })
        .collect();
    let mut out = Out::new();
    let mut valid = 0;
    for v in items.into_iter().flatten() {
        if v["res"]["v1"] == json!("ok") && !v["id"].as_str().unwrap().contains('/') {
            valid += 1;
        }
        if v["res"]["v1"] == json!("ok") && v["id"].as_str().unwrap().matches('/').count() == 2 {
            valid += 1;
        }
        out.push(v);
    }
    eprintln!("zklogin: {valid} corpus authenticators verify under v1");
    // Split into files of 400 items so bench inputs can be subset evenly.
    let dir = corpus.join("vectors/zklogin");
    for old in std::fs::read_dir(&dir)? {
        let p = old?.path();
        if p.to_string_lossy().ends_with(".items.jsonl") {
            std::fs::remove_file(p)?;
        }
    }
    for (i, chunk) in out.lines.chunks(400).enumerate() {
        let o = Out { lines: chunk.to_vec() };
        o.write(&dir.join(format!("corpus{i:03}.items.jsonl")))?;
    }
    write_readme(corpus, "zklogin")?;
    Ok(())
}

// ------------------------------------------------------------------------------------------------
// zkLogin edge cases the mainnet corpus lacks: JWT header and iss claim JSON (serde_json rules),
// the iss bit-decoder, header and iss length limits, long claims, and JWK moduli. Each item is a
// real corpus authenticator with one field replaced; verdicts come from the same `verify_all`.
// Items whose iss parses get an extra JWK (`xjwk`) for that iss so verification runs past the
// JWK lookup into the input hashing and Groth16.

fn b64u(b: &[u8]) -> String {
    use fastcrypto::rsa::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(b)
}

/// JSON object text of exactly `n` bytes: `{"alg":"RS256","kid":<kid>,"x":"aaaa"}`.
fn header_of_len(kid: &str, n: usize) -> String {
    let base = format!("{{\"alg\":\"RS256\",\"kid\":{},\"x\":\"\"}}", serde_json::to_string(kid).unwrap());
    assert!(n >= base.len());
    format!("{{\"alg\":\"RS256\",\"kid\":{},\"x\":\"{}\"}}", serde_json::to_string(kid).unwrap(), "a".repeat(n - base.len()))
}

/// Claim text of exactly `n` bytes: `"iss":"aaaa",`.
fn claim_of_len(n: usize) -> String {
    let base = "\"iss\":\"\",";
    assert!(n >= base.len());
    format!("\"iss\":\"{}\",", "a".repeat(n - base.len()))
}

fn zklogin_edge_vectors(corpus: &Path) -> Result<()> {
    let dir = corpus.join("vectors/zklogin");
    // Base: the first corpus authenticator that parses and verifies.
    let mut base: Option<Value> = None;
    for l in std::fs::read_to_string(dir.join("corpus000.items.jsonl"))?.lines() {
        let v: Value = serde_json::from_str(l)?;
        if v["res"]["v1"] == json!("ok") && !v["id"].as_str().unwrap().contains("/m") && v["id"].as_str().unwrap().matches('/').count() == 2 {
            base = Some(v);
            break;
        }
    }
    let base = base.ok_or_else(|| anyhow!("no verifying corpus authenticator in corpus000"))?;
    let auth0 = hex::decode(base["auth"].as_str().unwrap())?;
    let m0: MAuth = bcs::from_bytes(&auth0)?;
    let sender = SuiAddress::from_bytes(hex::decode(base["sender"].as_str().unwrap())?)?;
    let epoch = base["epoch"].as_u64().unwrap();
    let delta = base["delta"].as_u64();
    let full0 = {
        let mut f = vec![0x05u8];
        f.extend_from_slice(&auth0);
        ZkLoginAuthenticator::from_bytes(&f)?
    };
    let (base_iss, base_kid) = (full0.get_iss().to_string(), full0.inputs.get_kid().to_string());

    let mut union: imbl::HashMap<JwkId, JWK> = imbl::HashMap::new();
    let mut base_n = String::new();
    for l in std::fs::read_to_string(dir.join("jwks.jsonld"))?.lines() {
        let v: Value = serde_json::from_str(l)?;
        let s = |k: &str| v[k].as_str().unwrap().to_string();
        let id = JwkId::new(s("iss"), s("kid"));
        if id.iss == JwkId::new(base_iss.clone(), base_kid.clone()).iss && id.kid == base_kid {
            base_n = s("n");
        }
        union.insert(id, JWK { kty: s("kty"), e: s("e"), n: s("n"), alg: s("alg") });
    }
    if base_n.is_empty() {
        bail!("base JWK ({base_iss}, {base_kid}) missing from jwks.jsonld");
    }
    let base_hdr = String::from_utf8(<fastcrypto::rsa::Base64UrlUnpadded as fastcrypto::rsa::Encoding>::decode_vec(&m0.inputs.header_base64).map_err(|e| anyhow!("{e}"))?)?;

    let mut out = Out::new();
    // `xn`: Some(n) attaches a JWK with modulus n for the authenticator's own (iss, kid).
    let mut push = |name: &str, m: &MAuth, xn: Option<&str>| {
        let auth = bcs::to_bytes(m).unwrap();
        let mut full = vec![0x05u8];
        full.extend_from_slice(&auth);
        let parsed = ZkLoginAuthenticator::from_bytes(&full).ok();
        let mut map = union.clone();
        let mut xjwk = Value::Null;
        if let (Some(a), Some(n)) = (&parsed, xn) {
            let id = JwkId::new(a.get_iss().to_string(), a.inputs.get_kid().to_string());
            xjwk = json!({"iss": id.iss, "kid": id.kid, "n": n});
            map.insert(id, JWK { kty: "RSA".into(), e: "AQAB".into(), n: n.into(), alg: "RS256".into() });
        }
        let r = verify_all(&auth, sender, epoch, delta, &map);
        out.push(json!({"id": format!("edge/{name}"), "seq": base["seq"], "epoch": epoch, "pv": base["pv"], "delta": delta,
            "mode": base["mode"], "legacy": base["legacy"], "jwks": true, "sender": base["sender"],
            "auth": hex::encode(&auth), "xjwk": xjwk, "res": r}));
    };
    push("base", &m0, Some(&base_n));

    // iss claim texts (index_mod_4 = 0, so the value is plain unpadded base64url of the text).
    let mut claims: Vec<(String, Vec<u8>)> = vec![
        ("plain".into(), b"\"iss\":\"https://accounts.google.com\",".to_vec()),
        ("brace".into(), b"\"iss\":\"https://accounts.google.com\"}".to_vec()),
        ("ws".into(), b" \"iss\" :\t\"https://x\" ,".to_vec()),
        ("ws-end".into(), b"\"iss\":\"https://x\" \n,".to_vec()),
        ("no-end".into(), b"\"iss\":\"https://x\"".to_vec()),
        ("esc-slash".into(), b"\"iss\":\"https:\\/\\/accounts.google.com\",".to_vec()),
        ("esc-u".into(), b"\"iss\":\"\\u0068ttps://x\\u00e9\",".to_vec()),
        ("esc-pair".into(), b"\"iss\":\"a\\ud83d\\ude00b\",".to_vec()),
        ("esc-lone-hi".into(), b"\"iss\":\"a\\ud83db\",".to_vec()),
        ("esc-lone-lo".into(), b"\"iss\":\"a\\ude00b\",".to_vec()),
        ("esc-hi-hi".into(), b"\"iss\":\"a\\ud83d\\ud83d\",".to_vec()),
        ("esc-bad".into(), b"\"iss\":\"a\\x\",".to_vec()),
        ("esc-short".into(), b"\"iss\":\"a\\u12\",".to_vec()),
        ("esc-key".into(), b"\"\\u0069ss\":\"https://k\",".to_vec()),
        ("esc-all".into(), b"\"iss\":\"\\\"\\\\\\/\\b\\f\\n\\r\\t\",".to_vec()),
        ("ctrl".into(), b"\"iss\":\"a\tb\",".to_vec()),
        ("utf8".into(), "\"iss\":\"h\u{e9}llo\u{1F600}\",".as_bytes().to_vec()),
        ("bad-utf8".into(), b"\"iss\":\"a\xff\",".to_vec()),
        ("bad-utf8-other".into(), b"\"x\":\"\xc3\",\"iss\":\"a\",".to_vec()),
        ("dup".into(), b"\"iss\":\"a\",\"iss\":\"b\",".to_vec()),
        ("dup-num".into(), b"\"iss\":\"a\",\"iss\":1,".to_vec()),
        ("dup-then-str".into(), b"\"iss\":1,\"iss\":\"c\",".to_vec()),
        ("num".into(), b"\"iss\":12,".to_vec()),
        ("null".into(), b"\"iss\":null,".to_vec()),
        ("missing".into(), b"\"sub\":\"x\",".to_vec()),
        ("empty".into(), b"}".to_vec()),
        ("comma-only".into(), b",".to_vec()),
        ("trailing-comma".into(), b"\"iss\":\"a\",,".to_vec()),
        ("nested".into(), b"\"a\":{\"iss\":\"in\",\"b\":[1,2.5e3,{\"c\":null}]},\"iss\":\"out\",".to_vec()),
        ("only-nested".into(), b"\"a\":{\"iss\":\"in\"},".to_vec()),
        ("num-inf".into(), b"\"n\":1e400,\"iss\":\"a\",".to_vec()),
        ("num-max".into(), b"\"n\":1.7976931348623157e308,\"iss\":\"a\",".to_vec()),
        ("num-max+".into(), b"\"n\":1.7976931348623159e308,\"iss\":\"a\",".to_vec()),
        ("num-tiny".into(), b"\"n\":1e-400,\"iss\":\"a\",".to_vec()),
        ("num-negzero".into(), b"\"n\":-0,\"iss\":\"a\",".to_vec()),
        ("num-lead0".into(), b"\"n\":01,\"iss\":\"a\",".to_vec()),
        ("num-dot".into(), b"\"n\":1.,\"iss\":\"a\",".to_vec()),
        ("num-exp".into(), b"\"n\":1e,\"iss\":\"a\",".to_vec()),
        ("num-minus".into(), b"\"n\":-,\"iss\":\"a\",".to_vec()),
        ("num-plus".into(), b"\"n\":+1,\"iss\":\"a\",".to_vec()),
        ("num-u64max".into(), b"\"n\":18446744073709551616,\"iss\":\"a\",".to_vec()),
        ("lit-bad".into(), b"\"n\":tru,\"iss\":\"a\",".to_vec()),
        ("lit-ok".into(), b"\"n\":[true,false,null],\"iss\":\"a\",".to_vec()),
        ("ms".into(), b"\"iss\":\"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0\",".to_vec()),
        ("ms-short".into(), b"\"iss\":\"https://login.microsoftonline.com//v2.0\",".to_vec()),
    ];
    let big_int = format!("\"n\":{},\"iss\":\"a\",", "9".repeat(400));
    claims.push(("num-bigint".into(), big_int.into_bytes()));
    for d in [125usize, 126, 127, 128] {
        claims.push((format!("depth{d}"), format!("\"a\":{}{},\"iss\":\"a\",", "[".repeat(d), "]".repeat(d)).into_bytes()));
    }
    // Lengths around the v1 iss_base64 limit (224 chars) and the v2 decoded limit (186 chars).
    for n in [168usize, 169, 186, 187] {
        claims.push((format!("len{n}"), claim_of_len(n).into_bytes()));
    }
    // Long claims: decoded strings larger than any header-sized scratch, and past 4096 chars.
    for n in [1000usize, 2000, 3000, 3100, 4000, 6000] {
        claims.push((format!("long{n}"), claim_of_len(n).into_bytes()));
    }
    for (name, text) in &claims {
        let mut m = m0.clone();
        m.inputs.iss_base64_details = MClaim { value: b64u(text), index_mod_4: 0 };
        push(&format!("claim/{name}"), &m, Some(&base_n));
    }
    // The iss value as raw text (bit decoder rules).
    for (name, v, i) in [
        ("short1", "A", 0u8),
        ("bad-char", "eyJ+", 0),
        ("pad", "eyJ=", 0),
        ("multibyte", "\u{e9}\u{e9}", 0),
        ("idx3", "eyJpc3MiOiJhIiw", 3),
        ("idx1-len", "eyJpc3MiOiJhIiw", 1),
        ("idx2-len", "eyJpc3MiOiJhIiw", 2),
        ("off0", "eyJpc3MiOiJhIiwi", 0),
        ("len256-idx0", &"A".repeat(256), 0),
        ("len255-idx1", &"A".repeat(255), 1),
        ("len255-idx2", &"A".repeat(255), 2),
    ] {
        let mut m = m0.clone();
        m.inputs.iss_base64_details = MClaim { value: v.to_string(), index_mod_4: i };
        push(&format!("issraw/{name}"), &m, Some(&base_n));
    }

    // JWT header JSON (decoded text; the base header keeps the real kid so the base JWK applies).
    let kid_json = serde_json::to_string(&base_kid).unwrap();
    let hdrs: Vec<(String, Vec<u8>)> = vec![
        ("orig".into(), base_hdr.clone().into_bytes()),
        ("min".into(), format!("{{\"alg\":\"RS256\",\"kid\":{kid_json}}}").into_bytes()),
        ("typ-null".into(), format!("{{\"alg\":\"RS256\",\"kid\":{kid_json},\"typ\":null}}").into_bytes()),
        ("typ-num".into(), format!("{{\"alg\":\"RS256\",\"kid\":{kid_json},\"typ\":1}}").into_bytes()),
        ("typ-dup".into(), format!("{{\"alg\":\"RS256\",\"kid\":{kid_json},\"typ\":\"a\",\"typ\":\"b\"}}").into_bytes()),
        ("alg-dup".into(), format!("{{\"alg\":\"RS256\",\"alg\":\"RS256\",\"kid\":{kid_json}}}").into_bytes()),
        ("kid-dup".into(), format!("{{\"alg\":\"RS256\",\"kid\":{kid_json},\"kid\":{kid_json}}}").into_bytes()),
        ("alg-rs384".into(), format!("{{\"alg\":\"RS384\",\"kid\":{kid_json}}}").into_bytes()),
        ("alg-num".into(), format!("{{\"alg\":256,\"kid\":{kid_json}}}").into_bytes()),
        ("alg-missing".into(), format!("{{\"kid\":{kid_json}}}").into_bytes()),
        ("kid-missing".into(), b"{\"alg\":\"RS256\"}".to_vec()),
        ("esc-key".into(), format!("{{\"\\u0061lg\":\"RS256\",\"kid\":{kid_json}}}").into_bytes()),
        ("esc-val".into(), format!("{{\"alg\":\"RS\\u0032\\u00356\",\"kid\":{kid_json}}}").into_bytes()),
        ("unknown-nested".into(), format!("{{\"x\":{{\"y\":[1,{{\"z\":null}},\"s\"]}},\"alg\":\"RS256\",\"kid\":{kid_json}}}").into_bytes()),
        ("unknown-deep".into(), format!("{{\"x\":{}{},\"alg\":\"RS256\",\"kid\":{kid_json}}}", "[".repeat(300), "]".repeat(300)).into_bytes()),
        ("unknown-deep90k".into(), format!("{{\"x\":{}{},\"alg\":\"RS256\",\"kid\":{kid_json}}}", "[".repeat(90_000), "]".repeat(90_000)).into_bytes()),
        ("unknown-badutf8".into(), [b"{\"x\":\"\xff\xfe\",".as_slice(), format!("\"alg\":\"RS256\",\"kid\":{kid_json}}}").as_bytes()].concat()),
        ("unknown-lone-surrogate".into(), format!("{{\"x\":\"\\ud800\",\"alg\":\"RS256\",\"kid\":{kid_json}}}").into_bytes()),
        ("unknown-num-inf".into(), format!("{{\"x\":1e400,\"alg\":\"RS256\",\"kid\":{kid_json}}}").into_bytes()),
        ("unknown-num-bad".into(), format!("{{\"x\":01,\"alg\":\"RS256\",\"kid\":{kid_json}}}").into_bytes()),
        ("kid-badutf8".into(), b"{\"alg\":\"RS256\",\"kid\":\"\xff\"}".to_vec()),
        ("kid-lone-surrogate".into(), b"{\"alg\":\"RS256\",\"kid\":\"\\udc00\"}".to_vec()),
        ("array".into(), format!("[\"RS256\",{kid_json},null]").into_bytes()),
        ("array-typ".into(), format!("[\"RS256\",{kid_json},\"JWT\"]").into_bytes()),
        ("array-2".into(), format!("[\"RS256\",{kid_json}]").into_bytes()),
        ("array-4".into(), format!("[\"RS256\",{kid_json},null,1]").into_bytes()),
        ("array-trailing-comma".into(), format!("[\"RS256\",{kid_json},null,]").into_bytes()),
        ("ws".into(), format!(" \n{{ \"alg\" : \"RS256\" ,\r\"kid\":{kid_json} }}\t").into_bytes()),
        ("trailing".into(), format!("{{\"alg\":\"RS256\",\"kid\":{kid_json}}}x").into_bytes()),
        ("trailing-comma".into(), format!("{{\"alg\":\"RS256\",\"kid\":{kid_json},}}").into_bytes()),
        ("bom".into(), [b"\xef\xbb\xbf".as_slice(), format!("{{\"alg\":\"RS256\",\"kid\":{kid_json}}}").as_bytes()].concat()),
        ("not-object".into(), b"\"RS256\"".to_vec()),
        ("empty-object".into(), b"{}".to_vec()),
        ("len186".into(), header_of_len(&base_kid, 186).into_bytes()),
        ("len187".into(), header_of_len(&base_kid, 187).into_bytes()),
        ("len209".into(), header_of_len(&base_kid, 209).into_bytes()),
        ("len210".into(), header_of_len(&base_kid, 210).into_bytes()),
        ("len3000".into(), header_of_len(&base_kid, 3000).into_bytes()),
    ];
    for (name, text) in &hdrs {
        let mut m = m0.clone();
        m.inputs.header_base64 = b64u(text);
        push(&format!("hdr/{name}"), &m, Some(&base_n));
    }
    for (name, v) in [("short1", "e"), ("pad", "eyJ="), ("noncanon", "eyJhbGciOiJSUzI1NiJ9"), ("bad-char", "eyJ+")] {
        let mut m = m0.clone();
        m.inputs.header_base64 = v.to_string();
        push(&format!("hdrraw/{name}"), &m, Some(&base_n));
    }

    // JWK moduli for the base authenticator's (iss, kid).
    let base_mod = <fastcrypto::rsa::Base64UrlUnpadded as fastcrypto::rsa::Encoding>::decode_vec(&base_n).map_err(|e| anyhow!("{e}"))?;
    let lead0 = [vec![0u8; 3], base_mod.clone()].concat();
    let many0 = [vec![0u8; 2000], vec![5u8]].concat();
    let bits2049 = [vec![1u8], vec![0xffu8; 256]].concat();
    let bits8192 = vec![0xffu8; 1024];
    let bits8192z = [vec![0u8], vec![0xffu8; 1024]].concat();
    let bits8193 = [vec![1u8], vec![0xffu8; 1024]].concat();
    let huge = vec![0x7fu8; 9000];
    let mods: Vec<(&str, String)> = vec![
        ("lead0", b64u(&lead0)),
        ("many0", b64u(&many0)),
        ("empty", String::new()),
        ("zero", b64u(&[0u8])),
        ("bits2049", b64u(&bits2049)),
        ("bits8192", b64u(&bits8192)),
        ("bits8192z", b64u(&bits8192z)),
        ("bits8193", b64u(&bits8193)),
        ("huge", b64u(&huge)),
        ("len1", "A".into()),
        ("noncanon", "AB".into()),
        ("pad", "AA==".into()),
        ("bad-char", "AA+A".into()),
        ("std-alphabet", format!("{}/", &base_n[..base_n.len() - 1])),
    ];
    for (name, n) in &mods {
        push(&format!("jwk/{name}"), &m0, Some(n));
    }
    out.write(&dir.join("edge.items.jsonl"))?;
    Ok(())
}

fn write_readme(corpus: &Path, suite: &str) -> Result<()> {
    let p = corpus.join(format!("vectors/{suite}/README.md"));
    std::fs::write(
        p,
        format!(
            "Written by tools/truth/crypto-zk (`zui-zk-truth vectors`), fastcrypto rev da61cd46, sui mainnet-v1.83.1.\n\
             Formats: tools/truth/crypto-zk/README.md (suite `{suite}`).\n"
        ),
    )?;
    Ok(())
}

// ------------------------------------------------------------------------------------------------
// Bench

fn passes(iters: usize, mut f: impl FnMut() -> Result<()>) -> Result<Vec<u128>> {
    f()?;
    let mut v = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        f()?;
        v.push(t.elapsed().as_nanos());
    }
    v.sort();
    Ok(v)
}

fn report(name: &str, unit: &str, units: u64, p: &[u128]) {
    let med = p[p.len() / 2] as f64;
    println!(
        "{}",
        json!({"impl": "rust", "bench": name, "unit": unit, "units": units, "ns_per_unit": med / units as f64})
    );
}

fn read_list(list: &str) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for f in std::fs::read_to_string(list)?.lines().filter(|l| !l.is_empty()) {
        for l in std::fs::read_to_string(f)?.lines() {
            out.push(serde_json::from_str(l)?);
        }
    }
    Ok(out)
}

fn cmd_bench(args: &[String]) -> Result<()> {
    let name = args.first().ok_or_else(|| anyhow!("bench <name>"))?.clone();
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
    let list = list.ok_or_else(|| anyhow!("--list FILE"))?;
    let items = read_list(&list)?;
    match name.as_str() {
        "poseidon" => {
            use fastcrypto_zkp::bn254::poseidon::poseidon_bytes;
            let ins: Vec<Vec<Vec<u8>>> = items
                .iter()
                .filter(|v| v["fn"] == "bytes" && v["out"].is_string())
                .map(|v| v["in"].as_array().unwrap().iter().map(|h| hex::decode(h.as_str().unwrap()).unwrap()).collect())
                .collect();
            let p = passes(iters, || {
                for x in &ins {
                    std::hint::black_box(poseidon_bytes(x)?);
                }
                Ok(())
            })?;
            report("poseidon", "hash", ins.len() as u64, &p);
        }
        "groth16-verify" => {
            use fastcrypto_zkp::bn254::api as bn;
            let vs: Vec<[Vec<u8>; 6]> = items
                .iter()
                .filter(|v| v["op"] == "verify" && v["res"] == json!(true))
                .map(|v| {
                    let p = v["pvk"].as_array().unwrap();
                    let h = |x: &Value| hex::decode(x.as_str().unwrap()).unwrap();
                    [h(&p[0]), h(&p[1]), h(&p[2]), h(&p[3]), h(&v["inputs"]), h(&v["proof"])]
                })
                .collect();
            let p = passes(iters, || {
                for v in &vs {
                    std::hint::black_box(bn::verify_groth16_in_bytes(&v[0], &v[1], &v[2], &v[3], &v[4], &v[5])?);
                }
                Ok(())
            })?;
            report("groth16-verify", "proof", vs.len() as u64, &p);
            let ks: Vec<Vec<u8>> = items
                .iter()
                .filter(|v| v["op"] == "prepare" && v["pvk"].is_array())
                .map(|v| hex::decode(v["vk"].as_str().unwrap()).unwrap())
                .collect();
            let p = passes(iters, || {
                for k in &ks {
                    std::hint::black_box(bn::prepare_pvk_bytes(k)?);
                }
                Ok(())
            })?;
            report("groth16-prepare", "vk", ks.len() as u64, &p);
        }
        "zklogin-verify" => {
            // jwks file sits next to the item files
            let first = std::fs::read_to_string(&list)?.lines().next().unwrap().to_string();
            let dir = Path::new(&first).parent().unwrap().to_path_buf();
            let mut map: imbl::HashMap<JwkId, JWK> = imbl::HashMap::new();
            for l in std::fs::read_to_string(dir.join("jwks.jsonld"))?.lines() {
                let v: Value = serde_json::from_str(l)?;
                let s = |k: &str| v[k].as_str().unwrap().to_string();
                map.insert(JwkId { iss: s("iss"), kid: s("kid") }, JWK { kty: s("kty"), e: s("e"), n: s("n"), alg: s("alg") });
            }
            let auths: Vec<Vec<u8>> = items
                .iter()
                .filter(|v| v["res"]["v1"] == "ok" && v["jwks"] == true)
                .map(|v| {
                    let mut b = vec![0x05u8];
                    b.extend(hex::decode(v["auth"].as_str().unwrap()).unwrap());
                    b
                })
                .collect();
            // Full proof-side verification from bytes: parse + init + verify_zk_login (v1), no cache.
            let p = passes(iters, || {
                for b in &auths {
                    let a = ZkLoginAuthenticator::from_bytes(b)?;
                    let mut ext = vec![a.user_signature.scheme().flag()];
                    ext.extend(a.user_signature.public_key_bytes());
                    fastcrypto_zkp::bn254::zk_login_api::verify_zk_login(
                        &a.inputs,
                        a.get_max_epoch(),
                        &ext,
                        &map,
                        &ZkLoginEnv::Prod,
                        ZkLoginCircuitMode::V1Only,
                    )?;
                }
                Ok(())
            })?;
            report("zklogin-verify", "sig", auths.len() as u64, &p);
        }
        n => bail!("unknown bench {n}"),
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------
// Poseidon constants for Zig: parsed from fastcrypto-zkp's constants.rs (the strings neptune loads).

fn cmd_gen_poseidon(args: &[String]) -> Result<()> {
    let out_path = args.first().ok_or_else(|| anyhow!("gen-poseidon <out.zig> [constants.rs]"))?;
    let src_path = args.get(1).cloned().unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap();
        format!("{home}/.cargo/git/checkouts/fastcrypto-9995504e1c5344d5/da61cd4/fastcrypto-zkp/src/bn254/poseidon/constants.rs")
    });
    let src = std::fs::read_to_string(&src_path)?;
    // The constants() function body is `(vec![vec![..]..], vec![vec![vec![..]..]..])`.
    let body = &src[src.find("fn constants()").ok_or_else(|| anyhow!("no fn constants"))?..];
    let nums: Vec<&str> = {
        let mut v = Vec::new();
        let mut rest = body;
        while let Some(i) = rest.find('"') {
            let r2 = &rest[i + 1..];
            let j = r2.find('"').unwrap();
            v.push(&r2[..j]);
            rest = &r2[j + 1..];
        }
        v
    };
    // Shape: constants for t = 2..=17: (8 + RP[t-2]) * t entries; then matrices t x t for t = 2..=17.
    let rp = [56usize, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68];
    let mut idx = 0;
    let mut cs: Vec<Vec<ark_bn254::Fr>> = Vec::new();
    for t in 2..=17usize {
        let n = (8 + rp[t - 2]) * t;
        cs.push(nums[idx..idx + n].iter().map(|s| parse_fr(s)).collect::<Result<_>>()?);
        idx += n;
    }
    let mut ms: Vec<Vec<ark_bn254::Fr>> = Vec::new();
    for t in 2..=17usize {
        let n = t * t;
        ms.push(nums[idx..idx + n].iter().map(|s| parse_fr(s)).collect::<Result<_>>()?);
        idx += n;
    }
    if idx != nums.len() {
        bail!("constants.rs: {} strings, consumed {}", nums.len(), idx);
    }
    let mut z = String::new();
    z.push_str("//! Generated by `zui-zk-truth gen-poseidon` from fastcrypto-zkp da61cd46\n");
    z.push_str("//! src/bn254/poseidon/constants.rs (the circomlib Poseidon constants neptune loads).\n");
    z.push_str("//! Montgomery form (R = 2^256) little-endian u64 limbs. Do not edit.\n\n");
    z.push_str("pub const partial_rounds = [16]u8{ ");
    for r in rp {
        z.push_str(&format!("{r}, "));
    }
    z.push_str("};\n\n");
    let mont = |f: &ark_bn254::Fr| -> String {
        // ark keeps Fr in Montgomery form internally: f.0 .0 is the limb array.
        let l = (f.0).0;
        format!(".{{ 0x{:016x}, 0x{:016x}, 0x{:016x}, 0x{:016x} }}", l[0], l[1], l[2], l[3])
    };
    for (i, c) in cs.iter().enumerate() {
        z.push_str(&format!("pub const c{} = [_][4]u64{{\n", i + 2));
        for f in c {
            z.push_str(&format!("    {},\n", mont(f)));
        }
        z.push_str("};\n");
    }
    for (i, m) in ms.iter().enumerate() {
        z.push_str(&format!("pub const m{} = [_][4]u64{{\n", i + 2));
        for f in m {
            z.push_str(&format!("    {},\n", mont(f)));
        }
        z.push_str("};\n");
    }
    // Optimized tables (the Poseidon paper's appendix B, as neptune's OptimizedStatic does):
    // partial-round constants folded forward so each partial round adds one scalar to state[0],
    // and each partial-round matrix factored as sparse * diag(1, A) with the dense part pushed
    // back into the last first-half full round (matrix P).
    z.push_str("\n// Optimized tables: cf = full-round constants (8 rounds x t), cp = partial-round scalars,\n");
    z.push_str("// p = matrix of full round 3, sp = per partial round [m00, w[0..t-1], v[0..t-1]].\n");
    for (i, (c, m)) in cs.iter().zip(ms.iter()).enumerate() {
        let t = i + 2;
        let (cf, cp, pm, sp) = poseidon_optimize(t, rp[i], c, m)?;
        for (name, v) in [("cf", &cf), ("cp", &cp), ("p", &pm), ("sp", &sp)] {
            z.push_str(&format!("pub const {}{} = [_][4]u64{{\n", name, t));
            for f in v.iter() {
                z.push_str(&format!("    {},\n", mont(f)));
            }
            z.push_str("};\n");
        }
    }
    std::fs::write(out_path, z)?;
    eprintln!("wrote {out_path}: {} constants, {} matrix entries", cs.iter().map(|c| c.len()).sum::<usize>(), ms.iter().map(|m| m.len()).sum::<usize>());
    Ok(())
}

type PFr = ark_bn254::Fr;

/// Solves A x = b over Fr (Gauss-Jordan); A is n x n row-major.
fn solve(n: usize, a: &[PFr], b: &[PFr]) -> Result<Vec<PFr>> {
    use ark_ff::Zero;
    let mut m: Vec<Vec<PFr>> = (0..n).map(|i| {
        let mut r = a[i * n..(i + 1) * n].to_vec();
        r.push(b[i]);
        r
    }).collect();
    for col in 0..n {
        let piv = (col..n).find(|&r| !m[r][col].is_zero()).ok_or_else(|| anyhow!("singular"))?;
        m.swap(col, piv);
        let inv = m[col][col].inverse().unwrap();
        for k in col..=n {
            m[col][k] *= inv;
        }
        for r in 0..n {
            if r != col && !m[r][col].is_zero() {
                let f = m[r][col];
                for k in col..=n {
                    let x = m[col][k] * f;
                    m[r][k] -= x;
                }
            }
        }
    }
    Ok(m.into_iter().map(|r| r[n]).collect())
}

fn poseidon_optimize(t: usize, rp: usize, c: &[PFr], m: &[PFr]) -> Result<(Vec<PFr>, Vec<PFr>, Vec<PFr>, Vec<PFr>)> {
    use ark_ff::{One, Zero};
    let mv = |mat: &[PFr], x: &[PFr]| -> Vec<PFr> {
        (0..t).map(|i| (0..t).map(|j| mat[i * t + j] * x[j]).sum()).collect()
    };
    let mut rc: Vec<Vec<PFr>> = (0..8 + rp).map(|r| c[r * t..(r + 1) * t].to_vec()).collect();
    // Fold: S0(s + c) = S0(s + c0 e0) + (0, c[1..]); push M (0, c[1..]) into the next round.
    for k in 4..4 + rp {
        let mut rest = rc[k].clone();
        rest[0] = PFr::zero();
        let add = mv(m, &rest);
        for j in 1..t {
            rc[k][j] = PFr::zero();
        }
        for j in 0..t {
            rc[k + 1][j] += add[j];
        }
    }
    let mut cf = Vec::new();
    for r in (0..4).chain(4 + rp..8 + rp) {
        cf.extend(rc[r].iter().copied());
    }
    let cp: Vec<PFr> = (4..4 + rp).map(|k| rc[k][0]).collect();
    // Factor backwards: X = S_k * diag(1, Xhat); next X = diag(1, Xhat) * M.
    let mut x = m.to_vec();
    let mut sp_rev: Vec<Vec<PFr>> = Vec::new();
    for _ in 0..rp {
        let n = t - 1;
        let xhat_t: Vec<PFr> = (0..n * n).map(|idx| {
            let (i, j) = (idx / n, idx % n);
            x[(j + 1) * t + (i + 1)] // transpose
        }).collect();
        let x0r: Vec<PFr> = (1..t).map(|j| x[j]).collect();
        let w = solve(n, &xhat_t, &x0r)?;
        let mut row = vec![x[0]];
        row.extend(w);
        row.extend((1..t).map(|i| x[i * t]));
        sp_rev.push(row);
        // D * M with D = diag(1, Xhat)
        let mut d = vec![PFr::zero(); t * t];
        d[0] = PFr::one();
        for i in 1..t {
            for j in 1..t {
                d[i * t + j] = x[i * t + j];
            }
        }
        let mut nx = vec![PFr::zero(); t * t];
        for i in 0..t {
            for j in 0..t {
                nx[i * t + j] = (0..t).map(|k| d[i * t + k] * m[k * t + j]).sum();
            }
        }
        x = nx;
    }
    let sp: Vec<PFr> = sp_rev.into_iter().rev().flatten().collect();
    Ok((cf, cp, x, sp))
}

fn parse_fr(s: &str) -> Result<ark_bn254::Fr> {
    use std::str::FromStr;
    if let Some(h) = s.strip_prefix("0x") {
        let b = num_bigint::BigUint::parse_bytes(h.as_bytes(), 16).ok_or_else(|| anyhow!("hex {s}"))?;
        return Ok(ark_bn254::Fr::from_le_bytes_mod_order(&b.to_bytes_le()));
    }
    ark_bn254::Fr::from_str(s).map_err(|_| anyhow!("bad constant {s}"))
}
