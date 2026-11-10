//! zui-truth-sui-natives: ground truth for the sui-natives lane (README.md has the formats).
//!
//!   zui-truth-sui-natives natives <corpus>     vectors/natives/<group>.jsonl
//!   zui-truth-sui-natives framework <corpus>   vectors/framework/framework.jsonl
//!   zui-truth-sui-natives cut <v0|v1|v2|v3> <pv> [corpus]
//!                                              vectors/natives/cuts/<vN or vN-pv>/<group>.jsonl:
//!                                              every natives script again through an older
//!                                              execution cut at pv and its framework (cut.rs)
//!
//! Every native call runs through Mysten's own move-vm-runtime and sui-move-natives (1.83.1).
//! Inputs are synthetic (seeded) or taken from the input side of other lanes' vector files; the
//! outcomes and costs always come from the Rust natives.

mod cut;
mod nitro;
mod validator;
mod direct;
mod objrt;
mod zkl;
mod vm;
#[cfg(feature = "sui_184")]
mod v142;

use anyhow::{Context, Result, anyhow};
use fastcrypto::traits::{KeyPair as _, Signer, ToFromBytes};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde_json::{Value as J, json};
use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use vm::{Call, Ctx, DEFAULT_CTX, Env, Outcome};

const BIG: u64 = 1_000_000_000_000;
// The built-in framework's protocol version (the tree's MAX_PROTOCOL_VERSION).
#[cfg(not(feature = "sui_184"))]
const PV_MAX: u64 = 141;
#[cfg(feature = "sui_184")]
const PV_MAX: u64 = 142;
const PV_MIN_V4: u64 = 119;

struct Item {
    id: String,
    pv: u64,
    ctx: Option<Ctx>,
    calls: Vec<Call>,
    env: Option<vm::ObjEnv>,
}

fn bv(b: &[u8]) -> Vec<u8> {
    bcs::to_bytes(&b.to_vec()).unwrap()
}
fn bvv(b: &[Vec<u8>]) -> Vec<u8> {
    bcs::to_bytes(&b.to_vec()).unwrap()
}
fn b8(x: u8) -> Vec<u8> {
    vec![x]
}
fn b64(x: u64) -> Vec<u8> {
    x.to_le_bytes().to_vec()
}
fn bbool(x: bool) -> Vec<u8> {
    vec![x as u8]
}
fn tag(s: &str) -> move_core_types::language_storage::TypeTag {
    sui_types::parse_sui_type_tag(s).unwrap_or_else(|e| panic!("type tag {s}: {e}"))
}
fn call(addr: u16, module: &'static str, func: &'static str, ty_args: Vec<&str>, args: Vec<Vec<u8>>) -> Call {
    Call { addr, module, func, ty_args: ty_args.into_iter().map(tag).collect(), args, budget: BIG, write: None, shapes: vec![] }
}
fn rnd(rng: &mut ChaCha20Rng, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rng.fill_bytes(&mut v);
    v
}
fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("hex {s}: {e}"))
}

struct Gen {
    items: BTreeMap<String, Vec<Item>>, // group -> items
    rng: ChaCha20Rng,
    corpus: PathBuf,
}

impl Gen {
    fn push(&mut self, group: &str, id: String, calls: Vec<Call>) {
        self.push_full(group, id, PV_MAX, None, calls)
    }
    fn push_full(&mut self, group: &str, id: String, pv: u64, ctx: Option<Ctx>, calls: Vec<Call>) {
        self.items.entry(group.to_string()).or_default().push(Item { id, pv, ctx, calls, env: None });
    }
    fn lines(&self, rel: &str) -> Vec<J> {
        let p = self.corpus.join(rel);
        let f = std::fs::File::open(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        std::io::BufReader::new(f).lines().map(|l| serde_json::from_str(&l.unwrap()).unwrap()).collect()
    }
}

const LENS: &[usize] = &[0, 1, 2, 31, 32, 33, 55, 56, 63, 64, 65, 127, 128, 129, 135, 136, 137, 200, 255, 256, 1000, 4096, 10_000];

fn gen_hash(g: &mut Gen) {
    for &n in LENS {
        let d = rnd(&mut g.rng, n);
        for (a, m, f) in [(1u16, "hash", "sha2_256"), (1, "hash", "sha3_256"), (2, "hash", "blake2b256"), (2, "hash", "keccak256")] {
            g.push("hash", format!("{m}/{f}/{a}/{n}"), vec![call(a, m, f, vec![], vec![bv(&d)])]);
        }
        let k = rnd(&mut g.rng, n % 200);
        g.push("hash", format!("hmac/{n}"), vec![call(2, "hmac", "hmac_sha3_256", vec![], vec![bv(&k), bv(&d)])]);
    }
}

fn gen_string(g: &mut Gen) {
    let samples: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"hello".to_vec(),
        "héllo wörld".as_bytes().to_vec(),
        "日本語テキスト".as_bytes().to_vec(),
        "😀a😀".as_bytes().to_vec(),
        vec![0xff],
        vec![0xc3],
        vec![0xe2, 0x82],
        vec![0xed, 0xa0, 0x80],
        vec![0xf4, 0x90, 0x80, 0x80],
        vec![0xc0, 0x80],
        b"abcabcabd".to_vec(),
        b"aaaaab".to_vec(),
    ];
    for (i, s) in samples.iter().enumerate() {
        g.push("string", format!("check_utf8/{i}"), vec![call(1, "string", "internal_check_utf8", vec![], vec![bv(s)])]);
        if std::str::from_utf8(s).is_err() {
            continue; // Move checks utf8 before the other natives; they assume it
        }
        for j in 0..=s.len() + 1 {
            g.push("string", format!("is_char_boundary/{i}/{j}"), vec![call(1, "string", "internal_is_char_boundary", vec![], vec![bv(s), b64(j as u64)])]);
        }
        let st = std::str::from_utf8(s).unwrap();
        for a in 0..=s.len() {
            for b in a..=s.len() {
                if st.is_char_boundary(a) && st.is_char_boundary(b) {
                    g.push("string", format!("sub_string/{i}/{a}/{b}"), vec![call(1, "string", "internal_sub_string", vec![], vec![bv(s), b64(a as u64), b64(b as u64)])]);
                }
            }
        }
        for r in [&b""[..], b"a", b"abd", b"c", b"\xc3\xb6", b"zz", "😀".as_bytes(), b"ab"] {
            g.push("string", format!("index_of/{i}/{}", hex::encode(r)), vec![call(1, "string", "internal_index_of", vec![], vec![bv(s), bv(r)])]);
        }
    }
}

/// (type tag, BCS of a value of it)
fn sample_values(rng: &mut ChaCha20Rng) -> Vec<(&'static str, Vec<u8>)> {
    let mut v: Vec<(&'static str, Vec<u8>)> = vec![
        ("bool", vec![1]),
        ("u8", vec![7]),
        ("u16", 0xbeefu16.to_le_bytes().to_vec()),
        ("u32", 0xdeadbeefu32.to_le_bytes().to_vec()),
        ("u64", u64::MAX.to_le_bytes().to_vec()),
        ("u128", (u128::MAX - 5).to_le_bytes().to_vec()),
        ("u256", vec![0xab; 32]),
        ("address", vec![0x11; 32]),
        ("vector<u8>", bv(&[1, 2, 3])),
        ("vector<u8>", bv(&[])),
        ("vector<u64>", bcs::to_bytes(&vec![1u64, 2, 3]).unwrap()),
        ("vector<vector<u8>>", bvv(&[vec![1], vec![], vec![2, 3]])),
        ("vector<bool>", bcs::to_bytes(&vec![true, false]).unwrap()),
        ("vector<address>", bcs::to_bytes(&vec![[1u8; 32], [2u8; 32]]).unwrap()),
        ("0x1::string::String", bv(b"move")),
        ("0x1::option::Option<u64>", bcs::to_bytes(&Some(5u64)).unwrap()),
        ("0x1::option::Option<u64>", bcs::to_bytes(&None::<u64>).unwrap()),
        ("0x2::object::ID", vec![0x22; 32]),
        ("0x2::object::UID", vec![0x33; 32]),
        ("0x1::type_name::TypeName", bv(b"0000000000000000000000000000000000000000000000000000000000000002::sui::SUI")),
        ("0x2::balance::Balance<0x2::sui::SUI>", 1234u64.to_le_bytes().to_vec()),
        ("0x2::sui::SUI", vec![0]),
    ];
    let big = rnd(rng, 3000);
    v.push(("vector<u8>", bv(&big)));
    let many: Vec<u64> = (0..300).collect();
    v.push(("vector<u64>", bcs::to_bytes(&many).unwrap()));
    v
}

fn gen_bcs(g: &mut Gen) {
    let vals = sample_values(&mut g.rng);
    for (i, (t, b)) in vals.iter().enumerate() {
        g.push("bcs", format!("to_bytes/{i}/{t}"), vec![call(1, "bcs", "to_bytes", vec![t], vec![b.clone()])]);
    }
}

const TYPES: &[&str] = &[
    "bool", "u8", "u16", "u32", "u64", "u128", "u256", "address", "signer",
    "vector<u8>", "vector<vector<address>>",
    "0x1::string::String", "0x1::ascii::String", "0x1::option::Option<0x1::string::String>",
    "0x2::sui::SUI", "0x2::coin::Coin<0x2::sui::SUI>", "0x2::balance::Balance<0x2::sui::SUI>",
    "0x2::dynamic_field::Field<u64, vector<0x2::coin::Coin<0x2::sui::SUI>>>",
    "0x3::sui_system::SuiSystemState", "0xdee9::clob_v2::Pool<0x2::sui::SUI, 0x2::sui::SUI>",
    "0x2::table::Table<address, 0x1::option::Option<u8>>",
];

fn gen_type_name(g: &mut Gen) {
    for t in TYPES {
        for f in ["with_defining_ids", "with_original_ids", "defining_id", "original_id"] {
            g.push("type_name", format!("{f}/{t}"), vec![call(1, "type_name", f, vec![t], vec![])]);
        }
    }
}

fn gen_vector(g: &mut Gen) {
    let elems: &[(&str, fn(u64) -> Vec<u8>)] = &[
        ("u8", |i| vec![i as u8]),
        ("u64", |i| (i * 7).to_le_bytes().to_vec()),
        ("u256", |i| {
            let mut b = vec![0u8; 32];
            b[0] = i as u8;
            b[31] = 0xf0;
            b
        }),
        ("bool", |i| vec![(i % 2) as u8]),
        ("address", |i| vec![i as u8; 32]),
        ("vector<u8>", |i| bv(&vec![i as u8; i as usize % 5])),
        ("0x1::string::String", |i| bv(format!("s{i}").as_bytes())),
    ];
    for (t, mk) in elems {
        let vt = format!("vector<{t}>");
        let vt: &'static str = Box::leak(vt.into_boxed_str());
        let t: &'static str = t;
        for n in [0u64, 1, 2, 5, 17] {
            let items: Vec<Vec<u8>> = (0..n).map(mk).collect();
            let mut enc = Vec::new();
            let mut uleb = Vec::new();
            let mut x = n;
            loop {
                let b = (x & 0x7f) as u8;
                x >>= 7;
                if x == 0 {
                    uleb.push(b);
                    break;
                }
                uleb.push(b | 0x80);
            }
            enc.extend(uleb);
            for it in &items {
                enc.extend(it);
            }
            let id = |f: &str, extra: String| format!("{f}/{t}/{n}{extra}");
            g.push("vector", id("length", String::new()), vec![call(1, "vector", "length", vec![t], vec![enc.clone()])]);
            g.push("vector", id("push_back", String::new()), vec![call(1, "vector", "push_back", vec![t], vec![enc.clone(), mk(99)])]);
            g.push("vector", id("pop_back", String::new()), vec![call(1, "vector", "pop_back", vec![t], vec![enc.clone()])]);
            g.push("vector", id("destroy_empty", String::new()), vec![call(1, "vector", "destroy_empty", vec![t], vec![enc.clone()])]);
            g.push("vector", id("reverse", String::new()), vec![call(1, "vector", "reverse", vec![t], vec![enc.clone()])]);
            for (i, j) in [(0u64, 0u64), (0, 1), (1, 3), (n.saturating_sub(1), 0), (n, 0), (0, n), (2, 2)] {
                g.push("vector", id("swap", format!("/{i}/{j}")), vec![call(1, "vector", "swap", vec![t], vec![enc.clone(), b64(i), b64(j)])]);
            }
            for (i, j) in [(0u64, 0u64), (0, n), (1, n), (0, 1), (2, 4), (n, n), (3, 1), (0, n + 1), (n + 1, n + 2)] {
                g.push("vector", id("keep_range", format!("/{i}/{j}")), vec![call(1, "vector", "keep_range", vec![t], vec![enc.clone(), b64(i), b64(j)])]);
                g.push("vector", id("copy_range", format!("/{i}/{j}")), vec![call(1, "vector", "copy_range", vec![t], vec![enc.clone(), b64(i), b64(j)])]);
                // replace_range(v: &mut vector<T>, i, j, other: vector<T>): vector<T>
                let other: Vec<Vec<u8>> = (0..3).map(|k| mk(50 + k)).collect();
                let mut oenc = vec![3u8];
                for it in &other {
                    oenc.extend(it);
                }
                g.push("vector", id("replace_range", format!("/{i}/{j}")), vec![call(1, "vector", "replace_range", vec![t], vec![enc.clone(), b64(i), b64(j), oenc])]);
            }
        }
        g.push("vector", format!("empty/{t}"), vec![call(1, "vector", "empty", vec![t], vec![])]);
        let _ = vt;
    }
}

fn gen_debug(g: &mut Gen) {
    let vals = sample_values(&mut g.rng);
    for (i, (t, b)) in vals.iter().enumerate().take(6) {
        g.push("debug", format!("print/{i}/{t}"), vec![call(1, "debug", "print", vec![t], vec![b.clone()])]);
    }
    g.push("debug", "print_stack_trace".into(), vec![call(1, "debug", "print_stack_trace", vec![], vec![])]);
}

fn gen_address(g: &mut Gen) {
    for n in [0usize, 1, 20, 31, 32, 33, 64] {
        let b = rnd(&mut g.rng, n);
        g.push("address", format!("from_bytes/{n}"), vec![call(2, "address", "from_bytes", vec![], vec![bv(&b)])]);
    }
    for i in 0..8 {
        let mut a = rnd(&mut g.rng, 32);
        if i == 0 {
            a = vec![0; 32];
        }
        if i == 1 {
            a = vec![0xff; 32];
        }
        g.push("address", format!("to_u256/{i}"), vec![call(2, "address", "to_u256", vec![], vec![a.clone()])]);
        g.push("address", format!("from_u256/{i}"), vec![call(2, "address", "from_u256", vec![], vec![a])]);
    }
}

fn gen_sig(g: &mut Gen) {
    let v = g.lines("vectors/sig-vectors/vectors.jsonl");
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for x in &v {
        let op = x["op"].as_str().unwrap();
        let c = counts.entry(op.to_string()).or_default();
        *c += 1;
        if *c > 600 {
            continue;
        }
        let id = x["id"].as_str().unwrap().to_string();
        let h = |x: &J| -> u8 { if x["h"].as_str() == Some("keccak256") { 0 } else { 1 } };
        let s = |k: &str| unhex(x[k].as_str().unwrap_or(""));
        match op {
            "ed25519_verify" => g.push("ed25519", id, vec![call(2, "ed25519", "ed25519_verify", vec![], vec![bv(&s("sig")), bv(&s("pk")), bv(&s("msg"))])]),
            "secp256k1_verify" => g.push("ecdsa_k1", id, vec![call(2, "ecdsa_k1", "secp256k1_verify", vec![], vec![bv(&s("sig")), bv(&s("pk")), bv(&s("msg")), b8(h(x))])]),
            "secp256r1_verify" => g.push("ecdsa_r1", id, vec![call(2, "ecdsa_r1", "secp256r1_verify", vec![], vec![bv(&s("sig")), bv(&s("pk")), bv(&s("msg")), b8(h(x))])]),
            "secp256k1_recover" => g.push("ecdsa_k1", id, vec![call(2, "ecdsa_k1", "secp256k1_ecrecover", vec![], vec![bv(&s("sig")), bv(&s("msg")), b8(h(x))])]),
            "secp256r1_recover" => g.push("ecdsa_r1", id, vec![call(2, "ecdsa_r1", "secp256r1_ecrecover", vec![], vec![bv(&s("sig")), bv(&s("msg")), b8(h(x))])]),
            _ => {}
        }
    }
    // hash selector outside {0, 1}, and decompress_pubkey over keys seen above
    let pk = unhex("03b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f");
    for hsel in [2u8, 255] {
        g.push("ecdsa_k1", format!("verify/badhash/{hsel}"), vec![call(2, "ecdsa_k1", "secp256k1_verify", vec![], vec![bv(&[1; 64]), bv(&pk), bv(b"m"), b8(hsel)])]);
        g.push("ecdsa_k1", format!("ecrecover/badhash/{hsel}"), vec![call(2, "ecdsa_k1", "secp256k1_ecrecover", vec![], vec![bv(&[1; 65]), bv(b"m"), b8(hsel)])]);
        g.push("ecdsa_r1", format!("verify/badhash/{hsel}"), vec![call(2, "ecdsa_r1", "secp256r1_verify", vec![], vec![bv(&[1; 64]), bv(&pk), bv(b"m"), b8(hsel)])]);
        g.push("ecdsa_r1", format!("ecrecover/badhash/{hsel}"), vec![call(2, "ecdsa_r1", "secp256r1_ecrecover", vec![], vec![bv(&[1; 65]), bv(b"m"), b8(hsel)])]);
    }
    let mut keys: Vec<Vec<u8>> = vec![pk.clone(), vec![], vec![2; 33], vec![4; 65], pk[..32].to_vec()];
    for x in v.iter().filter(|x| x["op"] == "secp256k1_verify").take(200) {
        keys.push(unhex(x["pk"].as_str().unwrap()));
    }
    keys.dedup();
    for (i, k) in keys.iter().enumerate() {
        g.push("ecdsa_k1", format!("decompress_pubkey/{i}"), vec![call(2, "ecdsa_k1", "decompress_pubkey", vec![], vec![bv(k)])]);
    }
    // secp256k1_sign / secp256k1_keypair_from_seed are #[test_only] in the published framework
}

fn gen_bls(g: &mut Gen) {
    use fastcrypto::bls12381::{min_pk, min_sig};
    let mut krng = rand::rngs::StdRng::seed_from_u64(0xb15);
    for i in 0..60 {
        let msg = rnd(&mut g.rng, i * 5);
        let kp = min_sig::BLS12381KeyPair::generate(&mut krng);
        let sig = kp.sign(&msg);
        let (mut s, mut p, mut m) = (sig.as_bytes().to_vec(), kp.public().as_bytes().to_vec(), msg.clone());
        match i % 6 {
            1 => s[5] ^= 1,
            2 => m.push(0),
            3 => p.truncate(40),
            4 => s = vec![0xc0].into_iter().chain(std::iter::repeat_n(0, 47)).collect(),
            5 => p = rnd(&mut g.rng, 96),
            _ => {}
        }
        g.push("bls12381", format!("min_sig/{i}"), vec![call(2, "bls12381", "bls12381_min_sig_verify", vec![], vec![bv(&s), bv(&p), bv(&m)])]);
        let kp = min_pk::BLS12381KeyPair::generate(&mut krng);
        let sig = kp.sign(&msg);
        let (mut s, mut p, mut m) = (sig.as_bytes().to_vec(), kp.public().as_bytes().to_vec(), msg.clone());
        match i % 6 {
            1 => s[5] ^= 1,
            2 => m.push(0),
            3 => p.truncate(40),
            4 => p = vec![0xc0].into_iter().chain(std::iter::repeat_n(0, 47)).collect(),
            5 => s = rnd(&mut g.rng, 96),
            _ => {}
        }
        g.push("bls12381", format!("min_pk/{i}"), vec![call(2, "bls12381", "bls12381_min_pk_verify", vec![], vec![bv(&s), bv(&p), bv(&m)])]);
    }
}

fn gen_ecvrf(g: &mut Gen) {
    let v = g.lines("vectors/ecvrf/vectors.jsonl");
    for x in v.iter().filter(|x| x["op"] == "ecvrf_verify").take(800) {
        let s = |k: &str| unhex(x[k].as_str().unwrap_or(""));
        g.push("ecvrf", x["id"].as_str().unwrap().into(), vec![call(2, "ecvrf", "ecvrf_verify", vec![], vec![bv(&s("hash")), bv(&s("alpha")), bv(&s("pk")), bv(&s("proof"))])]);
    }
}

fn gen_group_ops(g: &mut Gen) {
    let v = g.lines("vectors/bls-group-ops/fastcrypto.jsonl");
    for x in &v {
        let id = format!("bls/{}", x["id"].as_str().unwrap());
        let gi = x["g"].as_u64().unwrap() as u8;
        let s = |k: &str| unhex(x[k].as_str().unwrap_or(""));
        let c = match x["op"].as_str().unwrap() {
            "validate" => call(2, "group_ops", "internal_validate", vec![], vec![b8(gi), bv(&s("a"))]),
            "add" => call(2, "group_ops", "internal_add", vec![], vec![b8(gi), bv(&s("a")), bv(&s("b"))]),
            "sub" => call(2, "group_ops", "internal_sub", vec![], vec![b8(gi), bv(&s("a")), bv(&s("b"))]),
            "mul" => call(2, "group_ops", "internal_mul", vec![], vec![b8(gi), bv(&s("a")), bv(&s("b"))]),
            "div" => call(2, "group_ops", "internal_div", vec![], vec![b8(gi), bv(&s("a")), bv(&s("b"))]),
            "hash_to" => call(2, "group_ops", "internal_hash_to", vec![], vec![b8(gi), bv(&s("a"))]),
            "msm" => call(2, "group_ops", "internal_multi_scalar_mul", vec![], vec![b8(gi), bv(&s("a")), bv(&s("b"))]),
            "pairing" => call(2, "group_ops", "internal_pairing", vec![], vec![b8(gi), bv(&s("a")), bv(&s("b"))]),
            "convert" => call(2, "group_ops", "internal_convert", vec![], vec![b8(gi), b8(x["to"].as_u64().unwrap() as u8), bv(&s("a"))]),
            "sum" => {
                let terms: Vec<Vec<u8>> = x["terms"].as_array().unwrap().iter().map(|t| unhex(t.as_str().unwrap())).collect();
                call(2, "group_ops", "internal_sum", vec![], vec![b8(gi), bvv(&terms)])
            }
            o => panic!("group op {o}"),
        };
        g.push("group_ops", id, vec![c]);
    }
    // bad group ids for every op
    for gi in [7u8, 255] {
        let e = bv(&[0; 32]);
        for f in ["internal_add", "internal_sub", "internal_mul", "internal_div", "internal_pairing", "internal_multi_scalar_mul"] {
            g.push("group_ops", format!("badgroup/{f}/{gi}"), vec![call(2, "group_ops", f, vec![], vec![b8(gi), e.clone(), e.clone()])]);
        }
        g.push("group_ops", format!("badgroup/validate/{gi}"), vec![call(2, "group_ops", "internal_validate", vec![], vec![b8(gi), e.clone()])]);
        g.push("group_ops", format!("badgroup/hash_to/{gi}"), vec![call(2, "group_ops", "internal_hash_to", vec![], vec![b8(gi), e.clone()])]);
        g.push("group_ops", format!("badgroup/sum/{gi}"), vec![call(2, "group_ops", "internal_sum", vec![], vec![b8(gi), bvv(&[])])]);
        g.push("group_ops", format!("badgroup/convert/{gi}"), vec![call(2, "group_ops", "internal_convert", vec![], vec![b8(gi), b8(1), e.clone()])]);
    }
    // ristretto255 groups (5 scalar, 6 point)
    use fastcrypto::groups::{GroupElement, ristretto255::{RistrettoPoint, RistrettoScalar}};
    use fastcrypto::serde_helpers::ToFromByteArray;
    for i in 0..40u64 {
        let a = RistrettoScalar::from(i * 1_000_003 + 1);
        let b = RistrettoScalar::from(i + 2);
        let p = RistrettoPoint::generator() * a;
        let q = RistrettoPoint::generator() * b;
        let sa = a.to_byte_array().to_vec();
        let sb = b.to_byte_array().to_vec();
        let pa = p.to_byte_array().to_vec();
        let qb = q.to_byte_array().to_vec();
        let junk = rnd(&mut g.rng, 32);
        for (gi, x, y) in [(5u8, &sa, &sb), (6, &pa, &qb)] {
            for f in ["internal_add", "internal_sub", "internal_div"] {
                g.push("group_ops", format!("ristretto/{f}/{gi}/{i}"), vec![call(2, "group_ops", f, vec![], vec![b8(gi), bv(x), bv(y)])]);
            }
            g.push("group_ops", format!("ristretto/validate/{gi}/{i}"), vec![call(2, "group_ops", "internal_validate", vec![], vec![b8(gi), bv(x)])]);
            g.push("group_ops", format!("ristretto/validate-junk/{gi}/{i}"), vec![call(2, "group_ops", "internal_validate", vec![], vec![b8(gi), bv(&junk)])]);
            g.push("group_ops", format!("ristretto/hash_to/{gi}/{i}"), vec![call(2, "group_ops", "internal_hash_to", vec![], vec![b8(gi), bv(&junk[..(i as usize % 33)])])]);
        }
        g.push("group_ops", format!("ristretto/mul/{i}"), vec![call(2, "group_ops", "internal_mul", vec![], vec![b8(6), bv(&sa), bv(&qb)])]);
        g.push("group_ops", format!("ristretto/mul-s/{i}"), vec![call(2, "group_ops", "internal_mul", vec![], vec![b8(5), bv(&sa), bv(&sb)])]);
        let n = (i % 5) as usize;
        let scal: Vec<u8> = (0..n).flat_map(|k| RistrettoScalar::from(k as u64 + i).to_byte_array().to_vec()).collect();
        let pts: Vec<u8> = (0..n).flat_map(|k| (RistrettoPoint::generator() * RistrettoScalar::from(k as u64 + 3)).to_byte_array().to_vec()).collect();
        g.push("group_ops", format!("ristretto/msm/{i}"), vec![call(2, "group_ops", "internal_multi_scalar_mul", vec![], vec![b8(6), bv(&scal), bv(&pts)])]);
        let terms: Vec<Vec<u8>> = (0..n).map(|k| (RistrettoPoint::generator() * RistrettoScalar::from(k as u64 + i)).to_byte_array().to_vec()).collect();
        g.push("group_ops", format!("ristretto/sum/{i}"), vec![call(2, "group_ops", "internal_sum", vec![], vec![b8(6), bvv(&terms)])]);
    }
}

fn gen_groth16(g: &mut Gen) {
    for (file, curve) in [("vectors/groth16/bn254.jsonl", 1u8), ("vectors/groth16/bls12381.jsonl", 0u8)] {
        let v = g.lines(file);
        let mut n = 0;
        for x in &v {
            n += 1;
            if n > 700 {
                break;
            }
            let id = format!("{}", x["id"].as_str().unwrap());
            match x["op"].as_str().unwrap() {
                "prepare" => {
                    let vk = unhex(x["vk"].as_str().unwrap());
                    g.push("groth16", id, vec![call(2, "groth16", "prepare_verifying_key_internal", vec![], vec![b8(curve), bv(&vk)])]);
                }
                "verify" => {
                    let p: Vec<Vec<u8>> = x["pvk"].as_array().unwrap().iter().map(|t| unhex(t.as_str().unwrap())).collect();
                    let inp = unhex(x["inputs"].as_str().unwrap_or(""));
                    let proof = unhex(x["proof"].as_str().unwrap_or(""));
                    g.push("groth16", id, vec![call(2, "groth16", "verify_groth16_proof_internal", vec![], vec![b8(curve), bv(&p[0]), bv(&p[1]), bv(&p[2]), bv(&p[3]), bv(&inp), bv(&proof)])]);
                }
                _ => {}
            }
        }
    }
    g.push("groth16", "prepare/badcurve".into(), vec![call(2, "groth16", "prepare_verifying_key_internal", vec![], vec![b8(2), bv(&[0; 10])])]);
    g.push("groth16", "verify/badcurve".into(), vec![call(2, "groth16", "verify_groth16_proof_internal", vec![], vec![b8(9), bv(&[]), bv(&[]), bv(&[]), bv(&[]), bv(&[]), bv(&[])])]);
}

fn gen_poseidon(g: &mut Gen) {
    let v = g.lines("vectors/poseidon/fastcrypto.jsonl");
    for x in v.iter().filter(|x| x["fn"] == "bytes") {
        let ins: Vec<Vec<u8>> = x["in"].as_array().unwrap().iter().map(|t| unhex(t.as_str().unwrap())).collect();
        g.push("poseidon", x["id"].as_str().unwrap().into(), vec![call(2, "poseidon", "poseidon_bn254_internal", vec![], vec![bvv(&ins)])]);
    }
}

fn gen_tx_context(g: &mut Gen) {
    let reads = ["native_sender", "native_epoch", "native_epoch_timestamp_ms", "native_rgp", "native_gas_price", "native_gas_budget", "native_ids_created", "native_sponsor"];  // last_created_id and replace are #[test_only]
    let mut ctxs = vec![DEFAULT_CTX.clone()];
    let mut c2 = DEFAULT_CTX.clone();
    c2.sponsor = Some([0x77; 32]);
    c2.epoch = 0;
    c2.gas_budget = u64::MAX;
    ctxs.push(c2);
    for (ci, c) in ctxs.iter().enumerate() {
        for f in reads {
            g.push_full("tx_context", format!("{f}/{ci}"), PV_MAX, Some(c.clone()), vec![call(2, "tx_context", f, vec![], vec![])]);
        }
        let fresh = || call(2, "tx_context", "fresh_id", vec![], vec![]);
        g.push_full(
            "tx_context",
            format!("fresh_seq/{ci}"),
            PV_MAX,
            Some(c.clone()),
            vec![fresh(), fresh(), call(2, "tx_context", "native_ids_created", vec![], vec![]), fresh(), call(2, "tx_context", "native_ids_created", vec![], vec![])],
        );
    }
    for i in 0..20u64 {
        let h = rnd(&mut g.rng, if i == 3 { 31 } else { 32 });
        g.push("tx_context", format!("derive_id/{i}"), vec![call(2, "tx_context", "derive_id", vec![], vec![bv(&h), b64(i * 1_000_003)])]);
    }
}

fn gen_misc(g: &mut Gen) {
    // types::is_one_time_witness
    for (t, b) in [("0x2::sui::SUI", vec![0u8]), ("0x2::sui::SUI", vec![1u8]), ("0x1::string::String", bv(b"x")), ("u64", b64(1)), ("0x2::object::ID", vec![0; 32]), ("0x1::option::Option<u8>", vec![0])] {
        g.push("types", format!("is_one_time_witness/{t}/{}", hex::encode(&b)), vec![call(2, "types", "is_one_time_witness", vec![t], vec![b])]);
    }
    // protocol_config::is_feature_enabled
    for name in ["enable_group_ops_native_functions", "enable_poseidon", "enable_vdf", "accept_zklogin_in_multisig", "zklogin_auth", "no_such_flag", "", "ENABLE_POSEIDON", "enable_nitro_attestation", "enable_accumulators", "random_beacon"] {
        g.push("protocol_config", format!("is_feature_enabled/{name}"), vec![call(2, "protocol_config", "is_feature_enabled", vec![], vec![bv(name.as_bytes())])]);
    }
    // dynamic_field::hash_type_and_key
    let vals = sample_values(&mut g.rng);
    for (i, (t, b)) in vals.iter().enumerate() {
        if matches!(*t, "0x2::object::UID" | "0x2::balance::Balance<0x2::sui::SUI>" | "0x2::sui::SUI") {
            continue; // K: copy + drop
        }
        g.push("dynamic_field", format!("hash_type_and_key/{i}/{t}"), vec![call(2, "dynamic_field", "hash_type_and_key", vec![t], vec![vec![0x5c; 32], b.clone()])]);
    }
}

/// Every native in the sweep, run at every protocol version served by the latest executor, so
/// per-version cost parameters and feature gates are covered.
fn gen_sweep(g: &mut Gen) {
    let mut base: Vec<(String, Vec<Call>)> = Vec::new();
    for (_, items) in g.items.iter() {
        let mut seen = std::collections::BTreeSet::new();
        for it in items {
            let key = (it.calls[0].module, it.calls[0].func);
            if it.ctx.is_some() || !seen.insert(key) {
                continue;
            }
            base.push((it.id.clone(), it.calls.clone()));
        }
    }
    for pv in PV_MIN_V4..PV_MAX {
        for (id, calls) in &base {
            g.push_full("sweep", format!("{id}@{pv}"), pv, None, calls.clone());
        }
    }
}

/// Reviewer additions (round 1): edges the generators above miss, from the Rust source. Kept in
/// their own group and run last so the other groups (and their oog/sweep derivatives) are unchanged.
fn gen_review(g: &mut Gen) {
    // string::internal_sub_string: j < i aborts 1 after the base charge; j past the end is the
    // `safe_get` invariant violation after the per-byte charge.
    for (i, j) in [(3u64, 1u64), (0, 6), (6, 6), (5, 9), (u64::MAX - 1, u64::MAX), (u64::MAX, 0)] {
        g.push("review", format!("sub_string/hello/{i}/{j}"), vec![call(1, "string", "internal_sub_string", vec![], vec![bv(b"hello"), b64(i), b64(j)])]);
    }
    for j in [u64::MAX, 1 << 40] {
        g.push("review", format!("is_char_boundary/{j}"), vec![call(1, "string", "internal_is_char_boundary", vec![], vec![bv("h\u{e9}llo".as_bytes()), b64(j)])]);
    }
    g.push("review", "index_of/longer".into(), vec![call(1, "string", "internal_index_of", vec![], vec![bv(b"ab"), bv(b"abc")])]);
    // protocol_config::is_feature_enabled on bytes that are not UTF-8 or not a flag name
    for (k, name) in [vec![0xffu8], b"enable_poseidon\0".to_vec(), b" enable_poseidon".to_vec()].iter().enumerate() {
        g.push("review", format!("is_feature_enabled/{k}"), vec![call(2, "protocol_config", "is_feature_enabled", vec![], vec![bv(name)])]);
    }
    // ObjectRuntime::new_id: the 2049th new id in a metered transaction is MEMORY_LIMIT_EXCEEDED /
    // NEW_ID_COUNT_LIMIT_EXCEEDED; derive_id of an id fresh_id already made does not count twice.
    let fresh = || call(2, "tx_context", "fresh_id", vec![], vec![]);
    let mut calls = vec![call(2, "tx_context", "derive_id", vec![], vec![bv(&DEFAULT_CTX.digest), b64(1)])];
    calls.push(fresh());
    calls.push(fresh()); // id 1 again: already in new_ids
    calls.push(call(2, "tx_context", "derive_id", vec![], vec![bv(&DEFAULT_CTX.digest), b64(u64::MAX)]));
    calls.push(call(2, "tx_context", "native_ids_created", vec![], vec![]));
    g.push_full("review", "new_id/dedup".into(), PV_MAX, Some(DEFAULT_CTX.clone()), calls);
    let mut calls: Vec<Call> = (0..2050).map(|_| fresh()).collect();
    calls.push(call(2, "tx_context", "native_ids_created", vec![], vec![]));
    g.push_full("review", "new_id/limit".into(), PV_MAX, Some(DEFAULT_CTX.clone()), calls);
    // vector length limit (max_move_vector_len = 256 Ki): push_back and replace_range past it
    let lim: u64 = 256 * 1024;
    let vec_u8 = |n: u64| bv(&vec![7u8; n as usize]);
    g.push("review", "push_back/at-limit".into(), vec![call(1, "vector", "push_back", vec!["u8"], vec![vec_u8(lim), b8(1)])]);
    g.push("review", "push_back/below-limit".into(), vec![call(1, "vector", "push_back", vec!["u8"], vec![vec_u8(lim - 1), b8(1)])]);
    g.push("review", "replace_range/over-limit".into(), vec![call(1, "vector", "replace_range", vec!["u8"], vec![vec_u8(lim - 1), b64(0), b64(1), bv(&[1, 2, 3])])]);
    g.push("review", "replace_range/to-limit".into(), vec![call(1, "vector", "replace_range", vec!["u8"], vec![vec_u8(lim - 2), b64(0), b64(1), bv(&[1, 2, 3])])]);
    g.push("review", "replace_range/same-len".into(), vec![call(1, "vector", "replace_range", vec!["u8"], vec![vec_u8(10), b64(2), b64(5), bv(&[1, 2, 3])])]);
    // push_back's legacy abstract-size charge on signers (a struct of one address: 2 + 32)
    g.push("review", "push_back/signer".into(), vec![call(1, "vector", "push_back", vec!["signer"], vec![bcs::to_bytes(&vec![[3u8; 32]]).unwrap(), vec![4u8; 32]])]);
    g.push("review", "push_back/vector-signer".into(), vec![call(1, "vector", "push_back", vec!["vector<signer>"], vec![vec![0], bcs::to_bytes(&vec![[3u8; 32], [5u8; 32]]).unwrap()])]);
    // types::is_one_time_witness over more shapes
    for t in ["bool", "vector<u8>", "0x1::ascii::String", "0x1::type_name::TypeName"] {
        let b = match t {
            "bool" => vec![1],
            _ => bv(&[0x41]),
        };
        g.push("review", format!("is_one_time_witness/{t}"), vec![call(2, "types", "is_one_time_witness", vec![t], vec![b])]);
    }
}

/// Out-of-gas: a native given less budget than its cost (early exit returns the budget with
/// NFE_OUT_OF_GAS; natives that charge only at the end overspend).
fn gen_oog(g: &mut Gen) {
    let mut out = Vec::new();
    for (grp, items) in g.items.iter() {
        if grp == "sweep" {
            continue;
        }
        for it in items.iter().step_by(13) {
            if it.ctx.is_some() || it.calls.len() != 1 {
                continue;
            }
            for budget in [0u64, 1, 50, 500, 5000] {
                let mut c = it.calls[0].clone();
                c.budget = budget;
                out.push((format!("{}#b{budget}", it.id), c));
            }
        }
    }
    for (id, c) in out {
        g.push("oog", id, vec![c]);
    }
}

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

fn run_natives(corpus: &Path) -> Result<()> {
    let mut g = Gen { items: BTreeMap::new(), rng: ChaCha20Rng::seed_from_u64(0x5a1_7a71e5), corpus: corpus.to_path_buf() };
    gen_hash(&mut g);
    gen_string(&mut g);
    gen_bcs(&mut g);
    gen_type_name(&mut g);
    gen_vector(&mut g);
    gen_debug(&mut g);
    gen_address(&mut g);
    gen_sig(&mut g);
    gen_bls(&mut g);
    gen_ecvrf(&mut g);
    gen_group_ops(&mut g);
    gen_groth16(&mut g);
    gen_poseidon(&mut g);
    gen_tx_context(&mut g);
    gen_misc(&mut g);
    gen_oog(&mut g);
    gen_sweep(&mut g);
    gen_review(&mut g);
    // round 2: object runtime groups (after review so earlier groups stay byte-identical)
    objrt::gen_all(&mut g);
    zkl::gen_all(&mut g);
    // reviewer edges for round 2 (last, so every earlier group stays byte-identical)
    objrt::gen_review_rt(&mut g);
    // round 3 (own rng, after every earlier group)
    nitro::gen_all(&mut g);
    validator::gen_all(&mut g);
    objrt::gen_event_total(&mut g);
    write_groups(&g, corpus)
}

/// 1.84 only: the groups for what protocol 142 added (`natives-v142`), written to
/// `vectors/natives/v142.jsonl` and nothing else, so every other natives file stays the
/// 1.83.1 truth. Items run at 142 and at 141 (the natives or checks absent there).
#[cfg(feature = "sui_184")]
fn run_natives_v142(corpus: &Path) -> Result<()> {
    let mut g = Gen { items: BTreeMap::new(), rng: ChaCha20Rng::seed_from_u64(0x142_0184), corpus: corpus.to_path_buf() };
    v142::gen_all(&mut g);
    write_groups(&g, corpus)
}

fn write_groups(g: &Gen, corpus: &Path) -> Result<()> {
    let out_dir = corpus.join("vectors/natives");
    std::fs::create_dir_all(&out_dir)?;
    let mut envs: BTreeMap<u64, Env> = BTreeMap::new();
    let mut total = 0usize;
    let mut bad = 0usize;
    for (grp, items) in &g.items {
        let path = out_dir.join(format!("{grp}.jsonl"));
        let mut f = std::io::BufWriter::new(std::fs::File::create(&path)?);
        for it in items {
            if !envs.contains_key(&it.pv) {
                envs.insert(it.pv, Env::new(it.pv)?);
            }
            let env = &envs[&it.pv];
            let ctx = it.ctx.clone().unwrap_or(DEFAULT_CTX);
            let (truths, results) = match env.run_env(&it.calls, &ctx, it.env.as_ref()) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("{grp}/{}: {e:#}", it.id);
                    bad += 1;
                    continue;
                }
            };
            let mut calls = Vec::new();
            for (c, t) in it.calls.iter().zip(&truths) {
                let out = match &t.outcome {
                    Outcome::Ok { rets, muts } => json!({"ok": {"rets": rets.iter().map(|r| hx(r)).collect::<Vec<_>>(), "muts": muts.iter().map(|r| hx(r)).collect::<Vec<_>>()}}),
                    Outcome::Abort(code) => json!({"abort": code}),
                    Outcome::Err { status, sub } => json!({"err": {"status": *status as u64, "sub": sub}}),
                };
                let mut cj = json!({
                    "addr": c.addr, "module": c.module, "func": c.func,
                    "tys": t.tys.iter().map(|ty| {
                        let mut o = json!({"tag": hx(&ty.tag), "layout": ty.layout.as_ref().map(|l| hx(l))});
                        if it.env.is_some() { o["ann"] = json!(ty.annotated.as_ref().map(|l| hx(l))); }
                        if let Some(sh) = &ty.shape { o["shape"] = json!(hx(sh)); }
                        o
                    }).collect::<Vec<_>>(),
                    "params": t.params.iter().map(|(k, l)| json!([k, hx(l)])).collect::<Vec<_>>(),
                    "rets": t.rets.iter().map(|(_, l)| hx(l)).collect::<Vec<_>>(),
                    "args": c.args.iter().map(|a| hx(a)).collect::<Vec<_>>(),
                    "budget": c.budget, "out": out, "cost": t.cost,
                });
                if t.rets.iter().any(|(k, _)| *k != 0) { cj["ret_ref"] = json!(true); }
                if let Some(w) = &c.write { cj["write"] = json!(hx(w)); }
                calls.push(cj);
            }
            let ctxj = it.ctx.as_ref().map(|c| json!({
                "sender": hx(&c.sender), "digest": hx(&c.digest), "epoch": c.epoch, "epoch_ts_ms": c.epoch_ts_ms,
                "rgp": c.rgp, "gas_price": c.gas_price, "gas_budget": c.gas_budget, "sponsor": c.sponsor.map(|s| hx(&s)),
            }));
            let mut line = json!({"id": format!("{grp}/{}", it.id), "pv": it.pv, "ctx": ctxj, "calls": calls});
            if let Some(e) = &it.env {
                line["env"] = json!({
                    "metered": !e.unmetered,
                    "inputs": e.inputs.iter().map(|(id, v, o, u)| json!([hx(id.as_ref()), v, hx(&bcs::to_bytes(o).unwrap()), u.iter().map(|x| hx(x.as_ref())).collect::<Vec<_>>()])).collect::<Vec<_>>(),
                    "objects": e.objects.iter().map(|o| objrt::object_json(o)).collect::<Vec<_>>(),
                    "balances": e.balances.iter().map(|(a, t, n)| json!([hx(a.as_ref()), hx(&bcs::to_bytes(t).unwrap()), n.to_string()])).collect::<Vec<_>>(),
                });
                if let Some(c) = &e.clock {
                    line["env"]["clock"] = json!(hx(c.data.try_as_move().unwrap().contents()));
                }
                line["results"] = results.unwrap_or(J::Null);
            }
            writeln!(f, "{}", line)?;
            total += 1;
        }
        f.flush()?;
        eprintln!("{grp}: {} items", items.len());
    }
    eprintln!("natives: {total} items written, {bad} generator errors");
    anyhow::ensure!(bad == 0, "generator errors");
    Ok(())
}

/// Framework truth: for every snapshot version (and the built-in framework at the max
/// protocol version), every system package's SystemPackage BCS digest and the package object
/// Rust builds from it (`Object::new_system_package` at a fixed version and previous tx).
fn run_framework(corpus: &Path) -> Result<()> {
    use sui_types::base_types::SequenceNumber;
    use sui_types::digests::TransactionDigest;
    use sui_types::object::Object;
    let manifest = sui_framework_snapshot::load_bytecode_snapshot_manifest();
    let out_dir = corpus.join("vectors/framework");
    std::fs::create_dir_all(&out_dir)?;
    let mut f = std::io::BufWriter::new(std::fs::File::create(out_dir.join("framework.jsonl"))?);
    let mut versions: Vec<u64> = manifest.keys().copied().collect();
    // a release that snapshots its own framework (1.84: snapshot 142) lists it once
    if !versions.contains(&PV_MAX) {
        versions.push(PV_MAX);
    }
    let prev = TransactionDigest::new([0x7e; 32]);
    let seq = SequenceNumber::from_u64(9);
    for v in versions {
        let pkgs: Vec<sui_framework::SystemPackage> = if v == PV_MAX {
            sui_framework::BuiltInFramework::iter_system_packages().cloned().collect()
        } else {
            sui_framework_snapshot::load_bytecode_snapshot(v)?
        };
        let mut arr = Vec::new();
        for p in &pkgs {
            let sp = bcs::to_bytes(p)?;
            let modules = p.modules();
            let obj = Object::new_system_package(&modules, seq, p.dependencies.clone(), prev);
            let obj_bcs = bcs::to_bytes(&obj)?;
            arr.push(json!({
                "id": hx(p.id.as_ref()),
                "modules": p.bytes.len(),
                "system_package_blake2b": hx(&blake(&sp)),
                "deps": p.dependencies.iter().map(|d| hx(d.as_ref())).collect::<Vec<_>>(),
                "object": hx(&obj_bcs),
                "object_digest": hx(obj.digest().inner()),
            }));
        }
        writeln!(f, "{}", json!({"version": v, "snapshot": v != PV_MAX, "packages": arr}))?;
    }
    f.flush()?;
    Ok(())
}

/// The deduplicated framework bytecode deepwave embeds (src/natives/framework.bin): every module
/// once, then per version (each snapshot plus the built-in framework as PV_MAX) its packages.
/// Little endian: "ZUIFW001", u32 n_modules, {u32 len, bytes}*, u32 n_versions,
/// {u64 version, u32 n_packages, {[32] id, u32 n_modules, u32 index*, u32 n_deps, [32]*}*}*.
fn run_framework_blob(out: &Path) -> Result<()> {
    let manifest = sui_framework_snapshot::load_bytecode_snapshot_manifest();
    let mut versions: Vec<u64> = manifest.keys().copied().collect();
    // a release that snapshots its own framework (1.84: snapshot 142) lists it once
    if !versions.contains(&PV_MAX) {
        versions.push(PV_MAX);
    }
    let mut modules: Vec<Vec<u8>> = Vec::new();
    let mut index: std::collections::HashMap<Vec<u8>, u32> = std::collections::HashMap::new();
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&(versions.len() as u32).to_le_bytes());
    for v in versions {
        let pkgs: Vec<sui_framework::SystemPackage> = if v == PV_MAX {
            sui_framework::BuiltInFramework::iter_system_packages().cloned().collect()
        } else {
            sui_framework_snapshot::load_bytecode_snapshot(v)?
        };
        body.extend_from_slice(&v.to_le_bytes());
        body.extend_from_slice(&(pkgs.len() as u32).to_le_bytes());
        for p in &pkgs {
            body.extend_from_slice(p.id.as_ref());
            body.extend_from_slice(&(p.bytes.len() as u32).to_le_bytes());
            for m in &p.bytes {
                let i = *index.entry(m.clone()).or_insert_with(|| {
                    modules.push(m.clone());
                    (modules.len() - 1) as u32
                });
                body.extend_from_slice(&i.to_le_bytes());
            }
            body.extend_from_slice(&(p.dependencies.len() as u32).to_le_bytes());
            for d in &p.dependencies {
                body.extend_from_slice(d.as_ref());
            }
        }
    }
    let mut blob: Vec<u8> = b"ZUIFW001".to_vec();
    blob.extend_from_slice(&(modules.len() as u32).to_le_bytes());
    for m in &modules {
        blob.extend_from_slice(&(m.len() as u32).to_le_bytes());
        blob.extend_from_slice(m);
    }
    blob.extend_from_slice(&body);
    std::fs::write(out, &blob)?;
    eprintln!("framework blob: {} modules, {} bytes", modules.len(), blob.len());
    Ok(())
}

/// `bench <group> --iters N --list FILE`: every item of the listed `vectors/natives/<group>.jsonl`
/// run through Mysten's Move VM (`execute_function_bypass_visibility` on the native, as the truth
/// was made), timed per pass; one JSON record with the median pass per native call.
fn run_bench(args: &[String]) -> Result<()> {
    let group = args.get(2).context("bench <group>")?.clone();
    let mut iters = 5usize;
    let mut list = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--iters" => { iters = args[i + 1].parse()?; i += 2; }
            "--list" => { list = Some(args[i + 1].clone()); i += 2; }
            _ => i += 1,
        }
    }
    let list = std::fs::read_to_string(list.context("--list")?)?;
    let hexd = |s: &str| hex::decode(s).map_err(|e| anyhow!("{e}"));
    let mut envs: BTreeMap<u64, Env> = BTreeMap::new();
    let mut items: Vec<(u64, Ctx, Vec<Call>, Option<vm::ObjEnv>, Option<sui_types::in_memory_storage::InMemoryStorage>)> = Vec::new();
    let mut n_calls = 0u64;
    for path in list.lines().filter(|l| !l.is_empty()) {
        if Path::new(path).file_stem().and_then(|s| s.to_str()) != Some(group.as_str()) { continue; }
        for line in std::fs::read_to_string(path)?.lines().filter(|l| !l.is_empty()) {
            let d: J = serde_json::from_str(line)?;
            let pv = d["pv"].as_u64().context("pv")?;
            let ctx = match &d["ctx"] {
                J::Object(o) => Ctx {
                    sender: hexd(o["sender"].as_str().unwrap())?.try_into().unwrap(),
                    digest: hexd(o["digest"].as_str().unwrap())?.try_into().unwrap(),
                    epoch: o["epoch"].as_u64().unwrap(),
                    epoch_ts_ms: o["epoch_ts_ms"].as_u64().unwrap(),
                    rgp: o["rgp"].as_u64().unwrap(),
                    gas_price: o["gas_price"].as_u64().unwrap(),
                    gas_budget: o["gas_budget"].as_u64().unwrap(),
                    sponsor: o["sponsor"].as_str().map(|s| hexd(s).unwrap().try_into().unwrap()),
                },
                _ => DEFAULT_CTX.clone(),
            };
            let mut calls = Vec::new();
            for c in d["calls"].as_array().unwrap() {
                calls.push(Call {
                    addr: c["addr"].as_u64().unwrap() as u16,
                    module: Box::leak(c["module"].as_str().unwrap().to_string().into_boxed_str()),
                    func: Box::leak(c["func"].as_str().unwrap().to_string().into_boxed_str()),
                    ty_args: c["tys"].as_array().unwrap().iter()
                        .map(|t| bcs::from_bytes(&hexd(t["tag"].as_str().unwrap()).unwrap()).unwrap()).collect(),
                    args: c["args"].as_array().unwrap().iter().map(|a| hexd(a.as_str().unwrap()).unwrap()).collect(),
                    budget: c["budget"].as_u64().unwrap(),
                    write: c["write"].as_str().map(|w| hexd(w).unwrap()),
                    shapes: c["tys"].as_array().unwrap().iter()
                        .map(|t| t["shape"].as_str().map(|s| bcs::from_bytes(&hexd(s).unwrap()).unwrap())).collect(),
                });
            }
            n_calls += calls.len() as u64;
            if !envs.contains_key(&pv) { envs.insert(pv, Env::new(pv)?); }
            let obj_env = match &d["env"] {
                J::Object(e) => Some(objrt::env_from_json(e)?),
                _ => None,
            };
            let storage = envs[&pv].storage_for(obj_env.as_ref());
            items.push((pv, ctx, calls, obj_env, storage));
        }
    }
    // per pass: a fresh object runtime and VM over the item's prebuilt storage, the calls, finish
    let pass = |envs: &BTreeMap<u64, Env>| -> Result<()> {
        for (pv, ctx, calls, oe, st) in &items {
            std::hint::black_box(envs[pv].run_in(calls, ctx, oe.as_ref(), st.as_ref(), false)?);
        }
        Ok(())
    };
    pass(&envs)?;
    let mut times = Vec::new();
    for _ in 0..iters.max(1) {
        let t0 = std::time::Instant::now();
        pass(&envs)?;
        times.push(t0.elapsed().as_nanos() as u64);
    }
    times.sort();
    let med = times[times.len() / 2];
    println!("{}", json!({"impl": "rust", "bench": group, "unit": "call", "units": n_calls, "iters": times.len(),
        "median_ns": med, "min_ns": times[0], "ns_per_unit": med as f64 / n_calls.max(1) as f64}));
    Ok(())
}

fn blake(b: &[u8]) -> [u8; 32] {
    use fastcrypto::hash::{Blake2b256, HashFunction};
    Blake2b256::digest(b).digest
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("bench") {
        return run_bench(&args);
    }
    if args.get(1).map(String::as_str) == Some("cut") {
        let cutv = args.get(2).context("usage: cut <v0|v1|v2|v3> <pv> [corpus]")?;
        let pv: u64 = args.get(3).context("pv")?.parse()?;
        let corpus = PathBuf::from(args.get(4).cloned().or_else(|| std::env::var("ZUI_CORPUS").ok()).context("corpus dir")?);
        return cut::run_cut(cutv, pv, &corpus);
    }
    if args.get(1).map(String::as_str) == Some("bench-direct") {
        return direct::run_bench_direct(&args);
    }
    let corpus = PathBuf::from(args.get(2).cloned().or_else(|| std::env::var("ZUI_CORPUS").ok()).context("corpus dir")?);
    match args.get(1).map(String::as_str) {
        Some("natives") => run_natives(&corpus),
        #[cfg(feature = "sui_184")]
        Some("natives-v142") => run_natives_v142(&corpus),
        Some("framework") => run_framework(&corpus),
        Some("framework-blob") => run_framework_blob(&corpus),
        _ => Err(anyhow!("usage: zui-truth-sui-natives natives|framework [corpus] | framework-blob <out> | cut <v0|v1|v2|v3> <pv> [corpus]")),
    }
}

#[allow(dead_code)]
fn _unused(r: &mut ChaCha20Rng) -> u8 {
    r.r#gen()
}
