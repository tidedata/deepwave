//! Round 3: nitro_attestation::load_nitro_attestation_internal.
//!
//! Inputs are the three genuine AWS Nitro attestation documents in Mysten's own tests
//! (data/nitro_docs.hex), run at times around every certificate's validity bounds, plus:
//! - COSE re-encodings that keep the signature valid (tags, indefinite and chunked strings,
//!   non-minimal lengths, extra array elements, unprotected header contents, trailing bytes,
//!   a high-s signature);
//! - payload rewrites (every field rule of AttestationDocument::validate_document_map) behind the
//!   original protected header and signature, so parse-or-verify and the verify charge (which
//!   counts the cabundle) are what is compared;
//! - CBOR edge cases at every level ciborium sees (bignum tags before and after the
//!   re-encode round trip, floats, simple values, reserved minors, recursion limit, UTF-8 across
//!   segment and scratch boundaries);
//! - random byte flips and truncations, out-of-gas budgets and a protocol sweep.

use crate::vm::Call;
use crate::{Gen, PV_MAX, PV_MIN_V4, b64, bv, call};
use ciborium::value::{Integer, Value as CV};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use x509_parser::prelude::FromDer;

const DOCS: &str = include_str!("../data/nitro_docs.hex");
const G: &str = "nitro";

fn nitro(doc: &[u8], ts: u64) -> Call {
    call(2, "nitro_attestation", "load_nitro_attestation_internal", vec![], vec![bv(doc), b64(ts)])
}

// ---- raw CBOR writers ------------------------------------------------------------------------

fn head(major: u8, n: u64) -> Vec<u8> {
    let m = major << 5;
    if n < 24 {
        vec![m | n as u8]
    } else if n <= 0xff {
        vec![m | 24, n as u8]
    } else if n <= 0xffff {
        let mut v = vec![m | 25];
        v.extend_from_slice(&(n as u16).to_be_bytes());
        v
    } else if n <= 0xffff_ffff {
        let mut v = vec![m | 26];
        v.extend_from_slice(&(n as u32).to_be_bytes());
        v
    } else {
        let mut v = vec![m | 27];
        v.extend_from_slice(&n.to_be_bytes());
        v
    }
}
/// Head with a forced width (0 = in-byte, 1, 2, 4, 8 extra bytes).
fn head_w(major: u8, n: u64, w: u8) -> Vec<u8> {
    let m = major << 5;
    match w {
        0 => vec![m | n as u8],
        1 => vec![m | 24, n as u8],
        2 => [vec![m | 25], (n as u16).to_be_bytes().to_vec()].concat(),
        4 => [vec![m | 26], (n as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![m | 27], n.to_be_bytes().to_vec()].concat(),
    }
}
fn cb(b: &[u8]) -> Vec<u8> {
    [head(2, b.len() as u64), b.to_vec()].concat()
}
fn ct(s: &[u8]) -> Vec<u8> {
    [head(3, s.len() as u64), s.to_vec()].concat()
}
/// Indefinite byte string in chunks of `n`.
fn cb_chunks(b: &[u8], n: usize) -> Vec<u8> {
    let mut v = vec![0x5f];
    for c in b.chunks(n.max(1)) {
        v.extend(cb(c));
    }
    v.push(0xff);
    v
}
fn arr(items: &[Vec<u8>]) -> Vec<u8> {
    let mut v = head(4, items.len() as u64);
    for i in items {
        v.extend_from_slice(i);
    }
    v
}
fn arr_indef(items: &[Vec<u8>]) -> Vec<u8> {
    let mut v = vec![0x9f];
    for i in items {
        v.extend_from_slice(i);
    }
    v.push(0xff);
    v
}
fn map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut v = head(5, entries.len() as u64);
    for (k, x) in entries {
        v.extend_from_slice(k);
        v.extend_from_slice(x);
    }
    v
}
fn uint(n: u64) -> Vec<u8> {
    head(0, n)
}
fn nint(n: u64) -> Vec<u8> {
    head(1, n)
}
fn tag(t: u64, inner: Vec<u8>) -> Vec<u8> {
    [head(6, t), inner].concat()
}
fn enc(v: &CV) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(v, &mut out).unwrap();
    out
}

struct Doc {
    raw: Vec<u8>,
    protected: Vec<u8>,
    payload: Vec<u8>,
    sig: Vec<u8>,
    /// timestamp in the payload (ms)
    ts: u64,
    /// (not_before, not_after) in seconds of the leaf and every cabundle certificate
    bounds: Vec<(i64, i64)>,
    pmap: Vec<(CV, CV)>,
}

fn load() -> Vec<Doc> {
    let mut out = Vec::new();
    for line in DOCS.lines().filter(|l| !l.trim().is_empty()) {
        let raw = hex::decode(line.trim()).unwrap();
        let v: CV = ciborium::de::from_reader(&raw[..]).unwrap();
        let a = match v {
            CV::Array(a) => a,
            _ => panic!("doc is not an array"),
        };
        let protected = a[0].as_bytes().unwrap().clone();
        let payload = a[2].as_bytes().unwrap().clone();
        let sig = a[3].as_bytes().unwrap().clone();
        let pv: CV = ciborium::de::from_reader(&payload[..]).unwrap();
        let pmap = match pv {
            CV::Map(m) => m,
            _ => panic!(),
        };
        let get = |k: &str| pmap.iter().find(|(kk, _)| kk.as_text() == Some(k)).map(|(_, v)| v.clone()).unwrap();
        let ts: u64 = get("timestamp").as_integer().unwrap().try_into().unwrap();
        let mut bounds = Vec::new();
        let mut certs = vec![get("certificate").as_bytes().unwrap().clone()];
        for c in get("cabundle").as_array().unwrap() {
            certs.push(c.as_bytes().unwrap().clone());
        }
        for c in &certs {
            let (_, x) = x509_parser::certificate::X509Certificate::from_der(c).unwrap();
            bounds.push((x.validity().not_before.timestamp(), x.validity().not_after.timestamp()));
        }
        out.push(Doc { raw, protected, payload, sig, ts, bounds, pmap });
    }
    out
}

fn cose(protected: &[u8], unprot: Vec<u8>, payload: &[u8], sig: &[u8]) -> Vec<u8> {
    arr(&[cb(protected), unprot, cb(payload), cb(sig)])
}

/// The document with its payload map replaced (same protected header and signature).
fn with_map(d: &Doc, m: Vec<(CV, CV)>) -> Vec<u8> {
    cose(&d.protected, map(&[]), &enc(&CV::Map(m)), &d.sig)
}

fn set(m: &[(CV, CV)], k: &str, v: Option<CV>) -> Vec<(CV, CV)> {
    let mut out: Vec<(CV, CV)> = Vec::new();
    let mut done = false;
    for (kk, vv) in m {
        if kk.as_text() == Some(k) {
            if let Some(v) = &v {
                if !done {
                    out.push((kk.clone(), v.clone()));
                }
            }
            done = true;
        } else {
            out.push((kk.clone(), vv.clone()));
        }
    }
    if !done {
        if let Some(v) = v {
            out.push((CV::Text(k.into()), v));
        }
    }
    out
}

fn get<'a>(m: &'a [(CV, CV)], k: &str) -> &'a CV {
    &m.iter().find(|(kk, _)| kk.as_text() == Some(k)).unwrap().1
}

pub fn gen_all(g: &mut Gen) {
    let docs = load();
    let mut rng = ChaCha20Rng::seed_from_u64(0x0517_0a77);
    for (di, d) in docs.iter().enumerate() {
        gen_genuine(g, di, d);
        gen_cose(g, di, d);
        gen_payload(g, di, d, &mut rng);
        gen_flips(g, di, d, &mut rng);
    }
    gen_cbor_edges(g, &docs[0]);
    gen_misc(g, &docs);
}

fn gen_genuine(g: &mut Gen, di: usize, d: &Doc) {
    g.push(G, format!("d{di}/genuine"), vec![nitro(&d.raw, d.ts)]);
    // every certificate's validity bounds (seconds, inclusive) at ms resolution
    let mut times = std::collections::BTreeSet::new();
    for &(nb, na) in &d.bounds {
        for s in [nb - 1, nb, nb + 1, na - 1, na, na + 1] {
            if s >= 0 {
                let ms = s as u64 * 1000;
                times.insert(ms);
                times.insert(ms + 999);
                if ms > 0 {
                    times.insert(ms - 1);
                }
            }
        }
    }
    for t in [0u64, 1, 999, 1000, i64::MAX as u64, i64::MAX as u64 + 1, u64::MAX, d.ts - 600_000, d.ts + 600_000] {
        times.insert(t);
    }
    for t in times {
        g.push(G, format!("d{di}/time/{t}"), vec![nitro(&d.raw, t)]);
    }
    // the protocol sweep and out-of-gas budgets on the genuine document
    for pv in PV_MIN_V4..=PV_MAX {
        g.push_full(G, format!("d{di}/pv{pv}"), pv, None, vec![nitro(&d.raw, d.ts)]);
    }
    let parse = 53 * 50 + 50 * d.raw.len() as u64;
    let verify = 49632 * 50 + 52369 * 50 * (d.bounds.len() as u64 - 1);
    for b in [0, 1, parse - 1, parse, parse + 1, parse + verify - 1, parse + verify, parse + verify + 1] {
        let mut c = nitro(&d.raw, d.ts);
        c.budget = b;
        g.push(G, format!("d{di}/budget/{b}"), vec![c]);
    }
    // parse ok, verify fails (expired): budget between the charges
    for b in [parse + verify - 1, parse + verify] {
        let mut c = nitro(&d.raw, 0);
        c.budget = b;
        g.push(G, format!("d{di}/budget-expired/{b}"), vec![c]);
    }
}

fn gen_cose(g: &mut Gen, di: usize, d: &Doc) {
    let (p, pl, s) = (&d.protected, &d.payload, &d.sig);
    let t = d.ts;
    let mut v: Vec<(&str, Vec<u8>)> = vec![
        ("tag18", tag(18, cose(p, map(&[]), pl, s))),
        ("tag18x2", tag(18, tag(18, cose(p, map(&[]), pl, s)))),
        ("tag17", tag(17, cose(p, map(&[]), pl, s))),
        ("tag18-wide", [head_w(6, 18, 8), cose(p, map(&[]), pl, s)].concat()),
        ("tag2-wrap", tag(2, cose(p, map(&[]), pl, s))),
        ("indef-array", arr_indef(&[cb(p), map(&[]), cb(pl), cb(s)])),
        ("extra-elem", arr(&[cb(p), map(&[]), cb(pl), cb(s), uint(7)])),
        ("extra-elem-junk", arr(&[cb(p), map(&[]), cb(pl), cb(s), tag(99, arr(&[ct(b"x"), map(&[(uint(1), uint(2))])]))])),
        ("three-elems", arr(&[cb(p), map(&[]), cb(pl)])),
        ("trailing", [cose(p, map(&[]), pl, s), vec![0xff, 0x00, 0x12]].concat()),
        ("chunked-payload", arr(&[cb(p), map(&[]), cb_chunks(pl, 1000), cb(s)])),
        ("chunked-payload-1", arr(&[cb(p), map(&[]), cb_chunks(pl, 4097), cb(s)])),
        ("chunked-all", arr(&[cb_chunks(p, 1), map(&[]), cb_chunks(pl, 7), cb_chunks(s, 50)])),
        ("nested-indef", arr(&[cb(p), map(&[]), [vec![0x5f, 0x5f], cb(&pl[..10]), vec![0xff], cb(&pl[10..]), vec![0xff]].concat(), cb(s)])),
        ("wide-len", arr(&[[head_w(2, p.len() as u64, 8), p.clone()].concat(), map(&[]), [head_w(2, pl.len() as u64, 8), pl.clone()].concat(), [head_w(2, 96, 4), s.clone()].concat()])),
        ("wide-array", [head_w(4, 4, 2), cb(p), map(&[]), cb(pl), cb(s)].concat()),
        ("unprot-entries", cose(p, map(&[(uint(4), cb(b"kid")), (ct(b"x"), arr(&[]))]), pl, s)),
        ("unprot-dup", cose(p, map(&[(uint(4), uint(1)), (uint(4), uint(2))]), pl, s)),
        ("unprot-dup-bignum", cose(p, map(&[(uint(1), uint(0)), (tag(2, cb(&[1])), uint(0))]), pl, s)),
        ("unprot-dup-bignum-indef", cose(p, map(&[(uint(1), uint(0)), (tag(2, cb_chunks(&[1], 1)), uint(0))]), pl, s)),
        ("unprot-dup-bignum-zeros", cose(p, map(&[(uint(1), uint(0)), (tag(2, cb_chunks(&[0, 0, 1], 1)), uint(0))]), pl, s)),
        ("unprot-dup-float", cose(p, map(&[(vec![0xf9, 0x00, 0x00], uint(0)), (vec![0xf9, 0x80, 0x00], uint(0))]), pl, s)),
        ("unprot-dup-float-widths", cose(p, map(&[(vec![0xf9, 0x3c, 0x00], uint(0)), (vec![0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0], uint(0))]), pl, s)),
        ("unprot-nan-keys", cose(p, map(&[(vec![0xf9, 0x7e, 0x00], uint(0)), (vec![0xf9, 0x7e, 0x00], uint(0))]), pl, s)),
        ("unprot-dup-neg", cose(p, map(&[(nint(0), uint(0)), (tag(3, cb(&[0])), uint(0))]), pl, s)),
        ("unprot-dup-int-widths", cose(p, map(&[(uint(5), uint(0)), (head_w(0, 5, 8), uint(0))]), pl, s)),
        ("unprot-dup-text", cose(p, map(&[(ct(b"ab"), uint(0)), ([vec![0x7f], ct(b"a"), ct(b"b"), vec![0xff]].concat(), uint(0))]), pl, s)),
        ("unprot-dup-undef-null", cose(p, map(&[(vec![0xf6], uint(0)), (vec![0xf7], uint(0))]), pl, s)),
        ("unprot-dup-values-differ", cose(p, map(&[(uint(1), uint(0)), (uint(2), uint(0))]), pl, s)),
        ("unprot-dup-tagged-keys", cose(p, map(&[(tag(5, uint(1)), uint(0)), (tag(5, uint(1)), uint(1))]), pl, s)),
        ("unprot-tagged", cose(p, tag(7, map(&[])), pl, s)),
        ("unprot-tagged-bignum", cose(p, tag(2, map(&[])), pl, s)),
        ("unprot-tagged-x2", cose(p, tag(7, tag(8, map(&[(uint(1), uint(1))]))), pl, s)),
        ("unprot-indef", cose(p, vec![0xbf, 0x01, 0x02, 0xff], pl, s)),
        ("unprot-array", cose(p, arr(&[]), pl, s)),
        ("unprot-null", cose(p, vec![0xf6], pl, s)),
        ("unprot-bytes", cose(p, cb(b""), pl, s)),
        ("protected-tagged", arr(&[tag(24, cb(p)), map(&[]), cb(pl), cb(s)])),
        ("payload-tagged", arr(&[cb(p), map(&[]), tag(24, cb(pl)), cb(s)])),
        ("sig-tagged", arr(&[cb(p), map(&[]), cb(pl), tag(1, cb(s))])),
        ("sig-bignum-tag", arr(&[cb(p), map(&[]), cb(pl), tag(2, cb(s))])),
        ("payload-text", arr(&[cb(p), map(&[]), ct(b"x"), cb(s)])),
        ("sig-95", cose(p, map(&[]), pl, &s[..95])),
        ("sig-97", cose(p, map(&[]), pl, &[s.clone(), vec![0]].concat())),
        ("sig-zero-r", cose(p, map(&[]), pl, &[vec![0u8; 48], s[48..].to_vec()].concat())),
        ("sig-ff", cose(p, map(&[]), pl, &vec![0xffu8; 96])),
        ("sig-flip", cose(p, map(&[]), pl, &{
            let mut x = s.clone();
            x[60] ^= 1;
            x
        })),
        ("map-top", map(&[(uint(1), cb(p))])),
        ("empty", vec![]),
        ("zero", vec![0x00, 0x00]),
        ("array-empty", arr(&[])),
    ];
    // high-s: s' = n - s is accepted by RustCrypto's p384 verify
    let n = num_bigint::BigUint::parse_bytes(b"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16).unwrap();
    let sv = num_bigint::BigUint::from_bytes_be(&s[48..]);
    let mut hs = (n - sv).to_bytes_be();
    while hs.len() < 48 {
        hs.insert(0, 0);
    }
    v.push(("sig-high-s", cose(p, map(&[]), pl, &[s[..48].to_vec(), hs].concat())));
    for (name, doc) in v {
        g.push(G, format!("d{di}/cose/{name}"), vec![nitro(&doc, t)]);
    }
}

fn gen_payload(g: &mut Gen, di: usize, d: &Doc, rng: &mut ChaCha20Rng) {
    let m = &d.pmap;
    let mut v: Vec<(String, Vec<(CV, CV)>)> = Vec::new();
    let txt = |s: &str| CV::Text(s.into());
    let byt = |n: usize| CV::Bytes(vec![0x5a; n]);
    let int = |n: i128| CV::Integer(Integer::try_from(n).unwrap());
    v.push(("identity".into(), m.clone()));
    for k in ["module_id", "digest", "timestamp", "pcrs", "certificate", "cabundle", "public_key", "user_data", "nonce"] {
        v.push((format!("drop/{k}"), set(m, k, None)));
        v.push((format!("null/{k}"), set(m, k, Some(CV::Null))));
        v.push((format!("text/{k}"), set(m, k, Some(txt("x")))));
        v.push((format!("bytes/{k}"), set(m, k, Some(byt(3)))));
        v.push((format!("int/{k}"), set(m, k, Some(int(5)))));
        v.push((format!("tagged/{k}"), set(m, k, Some(CV::Tag(24, Box::new(get(m, k).clone()))))));
    }
    v.push(("module_id/empty".into(), set(m, "module_id", Some(txt("")))));
    v.push(("module_id/long".into(), set(m, "module_id", Some(txt(&"m".repeat(5000))))));
    for dg in ["SHA256", "sha384", "SHA384 ", ""] {
        v.push((format!("digest/{dg}"), set(m, "digest", Some(txt(dg)))));
    }
    for n in [0usize, 1, 1024, 1025] {
        v.push((format!("certificate/{n}"), set(m, "certificate", Some(byt(n)))));
        v.push((format!("public_key/{n}"), set(m, "public_key", Some(byt(n)))));
    }
    for n in [0usize, 1, 512, 513] {
        v.push((format!("user_data/{n}"), set(m, "user_data", Some(byt(n)))));
        v.push((format!("nonce/{n}"), set(m, "nonce", Some(byt(n)))));
    }
    for ts in [int(-1), int(0), int(u64::MAX as i128), CV::Tag(2, Box::new(CV::Bytes(vec![1; 9]))), CV::Float(1.0), CV::Bool(true)] {
        v.push((format!("timestamp/{}", hex::encode(enc(&ts))), set(m, "timestamp", Some(ts))));
    }
    // pcrs
    let pcrs = get(m, "pcrs").as_map().unwrap().clone();
    let pset = |p: Vec<(CV, CV)>| set(m, "pcrs", Some(CV::Map(p)));
    v.push(("pcrs/empty".into(), pset(vec![])));
    v.push(("pcrs/array".into(), set(m, "pcrs", Some(CV::Array(vec![])))));
    let mut p33 = pcrs.clone();
    while p33.len() < 33 {
        let i = p33.len() as i128;
        p33.push((int(i), byt(48)));
    }
    v.push(("pcrs/33".into(), pset(p33.clone())));
    p33.pop();
    v.push(("pcrs/32".into(), pset(p33)));
    for (name, key) in [("neg", int(-1)), ("256", int(256)), ("255", int(255)), ("31", int(31)), ("32", int(32)), ("u64max", int(u64::MAX as i128)), ("text", txt("0")), ("bignum", CV::Tag(2, Box::new(CV::Bytes(vec![0, 3]))))] {
        let mut p = pcrs.clone();
        p.push((key, byt(48)));
        v.push((format!("pcrs/key-{name}"), pset(p)));
    }
    for (name, val) in [("31", byt(31)), ("32", byt(32)), ("64", byt(64)), ("65", byt(65)), ("0", byt(0)), ("text", txt("a")), ("zero48", CV::Bytes(vec![0; 48])), ("zero32", CV::Bytes(vec![0; 32]))] {
        let mut p = pcrs.clone();
        p[0].1 = val.clone();
        v.push((format!("pcrs/val0-{name}"), pset(p)));
        let mut p = pcrs.clone();
        p.push((int(20), val));
        v.push((format!("pcrs/add20-{name}"), pset(p)));
    }
    let mut p = pcrs.clone();
    p.push((int(3), byt(48)));
    v.push(("pcrs/dup3".into(), pset(p)));
    let mut p = pcrs.clone();
    p.reverse();
    v.push(("pcrs/reversed".into(), pset(p)));
    let p: Vec<_> = pcrs.iter().filter(|(k, _)| !matches!(i128::from(k.as_integer().unwrap()), 3 | 8)).cloned().collect();
    v.push(("pcrs/no-3-8".into(), pset(p)));
    let p: Vec<_> = pcrs.iter().map(|(k, x)| (k.clone(), if i128::from(k.as_integer().unwrap()) == 0 { CV::Bytes(vec![0; x.as_bytes().unwrap().len()]) } else { x.clone() })).collect();
    v.push(("pcrs/zero0".into(), pset(p)));
    // cabundle
    let cab = get(m, "cabundle").as_array().unwrap().clone();
    let cset = |c: Vec<CV>| set(m, "cabundle", Some(CV::Array(c)));
    v.push(("cabundle/empty".into(), cset(vec![])));
    v.push(("cabundle/one".into(), cset(cab[..1].to_vec())));
    v.push(("cabundle/pop".into(), cset(cab[..cab.len() - 1].to_vec())));
    let mut c10 = cab.clone();
    while c10.len() < 10 {
        c10.push(cab[0].clone());
    }
    v.push(("cabundle/10".into(), cset(c10.clone())));
    c10.push(cab[0].clone());
    v.push(("cabundle/11".into(), cset(c10)));
    let mut c = cab.clone();
    c.push(byt(0));
    v.push(("cabundle/empty-cert".into(), cset(c)));
    let mut c = cab.clone();
    c.push(byt(1025));
    v.push(("cabundle/1025".into(), cset(c)));
    let mut c = cab.clone();
    c.push(byt(1024));
    v.push(("cabundle/1024".into(), cset(c)));
    let mut c = cab.clone();
    c.push(txt("x"));
    v.push(("cabundle/text".into(), cset(c)));
    let mut c = cab.clone();
    c.reverse();
    v.push(("cabundle/reversed".into(), cset(c)));
    // key-level: non-text keys, duplicate keys (last wins in the BTreeMap; upgraded parsing rejects)
    let mut mm = m.clone();
    mm.push((int(1), int(2)));
    v.push(("key/int".into(), mm));
    let mut mm = m.clone();
    mm.push((txt("module_id"), txt("other")));
    v.push(("key/dup-module_id".into(), mm));
    let mut mm = m.clone();
    mm.push((txt("extra"), CV::Array(vec![CV::Null])));
    v.push(("key/extra".into(), mm));
    let mut mm = m.clone();
    mm.reverse();
    v.push(("key/reversed".into(), mm));
    // random field shuffles
    for i in 0..10 {
        let mut mm = m.clone();
        for j in (1..mm.len()).rev() {
            let k = rng.gen_range(0..=j);
            mm.swap(j, k);
        }
        v.push((format!("shuffle/{i}"), mm));
    }
    for (name, mm) in v {
        g.push(G, format!("d{di}/payload/{name}"), vec![nitro(&with_map(d, mm), d.ts)]);
    }
    // payload that is not a map / not CBOR / sizes at the COSE limits
    let raw_payloads: Vec<(&str, Vec<u8>)> = vec![
        ("array", arr(&[])),
        ("tagged-map", tag(1, d.payload.clone())),
        ("empty", vec![]),
        ("one", vec![0xa0]),
        ("bad", vec![0x1c]),
        ("trailing", [d.payload.clone(), vec![0xff, 0xff]].concat()),
        ("16383", [d.payload.clone(), vec![0u8; 16383 - d.payload.len()]].concat()),
        ("16384", [d.payload.clone(), vec![0u8; 16384 - d.payload.len()]].concat()),
        ("indef-map", {
            let mut x = vec![0xbf];
            for (k, val) in m {
                x.extend(enc(k));
                x.extend(enc(val));
            }
            x.push(0xff);
            x
        }),
    ];
    for (name, pl) in raw_payloads {
        g.push(G, format!("d{di}/payload-raw/{name}"), vec![nitro(&cose(&d.protected, map(&[]), &pl, &d.sig), d.ts)]);
    }
    // protected header variants (all break the signature; parse rules only)
    let prots: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("empty-map", map(&[])),
        ("alg-256", map(&[(uint(1), nint(6))])),
        ("two", map(&[(uint(1), nint(34)), (uint(4), uint(0))])),
        ("dup", map(&[(uint(1), nint(34)), (uint(1), nint(34))])),
        ("wide", map(&[(head_w(0, 1, 8), head_w(1, 34, 2))])),
        ("bignum", map(&[(tag(2, cb(&[1])), tag(3, cb(&[34])))])),
        ("tagged", tag(5, map(&[(uint(1), nint(34))]))),
        ("trailing", [map(&[(uint(1), nint(34))]), vec![0x00]].concat()),
        ("indef", vec![0xbf, 0x01, 0x38, 0x22, 0xff]),
        ("text-key", map(&[(ct(b"1"), nint(34))])),
        ("not-cbor", vec![0x1c]),
    ];
    for (name, pr) in prots {
        g.push(G, format!("d{di}/protected/{name}"), vec![nitro(&cose(&pr, map(&[]), &d.payload, &d.sig), d.ts)]);
    }
}

fn gen_flips(g: &mut Gen, di: usize, d: &Doc, rng: &mut ChaCha20Rng) {
    let n = d.raw.len();
    // the first 64 bytes cover the COSE and payload headers; flip each bit there
    for i in 0..64.min(n) {
        for bit in [0u8, 3, 5, 7] {
            let mut x = d.raw.clone();
            x[i] ^= 1 << bit;
            g.push(G, format!("d{di}/flip/{i}.{bit}"), vec![nitro(&x, d.ts)]);
        }
    }
    for k in 0..150 {
        let mut x = d.raw.clone();
        let i = rng.gen_range(0..n);
        x[i] = rng.r#gen();
        g.push(G, format!("d{di}/rand/{k}.{i}"), vec![nitro(&x, d.ts)]);
    }
    for k in 0..30 {
        let l = rng.gen_range(0..n);
        g.push(G, format!("d{di}/trunc/{k}.{l}"), vec![nitro(&d.raw[..l], d.ts)]);
    }
}

/// CBOR edge cases in the unprotected header (the only free-form part of a COSE_Sign1 that both
/// parses reach) and at the top level. Each keeps the genuine document's other fields, so a
/// value ciborium accepts verifies (success) and one it rejects is a parse error.
fn gen_cbor_edges(g: &mut Gen, d: &Doc) {
    let mut v: Vec<(String, Vec<u8>)> = Vec::new();
    let mut val = |name: &str, x: Vec<u8>| v.push((name.to_string(), x));
    val("simple-0", vec![0xe0]);
    val("simple-19", vec![0xf3]);
    val("simple-20", vec![0xf4]);
    val("simple-23", vec![0xf7]);
    val("simple-24-20", vec![0xf8, 0x14]);
    val("simple-24-0", vec![0xf8, 0x00]);
    val("simple-24-255", vec![0xf8, 0xff]);
    val("f16", vec![0xf9, 0x3c, 0x00]);
    val("f32", vec![0xfa, 0x3f, 0x80, 0, 0]);
    val("f64-nan", vec![0xfb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 1]);
    val("f16-snan", vec![0xf9, 0x7c, 0x01]);
    val("minor-28", vec![0x1c]);
    val("minor-29", vec![0x3d]);
    val("minor-30", vec![0x5e]);
    val("major7-28", vec![0xfc]);
    val("break", vec![0xff]);
    val("indef-int", vec![0x1f]);
    val("indef-neg", vec![0x3f]);
    val("indef-tag", vec![0xdf, 0x00]);
    val("neg-max", vec![0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    val("neg-i64", vec![0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    val("pos-max", vec![0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    val("bignum-16", tag(2, cb(&[0xff; 16])));
    val("bignum-17", tag(2, cb(&[0xff; 17])));
    val("bignum-17-lead0", tag(2, cb(&[[0u8].to_vec(), vec![0xff; 16]].concat())));
    val("bignum-neg-16-big", tag(3, cb(&[0x80; 16])));
    val("bignum-neg-16-ok", tag(3, cb(&[[0x7f].to_vec(), vec![0xff; 15]].concat())));
    val("bignum-neg-indef-big", tag(3, cb_chunks(&[0x80; 16], 4)));
    val("bignum-neg-indef-ok", tag(3, cb_chunks(&[[0x7f].to_vec(), vec![0xff; 15]].concat(), 4)));
    val("bignum-text", tag(2, ct(b"1")));
    val("bignum-empty", tag(2, cb(&[])));
    val("bignum-eof", tag(2, vec![]));
    val("tag-eof", tag(9, vec![]));
    val("tag-bad-next", tag(9, vec![0x1c]));
    val("text-bad-utf8", ct(&[0x61, 0xff]));
    val("text-surrogate", ct(&[0xed, 0xa0, 0x80]));
    val("text-overlong", ct(&[0xc0, 0x80]));
    val("text-4096-split", ct(&[vec![b'a'; 4095], "é".as_bytes().to_vec()].concat()));
    val("text-4097-split", ct(&[vec![b'a'; 4095], "€".as_bytes().to_vec()].concat()));
    val("text-big-bad-end", ct(&[vec![b'a'; 5000], vec![0xe2, 0x82]].concat()));
    val("text-big-bad-mid", ct(&[vec![b'a'; 4094], vec![0xff], vec![b'a'; 100]].concat()));
    val("text-big-bad-at-4093", ct(&[vec![b'a'; 4093], vec![0xff], vec![b'a'; 100]].concat()));
    val("text-big-bad-at-4095", ct(&[vec![b'a'; 4095], vec![0xff, 0x61], vec![b'a'; 100]].concat()));
    val("text-big-ok", ct(&"€".repeat(3000).into_bytes()));
    val("text-indef-split-char", [vec![0x7f], ct(&[0xe2, 0x82]), ct(&[0xac]), vec![0xff]].concat());
    val("text-indef-ok", [vec![0x7f], ct("é".as_bytes()), ct(b"a"), vec![0xff]].concat());
    val("text-indef-nested", [vec![0x7f, 0x7f], ct(b"a"), vec![0xff], ct(b"b"), vec![0xff]].concat());
    val("text-indef-bytes-chunk", [vec![0x7f], cb(b"a"), vec![0xff]].concat());
    val("bytes-indef-text-chunk", [vec![0x5f], ct(b"a"), vec![0xff]].concat());
    val("bytes-indef-empty", vec![0x5f, 0xff]);
    val("bytes-indef-eof", vec![0x5f, 0x41, 0x00]);
    val("bytes-len-huge", vec![0x5b, 0, 0, 0, 1, 0, 0, 0, 0]);
    val("text-len-huge", vec![0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    val("array-len-huge", vec![0x9b, 0, 0, 0, 1, 0, 0, 0, 0]);
    val("map-odd-indef", vec![0xbf, 0x01, 0xff]);
    val("map-indef-break-key", vec![0xbf, 0x01, 0x02, 0xff]);
    val("array-indef-unterminated", vec![0x9f, 0x01]);
    for depth in [250usize, 251, 252, 253, 254, 255, 256] {
        val(&format!("nest-array-{depth}"), [vec![0x81; depth], vec![0x00]].concat());
        val(&format!("nest-tag-{depth}"), [vec![0xc9; depth], vec![0x00]].concat());
        val(&format!("nest-map-{depth}"), {
            let mut x = Vec::new();
            for _ in 0..depth {
                x.extend([0xa1, 0x00]);
            }
            x.push(0x00);
            x
        });
    }
    val("nest-bignum-tags", [vec![0xc2; 300], cb(&[1])].concat());
    // ciborium reads text in 4096-byte windows of its scratch buffer; a character across a
    // window boundary is an error, also after the round trip joins indefinite chunks
    val("text-indef-join-straddle", [vec![0x7f], ct(&vec![b'a'; 4095]), ct("é".as_bytes()), vec![0xff]].concat());
    val("text-indef-join-aligned", [vec![0x7f], ct(&vec![b'a'; 4096]), ct("é".as_bytes()), vec![0xff]].concat());
    val("text-8192-straddle", ct(&[vec![b'a'; 8191], "é".as_bytes().to_vec()].concat()));
    val("text-8192-aligned", ct(&[vec![b'a'; 8192], "é".as_bytes().to_vec()].concat()));
    val("text-4096-exact", ct(&vec![b'a'; 4096]));
    val("text-4095-then-3", ct(&[vec![b'a'; 4094], "€".as_bytes().to_vec()].concat()));
    val("text-indef-big-chunk-straddle", [vec![0x7f], ct(&[vec![b'a'; 4095], "é".as_bytes().to_vec()].concat()), vec![0xff]].concat());
    // random CBOR token soup (valid and invalid)
    let mut rng = ChaCha20Rng::seed_from_u64(0xc0b0_5eed);
    for k in 0..400 {
        v.push((format!("fuzz/{k}"), fuzz_item(&mut rng, 0)));
    }
    for (name, x) in v {
        // as an unprotected-header value
        let doc = cose(&d.protected, [vec![0xa1, 0x05], x.clone()].concat(), &d.payload, &d.sig);
        g.push(G, format!("cbor/unprot-val/{name}"), vec![nitro(&doc, d.ts)]);
        // as an unprotected-header key
        let doc = cose(&d.protected, [vec![0xa1], x.clone(), vec![0x05]].concat(), &d.payload, &d.sig);
        g.push(G, format!("cbor/unprot-key/{name}"), vec![nitro(&doc, d.ts)]);
        // as a fifth array element
        let doc = arr(&[cb(&d.protected), map(&[]), cb(&d.payload), cb(&d.sig), x.clone()]);
        g.push(G, format!("cbor/elem5/{name}"), vec![nitro(&doc, d.ts)]);
        // as a payload map value (signature breaks: parse-or-verify)
        let pl = {
            let mut m = enc(&CV::Map(d.pmap.clone()));
            // bump the map length by one and append ("zz": x)
            let n = d.pmap.len() as u64 + 1;
            let h = head(5, d.pmap.len() as u64).len();
            m.splice(0..h, head(5, n));
            m.extend(ct(b"zz"));
            m.extend(x.clone());
            m
        };
        g.push(G, format!("cbor/payload-val/{name}"), vec![nitro(&cose(&d.protected, map(&[]), &pl, &d.sig), d.ts)]);
    }
}

fn gen_misc(g: &mut Gen, docs: &[Doc]) {
    // swapped payloads and signatures across documents
    for (i, a) in docs.iter().enumerate() {
        for (j, b) in docs.iter().enumerate() {
            if i != j {
                g.push(G, format!("swap/sig/{i}-{j}"), vec![nitro(&cose(&a.protected, map(&[]), &a.payload, &b.sig), a.ts)]);
            }
        }
    }
    // several calls in one item (the extension state does not change across calls)
    let d = &docs[0];
    g.push(G, "multi/3".into(), vec![nitro(&d.raw, d.ts), nitro(&d.raw, 0), nitro(&docs[1].raw, docs[1].ts)]);
}

/// A random CBOR item, mostly well formed, sometimes not (reserved minors, stray breaks,
/// truncation, bad UTF-8, odd tags).
fn fuzz_item(rng: &mut ChaCha20Rng, depth: usize) -> Vec<u8> {
    let k = rng.gen_range(0..if depth > 6 { 10 } else { 16 });
    match k {
        0 => uint(rng.gen_range(0..100_000)),
        1 => head_w(1, rng.r#gen(), [0u8, 1, 2, 4, 8][rng.gen_range(0..5)]),
        2 => cb(&(0..rng.gen_range(0..20)).map(|_| rng.r#gen()).collect::<Vec<u8>>()),
        3 => {
            let s: Vec<u8> = (0..rng.gen_range(0..12)).map(|_| if rng.gen_bool(0.9) { rng.gen_range(0x20..0x7f) } else { rng.r#gen() }).collect();
            ct(&s)
        }
        4 => vec![[0xf4u8, 0xf5, 0xf6, 0xf7, 0xf0, 0xf8][rng.gen_range(0..6)]],
        5 => {
            let mut v = vec![0xf9];
            v.extend((0..2).map(|_| rng.r#gen::<u8>()));
            v
        }
        6 => {
            let mut v = vec![[0xfau8, 0xfb][rng.gen_range(0..2)]];
            let n = if v[0] == 0xfa { 4 } else { 8 };
            v.extend((0..n).map(|_| rng.r#gen::<u8>()));
            v
        }
        7 => tag([2u64, 3, 0, 1, 18, 24, 55799, 1 << 40][rng.gen_range(0..8)], if rng.gen_bool(0.5) { cb(&(0..rng.gen_range(0..18)).map(|_| rng.r#gen()).collect::<Vec<u8>>()) } else { fuzz_item(rng, depth + 1) }),
        8 => vec![[0x1cu8, 0xff, 0x1f, 0x3f, 0xdf, 0x5f][rng.gen_range(0..6)]],
        9 => {
            let x = fuzz_item(rng, depth + 1);
            x[..rng.gen_range(0..=x.len())].to_vec()
        }
        10 | 11 => {
            let n = rng.gen_range(0..4);
            let items: Vec<Vec<u8>> = (0..n).map(|_| fuzz_item(rng, depth + 1)).collect();
            if rng.gen_bool(0.3) { arr_indef(&items) } else { arr(&items) }
        }
        12 | 13 => {
            let n = rng.gen_range(0..4);
            let e: Vec<(Vec<u8>, Vec<u8>)> = (0..n).map(|_| (fuzz_item(rng, depth + 1), fuzz_item(rng, depth + 1))).collect();
            if rng.gen_bool(0.3) {
                let mut v = vec![0xbf];
                for (a, b) in e {
                    v.extend(a);
                    v.extend(b);
                }
                v.push(0xff);
                v
            } else {
                map(&e)
            }
        }
        14 => {
            let mut v = vec![0x5f];
            for _ in 0..rng.gen_range(0..3) {
                v.extend(if rng.gen_bool(0.8) { cb(&[rng.r#gen()]) } else { ct(b"x") });
            }
            v.push(0xff);
            v
        }
        _ => {
            let mut v = vec![0x7f];
            for _ in 0..rng.gen_range(0..3) {
                v.extend(if rng.gen_bool(0.7) { ct(&[rng.gen_range(0x20..0xff)]) } else { cb(b"x") });
            }
            v.push(0xff);
            v
        }
    }
}
