//! Round 3: 0x3::validator::validate_metadata_bcs.
//!
//! Inputs are the real metadata of every active mainnet validator (data/validators.json, read
//! from the public GraphQL endpoint at epoch 1304), plus:
//! - per-field mutations: BLS protocol key and proof of possession (lengths, uncompressed forms,
//!   infinity, off-subgroup points, swapped keys), ed25519 network/worker keys (lengths,
//!   non-canonical and small-order encodings, equal keys), every next-epoch combination of the
//!   metadata_v2 rules, freshly made next-epoch keys and PoPs;
//! - multiaddr strings in every address slot (hand-made edge cases for each protocol's value
//!   grammar, then random multiaddrs), so both Multiaddr::from_str and to_anemo_address are
//!   compared;
//! - BCS damage (every truncation, trailing bytes, bad option tags, non-canonical ULEB, bad
//!   UTF-8), several errors at once (check order), budgets around both charges and a protocol
//!   sweep.

use crate::vm::Call;
use crate::{Gen, PV_MAX, PV_MIN_V4, bv, call};
use fastcrypto::traits::{KeyPair as _, ToFromBytes};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde_json::Value as J;

const VALIDATORS: &str = include_str!("../data/validators.json");
const G: &str = "validator";

fn vcall(b: &[u8]) -> Call {
    call(3, "validator", "validate_metadata_bcs", vec![], vec![bv(b)])
}

#[derive(Clone)]
struct Meta {
    addr: Vec<u8>,
    ppk: Vec<u8>,
    npk: Vec<u8>,
    wpk: Vec<u8>,
    pop: Vec<u8>,
    name: Vec<u8>,
    desc: Vec<u8>,
    img: Vec<u8>,
    proj: Vec<u8>,
    net: Vec<u8>,
    p2p: Vec<u8>,
    pri: Vec<u8>,
    wrk: Vec<u8>,
    n_ppk: Option<Vec<u8>>,
    n_pop: Option<Vec<u8>>,
    n_npk: Option<Vec<u8>>,
    n_wpk: Option<Vec<u8>>,
    n_net: Option<Vec<u8>>,
    n_p2p: Option<Vec<u8>>,
    n_pri: Option<Vec<u8>>,
    n_wrk: Option<Vec<u8>>,
    bag_id: Vec<u8>,
    bag_size: u64,
}

fn uleb(mut n: u64, out: &mut Vec<u8>) {
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
fn vecb(b: &[u8], out: &mut Vec<u8>) {
    uleb(b.len() as u64, out);
    out.extend_from_slice(b);
}
fn optb(b: &Option<Vec<u8>>, out: &mut Vec<u8>) {
    match b {
        None => out.push(0),
        Some(b) => {
            out.push(1);
            vecb(b, out);
        }
    }
}

impl Meta {
    fn enc(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&self.addr);
        for f in [&self.ppk, &self.npk, &self.wpk, &self.pop, &self.name, &self.desc, &self.img, &self.proj, &self.net, &self.p2p, &self.pri, &self.wrk] {
            vecb(f, &mut o);
        }
        for f in [&self.n_ppk, &self.n_pop, &self.n_npk, &self.n_wpk, &self.n_net, &self.n_p2p, &self.n_pri, &self.n_wrk] {
            optb(f, &mut o);
        }
        o.extend_from_slice(&self.bag_id);
        o.extend_from_slice(&self.bag_size.to_le_bytes());
        o
    }
    /// The 8 address slots: 0 net, 1 p2p, 2 primary, 3 worker, 4..8 the next-epoch ones.
    fn set_addr(&mut self, slot: usize, s: &[u8]) {
        let v = s.to_vec();
        match slot {
            0 => self.net = v,
            1 => self.p2p = v,
            2 => self.pri = v,
            3 => self.wrk = v,
            4 => self.n_net = Some(v),
            5 => self.n_p2p = Some(v),
            6 => self.n_pri = Some(v),
            _ => self.n_wrk = Some(v),
        }
    }
}

fn b64d(s: &str) -> Vec<u8> {
    use fastcrypto::encoding::{Base64, Encoding};
    Base64::decode(s).unwrap_or_else(|e| panic!("b64 {s}: {e}"))
}
fn hexd(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).unwrap()
}
fn sb(j: &J) -> Vec<u8> {
    j.as_str().unwrap().as_bytes().to_vec()
}
fn ob(j: &J, f: fn(&str) -> Vec<u8>) -> Option<Vec<u8>> {
    j.as_str().map(f)
}

fn load() -> Vec<Meta> {
    let all: Vec<J> = serde_json::from_str(VALIDATORS).unwrap();
    all.iter()
        .map(|m| Meta {
            addr: hexd(m["sui_address"].as_str().unwrap()),
            ppk: b64d(m["protocol_pubkey_bytes"].as_str().unwrap()),
            npk: b64d(m["network_pubkey_bytes"].as_str().unwrap()),
            wpk: b64d(m["worker_pubkey_bytes"].as_str().unwrap()),
            pop: b64d(m["proof_of_possession"].as_str().unwrap()),
            name: sb(&m["name"]),
            desc: sb(&m["description"]),
            img: sb(&m["image_url"]),
            proj: sb(&m["project_url"]),
            net: sb(&m["net_address"]),
            p2p: sb(&m["p2p_address"]),
            pri: sb(&m["primary_address"]),
            wrk: sb(&m["worker_address"]),
            n_ppk: ob(&m["next_epoch_protocol_pubkey_bytes"], b64d),
            n_pop: ob(&m["next_epoch_proof_of_possession"], b64d),
            n_npk: ob(&m["next_epoch_network_pubkey_bytes"], b64d),
            n_wpk: ob(&m["next_epoch_worker_pubkey_bytes"], b64d),
            n_net: ob(&m["next_epoch_net_address"], |s| s.as_bytes().to_vec()),
            n_p2p: ob(&m["next_epoch_p2p_address"], |s| s.as_bytes().to_vec()),
            n_pri: ob(&m["next_epoch_primary_address"], |s| s.as_bytes().to_vec()),
            n_wrk: ob(&m["next_epoch_worker_address"], |s| s.as_bytes().to_vec()),
            bag_id: hexd(m["extra_fields"]["id"].as_str().unwrap()),
            bag_size: m["extra_fields"]["size"].as_str().unwrap().parse().unwrap(),
        })
        .collect()
}

// ---- keys ------------------------------------------------------------------------------------

struct Keys {
    /// next-epoch key pairs: (pk compressed, pk uncompressed, pop for each base address)
    fresh: Vec<sui_types::crypto::AuthorityKeyPair>,
    off_g2: Vec<Vec<u8>>, // on the curve, not in G2's subgroup
    off_g1: Vec<Vec<u8>>,
    ed_bad: Vec<Vec<u8>>, // 32 bytes that do not decompress
    ed_ok: Vec<Vec<u8>>,  // 32 bytes that decompress (random)
}

fn make_keys(rng: &mut ChaCha20Rng) -> Keys {
    use fastcrypto::bls12381::min_sig::{BLS12381PublicKey, BLS12381Signature};
    let mut std_rng = rand::rngs::StdRng::seed_from_u64(0x7a11_da7e);
    let fresh = (0..6).map(|_| sui_types::crypto::get_key_pair_from_rng::<sui_types::crypto::AuthorityKeyPair, _>(&mut std_rng).1).collect();
    let mut off_g2 = Vec::new();
    while off_g2.len() < 3 {
        let mut b = vec![0u8; 96];
        rng.fill(&mut b[..]);
        b[0] = (b[0] & 0x1f) | 0x80 | (rng.r#gen::<u8>() & 0x20);
        if let Ok(pk) = BLS12381PublicKey::from_bytes(&b) {
            if pk.validate().is_err() {
                off_g2.push(b);
            }
        }
    }
    let mut off_g1 = Vec::new();
    while off_g1.len() < 3 {
        let mut b = vec![0u8; 48];
        rng.fill(&mut b[..]);
        b[0] = (b[0] & 0x1f) | 0x80;
        if BLS12381Signature::from_bytes(&b).is_ok() {
            off_g1.push(b);
        }
    }
    let mut ed_bad = Vec::new();
    let mut ed_ok = Vec::new();
    while ed_bad.len() < 4 || ed_ok.len() < 4 {
        let mut b = vec![0u8; 32];
        rng.fill(&mut b[..]);
        if fastcrypto::ed25519::Ed25519PublicKey::from_bytes(&b).is_ok() {
            if ed_ok.len() < 4 {
                ed_ok.push(b);
            }
        } else if ed_bad.len() < 4 {
            ed_bad.push(b);
        }
    }
    Keys { fresh, off_g2, off_g1, ed_bad, ed_ok }
}

fn g2_uncompressed(pk: &[u8]) -> Vec<u8> {
    blst::min_sig::PublicKey::from_bytes(pk).unwrap().serialize().to_vec()
}
fn g1_uncompressed(s: &[u8]) -> Vec<u8> {
    blst::min_sig::Signature::from_bytes(s).unwrap().serialize().to_vec()
}

fn pop_for(kp: &sui_types::crypto::AuthorityKeyPair, addr: &[u8]) -> Vec<u8> {
    let a = sui_types::base_types::SuiAddress::from_bytes(addr).unwrap();
    sui_types::crypto::generate_proof_of_possession(kp, a).as_bytes().to_vec()
}
fn pk_of(kp: &sui_types::crypto::AuthorityKeyPair) -> Vec<u8> {
    kp.public().as_bytes().to_vec()
}

/// ed25519 encodings around the edges: identity, y = 0, non-canonical y >= p, sign bits.
fn ed_edges() -> Vec<(&'static str, Vec<u8>)> {
    let mut v = Vec::new();
    let mut id = vec![0u8; 32];
    id[0] = 1;
    v.push(("identity", id.clone()));
    let mut idn = id.clone();
    idn[31] |= 0x80;
    v.push(("identity-neg", idn));
    v.push(("zero", vec![0u8; 32]));
    let mut zn = vec![0u8; 32];
    zn[31] = 0x80;
    v.push(("zero-neg", zn));
    let mut p = vec![0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    v.push(("y=p", p.clone()));
    let mut p1 = p.clone();
    p1[0] = 0xee;
    v.push(("y=p+1", p1));
    let mut pm1 = p.clone();
    pm1[0] = 0xec;
    v.push(("y=p-1", pm1.clone()));
    let mut pm1n = pm1;
    pm1n[31] |= 0x80;
    v.push(("y=p-1-neg", pm1n));
    v.push(("all-ff", vec![0xffu8; 32]));
    let mut a7 = vec![0xffu8; 32];
    a7[31] = 0x7f;
    v.push(("2^255-1", a7));
    // small-order point of order 4 (x = sqrt(-1), y = 0) and of order 8
    v.push(("order8", hex::decode("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05").unwrap()));
    v.push(("order8b", hex::decode("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a").unwrap()));
    v
}

// ---- multiaddrs --------------------------------------------------------------------------------

fn mb(base: multibase::Base, d: &[u8]) -> String {
    multibase::encode(base, d)
}
fn b58(d: &[u8]) -> String {
    let s = mb(multibase::Base::Base58Btc, d);
    s[1..].to_string()
}
fn mh(code: u64, digest: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    uleb(code, &mut v);
    uleb(digest.len() as u64, &mut v);
    v.extend_from_slice(digest);
    v
}
fn b32up(d: &[u8]) -> String {
    let s = mb(multibase::Base::Base32Upper, d);
    s[1..].to_string()
}

fn ip4_vals() -> Vec<String> {
    [
        "0.0.0.0", "255.255.255.255", "256.0.0.1", "01.2.3.4", "1.2.3", "1.2.3.4.5", "1..2.3", " 1.2.3.4", "1.2.3.4 ", "001.2.3.4",
        "000.0.0.0", "0.00.0.0", "+1.2.3.4", "1.2.3.04", "a.b.c.d", "", "1.2.3.4%", "100.100.100.100", "100.100.100.1000", "255.255.255.256",
        "1.2.3.4.", ".1.2.3.4", "1.2.3.-4", "0x1.2.3.4", "１.2.3.4", "127.0.0.1", "10.0.0.255", "199.199.199.199", "1.2.3.4:80", "1.2.3.4/32",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn ip6_vals() -> Vec<String> {
    [
        "::", "::1", "1::", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9", "1::2::3", "::ffff:1.2.3.4", "1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:7:1.2.3.4",
        "::1.2.3.4", "1::1.2.3.4", "fe80::1%eth0", "[::1]", "12345::", "0000:0000::", "00000::", "1:::2", ":1::", "1::2:", ":", "1:2:3:4:5:6:7::",
        "::1:2:3:4:5:6:7", "::1:2:3:4:5:6:7:8", "1:2:3:4::5:6:7:8", "FFFF::", "g::", "1.2.3.4", "::1.2.3", "::01.2.3.4", "::1.2.3.4:5",
        "1:2:3:4:5:6:7:8:", "1:2:3:4:5:6::1.2.3.4", "1:2:3:4:5::1.2.3.4", "::1.2.3.4::", "1.2.3.4::", "1:2:3:4:5:6:7:8::", "::ffff:256.1.1.1",
        "abcd:EF01::", "0:0:0:0:0:0:0:0", "2001:db8::8a2e:370:7334", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "", "::0", "0::0", ":::",
        "1:2:3:4:5:6:7", "1:2", "1::2:3:4:5:6:7", "1::2:3:4:5:6:7:8", "::2:3:4:5:6:7:8", "1:2:3:4:5:6:7::8", "1:2::1.2.3.4", "::1.2.3.4.5",
        "1:2:3:4:5:6:1.2.3", "fffff::", "+1::", "1:+2::", "::1.2.3.4/", "::-1",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn port_vals() -> Vec<String> {
    ["0", "1", "65535", "65536", "+1", "+", "-1", "", "00080", "1a", " 1", "٣", "99999999999999999999", "++1", "+0", "08", "-0", "1 "]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn p2p_vals(rng: &mut ChaCha20Rng) -> Vec<String> {
    let d32: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
    let mut v = vec![
        b58(&mh(0x12, &d32)),
        b58(&mh(0x12, &d32[..20])),
        b58(&mh(0x12, &[])),
        b58(&mh(0, &d32)),
        b58(&mh(0, &[d32.clone(), d32[..10].to_vec()].concat())), // 42
        b58(&mh(0, &[d32.clone(), d32[..11].to_vec()].concat())), // 43
        b58(&mh(0x13, &d32)),
        b58(&mh(0x12, &[d32.clone(), d32.clone(), vec![1]].concat())), // 65
        b58(&mh(0x12, &[d32.clone(), d32.clone()].concat())),         // 64
        b58(&[mh(0x12, &d32), vec![0]].concat()),                       // trailing
        b58(&mh(0x12, &d32)[..33]),                                     // short
        b58(&[vec![0x92, 0x00], vec![32], d32.clone()].concat()),      // non-minimal code varint
        b58(&[vec![0x12], vec![0xa0, 0x00], d32.clone()].concat()),    // non-minimal size varint
        b58(&[vec![0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01], vec![0], ].concat()), // 10-byte code, wraps to 2^63
        b58(&[vec![0x92, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02], vec![0]].concat()),  // 10-byte, low bits 0x12
        b58(&[vec![0x92, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00], vec![0]].concat()), // 11 bytes
        b58(&[vec![0x12], vec![0xa0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02], d32.clone()].concat()), // size wraps to 32
        "".into(),
        "1".into(),
        "11111".into(),
        "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC".into(),
        "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNK0".into(),
        "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKI".into(),
        "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA".into(),
        "zQmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC".into(),
    ];
    let lead = format!("1{}", b58(&mh(0x12, &d32)));
    v.push(lead);
    v
}

fn onion_vals() -> Vec<(bool, String)> {
    // (onion3?, value)
    let a10 = b32up(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    let a35 = b32up(&(0..35u8).collect::<Vec<_>>());
    let mut v = vec![
        (false, format!("{a10}:80")),
        (false, format!("{}:80", a10.to_lowercase())),
        (false, format!("{a10}:0")),
        (false, format!("{a10}:65535")),
        (false, format!("{a10}:65536")),
        (false, format!("{a10}")),
        (false, format!("{a10}:")),
        (false, format!("{a10}:80:1")),
        (false, format!("{}:80", &a10[..15])),
        (false, format!("{a10}A:80")),
        (false, format!("{a10}:+80")),
        (false, "AAAAAAAAAAAAAA==:80".into()),
        (false, "AAAAAAAAAAAAAAA=:80".into()),
        (false, "AAAAAAAAAAAA====:80".into()),
        (false, "AAAAAAAAAAA=====:80".into()),
        (false, "AAAAAAAAAAAAAAAB:80".into()),
        (false, "AAAAAAAA========:80".into()),
        (false, "========AAAAAAAA:80".into()),
        (false, "AAAAAAAAAAAAAAA1:80".into()),
        (false, "aaaaaaaaaaaaaaıa:80".into()),
        (false, "aaaaaaaaaaaaaaſa:80".into()),
        (false, "aaaaaaaaaaaaaaß:80".into()),
        (false, "aaaaaaaaaaaaﬃa:80".into()),
        (false, "aaaaaaaaaaaaaﬀa:80".into()),
        (false, "aaaaaaaaaaaaaﬅa:80".into()),
        (false, "aaaaaaaaaaaaaaKa:80".into()),
        (false, "aaaaaaaaaaaaaaéa:80".into()),
        (false, "aaaaaaaaaaaaaaaa:8０".into()),
        (true, format!("{a35}:1234")),
        (true, format!("{}:1234", a35.to_lowercase())),
        (true, format!("{a35}:0")),
        (true, format!("{}:1234", &a35[..55])),
        (true, format!("{a10}:1234")),
        (true, format!("{}=:1", &a35[..55])),
    ];
    // the last character carries trailing bits in a 16 = 2*8 block? No: 10 bytes = 16 chars is
    // exact; flip the last character instead to exercise the alphabet.
    let mut x = a10.clone().into_bytes();
    x[15] = b'9';
    v.push((false, format!("{}:1", String::from_utf8(x).unwrap())));
    v
}

fn certhash_vals(rng: &mut ChaCha20Rng) -> Vec<String> {
    use multibase::Base::*;
    let d: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
    let good = mh(0x12, &d);
    let mut v = Vec::new();
    for base in [
        Identity, Base2, Base8, Base10, Base16Lower, Base16Upper, Base32Lower, Base32Upper, Base32PadLower, Base32PadUpper, Base32HexLower,
        Base32HexUpper, Base32HexPadLower, Base32HexPadUpper, Base32Z, Base36Lower, Base36Upper, Base58Flickr, Base58Btc, Base64, Base64Pad,
        Base64Url, Base64UrlPad,
    ] {
        for data in [good.clone(), mh(0x1e, &d[..20]), mh(0, &[]), vec![0, 0], vec![0x12, 0x20], [good.clone(), vec![7]].concat(), vec![0x12, 0x41]] {
            if base == Identity && std::str::from_utf8(&data).is_err() {
                continue;
            }
            v.push(mb(base, &data));
        }
    }
    let u = mb(Base64Url, &good);
    v.extend([
        "".to_string(),
        "x".into(),
        "u".into(),
        "é".into(),
        format!("{u}="),
        format!("{}A", u),
        u.replace('u', "U"),
        format!("f{}", hex::encode(&good).to_uppercase()),
        format!("F{}", hex::encode(&good)),
        format!("f{}0", hex::encode(&good)),
        format!("k{}", mb(Base36Lower, &good)[1..].to_uppercase()),
        format!("K{}", mb(Base36Upper, &good)[1..].to_lowercase()),
        format!("b{}", mb(Base32Lower, &good)[1..].to_uppercase()),
        format!("h{}", mb(Base32Z, &good)[1..].to_uppercase()),
        format!("c{}", mb(Base32PadLower, &good)[1..].trim_end_matches('=')),
        format!("M{}", mb(Base64, &good)[1..].to_string()),
        format!("m{}", mb(Base64Pad, &good)[1..].to_string()),
        format!("C{}", mb(Base32PadUpper, &[good.clone(), good.clone()].concat())[1..].to_string()),
        "C========".into(),
        "CAA======".into(),
        "CAE======".into(),
        "MAA==AA==".into(),
        "MAQ==CBI=".into(),
        "MEiA=AAAA".into(),
        "0".into(),
        "000010010".into(),
        "0000100100010000".into(),
        "7".into(),
        "7044".into(),
        "70440".into(),
        "9".into(),
        "9000".into(),
        "z".into(),
        "z1111".into(),
        "f".into(),
        "f1".into(),
        "fgg".into(),
        "m=".into(),
        "mAB".into(),
        "mAA".into(),
        "mA".into(),
        "bAA".into(),
        "bAB".into(),
        "vAA".into(),
        "vAW".into(),
        "\u{0}\u{12}\u{0}".into(),
        "\u{0}\u{0}\u{0}".into(),
    ]);
    v
}

fn ws_vals() -> Vec<String> {
    ["%2F", "%2f", "%ff", "%zz", "%", "%2", "a%", "%e2%82%ac", "%E2%82", "%C3%A9x", "plain", "", "%%41", "%4", "%41%"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn garlic_vals(rng: &mut ChaCha20Rng) -> Vec<(bool, String)> {
    // (garlic64?, value)
    use multibase::Base::*;
    let mut v = Vec::new();
    for n in [386usize, 387, 388, 389, 462, 463, 464] {
        let d: Vec<u8> = (0..n).map(|_| rng.r#gen()).collect();
        let s = mb(Base64, &d)[1..].replace('+', "-").replace('/', "~");
        v.push((true, s.clone()));
        if s.len() > 0 {
            v.push((true, format!("{}A", s)));
            v.push((true, s.replace('-', "+")));
        }
    }
    v.push((true, "A".repeat(515)));
    v.push((true, "A".repeat(516)));
    v.push((true, "A".repeat(617)));
    v.push((true, "A".repeat(616)));
    v.push((true, format!("{}B", "A".repeat(515)))); // 516: trailing bits
    for n in [32usize, 33, 34, 35, 36, 40] {
        let d: Vec<u8> = (0..n).map(|_| rng.r#gen()).collect();
        let s = mb(Base32Lower, &d)[1..].to_string();
        v.push((false, s.clone()));
        v.push((false, s.to_uppercase()));
    }
    v.push((false, "a".repeat(52)));
    v.push((false, "a".repeat(54)));
    v.push((false, "a".repeat(55)));
    v.push((false, "a".repeat(56)));
    v.push((false, format!("{}b", "a".repeat(51))));
    v.push((false, "".into()));
    v
}

/// Hand-made multiaddr strings: every protocol, with each value grammar's edges.
fn handmade(rng: &mut ChaCha20Rng) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for s in ["", "/", "//", "ip4/1.2.3.4/udp/1", "/ip4/1.2.3.4/udp/1/", "/ip4/1.2.3.4//udp/1", "/ip4", "/ip4/", "/udp", "/UDP/1", "/ip5/1", " /ip4/1.2.3.4/udp/1"] {
        v.push(s.into());
    }
    for ip in ip4_vals() {
        v.push(format!("/ip4/{ip}/udp/8080"));
        v.push(format!("/ip4/{ip}"));
    }
    for ip in ip6_vals() {
        v.push(format!("/ip6/{ip}/udp/8080"));
    }
    for p in port_vals() {
        v.push(format!("/dns/x.y/udp/{p}"));
        v.push(format!("/ip4/1.2.3.4/tcp/{p}/http"));
    }
    for p in ["tcp", "udp", "dccp", "sctp"] {
        v.push(format!("/ip4/1.2.3.4/{p}/80"));
        v.push(format!("/ip4/1.2.3.4/{p}"));
    }
    for d in ["", "a", "x.y", "localhost", "héllo", "a b", "a%2Fb", "-", "😀", "a:b", "."] {
        for p in ["dns", "dns4", "dns6", "dnsaddr", "unix", "ip6zone", "sni"] {
            v.push(format!("/{p}/{d}/udp/1"));
        }
    }
    v.push("/dns".into());
    v.push("/dns/".into());
    for p in [
        "tls", "noise", "udt", "utp", "http", "https", "quic", "quic-v1", "webtransport", "ws", "wss", "p2p-websocket-star", "p2p-webrtc-star",
        "webrtc-direct", "p2p-webrtc-direct", "p2p-circuit", "p2p-stardust", "webrtc",
    ] {
        v.push(format!("/{p}"));
        v.push(format!("/dns/a/udp/1/{p}"));
        v.push(format!("/{p}/udp/1"));
    }
    for p in p2p_vals(rng) {
        v.push(format!("/dns/a/udp/1/p2p/{p}"));
        v.push(format!("/ip4/1.2.3.4/udp/1/ipfs/{p}"));
    }
    for (three, o) in onion_vals() {
        v.push(format!("/dns/a/udp/1/{}/{o}", if three { "onion3" } else { "onion" }));
    }
    for c in certhash_vals(rng) {
        v.push(format!("/ip4/1.2.3.4/udp/1/certhash/{c}"));
    }
    for w in ws_vals() {
        v.push(format!("/dns/a/udp/1/x-parity-ws/{w}"));
        v.push(format!("/dns/a/udp/1/x-parity-wss/{w}"));
    }
    for m in ["0", "18446744073709551615", "18446744073709551616", "+5", "-5", ""] {
        v.push(format!("/dns/a/udp/1/memory/{m}"));
    }
    for m in ["0", "255", "256", "+5", "-5", "", "033"] {
        v.push(format!("/dns/a/udp/1/ipcidr/{m}"));
    }
    for (g64, s) in garlic_vals(rng) {
        v.push(format!("/dns/a/udp/1/{}/{s}", if g64 { "garlic64" } else { "garlic32" }));
    }
    // first two protocols for to_anemo_address
    for (a, b) in [
        ("/ip4/1.2.3.4", "/udp/1"),
        ("/ip6/::1", "/udp/1"),
        ("/dns/a", "/udp/1"),
        ("/dns4/a", "/udp/1"),
        ("/dns6/a", "/udp/1"),
        ("/dnsaddr/a", "/udp/1"),
        ("/ip4/1.2.3.4", "/tcp/1"),
        ("/udp/1", "/ip4/1.2.3.4"),
        ("/ip4/1.2.3.4", ""),
        ("/dns/a", "/quic"),
        ("/ip4/1.2.3.4", "/ip4/1.2.3.4"),
    ] {
        v.push(format!("{a}{b}"));
        v.push(format!("{a}{b}/quic-v1/tls/http"));
    }
    v
}

const PROTOS: &[&str] = &[
    "ip4", "ip6", "dns", "udp", "tcp", "dns4", "dns6", "dnsaddr", "sctp", "dccp", "unix", "p2p", "ipfs", "http", "https", "onion", "onion3",
    "quic", "quic-v1", "webtransport", "ws", "wss", "x-parity-ws", "x-parity-wss", "certhash", "memory", "ip6zone", "ipcidr", "garlic64",
    "garlic32", "sni", "tls", "noise", "webrtc", "p2p-circuit",
];

fn rand_value(rng: &mut ChaCha20Rng, p: &str) -> Option<String> {
    let edgy = rng.gen_bool(0.25);
    let pick = |rng: &mut ChaCha20Rng, v: Vec<String>| v[rng.gen_range(0..v.len())].clone();
    Some(match p {
        "ip4" => {
            if edgy {
                pick(rng, ip4_vals())
            } else {
                format!("{}.{}.{}.{}", rng.r#gen::<u8>(), rng.r#gen::<u8>(), rng.r#gen::<u8>(), rng.r#gen::<u8>())
            }
        }
        "ip6" => {
            if edgy {
                pick(rng, ip6_vals())
            } else {
                let n = rng.gen_range(0..=8);
                let gs: Vec<String> = (0..n).map(|_| format!("{:x}", rng.r#gen::<u16>() >> rng.gen_range(0..16))).collect();
                if n == 8 {
                    gs.join(":")
                } else {
                    let k = rng.gen_range(0..=n);
                    format!("{}::{}", gs[..k].join(":"), gs[k..].join(":"))
                }
            }
        }
        "udp" | "tcp" | "sctp" | "dccp" => {
            if edgy {
                pick(rng, port_vals())
            } else {
                rng.r#gen::<u16>().to_string()
            }
        }
        "dns" | "dns4" | "dns6" | "dnsaddr" | "unix" | "ip6zone" | "sni" => {
            let n = rng.gen_range(0..12);
            (0..n).map(|_| ['a', 'b', '.', '-', '0', 'é', ':', '%'][rng.gen_range(0..8)]).collect()
        }
        "p2p" | "ipfs" => {
            let v = p2p_vals(rng);
            pick(rng, v)
        }
        "onion" | "onion3" => {
            let all = onion_vals();
            let (_, s) = &all[rng.gen_range(0..all.len())];
            s.clone()
        }
        "x-parity-ws" | "x-parity-wss" => pick(rng, ws_vals()),
        "certhash" => {
            let v = certhash_vals(rng);
            pick(rng, v)
        }
        "memory" => {
            if edgy {
                "18446744073709551616".into()
            } else {
                rng.r#gen::<u64>().to_string()
            }
        }
        "ipcidr" => rng.gen_range(0u32..300).to_string(),
        "garlic64" | "garlic32" => {
            let all = garlic_vals(rng);
            let (_, s) = &all[rng.gen_range(0..all.len())];
            s.clone()
        }
        _ => return None,
    })
}

fn random_multiaddr(rng: &mut ChaCha20Rng) -> String {
    let mut s = String::new();
    let n = rng.gen_range(1..=4);
    for i in 0..n {
        let p = if i == 0 && rng.gen_bool(0.6) {
            ["ip4", "ip6", "dns"][rng.gen_range(0..3)]
        } else if i == 1 && rng.gen_bool(0.6) {
            "udp"
        } else {
            PROTOS[rng.gen_range(0..PROTOS.len())]
        };
        s.push('/');
        s.push_str(p);
        if let Some(v) = rand_value(rng, p) {
            s.push('/');
            s.push_str(&v);
        } else if rng.gen_bool(0.05) {
            s.push_str("/x");
        }
    }
    match rng.gen_range(0..40) {
        0 => s.push('/'),
        1 => s = s[1..].to_string(),
        2 => s.push_str("//"),
        _ => {}
    }
    s
}

// ---- generation --------------------------------------------------------------------------------

pub fn gen_all(g: &mut Gen) {
    let ms = load();
    let mut rng = ChaCha20Rng::seed_from_u64(0x0517_ba11);
    let keys = make_keys(&mut rng);

    // every active mainnet validator as is
    for (i, m) in ms.iter().enumerate() {
        g.push(G, format!("mainnet/{i}"), vec![vcall(&m.enc())]);
    }
    let bases: Vec<usize> = {
        let mut b = vec![0usize, 1];
        if let Some(i) = ms.iter().position(|m| m.p2p.starts_with(b"/ip4")) {
            b.push(i);
        }
        b
    };
    for &bi in &bases {
        gen_fields(g, &ms, bi, &keys, &mut rng);
        gen_next(g, &ms, bi, &keys);
    }
    gen_bcs(g, &ms[0], &mut rng);
    gen_addrs(g, &ms[0], &mut rng);
    gen_multi(g, &ms, &keys, &mut rng);
    gen_budget(g, &ms[0]);
    gen_addr_mutations(g, &ms[0]);
    gen_official(g, &ms[0]);
}

/// The multiaddr crate's own test addresses (tests/lib.rs construct_success/construct_fail and
/// the doc examples) and mysten-network's, in the net, p2p and next-epoch p2p slots.
fn gen_official(g: &mut Gen, b: &Meta) {
    const OFFICIAL: &str = include_str!("../data/multiaddr_official.txt");
    for (i, s) in OFFICIAL.lines().filter(|l| !l.is_empty()).enumerate() {
        for slot in [0usize, 1, 5] {
            let mut m = b.clone();
            m.set_addr(slot, s.as_bytes());
            g.push(G, format!("addr/official{i}/s{slot}"), vec![vcall(&m.enc())]);
        }
    }
}

/// Character-level damage to valid multiaddrs (insert, delete, replace from an alphabet heavy
/// in separators, digits, hex and base-N symbols), plus random IPv6 text with embedded IPv4.
fn gen_addr_mutations(g: &mut Gen, b: &Meta) {
    let mut rng = ChaCha20Rng::seed_from_u64(0x0517_ad2e);
    let seeds: Vec<String> = {
        let mut v = handmade(&mut rng);
        v.retain(|s| s.len() < 300);
        v
    };
    const ALPHA: &[&str] = &["/", ":", ".", "%", "+", "-", "=", "0", "1", "9", "a", "f", "F", "g", "z", "Z", "~", "_", " ", "é", "ı", "ß", "ﬀ", "\u{0}", "::", "udp", "ip4", "ip6", "dns", "/udp/1"];
    for i in 0..2000 {
        let mut s: Vec<char> = seeds[rng.gen_range(0..seeds.len())].chars().collect();
        for _ in 0..rng.gen_range(1..=3) {
            let op = rng.gen_range(0..3);
            let pos = if s.is_empty() { 0 } else { rng.gen_range(0..=s.len()) };
            let ins: Vec<char> = ALPHA[rng.gen_range(0..ALPHA.len())].chars().collect();
            match op {
                0 => {
                    for (k, ch) in ins.into_iter().enumerate() {
                        s.insert(pos + k, ch);
                    }
                }
                1 => {
                    if pos < s.len() {
                        s.remove(pos);
                    }
                }
                _ => {
                    if pos < s.len() {
                        s[pos] = ins[0];
                    }
                }
            }
        }
        let st: String = s.into_iter().collect();
        let slot = i % 8;
        let mut m = b.clone();
        m.set_addr(slot, st.as_bytes());
        g.push(G, format!("addr/mut{i}/s{slot}"), vec![vcall(&m.enc())]);
    }
    for i in 0..800 {
        let mut t = String::new();
        let n = rng.gen_range(0..10);
        for k in 0..n {
            match rng.gen_range(0..10) {
                0 => t.push_str("::"),
                1 => t.push_str(&format!("{}.{}.{}.{}", rng.gen_range(0..300), rng.gen_range(0..300), rng.r#gen::<u8>(), rng.r#gen::<u8>())),
                2 => t.push(':'),
                _ => {
                    if k > 0 && !t.ends_with(':') {
                        t.push(':');
                    }
                    let w = rng.gen_range(0..6);
                    for _ in 0..w {
                        t.push(b"0123456789abcdefABCDEFg"[rng.gen_range(0..23)] as char);
                    }
                }
            }
        }
        let mut m = b.clone();
        m.set_addr(1, format!("/ip6/{t}/udp/1").as_bytes());
        g.push(G, format!("addr/ip6rand{i}"), vec![vcall(&m.enc())]);
    }
}

fn push(g: &mut Gen, id: String, m: &Meta) {
    g.push(G, id, vec![vcall(&m.enc())]);
}

fn gen_fields(g: &mut Gen, ms: &[Meta], bi: usize, k: &Keys, rng: &mut ChaCha20Rng) {
    let b = &ms[bi];
    let other = &ms[(bi + 7) % ms.len()];
    let id = |s: &str| format!("b{bi}/{s}");
    // sui_address
    let mut m = b.clone();
    m.addr = other.addr.clone();
    push(g, id("addr-other"), &m);
    // protocol key
    let ppks: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("95", b.ppk[..95].to_vec()),
        ("97", [b.ppk.clone(), vec![0]].concat()),
        ("uncompressed", g2_uncompressed(&b.ppk)),
        ("uncompressed-flip", {
            let mut u = g2_uncompressed(&b.ppk);
            u[100] ^= 1;
            u
        }),
        ("uncompressed-with-cflag", {
            let mut u = g2_uncompressed(&b.ppk);
            u[0] |= 0x80;
            u
        }),
        ("sign-flip", {
            let mut u = b.ppk.clone();
            u[0] ^= 0x20;
            u
        }),
        ("no-cflag", {
            let mut u = b.ppk.clone();
            u[0] &= 0x7f;
            u
        }),
        ("inf", [vec![0xc0], vec![0; 95]].concat()),
        ("inf-dirty", [vec![0xc0], vec![0; 94], vec![1]].concat()),
        ("inf-uncompressed", [vec![0x40], vec![0; 191]].concat()),
        ("off-g2", k.off_g2[0].clone()),
        ("other", other.ppk.clone()),
        ("random", (0..96).map(|_| rng.r#gen()).collect()),
        ("x-ge-p", [vec![0x9a], vec![0xff; 95]].concat()),
    ];
    for (n, v) in ppks {
        let mut m = b.clone();
        m.ppk = v;
        push(g, id(&format!("ppk/{n}")), &m);
    }
    // off-subgroup key with a next-epoch key that is fine (order of checks)
    // proof of possession
    let pops: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("47", b.pop[..47].to_vec()),
        ("49", [b.pop.clone(), vec![0]].concat()),
        ("uncompressed", g1_uncompressed(&b.pop)),
        ("uncompressed-flip", {
            let mut u = g1_uncompressed(&b.pop);
            u[60] ^= 1;
            u
        }),
        ("sign-flip", {
            let mut u = b.pop.clone();
            u[0] ^= 0x20;
            u
        }),
        ("inf", [vec![0xc0], vec![0; 47]].concat()),
        ("inf-uncompressed", [vec![0x40], vec![0; 95]].concat()),
        ("off-g1", k.off_g1[0].clone()),
        ("other", other.pop.clone()),
        ("random", (0..48).map(|_| rng.r#gen()).collect()),
        ("fresh-wrong-key", pop_for(&k.fresh[0], &b.addr)),
    ];
    for (n, v) in pops {
        let mut m = b.clone();
        m.pop = v;
        push(g, id(&format!("pop/{n}")), &m);
    }
    // a fresh protocol key with its own PoP for this address
    let mut m = b.clone();
    m.ppk = pk_of(&k.fresh[1]);
    m.pop = pop_for(&k.fresh[1], &b.addr);
    push(g, id("fresh-key"), &m);
    let mut m2 = m.clone();
    m2.ppk = g2_uncompressed(&m.ppk);
    m2.pop = g1_uncompressed(&m.pop);
    push(g, id("fresh-key-uncompressed"), &m2);
    // network / worker keys
    let mut eds: Vec<(String, Vec<u8>)> = ed_edges().into_iter().map(|(n, v)| (n.to_string(), v)).collect();
    eds.push(("empty".into(), vec![]));
    eds.push(("31".into(), b.npk[..31].to_vec()));
    eds.push(("33".into(), [b.npk.clone(), vec![0]].concat()));
    for (i, x) in k.ed_bad.iter().enumerate() {
        eds.push((format!("bad{i}"), x.clone()));
    }
    for (i, x) in k.ed_ok.iter().enumerate() {
        eds.push((format!("ok{i}"), x.clone()));
    }
    eds.push(("same-as-other".into(), b.wpk.clone()));
    eds.push(("high-bit".into(), {
        let mut x = b.npk.clone();
        x[31] ^= 0x80;
        x
    }));
    for (n, v) in &eds {
        let mut m = b.clone();
        m.npk = v.clone();
        push(g, id(&format!("npk/{n}")), &m);
        let mut m = b.clone();
        m.wpk = if n == "same-as-other" { b.npk.clone() } else { v.clone() };
        push(g, id(&format!("wpk/{n}")), &m);
    }
    // equal keys by value but different encodings (y and y+p)
    let mut m = b.clone();
    let mut p = vec![0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    m.npk = p;
    m.wpk = vec![0u8; 32];
    push(g, id("npk-wpk-same-point-diff-bytes"), &m);
    // strings: name/description/urls are not checked beyond UTF-8
    for (n, v) in [("empty", b"".to_vec()), ("long", vec![b'a'; 5000]), ("bad-utf8", vec![0xff]), ("surrogate", vec![0xed, 0xa0, 0x80]), ("emoji", "😀".as_bytes().to_vec())] {
        for f in 0..4 {
            let mut m = b.clone();
            match f {
                0 => m.name = v.clone(),
                1 => m.desc = v.clone(),
                2 => m.img = v.clone(),
                _ => m.proj = v.clone(),
            }
            push(g, id(&format!("str{f}/{n}")), &m);
        }
    }
    // bag
    let mut m = b.clone();
    m.bag_size = u64::MAX;
    push(g, id("bag-size-max"), &m);
}

fn gen_next(g: &mut Gen, ms: &[Meta], bi: usize, k: &Keys) {
    let b = &ms[bi];
    let id = |s: &str| format!("b{bi}/next/{s}");
    let fpk = pk_of(&k.fresh[2]);
    let fpop = pop_for(&k.fresh[2], &b.addr);
    let other = &ms[(bi + 3) % ms.len()];
    let cases: Vec<(&str, Option<Vec<u8>>, Option<Vec<u8>>)> = vec![
        ("ok", Some(fpk.clone()), Some(fpop.clone())),
        ("ok-uncompressed", Some(g2_uncompressed(&fpk)), Some(g1_uncompressed(&fpop))),
        ("current", Some(b.ppk.clone()), Some(b.pop.clone())),
        ("pk-no-pop", Some(fpk.clone()), None),
        ("pop-no-pk", None, Some(fpop.clone())),
        ("bad-pop-no-pk", None, Some(vec![1, 2, 3])),
        ("inf-pop-no-pk", None, Some([vec![0xc0], vec![0; 47]].concat())),
        ("bad-pk", Some(vec![1, 2, 3]), Some(fpop.clone())),
        ("bad-pk-no-pop", Some(vec![1, 2, 3]), None),
        ("pk-bad-pop", Some(fpk.clone()), Some(vec![1, 2, 3])),
        ("pk-other-pop", Some(fpk.clone()), Some(b.pop.clone())),
        ("pop-wrong-address", Some(fpk.clone()), Some(pop_for(&k.fresh[2], &other.addr))),
        ("off-g2", Some(k.off_g2[1].clone()), Some(fpop.clone())),
        ("inf-pk", Some([vec![0xc0], vec![0; 95]].concat()), Some(fpop.clone())),
        ("empty-both", Some(vec![]), Some(vec![])),
    ];
    for (n, pk, pop) in cases {
        let mut m = b.clone();
        m.n_ppk = pk;
        m.n_pop = pop;
        push(g, id(&n), &m);
    }
    // metadata_v2 network/worker rules
    let x = k.ed_ok[0].clone();
    let y = k.ed_ok[1].clone();
    let bad = k.ed_bad[0].clone();
    let cases: Vec<(&str, Option<Vec<u8>>, Option<Vec<u8>>)> = vec![
        ("xy", Some(x.clone()), Some(y.clone())),
        ("xx", Some(x.clone()), Some(x.clone())),
        ("x-none", Some(x.clone()), None),
        ("none-y", None, Some(y.clone())),
        ("net=cur-worker", Some(b.wpk.clone()), None),
        ("net=cur-net", Some(b.npk.clone()), None),
        ("worker=cur-net", None, Some(b.npk.clone())),
        ("worker=cur-worker", None, Some(b.wpk.clone())),
        ("swap", Some(b.wpk.clone()), Some(b.npk.clone())),
        ("cur-worker-and-y", Some(b.wpk.clone()), Some(y.clone())),
        ("x-and-cur-net", Some(x.clone()), Some(b.npk.clone())),
        ("bad-net", Some(bad.clone()), Some(y.clone())),
        ("bad-worker", Some(x.clone()), Some(bad.clone())),
        ("bad-both", Some(bad.clone()), Some(bad.clone())),
        ("short-net", Some(vec![1; 31]), None),
        ("short-worker", None, Some(vec![1; 33])),
        ("same-point-diff-bytes", Some({
            let mut p = vec![0xffu8; 32];
            p[0] = 0xed;
            p[31] = 0x7f;
            p
        }), Some(vec![0u8; 32])),
    ];
    for (n, a, w) in cases {
        let mut m = b.clone();
        m.n_npk = a;
        m.n_wpk = w;
        push(g, id(&format!("keys/{n}")), &m);
        // the same with a bad next protocol key first (order: protocol key before network keys)
        let mut m2 = m.clone();
        m2.n_ppk = Some(vec![0]);
        push(g, id(&format!("keys/{n}+badpk")), &m2);
    }
    // next-epoch addresses
    for slot in 4..8 {
        for (n, s) in [("ok", "/dns/a.b/udp/1"), ("tcp", "/dns/a.b/tcp/1/http"), ("bad", "/bogus"), ("empty", "")] {
            let mut m = b.clone();
            m.set_addr(slot, s.as_bytes());
            push(g, id(&format!("addr{slot}/{n}")), &m);
        }
    }
}

fn gen_bcs(g: &mut Gen, b: &Meta, rng: &mut ChaCha20Rng) {
    let mut full = b.clone();
    full.n_ppk = Some(vec![1, 2]);
    full.n_pop = Some(vec![3]);
    full.n_npk = Some(vec![]);
    full.n_wpk = Some(vec![4]);
    full.n_net = Some(b"/a".to_vec());
    full.n_p2p = Some(b"/b".to_vec());
    full.n_pri = Some(b"/c".to_vec());
    full.n_wrk = Some(b"/d".to_vec());
    for (tag, m) in [("min", b.clone()), ("full", full)] {
        let e = m.enc();
        for n in 0..e.len() {
            g.push(G, format!("bcs/{tag}/trunc{n}"), vec![vcall(&e[..n])]);
        }
        g.push(G, format!("bcs/{tag}/trail1"), vec![vcall(&[e.clone(), vec![0]].concat())]);
        g.push(G, format!("bcs/{tag}/trail8"), vec![vcall(&[e.clone(), vec![0; 8]].concat())]);
    }
    // option tags
    let base = b.enc();
    let opt_start = base.len() - 40 - 8; // 8 option bytes (all None) before bag id + size
    for i in 0..8 {
        for t in [1u8, 2, 0xff] {
            let mut e = base.clone();
            e[opt_start + i] = t;
            g.push(G, format!("bcs/opt{i}/tag{t}"), vec![vcall(&e)]);
        }
    }
    // non-canonical and oversized lengths for protocol_pubkey_bytes (offset 32)
    let rest = &base[32 + 1 + 96..];
    for (n, len) in [
        ("noncanon", vec![0xe0, 0x00]),
        ("noncanon2", vec![0xe0, 0x80, 0x00]),
        ("over", vec![0x80, 0x80, 0x80, 0x80, 0x08]),
        ("max31", vec![0xff, 0xff, 0xff, 0xff, 0x07]),
        ("2^31", vec![0x80, 0x80, 0x80, 0x80, 0x08]),
        ("97", vec![97]),
        ("95", vec![95]),
    ] {
        let e = [base[..32].to_vec(), len, base[33..33 + 96].to_vec(), rest.to_vec()].concat();
        g.push(G, format!("bcs/len/{n}"), vec![vcall(&e)]);
    }
    // random byte damage
    for i in 0..60 {
        let mut e = base.clone();
        let p = rng.gen_range(0..e.len());
        e[p] = rng.r#gen();
        g.push(G, format!("bcs/rand{i}"), vec![vcall(&e)]);
    }
    g.push(G, "bcs/empty".into(), vec![vcall(&[])]);
}

fn gen_addrs(g: &mut Gen, b: &Meta, rng: &mut ChaCha20Rng) {
    let hm = handmade(rng);
    for (i, s) in hm.iter().enumerate() {
        for slot in [0usize, 1] {
            let mut m = b.clone();
            m.set_addr(slot, s.as_bytes());
            g.push(G, format!("addr/hand{i}/s{slot}"), vec![vcall(&m.enc())]);
        }
    }
    for i in 0..1500 {
        let s = random_multiaddr(rng);
        let slot = i % 8;
        let mut m = b.clone();
        m.set_addr(slot, s.as_bytes());
        g.push(G, format!("addr/rand{i}/s{slot}"), vec![vcall(&m.enc())]);
    }
}

fn gen_multi(g: &mut Gen, ms: &[Meta], k: &Keys, rng: &mut ChaCha20Rng) {
    // several fields wrong at once: the first failing check decides the code
    for i in 0..300 {
        let b = &ms[rng.gen_range(0..ms.len())];
        let mut m = b.clone();
        for f in 0..20 {
            if !rng.gen_bool(0.15) {
                continue;
            }
            match f {
                0 => m.ppk = k.off_g2[2].clone(),
                1 => m.ppk = vec![7; 96],
                2 => m.pop = vec![7; 48],
                3 => m.pop = k.off_g1[1].clone(),
                4 => m.npk = k.ed_bad[1].clone(),
                5 => m.wpk = k.ed_bad[2].clone(),
                6 => m.wpk = m.npk.clone(),
                7 => m.net = b"/x".to_vec(),
                8 => m.p2p = b"/dns/a/tcp/1".to_vec(),
                9 => m.pri = b"/ip4/1.2.3.4".to_vec(),
                10 => m.wrk = b"/udp/1".to_vec(),
                11 => m.n_ppk = Some(vec![1]),
                12 => m.n_pop = Some(vec![1]),
                13 => m.n_ppk = Some(pk_of(&k.fresh[3])),
                14 => m.n_npk = Some(m.wpk.clone()),
                15 => m.n_wpk = Some(m.npk.clone()),
                16 => m.n_net = Some(b"".to_vec()),
                17 => m.n_p2p = Some(b"/ip6/::/tcp/1".to_vec()),
                18 => m.n_pri = Some(b"/".to_vec()),
                _ => m.n_wrk = Some(b"/dns".to_vec()),
            }
        }
        push(g, format!("multi/{i}"), &m);
    }
}

fn gen_budget(g: &mut Gen, b: &Meta) {
    let e = b.enc();
    let big = {
        let mut m = b.clone();
        m.desc = vec![b'd'; 20_000];
        m.enc()
    };
    for pv in PV_MIN_V4..=PV_MAX {
        g.push_full(G, format!("pv{pv}/ok"), pv, None, vec![vcall(&e)]);
        g.push_full(G, format!("pv{pv}/malformed"), pv, None, vec![vcall(&e[..10])]);
        g.push_full(G, format!("pv{pv}/big"), pv, None, vec![vcall(&big)]);
    }
    let cfg = sui_protocol_config::ProtocolConfig::get_for_version(PV_MAX.into(), sui_protocol_config::Chain::Mainnet);
    let base = cfg.validator_validate_metadata_cost_base();
    let per = cfg.validator_validate_metadata_data_cost_per_byte();
    for (tag, bytes) in [("ok", e.clone()), ("malformed", e[..e.len() - 1].to_vec()), ("big", big.clone())] {
        let total = base + per * bytes.len() as u64;
        let mut budgets = vec![0, 1, base - 1, base, base + 1, total - 1, total, total + 1];
        budgets.dedup();
        for bud in budgets {
            let mut c = vcall(&bytes);
            c.budget = bud;
            g.push(G, format!("budget/{tag}/{bud}"), vec![c]);
        }
    }
    // two calls in one item: the second sees its own budget
    g.push(G, "two-calls".into(), vec![vcall(&e), vcall(&e[..5])]);
}
