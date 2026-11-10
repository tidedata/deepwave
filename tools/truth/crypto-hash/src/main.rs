//! zui-truth-hash: ground truth for the deepwave `hash` suite (CONTRACTS.md 3.3, 5.3).
//!
//! Every output is computed by the Rust code Sui runs: fastcrypto `hash::{Blake2b256, Sha256,
//! Sha512, Sha3_256, Sha3_512, Keccak256}` and `hmac::{hmac_sha3_256, hkdf_sha3_256}` at the
//! pinned fastcrypto revision. SHA-384, HMAC-SHA256 and HKDF-SHA256 (used by deepwave's net lane for
//! TLS 1.3 / QUIC) come from the same backend crates fastcrypto links (sha2 0.10, hmac 0.12,
//! hkdf 0.12).
//!
//! Commands:
//!   gen <out_dir>                  write <out_dir>/synthetic.tsv.zst (vectors) and
//!                                  <out_dir>/corpus-blobs.tsv.zst (every chk blob hashed)
//!   blobs <chk_dir> <out.tsv.zst>  only the corpus blob hashes
//!   bench <name> --iters N --list FILE
//!                                  speed baseline, JSON lines like zui-dumper bench
//!
//! Vector line format (TSV, no header): `alg \t arg... \t out`. An arg is lowercase hex, or
//! `@<len>,<seed>` meaning `len` bytes from the splitmix64 stream seeded with `seed` (each 64-bit
//! output written little-endian, the last one truncated). `out` is hex, or `ERR` when the Rust
//! function returns an error.
use anyhow::{Result, bail};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

fn gen_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed;
    let mut v = Vec::with_capacity(len + 8);
    while v.len() < len {
        v.extend_from_slice(&splitmix(&mut s).to_le_bytes());
    }
    v.truncate(len);
    v
}

#[cfg(feature = "fastcrypto")]
mod backend {
    use fastcrypto::hash::{Blake2b256, HashFunction, Keccak256, Sha3_256, Sha3_512, Sha256, Sha512};
    use fastcrypto::hmac::{HkdfIkm, HmacKey, hkdf_sha3_256, hmac_sha3_256};
    use fastcrypto::traits::ToFromBytes;
    macro_rules! hf {
        ($name:ident, $t:ty) => {
            pub fn $name(m: &[u8]) -> Vec<u8> {
                let mut h = <$t>::default();
                h.update(m);
                h.finalize().digest.to_vec()
            }
        };
    }
    hf!(blake2b256, Blake2b256);
    hf!(sha256, Sha256);
    hf!(sha512, Sha512);
    hf!(sha3_256, Sha3_256);
    hf!(sha3_512, Sha3_512);
    hf!(keccak256, Keccak256);
    pub fn hmac_sha3(key: &[u8], msg: &[u8]) -> Vec<u8> {
        let k = HmacKey::from_bytes(key).unwrap();
        hmac_sha3_256(&k, msg).digest.to_vec()
    }
    pub fn hkdf_sha3(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Option<Vec<u8>> {
        let k = HkdfIkm::from_bytes(ikm).unwrap();
        hkdf_sha3_256(&k, salt, info, len).ok()
    }
}

#[cfg(not(feature = "fastcrypto"))]
mod backend {
    use digest::Digest;
    use hmac::{Hmac, Mac};
    macro_rules! hf {
        ($name:ident, $t:ty) => {
            pub fn $name(m: &[u8]) -> Vec<u8> {
                let mut h = <$t>::new();
                h.update(m);
                h.finalize().to_vec()
            }
        };
    }
    hf!(blake2b256, blake2::Blake2b<digest::consts::U32>);
    hf!(sha256, sha2::Sha256);
    hf!(sha512, sha2::Sha512);
    hf!(sha3_256, sha3::Sha3_256);
    hf!(sha3_512, sha3::Sha3_512);
    hf!(keccak256, sha3::Keccak256);
    pub fn hmac_sha3(key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut m = Hmac::<sha3::Sha3_256>::new_from_slice(key).unwrap();
        m.update(msg);
        m.finalize().into_bytes().to_vec()
    }
    pub fn hkdf_sha3(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Option<Vec<u8>> {
        if len > 32 * 255 {
            return None;
        }
        let hk = hkdf::Hkdf::<sha3::Sha3_256, Hmac<sha3::Sha3_256>>::new(Some(salt), ikm);
        let mut out = vec![0u8; len];
        hk.expand(info, &mut out).ok()?;
        Some(out)
    }
}
use backend::{blake2b256, hkdf_sha3, hmac_sha3, keccak256, sha256, sha3_256, sha3_512, sha512};

fn sha384(m: &[u8]) -> Vec<u8> {
    use digest::Digest;
    sha2::Sha384::digest(m).to_vec()
}

const HASHES: &[(&str, fn(&[u8]) -> Vec<u8>)] = &[
    ("blake2b256", blake2b256),
    ("sha256", sha256),
    ("sha384", sha384),
    ("sha512", sha512),
    ("sha3_256", sha3_256),
    ("sha3_512", sha3_512),
    ("keccak256", keccak256),
];

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}
fn hkdf_sha256_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let (prk, _) = Hkdf::<sha2::Sha256>::extract(Some(salt), ikm);
    prk.to_vec()
}
fn hkdf_sha256_expand(prk: &[u8], info: &[u8], len: usize) -> Option<Vec<u8>> {
    let hk = Hkdf::<sha2::Sha256>::from_prk(prk).ok()?;
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out).ok()?;
    Some(out)
}

struct Out(Vec<u8>);
impl Out {
    fn line(&mut self, alg: &str, args: &[String], out: Option<Vec<u8>>) {
        let w = &mut self.0;
        w.extend_from_slice(alg.as_bytes());
        for a in args {
            w.push(b'\t');
            w.extend_from_slice(a.as_bytes());
        }
        w.push(b'\t');
        match out {
            Some(o) => w.extend_from_slice(hex::encode(o).as_bytes()),
            None => w.extend_from_slice(b"ERR"),
        }
        w.push(b'\n');
    }
}

fn arg(len: usize, seed: u64) -> (String, Vec<u8>) {
    if len <= 64 && seed == 0 {
        let b = gen_bytes(len, 0x5eed0000 + len as u64);
        (hex::encode(&b), b)
    } else {
        (format!("@{len},{seed}"), gen_bytes(len, seed))
    }
}

fn synthetic() -> Vec<u8> {
    let mut o = Out(Vec::new());
    // Every length 0..=1100 covers every block/rate boundary of every algorithm several times.
    let mut lens: Vec<usize> = (0..=1100).collect();
    // Block edges of larger sizes: 4 KiB, 8 KiB, 64 KiB, 1 MiB, odd sizes, Sui-typical sizes.
    for base in [2048usize, 4096, 8192, 16384, 65536, 1 << 20] {
        for d in [-1i64, 0, 1] {
            lens.push((base as i64 + d) as usize);
        }
    }
    lens.extend([135, 136, 137, 143, 144, 145, 4095 + 128, 100_003, 262_147, 5 << 20, (5 << 20) + 77]);
    lens.sort();
    lens.dedup();
    for &(name, f) in HASHES {
        for &len in &lens {
            let seed = 0xA5A5_0000_0000_0000u64 ^ (len as u64) << 8 ^ name.len() as u64;
            let (a, m) = arg(len, if len <= 64 { 0 } else { seed });
            o.line(name, &[a], Some(f(&m)));
        }
    }
    // HMAC: key lengths around block sizes (SHA3-256 rate 136, SHA-256 block 64), empty and long.
    let klens = [0usize, 1, 16, 31, 32, 33, 63, 64, 65, 100, 135, 136, 137, 200, 1000];
    let mlens = [0usize, 1, 31, 32, 55, 56, 63, 64, 65, 135, 136, 137, 271, 272, 273, 1000, 10_000];
    for &kl in &klens {
        for &ml in &mlens {
            let (ka, k) = arg(kl, if kl <= 64 { 0 } else { 0xC0DE0000 + kl as u64 });
            let (ma, m) = arg(ml, if ml <= 64 { 0 } else { 0xFEED0000 + ml as u64 });
            o.line("hmac_sha3_256", &[ka.clone(), ma.clone()], Some(hmac_sha3(&k, &m)));
            o.line("hmac_sha256", &[ka, ma], Some(hmac_sha256(&k, &m)));
        }
    }
    // HKDF: ikm/salt/info lengths and output lengths incl. 0, block edges and the 255*32 limit.
    let ilens = [0usize, 1, 22, 32, 33, 64, 80, 137];
    let olens = [0usize, 1, 31, 32, 33, 42, 64, 100, 255, 1000, 8159, 8160, 8161, 10_000];
    let mut c = 0u64;
    for &il in &ilens {
        for &sl in &[0usize, 13, 32, 64, 137] {
            for &nl in &[0usize, 10, 80] {
                for &ol in &olens {
                    c += 1;
                    let (ia, ikm) = arg(il, if il <= 64 { 0 } else { 0x1000 + c });
                    let (sa, salt) = arg(sl, if sl <= 64 { 0 } else { 0x2000 + c });
                    let (na, info) = arg(nl, if nl <= 64 { 0 } else { 0x3000 + c });
                    let a = [ia.clone(), sa.clone(), na.clone(), ol.to_string()];
                    o.line("hkdf_sha3_256", &a, hkdf_sha3(&ikm, &salt, &info, ol));
                    // SHA-256 HKDF: extract with salt, expand from the PRK. Limit 255*32.
                    let prk = hkdf_sha256_extract(&salt, &ikm);
                    if ol == olens[0] {
                        o.line("hkdf_sha256_extract", &[sa.clone(), ia.clone()], Some(prk.clone()));
                    }
                    o.line("hkdf_sha256_expand", &[hex::encode(&prk), na, ol.to_string()], hkdf_sha256_expand(&prk, &info, ol));
                }
            }
        }
    }
    o.0
}

fn blobs(chk_dir: &str, out: &str) -> Result<()> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(chk_dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "chk"))
        .collect();
    files.sort_by_key(|p| p.file_stem().and_then(|s| s.to_str()).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0));
    use std::sync::{Mutex, atomic::{AtomicUsize, Ordering}};
    let next = AtomicUsize::new(0);
    let lines: Mutex<Vec<(usize, String)>> = Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for _ in 0..12 {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= files.len() {
                    break;
                }
                let b = std::fs::read(&files[i]).unwrap();
                let mut l = files[i].file_name().unwrap().to_string_lossy().to_string();
                for &(name, f) in HASHES {
                    l.push('\t');
                    l.push_str(name);
                    l.push('=');
                    l.push_str(&hex::encode(f(&b)));
                }
                lines.lock().unwrap().push((i, l));
            });
        }
    });
    let mut lines = lines.into_inner().unwrap();
    lines.sort();
    let mut text = String::new();
    for (_, l) in lines {
        text.push_str(&l);
        text.push('\n');
    }
    std::fs::write(out, zstd::encode_all(text.as_bytes(), 9)?)?;
    Ok(())
}

fn median(mut v: Vec<u128>) -> u128 {
    v.sort();
    v[v.len() / 2]
}

fn emit(name: &str, unit: &str, units: u64, passes: Vec<u128>) {
    let ns = median(passes) as f64;
    println!(
        "{{\"impl\":\"rust\",\"bench\":\"{name}\",\"unit\":\"{unit}\",\"units\":{units},\"ns_per_unit\":{:.4}}}",
        ns / units as f64
    );
}

fn run_passes(iters: usize, mut f: impl FnMut()) -> Vec<u128> {
    f(); // warm-up
    (0..iters.max(1))
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_nanos()
        })
        .collect()
}

fn bench(args: &[String]) -> Result<()> {
    let mut iters = 5usize;
    let mut list = None;
    let mut name = None;
    let mut i = 0;
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
            a => {
                name = Some(a.to_string());
                i += 1;
            }
        }
    }
    let name = name.unwrap_or_default();
    let Some(list) = list else { bail!("--list FILE is required") };
    let files: Vec<PathBuf> = std::fs::read_to_string(&list)?.lines().filter(|l| !l.is_empty()).map(PathBuf::from).collect();
    let blobs: Vec<Vec<u8>> = files.iter().map(std::fs::read).collect::<Result<_, _>>()?;
    let bytes: u64 = blobs.iter().map(|b| b.len() as u64).sum();
    // Every name below is one bench record; `all` (and the empty name) prints all of them.
    let want = |n: &str| name.is_empty() || name == "all" || name == n;
    for &(h, f) in HASHES {
        if h == "sha384" {
            continue;
        }
        let rec = format!("blob-{h}");
        if want(&rec) {
            emit(&rec, "byte", bytes, run_passes(iters, || {
                for b in &blobs {
                    std::hint::black_box(f(std::hint::black_box(b)));
                }
            }));
        }
    }
    // Small messages cut from the same blobs: the shape of object / tx / effects digests.
    for size in [32usize, 128, 512, 4096] {
        let mut msgs: Vec<&[u8]> = Vec::new();
        for b in &blobs {
            let mut off = 0;
            while off + size <= b.len() && msgs.len() < 200_000 {
                msgs.push(&b[off..off + size]);
                off += 4099; // odd stride so alignments vary
            }
        }
        let total = (msgs.len() * size) as u64;
        for &(h, f) in HASHES {
            if h != "blake2b256" && h != "sha256" && h != "keccak256" {
                continue;
            }
            let rec = format!("small{size}-{h}");
            if want(&rec) {
                emit(&rec, "msg", msgs.len() as u64, run_passes(iters, || {
                    for m in &msgs {
                        std::hint::black_box(f(std::hint::black_box(m)));
                    }
                }));
            }
        }
        let _ = total;
    }
    if want("hmac-sha3-256-small") {
        let msgs: Vec<&[u8]> = blobs.iter().map(|b| &b[..256.min(b.len())]).collect();
        emit("hmac-sha3-256-small", "msg", msgs.len() as u64, run_passes(iters, || {
            for m in &msgs {
                std::hint::black_box(hmac_sha3(&[7u8; 32], std::hint::black_box(m)));
            }
        }));
    }
    let _ = std::io::stdout().flush();
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("gen") => {
            let dir = args.get(2).ok_or_else(|| anyhow::anyhow!("gen <out_dir>"))?;
            std::fs::create_dir_all(dir)?;
            let s = synthetic();
            std::fs::write(format!("{dir}/synthetic.tsv.zst"), zstd::encode_all(&s[..], 9)?)?;
            eprintln!("synthetic: {} bytes", s.len());
            Ok(())
        }
        Some("blobs") => blobs(&args[2], &args[3]),
        Some("bench") => bench(&args[2..]),
        _ => bail!("usage: gen <out_dir> | blobs <chk_dir> <out> | bench [name] --iters N --list FILE"),
    }
}
