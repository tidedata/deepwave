//! `groupops <out_file>`: vectors for the bls-group-ops suite. Every result is computed by the
//! same fastcrypto calls, in the same order and with the same parsing (trusted vs untrusted) as
//! the BLS12-381 arms of sui-move-natives/src/crypto/group_ops.rs in mainnet-v1.83.1; gas,
//! feature flags and the MSM/sum length limits stay with the natives lane.
//!
//! One JSON object per line: {"id","op","g","a","b","out"} where `out` is the result bytes as hex
//! or null when the native returns its error. `validate` has "ok" instead of "out"; `sum` has
//! "terms" instead of "a"/"b"; `convert` has "to".

use anyhow::Result;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::bls12381::{G1Element, G1ElementUncompressed, G2Element, GTElement, Scalar};
use fastcrypto::groups::{
    FromTrustedByteArray, GroupElement, HashToGroupElement, MultiScalarMul, Pairing,
    Scalar as ScalarTrait,
};
use fastcrypto::serde_helpers::ToFromByteArray;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use serde_json::json;
use std::io::Write;

const SCALAR: u8 = 0;
const G1: u8 = 1;
const G2: u8 = 2;
const GT: u8 = 3;
const G1U: u8 = 4;

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

fn parse_untrusted<G: ToFromByteArray<S> + FromTrustedByteArray<S>, const S: usize>(e: &[u8]) -> FastCryptoResult<G> {
    G::from_byte_array(e.try_into().map_err(|_| FastCryptoError::InvalidInput)?)
}

fn parse_trusted<G: ToFromByteArray<S> + FromTrustedByteArray<S>, const S: usize>(e: &[u8]) -> FastCryptoResult<G> {
    G::from_trusted_byte_array(e.try_into().map_err(|_| FastCryptoError::InvalidInput)?)
}

fn binary_op_diff<
    A: ToFromByteArray<S1> + FromTrustedByteArray<S1>,
    B: ToFromByteArray<S2> + FromTrustedByteArray<S2>,
    const S1: usize,
    const S2: usize,
>(
    op: impl Fn(A, B) -> FastCryptoResult<B>,
    a1: &[u8],
    a2: &[u8],
) -> FastCryptoResult<Vec<u8>> {
    let e1 = parse_trusted::<A, S1>(a1)?;
    let e2 = parse_trusted::<B, S2>(a2)?;
    Ok(op(e1, e2)?.to_byte_array().to_vec())
}

fn binary_op<G: ToFromByteArray<S> + FromTrustedByteArray<S>, const S: usize>(
    op: impl Fn(G, G) -> FastCryptoResult<G>,
    a1: &[u8],
    a2: &[u8],
) -> FastCryptoResult<Vec<u8>> {
    binary_op_diff::<G, G, S, S>(op, a1, a2)
}

fn validate(g: u8, b: &[u8]) -> bool {
    match g {
        SCALAR => parse_untrusted::<Scalar, 32>(b).is_ok(),
        G1 => parse_untrusted::<G1Element, 48>(b).is_ok(),
        G2 => parse_untrusted::<G2Element, 96>(b).is_ok(),
        _ => false,
    }
}

fn add(g: u8, a: &[u8], b: &[u8]) -> FastCryptoResult<Vec<u8>> {
    match g {
        SCALAR => binary_op::<Scalar, 32>(|a, b| Ok(a + b), a, b),
        G1 => binary_op::<G1Element, 48>(|a, b| Ok(a + b), a, b),
        G2 => binary_op::<G2Element, 96>(|a, b| Ok(a + b), a, b),
        GT => binary_op::<GTElement, 576>(|a, b| Ok(a + b), a, b),
        _ => Err(FastCryptoError::InvalidInput),
    }
}

fn sub(g: u8, a: &[u8], b: &[u8]) -> FastCryptoResult<Vec<u8>> {
    match g {
        SCALAR => binary_op::<Scalar, 32>(|a, b| Ok(a - b), a, b),
        G1 => binary_op::<G1Element, 48>(|a, b| Ok(a - b), a, b),
        G2 => binary_op::<G2Element, 96>(|a, b| Ok(a - b), a, b),
        GT => binary_op::<GTElement, 576>(|a, b| Ok(a - b), a, b),
        _ => Err(FastCryptoError::InvalidInput),
    }
}

fn mul(g: u8, a: &[u8], b: &[u8]) -> FastCryptoResult<Vec<u8>> {
    match g {
        SCALAR => binary_op::<Scalar, 32>(|a, b| Ok(b * a), a, b),
        G1 => binary_op_diff::<Scalar, G1Element, 32, 48>(|a, b| Ok(b * a), a, b),
        G2 => binary_op_diff::<Scalar, G2Element, 32, 96>(|a, b| Ok(b * a), a, b),
        GT => binary_op_diff::<Scalar, GTElement, 32, 576>(|a, b| Ok(b * a), a, b),
        _ => Err(FastCryptoError::InvalidInput),
    }
}

fn div(g: u8, a: &[u8], b: &[u8]) -> FastCryptoResult<Vec<u8>> {
    match g {
        SCALAR => binary_op::<Scalar, 32>(|a, b| b / a, a, b),
        G1 => binary_op_diff::<Scalar, G1Element, 32, 48>(|a, b| b / a, a, b),
        G2 => binary_op_diff::<Scalar, G2Element, 32, 96>(|a, b| b / a, a, b),
        GT => binary_op_diff::<Scalar, GTElement, 32, 576>(|a, b| b / a, a, b),
        _ => Err(FastCryptoError::InvalidInput),
    }
}

fn hash_to(g: u8, m: &[u8]) -> FastCryptoResult<Vec<u8>> {
    if m.is_empty() {
        return Err(FastCryptoError::InvalidInput);
    }
    match g {
        G1 => Ok(G1Element::hash_to_group_element(m).to_byte_array().to_vec()),
        G2 => Ok(G2Element::hash_to_group_element(m).to_byte_array().to_vec()),
        _ => Err(FastCryptoError::InvalidInput),
    }
}

fn msm_impl<G, const P: usize>(scalars: &[u8], points: &[u8]) -> FastCryptoResult<Vec<u8>>
where
    G: GroupElement<ScalarType = Scalar> + ToFromByteArray<P> + FromTrustedByteArray<P> + MultiScalarMul,
{
    if points.is_empty()
        || scalars.is_empty()
        || scalars.len() % 32 != 0
        || points.len() % P != 0
        || points.len() / P != scalars.len() / 32
    {
        return Err(FastCryptoError::InvalidInput);
    }
    let s = scalars.chunks(32).map(parse_trusted::<Scalar, 32>).collect::<Result<Vec<_>, _>>();
    let p = points.chunks(P).map(parse_trusted::<G, P>).collect::<Result<Vec<_>, _>>();
    match (s, p) {
        (Ok(s), Ok(p)) => Ok(G::multi_scalar_mul(&s, &p).expect("msm").to_byte_array().to_vec()),
        _ => Err(FastCryptoError::InvalidInput),
    }
}

fn msm(g: u8, scalars: &[u8], points: &[u8]) -> FastCryptoResult<Vec<u8>> {
    match g {
        G1 => msm_impl::<G1Element, 48>(scalars, points),
        G2 => msm_impl::<G2Element, 96>(scalars, points),
        _ => Err(FastCryptoError::InvalidInput),
    }
}

fn pairing(g: u8, a: &[u8], b: &[u8]) -> FastCryptoResult<Vec<u8>> {
    match g {
        G1 => parse_trusted::<G1Element, 48>(a)
            .and_then(|e1| parse_trusted::<G2Element, 96>(b).map(|e2| e1.pairing(&e2).to_byte_array().to_vec())),
        _ => Err(FastCryptoError::InvalidInput),
    }
}

fn convert(from: u8, to: u8, e: &[u8]) -> FastCryptoResult<Vec<u8>> {
    match (from, to) {
        (G1U, G1) => e
            .to_vec()
            .try_into()
            .map_err(|_| FastCryptoError::InvalidInput)
            .map(G1ElementUncompressed::from_trusted_byte_array)
            .and_then(|e| G1Element::try_from(&e))
            .map(|e| e.to_byte_array().to_vec()),
        (G1, G1U) => parse_trusted::<G1Element, 48>(e)
            .map(|e| G1ElementUncompressed::from(&e))
            .map(|e| e.into_byte_array().to_vec()),
        _ => Err(FastCryptoError::InvalidInput),
    }
}

fn sum(g: u8, terms: &[Vec<u8>]) -> FastCryptoResult<Vec<u8>> {
    match g {
        G1U => terms
            .iter()
            .map(|v| {
                v.clone()
                    .try_into()
                    .map_err(|_| FastCryptoError::InvalidInput)
                    .map(G1ElementUncompressed::from_trusted_byte_array)
            })
            .collect::<FastCryptoResult<Vec<_>>>()
            .and_then(|e| G1ElementUncompressed::sum(&e))
            .map(|e| G1ElementUncompressed::from(&e))
            .map(|e| e.into_byte_array().to_vec()),
        _ => Err(FastCryptoError::InvalidInput),
    }
}

fn out(r: FastCryptoResult<Vec<u8>>) -> serde_json::Value {
    match r {
        Ok(b) => json!(h(&b)),
        Err(_) => serde_json::Value::Null,
    }
}

fn rand_scalar(rng: &mut StdRng) -> Scalar {
    Scalar::rand(rng)
}

pub fn cmd_groupops(args: &[String]) -> Result<()> {
    let [out_file] = args else { anyhow::bail!("groupops <out_file>") };
    let mut rng = StdRng::seed_from_u64(0x7a75_692d_6772_6f70);
    let mut buf = Vec::new();
    let mut n = 0usize;
    let mut put = |v: serde_json::Value, buf: &mut Vec<u8>| -> Result<()> {
        serde_json::to_writer(&mut *buf, &v)?;
        buf.push(b'\n');
        n += 1;
        Ok(())
    };

    // Elements as Move code holds them: scalars < r, subgroup points, GT values from pairings.
    let r_minus_1 = (Scalar::zero() - Scalar::generator()).to_byte_array();
    let mut scalars: Vec<[u8; 32]> = vec![
        Scalar::zero().to_byte_array(),
        Scalar::generator().to_byte_array(),
        Scalar::from(2u128).to_byte_array(),
        r_minus_1,
        Scalar::from(u128::MAX).to_byte_array(),
    ];
    for _ in 0..27 {
        scalars.push(rand_scalar(&mut rng).to_byte_array());
    }
    let mut g1s: Vec<[u8; 48]> = vec![G1Element::zero().to_byte_array(), G1Element::generator().to_byte_array()];
    let mut g2s: Vec<[u8; 96]> = vec![G2Element::zero().to_byte_array(), G2Element::generator().to_byte_array()];
    let mut gts: Vec<[u8; 576]> = vec![GTElement::zero().to_byte_array(), GTElement::generator().to_byte_array()];
    for i in 0..14 {
        let s = rand_scalar(&mut rng);
        g1s.push((G1Element::generator() * s).to_byte_array());
        let t = rand_scalar(&mut rng);
        g2s.push((G2Element::generator() * t).to_byte_array());
        if i < 8 {
            gts.push((GTElement::generator() * (s * t)).to_byte_array());
        }
    }
    // a negated generator and a doubled one, to exercise add's doubling and cancellation
    g1s.push((-G1Element::generator()).to_byte_array());
    g2s.push((-G2Element::generator()).to_byte_array());

    // validate: valid encodings plus rejects (non-canonical scalars, bad flags, off-curve,
    // non-subgroup points, wrong lengths)
    let mut vcases: Vec<(u8, Vec<u8>)> = Vec::new();
    for s in &scalars {
        vcases.push((SCALAR, s.to_vec()));
    }
    let r_be = {
        let mut b = r_minus_1;
        // r = (r - 1) + 1 in big-endian
        let mut i = 31;
        loop {
            let (v, c) = b[i].overflowing_add(1);
            b[i] = v;
            if !c || i == 0 {
                break;
            }
            i -= 1;
        }
        b
    };
    vcases.push((SCALAR, r_be.to_vec()));
    vcases.push((SCALAR, [0xffu8; 32].to_vec()));
    vcases.push((SCALAR, vec![1u8; 31]));
    vcases.push((SCALAR, vec![1u8; 33]));
    for g in &g1s {
        vcases.push((G1, g.to_vec()));
    }
    for g in &g2s {
        vcases.push((G2, g.to_vec()));
    }
    for i in 0..24 {
        let mut b = vec![0u8; 48];
        rng.fill_bytes(&mut b);
        b[0] = (b[0] & 0x3f) | 0x80;
        if i % 3 == 0 {
            b[0] &= 0x1f; // not compressed
        }
        vcases.push((G1, b));
        let mut b = vec![0u8; 96];
        rng.fill_bytes(&mut b);
        b[0] = (b[0] & 0x1f) | 0x80;
        b[48] &= 0x1f;
        vcases.push((G2, b));
    }
    for i in 0..12u64 {
        vcases.push((G1, crate::non_subgroup_g1(0x6770_0000 + i).to_vec()));
        vcases.push((G2, crate::non_subgroup_g2(&mut rng).to_vec()));
    }
    vcases.push((G1, vec![0xc0; 48]));
    vcases.push((G1, g1s[1][..47].to_vec()));
    vcases.push((G2, g2s[1][..95].to_vec()));
    vcases.push((GT, gts[1].to_vec()));
    vcases.push((G1U, vec![0u8; 96]));
    vcases.push((9, vec![]));
    for (i, (g, b)) in vcases.iter().enumerate() {
        put(json!({"id": format!("validate/{i}"), "op": "validate", "g": g, "a": h(b), "ok": validate(*g, b)}), &mut buf)?;
    }

    // binary ops on every pair from small pools, all four groups
    let pick = |rng: &mut StdRng, k: usize| (rng.next_u32() as usize) % k;
    for (op, f) in [("add", add as fn(u8, &[u8], &[u8]) -> FastCryptoResult<Vec<u8>>), ("sub", sub)] {
        for i in 0..scalars.len() {
            let j = pick(&mut rng, scalars.len());
            put(json!({"id": format!("{op}/s/{i}"), "op": op, "g": SCALAR, "a": h(&scalars[i]), "b": h(&scalars[j]), "out": out(f(SCALAR, &scalars[i], &scalars[j]))}), &mut buf)?;
        }
        for i in 0..g1s.len() {
            for j in [i, (i + 1) % g1s.len(), pick(&mut rng, g1s.len())] {
                put(json!({"id": format!("{op}/g1/{i}.{j}"), "op": op, "g": G1, "a": h(&g1s[i]), "b": h(&g1s[j]), "out": out(f(G1, &g1s[i], &g1s[j]))}), &mut buf)?;
            }
        }
        for i in 0..g2s.len() {
            for j in [i, (i + 1) % g2s.len(), pick(&mut rng, g2s.len())] {
                put(json!({"id": format!("{op}/g2/{i}.{j}"), "op": op, "g": G2, "a": h(&g2s[i]), "b": h(&g2s[j]), "out": out(f(G2, &g2s[i], &g2s[j]))}), &mut buf)?;
            }
        }
        for i in 0..gts.len() {
            for j in [i, (i + 1) % gts.len()] {
                put(json!({"id": format!("{op}/gt/{i}.{j}"), "op": op, "g": GT, "a": h(&gts[i]), "b": h(&gts[j]), "out": out(f(GT, &gts[i], &gts[j]))}), &mut buf)?;
            }
        }
    }
    for (op, f) in [("mul", mul as fn(u8, &[u8], &[u8]) -> FastCryptoResult<Vec<u8>>), ("div", div)] {
        for (i, s) in scalars.iter().enumerate() {
            let j = pick(&mut rng, scalars.len());
            put(json!({"id": format!("{op}/s/{i}"), "op": op, "g": SCALAR, "a": h(s), "b": h(&scalars[j]), "out": out(f(SCALAR, s, &scalars[j]))}), &mut buf)?;
            let j = pick(&mut rng, g1s.len());
            put(json!({"id": format!("{op}/g1/{i}"), "op": op, "g": G1, "a": h(s), "b": h(&g1s[j]), "out": out(f(G1, s, &g1s[j]))}), &mut buf)?;
            let j = pick(&mut rng, g2s.len());
            put(json!({"id": format!("{op}/g2/{i}"), "op": op, "g": G2, "a": h(s), "b": h(&g2s[j]), "out": out(f(G2, s, &g2s[j]))}), &mut buf)?;
            if i < 12 {
                let j = pick(&mut rng, gts.len());
                put(json!({"id": format!("{op}/gt/{i}"), "op": op, "g": GT, "a": h(s), "b": h(&gts[j]), "out": out(f(GT, s, &gts[j]))}), &mut buf)?;
            }
        }
    }
    // parse failures and wrong lengths in binary ops
    let bad_g1 = {
        let mut b = g1s[1];
        b[0] &= 0x7f;
        b
    };
    let bad_gt = {
        let mut b = gts[1];
        b[..48].copy_from_slice(&hex::decode(crate::P_BE)?);
        b
    };
    put(json!({"id": "add/g1/bad", "op": "add", "g": G1, "a": h(&bad_g1), "b": h(&g1s[1]), "out": out(add(G1, &bad_g1, &g1s[1]))}), &mut buf)?;
    put(json!({"id": "add/gt/noncanonical", "op": "add", "g": GT, "a": h(&bad_gt), "b": h(&gts[1]), "out": out(add(GT, &bad_gt, &gts[1]))}), &mut buf)?;
    put(json!({"id": "add/s/short", "op": "add", "g": SCALAR, "a": h(&scalars[1][1..]), "b": h(&scalars[1]), "out": out(add(SCALAR, &scalars[1][1..], &scalars[1]))}), &mut buf)?;
    put(json!({"id": "mul/g1/badgroup", "op": "mul", "g": 7, "a": h(&scalars[1]), "b": h(&g1s[1]), "out": out(mul(7, &scalars[1], &g1s[1]))}), &mut buf)?;

    // hash_to
    for len in [0usize, 1, 2, 31, 32, 33, 64, 100, 255, 256, 1000] {
        let mut m = vec![0u8; len];
        rng.fill_bytes(&mut m);
        for g in [G1, G2, GT] {
            put(json!({"id": format!("hash_to/{g}/{len}"), "op": "hash_to", "g": g, "a": h(&m), "out": out(hash_to(g, &m))}), &mut buf)?;
        }
    }

    // msm, including zero scalars and identity points (filtered by fastcrypto)
    for (t, k) in [1usize, 2, 3, 5, 8, 13, 16, 32, 33].iter().enumerate() {
        let mut ss = Vec::new();
        let mut p1 = Vec::new();
        let mut p2 = Vec::new();
        for _ in 0..*k {
            ss.extend_from_slice(&scalars[pick(&mut rng, scalars.len())]);
            p1.extend_from_slice(&g1s[pick(&mut rng, g1s.len())]);
            p2.extend_from_slice(&g2s[pick(&mut rng, g2s.len())]);
        }
        put(json!({"id": format!("msm/g1/{t}"), "op": "msm", "g": G1, "a": h(&ss), "b": h(&p1), "out": out(msm(G1, &ss, &p1))}), &mut buf)?;
        put(json!({"id": format!("msm/g2/{t}"), "op": "msm", "g": G2, "a": h(&ss), "b": h(&p2), "out": out(msm(G2, &ss, &p2))}), &mut buf)?;
    }
    let zeros: Vec<u8> = scalars[0].repeat(3);
    let three: Vec<u8> = g1s[1].repeat(3);
    put(json!({"id": "msm/g1/zeros", "op": "msm", "g": G1, "a": h(&zeros), "b": h(&three), "out": out(msm(G1, &zeros, &three))}), &mut buf)?;
    put(json!({"id": "msm/g1/mismatch", "op": "msm", "g": G1, "a": h(&zeros), "b": h(&three[..96]), "out": out(msm(G1, &zeros, &three[..96]))}), &mut buf)?;
    put(json!({"id": "msm/g1/empty", "op": "msm", "g": G1, "a": "", "b": "", "out": out(msm(G1, &[], &[]))}), &mut buf)?;

    // pairing
    for i in 0..g1s.len() {
        let j = if i < g2s.len() { i } else { pick(&mut rng, g2s.len()) };
        put(json!({"id": format!("pairing/{i}.{j}"), "op": "pairing", "g": G1, "a": h(&g1s[i]), "b": h(&g2s[j]), "out": out(pairing(G1, &g1s[i], &g2s[j]))}), &mut buf)?;
    }

    // convert and sum of uncompressed G1
    let mut unc: Vec<Vec<u8>> = Vec::new();
    for (i, g) in g1s.iter().enumerate() {
        let u = convert(G1, G1U, g).expect("compress->uncompressed");
        put(json!({"id": format!("convert/g1-u/{i}"), "op": "convert", "g": G1, "to": G1U, "a": h(g), "out": json!(h(&u))}), &mut buf)?;
        put(json!({"id": format!("convert/u-g1/{i}"), "op": "convert", "g": G1U, "to": G1, "a": h(&u), "out": out(convert(G1U, G1, &u))}), &mut buf)?;
        unc.push(u);
    }
    let mut weird: Vec<Vec<u8>> = Vec::new();
    {
        let mut b = unc[1].clone();
        b[0] |= 0x20;
        weird.push(b);
        let mut b = unc[1].clone();
        b[95] ^= 1; // off curve
        weird.push(b);
        let mut b = vec![0u8; 96];
        b[0] = 0x40;
        weird.push(b);
        weird.push(unc[1][..95].to_vec());
        let ns = crate::non_subgroup_g1(0x6771_0000);
        let blst_p = blst::min_sig::Signature::from_bytes(&ns);
        if let Ok(p) = blst_p {
            weird.push(p.serialize().to_vec());
        }
    }
    for (i, w) in weird.iter().enumerate() {
        put(json!({"id": format!("convert/u-g1/weird{i}"), "op": "convert", "g": G1U, "to": G1, "a": h(w), "out": out(convert(G1U, G1, w))}), &mut buf)?;
    }
    put(json!({"id": "convert/bad-pair", "op": "convert", "g": G1, "to": G2, "a": h(&g1s[1]), "out": out(convert(G1, G2, &g1s[1]))}), &mut buf)?;
    for (t, k) in [0usize, 1, 2, 3, 7, 16, 64].iter().enumerate() {
        let terms: Vec<Vec<u8>> = (0..*k).map(|_| unc[pick(&mut rng, unc.len())].clone()).collect();
        let th: Vec<String> = terms.iter().map(|x| h(x)).collect();
        put(json!({"id": format!("sum/{t}"), "op": "sum", "g": G1U, "terms": th, "out": out(sum(G1U, &terms))}), &mut buf)?;
    }
    for (i, w) in weird.iter().enumerate() {
        let terms = vec![unc[2].clone(), w.clone()];
        let th: Vec<String> = terms.iter().map(|x| h(x)).collect();
        put(json!({"id": format!("sum/weird{i}"), "op": "sum", "g": G1U, "terms": th, "out": out(sum(G1U, &terms))}), &mut buf)?;
    }

    std::fs::File::create(out_file)?.write_all(&buf)?;
    println!("{}", json!({"vectors": n, "file": out_file}));
    Ok(())
}
