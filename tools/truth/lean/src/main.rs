//! Ground truth for the lean lane. The Lean specs export vectors (inputs plus the Lean model's
//! verdicts); this tool runs the same inputs through Mysten's own Rust at sui 1.83.1 and reports
//! every disagreement. It never computes truth with its own reimplementation: BCS verdicts come
//! from crates.io `bcs` 0.1.6 (driven by a format-directed `DeserializeSeed`, so every length,
//! depth, tag, UTF-8 and map-order check is the crate's own), gas numbers from `sui-types`'
//! `SuiGasStatus` with `ProtocolConfig::get_for_version(_, Mainnet)`.
//!
//! Commands (formats: README.md):
//!   registry <format.yaml.snap> <out.json>     serde-reflection registry as JSON (Lean input)
//!   bcs-check <registry.json> <vectors.jsonl>  BCS verdicts vs bcs 0.1.6
//!   gas-config <out.json>                      gas parameters per mainnet protocol version
//!   gas-check <vectors.jsonl>                  gas op scripts vs sui-types SuiGasStatus

use anyhow::{Context, Result, anyhow, bail};
use serde::de::{self, DeserializeSeed, Deserializer, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};
use serde_reflection::{ContainerFormat, Format, VariantFormat};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{BufRead, Write};

type Reg = BTreeMap<String, ContainerFormat>;

/// bcs only uses field-name slices for their length; one leaked slice serves every container.
static FIELDS: std::sync::LazyLock<&'static [&'static str]> =
    std::sync::LazyLock::new(|| Box::leak(vec!["f"; 1 << 16].into_boxed_slice()));

fn fields(n: usize) -> &'static [&'static str] {
    &FIELDS[..n]
}

struct Ctx<'a> {
    base: &'a Reg,
    extra: Option<&'a Reg>,
}

impl<'a> Ctx<'a> {
    fn get(&self, name: &str) -> Option<&'a ContainerFormat> {
        self.extra.and_then(|e| e.get(name)).or_else(|| self.base.get(name))
    }
}

#[derive(Clone, Copy)]
struct S<'a> {
    c: &'a Ctx<'a>,
    f: &'a Format,
}

struct Any;
impl<'de> Visitor<'de> for Any {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any primitive")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> { Ok(()) }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> { Ok(()) }
    fn visit_i128<E: de::Error>(self, _: i128) -> Result<(), E> { Ok(()) }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> { Ok(()) }
    fn visit_u128<E: de::Error>(self, _: u128) -> Result<(), E> { Ok(()) }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> { Ok(()) }
    fn visit_bytes<E: de::Error>(self, _: &[u8]) -> Result<(), E> { Ok(()) }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> { Ok(()) }
}

struct OptV<'a>(S<'a>);
impl<'de, 'a> Visitor<'de> for OptV<'a> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("option") }
    fn visit_none<E: de::Error>(self) -> Result<(), E> { Ok(()) }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> { self.0.deserialize(d) }
}

struct NewV<'a>(S<'a>);
impl<'de, 'a> Visitor<'de> for NewV<'a> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("newtype") }
    fn visit_newtype_struct<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> { self.0.deserialize(d) }
}

struct SeqV<'a>(S<'a>);
impl<'de, 'a> Visitor<'de> for SeqV<'a> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("seq") }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<(), A::Error> {
        while a.next_element_seed(self.0)?.is_some() {}
        Ok(())
    }
}

struct TupV<'a> {
    c: &'a Ctx<'a>,
    fs: Vec<&'a Format>,
}
impl<'de, 'a> Visitor<'de> for TupV<'a> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("tuple") }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<(), A::Error> {
        for (i, f) in self.fs.iter().enumerate() {
            if a.next_element_seed(S { c: self.c, f })?.is_none() {
                return Err(de::Error::invalid_length(i, &self));
            }
        }
        Ok(())
    }
}

struct MapV<'a>(S<'a>, S<'a>);
impl<'de, 'a> Visitor<'de> for MapV<'a> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("map") }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<(), A::Error> {
        while a.next_key_seed(self.0)?.is_some() {
            a.next_value_seed(self.1)?;
        }
        Ok(())
    }
}

/// Variant index as serde's derived `__Field` visitor reads it: `invalid_value` past the end.
struct IdxSeed(u64);
impl<'de> DeserializeSeed<'de> for IdxSeed {
    type Value = u32;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<u32, D::Error> {
        d.deserialize_identifier(IdxV(self.0))
    }
}
struct IdxV(u64);
impl<'de> Visitor<'de> for IdxV {
    type Value = u32;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "variant index 0 <= i < {}", self.0) }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<u32, E> {
        if v < self.0 { Ok(v as u32) } else { Err(E::invalid_value(de::Unexpected::Unsigned(v), &self)) }
    }
}

struct EnumV<'a> {
    c: &'a Ctx<'a>,
    vs: &'a BTreeMap<u32, serde_reflection::Named<VariantFormat>>,
}
impl<'de, 'a> Visitor<'de> for EnumV<'a> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("enum") }
    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<(), A::Error> {
        let (idx, var) = data.variant_seed(IdxSeed(self.vs.len() as u64))?;
        let vf = &self.vs.get(&idx).ok_or_else(|| de::Error::custom("variant gap"))?.value;
        match vf {
            VariantFormat::Unit => var.unit_variant(),
            VariantFormat::NewType(f) => var.newtype_variant_seed(S { c: self.c, f }),
            VariantFormat::Tuple(fs) => var.tuple_variant(fs.len(), TupV { c: self.c, fs: fs.iter().collect() }),
            VariantFormat::Struct(nf) => var.struct_variant(
                fields(nf.len()),
                TupV { c: self.c, fs: nf.iter().map(|n| &n.value).collect() },
            ),
            VariantFormat::Variable(_) => Err(de::Error::custom("variable")),
        }
    }
}

impl<'de, 'a> DeserializeSeed<'de> for S<'a> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        let c = self.c;
        match self.f {
            Format::Unit => d.deserialize_unit(Any),
            Format::Bool => d.deserialize_bool(Any),
            Format::I8 => d.deserialize_i8(Any),
            Format::I16 => d.deserialize_i16(Any),
            Format::I32 => d.deserialize_i32(Any),
            Format::I64 => d.deserialize_i64(Any),
            Format::I128 => d.deserialize_i128(Any),
            Format::U8 => d.deserialize_u8(Any),
            Format::U16 => d.deserialize_u16(Any),
            Format::U32 => d.deserialize_u32(Any),
            Format::U64 => d.deserialize_u64(Any),
            Format::U128 => d.deserialize_u128(Any),
            Format::Str => d.deserialize_str(Any),
            Format::Bytes => d.deserialize_bytes(Any),
            Format::Option(f) => d.deserialize_option(OptV(S { c, f })),
            Format::Seq(f) => d.deserialize_seq(SeqV(S { c, f })),
            Format::Map { key, value } => d.deserialize_map(MapV(S { c, f: key }, S { c, f: value })),
            Format::Tuple(fs) => d.deserialize_tuple(fs.len(), TupV { c, fs: fs.iter().collect() }),
            Format::TupleArray { content, size } => {
                d.deserialize_tuple(*size, TupV { c, fs: vec![&**content; *size] })
            }
            Format::TypeName(n) => match c.get(n) {
                None => Err(de::Error::custom(format!("unknown type {n}"))),
                Some(ContainerFormat::UnitStruct) => d.deserialize_unit_struct("T", Any),
                Some(ContainerFormat::NewTypeStruct(f)) => d.deserialize_newtype_struct("T", NewV(S { c, f })),
                Some(ContainerFormat::TupleStruct(fs)) => {
                    d.deserialize_tuple_struct("T", fs.len(), TupV { c, fs: fs.iter().collect() })
                }
                Some(ContainerFormat::Struct(nf)) => d.deserialize_struct(
                    "T",
                    fields(nf.len()),
                    TupV { c, fs: nf.iter().map(|n| &n.value).collect() },
                ),
                Some(ContainerFormat::Enum(vs)) => d.deserialize_enum("T", fields(vs.len()), EnumV { c, vs }),
            },
            _ => Err(de::Error::custom("unsupported format")),
        }
    }
}

/// `bcs::Error` variant name (`Eof`, `ExceededMaxLen`, `Custom`, ...).
fn err_name(e: &bcs::Error) -> String {
    let s = format!("{e:?}");
    s.split('(').next().unwrap_or("").to_string()
}

fn read_registry_snap(path: &str) -> Result<Reg> {
    let text = std::fs::read_to_string(path).with_context(|| path.to_string())?;
    // insta header: "---\n...\n---\n" then the YAML body
    let body = if let Some(rest) = text.strip_prefix("---\n") {
        let end = rest.find("\n---\n").ok_or_else(|| anyhow!("no insta header end"))?;
        &rest[end + 5..]
    } else {
        &text[..]
    };
    Ok(serde_yaml::from_str(body)?)
}

/// The snapshot registry misses variants that serde-reflection never reached when Mysten
/// generated it (in 1.83.1: variant 4, `Passkey`, of `PublicKey` and `CompressedSignature`).
/// Trace those enums again here, from the real Rust types, and add only what is missing.
fn complete_registry(reg: &mut Reg) -> Result<Vec<String>> {
    use serde_reflection::{Samples, Tracer, TracerConfig};
    let mut tracer = Tracer::new(TracerConfig::default());
    let samples = Samples::new();
    tracer.trace_type::<sui_types::crypto::PublicKey>(&samples).map_err(|e| anyhow!("{e:?}"))?;
    tracer.trace_type::<sui_types::crypto::CompressedSignature>(&samples).map_err(|e| anyhow!("{e:?}"))?;
    let traced = tracer.registry().map_err(|e| anyhow!("{e:?}"))?;
    let mut added = vec![];
    for (name, c) in traced {
        match (reg.get_mut(&name), c) {
            (None, c) => {
                added.push(format!("type {name}"));
                reg.insert(name, c);
            }
            (Some(ContainerFormat::Enum(have)), ContainerFormat::Enum(full)) => {
                for (i, v) in full {
                    match have.get(&i) {
                        None => {
                            added.push(format!("{name} variant {i} {}", v.name));
                            have.insert(i, v);
                        }
                        Some(h) if h.name != v.name => bail!("{name} variant {i}: {} vs traced {}", h.name, v.name),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Ok(added)
}

fn cmd_registry(snap: &str, out: &str) -> Result<()> {
    let mut reg = read_registry_snap(snap)?;
    for a in complete_registry(&mut reg)? {
        eprintln!("added from a fresh trace: {a}");
    }
    std::fs::write(out, serde_json::to_string(&reg)?)?;
    eprintln!("{} types -> {out}", reg.len());
    Ok(())
}

#[derive(serde::Deserialize)]
struct BcsVector {
    id: String,
    #[serde(default)]
    types: Option<Reg>,
    fmt: Format,
    hex: String,
    expect: String,
}

fn cmd_bcs_check(reg_path: &str, vec_path: &str) -> Result<()> {
    let base: Reg = serde_json::from_str(&std::fs::read_to_string(reg_path)?)?;
    let f = std::io::BufReader::new(std::fs::File::open(vec_path)?);
    let (mut items, mut failed) = (0u64, 0u64);
    let mut by_expect: BTreeMap<String, u64> = BTreeMap::new();
    let out = std::io::stdout();
    let mut out = out.lock();
    for line in f.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let v: BcsVector = serde_json::from_str(&line).with_context(|| format!("bad vector: {line}"))?;
        let bytes = hex::decode(&v.hex)?;
        let ctx = Ctx { base: &base, extra: v.types.as_ref() };
        let got = match bcs::from_bytes_seed(S { c: &ctx, f: &v.fmt }, &bytes) {
            Ok(()) => "ok".to_string(),
            Err(e) => err_name(&e),
        };
        items += 1;
        *by_expect.entry(v.expect.clone()).or_default() += 1;
        if got != v.expect {
            failed += 1;
            if failed <= 50 {
                writeln!(out, "FAIL {} lean={} rust={}", v.id, v.expect, got)?;
            }
        }
    }
    writeln!(
        out,
        "{}",
        serde_json::json!({"check":"bcs","items":items,"failed":failed,"by_verdict":by_expect,"done": failed == 0 && items > 0})
    )?;
    if failed > 0 {
        bail!("{failed} of {items} BCS vectors disagree with bcs 0.1.6");
    }
    Ok(())
}

// ---------------------------------------------------------------- gas

use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};

fn gas_cfg_json(pv: u64) -> serde_json::Value {
    let c = ProtocolConfig::get_for_version(ProtocolVersion::new(pv), Chain::Mainnet);
    serde_json::json!({
        "pv": pv,
        "gas_model_version": c.gas_model_version_as_option(),
        "max_gas_computation_bucket": c.max_gas_computation_bucket_as_option(),
        "base_tx_cost_fixed": c.base_tx_cost_fixed_as_option(),
        "txn_base_cost_as_multiplier": c.txn_base_cost_as_multiplier(),
        "max_tx_gas": c.max_tx_gas_as_option(),
        "max_gas_price": c.max_gas_price_as_option(),
        "obj_access_cost_read_per_byte": c.obj_access_cost_read_per_byte_as_option(),
        "obj_access_cost_read_per_package_kb": c.obj_access_cost_read_per_package_kb_as_option(),
        "package_publish_cost_per_byte": c.package_publish_cost_per_byte_as_option(),
        "obj_data_cost_refundable": c.obj_data_cost_refundable_as_option(),
        "storage_gas_price": c.storage_gas_price_as_option(),
        "storage_rebate_rate": c.storage_rebate_rate_as_option(),
        "max_gas_price_rgp_factor_for_aborted_transactions": c.max_gas_price_rgp_factor_for_aborted_transactions_as_option(),
        "gas_rounding_halve_digits": c.gas_rounding_halve_digits(),
        "gas_rounding_step": c.gas_rounding_step_as_option(),
    })
}

fn cmd_gas_config(out: &str) -> Result<()> {
    let max = ProtocolVersion::MAX.as_u64();
    let all: Vec<_> = (1..=max).map(gas_cfg_json).collect();
    std::fs::write(out, serde_json::to_string(&all)?)?;
    eprintln!("protocol versions 1..={max} -> {out}");
    Ok(())
}

fn gas_run(v: &serde_json::Value) -> Result<serde_json::Value> {
    use move_core_types::gas_algebra::InternalGas;
    use sui_types::base_types::ObjectID;
    use sui_types::gas::{SuiGasStatus, SuiGasStatusAPI};
    let n = |k: &str| v[k].as_u64().ok_or_else(|| anyhow!("missing {k}"));
    let pv = n("pv")?;
    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(pv), Chain::Mainnet);
    // The vector carries the Lean side's copy of the config; it must equal the Rust one.
    if v["cfg"] != gas_cfg_json(pv) {
        bail!("config mismatch for pv {pv}: lean {} rust {}", v["cfg"], gas_cfg_json(pv));
    }
    let mut st = match SuiGasStatus::new(n("budget")?, n("price")?, n("rgp")?, &cfg) {
        Ok(s) => s,
        Err(e) => {
            let s = format!("{e:?}");
            let kind = if s.contains("GasPriceUnderRGP") {
                "GasPriceUnderRGP"
            } else if s.contains("GasPriceTooHigh") {
                "GasPriceTooHigh"
            } else {
                "other"
            };
            return Ok(serde_json::json!({"new": kind}));
        }
    };
    let ex = |r: Result<(), sui_types::error::ExecutionError>| -> String {
        match r {
            Ok(()) => "ok".into(),
            Err(e) => format!("{:?}", e.kind()),
        }
    };
    let vm = |r: move_binary_format::errors::PartialVMResult<()>| -> String {
        match r {
            Ok(()) => "ok".into(),
            Err(e) => format!("{:?}", e.major_status()),
        }
    };
    let mut res = vec![];
    for op in v["ops"].as_array().ok_or_else(|| anyhow!("ops"))? {
        let a = op.as_array().ok_or_else(|| anyhow!("op"))?;
        let name = a[0].as_str().unwrap_or("");
        let arg = |i: usize| a[i].as_u64().unwrap_or(0);
        let r = match name {
            "charge" => vm(st.move_gas_status_mut().charge(arg(1), arg(2), arg(3), arg(4), arg(5))),
            "deduct" => vm(st.move_gas_status_mut().deduct_gas(InternalGas::new(arg(1)))),
            "read" => ex(st.charge_storage_read(arg(1) as usize)),
            "pkgread" => ex(st.charge_package_object_read(arg(1) as usize)),
            "publish" => ex(st.charge_publish_package(arg(1) as usize)),
            "mutate" => match st.track_storage_mutation(ObjectID::ZERO, arg(1) as usize, arg(2)) {
                Some(c) => c.to_string(),
                None => "none".into(),
            },
            "bucketize" => ex(st.bucketize_computation(Some(arg(1) == 1))),
            "storage" => ex(st.charge_storage_and_rebate()),
            "oog" => {
                st.adjust_computation_on_out_of_gas();
                "ok".into()
            }
            "reset" => {
                st.reset_storage_cost_and_rebate();
                "ok".into()
            }
            _ => bail!("unknown op {name}"),
        };
        res.push(r);
    }
    let s = st.summary();
    Ok(serde_json::json!({
        "res": res,
        "summary": [s.computation_cost, s.storage_cost, s.storage_rebate, s.non_refundable_storage_fee],
        "used": st.gas_used(),
        "left": u64::from(st.move_gas_status().gas_left),
    }))
}

fn cmd_gas_check(vec_path: &str) -> Result<()> {
    let f = std::io::BufReader::new(std::fs::File::open(vec_path)?);
    let (mut items, mut failed) = (0u64, 0u64);
    let out = std::io::stdout();
    let mut out = out.lock();
    for line in f.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(&line)?;
        let got = gas_run(&v)?;
        items += 1;
        if got != v["expect"] {
            failed += 1;
            if failed <= 50 {
                writeln!(out, "FAIL {} lean={} rust={}", v["id"], v["expect"], got)?;
            }
        }
    }
    writeln!(out, "{}", serde_json::json!({"check":"gas","items":items,"failed":failed,"done": failed == 0 && items > 0}))?;
    if failed > 0 {
        bail!("{failed} of {items} gas vectors disagree with sui-types");
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let a = |i: usize| args.get(i).map(String::as_str).ok_or_else(|| anyhow!("missing argument {i}"));
    match args.get(1).map(String::as_str) {
        Some("registry") => cmd_registry(a(2)?, a(3)?),
        Some("bcs-check") => cmd_bcs_check(a(2)?, a(3)?),
        Some("gas-config") => cmd_gas_config(a(2)?),
        Some("gas-check") => cmd_gas_check(a(2)?),
        _ => bail!("usage: zui-lean-truth registry|bcs-check|gas-config|gas-check ..."),
    }
}
