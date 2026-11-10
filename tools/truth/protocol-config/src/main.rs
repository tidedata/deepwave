//! zui-pc-truth: ground truth for the protocol-config lane.
//!
//! Runs Mysten's `sui-protocol-config` (never a reimplementation) for every (chain, version)
//! and writes, into the output directory:
//!   yaml/<Chain>_<version>.yaml   the insta YAML body of the real config (header-less), after
//!                                 asserting it equals the checked-in `.snap` body byte for byte
//!   dump.jsonl                    one line per (chain, version): {"chain","v","cfg":<serde_json>}
//!   gas.json                      sui-types gas_model tables and tier lookups
//! See README.md.
use std::{collections::BTreeMap, fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use insta::_macro_support::{SerializationFormat, serialize_value};
use serde_json::{Value, json};
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use sui_types::gas_model::{gas_predicates as gp, tables as t, units_types::CostTable};

fn chains() -> [(Chain, &'static str, &'static str); 3] {
    // (chain, file prefix, snapshot name prefix)
    [(Chain::Unknown, "Unknown", ""), (Chain::Mainnet, "Mainnet", "Mainnet_"), (Chain::Testnet, "Testnet", "Testnet_")]
}

fn table_json(c: &CostTable) -> Value {
    let m = |b: &BTreeMap<u64, u64>| b.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>();
    json!({"instruction": m(&c.instruction_tiers), "stack_height": m(&c.stack_height_tiers), "stack_size": m(&c.stack_size_tiers)})
}

/// Probe points: every tier boundary -1, 0, +1, a few midpoints, and a sweep.
fn probes(c: &CostTable) -> Vec<u64> {
    let mut p: Vec<u64> = vec![0, 1, 2, 3, 7, 100, 1000, u64::MAX / 2, u64::MAX - 1, u64::MAX];
    for m in [&c.instruction_tiers, &c.stack_height_tiers, &c.stack_size_tiers] {
        for k in m.keys() {
            p.extend([k.saturating_sub(1), *k, k + 1, k + 7]);
        }
    }
    let mut x: u64 = 0x9e3779b97f4a7c15;
    for _ in 0..64 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        p.push(x % 300_000_000);
    }
    p.sort();
    p.dedup();
    p
}

fn tier_json(c: &CostTable, p: &[u64]) -> Value {
    let f = |g: &dyn Fn(u64) -> (u64, Option<u64>)| p.iter().map(|x| { let (a, b) = g(*x); json!([a, b]) }).collect::<Vec<_>>();
    json!({
        "instruction": f(&|x| c.instruction_tier(x)),
        "stack_height": f(&|x| c.stack_height_tier(x)),
        "stack_size": f(&|x| c.stack_size_tier(x)),
    })
}

/// Runs `f`, mapping a panic (Rust's "config value missing" or failed invariant) to {"panic":true}.
fn guarded<F: FnOnce() -> Value + std::panic::UnwindSafe>(f: F) -> Value {
    std::panic::catch_unwind(f).unwrap_or_else(|_| json!({"panic": true}))
}

fn getters(c: &ProtocolConfig) -> Value {
    macro_rules! g {
        ($m:ident, $e:expr) => {
            ($m.0.insert(stringify!($e).split("c.").nth(1).unwrap().split('(').next().unwrap().to_string(), guarded(std::panic::AssertUnwindSafe(|| json!($e))))).take()
        };
    }
    let mut m = (serde_json::Map::new(),);
    let _ = g!(m, c.check_package_upgrades_supported().is_ok());
    let _ = g!(m, c.zklogin_supported_providers());
    let _ = g!(m, c.zklogin_circuit_mode());
    let _ = g!(m, c.consensus_transaction_ordering());
    let _ = g!(m, c.enable_jwk_consensus_updates());
    let _ = g!(m, c.staggered_submission_signal());
    let _ = g!(m, c.end_of_epoch_transaction_supported());
    let _ = g!(m, c.dkg_version());
    let _ = g!(m, c.bridge());
    let _ = g!(m, c.should_try_to_finalize_bridge_committee());
    let _ = g!(m, c.zklogin_max_epoch_upper_bound_delta());
    let _ = g!(m, c.enable_allowances());
    let _ = g!(m, c.enable_coin_reservation_obj_refs());
    let _ = g!(m, c.enable_authenticated_event_streams());
    let _ = g!(m, c.per_object_congestion_control_mode());
    let _ = g!(m, c.consensus_choice());
    let _ = g!(m, c.consensus_network());
    let _ = g!(m, c.mysticeti_num_leaders_per_round());
    let _ = g!(m, c.max_transaction_size_bytes());
    let _ = g!(m, c.max_transactions_in_block_bytes());
    let _ = g!(m, c.max_num_transactions_in_block());
    let _ = g!(m, c.gc_depth());
    let _ = g!(m, c.consensus_linearize_subdag_v2());
    let _ = g!(m, c.consensus_median_based_commit_timestamp());
    let _ = g!(m, c.get_consensus_commit_rate_estimation_window_size());
    let _ = g!(m, c.consensus_num_requested_prior_commits_at_startup());
    let _ = g!(m, c.address_aliases());
    let _ = g!(m, c.new_vm_enabled());
    let _ = g!(m, c.gasless_allowed_token_types());
    let _ = g!(m, c.get_gasless_max_unused_inputs());
    let _ = g!(m, c.get_gasless_max_pure_input_bytes());
    let _ = g!(m, c.get_gasless_max_tx_size_bytes());
    Value::Object(m.0)
}

/// Names that are not bool feature flags (other flag types, config fields, unknown, case, empty).
fn lookup_probes() -> [&'static str; 9] {
    ["zklogin_circuit_mode", "consensus_choice", "per_object_congestion_control_mode", "zklogin_supported_providers",
     "max_tx_size_bytes", "", "PACKAGE_UPGRADES", "package_upgrades ", "no_such_flag"]
}

fn verifier_json(c: &ProtocolConfig, signing: Option<(usize, usize, usize)>) -> Value {
    guarded(std::panic::AssertUnwindSafe(|| {
        let v = c.verifier_config(signing);
        json!({
            "max_loop_depth": v.max_loop_depth,
            "max_function_parameters": v.max_function_parameters,
            "max_generic_instantiation_length": v.max_generic_instantiation_length,
            "max_basic_blocks": v.max_basic_blocks,
            "max_value_stack_size": v.max_value_stack_size,
            "max_type_nodes": v.max_type_nodes,
            "max_push_size": v.max_push_size,
            "max_dependency_depth": v.max_dependency_depth,
            "max_data_definitions": v.max_data_definitions,
            "max_fields_in_struct": v.max_fields_in_struct,
            "max_function_definitions": v.max_function_definitions,
            "max_constant_vector_len": v.max_constant_vector_len,
            "max_back_edges_per_function": v.max_back_edges_per_function,
            "max_back_edges_per_module": v.max_back_edges_per_module,
            "max_basic_blocks_in_script": v.max_basic_blocks_in_script,
            "max_identifier_len": v.max_identifier_len,
            "disallow_self_identifier": v.disallow_self_identifier,
            "allow_receiving_object_id": v.allow_receiving_object_id,
            "reject_mutable_random_on_entry_functions": v.reject_mutable_random_on_entry_functions,
            "bytecode_version": v.bytecode_version,
            "max_variants_in_enum": v.max_variants_in_enum,
            "additional_borrow_checks": v.additional_borrow_checks,
            "better_loader_errors": v.better_loader_errors,
            "private_generics_verifier_v2": v.private_generics_verifier_v2,
            "sanity_check_with_regex_reference_safety": v.sanity_check_with_regex_reference_safety.map(|x| x.to_string()),
            "deprecate_global_storage_ops": v.deprecate_global_storage_ops,
            "disable_entry_point_signature_check": v.disable_entry_point_signature_check,
            "switch_to_regex_reference_safety": v.switch_to_regex_reference_safety,
            "framework_tx_context_mut_restrictions": v.framework_tx_context_mut_restrictions,
            "disallow_jump_orphans": v.disallow_jump_orphans,
            "max_generic_instantiation_type_nodes_per_function": v.max_generic_instantiation_type_nodes_per_function,
            "max_generic_instantiation_type_nodes_per_module": v.max_generic_instantiation_type_nodes_per_module,
            "include_function_signatures_in_instantiation_limits": v.include_function_signatures_in_instantiation_limits,
            "disable_id_leak_verifier": v.disable_id_leak_verifier,
        })
    }))
}

fn binary_json(c: &ProtocolConfig, o: Option<bool>) -> Value {
    guarded(std::panic::AssertUnwindSafe(|| {
        let b = c.binary_config(o);
        let t = &b.table_config;
        #[allow(unused_mut)]
        let mut v = json!({
            "max_binary_format_version": b.max_binary_format_version,
            "min_binary_format_version": b.min_binary_format_version,
            "check_no_extraneous_bytes": b.check_no_extraneous_bytes,
            "deprecate_global_storage_ops": b.deprecate_global_storage_ops,
            "allow_unpublishable": b.allow_unpublishable(),
            "table": [t.module_handles, t.datatype_handles, t.function_handles, t.function_instantiations, t.signatures,
                      t.constant_pool, t.identifiers, t.address_identifiers, t.struct_defs, t.struct_def_instantiations,
                      t.function_defs, t.field_handles, t.field_instantiations, t.friend_decls, t.enum_defs,
                      t.enum_def_instantiations, t.variant_handles, t.variant_instantiation_handles],
        });
        #[cfg(feature = "sui_184")]
        { v["type_parameter_index_max"] = json!(b.binary_format_limits.type_parameter_index_max()); }
        v
    }))
}

fn main() -> Result<()> {
    std::panic::set_hook(Box::new(|_| {})); // guarded() panics are expected truth, not noise
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "bench" {
        return bench(&args[2..]);
    }
    if args.len() < 3 || args[1] != "dump" {
        bail!("usage: zui-pc-truth dump <out_dir> [snapshots_dir] | bench get|render --iters N --list <file>");
    }
    let out = PathBuf::from(&args[2]);
    let snaps = PathBuf::from(
        args.get(3).cloned().unwrap_or_else(|| "../../sui/crates/sui-protocol-config/src/snapshots".into()),
    );
    fs::create_dir_all(out.join("yaml"))?;
    let mut dump = String::new();
    let mut gdump = String::new();
    let mut n = 0usize;
    for (chain, cname, sprefix) in chains() {
        for v in ProtocolVersion::MIN.as_u64()..=ProtocolVersion::MAX.as_u64() {
            let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(v), chain);
            let yaml = serialize_value(&cfg, SerializationFormat::Yaml);
            // insta writes the snapshot as header + "---\n" + yaml + "\n"; serialize_value returns "---\n<body>".
            let body = yaml.strip_prefix("---\n").unwrap_or(&yaml);
            let snap_path = snaps.join(format!("sui_protocol_config__test__{sprefix}version_{v}.snap"));
            let snap = fs::read_to_string(&snap_path).with_context(|| snap_path.display().to_string())?;
            let sb = snap.splitn(3, "---\n").nth(2).context("snap header")?;
            let sb = sb.trim_end();
            let body = body.trim_end();
            if sb != body {
                                bail!("{cname} v{v}: Mysten real config does not match its own checked-in snapshot");
            }
            fs::write(out.join("yaml").join(format!("{cname}_{v}.yaml")), format!("{body}\n"))?;
            let cfgv = serde_json::to_value(&cfg)?;
            dump.push_str(&serde_json::to_string(&json!({"chain": cname, "v": v, "cfg": cfgv}))?);
            dump.push('\n');
            let gl = json!({
                "chain": cname, "v": v, "g": getters(&cfg),
                "verifier": verifier_json(&cfg, None),
                "verifier_signing": verifier_json(&cfg, Some((100, 200, 300))),
                "binary": binary_json(&cfg, None),
                "binary_true": binary_json(&cfg, Some(true)),
                "binary_false": binary_json(&cfg, Some(false)),
                // Macro-generated lookups: every bool feature flag by name (the Move native
                // `protocol_config::is_feature_enabled` goes through lookup_feature), and probes of
                // names that are not bool flags.
                "feature_map": cfg.feature_map(),
                "lookup_feature": lookup_probes().iter().map(|n| json!([n, cfg.lookup_feature(n.to_string())])).collect::<Vec<_>>(),
            });
            gdump.push_str(&serde_json::to_string(&gl)?);
            gdump.push('\n');
            n += 1;
        }
    }
    fs::write(out.join("dump.jsonl"), dump)?;
    fs::write(out.join("getters.jsonl"), gdump)?;

    // Gas model tables and predicates.
    let named: Vec<(&str, CostTable)> = vec![
        ("zero", t::zero_cost_schedule()),
        ("unit", t::unit_cost_schedule()),
        ("v1", t::initial_cost_schedule_v1()),
        ("v2", t::initial_cost_schedule_v2()),
        ("v3", t::initial_cost_schedule_v3()),
        ("v4", t::initial_cost_schedule_v4()),
        ("v5", t::initial_cost_schedule_v5()),
    ];
    let mut tables = serde_json::Map::new();
    for (name, c) in &named {
        let p = probes(c);
        tables.insert(name.to_string(), json!({"table": table_json(c), "probes": p, "tiers": tier_json(c, &p)}));
    }
    let mut by_gm = Vec::new();
    let mut preds = Vec::new();
    for gm in 0..=40u64 {
        let c = gp::cost_table_for_version(gm);
        by_gm.push(table_json(&c));
        preds.push(json!({
            "gm": gm,
            "dont_charge_budget_on_storage_oog": gp::dont_charge_budget_on_storage_oog(gm),
            "check_for_gas_price_too_high": gp::check_for_gas_price_too_high(gm),
            "charge_input_as_memory": gp::charge_input_as_memory(gm),
            "use_legacy_abstract_size": gp::use_legacy_abstract_size(gm),
            "charge_upgrades": gp::charge_upgrades(gm),
            "legacy_charge_native_pops_args": gp::legacy_charge_native_pops_args(gm),
            "refresh_gas_payment_location": gp::refresh_gas_payment_location(gm),
            "bump_only_enabled": gp::bump_only_enabled(gm),
            "native_function_threshold_exceeded": [gp::native_function_threshold_exceeded(gm, 700), gp::native_function_threshold_exceeded(gm, 701)],
        }));
    }
    let gas = json!({"tables": tables, "cost_table_for_version": by_gm, "predicates": preds});
    fs::write(out.join("gas.json"), serde_json::to_string(&gas)?)?;
    eprintln!("wrote {n} configs, {} gas tables", named.len());
    Ok(())
}

/// Rust side of `zig build bench -Dsuite=protocol-config` (CONTRACTS.md section 7): the input list
/// names `<Chain>_<version>.yaml` files; one pass handles every listed (chain, version) once.
///   get     `ProtocolConfig::get_for_version`
///   render  insta YAML serialization of the already-built config
fn bench(args: &[String]) -> Result<()> {
    let name = args[0].clone();
    let mut iters = 5usize;
    let mut list = String::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--iters" => { iters = args[i + 1].parse()?; i += 2; }
            "--list" => { list = args[i + 1].clone(); i += 2; }
            a => bail!("unknown bench argument {a}"),
        }
    }
    let mut items: Vec<(Chain, u64)> = Vec::new();
    for l in fs::read_to_string(&list)?.lines() {
        let base = l.rsplit('/').next().unwrap();
        let (c, rest) = base.split_once('_').context("bench input name")?;
        let v: u64 = rest.split('.').next().unwrap().parse()?;
        items.push((match c { "Mainnet" => Chain::Mainnet, "Testnet" => Chain::Testnet, _ => Chain::Unknown }, v));
    }
    let prebuilt: Vec<ProtocolConfig> = items.iter().map(|(c, v)| ProtocolConfig::get_for_version(ProtocolVersion::new(*v), *c)).collect();
    let pass = |name: &str| -> u64 {
        let t0 = std::time::Instant::now();
        match name {
            "get" => {
                let mut acc = 0u64;
                for (c, v) in &items {
                    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(*v), *c);
                    acc = acc.wrapping_add(cfg.max_tx_size_bytes_as_option().unwrap_or(0));
                    std::hint::black_box(&cfg);
                }
                std::hint::black_box(acc);
            }
            _ => {
                let mut total = 0usize;
                for cfg in &prebuilt {
                    total += serialize_value(cfg, SerializationFormat::Yaml).len();
                }
                std::hint::black_box(total);
            }
        }
        t0.elapsed().as_nanos() as u64
    };
    if name != "get" && name != "render" {
        bail!("unknown bench {name} (get, render)");
    }
    pass(&name); // warm-up
    let mut times: Vec<u64> = (0..iters).map(|_| pass(&name)).collect();
    times.sort();
    let med = times[times.len() / 2];
    let units = items.len() as u64;
    println!(
        "{}",
        json!({"impl":"rust","bench":name,"unit":"config","units":units,"iters":iters,"median_ns":med,"min_ns":times[0],"ns_per_unit":(med as f64 / units as f64 * 100.0).round() / 100.0})
    );
    Ok(())
}
