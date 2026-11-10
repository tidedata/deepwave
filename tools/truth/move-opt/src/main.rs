//! zui-truth-move-opt: does what deepwave-move emits verify in Mysten's Rust?
//!
//!   zui-truth-move-opt verify <protocol version> <file.mv>...
//!
//! One JSON line per file: deserialization result, the Move bytecode verifier and the Sui
//! verifier (the publish path of mainnet-v1.83.1, no signing limits), and the instruction count.
//! It is run over the output of `deepwave-move optimize` / `superopt` and
//! compares with deepwave's own verdict (`deepwave-move equiv` prints it as `verifier`).
use anyhow::{Result, anyhow};
use move_binary_format::CompiledModule;
use move_bytecode_verifier_meter::{Meter, Scope};
use std::collections::BTreeMap;
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};

#[derive(Default)]
struct Unmetered;

impl Meter for Unmetered {
    fn enter_scope(&mut self, _name: &str, _scope: Scope) {}
    fn transfer(&mut self, _from: Scope, _to: Scope, _factor: f32) -> move_binary_format::errors::PartialVMResult<()> {
        Ok(())
    }
    fn add(&mut self, _scope: Scope, _units: u128) -> move_binary_format::errors::PartialVMResult<()> {
        Ok(())
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 || args[1] != "verify" {
        return Err(anyhow!("usage: zui-truth-move-opt verify <protocol version> <file.mv>..."));
    }
    let pv: u64 = args[2].parse()?;
    let cfg = ProtocolConfig::get_for_version(ProtocolVersion::new(pv), Chain::Mainnet);
    let bc = cfg.binary_config(None);
    let vcfg = cfg.verifier_config(None);
    for path in &args[3..] {
        let bytes = std::fs::read(path)?;
        let out = match CompiledModule::deserialize_with_config(&bytes, &bc) {
            Err(e) => serde_json::json!({ "file": path, "deserialize": format!("{e:?}") }),
            Ok(m) => {
                let mut meter = Unmetered;
                let mv = move_bytecode_verifier::verify_module_with_config_metered(&vcfg, &m, &mut meter);
                let (move_json, sui_json) = match mv {
                    Err(e) => (serde_json::json!({ "err": format!("{:?}", e.major_status()) }), serde_json::Value::Null),
                    Ok(()) => {
                        let sui = sui_verifier_latest::verifier::sui_verify_module_metered(&m, &BTreeMap::new(), &mut meter, &vcfg);
                        (
                            serde_json::json!("ok"),
                            match sui {
                                Ok(()) => serde_json::json!("ok"),
                                Err(e) => serde_json::json!({ "err": format!("{:?}", e.kind()), "msg": e.source().as_ref().map(|s| s.to_string()) }),
                            },
                        )
                    }
                };
                let instructions: usize = m.function_defs().iter().filter_map(|f| f.code.as_ref()).map(|c| c.code.len()).sum();
                serde_json::json!({ "file": path, "deserialize": "ok", "move": move_json, "sui": sui_json, "instructions": instructions })
            }
        };
        println!("{out}");
    }
    Ok(())
}
