//! Dumps the per-epoch authority tables of a stopped Mysten localnet validator (read only) as
//! jsonl, one file per table. See ../README.md. The table list and page loop use typed-store's
//! generated `dump` on `AuthorityEpochTablesReadOnly` (the same call `sui-tool db-tool dump` makes).
use anyhow::{Context, Result};
use clap::Parser;
use std::{fs, io::Write, path::PathBuf};
use sui_core::authority::authority_per_epoch_store::AuthorityEpochTables;

#[derive(Parser)]
struct Args {
    /// Mysten source checkout (only used to name the pinned version in the output).
    #[arg(long)]
    sui_src: PathBuf,
    /// The localnet working dir written by `sui genesis`.
    #[arg(long)]
    localnet: PathBuf,
    #[arg(long)]
    out: PathBuf,
    /// Epoch to read.
    #[arg(long, default_value_t = 0)]
    epoch: u64,
}

const TABLES: &[&str] = &[
    "owned_object_locked_transactions",
    "consensus_message_processed",
    "shared_object_next_versions_v2",
    "assigned_shared_object_versions_v3",
    "deferred_transactions_v2",
    "deferred_transactions_with_aliases_v2",
    "congestion_control_object_debts",
    "congestion_control_randomness_object_debts",
    "last_consensus_stats_v2",
    "pending_checkpoints_v2",
    "execution_time_observations",
];

fn main() -> Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.out)?;
    let mut manifest = fs::File::create(args.out.join("manifest.json"))?;
    writeln!(manifest, "{{\"sui_src\": {:?}, \"epoch\": {}}}", args.sui_src, args.epoch)?;
    // each validator directory under the localnet holds its own authorities db
    for entry in fs::read_dir(&args.localnet)? {
        let dir = entry?.path();
        let db = dir.join("authorities_db");
        if !db.is_dir() {
            continue;
        }
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        let epoch_dir = db.join("live").join("store").join(format!("epoch_{}", args.epoch));
        let parent = if epoch_dir.is_dir() { epoch_dir.parent().unwrap().to_path_buf() } else { db.clone() };
        let ro = AuthorityEpochTables::open_readonly(args.epoch, &parent);
        let vdir = args.out.join(&name);
        fs::create_dir_all(&vdir)?;
        for table in TABLES {
            let mut f = fs::File::create(vdir.join(format!("{table}.jsonl")))?;
            let mut page = 0;
            loop {
                let rows = ro
                    .dump(table, 1000, page)
                    .with_context(|| format!("dump {table} for {name}"))?;
                if rows.is_empty() {
                    break;
                }
                for (k, v) in rows {
                    writeln!(f, "{}", serde_json::json!({ "key": k, "value": v }))?;
                }
                page += 1;
            }
        }
    }
    Ok(())
}
