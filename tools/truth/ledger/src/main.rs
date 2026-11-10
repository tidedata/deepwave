//! zui-ledger-truth dims <out_dir> <chk>...
//! For each corpus checkpoint blob (0x01 ++ BCS CheckpointData) writes `<out_dir>/<seq>.txt`:
//! one line per distinct (space, tx_seq, event_idx, key) as sui-rpc-store's bitmap indexers
//! emit them: `t <tx_seq> <hex key>` (tx-space, deduplicated per transaction) and
//! `e <tx_seq> <event_idx> <hex key>` (event-space), sorted. Keys are `[tag][value]` from
//! sui_inverted_index::encode_dimension_key.
use std::collections::BTreeSet;
use std::io::Write;

use sui_inverted_index::{encode_dimension_key, for_each_event_dimension, for_each_transaction_dimension};
use sui_types::full_checkpoint_content::{Checkpoint, CheckpointData};
use sui_types::transaction::TransactionDataAPI;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    anyhow::ensure!(args.len() >= 3 && args[1] == "dims", "usage: zui-ledger-truth dims <out_dir> <chk>...");
    let out = std::path::PathBuf::from(&args[2]);
    std::fs::create_dir_all(&out)?;
    for path in &args[3..] {
        let blob = std::fs::read(path)?;
        anyhow::ensure!(blob.first() == Some(&1), "{path}: not a CheckpointData blob");
        let data: CheckpointData = bcs::from_bytes(&blob[1..])?;
        let summary = data.checkpoint_summary.data().clone();
        let n = data.transactions.len() as u64;
        let first = summary.network_total_transactions - n;
        let cp: Checkpoint = data.into();
        let mut lines: BTreeSet<String> = BTreeSet::new();
        for (i, tx) in cp.transactions.iter().enumerate() {
            let tx_seq = first + i as u64;
            let mut keys: BTreeSet<Vec<u8>> = BTreeSet::new();
            for_each_transaction_dimension(&tx.transaction, &tx.effects, tx.events.as_ref(), &cp.object_set, |d, v| {
                keys.insert(encode_dimension_key(d, v));
            });
            for k in keys {
                lines.insert(format!("t {tx_seq:020} {}", hex::encode(k)));
            }
            for_each_event_dimension(tx.transaction.sender(), &tx.effects, tx.events.as_ref(), |idx, d, v| {
                lines.insert(format!("e {tx_seq:020} {idx:05} {}", hex::encode(encode_dimension_key(d, v))));
            });
        }
        let mut f = std::fs::File::create(out.join(format!("{}.txt", summary.sequence_number)))?;
        for l in lines {
            writeln!(f, "{l}")?;
        }
    }
    Ok(())
}
