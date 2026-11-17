// deepwave truth: dump of sui-node consensus stores (Mysten consensus-core at mainnet-v1.83.1).
//
// A child module of consensus/core/src/storage/rocksdb_store.rs (dropped in by dump/run.sh into a
// scratch worktree of the sui checkout, never into the checkout itself), so it reads the store's
// own tables through the store's own types. Run with the validators stopped. ZUI_DUMP_JOBS names a
// file with one job per line: the output file, then one epoch's store per validator
// (`<label>=<consensus db-path>/<epoch>`):
//
//   echo "epoch-3.vec v0=/path/to/db/3 v1=/path/..." > jobs
//   ZUI_DUMP_JOBS=jobs cargo test -p consensus-core --lib zui_consensus_dump -- --ignored --nocapture
//
// Output lines (hex is lowercase, no prefix), every list in key order:
//   store <label> <blocks> <commits> <commit_info> <finalized>       one per store
//   block <round> <author> <digest> <SignedBlock bytes>              union of every store, by (round, author, digest)
//   commit <index> <digest> <Commit bytes>                           union; equal at each index in every store (asserted)
//   info <index> <digest> <committed_rounds csv> <scores csv> <range start> <range end>
//   final <index> <digest> <n> [<round>,<author>,<block digest>=<tx indices csv|->]...
//   end <blocks> <commits> <max common commit>
// `final` lines come from every store that finalized the commit; they must agree (asserted).
use std::{
    collections::BTreeMap,
    fmt::Write as _,
    io::Write as _,
};

use consensus_types::block::{BlockRef, TransactionIndex};
use typed_store::Map as _;

use super::RocksDBStore;
use crate::commit::{CommitAPI as _, CommitInfo};

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

fn dhex<T: serde::Serialize>(d: &T) -> String {
    // BlockDigest and CommitDigest serialize as their 32 bytes.
    let b = bcs::to_bytes(d).unwrap();
    assert_eq!(b.len(), 32, "digest serializes to 32 bytes");
    hex(&b)
}

fn rejects_line(m: &BTreeMap<BlockRef, Vec<TransactionIndex>>) -> String {
    let mut s = format!("{}", m.len());
    for (r, txs) in m {
        let list = if txs.is_empty() {
            "-".to_string()
        } else {
            txs.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(",")
        };
        write!(s, " {},{},{}={}", r.round, r.author.value(), dhex(&r.digest), list).unwrap();
    }
    s
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn zui_consensus_dump() {
    let jobs = std::env::var("ZUI_DUMP_JOBS").expect("ZUI_DUMP_JOBS: file of `out label=path ...` lines");
    let text = std::fs::read_to_string(&jobs).unwrap();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let (out, dbs) = line.trim().split_once(' ').expect("out label=path ...");
        dump_one(out, dbs);
    }
}

fn dump_one(out_path: &str, dbs: &str) {

    // (round, author, digest) -> serialized SignedBlock
    let mut blocks: BTreeMap<(u32, u32, String), Vec<u8>> = BTreeMap::new();
    // index -> (digest, serialized Commit)
    let mut commits: BTreeMap<u32, (String, Vec<u8>)> = BTreeMap::new();
    let mut infos: BTreeMap<u32, (String, String)> = BTreeMap::new();
    let mut finals: BTreeMap<u32, (String, String)> = BTreeMap::new();
    let mut store_lines = Vec::new();
    let mut last_per_store = Vec::new();

    for spec in dbs.split_whitespace() {
        let (label, path) = spec.split_once('=').expect("label=path");
        let store = RocksDBStore::new(path);
        let (mut nb, mut nc, mut ni, mut nf) = (0usize, 0usize, 0usize, 0usize);
        for kv in store.blocks.safe_iter() {
            let ((round, author, digest), bytes) = kv.expect("blocks");
            nb += 1;
            let key = (round, author.value_u32(), dhex(&digest));
            match blocks.get(&key) {
                Some(prev) => assert_eq!(prev.as_slice(), bytes.as_ref(), "block {key:?} differs between stores"),
                None => {
                    blocks.insert(key, bytes.to_vec());
                }
            }
        }
        let mut last = 0u32;
        for kv in store.commits.safe_iter() {
            let ((index, digest), bytes) = kv.expect("commits");
            nc += 1;
            last = last.max(index);
            let d = dhex(&digest);
            match commits.get(&index) {
                Some((pd, pb)) => {
                    assert_eq!(pd, &d, "commit {index}: digest differs between stores");
                    assert_eq!(pb.as_slice(), bytes.as_ref(), "commit {index}: bytes differ");
                }
                None => {
                    commits.insert(index, (d, bytes.to_vec()));
                }
            }
        }
        last_per_store.push(last);
        for kv in store.commit_info.safe_iter() {
            let ((index, digest), info): ((u32, _), CommitInfo) = kv.expect("commit_info");
            ni += 1;
            let rounds = info.committed_rounds.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(",");
            let scores = info
                .reputation_scores
                .scores_per_authority
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let line = format!(
                "{rounds} {scores} {} {}",
                info.reputation_scores.commit_range.start(),
                info.reputation_scores.commit_range.end()
            );
            let d = dhex(&digest);
            match infos.get(&index) {
                Some((pd, pl)) => {
                    assert_eq!(pd, &d, "commit_info {index}: digest differs");
                    assert_eq!(pl, &line, "commit_info {index}: differs between stores");
                }
                None => {
                    infos.insert(index, (d, line));
                }
            }
        }
        for kv in store.finalized_commits.safe_iter() {
            let ((index, digest), m) = kv.expect("finalized_commits");
            nf += 1;
            let line = rejects_line(&m);
            let d = dhex(&digest);
            match finals.get(&index) {
                Some((pd, pl)) => {
                    assert_eq!(pd, &d, "finalized {index}: digest differs");
                    assert_eq!(pl, &line, "finalized {index}: rejected transactions differ between stores");
                }
                None => {
                    finals.insert(index, (d, line));
                }
            }
        }
        store_lines.push(format!("store {label} {nb} {nc} {ni} {nf}"));
    }

    // Commits are a gapless chain from 1 (all stores agree at every index they have).
    for (k, (i, _)) in commits.iter().enumerate() {
        assert_eq!(*i as usize, k + 1, "commit indices have a gap");
    }
    let common = last_per_store.iter().copied().min().unwrap_or(0);

    let mut f = std::io::BufWriter::new(std::fs::File::create(out_path).unwrap());
    for l in &store_lines {
        writeln!(f, "{l}").unwrap();
    }
    for ((round, author, digest), bytes) in &blocks {
        writeln!(f, "block {round} {author} {digest} {}", hex(bytes)).unwrap();
    }
    for (index, (digest, bytes)) in &commits {
        writeln!(f, "commit {index} {digest} {}", hex(bytes)).unwrap();
    }
    for (index, (digest, line)) in &infos {
        writeln!(f, "info {index} {digest} {line}").unwrap();
    }
    for (index, (digest, line)) in &finals {
        writeln!(f, "final {index} {digest} {line}").unwrap();
    }
    writeln!(f, "end {} {} {common}", blocks.len(), commits.len()).unwrap();
    f.flush().unwrap();
    eprintln!(
        "zui_consensus_dump: {} blocks, {} commits ({} common), {} info, {} finalized -> {out_path}",
        blocks.len(),
        commits.len(),
        common,
        infos.len(),
        finals.len()
    );
}
