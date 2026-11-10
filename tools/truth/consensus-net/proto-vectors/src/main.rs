// Prints `name hex` for fixed ConsensusService messages encoded by prost, the encoder tonic uses
// in consensus-core at mainnet-v1.83.1. The Zig side (src/consensus/net/proto.zig, test
// "prost vectors") encodes the same inputs and compares. The input table must stay identical to
// the one in that test.
use prost::Message;

#[derive(Clone, prost::Message)]
pub struct SendBlockRequest {
    #[prost(bytes = "vec", tag = "1")]
    block: Vec<u8>,
}
#[derive(Clone, prost::Message)]
pub struct SubscribeBlocksRequest {
    #[prost(uint32, tag = "1")]
    last_received_round: u32,
}
#[derive(Clone, prost::Message)]
pub struct SubscribeBlocksResponse {
    #[prost(bytes = "vec", tag = "1")]
    block: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    excluded_ancestors: Vec<Vec<u8>>,
}
#[derive(Clone, prost::Message)]
pub struct FetchBlocksRequest {
    #[prost(bytes = "vec", repeated, tag = "1")]
    block_refs: Vec<Vec<u8>>,
    #[prost(uint32, repeated, tag = "2")]
    fetch_after_rounds: Vec<u32>,
    #[prost(bool, tag = "3")]
    fetch_missing_ancestors: bool,
}
#[derive(Clone, prost::Message)]
pub struct FetchBlocksResponse {
    #[prost(bytes = "vec", repeated, tag = "1")]
    blocks: Vec<Vec<u8>>,
}
#[derive(Clone, prost::Message)]
pub struct FetchCommitsRequest {
    #[prost(uint32, tag = "1")]
    start: u32,
    #[prost(uint32, tag = "2")]
    end: u32,
}
#[derive(Clone, prost::Message)]
pub struct FetchCommitsResponse {
    #[prost(bytes = "vec", repeated, tag = "1")]
    commits: Vec<Vec<u8>>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    certifier_blocks: Vec<Vec<u8>>,
}
#[derive(Clone, prost::Message)]
pub struct FetchLatestBlocksRequest {
    #[prost(uint32, repeated, tag = "1")]
    authorities: Vec<u32>,
}
#[derive(Clone, prost::Message)]
pub struct GetLatestRoundsResponse {
    #[prost(uint32, repeated, tag = "1")]
    highest_received: Vec<u32>,
    #[prost(uint32, repeated, tag = "2")]
    highest_accepted: Vec<u32>,
}

fn show(name: &str, m: &impl Message) {
    println!("{name} {}", hex::encode(m.encode_to_vec()));
}

fn main() {
    show("send_block", &SendBlockRequest { block: vec![1, 2, 3] });
    show("send_block_empty", &SendBlockRequest { block: vec![] });
    show("subscribe_0", &SubscribeBlocksRequest { last_received_round: 0 });
    show("subscribe_300", &SubscribeBlocksRequest { last_received_round: 300 });
    show("subscribe_resp", &SubscribeBlocksResponse { block: vec![9; 5], excluded_ancestors: vec![vec![7; 3], vec![]] });
    show("fetch_blocks_req", &FetchBlocksRequest { block_refs: vec![vec![1; 4], vec![2; 2]], fetch_after_rounds: vec![0, 5, 200000, 7], fetch_missing_ancestors: true });
    show("fetch_blocks_req_empty", &FetchBlocksRequest { block_refs: vec![], fetch_after_rounds: vec![], fetch_missing_ancestors: false });
    show("fetch_blocks_resp", &FetchBlocksResponse { blocks: vec![vec![5; 2], vec![], vec![6; 1]] });
    show("fetch_commits_req", &FetchCommitsRequest { start: 1, end: 300 });
    show("fetch_commits_resp", &FetchCommitsResponse { commits: vec![vec![1; 3]], certifier_blocks: vec![vec![2; 2], vec![3; 2]] });
    show("fetch_latest_req", &FetchLatestBlocksRequest { authorities: vec![0, 1, 130, 7] });
    show("latest_rounds_resp", &GetLatestRoundsResponse { highest_received: vec![1, 2, 3], highest_accepted: vec![0, 0, 9] });
}
