//! Suite `rpc-proof`: sui.rpc.v2alpha.ProofService/GetCheckpointObjectProof replayed against deepwave
//! over a real h2c socket and compared with sui-node 1.83.1's localnet captures
//! (`src/serve/vectors/rpc-surface/proof/cases.jsonl`, 48 cases; truth tools/truth/rpc-surface
//! prep_proof.py + cap_ledger.py proof).
//!
//! The replay is suite rpc-events' (conformance_rpcevents.zig `runFeatures`): each case runs on a
//! node holding localnet/chk up to the capture's tip (its `x-sui-checkpoint-height`), with the
//! ledger-history index published to that tip (the highest indexed checkpoint sui-node names in
//! "not yet indexed"); variant `noidx` drops the index (sui-node with indexing off answers
//! `RpcError::not_found()`). Byte-equal: http status, every response header but `date` and
//! `server-timing` (the x-sui-* tip headers equal the capture's because the node stands at its
//! tip), the message (summary BCS + inclusion/non-inclusion proof), grpc-status, grpc-message and
//! grpc-status-details-bin.
const harness = @import("harness");
const rpcevents = @import("conformance_rpcevents.zig");

const features = [_][]const u8{"proof"};

pub fn run(ctx: *harness.Ctx) !void {
    return rpcevents.runFeatures(ctx, "rpc-proof", &features);
}
