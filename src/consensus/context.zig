//! consensus_core::context::Context: the immutable per-epoch settings every core component
//! reads. Owner lane: val-consensus-core.
const committee_mod = @import("committee.zig");
const config = @import("config.zig");
const iface = @import("iface.zig");
const types = @import("types.zig");

pub const Context = struct {
    /// Wall time of the epoch start, used for genesis block timestamps.
    epoch_start_timestamp_ms: u64,
    /// This authority's index in the committee (or null for an observer / shadow).
    own_index: ?types.AuthorityIndex,
    committee: committee_mod.Committee,
    parameters: config.Parameters,
    protocol_config: config.ProtocolConfig,
    clock: iface.Clock,
    tracer: iface.Tracer = .{},
};
