//! consensus_core::ancestor::AncestorStateManager and round_tracker (smart ancestor selection,
//! `consensus_smart_ancestor_selection` on mainnet 141): which peers' latest blocks to include
//! as ancestors, from propagation scores and accepted/received round reports.
//! Owner lane: val-consensus-core.
const types = @import("types.zig");
const Context = @import("context.zig").Context;

pub const AncestorState = enum { include, exclude };

pub const AncestorStateManager = struct {
    context: *const Context,

    pub fn updateAllAncestorsState(self: *AncestorStateManager) void {
        _ = self;
    }
    pub fn state(self: *const AncestorStateManager, who: types.AuthorityIndex) AncestorState {
        _ = .{ self, who };
        return .include;
    }
};

/// round_tracker::PeerRoundTracker: highest received/accepted rounds per authority reported by
/// peers (GetLatestRounds probes and block ancestors), for propagation delay.
pub const PeerRoundTracker = struct {
    context: *const Context,

    pub fn propagationDelay(self: *const PeerRoundTracker, last_proposed_round: types.Round) types.Round {
        _ = .{ self, last_proposed_round };
        return 0;
    }
};
