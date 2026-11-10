//! Transaction classes by what executing them needs. Replay coverage is reported per class so
//! the share that still waits on move_vm / natives is visible in every run.
const types = @import("types");

pub const Class = enum(u8) {
    /// Programmable transaction whose commands are only SplitCoins, MergeCoins, TransferObjects
    /// (no MoveCall, MakeMoveVec, Publish, Upgrade): executes without the Move VM.
    ptb_coin_transfer,
    /// Programmable transaction with MakeMoveVec but no MoveCall/Publish/Upgrade.
    ptb_make_vec,
    /// Programmable transaction with at least one MoveCall.
    ptb_move_call,
    /// Programmable transaction that publishes or upgrades a package.
    ptb_publish,
    ccp,
    randomness,
    authenticator,
    end_of_epoch,
    change_epoch,
    genesis,
    programmable_system,

    pub fn needsVm(c: Class) bool {
        return c != .ptb_coin_transfer and c != .ccp;
    }
};

pub const n_classes = @typeInfo(Class).@"enum".field_names.len;

pub fn classify(kind: *const types.TransactionKind) Class {
    return switch (kind.*) {
        .ProgrammableTransaction => |pt| ptb(&pt),
        .ProgrammableSystemTransaction => .programmable_system,
        .ConsensusCommitPrologue, .ConsensusCommitPrologueV2, .ConsensusCommitPrologueV3, .ConsensusCommitPrologueV4 => .ccp,
        .RandomnessStateUpdate => .randomness,
        .AuthenticatorStateUpdate => .authenticator,
        .EndOfEpochTransaction => .end_of_epoch,
        .ChangeEpoch => .change_epoch,
        .Genesis => .genesis,
    };
}

fn ptb(pt: *const types.ProgrammableTransaction) Class {
    var c: Class = .ptb_coin_transfer;
    for (pt.commands) |cmd| switch (cmd) {
        .Publish, .Upgrade => return .ptb_publish,
        .MoveCall => c = .ptb_move_call,
        .MakeMoveVec => if (c == .ptb_coin_transfer) {
            c = .ptb_make_vec;
        },
        .TransferObjects, .SplitCoins, .MergeCoins => {},
    };
    return c;
}
