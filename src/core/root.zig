//! deepwave core: the few types and rules every lane shares. Owned by the reviewer; lanes do not
//! edit this directory. Anything Sui-shaped (addresses with BCS, digests with names, objects)
//! lives in the `types` module; core only holds what must exist below every lane.
//!
//! Conventions (ARCHITECTURE.md section 5, CONTRACTS.md section 2):
//!   - Zig errors mean "cannot proceed": malformed input, I/O failure, out of memory, a bug.
//!   - Protocol-visible outcomes (ExecutionFailureStatus, Move abort codes, VM status codes,
//!     verifier verdicts) are values, never Zig errors, because they are encoded into effects.
//!   - Every function that allocates takes an explicit `std.mem.Allocator`. No globals.
//!   - Borrowed views are named `*View`, owning values are not. A view never outlives its bytes.

const std = @import("std");

pub const alloc = @import("alloc.zig");
pub const hex = @import("hex.zig");
pub const testing = @import("testing.zig");
/// Runtime CPU dispatch (x86-64 kernel tiers; the one process-wide cache, set once).
pub const cpu = @import("cpu.zig");
/// Prometheus plumbing (histograms, label tables, text helpers) shared by every lane.
pub const prom = @import("prom.zig");
/// sui-node's p2p metric families as hooks the p2p transport calls (anemo requests, quinn peers).
pub const p2p_metrics = @import("p2p_metrics.zig");
/// Machine detection, profiles and path overrides.
pub const hw = @import("hw.zig");
/// The shared CPU worker pool (batch verification, GPU host prep).
pub const pool = @import("pool.zig");
/// Batch dispatch table (CPU single, CPU pool, GPU on k devices) and its cache.
pub const dispatch = @import("dispatch.zig");

/// 32 raw bytes: the shape of every Sui digest, address and object id. Typed wrappers
/// (ObjectDigest, SuiAddress, ...) live in `types` and convert to/from this for free.
pub const Bytes32 = [32]u8;

/// Errors shared by every decoder in deepwave. Lanes extend these with their own sets via `||`.
pub const DecodeError = error{
    /// Input ended before the value was complete.
    EndOfInput,
    /// Bytes were left over after a value that must consume its whole input.
    TrailingBytes,
    /// A ULEB128 was longer than allowed, overflowed, or was not minimally encoded.
    InvalidUleb,
    /// A bool byte other than 0 or 1.
    InvalidBool,
    /// An enum variant index with no matching variant.
    InvalidEnumTag,
    /// A string that is not valid UTF-8.
    InvalidUtf8,
    /// A length prefix larger than the format allows (BCS: 2^31 - 1) or than the input.
    LengthTooLarge,
    /// Recursion deeper than the format allows (BCS container depth 500).
    DepthExceeded,
    /// A value that decodes but is not in canonical form (e.g. unsorted map keys).
    NonCanonical,
};

/// The build mode name, for bench records.
pub const build_mode = @tagName(@import("builtin").mode);

test {
    std.testing.refAllDecls(@This());
}
