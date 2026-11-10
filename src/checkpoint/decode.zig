//! The part of Rust's `CheckpointData` decode that the types module's `GenericSignature` does
//! not do yet (CONTRACTS.md 2.3 "still open"): every `GenericSignature` in an indexed blob (the
//! transactions' own and the ones pinned in the contents) goes through
//! `GenericSignature::from_bytes`, which is the sig lane's `sig.user.parse`. That covers the
//! zkLogin authenticator parse (header, iss claim, proof points), passkey client data, and the
//! legacy multisig's base64 keys and their point validity.
//!
//! When the types module's decode covers these, this file becomes redundant and goes away.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const sig = @import("sig");

/// Scratch for one zkLogin parse lives on the stack up to this size; a longer signature (never
/// seen on mainnet, where they are about 1 KB) takes a heap buffer for that one parse.
const stack_scratch = 16 << 10;

/// `sig_with_prefix`: one `GenericSignature` as it sits in the blob (length prefix included).
fn sigOk(sig_with_prefix: []const u8, scratch: []u8) bool {
    var r = bcs.Reader.init(sig_with_prefix);
    const n = r.length() catch return false;
    const b = r.bytes(n) catch return false;
    const need = sig.user.scratchLen(b.len);
    var buf = scratch;
    var heap: ?[]u8 = null;
    defer if (heap) |h| std.heap.page_allocator.free(h);
    if (need > scratch.len) {
        heap = std.heap.page_allocator.alloc(u8, need) catch return false;
        buf = heap.?;
    }
    var parsed: sig.user.Parsed = undefined;
    return sig.user.parse(b, &parsed, buf) == null;
}

/// True when every signature in the blob passes `GenericSignature::from_bytes`.
pub fn check(blob: []const u8, idx: *const types.CheckpointIndex) bool {
    var scratch: [stack_scratch]u8 = undefined;
    for (idx.sigs[0..idx.sig_total]) |rg| {
        if (!sigOk(rg.slice(blob), &scratch)) return false;
    }
    var r = bcs.Reader.init(idx.contents.slice(blob));
    const variant = r.uleb32() catch return false;
    const ntx = r.length() catch return false;
    if (variant == 0) {
        _ = r.bytes(std.math.mul(usize, ntx, 66) catch return false) catch return false;
        const nl = r.length() catch return false;
        for (0..nl) |_| {
            const n = r.length() catch return false;
            for (0..n) |_| {
                const s = r.at;
                const l = r.length() catch return false;
                _ = r.bytes(l) catch return false;
                if (!sigOk(r.buf[s..r.at], &scratch)) return false;
            }
        }
    } else {
        for (0..ntx) |_| {
            _ = r.bytes(66) catch return false;
            const n = r.length() catch return false;
            for (0..n) |_| {
                const s = r.at;
                const l = r.length() catch return false;
                _ = r.bytes(l) catch return false;
                if (!sigOk(r.buf[s..r.at], &scratch)) return false;
                switch (r.int(u8) catch return false) {
                    0 => {},
                    1 => _ = r.bytes(8) catch return false,
                    else => return false,
                }
            }
        }
    }
    return true;
}

test "every GenericSignature flag goes through from_bytes" {
    var scratch: [stack_scratch]u8 = undefined;
    // empty, an unknown flag, BLS (flag 4), a short Ed25519 signature
    try std.testing.expect(!sigOk(&.{0}, &scratch));
    try std.testing.expect(!sigOk(&.{ 1, 4 }, &scratch));
    try std.testing.expect(!sigOk(&.{ 2, 0, 1 }, &scratch));
    // a zkLogin flag with a body that is not a ZkLoginAuthenticator
    try std.testing.expect(!sigOk(&.{ 3, 5, 0, 0 }, &scratch));
    // a well-formed Ed25519 signature (flag, 64-byte signature, 32-byte key): from_bytes only
    // checks the length
    var ed: [1 + 97]u8 = @splat(0);
    ed[0] = 97;
    try std.testing.expect(sigOk(&ed, &scratch));
}
