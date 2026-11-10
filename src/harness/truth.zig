//! Checkpoint truth files (`truth/checkpoint/<seq>.jsonl.zst`, docs/CONFORMANCE.md).
//!
//! `zui-dumper truth` writes every object line in one fixed shape:
//!
//!     {"k":"<kind>","p":"<path>","o":<offset>,"n":<length>[,"d":"<hex>"][,"sd":"<hex>"][,"t":<tree>]}
//!
//! `parseLine` reads that shape without a JSON parser and returns slices into the line, so the
//! tree text `t` is exactly the bytes Rust wrote (suites compare it byte for byte). Any other
//! shape is an error, which makes a dumper format change fail loudly instead of silently.
const std = @import("std");

pub const ParseError = error{MalformedTruthLine};

pub const Line = struct {
    /// Rust type at this range, e.g. "TransactionEffects".
    k: []const u8,
    /// Path, e.g. "tx[3].effects".
    p: []const u8,
    /// Byte range in the blob (tag byte included): raw[o..o+n].
    o: u64,
    n: u64,
    /// Lowercase hex digest, when the type has one.
    d: ?[]const u8 = null,
    /// Lowercase hex Blake2b256 of the signed message, for TransactionData and CheckpointSummary.
    sd: ?[]const u8 = null,
    /// Canonical tree text (compact JSON), absent for envelope kinds.
    t: ?[]const u8 = null,

    /// The value's exact BCS bytes in `blob`, or error when the range is outside it.
    pub fn raw(l: Line, blob: []const u8) ParseError![]const u8 {
        if (l.o > blob.len or l.n > blob.len - l.o) return error.MalformedTruthLine;
        return blob[@intCast(l.o)..][0..@intCast(l.n)];
    }
};

/// Header line fields (line 1 of every truth file; the manifest line adds "cov").
pub const Header = struct {
    k: []const u8,
    seq: u64,
    epoch: u64,
    len: u64,
    txs: u64,
    eoe: bool,
    next_pv: ?u64 = null,
    ts: u64,
    kinds: []const []const u8,
    /// Signature scheme names per transaction (ED25519, Secp256k1, Secp256r1, MultiSig,
    /// MultiSigLegacy, ZkLoginAuthenticator, PasskeyAuthenticator, ...).
    sigs: []const []const []const u8 = &.{},
    /// Indices of transactions whose effects status is Failure.
    fail: []const u64 = &.{},
    /// Largest object (input or output) BCS length.
    big: u64 = 0,
};

/// Parses line 1 of a truth file. Strings borrow from `line` or `arena`.
pub fn parseHeader(arena: std.mem.Allocator, line: []const u8) !Header {
    const h = try std.json.parseFromSliceLeaky(Header, arena, line, .{ .ignore_unknown_fields = true });
    if (!std.mem.eql(u8, h.k, "Header")) return error.MalformedTruthLine;
    return h;
}

pub fn parseLine(line: []const u8) ParseError!Line {
    var s: Scanner = .{ .b = line };
    var l: Line = undefined;
    try s.lit("{\"k\":\"");
    l.k = try s.until('"');
    try s.lit(",\"p\":\"");
    l.p = try s.until('"');
    try s.lit(",\"o\":");
    l.o = try s.num();
    try s.lit(",\"n\":");
    l.n = try s.num();
    l.d = null;
    l.sd = null;
    l.t = null;
    if (s.opt(",\"d\":\"")) l.d = try s.hex();
    if (s.opt(",\"sd\":\"")) l.sd = try s.hex();
    if (s.opt(",\"t\":")) {
        if (line.len < s.i + 2 or line[line.len - 1] != '}') return error.MalformedTruthLine;
        l.t = line[s.i .. line.len - 1];
        s.i = line.len - 1;
    }
    try s.lit("}");
    if (s.i != line.len) return error.MalformedTruthLine;
    return l;
}

const Scanner = struct {
    b: []const u8,
    i: usize = 0,

    fn lit(s: *Scanner, comptime x: []const u8) ParseError!void {
        if (!s.opt(x)) return error.MalformedTruthLine;
    }
    fn opt(s: *Scanner, comptime x: []const u8) bool {
        if (!std.mem.startsWith(u8, s.b[s.i..], x)) return false;
        s.i += x.len;
        return true;
    }
    /// A string with no escapes (kinds and paths never contain '"' or '\\').
    fn until(s: *Scanner, c: u8) ParseError![]const u8 {
        const start = s.i;
        while (s.i < s.b.len and s.b[s.i] != c) : (s.i += 1) {
            if (s.b[s.i] == '\\') return error.MalformedTruthLine;
        }
        if (s.i == s.b.len) return error.MalformedTruthLine;
        defer s.i += 1;
        return s.b[start..s.i];
    }
    fn num(s: *Scanner) ParseError!u64 {
        const start = s.i;
        while (s.i < s.b.len and std.ascii.isDigit(s.b[s.i])) s.i += 1;
        return std.fmt.parseInt(u64, s.b[start..s.i], 10) catch error.MalformedTruthLine;
    }
    fn hex(s: *Scanner) ParseError![]const u8 {
        const h = try s.until('"');
        for (h) |c| if (!std.ascii.isDigit(c) and !(c >= 'a' and c <= 'f')) return error.MalformedTruthLine;
        if (h.len == 0 or h.len % 2 != 0) return error.MalformedTruthLine;
        return h;
    }
};

/// Decodes a lowercase hex digest from the truth into bytes.
pub fn digestBytes(comptime n: usize, hex_text: []const u8) ParseError![n]u8 {
    var out: [n]u8 = undefined;
    if (hex_text.len != 2 * n) return error.MalformedTruthLine;
    _ = std.fmt.hexToBytes(&out, hex_text) catch return error.MalformedTruthLine;
    return out;
}

/// Every line kind the dumper writes, in docs/CONFORMANCE.md order.
pub const kinds = [_][]const u8{
    "CheckpointSummary",    "AuthorityStrongQuorumSignInfo", "CertifiedCheckpointSummary", "CheckpointContents",
    "TransactionData",      "GenericSignature",              "MultiSig",                   "MultiSigLegacy",
    "ZkLoginAuthenticator", "PasskeyAuthenticator",          "Transaction",                "TransactionEffects",
    "TransactionEvents",    "Object",
};

pub fn isKind(k: []const u8) bool {
    for (kinds) |x| if (std.mem.eql(u8, x, k)) return true;
    return false;
}

test "parse full line" {
    const l = try parseLine("{\"k\":\"TransactionData\",\"p\":\"tx[0].data\",\"o\":12,\"n\":3,\"d\":\"ab01\",\"sd\":\"ff00\",\"t\":{\"V1\":{\"a\":[1,\"}\"]}}}");
    try std.testing.expectEqualStrings("TransactionData", l.k);
    try std.testing.expectEqualStrings("tx[0].data", l.p);
    try std.testing.expectEqual(@as(u64, 12), l.o);
    try std.testing.expectEqual(@as(u64, 3), l.n);
    try std.testing.expectEqualStrings("ab01", l.d.?);
    try std.testing.expectEqualStrings("ff00", l.sd.?);
    try std.testing.expectEqualStrings("{\"V1\":{\"a\":[1,\"}\"]}}", l.t.?);
    try std.testing.expectEqualStrings("cde", try l.raw("0123456789abcdef"[0..]));
}

test "parse envelope line and reject bad shapes" {
    const l = try parseLine("{\"k\":\"Transaction\",\"p\":\"tx[1].transaction\",\"o\":5,\"n\":100}");
    try std.testing.expect(l.t == null and l.d == null);
    try std.testing.expectError(error.MalformedTruthLine, parseLine("{\"k\":\"X\",\"p\":\"y\",\"o\":5}"));
    try std.testing.expectError(error.MalformedTruthLine, parseLine("{\"k\":\"X\",\"p\":\"y\",\"o\":5,\"n\":1,\"d\":\"AB\"}"));
    try std.testing.expectError(error.MalformedTruthLine, parseLine("{\"k\":\"X\",\"p\":\"y\",\"o\":5,\"n\":1} "));
    try std.testing.expectError(error.MalformedTruthLine, (Line{ .k = "", .p = "", .o = 3, .n = 9 }).raw("abcd"));
}

test "header" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const h = try parseHeader(arena.allocator(), "{\"k\":\"Header\",\"seq\":9769,\"epoch\":0,\"len\":264202,\"txs\":2,\"eoe\":true,\"next_pv\":4,\"ts\":1681405202097,\"kinds\":[\"ConsensusCommitPrologue\",\"ChangeEpoch\"],\"sigs\":[[\"ED25519\"],[\"ED25519\"]],\"fail\":[],\"big\":93641,\"cov\":[\"x\"]}");
    try std.testing.expectEqual(@as(u64, 9769), h.seq);
    try std.testing.expectEqual(@as(?u64, 4), h.next_pv);
    try std.testing.expectEqualStrings("ChangeEpoch", h.kinds[1]);
    try std.testing.expectEqualStrings("ED25519", h.sigs[1][0]);
    const d = try digestBytes(2, "ab01");
    try std.testing.expectEqualSlices(u8, &.{ 0xab, 0x01 }, &d);
}
