//! NameService (SuiNS) as sui-rpc-api 1.83.1 `grpc/v2/name_service.rs` and sui-name-service answer it:
//! domain parsing with `Domain::from_str`'s exact error texts, the registry record and reverse-record
//! dynamic-field ids, expiry against the latest checkpoint's timestamp (RESOURCE_EXHAUSTED
//! `name has expired`, which is what sui-node's ReverseLookupName RESOURCE_EXHAUSTED answers are:
//! expired names, not rate limiting), leaf records checked against their parent.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const hash = @import("hash");
const store = @import("store");
const proto = @import("proto.zig");
const sysstate = @import("sysstate.zig");

pub const Config = struct {
    package: [32]u8,
    registry: [32]u8,
    reverse_registry: [32]u8,

    pub const mainnet: Config = .{
        .package = hex32("d22b24490e0bae52676651b4f56660a5ff8022a2576e0089f79b3c88d44e08f0"),
        .registry = hex32("e64cd9db9f829c6cc405d9790bd71567ae07259855f4fba6f02c84f52298c106"),
        .reverse_registry = hex32("2fd099e17a292d2bc541df474f9fafa595653848cbabb2d7a4656ec786a1969f"),
    };
    pub const testnet: Config = .{
        .package = hex32("22fa05f21b1ad71442491220bb9338f7b7095fe35000ef88d5400d28523bdd93"),
        .registry = hex32("b120c0d55432630fce61f7854795a3463deb6e3b443cc4ae72e1282073ff56e4"),
        .reverse_registry = hex32("cee9dbb070db70936c3a374439a6adb16f3ba97eac5468d2e1e6fff6ed93e465"),
    };

    /// `record_field_id`: dfid(registry, Struct(pkg::domain::Domain), bcs(Domain { labels })).
    pub fn recordId(c: *const Config, labels: []const []const u8) [32]u8 {
        var key_buf: [16 * 1024]u8 = undefined;
        var n: usize = 0;
        n += uleb(key_buf[n..], labels.len);
        for (labels) |l| {
            n += uleb(key_buf[n..], l.len);
            @memcpy(key_buf[n..][0..l.len], l);
            n += l.len;
        }
        var tag: [1 + 32 + 1 + 6 + 1 + 6 + 1]u8 = undefined;
        tag[0] = 7;
        @memcpy(tag[1..33], &c.package);
        tag[33] = 6;
        @memcpy(tag[34..40], "domain");
        tag[40] = 6;
        @memcpy(tag[41..47], "Domain");
        tag[47] = 0;
        return dfid(&c.registry, key_buf[0..n], &tag);
    }

    /// `reverse_record_field_id`: dfid(reverse_registry, TypeTag::Address, address).
    pub fn reverseId(c: *const Config, address: *const [32]u8) [32]u8 {
        return dfid(&c.reverse_registry, address, &[_]u8{4});
    }
};

fn hex32(comptime s: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn uleb(out: []u8, v: usize) usize {
    var x = v;
    var i: usize = 0;
    while (x >= 0x80) : (x >>= 7) {
        out[i] = @as(u8, @truncate(x)) | 0x80;
        i += 1;
    }
    out[i] = @truncate(x);
    return i + 1;
}

fn dfid(parent: *const [32]u8, key: []const u8, type_tag: []const u8) [32]u8 {
    var klen: [8]u8 = undefined;
    std.mem.writeInt(u64, &klen, key.len, .little);
    return hash.blake2b256(&.{ &[_]u8{0xf0}, parent, &klen, key, type_tag });
}

// ---------------------------------------------------------------- Domain

pub const max_domain_length = 200;

/// `Domain { labels }`: labels in storage order (TLD first).
pub const Domain = struct {
    labels: []const []const u8,

    /// `Domain` Display (`DomainFormat::Dot`): labels from the leaf, joined by '.'.
    pub fn format(d: Domain, arena: Allocator) ![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        var i = d.labels.len;
        while (i > 0) {
            i -= 1;
            try out.appendSlice(arena, d.labels[i]);
            if (i > 0) try out.append(arena, '.');
        }
        return out.items;
    }

    pub fn parent(d: Domain) Domain {
        return .{ .labels = d.labels[0 .. d.labels.len - 1] };
    }
};

/// `Domain::from_str`. On error, `msg` is the NameServiceError Display.
pub fn parseDomain(arena: Allocator, s: []const u8, msg: *[]const u8) !?Domain {
    if (s.len > max_domain_length) {
        msg.* = try std.fmt.allocPrint(arena, "Name Service: String length: {d} exceeds maximum allowed length: {d}", .{ s.len, max_domain_length });
        return null;
    }
    const invalid_sep = "Name Service: Domain must include only one separator";
    // separator(): '.' and '*'; both present is an error; default '.'
    const has_dot = std.mem.indexOfScalar(u8, s, '.') != null;
    const has_star = std.mem.indexOfScalar(u8, s, '*') != null;
    if (has_dot and has_star) {
        msg.* = invalid_sep;
        return null;
    }
    const sep: u8 = if (has_star) '*' else '.';
    // convert_from_new_format
    var formatted: []const u8 = s;
    if (std.mem.indexOfScalar(u8, s, '@')) |at| {
        const before = s[0..at];
        const after = s[at + 1 ..];
        if (std.mem.indexOfScalar(u8, after, '@') != null or std.mem.indexOfScalar(u8, after, sep) != null or after.len == 0) {
            msg.* = invalid_sep;
            return null;
        }
        var buf: std.ArrayList(u8) = .empty;
        if (before.len != 0) {
            try buf.appendSlice(arena, before);
            try buf.append(arena, sep);
        }
        try buf.appendSlice(arena, after);
        try buf.append(arena, sep);
        try buf.appendSlice(arena, "sui");
        formatted = buf.items;
    }
    // labels = split(sep).rev().map(validate_label)
    var parts: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, formatted, sep);
    while (it.next()) |p| try parts.append(arena, p);
    std.mem.reverse([]const u8, parts.items);
    for (parts.items) |l| {
        if (try validateLabel(arena, l)) |e| {
            msg.* = e;
            return null;
        }
    }
    if (parts.items.len < 2) {
        msg.* = "Name Service: Domain must contain at least one label";
        return null;
    }
    return .{ .labels = parts.items };
}

fn validateLabel(arena: Allocator, label: []const u8) !?[]const u8 {
    if (label.len < 1 or label.len > 63)
        return try std.fmt.allocPrint(arena, "Name Service: String length: {d} outside of valid range: [1, 63]", .{label.len});
    for (label, 0..) |ch, i| {
        const ok = switch (ch) {
            'a'...'z', '0'...'9' => true,
            '-' => i != 0 and i != label.len - 1,
            else => false,
        };
        if (!ok) return if (ch == '-')
            "Name Service: Hyphens are not allowed as the first or last character"
        else
            "Name Service: Only lowercase letters, numbers, and hyphens are allowed";
    }
    return null;
}

// ---------------------------------------------------------------- records

pub const NameRecord = struct {
    nft_id: *const [32]u8,
    expiration_timestamp_ms: u64,
    target_address: ?*const [32]u8,
    /// VecMap entries in order.
    data: []const [2][]const u8,

    pub fn isLeaf(r: *const NameRecord) bool {
        return r.expiration_timestamp_ms == 0;
    }
    pub fn isExpired(r: *const NameRecord, now_ms: u64) bool {
        return r.expiration_timestamp_ms < now_ms;
    }
};

fn readStr(r: *bcs.Reader) ![]const u8 {
    const n = try r.length();
    const s = try r.bytes(n);
    if (!std.unicode.utf8ValidateSlice(s)) return error.InvalidUtf8;
    return s;
}

fn readDomain(arena: Allocator, r: *bcs.Reader) ![]const []const u8 {
    const n = try r.length();
    if (n > r.remaining()) return error.EndOfInput;
    const labels = try arena.alloc([]const u8, n);
    for (labels) |*l| l.* = try readStr(r);
    return labels;
}

/// `Object::to_rust::<Field<Domain, NameRecord>>()`: the whole contents must decode.
pub fn decodeRecord(arena: Allocator, object_bytes: []const u8) ?NameRecord {
    const c = sysstate.moveContents(object_bytes) orelse return null;
    var r = bcs.Reader.init(c);
    return decodeRecordInner(arena, &r) catch null;
}

fn decodeRecordInner(arena: Allocator, r: *bcs.Reader) !NameRecord {
    _ = try r.bytes(32); // UID
    _ = try readDomain(arena, r);
    var out: NameRecord = undefined;
    out.nft_id = (try r.bytes(32))[0..32];
    out.expiration_timestamp_ms = try r.int(u64);
    out.target_address = switch (try r.int(u8)) {
        0 => null,
        1 => (try r.bytes(32))[0..32],
        else => return error.InvalidEnumTag,
    };
    const n = try r.length();
    if (n > r.remaining()) return error.EndOfInput;
    const data = try arena.alloc([2][]const u8, n);
    for (data) |*e| e.* = .{ try readStr(r), try readStr(r) };
    out.data = data;
    try r.finish();
    return out;
}

/// `Object::to_rust::<Field<Address, Domain>>()` labels.
pub fn decodeReverse(arena: Allocator, object_bytes: []const u8) ?[]const []const u8 {
    const c = sysstate.moveContents(object_bytes) orelse return null;
    var r = bcs.Reader.init(c);
    _ = r.bytes(64) catch return null; // UID, address
    const labels = readDomain(arena, &r) catch return null;
    r.finish() catch return null;
    return labels;
}

// ---------------------------------------------------------------- service

pub const Outcome = union(enum) {
    ok: []const u8,
    /// INVALID_ARGUMENT with a BadRequest on `field` (description may be empty).
    bad_field: struct { field: []const u8, description: []const u8, missing: bool },
    not_found_bare,
    internal: []const u8,
    expired,
};

/// Timestamp of the latest committed checkpoint.
pub fn latestTimestamp(snap: *const store.Snapshot) ?u64 {
    const hi = snap.highestCommitted() orelse return null;
    const rec = snap.checkpoint(hi) orelse return null;
    return summaryTimestamp(rec.summary_cert) catch null;
}

pub fn summaryTimestamp(summary: []const u8) !u64 {
    const types = @import("types");
    var r = bcs.Reader.init(summary);
    _ = try r.bytes(24);
    try bcs.skip(types.CheckpointContentsDigest, &r);
    try bcs.skip(?types.CheckpointDigest, &r);
    try bcs.skip(types.GasCostSummary, &r);
    return r.int(u64);
}

fn writeTimestamp(w: *proto.Writer, field: u32, ms: u64) proto.Error!void {
    const m = try w.begin(field, 12);
    if (ms / 1000 != 0) try w.uint(1, ms / 1000);
    if (ms % 1000 != 0) try w.uint(2, (ms % 1000) * 1_000_000);
    try w.end(m);
}

const Found = struct { record_id: [32]u8, name: []const u8, rec: NameRecord };

fn lookup(arena: Allocator, snap: *const store.Snapshot, cfg: *const Config, name: []const u8, out: *Outcome) !?Found {
    var msg: []const u8 = "";
    const domain = (try parseDomain(arena, name, &msg)) orelse {
        out.* = .{ .bad_field = .{ .field = "name", .description = try std.fmt.allocPrint(arena, "invalid domain: {s}", .{msg}), .missing = false } };
        return null;
    };
    const rid = cfg.recordId(domain.labels);
    const now = latestTimestamp(snap) orelse {
        out.* = .{ .internal = "no checkpoint" };
        return null;
    };
    const obj = snap.liveObject(&rid) orelse {
        out.* = .not_found_bare;
        return null;
    };
    const rec = decodeRecord(arena, obj.bytes) orelse {
        var b: [66]u8 = undefined;
        out.* = .{ .internal = try std.fmt.allocPrint(arena, "Name Service: Malformed object for {s}", .{sysstate.hexAddr(&b, &rid)}) };
        return null;
    };
    var valid: bool = undefined;
    if (!rec.isLeaf()) {
        valid = !rec.isExpired(now);
    } else {
        const parent = domain.parent();
        const pid = cfg.recordId(parent.labels);
        if (snap.liveObject(&pid)) |pobj| {
            const prec = decodeRecord(arena, pobj.bytes) orelse {
                var b: [66]u8 = undefined;
                out.* = .{ .internal = try std.fmt.allocPrint(arena, "Name Service: Malformed object for {s}", .{sysstate.hexAddr(&b, &pid)}) };
                return null;
            };
            valid = std.mem.eql(u8, prec.nft_id, rec.nft_id) and !prec.isExpired(now);
        } else valid = false;
    }
    if (!valid) {
        out.* = .expired;
        return null;
    }
    return .{ .record_id = rid, .name = try domain.format(arena), .rec = rec };
}

const DataEntry = [2][]const u8;

fn writeRecord(arena: Allocator, w: *proto.Writer, f: *const Found) !void {
    var b: [66]u8 = undefined;
    try w.string(1, sysstate.hexAddr(&b, &f.record_id));
    try w.string(2, f.name);
    try w.string(3, sysstate.hexAddr(&b, f.rec.nft_id));
    try writeTimestamp(w, 4, f.rec.expiration_timestamp_ms);
    if (f.rec.target_address) |t| try w.string(5, sysstate.hexAddr(&b, t));
    // VecMap into a BTreeMap<String, String>: sorted, a later duplicate key wins
    const sorted = try arena.dupe(DataEntry, f.rec.data);
    std.sort.block(DataEntry, sorted, {}, struct {
        fn lt(_: void, a: DataEntry, c: DataEntry) bool {
            return std.mem.lessThan(u8, a[0], c[0]);
        }
    }.lt);
    for (sorted, 0..) |e, i| {
        if (i + 1 < sorted.len and std.mem.eql(u8, sorted[i + 1][0], e[0])) continue;
        const m = try w.begin(6, e[0].len + e[1].len + 4);
        if (e[0].len != 0) try w.string(1, e[0]);
        if (e[1].len != 0) try w.string(2, e[1]);
        try w.end(m);
    }
}

fn respondRecord(arena: Allocator, f: *const Found) ![]const u8 {
    var cap: usize = 1024;
    for (f.rec.data) |e| cap += e[0].len + e[1].len + 8;
    while (true) : (cap *= 2) {
        const buf = try arena.alloc(u8, cap);
        var w = proto.Writer.init(buf);
        const m = w.begin(1, cap) catch continue;
        writeRecord(arena, &w, f) catch |e| switch (e) {
            error.NoSpace => continue,
            else => return e,
        };
        w.end(m) catch continue;
        return w.bytesWritten();
    }
}

/// LookupNameRequest { name = 1 } (null when absent).
pub fn lookupName(arena: Allocator, snap: *const store.Snapshot, cfg: *const Config, name: ?[]const u8) !Outcome {
    const n = name orelse return .{ .bad_field = .{ .field = "name", .description = "", .missing = true } };
    var out: Outcome = undefined;
    const f = (try lookup(arena, snap, cfg, n, &out)) orelse return out;
    return .{ .ok = try respondRecord(arena, &f) };
}

/// ReverseLookupNameRequest { address = 1 }; `parsed` is `Address::from_str` of it (null: invalid).
pub fn reverseLookupName(arena: Allocator, snap: *const store.Snapshot, cfg: *const Config, address_text: ?[]const u8, parsed: ?[32]u8) !Outcome {
    _ = address_text orelse return .{ .bad_field = .{ .field = "address", .description = "", .missing = true } };
    const addr = parsed orelse return .{ .bad_field = .{ .field = "address", .description = "invalid address: Unable to parse Address (must be hex string of length 32)", .missing = false } };
    const rid = cfg.reverseId(&addr);
    const obj = snap.liveObject(&rid) orelse return .not_found_bare;
    const labels = decodeReverse(arena, obj.bytes) orelse {
        var b: [66]u8 = undefined;
        return .{ .internal = try std.fmt.allocPrint(arena, "Malformed Object {s}", .{sysstate.hexAddr(&b, &rid)}) };
    };
    const name = try (Domain{ .labels = labels }).format(arena);
    var out: Outcome = undefined;
    const f = (try lookup(arena, snap, cfg, name, &out)) orelse return out;
    const t = f.rec.target_address orelse return .not_found_bare;
    if (!std.mem.eql(u8, t, &addr)) return .not_found_bare;
    return .{ .ok = try respondRecord(arena, &f) };
}

test "domain parsing" {
    var ar = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    var msg: []const u8 = "";
    const d = (try parseDomain(a, "@test", &msg)).?;
    try std.testing.expectEqualStrings("test.sui", try d.format(a));
    const d2 = (try parseDomain(a, "abc@test", &msg)).?;
    try std.testing.expectEqualStrings("abc.test.sui", try d2.format(a));
    const d3 = (try parseDomain(a, "a*b*sui", &msg)).?;
    try std.testing.expectEqualStrings("a.b.sui", try d3.format(a));
    try std.testing.expect((try parseDomain(a, "sui", &msg)) == null);
    try std.testing.expectEqualStrings("Name Service: Domain must contain at least one label", msg);
    try std.testing.expect((try parseDomain(a, "a.b*c", &msg)) == null);
    try std.testing.expectEqualStrings("Name Service: Domain must include only one separator", msg);
    try std.testing.expect((try parseDomain(a, "-x.sui", &msg)) == null);
    try std.testing.expectEqualStrings("Name Service: Hyphens are not allowed as the first or last character", msg);
    try std.testing.expect((try parseDomain(a, "", &msg)) == null);
    try std.testing.expectEqualStrings("Name Service: String length: 0 outside of valid range: [1, 63]", msg);
}
