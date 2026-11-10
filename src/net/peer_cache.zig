//! sui-node's discovery peer cache, `<db-path>/discovery_peer_cache.yaml` (sui-network
//! discovery/store.rs, mainnet-v1.83.1): the signed `VersionedNodeInfo` of trusted peers (seeds
//! with an id, `allowlisted-peers`), written with serde_yaml 0.8 whenever one changes and at
//! shutdown, read back at startup so a restart knows where its trusted peers moved to. A file
//! that does not parse is ignored with a warning (sui-node: `load_stored_peers` returns nothing).
//!
//! The text is what serde_yaml 0.8 (yaml-rust 0.4 emitter) writes for
//! `Vec<Envelope<VersionedNodeInfo, Ed25519Signature>>`: PeerId as hex, Multiaddr as its string,
//! signatures and consensus keys in Base64, enums externally tagged, the `BTreeMap<EndpointId, _>`
//! keys as complex (`? P2p: <hex>`) keys:
//!
//!     ---
//!     - data:
//!         V2:
//!           addresses:
//!             ? P2p: 5f1c...
//!             : - /dns/peer.example/udp/8084
//!           timestamp_ms: 1762650000000
//!           access_type: Public
//!       auth_signature: 3q2+7w...==
//!
//! Entries are kept as the envelope bytes (BCS data ++ 64-byte signature); reading rebuilds the
//! BCS from the text and the caller verifies the signature, so an entry this reader gets wrong is
//! dropped, never trusted.
const std = @import("std");
const Allocator = std.mem.Allocator;
const b64 = std.base64.standard;

pub const Error = error{ Malformed, OutOfMemory };

// ------------------------------------------------------------------ BCS view of one envelope

const Endpoint = struct { kind: u8, key: [32]u8, addrs: []const []const u8 };

const Info = struct {
    version: u8, // 0: V1(NodeInfo), 1: V2(NodeInfoV2)
    peer_id: [32]u8 = @splat(0), // V1 only
    addrs: []const []const u8 = &.{}, // V1 only
    endpoints: []const Endpoint = &.{}, // V2 only
    ts: u64 = 0,
    access: u8 = 0,
    sig: [64]u8 = @splat(0),
};

const Cur = struct {
    b: []const u8,
    p: usize = 0,
    fn take(c: *Cur, n: usize) Error![]const u8 {
        if (n > c.b.len - c.p) return error.Malformed;
        defer c.p += n;
        return c.b[c.p..][0..n];
    }
    fn uleb(c: *Cur) Error!u64 {
        var v: u64 = 0;
        var shift: u6 = 0;
        while (true) {
            const b = (try c.take(1))[0];
            v |= @as(u64, b & 0x7f) << shift;
            if (b & 0x80 == 0) return v;
            if (shift >= 56) return error.Malformed;
            shift += 7;
        }
    }
    fn addrs(c: *Cur, a: Allocator) Error![]const []const u8 {
        const n = try c.uleb();
        if (n > 64) return error.Malformed;
        const out = try a.alloc([]const u8, @intCast(n));
        for (out) |*s| s.* = try c.take(@intCast(try c.uleb()));
        return out;
    }
};

fn parseEnvelope(a: Allocator, env: []const u8) Error!Info {
    var c: Cur = .{ .b = env };
    var info: Info = .{ .version = @intCast(@min(try c.uleb(), 255)) };
    switch (info.version) {
        0 => {
            info.peer_id = (try c.take(32))[0..32].*;
            info.addrs = try c.addrs(a);
        },
        1 => {
            const n = try c.uleb();
            if (n > 8) return error.Malformed;
            const eps = try a.alloc(Endpoint, @intCast(n));
            for (eps) |*e| {
                const k = try c.uleb();
                if (k > 1) return error.Malformed;
                e.* = .{ .kind = @intCast(k), .key = (try c.take(32))[0..32].*, .addrs = try c.addrs(a) };
            }
            info.endpoints = eps;
        },
        else => return error.Malformed,
    }
    info.ts = std.mem.readInt(u64, (try c.take(8))[0..8], .little);
    info.access = (try c.take(1))[0];
    if (info.access > 2) return error.Malformed;
    info.sig = (try c.take(64))[0..64].*;
    if (c.p != env.len) return error.Malformed;
    return info;
}

fn putUleb(out: *std.ArrayList(u8), a: Allocator, v: u64) Error!void {
    var x = v;
    while (true) {
        const b: u8 = @intCast(x & 0x7f);
        x >>= 7;
        if (x == 0) return out.append(a, b);
        try out.append(a, b | 0x80);
    }
}

fn putAddrs(out: *std.ArrayList(u8), a: Allocator, addrs: []const []const u8) Error!void {
    try putUleb(out, a, addrs.len);
    for (addrs) |s| {
        try putUleb(out, a, s.len);
        try out.appendSlice(a, s);
    }
}

fn encodeEnvelope(a: Allocator, info: *const Info) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try putUleb(&out, a, info.version);
    if (info.version == 0) {
        try out.appendSlice(a, &info.peer_id);
        try putAddrs(&out, a, info.addrs);
    } else {
        // BTreeMap<EndpointId, _>: P2p before Consensus (variant order), then by key bytes.
        const eps = try a.dupe(Endpoint, info.endpoints);
        std.mem.sort(Endpoint, eps, {}, struct {
            fn lt(_: void, x: Endpoint, y: Endpoint) bool {
                if (x.kind != y.kind) return x.kind < y.kind;
                return std.mem.order(u8, &x.key, &y.key) == .lt;
            }
        }.lt);
        try putUleb(&out, a, eps.len);
        for (eps) |e| {
            try putUleb(&out, a, e.kind);
            try out.appendSlice(a, &e.key);
            try putAddrs(&out, a, e.addrs);
        }
    }
    var ts: [8]u8 = undefined;
    std.mem.writeInt(u64, &ts, info.ts, .little);
    try out.appendSlice(a, &ts);
    try out.append(a, info.access);
    try out.appendSlice(a, &info.sig);
    return out.toOwnedSlice(a);
}

// ------------------------------------------------------------------ writing

const access_names = [_][]const u8{ "Public", "Private", "Trusted" };

/// yaml-rust's `need_quotes` for the strings this file holds.
fn needQuotes(s: []const u8) bool {
    if (s.len == 0 or s[0] == ' ' or s[s.len - 1] == ' ' or s[0] == '.') return true;
    if (std.mem.indexOfScalar(u8, "&*?|-<>=!%@", s[0]) != null) return true;
    for (s) |ch| if (std.mem.indexOfScalar(u8, ":{}[],#`\"'\\", ch) != null or ch < 0x20) return true;
    if (std.mem.startsWith(u8, s, "0x")) return true;
    // `parse::<i64>()` or `parse::<f64>()` would succeed: digits with at most one '.' and one
    // exponent (hex peer ids are all digits or `<digits>e<digits>` once in about 10^13).
    var digits: usize = 0;
    var dot = false;
    var exp = false;
    var after_exp = false;
    for (s, 0..) |ch, i| {
        if (ch >= '0' and ch <= '9') {
            digits += 1;
            if (exp) after_exp = true;
        } else if (ch == '.' and !dot and !exp) {
            dot = true;
        } else if ((ch == 'e' or ch == 'E') and !exp and digits > 0) {
            exp = true;
        } else if ((ch == '+' or ch == '-') and (i == 0 or s[i - 1] == 'e' or s[i - 1] == 'E')) {} else return false;
    }
    return digits > 0 and (!exp or after_exp);
}

fn scalar(w: *std.Io.Writer, s: []const u8) !void {
    if (!needQuotes(s)) return w.writeAll(s);
    try w.writeByte('"');
    for (s) |ch| switch (ch) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\t' => try w.writeAll("\\t"),
        '\r' => try w.writeAll("\\r"),
        else => if (ch < 0x20) try w.print("\\u{x:0>4}", .{ch}) else try w.writeByte(ch),
    };
    try w.writeByte('"');
}

fn hexId(w: *std.Io.Writer, id: *const [32]u8) !void {
    var buf: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{x}", .{id.*}) catch unreachable;
    try scalar(w, &buf);
}

fn base64Of(w: *std.Io.Writer, bytes: []const u8) !void {
    var buf: [128]u8 = undefined;
    try scalar(w, b64.Encoder.encode(&buf, bytes));
}

/// Array items at `indent`: the first after "- " on the current line, the rest each on a line.
fn addrList(w: *std.Io.Writer, addrs: []const []const u8, indent: usize) !void {
    if (addrs.len == 0) return w.writeAll(" []");
    for (addrs, 0..) |s, i| {
        if (i > 0) {
            try w.writeByte('\n');
            try w.splatByteAll(' ', indent);
        }
        try w.writeAll(if (i == 0) " - " else "- ");
        try scalar(w, s);
    }
}

/// The YAML serde_yaml 0.8 writes for these envelopes (data ++ signature each). An envelope that
/// does not parse is left out.
pub fn write(a: Allocator, w: *std.Io.Writer, envelopes: []const []const u8) !void {
    try w.writeAll("---\n");
    var n: usize = 0;
    for (envelopes) |env| {
        const info = parseEnvelope(a, env) catch continue;
        if (n > 0) try w.writeByte('\n');
        n += 1;
        try w.writeAll("- data:\n    ");
        if (info.version == 0) {
            try w.writeAll("V1:\n      peer_id: ");
            try hexId(w, &info.peer_id);
            try w.writeAll("\n      addresses:");
            if (info.addrs.len == 0) try w.writeAll(" []") else {
                try w.writeAll("\n        ");
                for (info.addrs, 0..) |s, i| {
                    if (i > 0) try w.writeAll("\n        ");
                    try w.writeAll("- ");
                    try scalar(w, s);
                }
            }
        } else {
            try w.writeAll("V2:\n      addresses:");
            if (info.endpoints.len == 0) try w.writeAll(" {}") else {
                for (info.endpoints, 0..) |e, i| {
                    _ = i;
                    try w.writeAll("\n        ? ");
                    if (e.kind == 0) {
                        try w.writeAll("P2p: ");
                        try hexId(w, &e.key);
                    } else {
                        try w.writeAll("Consensus: ");
                        try base64Of(w, &e.key);
                    }
                    try w.writeAll("\n        :");
                    try addrList(w, e.addrs, 10);
                }
            }
        }
        try w.print("\n      timestamp_ms: {d}\n      access_type: {s}\n  auth_signature: ", .{ info.ts, access_names[info.access] });
        try base64Of(w, &info.sig);
    }
    if (n == 0) try w.writeAll("[]");
}

// ------------------------------------------------------------------ reading

fn unquote(a: Allocator, raw: []const u8) Error![]const u8 {
    const s = std.mem.trim(u8, raw, " ");
    if (s.len >= 2 and s[0] == '\'' and s[s.len - 1] == '\'') {
        return std.mem.replaceOwned(u8, a, s[1 .. s.len - 1], "''", "'");
    }
    if (s.len >= 2 and s[0] == '"' and s[s.len - 1] == '"') {
        var out: std.ArrayList(u8) = .empty;
        var i: usize = 1;
        while (i < s.len - 1) : (i += 1) {
            if (s[i] != '\\') {
                try out.append(a, s[i]);
                continue;
            }
            i += 1;
            if (i >= s.len - 1) return error.Malformed;
            switch (s[i]) {
                'n' => try out.append(a, '\n'),
                't' => try out.append(a, '\t'),
                'r' => try out.append(a, '\r'),
                'u' => {
                    if (i + 4 >= s.len) return error.Malformed;
                    const v = std.fmt.parseInt(u8, s[i + 1 .. i + 5], 16) catch return error.Malformed;
                    try out.append(a, v);
                    i += 4;
                },
                else => try out.append(a, s[i]),
            }
        }
        return out.items;
    }
    return s;
}

fn hex32(s: []const u8) Error![32]u8 {
    var out: [32]u8 = undefined;
    if (s.len != 64) return error.Malformed;
    _ = std.fmt.hexToBytes(&out, s) catch return error.Malformed;
    return out;
}

fn fixedB64(comptime n: usize, s: []const u8) Error![n]u8 {
    var out: [n]u8 = undefined;
    const len = b64.Decoder.calcSizeForSlice(s) catch return error.Malformed;
    if (len != n) return error.Malformed;
    b64.Decoder.decode(&out, s) catch return error.Malformed;
    return out;
}

/// The entries of a peer cache file as envelope bytes (data ++ signature). Entries this reader
/// cannot rebuild are skipped; `skipped` counts them. The caller verifies each signature.
pub fn read(a: Allocator, text: []const u8, skipped: *usize) Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var cur: ?Info = null;
    var bad = false;
    var addrs: std.ArrayList([]const u8) = .empty;
    var eps: std.ArrayList(Endpoint) = .empty;
    var have_sig = false;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (true) {
        const next = it.next();
        const raw = if (next) |l| std.mem.trimEnd(u8, l, "\r ") else "";
        const starts = next == null or (raw.len > 0 and raw[0] == '-' and (raw.len == 1 or raw[1] == ' '));
        if (starts) {
            // close the previous entry
            if (cur) |*c| {
                if (!bad and have_sig) {
                    if (c.version == 0) c.addrs = addrs.items else {
                        if (eps.items.len > 0) eps.items[eps.items.len - 1].addrs = addrs.items;
                        c.endpoints = eps.items;
                    }
                    try out.append(a, try encodeEnvelope(a, c));
                } else skipped.* += 1;
            }
            if (next == null) break;
            cur = .{ .version = 255 };
            bad = false;
            have_sig = false;
            addrs = .empty;
            eps = .empty;
        }
        if (next == null) break;
        var line = std.mem.trim(u8, raw, " ");
        if (starts) line = std.mem.trimStart(u8, line[1..], " ");
        if (line.len == 0 or line[0] == '#' or std.mem.eql(u8, line, "---") or std.mem.eql(u8, line, "[]")) continue;
        const c = if (cur) |*x| x else continue;
        if (bad) continue;
        parseLine(a, c, line, &addrs, &eps, &have_sig) catch {
            bad = true;
        };
    }
    return out.items;
}

fn parseLine(a: Allocator, c: *Info, line0: []const u8, addrs: *std.ArrayList([]const u8), eps: *std.ArrayList(Endpoint), have_sig: *bool) Error!void {
    var line = line0;
    if (line[0] == '?') {
        // complex key: `? P2p: <hex>` / `? Consensus: <base64>` opens an endpoint
        line = std.mem.trimStart(u8, line[1..], " ");
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.Malformed;
        const kind = line[0..colon];
        const val = try unquote(a, line[colon + 1 ..]);
        if (eps.items.len > 0) eps.items[eps.items.len - 1].addrs = try addrs.toOwnedSlice(a);
        addrs.* = .empty;
        if (std.mem.eql(u8, kind, "P2p")) {
            try eps.append(a, .{ .kind = 0, .key = try hex32(val), .addrs = &.{} });
        } else if (std.mem.eql(u8, kind, "Consensus")) {
            try eps.append(a, .{ .kind = 1, .key = try fixedB64(32, val), .addrs = &.{} });
        } else return error.Malformed;
        return;
    }
    if (line[0] == ':') {
        // the complex key's value: ` []` or ` - <addr>`
        line = std.mem.trimStart(u8, line[1..], " ");
        if (line.len == 0 or std.mem.eql(u8, line, "[]")) return;
        if (line[0] != '-') return error.Malformed;
    }
    if (line[0] == '-') {
        try addrs.append(a, try unquote(a, line[1..]));
        return;
    }
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.Malformed;
    const key = line[0..colon];
    const val = std.mem.trim(u8, line[colon + 1 ..], " ");
    if (std.mem.eql(u8, key, "data")) return;
    if (std.mem.eql(u8, key, "V1")) {
        c.version = 0;
    } else if (std.mem.eql(u8, key, "V2")) {
        c.version = 1;
    } else if (std.mem.eql(u8, key, "peer_id")) {
        c.peer_id = try hex32(try unquote(a, val));
    } else if (std.mem.eql(u8, key, "addresses")) {
        if (val.len != 0 and !std.mem.eql(u8, val, "[]") and !std.mem.eql(u8, val, "{}")) return error.Malformed;
    } else if (std.mem.eql(u8, key, "timestamp_ms")) {
        c.ts = std.fmt.parseInt(u64, try unquote(a, val), 10) catch return error.Malformed;
    } else if (std.mem.eql(u8, key, "access_type")) {
        const v = try unquote(a, val);
        c.access = for (access_names, 0..) |n, i| {
            if (std.mem.eql(u8, v, n)) break @intCast(i);
        } else return error.Malformed;
    } else if (std.mem.eql(u8, key, "auth_signature")) {
        c.sig = try fixedB64(64, try unquote(a, val));
        have_sig.* = true;
    } else return error.Malformed;
    if (c.version == 255 and !std.mem.eql(u8, key, "auth_signature")) return error.Malformed;
}

// ------------------------------------------------------------------ tests

test "peer cache: V1 and V2 envelopes round-trip through serde_yaml 0.8's text" {
    var ar: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(7));
    const id = kp.public_key.toBytes();
    // V2 with a P2p and a Consensus endpoint, two addresses, an IPv6 one (quoted)
    const v2: Info = .{ .version = 1, .endpoints = &.{
        .{ .kind = 1, .key = id, .addrs = &.{"/ip4/1.2.3.4/tcp/8080"} },
        .{ .kind = 0, .key = id, .addrs = &.{ "/dns/peer.example/udp/8084", "/ip6/::1/udp/8084" } },
    }, .ts = 1762650000000, .access = 0, .sig = @splat(0xab) };
    const v1: Info = .{ .version = 0, .peer_id = id, .addrs = &.{}, .ts = 5, .access = 2, .sig = @splat(1) };
    const e2 = try encodeEnvelope(a, &v2);
    const e1 = try encodeEnvelope(a, &v1);
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try write(a, &w, &.{ e2, e1 });
    const text = w.buffered();
    const hex = try std.fmt.allocPrint(a, "{x}", .{id});
    const want_v2 = try std.fmt.allocPrint(a,
        \\---
        \\- data:
        \\    V2:
        \\      addresses:
        \\        ? P2p: {s}
        \\        : - /dns/peer.example/udp/8084
        \\          - "/ip6/::1/udp/8084"
        \\        ? Consensus:
    , .{hex});
    try std.testing.expect(std.mem.startsWith(u8, text, want_v2));
    try std.testing.expect(std.mem.indexOf(u8, text, "\n        : - /ip4/1.2.3.4/tcp/8080\n      timestamp_ms: 1762650000000\n      access_type: Public\n  auth_signature: q6ur") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\n- data:\n    V1:\n      peer_id: ") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\n      addresses: []\n      timestamp_ms: 5\n      access_type: Trusted\n") != null);
    var skipped: usize = 0;
    const back = try read(a, text, &skipped);
    try std.testing.expectEqual(@as(usize, 0), skipped);
    try std.testing.expectEqual(@as(usize, 2), back.len);
    try std.testing.expectEqualSlices(u8, e2, back[0]);
    try std.testing.expectEqualSlices(u8, e1, back[1]);
    // empty list, and junk: nothing, never an error
    w = .fixed(&buf);
    try write(a, &w, &.{});
    try std.testing.expectEqualStrings("---\n[]", w.buffered());
    try std.testing.expectEqual(@as(usize, 0), (try read(a, "---\n[]", &skipped)).len);
    skipped = 0;
    try std.testing.expectEqual(@as(usize, 0), (try read(a, "---\n- data:\n    V9:\n  auth_signature: x\n", &skipped)).len);
    try std.testing.expectEqual(@as(usize, 1), skipped);
}

test "peer cache: yaml-rust quoting of numeric-looking scalars" {
    try std.testing.expect(needQuotes("1234"));
    try std.testing.expect(needQuotes("12e45"));
    try std.testing.expect(!needQuotes("12e4a"));
    try std.testing.expect(!needQuotes("5f1c"));
    try std.testing.expect(needQuotes("/ip6/::1/udp/8084"));
    try std.testing.expect(!needQuotes("/dns/a.b/udp/8084"));
    try std.testing.expect(!needQuotes("q6ur+/=="));
}
