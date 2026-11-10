//! sui-node's `fullnode.yaml` (crates/sui-config/src/node.rs, mainnet-v1.83.1) read by deepwave, so
//! the cutover is a binary swap with the same config: `deepwave --config-path FILE` (sui-node's
//! own flag) or `deepwave run --config FILE.yaml`.
//!
//! The file is parsed (a YAML subset: block mappings and sequences, plain and quoted scalars,
//! flow `[]`/`{}`, comments; enough for every sui-node config Mysten ships) and the keys that
//! map to deepwave behaviour become deepwave run flags, placed before the command line's so a flag
//! given there still wins. Every other key is kept out with a note: `info` for keys deepwave has no
//! use for (validator-only, RocksDB tuning, JSON-RPC indexes), `warn` for keys whose behaviour
//! deepwave does not have and for keys sui-node does not know either. Nothing in the file fails the
//! load except YAML deepwave cannot parse.
//!
//! Features owned by other lanes (p2p server, admin port, split retention) are emitted only
//! when the binary has their flag: `Options` names the flags this build parses.
const std = @import("std");
const p2p_config = @import("p2p_config.zig");

// ------------------------------------------------------------------ YAML subset

pub const Value = union(enum) {
    null,
    scalar: []const u8,
    seq: []const Value,
    map: []const Pair,

    pub fn get(v: Value, key: []const u8) ?Value {
        if (v != .map) return null;
        for (v.map) |p| if (std.mem.eql(u8, p.key, key)) return p.value;
        return null;
    }
};

pub const Pair = struct { key: []const u8, value: Value };

const Line = struct { indent: usize, text: []const u8, no: usize };

pub const ParseError = error{ YamlSyntax, OutOfMemory };

/// Parses `text` into a tree whose strings point into `text` or `arena`.
pub fn parse(arena: std.mem.Allocator, text: []const u8, err_line: *usize) ParseError!Value {
    var lines: std.ArrayList(Line) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    var no: usize = 0;
    while (it.next()) |raw0| {
        no += 1;
        const raw = std.mem.trimEnd(u8, raw0, "\r");
        if (std.mem.startsWith(u8, raw, "---") or std.mem.startsWith(u8, raw, "...")) continue;
        // YAML forbids tabs in indentation.
        const lead = raw.len - std.mem.trimStart(u8, raw, " \t").len;
        if (std.mem.indexOfScalar(u8, raw[0..lead], '\t') != null and lead < raw.len and raw[lead] != '#') {
            err_line.* = no;
            return error.YamlSyntax;
        }
        const body = std.mem.trimEnd(u8, stripComment(raw), " ");
        const ind = indentOf(body);
        if (ind == body.len) continue;
        try lines.append(arena, .{ .indent = ind, .text = body[ind..], .no = no });
    }
    var p: Parser = .{ .arena = arena, .lines = lines.items, .err_line = err_line };
    if (p.lines.len == 0) return .null;
    const v = try p.block(p.lines[0].indent);
    if (p.i != p.lines.len) return p.fail();
    return v;
}

fn indentOf(s: []const u8) usize {
    var i: usize = 0;
    while (i < s.len and s[i] == ' ') i += 1;
    return i;
}

/// The line without its comment: `#` at the start or after a space, outside quotes.
fn stripComment(s: []const u8) []const u8 {
    var q: u8 = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (q != 0) {
            if (c == '\\' and q == '"') {
                i += 1;
            } else if (c == q) q = 0;
        } else if (c == '"' or c == '\'') {
            q = c;
        } else if (c == '#' and (i == 0 or s[i - 1] == ' ')) return s[0..i];
    }
    return s;
}

const Parser = struct {
    arena: std.mem.Allocator,
    lines: []Line,
    i: usize = 0,
    err_line: *usize,

    fn fail(p: *Parser) ParseError {
        p.err_line.* = if (p.i < p.lines.len) p.lines[p.i].no else if (p.lines.len > 0) p.lines[p.lines.len - 1].no else 0;
        return error.YamlSyntax;
    }

    fn isSeqItem(t: []const u8) bool {
        return std.mem.eql(u8, t, "-") or std.mem.startsWith(u8, t, "- ");
    }

    /// A block (mapping or sequence) whose lines sit at exactly `indent`.
    fn block(p: *Parser, indent: usize) ParseError!Value {
        if (p.i >= p.lines.len) return .null;
        if (isSeqItem(p.lines[p.i].text)) return p.seqBlock(indent);
        return p.mapBlock(indent, null);
    }

    fn seqBlock(p: *Parser, indent: usize) ParseError!Value {
        var items: std.ArrayList(Value) = .empty;
        while (p.i < p.lines.len) {
            const l = p.lines[p.i];
            if (l.indent < indent) break;
            if (l.indent > indent) return p.fail();
            // a sequence at its key's column ends at the next key of that mapping
            if (!isSeqItem(l.text)) break;
            const rest = std.mem.trimStart(u8, l.text[1..], " ");
            if (rest.len == 0) {
                p.i += 1;
                if (p.i < p.lines.len and p.lines[p.i].indent > indent) {
                    try items.append(p.arena, try p.block(p.lines[p.i].indent));
                } else try items.append(p.arena, .null);
                continue;
            }
            // `- key: value` opens a mapping whose further keys sit at the column of `key`.
            const col = indent + (l.text.len - rest.len);
            // `- - x` (serde_yaml's tuples, e.g. `pinned-checkpoints`): a nested sequence whose
            // items sit at the column of the inner dash.
            if (isSeqItem(rest)) {
                p.lines[p.i] = .{ .indent = col, .text = rest, .no = l.no };
                try items.append(p.arena, try p.seqBlock(col));
                continue;
            }
            if (keySplit(rest) != null and rest[0] != '"' and rest[0] != '\'' and rest[0] != '[' and rest[0] != '{') {
                try items.append(p.arena, try p.mapBlock(col, rest));
            } else {
                p.i += 1;
                try items.append(p.arena, try p.inlineValue(rest, indent));
            }
        }
        return .{ .seq = items.items };
    }

    /// `first`: the text of the first entry when it shares its line with a sequence dash.
    fn mapBlock(p: *Parser, indent: usize, first: ?[]const u8) ParseError!Value {
        var pairs: std.ArrayList(Pair) = .empty;
        var pending = first;
        while (true) {
            var text: []const u8 = undefined;
            if (pending) |f| {
                text = f;
                pending = null;
            } else {
                if (p.i >= p.lines.len) break;
                const l = p.lines[p.i];
                if (l.indent < indent) break;
                if (l.indent > indent) return p.fail();
                if (isSeqItem(l.text)) break;
                text = l.text;
            }
            const ks = keySplit(text) orelse return p.fail();
            const key = try unquote(p.arena, std.mem.trim(u8, text[0..ks], " "));
            const rest = std.mem.trim(u8, text[ks + 1 ..], " ");
            p.i += 1;
            var v: Value = .null;
            if (rest.len == 0) {
                if (p.i < p.lines.len) {
                    const nl = p.lines[p.i];
                    if (nl.indent > indent) {
                        v = try p.block(nl.indent);
                    } else if (nl.indent == indent and isSeqItem(nl.text)) {
                        // `key:` followed by a sequence at the key's own column
                        v = try p.seqBlock(indent);
                    }
                }
            } else v = try p.inlineValue(rest, indent);
            try pairs.append(p.arena, .{ .key = key, .value = v });
        }
        return .{ .map = pairs.items };
    }

    /// A value on the key's line: flow collection, block scalar indicator, or scalar.
    fn inlineValue(p: *Parser, rest: []const u8, indent: usize) ParseError!Value {
        if (rest[0] == '[' or rest[0] == '{') {
            var f: Flow = .{ .arena = p.arena, .s = rest };
            const v = f.value() catch return p.fail();
            f.ws();
            if (f.i != f.s.len) return p.fail();
            return v;
        }
        if (rest[0] == '|' or rest[0] == '>') {
            // Block scalar: the more-indented lines that follow, joined.
            var out: std.ArrayList(u8) = .empty;
            while (p.i < p.lines.len and p.lines[p.i].indent > indent) : (p.i += 1) {
                if (out.items.len > 0) try out.append(p.arena, if (rest[0] == '|') '\n' else ' ');
                try out.appendSlice(p.arena, p.lines[p.i].text);
            }
            return .{ .scalar = out.items };
        }
        if (rest[0] == '&' or rest[0] == '*' or rest[0] == '!') return p.fail();
        return scalarOf(p.arena, rest);
    }
};

/// Position of the `:` that ends a mapping key (followed by a space or the end), outside quotes.
fn keySplit(t: []const u8) ?usize {
    var q: u8 = 0;
    for (t, 0..) |c, i| {
        if (q != 0) {
            if (c == q) q = 0;
        } else if ((c == '"' or c == '\'') and i == 0) {
            q = c;
        } else if (c == ':' and (i + 1 == t.len or t[i + 1] == ' ')) return i;
    }
    return null;
}

fn scalarOf(arena: std.mem.Allocator, s: []const u8) ParseError!Value {
    if (std.mem.eql(u8, s, "~") or std.mem.eql(u8, s, "null")) return .null;
    return .{ .scalar = try unquote(arena, s) };
}

fn unquote(arena: std.mem.Allocator, s: []const u8) ParseError![]const u8 {
    if (s.len >= 2 and s[0] == '\'' and s[s.len - 1] == '\'') {
        return std.mem.replaceOwned(u8, arena, s[1 .. s.len - 1], "''", "'");
    }
    if (s.len >= 2 and s[0] == '"' and s[s.len - 1] == '"') {
        var out: std.ArrayList(u8) = .empty;
        var i: usize = 1;
        while (i < s.len - 1) : (i += 1) {
            if (s[i] == '\\' and i + 1 < s.len - 1) {
                i += 1;
                try out.append(arena, switch (s[i]) {
                    'n' => '\n',
                    't' => '\t',
                    '0' => 0,
                    else => s[i],
                });
            } else try out.append(arena, s[i]);
        }
        return out.items;
    }
    return s;
}

const Flow = struct {
    arena: std.mem.Allocator,
    s: []const u8,
    i: usize = 0,

    fn ws(f: *Flow) void {
        while (f.i < f.s.len and f.s[f.i] == ' ') f.i += 1;
    }

    fn value(f: *Flow) ParseError!Value {
        f.ws();
        if (f.i >= f.s.len) return error.YamlSyntax;
        switch (f.s[f.i]) {
            '[' => {
                f.i += 1;
                var items: std.ArrayList(Value) = .empty;
                f.ws();
                if (f.i < f.s.len and f.s[f.i] == ']') {
                    f.i += 1;
                    return .{ .seq = items.items };
                }
                while (true) {
                    try items.append(f.arena, try f.value());
                    f.ws();
                    if (f.i >= f.s.len) return error.YamlSyntax;
                    if (f.s[f.i] == ',') {
                        f.i += 1;
                        continue;
                    }
                    if (f.s[f.i] != ']') return error.YamlSyntax;
                    f.i += 1;
                    return .{ .seq = items.items };
                }
            },
            '{' => {
                f.i += 1;
                var pairs: std.ArrayList(Pair) = .empty;
                f.ws();
                if (f.i < f.s.len and f.s[f.i] == '}') {
                    f.i += 1;
                    return .{ .map = pairs.items };
                }
                while (true) {
                    f.ws();
                    const k = try f.atom(":");
                    if (f.i >= f.s.len or f.s[f.i] != ':') return error.YamlSyntax;
                    f.i += 1;
                    const v = try f.value();
                    try pairs.append(f.arena, .{ .key = switch (k) {
                        .scalar => |x| x,
                        else => return error.YamlSyntax,
                    }, .value = v });
                    f.ws();
                    if (f.i >= f.s.len) return error.YamlSyntax;
                    if (f.s[f.i] == ',') {
                        f.i += 1;
                        continue;
                    }
                    if (f.s[f.i] != '}') return error.YamlSyntax;
                    f.i += 1;
                    return .{ .map = pairs.items };
                }
            },
            else => return f.atom(""),
        }
    }

    fn atom(f: *Flow, extra_stop: []const u8) ParseError!Value {
        f.ws();
        const start = f.i;
        if (f.i < f.s.len and (f.s[f.i] == '"' or f.s[f.i] == '\'')) {
            const q = f.s[f.i];
            f.i += 1;
            while (f.i < f.s.len and f.s[f.i] != q) : (f.i += 1) {
                if (f.s[f.i] == '\\' and q == '"') f.i += 1;
            }
            if (f.i >= f.s.len) return error.YamlSyntax;
            f.i += 1;
            return scalarOf(f.arena, f.s[start..f.i]);
        }
        while (f.i < f.s.len and std.mem.indexOfScalar(u8, ",]}", f.s[f.i]) == null and std.mem.indexOfScalar(u8, extra_stop, f.s[f.i]) == null) f.i += 1;
        return scalarOf(f.arena, std.mem.trim(u8, f.s[start..f.i], " "));
    }
};

// ------------------------------------------------------------------ sui-node keys -> deepwave flags

pub const Level = enum { info, warn };
pub const Note = struct { level: Level, text: []const u8 };

/// Run flags this deepwave build parses for features other lanes own (null: not in this build).
pub const Options = struct {
    /// `--p2p HOST:PORT@PEERID,...` (p2p state sync seeds).
    p2p_seeds_flag: ?[]const u8 = null,
    /// p2p network identity key file (`p2p-config` uses `network-key-pair`).
    p2p_key_flag: ?[]const u8 = null,
    /// p2p server listen address (UDP).
    p2p_listen_flag: ?[]const u8 = null,
    /// Advertised p2p multiaddr.
    p2p_external_flag: ?[]const u8 = null,
    /// `--p2p-opt KEY=VALUE` (p2p_config.zig): the other `p2p-config` keys.
    p2p_opt_flag: ?[]const u8 = null,
    /// `--p2p-access public|private|trusted` (`discovery.access-type`).
    p2p_access_flag: ?[]const u8 = null,
    /// `--p2p-pinned SEQ:DIGEST,...` (`state-sync.pinned-checkpoints`).
    p2p_pinned_flag: ?[]const u8 = null,
    /// 127.0.0.1 admin interface address.
    admin_flag: ?[]const u8 = null,
    /// Object-version retention separate from checkpoint retention (epochs).
    object_retention_flag: ?[]const u8 = null,
};

pub const Translation = struct {
    /// deepwave run flags, `--name value` pairs and bare `--name` switches.
    args: []const []const u8,
    notes: []const Note,
};

pub const mainnet_archive = "https://checkpoints.mainnet.sui.io";
/// sui-config `default_json_rpc_address` and `RpcConfig::https_address`'s default.
pub const default_rpc_address = "0.0.0.0:9000";
pub const default_https_address = "0.0.0.0:9443";

/// `rpc.*` scalars deepwave takes as `--rpc KEY=VALUE` (node.zig `setRpc`).
const rpc_scalars = [_][]const u8{ "grpc-timeout-ms", "max-connection-age-secs", "max-connection-age-grace-secs", "subscription-watermark-interval", "subscription-max-subscribers" };

const T = struct {
    arena: std.mem.Allocator,
    opts: Options,
    args: std.ArrayList([]const u8) = .empty,
    notes: std.ArrayList(Note) = .empty,

    fn flag(t: *T, name: []const u8, value: ?[]const u8) !void {
        try t.args.append(t.arena, name);
        if (value) |v| try t.args.append(t.arena, v);
    }

    fn note(t: *T, level: Level, comptime fmt: []const u8, args: anytype) !void {
        try t.notes.append(t.arena, .{ .level = level, .text = try std.fmt.allocPrint(t.arena, fmt, args) });
    }

    fn str(t: *T, path: []const u8, v: Value) !?[]const u8 {
        return switch (v) {
            .scalar => |s| s,
            .null => null,
            else => {
                try t.note(.warn, "{s}: expected a value, found a {s}; ignored", .{ path, @tagName(v) });
                return null;
            },
        };
    }

    fn int(t: *T, path: []const u8, v: Value) !?u64 {
        const s = (try t.str(path, v)) orelse return null;
        return std.fmt.parseInt(u64, s, 10) catch {
            try t.note(.warn, "{s}: {s} is not a number; ignored", .{ path, s });
            return null;
        };
    }

    fn boolean(t: *T, path: []const u8, v: Value) !?bool {
        const s = (try t.str(path, v)) orelse return null;
        if (std.mem.eql(u8, s, "true")) return true;
        if (std.mem.eql(u8, s, "false")) return false;
        try t.note(.warn, "{s}: {s} is not true or false; ignored", .{ path, s });
        return null;
    }
};

/// Keys that only matter to validators, RocksDB tuning sui-node does not share with deepwave, or
/// JSON-RPC (which deepwave does not serve): accepted, with an `info` note.
const no_effect = [_]struct { key: []const u8, why: []const u8 }{
    .{ .key = "network-address", .why = "validator network address (a full node does not listen on it)" },
    .{ .key = "protocol-key-pair", .why = "validator key" },
    .{ .key = "worker-key-pair", .why = "validator key" },
    .{ .key = "account-key-pair", .why = "validator key" },
    .{ .key = "consensus-config", .why = "validator only" },
    .{ .key = "enable-event-processing", .why = "JSON-RPC event indexes (zui serves sui.rpc.v2 only)" },
    .{ .key = "enable-index-processing", .why = "JSON-RPC indexes (zui serves sui.rpc.v2 only)" },
    .{ .key = "remove-deprecated-tables", .why = "RocksDB maintenance" },
    .{ .key = "execution-cache", .why = "sui-node execution cache tuning (zui's store has its own)" },
    .{ .key = "execution-cache-config", .why = "sui-node execution cache tuning (zui's store has its own)" },
    .{ .key = "authority-overload-config", .why = "validator overload control" },
    .{ .key = "enable-db-write-stall", .why = "RocksDB write stall" },
    .{ .key = "jwk-fetch-interval-seconds", .why = "validator JWK fetching" },
    .{ .key = "zklogin-oauth-providers", .why = "validator JWK fetching" },
    .{ .key = "supported-protocol-versions", .why = "deepwave --protocol-range is built in" },
    .{ .key = "end-of-epoch-broadcast-channel-capacity", .why = "sui-node internal channel" },
    .{ .key = "checkpoint-executor-config", .why = "sui-node executor tuning" },
    .{ .key = "expensive-safety-check-config", .why = "zui checks the ECMH root at every snapshot restore; the epoch SUI conservation check is --sui-conservation (off by default, as here)" },
    .{ .key = "indirect-objects-threshold", .why = "obsolete" },
    .{ .key = "chain-override-for-testing", .why = "tests" },
    .{ .key = "enable-soft-bundle", .why = "validator" },
    .{ .key = "enable-validator-tx-finalizer", .why = "validator" },
    .{ .key = "verifier-signing-config", .why = "validator" },
    .{ .key = "execution-time-observer-config", .why = "validator" },
    .{ .key = "enable-staggered-submission-signal", .why = "validator" },
    .{ .key = "state-debug-dump-config", .why = "zui logs the first mismatch reason and halts" },
    .{ .key = "fork-recovery", .why = "zui halts on a mismatch (--no-halt to continue)" },
    .{ .key = "fullnode-sync-mode", .why = "zui follows checkpoints (ConsensusObserver is not built)" },
    .{ .key = "db-checkpoint-config", .why = "use `deepwave-tool db-checkpoint` (offline, hard links + reflinks)" },
    // sui-node applies these to the validator gRPC server only (sui-node lib.rs: `server_conf`
    // of ValidatorServer); its full-node RPC port never sees them (rpc-surface limits/*: 24
    // concurrent calls with load-shed and a limit of 1 all answered OK).
    .{ .key = "grpc-load-shed", .why = "validator gRPC server only (sui-node's full-node RPC ignores it too)" },
    .{ .key = "grpc-concurrency-limit", .why = "validator gRPC server only (sui-node's full-node RPC ignores it too)" },
};

/// Behaviour deepwave does not have: accepted with a `warn` note.
const unsupported = [_]struct { key: []const u8, why: []const u8 }{
    .{ .key = "firewall-config", .why = "zui's traffic controller does not delegate to a remote firewall" },
    .{ .key = "certificate-deny-config", .why = "not built" },
};

fn findName(names: []const []const u8, key: []const u8) bool {
    for (names) |x| if (std.mem.eql(u8, x, key)) return true;
    return false;
}

fn findIn(comptime tbl: anytype, key: []const u8) ?[]const u8 {
    for (tbl) |e| if (std.mem.eql(u8, e.key, key)) return e.why;
    return null;
}

/// `/dns/HOST/udp/PORT`, `/ip4/A/udp/PORT`, `/ip6/A/udp/PORT` -> `HOST:PORT` (`[A]:PORT` for v6).
pub fn multiaddrHostPort(arena: std.mem.Allocator, m: []const u8) !?[]const u8 {
    var it = std.mem.tokenizeScalar(u8, m, '/');
    const proto = it.next() orelse return null;
    const host = it.next() orelse return null;
    const transport = it.next() orelse return null;
    const port = it.next() orelse return null;
    if (!std.mem.eql(u8, transport, "udp") and !std.mem.eql(u8, transport, "tcp")) return null;
    _ = std.fmt.parseInt(u16, port, 10) catch return null;
    if (std.mem.eql(u8, proto, "ip6")) return try std.fmt.allocPrint(arena, "[{s}]:{s}", .{ host, port });
    if (!std.mem.eql(u8, proto, "dns") and !std.mem.eql(u8, proto, "dns4") and !std.mem.eql(u8, proto, "dns6") and !std.mem.eql(u8, proto, "ip4")) return null;
    return try std.fmt.allocPrint(arena, "{s}:{s}", .{ host, port });
}

/// Translates a parsed fullnode.yaml into deepwave run flags plus notes.
pub fn translateValue(arena: std.mem.Allocator, root: Value, opts: Options) !Translation {
    var t: T = .{ .arena = arena, .opts = opts };
    if (root != .map) {
        if (root != .null) try t.note(.warn, "the file is not a mapping of keys; nothing applied", .{});
        return .{ .args = t.args.items, .notes = t.notes.items };
    }
    var rpc_address = false;
    for (root.map) |p| {
        const k = p.key;
        const v = p.value;
        if (std.mem.eql(u8, k, "json-rpc-address")) rpc_address = true;
        if (std.mem.eql(u8, k, "db-path")) {
            if (try t.str(k, v)) |s| try t.flag("--dir", s);
        } else if (std.mem.eql(u8, k, "json-rpc-address")) {
            if (try t.str(k, v)) |s| try t.flag("--serve", s);
        } else if (std.mem.eql(u8, k, "metrics-address")) {
            if (try t.str(k, v)) |s| try t.flag("--metrics", s);
        } else if (std.mem.eql(u8, k, "metrics")) {
            // sui-node MetricsConfig: push-url, push-interval-seconds (push is off without a url)
            for (mapOr(&t, k, v)) |q| {
                if (std.mem.eql(u8, q.key, "push-url")) {
                    if (try t.str("metrics.push-url", q.value)) |u| {
                        try t.flag("--metrics-push-url", u);
                        try t.note(.info, "metrics.push-url: deepwave sends no client certificate (sui-node's mTLS from the network key); the proxy must accept that", .{});
                    }
                } else if (std.mem.eql(u8, q.key, "push-interval-seconds")) {
                    if (try t.int("metrics.push-interval-seconds", q.value)) |n| try t.flag("--metrics-push-interval", try std.fmt.allocPrint(arena, "{d}", .{n}));
                } else try t.note(.warn, "metrics.{s}: unknown key; ignored", .{q.key});
            }
        } else if (std.mem.eql(u8, k, "admin-interface-port")) {
            if (try t.int(k, v)) |port| {
                if (opts.admin_flag) |f| {
                    try t.flag(f, try std.fmt.allocPrint(arena, "127.0.0.1:{d}", .{port}));
                } else try t.note(.warn, "admin-interface-port {d}: this deepwave build has no admin port; ignored", .{port});
            }
        } else if (std.mem.eql(u8, k, "genesis")) {
            for (mapOr(&t, k, v)) |g| {
                if (std.mem.eql(u8, g.key, "genesis-file-location")) {
                    if (try t.str("genesis.genesis-file-location", g.value)) |s| try t.flag("--genesis", s);
                } else try t.note(.warn, "genesis.{s}: unknown key; ignored (deepwave needs genesis-file-location)", .{g.key});
            }
        } else if (std.mem.eql(u8, k, "rpc")) {
            try rpcKeys(&t, v);
        } else if (std.mem.eql(u8, k, "p2p-config")) {
            try p2pKeys(&t, v);
        } else if (std.mem.eql(u8, k, "network-key-pair")) {
            const path = if (v.get("path")) |x| try t.str("network-key-pair.path", x) else null;
            if (path) |pth| {
                if (opts.p2p_key_flag) |f| try t.flag(f, pth) else try t.note(.info, "network-key-pair: this deepwave build has no p2p identity flag; ignored", .{});
            } else try t.note(.info, "network-key-pair: only `path:` key files are read; ignored", .{});
        } else if (std.mem.eql(u8, k, "authority-store-pruning-config")) {
            try pruningKeys(&t, v);
        } else if (std.mem.eql(u8, k, "state-archive-read-config")) {
            try archiveKeys(&t, v);
        } else if (std.mem.eql(u8, k, "enable-db-sync-to-disk")) {
            if (try t.boolean(k, v)) |b| {
                if (b) try t.flag("--sync", "full") else try t.note(.info, "enable-db-sync-to-disk false: deepwave keeps its default --sync data (fdatasync per commit group; sui-node's default never fsyncs)", .{});
            }
        } else if (std.mem.eql(u8, k, "state-snapshot-write-config")) {
            try snapshotWriteKeys(&t, v);
        } else if (std.mem.eql(u8, k, "zui")) {
            // zui-only section: where deepwave writes besides db-path (hardened units list these
            // in ReadWritePaths). Defaults: DB/rpc and DB/ledger-history.
            for (mapOr(&t, "zui", v)) |q| {
                const flag: ?[]const u8 = if (std.mem.eql(u8, q.key, "rpc-index-path")) "--rpc-index-dir" else if (std.mem.eql(u8, q.key, "ledger-history-path")) "--ledger-history-dir" else null;
                if (flag) |f| {
                    if (try t.str(try std.fmt.allocPrint(arena, "zui.{s}", .{q.key}), q.value)) |path| try t.flag(f, path);
                } else try t.note(.warn, "zui.{s}: unknown key; ignored", .{q.key});
            }
        } else if (std.mem.eql(u8, k, "run-with-range")) {
            if (v.get("checkpoint")) |c| {
                if (try t.int("run-with-range.checkpoint", c)) |n| try t.flag("--to", try std.fmt.allocPrint(arena, "{d}", .{n}));
            } else if (v.get("epoch")) |_| {
                try t.note(.warn, "run-with-range.epoch: deepwave stops at a checkpoint only (--to N); ignored", .{});
            } else try t.note(.warn, "run-with-range: expected `checkpoint: N` or `epoch: N`; ignored", .{});
        } else if (std.mem.eql(u8, k, "transaction-deny-config")) {
            try policy.denyKeys(&t, v);
        } else if (std.mem.eql(u8, k, "policy-config")) {
            try policy.policyKeys(&t, v);
        } else if (std.mem.eql(u8, k, "transaction-driver-config")) {
            try policy.driverKeys(&t, v);
        } else if (findIn(no_effect, k)) |why| {
            try t.note(.info, "{s}: {s}; ignored", .{ k, why });
        } else if (findIn(unsupported, k)) |why| {
            try t.note(.warn, "{s}: {s}; ignored", .{ k, why });
        } else {
            try t.note(.warn, "{s}: unknown key; ignored", .{k});
        }
    }
    if (!rpc_address) {
        // sui-config `default_json_rpc_address`: a full node always serves its RPC port
        try t.flag("--serve", default_rpc_address);
        try t.note(.info, "json-rpc-address: not set; serving on sui-node's default {s}", .{default_rpc_address});
    }
    return .{ .args = t.args.items, .notes = t.notes.items };
}

// ---- lane rpc-surface policy: transaction-deny-config and policy-config -> --tx-deny / --policy
// (kept in one block, apart from the rpc.* keys)
const policy = struct {
    const deny_lists = [_][]const u8{ "object-deny-list", "package-deny-list", "address-deny-list", "zklogin-disabled-providers" };
    const deny_bools = [_][]const u8{ "package-publish-disabled", "package-upgrade-disabled", "shared-object-disabled", "user-transaction-disabled", "gasless-disabled", "receiving-objects-disabled", "zklogin-sig-disabled" };

    fn isIn(comptime l: anytype, k: []const u8) bool {
        for (l) |x| if (std.mem.eql(u8, x, k)) return true;
        return false;
    }

    fn joined(t: *T, path: []const u8, v: Value) !?[]const u8 {
        const items = switch (v) {
            .seq => |x| x,
            .null => &[_]Value{},
            else => {
                try t.note(.warn, "{s}: expected a list; ignored", .{path});
                return null;
            },
        };
        var out: std.ArrayList(u8) = .empty;
        for (items) |it| {
            const s = (try t.str(path, it)) orelse continue;
            if (out.items.len > 0) try out.append(t.arena, ',');
            try out.appendSlice(t.arena, s);
        }
        return out.items;
    }

    fn denyKeys(t: *T, v: Value) !void {
        for (mapOr(t, "transaction-deny-config", v)) |p| {
            const path = try std.fmt.allocPrint(t.arena, "transaction-deny-config.{s}", .{p.key});
            if (isIn(deny_lists, p.key)) {
                if (try joined(t, path, p.value)) |l| try t.flag("--tx-deny", try std.fmt.allocPrint(t.arena, "{s}={s}", .{ p.key, l }));
            } else if (isIn(deny_bools, p.key)) {
                if (try t.boolean(path, p.value)) |b| try t.flag("--tx-deny", try std.fmt.allocPrint(t.arena, "{s}={}", .{ p.key, b }));
            } else if (std.mem.eql(u8, p.key, "dynamic-transaction-checks")) {
                try t.note(.warn, "{s}: deepwave evaluates constant Starlark programs only (True, False, integers, a // b); others pass", .{path});
                if (try t.str(path, p.value)) |prog| try t.flag("--tx-deny", try std.fmt.allocPrint(t.arena, "dynamic-transaction-checks={s}", .{prog}));
            } else try t.note(.warn, "{s}: unknown key; ignored (sui-node ignores it too)", .{path});
        }
    }

    /// sui-config `TransactionDriverConfig`: `enable-early-validation` (default true) maps to
    /// `--early-validation false`; the submission validator allow/block lists are not built.
    fn driverKeys(t: *T, v: Value) !void {
        for (mapOr(t, "transaction-driver-config", v)) |p| {
            const path = try std.fmt.allocPrint(t.arena, "transaction-driver-config.{s}", .{p.key});
            if (std.mem.eql(u8, p.key, "enable-early-validation")) {
                if (try t.boolean(path, p.value)) |b| if (!b) try t.flag("--early-validation", "false");
            } else if (std.mem.eql(u8, p.key, "allowed-submission-validators") or std.mem.eql(u8, p.key, "blocked-submission-validators")) {
                try t.note(.warn, "{s}: deepwave submits to every validator (no allow/block lists); ignored", .{path});
            } else try t.note(.warn, "{s}: unknown key; ignored", .{path});
        }
    }

    const policy_ints = [_][]const u8{ "connection-blocklist-ttl-sec", "proxy-blocklist-ttl-sec", "channel-capacity" };
    const freq_keys = [_][]const u8{ "client-threshold", "proxied-client-threshold", "window-size-secs", "update-interval-secs", "sketch-capacity", "sketch-probability", "sketch-tolerance" };

    fn policyKeys(t: *T, v: Value) !void {
        // `policy-config: null` is sui-node's kill switch (no traffic controller)
        if (v == .null) return t.flag("--policy", "off");
        const m = mapOr(t, "policy-config", v);
        // a section without keys still replaces the default DoS policy by serde's defaults
        if (m.len == 0) return t.flag("--policy", "dry-run=true");
        for (m) |p| {
            const path = try std.fmt.allocPrint(t.arena, "policy-config.{s}", .{p.key});
            if (isIn(policy_ints, p.key)) {
                if (try t.int(path, p.value)) |n| try t.flag("--policy", try std.fmt.allocPrint(t.arena, "{s}={d}", .{ p.key, n }));
            } else if (std.mem.eql(u8, p.key, "dry-run")) {
                if (try t.boolean(path, p.value)) |b| try t.flag("--policy", try std.fmt.allocPrint(t.arena, "dry-run={}", .{b}));
            } else if (std.mem.eql(u8, p.key, "spam-sample-rate")) {
                if (try t.str(path, p.value)) |s| try t.flag("--policy", try std.fmt.allocPrint(t.arena, "spam-sample-rate={s}", .{s}));
            } else if (std.mem.eql(u8, p.key, "allow-list")) {
                if (p.value == .null) continue;
                if (try joined(t, path, p.value)) |l| try t.flag("--policy", try std.fmt.allocPrint(t.arena, "allow-list={s}", .{l}));
            } else if (std.mem.eql(u8, p.key, "client-id-source")) {
                switch (p.value) {
                    .scalar => |s| try t.flag("--policy", try std.fmt.allocPrint(t.arena, "client-id-source={s}", .{s})),
                    .map => {
                        const hops = if (p.value.get("x-forwarded-for")) |h| try t.int("policy-config.client-id-source.x-forwarded-for", h) else null;
                        if (hops) |n| {
                            try t.flag("--policy", try std.fmt.allocPrint(t.arena, "client-id-source=x-forwarded-for:{d}", .{n}));
                        } else try t.note(.warn, "{s}: expected socket-addr or x-forwarded-for: N; ignored", .{path});
                    },
                    else => try t.note(.warn, "{s}: expected socket-addr or x-forwarded-for: N; ignored", .{path}),
                }
            } else if (std.mem.eql(u8, p.key, "spam-policy-type") or std.mem.eql(u8, p.key, "error-policy-type")) {
                switch (p.value) {
                    .scalar => |s| {
                        if (std.mem.eql(u8, s, "NoOp")) {
                            try t.flag("--policy", try std.fmt.allocPrint(t.arena, "{s}=no-op", .{p.key}));
                        } else try t.note(.warn, "{s}: {s}: deepwave knows NoOp and freq-threshold; ignored", .{ path, s });
                    },
                    .map => |pm| for (pm) |q| {
                        if (!std.mem.eql(u8, q.key, "freq-threshold") and !std.mem.eql(u8, q.key, "FreqThreshold")) {
                            try t.note(.warn, "{s}.{s}: deepwave knows NoOp and freq-threshold (test policies are not built); ignored", .{ path, q.key });
                            continue;
                        }
                        try t.flag("--policy", try std.fmt.allocPrint(t.arena, "{s}=freq-threshold", .{p.key}));
                        for (mapOr(t, path, q.value)) |r| {
                            const sub = try std.fmt.allocPrint(t.arena, "{s}.{s}", .{ path, r.key });
                            if (!isIn(freq_keys, r.key)) {
                                try t.note(.warn, "{s}: unknown key; ignored", .{sub});
                                continue;
                            }
                            if (try t.str(sub, r.value)) |s| try t.flag("--policy", try std.fmt.allocPrint(t.arena, "{s}.{s}={s}", .{ p.key, r.key, s }));
                        }
                    },
                    else => try t.note(.warn, "{s}: expected NoOp or freq-threshold: {{...}}; ignored", .{path}),
                }
            } else try t.note(.warn, "{s}: unknown key; ignored (sui-node ignores it too)", .{path});
        }
    }
};

fn mapOr(t: *T, path: []const u8, v: Value) []const Pair {
    return switch (v) {
        .map => |m| m,
        .null => &.{},
        else => blk: {
            t.note(.warn, "{s}: expected a mapping; ignored", .{path}) catch {};
            break :blk &.{};
        },
    };
}

fn rpcKeys(t: *T, v: Value) !void {
    var tls_seen = false;
    var tls_cert: ?[]const u8 = null;
    var tls_key: ?[]const u8 = null;
    var https: ?[]const u8 = null;
    for (mapOr(t, "rpc", v)) |p| {
        if (std.mem.eql(u8, p.key, "enable-indexing")) {
            if (try t.boolean("rpc.enable-indexing", p.value)) |b| if (b) try t.flag("--indexes", null);
        } else if (std.mem.eql(u8, p.key, "ledger-history")) {
            for (mapOr(t, "rpc.ledger-history", p.value)) |q| {
                const lists = [_][]const u8{ "list-transactions", "list-events", "list-checkpoints" };
                const is_list = for (lists) |l| {
                    if (std.mem.eql(u8, q.key, l)) break true;
                } else false;
                if (is_list) {
                    for (mapOr(t, q.key, q.value)) |r| {
                        const path = try std.fmt.allocPrint(t.arena, "{s}.{s}", .{ q.key, r.key });
                        if (!ledgerKeyKnown(path)) {
                            try t.note(.warn, "rpc.ledger-history.{s}: unknown key; ignored", .{path});
                            continue;
                        }
                        if (try t.int(path, r.value)) |n| try t.flag("--ledger-history", try std.fmt.allocPrint(t.arena, "{s}={d}", .{ path, n }));
                    }
                } else if (ledgerKeyKnown(q.key)) {
                    if (try t.int(q.key, q.value)) |n| try t.flag("--ledger-history", try std.fmt.allocPrint(t.arena, "{s}={d}", .{ q.key, n }));
                } else try t.note(.warn, "rpc.ledger-history.{s}: unknown key; ignored", .{q.key});
            }
        } else if (std.mem.eql(u8, p.key, "tls")) {
            for (mapOr(t, "rpc.tls", p.value)) |q| {
                if (std.mem.eql(u8, q.key, "cert")) {
                    tls_cert = try t.str("rpc.tls.cert", q.value);
                } else if (std.mem.eql(u8, q.key, "key")) {
                    tls_key = try t.str("rpc.tls.key", q.value);
                } else try t.note(.warn, "rpc.tls.{s}: unknown key; ignored", .{q.key});
            }
            tls_seen = true;
        } else if (std.mem.eql(u8, p.key, "https-address")) {
            https = try t.str("rpc.https-address", p.value);
        } else if (findName(&rpc_scalars, p.key)) {
            const path = try std.fmt.allocPrint(t.arena, "rpc.{s}", .{p.key});
            if (try t.int(path, p.value)) |n| try t.flag("--rpc", try std.fmt.allocPrint(t.arena, "{s}={d}", .{ p.key, n }));
        } else if (std.mem.eql(u8, p.key, "max-json-move-value-size") or std.mem.eql(u8, p.key, "max-json-move-value-response-size")) {
            const default: u64 = if (p.key.len == "max-json-move-value-size".len) 1024 * 1024 else 16 * 1024 * 1024;
            const path = try std.fmt.allocPrint(t.arena, "rpc.{s}", .{p.key});
            if (try t.int(path, p.value)) |n| {
                if (n != default) try t.note(.warn, "rpc.{s} {d}: deepwave renders with sui-node's default {d}; ignored", .{ p.key, n, default });
            }
        } else if (std.mem.eql(u8, p.key, "subscription-shards")) {
            try t.note(.info, "rpc.subscription-shards: deepwave's subscription hub sizes its own fan-out; ignored", .{});
        } else if (std.mem.eql(u8, p.key, "index-initialization")) {
            try t.note(.info, "rpc.index-initialization: deepwave builds its indexes with its own loaders (ZUI_INDEX_BUILD_*); ignored", .{});
        } else {
            try t.note(.warn, "rpc.{s}: not settable in deepwave (render budgets are sui-node's defaults); ignored", .{p.key});
        }
    }
    // sui-node lib.rs `build_http_servers`: an https listener only when `rpc.tls` is set, on
    // `https-address` (default 0.0.0.0:9443); both files must load or the node does not start.
    if (tls_seen) {
        if (tls_cert == null or tls_key == null) {
            try t.note(.warn, "rpc.tls: needs both cert and key (sui-node refuses the config); no https listener", .{});
        } else {
            try t.flag("--serve-tls", https orelse default_https_address);
            try t.flag("--serve-tls-cert", tls_cert.?);
            try t.flag("--serve-tls-key", tls_key.?);
        }
    } else if (https) |h| {
        try t.note(.info, "rpc.https-address {s}: no rpc.tls, so no https listener (as sui-node); ignored", .{h});
    }
}

pub const ledger_keys = [_][]const u8{
    "list-transactions.timeout-ms", "list-transactions.default-limit-items", "list-transactions.max-limit-items", "list-transactions.chunk-max",
    "list-events.timeout-ms",       "list-events.default-limit-items",       "list-events.max-limit-items",       "list-events.chunk-max",
    "list-checkpoints.timeout-ms",  "list-checkpoints.default-limit-items",  "list-checkpoints.max-limit-items",  "list-checkpoints.chunk-max",
    "bitmap-bucket-scan-budget",    "chunk-bucket-scan-budget",              "max-bitmap-filter-literals",
};

fn ledgerKeyKnown(k: []const u8) bool {
    for (ledger_keys) |x| if (std.mem.eql(u8, x, k)) return true;
    return false;
}

fn p2pOpt(t: *T, key: []const u8, value: []const u8) !void {
    const f = t.opts.p2p_opt_flag orelse {
        try t.note(.warn, "p2p-config.{s}: this deepwave build has no p2p tuning flag; ignored", .{key});
        return;
    };
    try t.flag(f, try std.fmt.allocPrint(t.arena, "{s}={s}", .{ key, value }));
}

/// A `p2p-config` scalar under `section` (`discovery`, `state-sync`, or "" for the top level)
/// that p2p_config.zig takes: emitted as `--p2p-opt section.key=value`.
fn p2pScalar(t: *T, section: []const u8, k: []const u8, v: Value) !void {
    const key = if (section.len == 0) k else try std.fmt.allocPrint(t.arena, "{s}.{s}", .{ section, k });
    if (!p2p_config.known(key)) {
        try t.note(.warn, "p2p-config.{s}: unknown key; ignored", .{key});
        return;
    }
    for (p2p_config.no_effect) |x| if (std.mem.eql(u8, x, key)) {
        try t.note(.info, "p2p-config.{s}: a sui-node internal (deepwave sizes its own queues and timeouts); ignored", .{key});
        return;
    };
    const s = (try t.str(try std.fmt.allocPrint(t.arena, "p2p-config.{s}", .{key}), v)) orelse return;
    var test_t: p2p_config.Tuning = .{};
    p2p_config.set(&test_t, try std.fmt.allocPrint(t.arena, "{s}={s}", .{ key, s })) catch {
        try t.note(.warn, "p2p-config.{s}: {s} is not a valid value; ignored", .{ key, s });
        return;
    };
    try p2pOpt(t, key, s);
}

fn p2pKeys(t: *T, v: Value) !void {
    for (mapOr(t, "p2p-config", v)) |p| {
        if (std.mem.eql(u8, p.key, "seed-peers")) {
            const items = switch (p.value) {
                .seq => |s| s,
                .null => &[_]Value{},
                else => {
                    try t.note(.warn, "p2p-config.seed-peers: expected a list; ignored", .{});
                    continue;
                },
            };
            var list: std.ArrayList(u8) = .empty;
            for (items) |it| {
                const addr = if (it.get("address")) |a| try t.str("seed-peers.address", a) else null;
                const hp = if (addr) |a| try multiaddrHostPort(t.arena, a) else null;
                if (hp == null) {
                    try t.note(.warn, "p2p-config.seed-peers: entry without a /dns|ip4|ip6/HOST/udp/PORT address; skipped", .{});
                    continue;
                }
                if (list.items.len > 0) try list.append(t.arena, ',');
                try list.appendSlice(t.arena, hp.?);
                if (it.get("peer-id")) |pid| if (try t.str("seed-peers.peer-id", pid)) |s| {
                    try list.append(t.arena, '@');
                    try list.appendSlice(t.arena, s);
                };
            }
            if (list.items.len == 0) continue;
            if (t.opts.p2p_seeds_flag) |f| {
                try t.flag(f, list.items);
            } else try t.note(.warn, "p2p-config.seed-peers ({d}): this deepwave build has no p2p state sync; it follows the archive and live streams", .{items.len});
        } else if (std.mem.eql(u8, p.key, "listen-address")) {
            // sui-node binds 0.0.0.0:8084 when the key is absent; deepwave listens only when it is
            // set (or with --p2p-listen), and `--p2p-listen off` on the command line wins.
            if (try t.str("p2p-config.listen-address", p.value)) |s| {
                if (t.opts.p2p_listen_flag) |f| try t.flag(f, s) else try t.note(.warn, "p2p-config.listen-address {s}: this deepwave build has no p2p server; ignored", .{s});
            }
        } else if (std.mem.eql(u8, p.key, "external-address")) {
            if (try t.str("p2p-config.external-address", p.value)) |s| {
                if (t.opts.p2p_external_flag) |f| try t.flag(f, s) else try t.note(.warn, "p2p-config.external-address {s}: this deepwave build has no p2p server; ignored", .{s});
            }
        } else if (std.mem.eql(u8, p.key, "peer-address-overrides")) {
            // [{peer-id, addresses: [multiaddr, ...]}] -> PEERID@A|B,...
            var list: std.ArrayList(u8) = .empty;
            const items = if (p.value == .seq) p.value.seq else &[_]Value{};
            for (items) |it| {
                const pid = if (it.get("peer-id")) |x| try t.str("peer-address-overrides.peer-id", x) else null;
                const addrs = if (it.get("addresses")) |x| (if (x == .seq) x.seq else &[_]Value{}) else &[_]Value{};
                if (pid == null or addrs.len == 0) {
                    try t.note(.warn, "p2p-config.peer-address-overrides: entry without peer-id or addresses; skipped", .{});
                    continue;
                }
                if (list.items.len > 0) try list.append(t.arena, ',');
                try list.appendSlice(t.arena, pid.?);
                for (addrs, 0..) |x, j| if (try t.str("peer-address-overrides.addresses", x)) |s| {
                    try list.append(t.arena, if (j == 0) '@' else '|');
                    try list.appendSlice(t.arena, s);
                };
            }
            if (list.items.len > 0) try p2pOpt(t, "peer-address-overrides", list.items);
        } else if (std.mem.eql(u8, p.key, "discovery")) {
            for (mapOr(t, "p2p-config.discovery", p.value)) |d| {
                if (std.mem.eql(u8, d.key, "access-type")) {
                    const s = (try t.str("p2p-config.discovery.access-type", d.value)) orelse continue;
                    const at = p2p_config.parseAccess(s) orelse {
                        try t.note(.warn, "p2p-config.discovery.access-type {s}: not Public, Private or Trusted; ignored", .{s});
                        continue;
                    };
                    if (t.opts.p2p_access_flag) |f| try t.flag(f, @tagName(at)) else try t.note(.warn, "p2p-config.discovery.access-type: this deepwave build has no access flag; ignored", .{});
                } else if (std.mem.eql(u8, d.key, "allowlisted-peers")) {
                    // [{peer-id, address?}] -> PEERID[@MULTIADDR],...
                    var list: std.ArrayList(u8) = .empty;
                    const items = if (d.value == .seq) d.value.seq else &[_]Value{};
                    for (items) |it| {
                        const pid = (if (it.get("peer-id")) |x| try t.str("allowlisted-peers.peer-id", x) else null) orelse {
                            try t.note(.warn, "p2p-config.discovery.allowlisted-peers: entry without peer-id; skipped", .{});
                            continue;
                        };
                        if (list.items.len > 0) try list.append(t.arena, ',');
                        try list.appendSlice(t.arena, pid);
                        if (it.get("address")) |x| if (try t.str("allowlisted-peers.address", x)) |s| {
                            try list.append(t.arena, '@');
                            try list.appendSlice(t.arena, s);
                        };
                    }
                    if (list.items.len > 0) try p2pOpt(t, "discovery.allowlisted-peers", list.items);
                } else try p2pScalar(t, "discovery", d.key, d.value);
            }
        } else if (std.mem.eql(u8, p.key, "state-sync")) {
            for (mapOr(t, "p2p-config.state-sync", p.value)) |d| {
                if (std.mem.eql(u8, d.key, "pinned-checkpoints")) {
                    // Vec<(seq, digest)>: `- - 123` / `  - Digest` or `- [123, Digest]`
                    var list: std.ArrayList(u8) = .empty;
                    const items = if (d.value == .seq) d.value.seq else &[_]Value{};
                    for (items) |it| {
                        if (it != .seq or it.seq.len != 2 or it.seq[0] != .scalar or it.seq[1] != .scalar) {
                            try t.note(.warn, "p2p-config.state-sync.pinned-checkpoints: entry is not [sequence-number, digest]; skipped", .{});
                            continue;
                        }
                        if (list.items.len > 0) try list.append(t.arena, ',');
                        try list.print(t.arena, "{s}:{s}", .{ it.seq[0].scalar, it.seq[1].scalar });
                    }
                    if (list.items.len == 0) continue;
                    if (t.opts.p2p_pinned_flag) |f| try t.flag(f, list.items) else try t.note(.warn, "p2p-config.state-sync.pinned-checkpoints: this deepwave build has no pinned-checkpoints flag; ignored", .{});
                } else try p2pScalar(t, "state-sync", d.key, d.value);
            }
        } else if (std.mem.eql(u8, p.key, "excessive-message-size")) {
            try p2pScalar(t, "", p.key, p.value);
        } else if (std.mem.eql(u8, p.key, "anemo-config")) {
            try t.note(.info, "p2p-config.anemo-config: deepwave's QUIC and anemo settings are sui-node 1.83.1's defaults (1 MiB requests, 128 MiB responses, 500 streams, 100/200 MiB windows); ignored", .{});
        } else if (std.mem.eql(u8, p.key, "randomness")) {
            try t.note(.info, "p2p-config.randomness: validator randomness (a full node answers SendSignatures with 404); ignored", .{});
        } else {
            try t.note(.warn, "p2p-config.{s}: unknown key; ignored", .{p.key});
        }
    }
}

fn pruningKeys(t: *T, v: Value) !void {
    var ckpt: ?u64 = null;
    var objs: ?u64 = null;
    for (mapOr(t, "authority-store-pruning-config", v)) |p| {
        if (std.mem.eql(u8, p.key, "num-epochs-to-retain-for-checkpoints")) {
            ckpt = try t.int("num-epochs-to-retain-for-checkpoints", p.value);
        } else if (std.mem.eql(u8, p.key, "num-epochs-to-retain")) {
            objs = try t.int("num-epochs-to-retain", p.value);
        } else {
            try t.note(.info, "authority-store-pruning-config.{s}: RocksDB pruner tuning; deepwave's segment cleaning has its own budget; ignored", .{p.key});
        }
    }
    // sui-node: checkpoints unset = kept forever (minimum 2 when set).
    const keep_ckpt: u64 = if (ckpt) |c| @max(c, 2) else std.math.maxInt(u32);
    if (ckpt == null) try t.note(.info, "num-epochs-to-retain-for-checkpoints unset: sui-node keeps every checkpoint; deepwave keeps all epochs too (--retention-epochs {d})", .{keep_ckpt});
    if (t.opts.object_retention_flag) |f| {
        try t.flag("--retention-epochs", try std.fmt.allocPrint(t.arena, "{d}", .{keep_ckpt}));
        if (objs) |o| try t.flag(f, try std.fmt.allocPrint(t.arena, "{d}", .{o}));
    } else {
        // One knob for checkpoints and object versions: the larger window, so deepwave never serves
        // less than sui-node would.
        const keep = @max(keep_ckpt, objs orelse 0);
        try t.flag("--retention-epochs", try std.fmt.allocPrint(t.arena, "{d}", .{keep}));
        if (objs) |o| if (o != keep) try t.note(.info, "num-epochs-to-retain {d}: deepwave keeps object versions as long as checkpoints ({d} epochs; one retention knob)", .{ o, keep });
    }
}

fn archiveKeys(t: *T, v: Value) !void {
    const items = switch (v) {
        .seq => |s| s,
        .map => &[_]Value{v},
        .null => &[_]Value{},
        else => {
            try t.note(.warn, "state-archive-read-config: expected a list; ignored", .{});
            return;
        },
    };
    var used = false;
    for (items, 0..) |it, i| {
        for (mapOr(t, "state-archive-read-config[]", it)) |p| {
            if (std.mem.eql(u8, p.key, "ingestion-url")) {
                const url = (try t.str("ingestion-url", p.value)) orelse continue;
                if (used) {
                    try t.note(.warn, "state-archive-read-config[{d}].ingestion-url {s}: deepwave reads one archive; ignored", .{ i, url });
                    continue;
                }
                used = true;
                const trimmed = std.mem.trimEnd(u8, url, "/");
                if (std.mem.eql(u8, trimmed, mainnet_archive)) {
                    try t.flag("--source", "http");
                } else if (std.mem.startsWith(u8, url, "http://") or std.mem.startsWith(u8, url, "https://")) {
                    try t.flag("--source", try std.fmt.allocPrint(t.arena, "http:{s}", .{trimmed}));
                } else try t.note(.warn, "state-archive-read-config ingestion-url {s}: not an http(s) URL; ignored", .{url});
            } else if (std.mem.eql(u8, p.key, "concurrency")) {
                try t.note(.info, "state-archive-read-config.concurrency: deepwave sizes its fetchers itself (--fetchers); ignored", .{});
            } else if (std.mem.eql(u8, p.key, "use-for-pruning-watermark")) {
                try t.note(.info, "state-archive-read-config.use-for-pruning-watermark: ignored", .{});
            } else {
                try t.note(.warn, "state-archive-read-config.{s}: deepwave reads the archive over http (--source s3 for the requester-pays bucket); ignored", .{p.key});
            }
        }
    }
}

fn snapshotWriteKeys(t: *T, v: Value) !void {
    for (mapOr(t, "state-snapshot-write-config", v)) |p| {
        if (std.mem.eql(u8, p.key, "object-store-config")) {
            const kind = if (p.value.get("object-store")) |x| try t.str("object-store", x) else null;
            const dir = if (p.value.get("directory")) |x| try t.str("directory", x) else null;
            if (kind != null and std.mem.eql(u8, kind.?, "File") and dir != null) {
                try t.flag("--snapshot-write", dir.?);
            } else try t.note(.warn, "state-snapshot-write-config.object-store-config: deepwave writes snapshots to a local directory only (object-store: File, directory: PATH); upload them with your own sync; ignored", .{});
        } else if (std.mem.eql(u8, p.key, "concurrency") or std.mem.eql(u8, p.key, "archive-interval-epochs")) {
            try t.note(.info, "state-snapshot-write-config.{s}: ignored", .{p.key});
        } else try t.note(.warn, "state-snapshot-write-config.{s}: unknown key; ignored", .{p.key});
    }
}

pub fn translate(arena: std.mem.Allocator, text: []const u8, opts: Options) !Translation {
    var line: usize = 0;
    const root = parse(arena, text, &line) catch |e| switch (e) {
        error.YamlSyntax => {
            std.log.err("fullnode.yaml: line {d}: YAML deepwave cannot read", .{line});
            return e;
        },
        else => return e,
    };
    return translateValue(arena, root, opts);
}

pub fn looksLikeYaml(path: []const u8) bool {
    return std.mem.endsWith(u8, path, ".yaml") or std.mem.endsWith(u8, path, ".yml");
}

// ------------------------------------------------------------------ tests

fn argsJoined(arena: std.mem.Allocator, tr: Translation) ![]const u8 {
    return std.mem.join(arena, " ", tr.args);
}

fn hasNote(tr: Translation, level: Level, needle: []const u8) bool {
    for (tr.notes) |n| if (n.level == level and std.mem.indexOf(u8, n.text, needle) != null) return true;
    return false;
}

test "fullnode.yaml: a production node's file maps to the equivalent zui flags" {
    var ar: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const tr = try translate(a, @embedFile("testdata/fullnode-box.yaml"), .{});
    const got = try argsJoined(a, tr);
    try std.testing.expectEqualStrings(
        "--dir /opt/sui/db --metrics 127.0.0.1:9184 --serve 0.0.0.0:9000 --indexes " ++
            "--ledger-history list-transactions.timeout-ms=5000 --ledger-history list-transactions.default-limit-items=50 --ledger-history list-transactions.max-limit-items=500 --ledger-history list-transactions.chunk-max=32 " ++
            "--ledger-history list-events.timeout-ms=5000 --ledger-history list-events.default-limit-items=50 --ledger-history list-events.max-limit-items=1000 --ledger-history list-events.chunk-max=32 " ++
            "--ledger-history list-checkpoints.timeout-ms=5000 --ledger-history list-checkpoints.default-limit-items=10 --ledger-history list-checkpoints.max-limit-items=100 --ledger-history list-checkpoints.chunk-max=16 " ++
            "--ledger-history bitmap-bucket-scan-budget=1024 --ledger-history chunk-bucket-scan-budget=256 --ledger-history max-bitmap-filter-literals=10 " ++
            "--genesis /opt/sui/config/genesis.blob --retention-epochs 2 --source http",
        got,
    );
    // p2p is reported, never fatal, in a build without it
    try std.testing.expect(hasNote(tr, .warn, "seed-peers (10)"));
    try std.testing.expect(hasNote(tr, .warn, "listen-address 0.0.0.0:8084"));
    try std.testing.expect(hasNote(tr, .info, "network-address"));
    try std.testing.expect(hasNote(tr, .info, "enable-index-processing"));
    // no unknown keys in the box's file
    for (tr.notes) |n| try std.testing.expect(std.mem.indexOf(u8, n.text, "unknown key") == null);
}

test "fullnode.yaml: p2p, admin and split retention flags when the build has them" {
    var ar: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const tr = try translate(a, @embedFile("testdata/fullnode-box.yaml"), .{ .p2p_seeds_flag = "--p2p", .p2p_listen_flag = "--p2p-listen", .p2p_external_flag = "--p2p-external", .object_retention_flag = "--retention-object-epochs" });
    const got = try argsJoined(a, tr);
    try std.testing.expect(std.mem.indexOf(u8, got, "--p2p mel-00.mainnet.sui.io:8084@d32b55bdf1737ec415df8c88b3bf91e194b59ee3127e3f38ea46fd88ba2e7849,ewr-00.mainnet.sui.io:8084@") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "--p2p-listen 0.0.0.0:8084 --p2p-external /ip4/203.0.113.8/udp/8084") != null);
    try std.testing.expect(std.mem.indexOf(u8, got, "--retention-epochs 2 --retention-object-epochs 1") != null);
}

test "fullnode.yaml: the whole p2p-config section maps to p2p flags" {
    var ar: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const text =
        \\p2p-config:
        \\  listen-address: 0.0.0.0:8084
        \\  excessive-message-size: 1048576
        \\  peer-address-overrides:
        \\    - peer-id: d32b55bdf1737ec415df8c88b3bf91e194b59ee3127e3f38ea46fd88ba2e7849
        \\      addresses:
        \\        - /ip4/10.0.0.1/udp/8084
        \\        - /dns/x.example/udp/8084
        \\  anemo-config:
        \\    max-frame-size: 1
        \\  discovery:
        \\    access-type: Private
        \\    peer-failure-cooldown-ms: 60000
        \\    mailbox-capacity: 10
        \\    allowlisted-peers:
        \\      - peer-id: c7bf6cb93ca8fdda655c47ebb85ace28e6931464564332bf63e27e90199c50ee
        \\        address: /ip4/10.0.0.2/udp/8084
        \\  state-sync:
        \\    use-get-checkpoint-contents-v2: false
        \\    pinned-checkpoints:
        \\      - - 1000
        \\        - 4fFvo2ZbJeKxJzWsNMFsuUm1jMAFZYzhFQyMmRzRtLeB
        \\      - [2000, 8rvKTV6iS9sYV8RyEUCkHAfkTUGqH8TvTEoZXFh5V9n4]
        \\    bogus-key: 1
    ;
    const tr = try translate(a, text, .{ .p2p_listen_flag = "--p2p-listen", .p2p_opt_flag = "--p2p-opt", .p2p_access_flag = "--p2p-access", .p2p_pinned_flag = "--p2p-pinned" });
    const got = try argsJoined(a, tr);
    const want = [_][]const u8{
        "--p2p-listen 0.0.0.0:8084",
        "--p2p-opt excessive-message-size=1048576",
        "--p2p-opt peer-address-overrides=d32b55bdf1737ec415df8c88b3bf91e194b59ee3127e3f38ea46fd88ba2e7849@/ip4/10.0.0.1/udp/8084|/dns/x.example/udp/8084",
        "--p2p-access private",
        "--p2p-opt discovery.peer-failure-cooldown-ms=60000",
        "--p2p-opt discovery.allowlisted-peers=c7bf6cb93ca8fdda655c47ebb85ace28e6931464564332bf63e27e90199c50ee@/ip4/10.0.0.2/udp/8084",
        "--p2p-opt state-sync.use-get-checkpoint-contents-v2=false",
        "--p2p-pinned 1000:4fFvo2ZbJeKxJzWsNMFsuUm1jMAFZYzhFQyMmRzRtLeB,2000:8rvKTV6iS9sYV8RyEUCkHAfkTUGqH8TvTEoZXFh5V9n4",
    };
    for (want) |w| if (std.mem.indexOf(u8, got, w) == null) {
        std.debug.print("missing {s} in {s}\n", .{ w, got });
        return error.TestUnexpectedResult;
    };
    try std.testing.expect(hasNote(tr, .info, "discovery.mailbox-capacity"));
    try std.testing.expect(hasNote(tr, .info, "anemo-config"));
    try std.testing.expect(hasNote(tr, .warn, "state-sync.bogus-key: unknown key"));
}

test "fullnode.yaml: Mysten's template (no checkpoint retention = keep every epoch)" {
    var ar: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const tr = try translate(a, @embedFile("testdata/fullnode-template.yaml"), .{});
    const got = try argsJoined(a, tr);
    // the template's placeholder archive URL is passed through as written
    try std.testing.expectEqualStrings("--dir /opt/sui/db --metrics 0.0.0.0:9184 --serve 0.0.0.0:9000 --genesis /opt/sui/config/genesis.blob --retention-epochs 4294967295 --source http:https://checkpoints.<mainnet|testnet>.sui.io", got);
    try std.testing.expect(hasNote(tr, .info, "keeps every checkpoint"));
}

test "fullnode.yaml: unknown keys warn and never fail; YAML forms" {
    var ar: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const text =
        \\--- # doc start
        \\db-path: '/data/it''s'   # quoted, with a comment
        \\no-such-key: {a: 1, b: [x, "y z"]}
        \\enable-db-sync-to-disk: true
        \\run-with-range: { checkpoint: 1234 }
        \\state-snapshot-write-config:
        \\  object-store-config:
        \\    object-store: "File"
        \\    directory: /snapshots
        \\  concurrency: 5
        \\transaction-deny-config:
        \\  package-deny-list: []
        \\p2p-config:
        \\  seed-peers:
        \\  - address: /ip4/1.2.3.4/udp/8084
        \\  - address: /ip6/::1/udp/8084
        \\    peer-id: ab
        \\  state-sync:
        \\    checkpoint-content-timeout-ms: 10000
        \\admin-interface-port: 1337
        \\rpc:
        \\  ledger-history:
        \\    bogus: 1
        \\notes: |
        \\  line one
        \\  line two
    ;
    const tr = try translate(a, text, .{ .p2p_seeds_flag = "--p2p", .admin_flag = "--admin" });
    const got = try argsJoined(a, tr);
    try std.testing.expectEqualStrings("--dir /data/it's --sync full --to 1234 --snapshot-write /snapshots --tx-deny package-deny-list= --p2p 1.2.3.4:8084,[::1]:8084@ab --admin 127.0.0.1:1337 --serve 0.0.0.0:9000", got);
    try std.testing.expect(hasNote(tr, .warn, "no-such-key: unknown key"));
    try std.testing.expect(hasNote(tr, .warn, "notes: unknown key"));
    try std.testing.expect(!hasNote(tr, .warn, "transaction-deny-config"));
    try std.testing.expect(hasNote(tr, .info, "p2p-config.state-sync.checkpoint-content-timeout-ms"));
    try std.testing.expect(hasNote(tr, .warn, "ledger-history.bogus"));
}

test "fullnode.yaml: transaction-deny-config and policy-config map to --tx-deny and --policy" {
    var ar = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const text =
        \\transaction-deny-config:
        \\  object-deny-list:
        \\    - "0x0a"
        \\    - "0x0b"
        \\  package-publish-disabled: true
        \\  zklogin-disabled-providers: [Google, Apple]
        \\  bogus: 1
        \\policy-config:
        \\  client-id-source:
        \\    x-forwarded-for: 2
        \\  dry-run: false
        \\  spam-policy-type:
        \\    freq-threshold:
        \\      client-threshold: 7
        \\      window-size-secs: 4
        \\  error-policy-type: NoOp
        \\  connection-blocklist-ttl-sec: 9
        \\
    ;
    const tr = try translate(a, text, .{});
    try std.testing.expectEqualStrings("--tx-deny object-deny-list=0x0a,0x0b --tx-deny package-publish-disabled=true --tx-deny zklogin-disabled-providers=Google,Apple " ++
        "--policy client-id-source=x-forwarded-for:2 --policy dry-run=false --policy spam-policy-type=freq-threshold --policy spam-policy-type.client-threshold=7 " ++
        "--policy spam-policy-type.window-size-secs=4 --policy error-policy-type=no-op --policy connection-blocklist-ttl-sec=9 --serve 0.0.0.0:9000", try argsJoined(a, tr));
    try std.testing.expect(hasNote(tr, .warn, "transaction-deny-config.bogus: unknown key"));
    const off = try translate(a, "policy-config: null\n", .{});
    try std.testing.expectEqualStrings("--policy off --serve 0.0.0.0:9000", try argsJoined(a, off));
}

test "fullnode.yaml: transaction-driver-config enable-early-validation maps to --early-validation" {
    var ar = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const off = try translate(a, "transaction-driver-config:\n  enable-early-validation: false\n  blocked-submission-validators: [v1]\n", .{});
    try std.testing.expectEqualStrings("--early-validation false --serve 0.0.0.0:9000", try argsJoined(a, off));
    try std.testing.expect(hasNote(off, .warn, "transaction-driver-config.blocked-submission-validators"));
    // true is sui-node's default: no flag (only the default RPC address)
    const on = try translate(a, "json-rpc-address: 127.0.0.1:9000\ntransaction-driver-config:\n  enable-early-validation: true\n", .{});
    try std.testing.expectEqualStrings("--serve 127.0.0.1:9000", try argsJoined(a, on));
    try std.testing.expectEqual(@as(usize, 0), on.notes.len);
}

test "fullnode.yaml: zui section sets the rpc index and ledger-history paths" {
    var ar = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer ar.deinit();
    const tr = try translate(ar.allocator(), "db-path: /opt/sui/db\nzui:\n  rpc-index-path: /var/lib/zui/rpc\n  ledger-history-path: \"/var/lib/zui/lh\"\n  bogus: 1\n", .{});
    const want = [_][]const u8{ "--dir", "/opt/sui/db", "--rpc-index-dir", "/var/lib/zui/rpc", "--ledger-history-dir", "/var/lib/zui/lh", "--serve", "0.0.0.0:9000" };
    try std.testing.expectEqual(want.len, tr.args.len);
    for (want, tr.args) |w, a| try std.testing.expectEqualStrings(w, a);
    try std.testing.expectEqual(@as(usize, 2), tr.notes.len); // zui.bogus, the default json-rpc-address
}

test "fullnode.yaml: rpc tls, https-address, timeouts and the validator-only grpc limits" {
    var ar = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    // the rpc-surface capture variants (src/serve/vectors/rpc-surface/configs/{tls,timeout,limits}.yaml)
    const tls = try translate(a, @embedFile("testdata/rpc-surface-tls.yaml"), .{});
    const got = try argsJoined(a, tls);
    try std.testing.expect(std.mem.indexOf(u8, got, "--serve 127.0.0.1:9102 ") != null);
    try std.testing.expect(std.mem.endsWith(u8, got, "--indexes --serve-tls 127.0.0.1:9502 --serve-tls-cert /home/ubuntu/cfg/tls/cert.pem --serve-tls-key /home/ubuntu/cfg/tls/key.pem"));
    // https-address defaults to 0.0.0.0:9443; without tls it does nothing
    const dflt = try translate(a, "json-rpc-address: 0.0.0.0:9000\nrpc:\n  tls: {cert: /c.pem, key: /k.pem}\n", .{});
    try std.testing.expectEqualStrings("--serve 0.0.0.0:9000 --serve-tls 0.0.0.0:9443 --serve-tls-cert /c.pem --serve-tls-key /k.pem", try argsJoined(a, dflt));
    const no_tls = try translate(a, "json-rpc-address: 0.0.0.0:9000\nrpc:\n  https-address: 0.0.0.0:9443\n", .{});
    try std.testing.expectEqualStrings("--serve 0.0.0.0:9000", try argsJoined(a, no_tls));
    try std.testing.expect(hasNote(no_tls, .info, "no rpc.tls"));
    const half = try translate(a, "json-rpc-address: 0.0.0.0:9000\nrpc:\n  tls:\n    cert: /c.pem\n", .{});
    try std.testing.expectEqualStrings("--serve 0.0.0.0:9000", try argsJoined(a, half));
    try std.testing.expect(hasNote(half, .warn, "needs both cert and key"));
    // the `timeout` and `limits` capture variants
    const to = try translate(a, @embedFile("testdata/rpc-surface-timeout.yaml"), .{});
    try std.testing.expect(std.mem.endsWith(u8, try argsJoined(a, to), "--indexes --rpc grpc-timeout-ms=1"));
    const lim = try translate(a, @embedFile("testdata/rpc-surface-limits.yaml"), .{});
    try std.testing.expect(std.mem.indexOf(u8, try argsJoined(a, lim), "grpc") == null);
    try std.testing.expect(hasNote(lim, .info, "grpc-load-shed: validator gRPC server only"));
    try std.testing.expect(hasNote(lim, .info, "grpc-concurrency-limit: validator gRPC server only"));
    const more = try translate(a,
        \\json-rpc-address: 0.0.0.0:9000
        \\rpc:
        \\  max-connection-age-secs: 0
        \\  max-connection-age-grace-secs: 30
        \\  subscription-watermark-interval: 10
        \\  subscription-max-subscribers: 64
        \\  subscription-shards: 4
        \\  max-json-move-value-size: 1048576
        \\  max-json-move-value-response-size: 1
        \\
    , .{});
    try std.testing.expectEqualStrings("--serve 0.0.0.0:9000 --rpc max-connection-age-secs=0 --rpc max-connection-age-grace-secs=30 --rpc subscription-watermark-interval=10 --rpc subscription-max-subscribers=64", try argsJoined(a, more));
    try std.testing.expect(hasNote(more, .info, "subscription-shards"));
    try std.testing.expect(hasNote(more, .warn, "max-json-move-value-response-size 1"));
    try std.testing.expect(!hasNote(more, .warn, "max-json-move-value-size"));
}

test "fullnode.yaml: syntax zui cannot read is an error with its line" {
    var ar: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer ar.deinit();
    var line: usize = 0;
    try std.testing.expectError(error.YamlSyntax, parse(ar.allocator(), "a: 1\n  b: 2\n", &line));
    try std.testing.expectEqual(@as(usize, 2), line);
    try std.testing.expectError(error.YamlSyntax, parse(ar.allocator(), "a: [1, 2\n", &line));
    const v = try parse(ar.allocator(), "# only a comment\n\n", &line);
    try std.testing.expect(v == .null);
}

test "fullnode.yaml: metrics push-url and push-interval-seconds map to the push flags" {
    var ar: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const tr = try translate(a,
        \\metrics:
        \\  push-url: https://metrics-proxy.mainnet.sui.io:8443/publish/metrics
        \\  push-interval-seconds: 30
        \\
    , .{});
    const got = try argsJoined(a, tr);
    try std.testing.expectEqualStrings("--metrics-push-url https://metrics-proxy.mainnet.sui.io:8443/publish/metrics --metrics-push-interval 30 --serve " ++ default_rpc_address, got);
    try std.testing.expect(hasNote(tr, .info, "no client certificate"));
}
