//! The wire contract between a node and its gate service (docs/GATE.md): URL joining, the JSON
//! answers of resolve, free and usage, and the JSON a node sends. Unknown fields are ignored; a
//! missing optional field takes the default named beside it.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const max_key_len = 256;
pub const max_key_id_len = 128;
pub const max_plan_len = 32;
pub const max_message_len = 200;
pub const max_edge_id_len = 64;
pub const min_token_len = 24;
pub const max_batch_rows = 1000;
/// Answers larger than this are refused unread.
pub const max_answer_bytes = 1 << 20;

pub const Status = enum(u8) {
    ok,
    invalid,
    suspended,
    exhausted,
    /// A status this build does not know: a denial (PERMISSION_DENIED).
    unknown,

    pub fn parse(s: []const u8) Status {
        inline for (.{ Status.ok, Status.invalid, Status.suspended, Status.exhausted }) |v| {
            if (std.mem.eql(u8, s, @tagName(v))) return v;
        }
        // "revoked" is how some gates spell a suspended key
        if (std.mem.eql(u8, s, "revoked")) return .suspended;
        return .unknown;
    }
};

pub const MethodNum = struct { method: []const u8, n: u32 };

/// What calls cost. `weights`: units per call. `per_item`: for a batch call of `ids` items,
/// units = 1 + ceil(ids / n) instead of the flat weight. `per_minute`: for a stream, n units per
/// started minute open instead of the flat weight once.
pub const Pricing = struct {
    default: u32 = 1,
    weights: []const MethodNum = &.{},
    per_item: []const MethodNum = &.{},
    per_minute: []const MethodNum = &.{},
    /// `forward_weight_mult` in thousandths (default 1000: no change).
    forward_milli: u32 = 1000,
};

pub const Resolve = struct {
    /// Empty when the gate sent none (an invalid key).
    key_id: []const u8 = "",
    status: Status,
    plan: []const u8 = "",
    rps: f64 = 0,
    burst: u32 = 0,
    pricing: Pricing = .{},
    max_streams: u32 = 1,
    /// null: no cap, and only an explicit JSON `null` says so. A missing field is 0: nothing
    /// may be spent on this answer, and the node resolves again.
    lease_units: ?u64 = 0,
    ttl_s: u32 = 60,
    /// Optional text for the caller when this key is refused ("" when absent or unusable).
    message: []const u8 = "",
};

pub const DenyItem = struct {
    key_id: []const u8 = "",
    ip_prefix: []const u8 = "",
    status: Status,
    /// null: until the gate says otherwise.
    until_ms: ?u64 = null,
    message: []const u8 = "",
};

pub const Free = struct {
    rps_per_ip: f64 = 2,
    burst: u32 = 4,
    pricing: Pricing = .{},
    max_streams: u32 = 1,
    ttl_s: u32 = 300,
    /// Informational: the gate enforces it from the usage rows and answers with `deny`.
    daily_cap_per_prefix: u64 = 0,
    deny: []const DenyItem = &.{},
};

pub const UsageAnswer = struct {
    deny: []const DenyItem = &.{},
    /// Rows of the batch the gate did not take (the batch is delivered all the same), and the
    /// indexes of up to `max_rejected_rows` of them.
    rejected: u64 = 0,
    rejected_rows: []const u32 = &.{},
};

pub const max_rejected_rows = 50;

pub const Error = error{ Malformed, OutOfMemory };

// ---------------------------------------------------------------- URLs

/// `base` (any number of trailing slashes) and `path` (with or without a leading slash) joined
/// by exactly one slash. The base may carry a path of its own (`https://gate.example/v1/gate`).
pub fn joinUrl(buf: []u8, base: []const u8, path: []const u8) error{NoSpaceLeft}![]const u8 {
    const b = std.mem.trimEnd(u8, base, "/");
    const p = std.mem.trimStart(u8, path, "/");
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ b, p });
}

pub const path_resolve = "resolve";
pub const path_usage = "usage";

pub fn freeUrl(buf: []u8, base: []const u8, edge: []const u8) error{NoSpaceLeft}![]const u8 {
    const b = std.mem.trimEnd(u8, base, "/");
    return std.fmt.bufPrint(buf, "{s}/free?edge={s}", .{ b, edge });
}

/// A gate base URL a node accepts: https, a host, no query or fragment.
pub fn validBase(url: []const u8) bool {
    const prefix = "https://";
    if (!std.mem.startsWith(u8, url, prefix)) return false;
    const rest = url[prefix.len..];
    if (rest.len == 0 or rest[0] == '/') return false;
    for (rest) |c| if (c <= 0x20 or c >= 0x7f or c == '?' or c == '#') return false;
    return url.len <= 512;
}

/// An edge id is 1 to 64 of `A-Z a-z 0-9 . _ -` (it goes into URLs and batch ids unescaped).
pub fn validEdgeId(id: []const u8) bool {
    if (id.len == 0 or id.len > max_edge_id_len) return false;
    for (id) |c| if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '-')) return false;
    return true;
}

/// A key a node will ask the gate about: 1 to 256 printable ASCII bytes without a space.
/// Anything else is refused locally, without a call.
pub fn validKey(key: []const u8) bool {
    if (key.len == 0 or key.len > max_key_len) return false;
    for (key) |c| if (c <= 0x20 or c >= 0x7f) return false;
    return true;
}

fn printable(s: []const u8) bool {
    for (s) |c| if (c < 0x20 or c >= 0x7f) return false;
    return true;
}

/// A gRPC path or a bare method name as the contract writes it: no leading slash.
pub fn methodName(path: []const u8) []const u8 {
    return if (path.len > 0 and path[0] == '/') path[1..] else path;
}

// ---------------------------------------------------------------- JSON in

const Value = std.json.Value;

fn parseObject(arena: Allocator, text: []const u8) Error!std.json.ObjectMap {
    if (text.len > max_answer_bytes) return error.Malformed;
    const v = std.json.parseFromSliceLeaky(Value, arena, text, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Malformed,
    };
    return switch (v) {
        .object => |o| o,
        else => error.Malformed,
    };
}

fn num(v: ?Value) ?f64 {
    const x = v orelse return null;
    const f: f64 = switch (x) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        .number_string => |s| std.fmt.parseFloat(f64, s) catch return null,
        else => return null,
    };
    if (!std.math.isFinite(f)) return null;
    return f;
}

/// A count: negative is 0, fractions round up, the top is `max`.
fn count(v: ?Value, default: u64, max: u64) u64 {
    const f = num(v) orelse return default;
    if (f <= 0) return 0;
    const c = @ceil(f);
    if (c >= @as(f64, @floatFromInt(max))) return max;
    return @intFromFloat(c);
}

fn str(v: ?Value) []const u8 {
    const x = v orelse return "";
    return switch (x) {
        .string => |s| s,
        else => "",
    };
}

/// Caller-facing text from the gate: kept only when it is 1 to 200 printable ASCII bytes.
fn message(v: ?Value) []const u8 {
    const s = str(v);
    if (s.len == 0 or s.len > max_message_len or !printable(s)) return "";
    return s;
}

fn methodMap(arena: Allocator, v: ?Value, skip_default: bool) Error![]const MethodNum {
    const x = v orelse return &.{};
    const o = switch (x) {
        .object => |o| o,
        else => return &.{},
    };
    var list: std.ArrayList(MethodNum) = .empty;
    var it = o.iterator();
    while (it.next()) |kv| {
        if (skip_default and std.mem.eql(u8, kv.key_ptr.*, "default")) continue;
        // an entry that is not a number is ignored (the default applies)
        if (num(kv.value_ptr.*) == null) continue;
        try list.append(arena, .{ .method = methodName(kv.key_ptr.*), .n = @intCast(count(kv.value_ptr.*, 1, 1_000_000)) });
    }
    return list.items;
}

fn pricing(arena: Allocator, o: *const std.json.ObjectMap) Error!Pricing {
    var p: Pricing = .{};
    if (o.get("weights")) |w| if (w == .object) {
        p.default = @intCast(count(w.object.get("default"), 1, 1_000_000));
        p.weights = try methodMap(arena, w, true);
    };
    p.per_item = try methodMap(arena, o.get("per_item"), false);
    p.per_minute = try methodMap(arena, o.get("per_minute"), false);
    if (num(o.get("forward_weight_mult"))) |m| {
        // never under 1: forwarding does not make a call cheaper
        p.forward_milli = if (m <= 1) 1000 else if (m >= 1000) 1_000_000 else @intFromFloat(@ceil(m * 1000));
    }
    return p;
}

fn rate(v: ?Value, default: f64) f64 {
    const f = num(v) orelse return default;
    return std.math.clamp(f, 0, 1_000_000);
}

pub fn parseResolve(arena: Allocator, text: []const u8) Error!Resolve {
    const o = try parseObject(arena, text);
    const st = o.get("status") orelse return error.Malformed;
    if (st != .string) return error.Malformed;
    var r: Resolve = .{ .status = Status.parse(st.string) };
    r.key_id = str(o.get("key_id"));
    if (r.key_id.len > max_key_id_len or !printable(r.key_id)) return error.Malformed;
    // usage rows name the key by its id: an accepted key without one cannot be metered
    if (r.status == .ok and r.key_id.len == 0) return error.Malformed;
    const plan = str(o.get("plan"));
    r.plan = if (printable(plan)) plan[0..@min(plan.len, max_plan_len)] else "";
    r.rps = rate(o.get("rps"), 0);
    r.burst = @intCast(count(o.get("burst"), 0, 10_000_000));
    r.pricing = try pricing(arena, &o);
    r.max_streams = @intCast(count(o.get("max_streams"), 1, 1_000_000));
    r.lease_units = if (o.get("lease_units")) |l| (if (l == .null) null else count(l, 0, std.math.maxInt(u62))) else 0;
    r.ttl_s = @intCast(std.math.clamp(count(o.get("ttl_s"), 60, 3600), 1, 3600));
    r.message = message(o.get("message"));
    return r;
}

fn denyList(arena: Allocator, v: ?Value) Error![]const DenyItem {
    const x = v orelse return &.{};
    const arr = switch (x) {
        .array => |a| a,
        else => return &.{},
    };
    var list: std.ArrayList(DenyItem) = .empty;
    for (arr.items) |item| {
        if (list.items.len >= 4096) break;
        const o = switch (item) {
            .object => |o| o,
            else => continue,
        };
        var d: DenyItem = .{ .status = Status.parse(str(o.get("status"))) };
        // a deny entry that says "ok" denies nothing
        if (d.status == .ok) continue;
        d.key_id = str(o.get("key_id"));
        d.ip_prefix = str(o.get("ip_prefix"));
        if (d.key_id.len == 0 and d.ip_prefix.len == 0) continue;
        if (d.key_id.len > max_key_id_len) continue;
        if (o.get("until_ms")) |u| if (num(u) != null) {
            d.until_ms = count(u, 0, std.math.maxInt(u62));
        };
        d.message = message(o.get("message"));
        try list.append(arena, d);
    }
    return list.items;
}

pub fn parseFree(arena: Allocator, text: []const u8) Error!Free {
    const o = try parseObject(arena, text);
    var f: Free = .{};
    // the one field without which the answer says nothing
    if (num(o.get("rps_per_ip")) == null) return error.Malformed;
    f.rps_per_ip = rate(o.get("rps_per_ip"), 2);
    f.burst = @intCast(count(o.get("burst"), @intFromFloat(@max(1, @ceil(f.rps_per_ip))), 10_000_000));
    f.pricing = try pricing(arena, &o);
    f.max_streams = @intCast(count(o.get("max_streams"), 1, 1_000_000));
    f.ttl_s = @intCast(std.math.clamp(count(o.get("ttl_s"), 300, 86400), 5, 86400));
    f.daily_cap_per_prefix = count(o.get("daily_cap_per_prefix"), 0, std.math.maxInt(u62));
    f.deny = try denyList(arena, o.get("deny"));
    return f;
}

/// The body of a 2xx usage answer. An empty or non-JSON body is an acknowledgement without a
/// deny list.
pub fn parseUsageAnswer(arena: Allocator, text: []const u8) Error!UsageAnswer {
    const o = parseObject(arena, text) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Malformed => return .{},
    };
    var ans: UsageAnswer = .{ .deny = try denyList(arena, o.get("deny")) };
    ans.rejected = count(o.get("rejected"), 0, max_batch_rows);
    if (o.get("rejected_rows")) |rr| if (rr == .array) {
        var list: std.ArrayList(u32) = .empty;
        for (rr.array.items) |x| {
            if (list.items.len == max_rejected_rows) break;
            if (num(x) == null) continue;
            try list.append(arena, @intCast(count(x, 0, max_batch_rows)));
        }
        ans.rejected_rows = list.items;
        // a list without a count still says rows were refused
        ans.rejected = @max(ans.rejected, list.items.len);
    };
    return ans;
}

/// `Retry-After` as seconds (the delta form; an HTTP date is not read), at most five minutes so
/// a wrong header cannot park the usage queue.
pub fn retryAfterMs(value: []const u8) ?u32 {
    const secs = std.fmt.parseInt(u32, std.mem.trim(u8, value, " \t"), 10) catch return null;
    return @as(u32, @min(secs, 300)) * 1000;
}

// ---------------------------------------------------------------- JSON out

pub fn jsonString(out: *std.ArrayList(u8), gpa: Allocator, s: []const u8) Allocator.Error!void {
    try out.append(gpa, '"');
    for (s) |c| switch (c) {
        '"' => try out.appendSlice(gpa, "\\\""),
        '\\' => try out.appendSlice(gpa, "\\\\"),
        0...0x1f, 0x7f...0xff => try out.print(gpa, "\\u{x:0>4}", .{c}),
        else => try out.append(gpa, c),
    };
    try out.append(gpa, '"');
}

/// `{"edge":"<id>","key":"<raw key>"}`.
pub fn resolveBody(out: *std.ArrayList(u8), gpa: Allocator, edge: []const u8, key: []const u8) Allocator.Error!void {
    try out.appendSlice(gpa, "{\"edge\":");
    try jsonString(out, gpa, edge);
    try out.appendSlice(gpa, ",\"key\":");
    try jsonString(out, gpa, key);
    try out.append(gpa, '}');
}

pub const Counters = struct {
    local: u64 = 0,
    forwarded: u64 = 0,
    units: u64 = 0,
    limited: u64 = 0,
    stream_msgs: u64 = 0,

    pub fn add(a: *Counters, b: Counters) void {
        a.local +|= b.local;
        a.forwarded +|= b.forwarded;
        a.units +|= b.units;
        a.limited +|= b.limited;
        a.stream_msgs +|= b.stream_msgs;
    }
    pub fn zero(c: Counters) bool {
        return c.local == 0 and c.forwarded == 0 and c.units == 0 and c.limited == 0 and c.stream_msgs == 0;
    }
};

/// One usage row. `subject` is `k` followed by the key id, or `i` followed by the prefix text.
pub const Row = struct {
    subject: []const u8,
    method: []const u8,
    c: Counters,
};

pub fn usageHead(out: *std.ArrayList(u8), gpa: Allocator, edge: []const u8, batch_id: []const u8, from_ms: u64, to_ms: u64) Allocator.Error!void {
    try out.appendSlice(gpa, "{\"edge\":");
    try jsonString(out, gpa, edge);
    try out.appendSlice(gpa, ",\"batch_id\":");
    try jsonString(out, gpa, batch_id);
    try out.print(gpa, ",\"from_ms\":{d},\"to_ms\":{d},\"rows\":[", .{ from_ms, to_ms });
}

pub fn usageRow(out: *std.ArrayList(u8), gpa: Allocator, first: bool, row: Row) Allocator.Error!void {
    if (!first) try out.append(gpa, ',');
    if (row.subject.len > 0 and row.subject[0] == 'k') {
        try out.appendSlice(gpa, "{\"key_id\":");
        try jsonString(out, gpa, row.subject[1..]);
    } else {
        try out.appendSlice(gpa, "{\"key_id\":null,\"ip_prefix\":");
        try jsonString(out, gpa, if (row.subject.len > 0) row.subject[1..] else "");
    }
    try out.appendSlice(gpa, ",\"method\":");
    try jsonString(out, gpa, row.method);
    try out.print(gpa, ",\"local\":{d},\"forwarded\":{d},\"units\":{d},\"limited\":{d},\"stream_msgs\":{d}}}", .{ row.c.local, row.c.forwarded, row.c.units, row.c.limited, row.c.stream_msgs });
}

pub fn usageTail(out: *std.ArrayList(u8), gpa: Allocator) Allocator.Error!void {
    try out.appendSlice(gpa, "]}");
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "url: the base may carry a path, slashes are neither doubled nor dropped" {
    var b: [600]u8 = undefined;
    try testing.expectEqualStrings("https://gate.example/v1/gate/resolve", try joinUrl(&b, "https://gate.example/v1/gate", path_resolve));
    try testing.expectEqualStrings("https://gate.example/v1/gate/resolve", try joinUrl(&b, "https://gate.example/v1/gate/", "/resolve"));
    try testing.expectEqualStrings("https://gate.example/v1/gate/usage", try joinUrl(&b, "https://gate.example/v1/gate///", path_usage));
    try testing.expectEqualStrings("https://gate.example/usage", try joinUrl(&b, "https://gate.example", path_usage));
    try testing.expectEqualStrings("https://gate.example:8443/usage", try joinUrl(&b, "https://gate.example:8443/", path_usage));
    try testing.expectEqualStrings("https://gate.example/v1/gate/free?edge=e1", try freeUrl(&b, "https://gate.example/v1/gate/", "e1"));
    try testing.expectEqualStrings("https://gate.example/free?edge=edge-a.2", try freeUrl(&b, "https://gate.example", "edge-a.2"));
    try testing.expect(validBase("https://gate.example/v1/gate"));
    try testing.expect(validBase("https://gate.example"));
    try testing.expect(!validBase("http://gate.example"));
    try testing.expect(!validBase("https://"));
    try testing.expect(!validBase("https:///x"));
    try testing.expect(!validBase("https://gate.example/v1?x=1"));
    try testing.expect(!validBase("gate.example"));
    try testing.expect(validEdgeId("edge-a.2_x"));
    try testing.expect(!validEdgeId(""));
    try testing.expect(!validEdgeId("a b"));
    try testing.expect(!validEdgeId("a&b"));
    try testing.expect(validKey("key_0123456789abcdef"));
    try testing.expect(!validKey(""));
    try testing.expect(!validKey("a b"));
    try testing.expect(!validKey("a\nb"));
    try testing.expect(!validKey(&@as([257]u8, @splat('a'))));
    try testing.expectEqualStrings("a.B/C", methodName("/a.B/C"));
    try testing.expectEqualStrings("a.B/C", methodName("a.B/C"));
}

/// The examples of the gate service's own contract text, with neutral names.
pub const fixtures = struct {
    pub const resolve_ok =
        \\{"key_id":"kid_3fJ9aQ2xLm0p","status":"ok","plan":"free","rps":25,"burst":50,"weights":{"default":1,"sui.rpc.v2.LedgerService/GetObject":1,"sui.rpc.v2.TransactionExecutionService/ExecuteTransaction":10},"forward_weight_mult":1,"max_streams":2,"ttl_s":60,"lease_units":2500000,"per_item":{"sui.rpc.v2.LedgerService/BatchGetObjects":10,"sui.rpc.v2.LedgerService/BatchGetTransactions":10},"per_minute":{"sui.rpc.v2.SubscriptionService/SubscribeCheckpoints":10}}
    ;
    pub const resolve_invalid =
        \\{"key_id":null,"status":"invalid","plan":null,"rps":0,"burst":0,"weights":{"default":1},"forward_weight_mult":1,"max_streams":0,"ttl_s":60,"lease_units":0,"message":"Unknown API key. Get one at gate.example."}
    ;
    pub const resolve_exhausted =
        \\{"key_id":"kid_3fJ9aQ2xLm0p","status":"exhausted","plan":"free","rps":25,"burst":50,"weights":{"default":1},"forward_weight_mult":1,"max_streams":2,"ttl_s":30,"lease_units":0,"per_item":{},"per_minute":{},"message":"Out of credits. Top up at gate.example."}
    ;
    pub const resolve_suspended =
        \\{"key_id":"kid_3fJ9aQ2xLm0p","status":"suspended","plan":"free","rps":25,"burst":50,"weights":{"default":1},"forward_weight_mult":1,"max_streams":0,"ttl_s":300,"lease_units":0,"per_item":{},"per_minute":{},"message":"This API key was revoked. Create a new one at gate.example."}
    ;
    pub const free =
        \\{"rps_per_ip":5,"burst":10,"weights":{"default":1},"max_streams":1,"ttl_s":300,"daily_cap_per_prefix":10000,"forward_weight_mult":1,"per_item":{},"per_minute":{},"deny":[{"ip_prefix":"203.0.113.0/24","status":"exhausted","until_ms":1794441600000,"message":"Free daily limit reached. Add an API key from gate.example for more."}]}
    ;
    pub const usage_request =
        \\{"edge":"e1","batch_id":"e1-1731230000-42","from_ms":1794355200000,"to_ms":1794355205000,"rows":[{"key_id":"kid_3fJ9aQ2xLm0p","method":"sui.rpc.v2.LedgerService/GetObject","local":90,"forwarded":10,"units":100,"limited":0,"stream_msgs":0},{"key_id":null,"ip_prefix":"203.0.113.0/24","method":"sui.rpc.v2.LedgerService/GetCheckpoint","local":12,"forwarded":0,"units":12,"limited":3,"stream_msgs":0}]}
    ;
    pub const usage_answer =
        \\{"ok":true,"duplicate":false,"rows":2,"rejected":0,"deny":[{"key_id":"kid_3fJ9aQ2xLm0p","status":"exhausted","until_ms":null,"message":"Out of credits. Top up at gate.example."},{"ip_prefix":"203.0.113.0/24","status":"exhausted","until_ms":1794441600000,"message":"Free daily limit reached. Add an API key from gate.example for more."}]}
    ;
    pub const usage_answer_rejected =
        \\{"ok":true,"duplicate":false,"rows":998,"rejected":2,"rejected_rows":[17,402]}
    ;
    pub const deny_entries = [_][]const u8{
        \\{"key_id":"kid_3fJ9aQ2xLm0p","status":"exhausted","until_ms":null,"message":"Out of credits. Top up at gate.example."}
        ,
        \\{"key_id":"kid_3fJ9aQ2xLm0p","status":"suspended","until_ms":null,"message":"This API key was revoked. Create a new one at gate.example."}
        ,
        \\{"ip_prefix":"203.0.113.0/24","status":"exhausted","until_ms":1794441600000,"message":"Free daily limit reached. Add an API key from gate.example for more."}
    };
    pub const error_body =
        \\{"error":{"code":"unauthorized","message":"missing or unknown edge token"}}
    ;
    /// An answer for a key the gate does not know, without the optional text.
    pub const resolve_invalid_plain =
        \\{"key_id":null,"status":"invalid","plan":null,"rps":0,"burst":0,"weights":{"default":1},"forward_weight_mult":1,"max_streams":0,"ttl_s":60,"lease_units":0}
    ;
};

fn find(list: []const MethodNum, method: []const u8) ?u32 {
    for (list) |m| if (std.mem.eql(u8, m.method, method)) return m.n;
    return null;
}

test "resolve: every example of the service's contract text" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const r = try parseResolve(a, fixtures.resolve_ok);
    try testing.expectEqualStrings("kid_3fJ9aQ2xLm0p", r.key_id);
    try testing.expectEqual(Status.ok, r.status);
    try testing.expectEqualStrings("free", r.plan);
    try testing.expectEqual(@as(f64, 25), r.rps);
    try testing.expectEqual(@as(u32, 50), r.burst);
    try testing.expectEqual(@as(u32, 1), r.pricing.default);
    try testing.expectEqual(@as(usize, 2), r.pricing.weights.len);
    try testing.expectEqual(@as(?u32, 10), find(r.pricing.weights, "sui.rpc.v2.TransactionExecutionService/ExecuteTransaction"));
    try testing.expectEqual(@as(?u32, 10), find(r.pricing.per_item, "sui.rpc.v2.LedgerService/BatchGetObjects"));
    try testing.expectEqual(@as(?u32, 10), find(r.pricing.per_item, "sui.rpc.v2.LedgerService/BatchGetTransactions"));
    try testing.expectEqual(@as(?u32, 10), find(r.pricing.per_minute, "sui.rpc.v2.SubscriptionService/SubscribeCheckpoints"));
    try testing.expectEqual(@as(u32, 1000), r.pricing.forward_milli);
    try testing.expectEqual(@as(u32, 2), r.max_streams);
    try testing.expectEqual(@as(u32, 60), r.ttl_s);
    try testing.expectEqual(@as(?u64, 2_500_000), r.lease_units);
    try testing.expectEqualStrings("", r.message);

    const inv = try parseResolve(a, fixtures.resolve_invalid);
    try testing.expectEqual(Status.invalid, inv.status);
    try testing.expectEqualStrings("", inv.key_id);
    try testing.expectEqualStrings("", inv.plan);
    try testing.expectEqual(@as(?u64, 0), inv.lease_units);
    try testing.expectEqual(@as(u32, 0), inv.max_streams);
    try testing.expectEqualStrings("Unknown API key. Get one at gate.example.", inv.message);
    try testing.expectEqualStrings("", (try parseResolve(a, fixtures.resolve_invalid_plain)).message);

    const exh = try parseResolve(a, fixtures.resolve_exhausted);
    try testing.expectEqual(Status.exhausted, exh.status);
    try testing.expectEqualStrings("kid_3fJ9aQ2xLm0p", exh.key_id);
    try testing.expectEqual(@as(u32, 30), exh.ttl_s);
    try testing.expectEqual(@as(?u64, 0), exh.lease_units);
    try testing.expectEqualStrings("Out of credits. Top up at gate.example.", exh.message);
    const susp = try parseResolve(a, fixtures.resolve_suspended);
    try testing.expectEqual(Status.suspended, susp.status);
    try testing.expectEqual(@as(u32, 300), susp.ttl_s);
    try testing.expectEqual(@as(u32, 0), susp.max_streams);
    try testing.expectEqualStrings("This API key was revoked. Create a new one at gate.example.", susp.message);

    // an error body is not a resolve answer
    try testing.expectError(error.Malformed, parseResolve(a, fixtures.error_body));
}

test "resolve: defaults, unknown fields, unknown statuses, messages" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // only what cannot be defaulted
    const r = try parseResolve(a, "{\"status\":\"ok\",\"key_id\":\"k_1\",\"future_field\":[1,2,{\"x\":null}]}");
    try testing.expectEqual(@as(f64, 0), r.rps); // no rate given: nothing passes, never unlimited
    try testing.expectEqual(@as(u32, 1), r.pricing.default);
    try testing.expectEqual(@as(u32, 1000), r.pricing.forward_milli);
    try testing.expectEqual(@as(u32, 1), r.max_streams);
    // no lease field: nothing may be spent on this answer (only an explicit null is "no cap")
    try testing.expectEqual(@as(?u64, 0), r.lease_units);
    try testing.expectEqual(@as(u32, 60), r.ttl_s);
    // explicit null lease, fractional numbers round up, the multiplier never goes under 1
    const f = try parseResolve(a, "{\"status\":\"ok\",\"key_id\":\"k_1\",\"lease_units\":null,\"rps\":0.5,\"burst\":2.2,\"ttl_s\":0,\"forward_weight_mult\":1.5,\"weights\":{\"default\":2.1,\"a.B/C\":0,\"/a.B/D\":7,\"a.B/E\":{\"x\":1}}}");
    try testing.expectEqual(@as(?u64, null), f.lease_units);
    try testing.expectEqual(@as(f64, 0.5), f.rps);
    try testing.expectEqual(@as(u32, 3), f.burst);
    try testing.expectEqual(@as(u32, 1), f.ttl_s);
    try testing.expectEqual(@as(u32, 1500), f.pricing.forward_milli);
    try testing.expectEqual(@as(u32, 3), f.pricing.default);
    try testing.expectEqual(@as(?u32, 0), find(f.pricing.weights, "a.B/C"));
    try testing.expectEqual(@as(?u32, 7), find(f.pricing.weights, "a.B/D")); // a leading slash is dropped
    try testing.expectEqual(@as(?u32, null), find(f.pricing.weights, "a.B/E")); // not a number: ignored
    const low = try parseResolve(a, "{\"status\":\"ok\",\"key_id\":\"k_1\",\"forward_weight_mult\":0.2}");
    try testing.expectEqual(@as(u32, 1000), low.pricing.forward_milli);
    // statuses
    try testing.expectEqual(Status.suspended, (try parseResolve(a, "{\"status\":\"suspended\",\"key_id\":\"k\"}")).status);
    try testing.expectEqual(Status.suspended, (try parseResolve(a, "{\"status\":\"revoked\"}")).status);
    try testing.expectEqual(Status.exhausted, (try parseResolve(a, "{\"status\":\"exhausted\",\"key_id\":\"k\"}")).status);
    try testing.expectEqual(Status.unknown, (try parseResolve(a, "{\"status\":\"paused_for_review\"}")).status);
    // message: verbatim when usable, dropped otherwise
    try testing.expectEqualStrings("Out of credits. Top up at gate.example.", (try parseResolve(a, "{\"status\":\"exhausted\",\"key_id\":\"k\",\"message\":\"Out of credits. Top up at gate.example.\"}")).message);
    try testing.expectEqualStrings("", (try parseResolve(a, "{\"status\":\"exhausted\",\"message\":\"line\\nbreak\"}")).message);
    try testing.expectEqualStrings("", (try parseResolve(a, "{\"status\":\"exhausted\",\"message\":\"" ++ @as([201]u8, @splat('x')) ++ "\"}")).message);
    try testing.expectEqualStrings("", (try parseResolve(a, "{\"status\":\"exhausted\",\"message\":7}")).message);
    // refused
    try testing.expectError(error.Malformed, parseResolve(a, "{\"key_id\":\"k\"}")); // no status
    try testing.expectError(error.Malformed, parseResolve(a, "{\"status\":\"ok\"}")); // ok without an id
    try testing.expectError(error.Malformed, parseResolve(a, "{\"status\":\"ok\",\"key_id\":\"" ++ @as([129]u8, @splat('k')) ++ "\"}"));
    try testing.expectError(error.Malformed, parseResolve(a, "[1]"));
    try testing.expectError(error.Malformed, parseResolve(a, "not json"));
    try testing.expectError(error.Malformed, parseResolve(a, ""));
}

test "free and usage answers: every example, deny entries, defaults" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const f = try parseFree(a, fixtures.free);
    try testing.expectEqual(@as(f64, 5), f.rps_per_ip);
    try testing.expectEqual(@as(u32, 10), f.burst);
    try testing.expectEqual(@as(u32, 1), f.max_streams);
    try testing.expectEqual(@as(u32, 300), f.ttl_s);
    try testing.expectEqual(@as(u64, 10000), f.daily_cap_per_prefix);
    try testing.expectEqual(@as(usize, 1), f.deny.len);
    try testing.expectEqualStrings("203.0.113.0/24", f.deny[0].ip_prefix);
    try testing.expectEqual(Status.exhausted, f.deny[0].status);
    try testing.expectEqual(@as(?u64, 1794441600000), f.deny[0].until_ms);
    try testing.expectEqualStrings("Free daily limit reached. Add an API key from gate.example for more.", f.deny[0].message);
    const small = try parseFree(a, "{\"rps_per_ip\":3}");
    try testing.expectEqual(@as(u32, 3), small.burst);
    try testing.expectEqual(@as(usize, 0), small.deny.len);
    try testing.expectError(error.Malformed, parseFree(a, "{}"));
    try testing.expectError(error.Malformed, parseFree(a, fixtures.error_body));

    const u = try parseUsageAnswer(a, fixtures.usage_answer);
    try testing.expectEqual(@as(usize, 2), u.deny.len);
    try testing.expectEqualStrings("kid_3fJ9aQ2xLm0p", u.deny[0].key_id);
    try testing.expectEqual(@as(?u64, null), u.deny[0].until_ms);
    try testing.expectEqualStrings("203.0.113.0/24", u.deny[1].ip_prefix);
    try testing.expectEqual(@as(?u64, 1794441600000), u.deny[1].until_ms);
    try testing.expectEqualStrings("Out of credits. Top up at gate.example.", u.deny[0].message);
    try testing.expectEqualStrings("Free daily limit reached. Add an API key from gate.example for more.", u.deny[1].message);
    try testing.expectEqual(@as(u64, 0), u.rejected);
    // absent deny, an empty body and a body that is not JSON are all "nothing denied"
    try testing.expectEqual(@as(usize, 0), (try parseUsageAnswer(a, "{\"ok\":true}")).deny.len);
    try testing.expectEqual(@as(usize, 0), (try parseUsageAnswer(a, "")).deny.len);
    try testing.expectEqual(@as(usize, 0), (try parseUsageAnswer(a, "ok")).deny.len);
    inline for (fixtures.deny_entries, .{ Status.exhausted, Status.suspended, Status.exhausted }) |text, want| {
        const one = try parseUsageAnswer(a, "{\"deny\":[" ++ text ++ "]}");
        try testing.expectEqual(@as(usize, 1), one.deny.len);
        try testing.expectEqual(want, one.deny[0].status);
        try testing.expect(one.deny[0].message.len > 0);
    }
    // rows the gate did not take: a count and up to 50 indexes; the batch is still delivered
    const rej = try parseUsageAnswer(a, fixtures.usage_answer_rejected);
    try testing.expectEqual(@as(u64, 2), rej.rejected);
    try testing.expectEqualSlices(u32, &.{ 17, 402 }, rej.rejected_rows);
    try testing.expectEqual(@as(usize, 0), rej.deny.len);
    var many: std.ArrayList(u8) = .empty;
    try many.appendSlice(a, "{\"rejected\":80,\"rejected_rows\":[");
    for (0..80) |i| try many.print(a, "{s}{d}", .{ if (i == 0) "" else ",", i });
    try many.appendSlice(a, "]}");
    const capped = try parseUsageAnswer(a, many.items);
    try testing.expectEqual(@as(u64, 80), capped.rejected);
    try testing.expectEqual(@as(usize, max_rejected_rows), capped.rejected_rows.len);
    try testing.expectEqual(@as(u64, 2), (try parseUsageAnswer(a, "{\"rejected_rows\":[4,9,\"x\"]}")).rejected);
    try testing.expectEqual(@as(?u32, 7000), retryAfterMs(" 7 "));
    try testing.expectEqual(@as(?u32, 300_000), retryAfterMs("86400"));
    try testing.expectEqual(@as(?u32, null), retryAfterMs("Wed, 21 Oct 2026 07:28:00 GMT"));
    try testing.expectEqual(@as(?u32, null), retryAfterMs(""));
    // entries that name nobody, or deny nothing, are skipped; an unknown status still denies
    const odd = try parseUsageAnswer(a, "{\"deny\":[{\"status\":\"exhausted\"},{\"key_id\":\"k\",\"status\":\"ok\"},7,{\"key_id\":\"k2\",\"status\":\"frozen\",\"message\":\"Ask support.\"}]}");
    try testing.expectEqual(@as(usize, 1), odd.deny.len);
    try testing.expectEqual(Status.unknown, odd.deny[0].status);
    try testing.expectEqualStrings("Ask support.", odd.deny[0].message);
}

test "usage body: the exact bytes of the contract's example" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try usageHead(&out, gpa, "e1", "e1-1731230000-42", 1794355200000, 1794355205000);
    try usageRow(&out, gpa, true, .{ .subject = "kkid_3fJ9aQ2xLm0p", .method = "sui.rpc.v2.LedgerService/GetObject", .c = .{ .local = 90, .forwarded = 10, .units = 100 } });
    try usageRow(&out, gpa, false, .{ .subject = "i203.0.113.0/24", .method = "sui.rpc.v2.LedgerService/GetCheckpoint", .c = .{ .local = 12, .units = 12, .limited = 3 } });
    try usageTail(&out, gpa);
    try testing.expectEqualStrings(fixtures.usage_request, out.items);
    out.clearRetainingCapacity();
    try resolveBody(&out, gpa, "e1", "a\"b\\c");
    try testing.expectEqualStrings("{\"edge\":\"e1\",\"key\":\"a\\\"b\\\\c\"}", out.items);
}
