//! `--gate`: the access gate (docs/GATE.md, src/edge/gate) wired into this node.
//! - `Http`: the gate's requests over the node's HTTPS client (netguard.Client, one per slot,
//!   every request under `netguard.timed`);
//! - `handler`: wraps the sui.rpc.v2 handler; a call is put to the gate before the service
//!   sees it and counted after the service answered;
//! - `nativeHook`: the same for zui/1 (native/gate.zig).
//! Without `--gate` the node never touches this file's code.
const std = @import("std");
const Io = std.Io;
const Atomic = std.atomic.Value;
const Allocator = std.mem.Allocator;
const edge = @import("edge");
const serve = @import("serve");
const native = @import("native");
const netguard = @import("netguard.zig");
const g = edge.gate;
const h2 = serve.h2;
const proto = native.proto;

/// Every method the gate prices: the gRPC paths of the sui.rpc.v2 services and the zui/1
/// methods (as `zui.1/<name>`). Anything else is "other" and costs the default weight.
pub const method_defs = [_]g.methods.Def{
    .{ .name = "grpc.health.v1.Health/Check", .kind = .free },
    .{ .name = "grpc.health.v1.Health/Watch", .kind = .free },
    .{ .name = "grpc.reflection.v1.ServerReflection/ServerReflectionInfo", .kind = .free },
    .{ .name = "grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", .kind = .free },
    .{ .name = "sui.rpc.v2.LedgerService/GetServiceInfo", .kind = .free },
    .{ .name = "sui.rpc.v2.LedgerService/GetObject" },
    .{ .name = "sui.rpc.v2.LedgerService/GetTransaction" },
    .{ .name = "sui.rpc.v2.LedgerService/GetCheckpoint" },
    .{ .name = "sui.rpc.v2.LedgerService/GetEpoch" },
    .{ .name = "sui.rpc.v2.LedgerService/BatchGetObjects", .kind = .batch },
    .{ .name = "sui.rpc.v2.LedgerService/BatchGetTransactions", .kind = .batch },
    .{ .name = "sui.rpc.v2.LedgerService/ListCheckpoints" },
    .{ .name = "sui.rpc.v2.LedgerService/ListTransactions" },
    .{ .name = "sui.rpc.v2.LedgerService/ListEvents" },
    .{ .name = "sui.rpc.v2.StateService/GetCoinInfo" },
    .{ .name = "sui.rpc.v2.StateService/GetBalance" },
    .{ .name = "sui.rpc.v2.StateService/ListBalances" },
    .{ .name = "sui.rpc.v2.StateService/ListOwnedObjects" },
    .{ .name = "sui.rpc.v2.StateService/ListDynamicFields" },
    .{ .name = "sui.rpc.v2.MovePackageService/GetPackage" },
    .{ .name = "sui.rpc.v2.MovePackageService/GetDatatype" },
    .{ .name = "sui.rpc.v2.MovePackageService/GetFunction" },
    .{ .name = "sui.rpc.v2.MovePackageService/ListPackageVersions" },
    .{ .name = "sui.rpc.v2.NameService/LookupName" },
    .{ .name = "sui.rpc.v2.NameService/ReverseLookupName" },
    .{ .name = "sui.rpc.v2.SignatureVerificationService/VerifySignature" },
    .{ .name = "sui.rpc.v2.TransactionExecutionService/SimulateTransaction" },
    .{ .name = "sui.rpc.v2.TransactionExecutionService/ExecuteTransaction" },
    .{ .name = "sui.rpc.v2.SubscriptionService/SubscribeCheckpoints", .kind = .stream },
    .{ .name = "sui.rpc.v2.SubscriptionService/SubscribeTransactions", .kind = .stream },
    .{ .name = "sui.rpc.v2.SubscriptionService/SubscribeEvents", .kind = .stream },
    .{ .name = "sui.rpc.v2alpha.ProofService/GetCheckpointObjectProof" },
    .{ .name = "zui.1/hello", .kind = .free },
    .{ .name = "zui.1/get_object" },
    .{ .name = "zui.1/batch_get_objects", .kind = .batch },
    .{ .name = "zui.1/get_checkpoint" },
    .{ .name = "zui.1/get_transaction" },
    .{ .name = "zui.1/batch_get_transactions", .kind = .batch },
    .{ .name = "zui.1/list_owned_objects" },
    .{ .name = "zui.1/get_balance" },
    .{ .name = "zui.1/list_balances" },
    .{ .name = "zui.1/dry_run" },
    .{ .name = "zui.1/submit_transaction" },
    .{ .name = "zui.1/get_dictionary" },
    .{ .name = "zui.1/get_epoch_proof" },
    .{ .name = "zui.1/get_epoch_info" },
    .{ .name = "zui.1/get_checkpoint_feed" },
    .{ .name = "zui.1/subscribe", .kind = .stream },
    .{ .name = "zui.1/pair_relay" },
};

pub const max_proxies = 8;

/// What the `--gate*` flags say.
pub const Settings = struct {
    url: []const u8,
    token_file: []const u8,
    edge_id: []const u8,
    /// `--gate-dir`: the free tier's last answer and the usage spool.
    dir: []const u8,
    proxies: []const g.ident.Cidr = &.{},
    /// `--gate-ca-file`: a PEM file of certificate authorities trusted for the gate connection
    /// only, in addition to the system roots (a gate behind a private CA). Null: system roots.
    ca_file: ?[]const u8 = null,
    /// Tests only: where the gate's own log lines go (null: std.log).
    log: ?g.gate.LogSink = null,
};

pub const StartError = error{ GateUrl, GateEdgeId, GateTokenFile, GateTokenTooShort, GateDir, GateTooManyProxies, GateCaFile };

/// A gate URL without TLS, allowed only when its host is this machine: `localhost`, an address
/// in 127.0.0.0/8, or `::1` (a local test gate). Anything else must be https.
pub fn loopbackHttp(url: []const u8) bool {
    const prefix = "http://";
    if (!std.mem.startsWith(u8, url, prefix)) return false;
    const rest = url[prefix.len..];
    for (rest) |c| if (c <= 0x20 or c >= 0x7f or c == '?' or c == '#' or c == '@') return false;
    const authority = rest[0 .. std.mem.indexOfScalar(u8, rest, '/') orelse rest.len];
    const host = if (authority.len > 0 and authority[0] == '[') blk: {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return false;
        // only a port may follow the bracket
        if (close + 1 != authority.len and authority[close + 1] != ':') return false;
        break :blk authority[1..close];
    } else authority[0 .. std.mem.lastIndexOfScalar(u8, authority, ':') orelse authority.len];
    if (std.ascii.eqlIgnoreCase(host, "localhost")) return true;
    const ip = g.Ip.parse(host) orelse return false;
    return switch (ip) {
        .v4 => |b| b[0] == 127,
        .v6 => |b| std.mem.eql(u8, b[0..15], &@as([15]u8, @splat(0))) and b[15] == 1,
    };
}

/// Checks the flags that can be checked without touching anything. The message names the flag.
pub fn check(s: *const Settings) ?[]const u8 {
    const url_ok = (g.contract.validBase(s.url) or loopbackHttp(s.url)) and s.url.len <= 512;
    if (!url_ok) return "--gate URL: an https:// base URL (a path is fine, no query); http:// only for localhost, 127.0.0.0/8 or [::1]";
    if (!g.contract.validEdgeId(s.edge_id)) return "--gate-edge-id NAME: 1 to 64 of A-Z a-z 0-9 . _ -";
    if (s.token_file.len == 0) return "--gate needs --gate-token-file FILE (this node's credential for the gate)";
    if (s.proxies.len > max_proxies) return "--gate-trusted-proxy: at most 8";
    return null;
}

/// Checks, before the node opens anything, the files the gate flags name: the credential (one
/// line, at least 24 characters) and the CA file (a PEM file with a certificate). The message
/// names the flag; the credential itself is never part of it.
pub fn preflight(gpa: Allocator, io: Io, s: *const Settings) ?[]const u8 {
    if (check(s)) |msg| return msg;
    const raw = Io.Dir.cwd().readFileAlloc(io, s.token_file, gpa, .limited(4096)) catch return "--gate-token-file: cannot read the file (this node's credential for the gate, one line)";
    defer {
        std.crypto.secureZero(u8, raw);
        gpa.free(raw);
    }
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len < g.contract.min_token_len or trimmed.len > 512) return "--gate-token-file: the credential must be one line of at least 24 characters";
    for (trimmed) |c| if (c <= 0x20 or c >= 0x7f) return "--gate-token-file: the credential must be one line of printable characters";
    if (s.ca_file) |path| Http.checkCaFile(gpa, io, path) catch return "--gate-ca-file: cannot read a PEM certificate from the file";
    return null;
}

/// The node's HTTPS client for the gate: a few clients, each used by one request at a time.
pub const Http = struct {
    gpa: Allocator,
    io: Io,
    slots: [slot_count]Slot,
    stopping: Atomic(bool) = .init(false),
    /// `--gate-ca-file` (null: the system roots alone).
    ca_file: ?[]const u8 = null,

    pub const slot_count = 6;
    const Slot = struct {
        busy: Atomic(bool) = .init(false),
        client: netguard.Client,
    };

    pub fn init(gpa: Allocator, io: Io) Http {
        var h: Http = .{ .gpa = gpa, .io = io, .slots = undefined };
        for (&h.slots) |*sl| {
            sl.* = .{ .client = netguard.Client.init(gpa, io) };
            sl.client.http.connection_pool.free_size = 2;
        }
        return h;
    }

    pub fn deinit(h: *Http) void {
        for (&h.slots) |*sl| sl.client.deinit();
    }

    pub fn transport(h: *Http) g.Transport {
        return .{ .ctx = h, .call = call, .cancel = cancel };
    }

    /// The system roots and, after them, the authorities of `path`.
    fn loadBundle(gpa: Allocator, io: Io, path: []const u8, now: Io.Timestamp, out: *std.crypto.Certificate.Bundle) !void {
        // a machine without system roots still trusts what the operator named
        out.rescan(gpa, io, now) catch |e| switch (e) {
            error.Canceled => return e,
            else => {},
        };
        const before = out.map.count();
        try out.addCertsFromFilePath(gpa, io, now, Io.Dir.cwd(), path);
        if (out.map.count() == before) return error.NoCertificateInFile;
    }

    /// Does `path` hold at least one certificate that parses? (Asked once, at start.)
    pub fn checkCaFile(gpa: Allocator, io: Io, path: []const u8) !void {
        var bundle: std.crypto.Certificate.Bundle = .empty;
        defer bundle.deinit(gpa);
        try loadBundle(gpa, io, path, Io.Clock.real.now(io), &bundle);
    }

    /// With `ca_file`: gives the client its trust store before std.http would scan the system
    /// roots on its own (it does so whenever its clock is unset: at first use, and again each
    /// time netguard.Client refreshes the clock), so the extra authorities are always in it.
    fn ensureCa(h: *Http, c: *std.http.Client) !void {
        const path = h.ca_file orelse return;
        if (c.now != null) return;
        var bundle: std.crypto.Certificate.Bundle = .empty;
        defer bundle.deinit(h.gpa);
        const t = Io.Clock.real.now(h.io);
        try loadBundle(h.gpa, h.io, path, t, &bundle);
        try c.ca_bundle_lock.lock(h.io);
        defer c.ca_bundle_lock.unlock(h.io);
        c.now = t;
        std.mem.swap(std.crypto.Certificate.Bundle, &c.ca_bundle, &bundle);
    }

    fn cancel(ctx: *anyopaque) void {
        const h: *Http = @ptrCast(@alignCast(ctx));
        h.stopping.store(true, .release);
    }

    fn acquire(h: *Http) ?*Slot {
        while (!h.stopping.load(.acquire)) {
            for (&h.slots) |*sl| {
                if (sl.busy.cmpxchgStrong(false, true, .acquire, .monotonic) == null) return sl;
            }
            h.io.sleep(.fromMilliseconds(1), .awake) catch {};
        }
        return null;
    }

    fn call(ctx: *anyopaque, req: *const g.HttpRequest, out: *std.ArrayList(u8), gpa: Allocator) anyerror!g.gate.Reply {
        const h: *Http = @ptrCast(@alignCast(ctx));
        const sl = h.acquire() orelse return error.Stopped;
        defer sl.busy.store(false, .release);
        sl.client.prepare(netguard.wallMs());
        defer sl.client.done(netguard.wallMs());
        try h.ensureCa(&sl.client.http);
        // std.http wants the body mutable; this copy is wiped (a resolve body holds a key)
        const body = try gpa.dupe(u8, req.body);
        defer {
            std.crypto.secureZero(u8, body);
            gpa.free(body);
        }
        var aw: Io.Writer.Allocating = .fromArrayList(gpa, out);
        defer out.* = aw.toArrayList();
        var ab: netguard.Abort = .{};
        // A pooled connection the gate closed fails on first use: once more on a fresh one.
        // Safe to repeat: resolve and free only read, usage is idempotent on its batch id.
        var attempt: u32 = 0;
        while (true) : (attempt += 1) {
            aw.writer.end = 0;
            ab.reset();
            return netguard.timed(h.io, req.timeout_ms, &h.stopping, &ab, once, .{ &sl.client.http, req, body, &aw.writer, &ab }) catch |e| {
                sl.client.noteError(e, netguard.wallMs());
                if (attempt == 0 and retryable(e)) {
                    sl.client.dropPool();
                    continue;
                }
                return e;
            };
        }
    }

    fn retryable(e: anyerror) bool {
        return switch (e) {
            error.HttpConnectionClosing, error.ConnectionResetByPeer, error.BrokenPipe, error.HttpRequestTruncated, error.ReadFailed, error.WriteFailed, error.EndOfStream => true,
            else => false,
        };
    }

    fn once(c: *std.http.Client, req: *const g.HttpRequest, body: []u8, w: *Io.Writer, abort: *netguard.Abort) !g.gate.Reply {
        const uri = try std.Uri.parse(req.url);
        var ab: [600]u8 = undefined;
        defer std.crypto.secureZero(u8, &ab);
        const auth = try std.fmt.bufPrint(&ab, "Bearer {s}", .{req.token});
        // (no redirects: the credential goes to the configured host only)
        var r = try c.request(if (req.post) .POST else .GET, uri, .{
            .redirect_behavior = .unhandled,
            .headers = .{
                .content_type = if (req.post) .{ .override = "application/json" } else .default,
                .accept_encoding = .omit,
                .user_agent = .{ .override = "deepwave" },
                .authorization = .{ .override = auth },
            },
            .extra_headers = &.{.{ .name = "accept", .value = "application/json" }},
        });
        defer r.deinit();
        errdefer if (r.connection) |conn| {
            conn.closing = true;
        };
        try abort.arm(netguard.socketOf(r.connection.?));
        defer abort.disarm();
        if (req.post) try r.sendBodyComplete(body) else try r.sendBodiless();
        var res = try r.receiveHead(&.{});
        if (res.head.content_encoding != .identity) return error.UnsupportedCompressionMethod;
        var reply: g.gate.Reply = .{ .status = @intFromEnum(res.head.status) };
        // (read before the body: the head's bytes are the connection's buffer)
        var it = res.head.iterateHeaders();
        while (it.next()) |hd| {
            if (std.ascii.eqlIgnoreCase(hd.name, "retry-after")) reply.retry_after_ms = g.contract.retryAfterMs(hd.value);
        }
        const reader = res.reader(&.{});
        var left: usize = g.contract.max_answer_bytes + 1;
        while (left > 0) {
            left -= reader.stream(w, .limited(left)) catch |err| switch (err) {
                error.EndOfStream => return reply,
                error.ReadFailed => return res.bodyErr() orelse error.ReadFailed,
                error.WriteFailed => return error.WriteFailed,
            };
        }
        return error.AnswerTooLarge;
    }
};

/// Top-level occurrences of field 1 in a protobuf message: the `requests` of a
/// BatchGetObjectsRequest, the `digests` of a BatchGetTransactionsRequest. Null when the bytes
/// do not parse (the service will say so; the gate then charges the flat weight).
pub fn countField1(b: []const u8) ?u32 {
    var p: usize = 0;
    var n: u32 = 0;
    while (p < b.len) {
        var tag: u64 = 0;
        var shift: u6 = 0;
        while (true) {
            if (p >= b.len or shift > 56) return null;
            const x = b[p];
            p += 1;
            tag |= @as(u64, x & 0x7f) << shift;
            if (x & 0x80 == 0) break;
            shift += 7;
        }
        const field = tag >> 3;
        switch (@as(u3, @truncate(tag))) {
            0 => {
                while (true) {
                    if (p >= b.len) return null;
                    p += 1;
                    if (b[p - 1] & 0x80 == 0) break;
                }
            },
            1 => p += 8,
            5 => p += 4,
            2 => {
                var len: u64 = 0;
                shift = 0;
                while (true) {
                    if (p >= b.len or shift > 56) return null;
                    const x = b[p];
                    p += 1;
                    len |= @as(u64, x & 0x7f) << shift;
                    if (x & 0x80 == 0) break;
                    shift += 7;
                }
                if (len > b.len - p) return null;
                p += @intCast(len);
                if (field == 1) n +|= 1;
            },
            else => return null,
        }
        if (p > b.len) return null;
    }
    return n;
}

comptime {
    std.debug.assert(@sizeOf(NodeGate.Scope) <= edge.forward.GateScope.size);
    std.debug.assert(@alignOf(NodeGate.Scope) <= 16);
}

comptime {
    std.debug.assert(@sizeOf(g.Ticket) <= native.gate.Ticket.size);
    std.debug.assert(@alignOf(g.Ticket) <= 16);
}

pub const NodeGate = struct {
    gpa: Allocator,
    io: Io,
    methods: g.Methods,
    http: Http,
    core: *g.Gate,
    token: []u8,
    dir: Io.Dir,
    proxies: [max_proxies]g.ident.Cidr = undefined,
    inner: h2.Handler = undefined,
    wrapped: bool = false,
    /// zui/1 method id -> gate method id.
    zui: [64]u8 = @splat(g.Methods.other),
    /// Streams open through the gate (tests: leak check).
    streams: Atomic(u32) = .init(0),

    /// Reads the credential, opens the directory and starts the gate's threads. `transport`
    /// null: the node's own HTTPS client.
    pub fn start(gpa: Allocator, io: Io, s: Settings, transport: ?g.Transport) !*NodeGate {
        if (check(&s) != null) return if (!g.contract.validEdgeId(s.edge_id)) error.GateEdgeId else error.GateUrl;
        // a named CA file that cannot be read is a mistake in the flags, not an outage
        if (s.ca_file) |path| Http.checkCaFile(gpa, io, path) catch return error.GateCaFile;
        const raw = Io.Dir.cwd().readFileAlloc(io, s.token_file, gpa, .limited(4096)) catch return error.GateTokenFile;
        defer {
            std.crypto.secureZero(u8, raw);
            gpa.free(raw);
        }
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        // the gate refuses a shorter credential, so a short one is a mistake in the file
        if (trimmed.len < g.contract.min_token_len or trimmed.len > 512) return error.GateTokenTooShort;
        for (trimmed) |c| if (c <= 0x20 or c >= 0x7f) return error.GateTokenFile;
        const token = try gpa.dupe(u8, trimmed);
        errdefer {
            std.crypto.secureZero(u8, token);
            gpa.free(token);
        }
        Io.Dir.cwd().createDirPath(io, s.dir) catch return error.GateDir;
        var dir = Io.Dir.cwd().openDir(io, s.dir, .{}) catch return error.GateDir;
        errdefer dir.close(io);
        const ng = try gpa.create(NodeGate);
        errdefer gpa.destroy(ng);
        ng.* = .{ .gpa = gpa, .io = io, .methods = g.Methods.init(&method_defs), .http = Http.init(gpa, io), .core = undefined, .token = token, .dir = dir };
        errdefer ng.http.deinit();
        ng.http.ca_file = s.ca_file;
        const np = @min(s.proxies.len, max_proxies);
        @memcpy(ng.proxies[0..np], s.proxies[0..np]);
        inline for (@typeInfo(proto.Method).@"enum".field_names) |name| {
            const id: u64 = @intFromEnum(@field(proto.Method, name));
            if (id < ng.zui.len) ng.zui[@intCast(id)] = ng.methods.id("zui.1/" ++ name);
        }
        ng.core = try g.Gate.init(gpa, io, .{
            .base_url = s.url,
            .token = token,
            .edge_id = s.edge_id,
            .dir = dir,
            .proxies = ng.proxies[0..np],
            .methods = &ng.methods,
            .transport = transport orelse ng.http.transport(),
            .log = s.log,
        });
        errdefer ng.core.deinit();
        try ng.core.start();
        return ng;
    }

    /// Stops the gate's threads and journals what was counted (nothing counted is lost).
    pub fn stop(ng: *NodeGate) void {
        ng.core.stop();
    }

    pub fn deinit(ng: *NodeGate) void {
        const gpa = ng.gpa;
        ng.core.deinit();
        ng.http.deinit();
        ng.dir.close(ng.io);
        std.crypto.secureZero(u8, ng.token);
        gpa.free(ng.token);
        gpa.destroy(ng);
    }

    pub fn renderMetrics(ng: *NodeGate, w: *Io.Writer) !void {
        return ng.core.renderMetrics(w);
    }

    // ------------------------------------------------------------ sui.rpc.v2

    /// The serve handler with the gate in front of `inner`. Call once.
    pub fn handler(ng: *NodeGate, inner: h2.Handler) h2.Handler {
        ng.inner = inner;
        ng.wrapped = true;
        return .{
            .ctx = ng,
            .call = callFn,
            .bidi = if (inner.bidi != null) bidiFn else null,
            .known = if (inner.known != null) knownFn else null,
            .method = if (inner.method != null) methodFn else null,
            .compress = if (inner.compress != null) compressFn else null,
            .info = if (inner.info != null) infoFn else null,
            .health = if (inner.health != null) healthFn else null,
        };
    }

    fn self(ctx: *anyopaque) *NodeGate {
        return @ptrCast(@alignCast(ctx));
    }
    fn bidiFn(ctx: *anyopaque, path: []const u8) bool {
        return self(ctx).inner.bidi.?(self(ctx).inner.ctx, path);
    }
    fn knownFn(ctx: *anyopaque, path: []const u8) bool {
        return self(ctx).inner.known.?(self(ctx).inner.ctx, path);
    }
    fn methodFn(ctx: *anyopaque, path: []const u8) bool {
        return self(ctx).inner.method.?(self(ctx).inner.ctx, path);
    }
    fn compressFn(ctx: *anyopaque, path: []const u8) bool {
        return self(ctx).inner.compress.?(self(ctx).inner.ctx, path);
    }
    fn infoFn(ctx: *anyopaque, out: *h2.meta.Info) void {
        return self(ctx).inner.info.?(self(ctx).inner.ctx, out);
    }
    fn healthFn(ctx: *anyopaque, threshold_s: ?u32) bool {
        return self(ctx).inner.health.?(self(ctx).inner.ctx, threshold_s);
    }

    fn refuseH2(rs: *h2.ResponseStream, d: *const g.Deny) h2.Status {
        rs.setMessage(d.message);
        if (d.reason == .limited) rs.retry_after_ms = d.retry_after_ms;
        return h2Status(d.code());
    }

    fn h2Status(c: g.gate.Code) h2.Status {
        return switch (c) {
            .unauthenticated => .unauthenticated,
            .permission_denied => .permission_denied,
            .resource_exhausted => .resource_exhausted,
        };
    }

    fn callFn(ctx: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const ng = self(ctx);
        const mid = ng.methods.id(h2.meta.pathOnly(req.path));
        const kind = ng.methods.kinds[mid];
        // health checks, reflection and service info: never limited, never counted
        if (kind == .free) return ng.inner.call(ng.inner.ctx, req, rs);
        const c: g.Call = .{
            .key = req.api_key,
            .peer = g.Ip.parsePeer(req.peer),
            .forwarded_for = req.forwarded_for,
            .method = mid,
            .items = if (kind == .batch) countField1(req.body) else null,
        };
        var ticket = switch (ng.core.admitWait(&c)) {
            .allow => |t| t,
            .deny => |d| return refuseH2(rs, &d),
            .wait => unreachable,
        };
        if (kind != .stream) {
            const status = ng.inner.call(ng.inner.ctx, req, rs);
            // Everything is answered here on a node without a forwarder: local.
            ng.core.settle(&ticket, .local, status == .ok or status == .deferred or status == .held, ticket.opened_ns);
            return status;
        }
        // A server stream: the pump the service attaches is wrapped, so its messages are
        // counted and the stream's slot is given back when it ends.
        var cap: Capture = .{ .ng = ng, .ticket = ticket, .key = req.api_key, .prev = h2.pump.current };
        h2.pump.current = .{ .ctx = &cap, .attach = Capture.attach };
        const status = ng.inner.call(ng.inner.ctx, req, rs);
        h2.pump.current = cap.prev;
        ng.core.settle(&ticket, .local, status == .deferred and cap.attached, ticket.opened_ns);
        if (!cap.attached) ng.core.streamClose(&ticket, ticket.opened_ns);
        return status;
    }

    const Capture = struct {
        ng: *NodeGate,
        ticket: g.Ticket,
        key: []const u8,
        prev: ?h2.pump.Attacher,
        attached: bool = false,

        fn attach(ctx: *anyopaque, stream_id: u32, p: h2.Pump) bool {
            const cap: *Capture = @ptrCast(@alignCast(ctx));
            const prev = cap.prev orelse return false;
            if (cap.attached) return false;
            const gpa = cap.ng.gpa;
            const w = gpa.create(StreamWrap) catch return false;
            w.* = .{ .ng = cap.ng, .inner = p, .ticket = cap.ticket };
            w.key_len = @intCast(@min(cap.key.len, w.key.len));
            @memcpy(w.key[0..w.key_len], cap.key[0..w.key_len]);
            if (!prev.attach(prev.ctx, stream_id, .{ .ctx = w, .run = StreamWrap.run, .wake = StreamWrap.wake, .done = StreamWrap.done })) {
                std.crypto.secureZero(u8, &w.key);
                gpa.destroy(w);
                return false;
            }
            _ = cap.ng.streams.fetchAdd(1, .monotonic);
            cap.attached = true;
            return true;
        }
    };

    /// A service's stream pump with the gate around it. Freed by `done`, which every runtime
    /// calls exactly once.
    const StreamWrap = struct {
        ng: *NodeGate,
        inner: h2.Pump,
        ticket: g.Ticket,
        key: [g.contract.max_key_len]u8 = undefined,
        key_len: u16 = 0,
        real: ?*h2.Link = null,
        ended: bool = false,

        fn run(ctx: *anyopaque, link: *h2.Link) void {
            const w: *StreamWrap = @ptrCast(@alignCast(ctx));
            w.real = link;
            var mine: h2.Link = .{ .impl = w, .vt = &vt, .stream_id = link.stream_id };
            w.inner.run(w.inner.ctx, &mine);
        }
        fn wake(ctx: *anyopaque) void {
            const w: *StreamWrap = @ptrCast(@alignCast(ctx));
            w.inner.wake(w.inner.ctx);
        }
        fn done(ctx: *anyopaque) void {
            const w: *StreamWrap = @ptrCast(@alignCast(ctx));
            if (w.inner.done) |d| d(w.inner.ctx);
            const ng = w.ng;
            ng.core.streamClose(&w.ticket, ng.core.cfg.clock.mono(ng.core.cfg.clock.ctx));
            std.crypto.secureZero(u8, &w.key);
            _ = ng.streams.fetchSub(1, .monotonic);
            ng.gpa.destroy(w);
        }
        fn send(impl: *anyopaque, _: u32, payload: []const u8) error{Closed}!void {
            const w: *StreamWrap = @ptrCast(@alignCast(impl));
            const real = w.real orelse return error.Closed;
            if (w.ended) return error.Closed;
            const core = w.ng.core;
            if (core.streamTick(&w.ticket, w.key[0..w.key_len], core.cfg.clock.mono(core.cfg.clock.ctx))) |deny| {
                // the caller may no longer hold the stream: it ends with the gate's status
                w.ended = true;
                real.finish(h2Status(deny.code()), deny.message);
                return error.Closed;
            }
            try real.send(payload);
            core.streamMsgs(&w.ticket, 1);
        }
        fn finish(impl: *anyopaque, _: u32, status: h2.Status, text: []const u8, details_bin: []const u8) void {
            const w: *StreamWrap = @ptrCast(@alignCast(impl));
            const real = w.real orelse return;
            if (w.ended) return;
            w.ended = true;
            real.finishDetails(status, text, details_bin);
        }
        fn blocked(impl: *anyopaque, _: u32) ?bool {
            const w: *StreamWrap = @ptrCast(@alignCast(impl));
            const real = w.real orelse return null;
            if (w.ended) return null;
            return real.blocked();
        }
        const vt: h2.Link.VTable = .{ .send = send, .finish = finish, .blocked = blocked };
    };

    // ------------------------------------------------------------ an edge that forwards

    /// What the gate keeps on the stack of one call through `edge.forward.Forwarder`.
    const Scope = struct {
        ng: *NodeGate,
        state: enum(u8) { free, denied, admitted } = .free,
        stream: bool = false,
        forwarded: bool = false,
        ticket: g.Ticket = .{},
        cap: Capture = undefined,
    };

    pub fn forwardHook(ng: *NodeGate) edge.forward.GateHook {
        return .{ .ctx = ng, .begin = fBegin, .end = fEnd };
    }

    pub fn meterHook(ng: *NodeGate) edge.forward.MeterHook {
        return .{ .ctx = ng, .f = fMeter };
    }

    fn scopeOf(s: *edge.forward.GateScope) *Scope {
        return @ptrCast(@alignCast(&s.bytes));
    }

    /// Before routing: admission. A refusal goes into `caller.deny` (the routing policy then
    /// denies the call); an admitted call's scope goes into `caller.ticket` for the meter.
    fn fBegin(ctx: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream, caller: *edge.route.Caller, scope: *edge.forward.GateScope) void {
        const ng = self(ctx);
        const sc = scopeOf(scope);
        sc.* = .{ .ng = ng };
        const mid = ng.methods.id(h2.meta.pathOnly(req.path));
        const kind = ng.methods.kinds[mid];
        if (kind == .free) return;
        const c: g.Call = .{
            .key = req.api_key,
            .peer = g.Ip.parsePeer(req.peer),
            .forwarded_for = req.forwarded_for,
            .method = mid,
            .items = if (kind == .batch) countField1(req.body) else null,
        };
        switch (ng.core.admitWait(&c)) {
            .deny => |d| {
                sc.state = .denied;
                if (d.reason == .limited) rs.retry_after_ms = d.retry_after_ms;
                caller.deny = .{ .code = @intFromEnum(h2Status(d.code())), .message = d.message };
            },
            .allow => |t| {
                sc.state = .admitted;
                sc.ticket = t;
                caller.ticket = sc;
                if (kind == .stream) {
                    // local or relayed from the core, the stream's pump is attached through here
                    sc.stream = true;
                    sc.cap = .{ .ng = ng, .ticket = t, .key = req.api_key, .prev = h2.pump.current };
                    h2.pump.current = .{ .ctx = &sc.cap, .attach = Capture.attach };
                }
            },
            .wait => unreachable,
        }
    }

    /// The forwarder's one metering point: was the call answered here or sent on to the core?
    fn fMeter(_: *anyopaque, m: *const edge.forward.Metered) void {
        const sc: *Scope = @ptrCast(@alignCast(m.caller.ticket orelse return));
        sc.forwarded = m.outcome == .forwarded;
    }

    /// The call is over: it is counted (local or forwarded, with the forward multiplier), and a
    /// call that failed costs nothing.
    fn fEnd(_: *anyopaque, scope: *edge.forward.GateScope, status: h2.Status) void {
        const sc = scopeOf(scope);
        if (sc.stream) h2.pump.current = sc.cap.prev;
        if (sc.state != .admitted) return;
        const ng = sc.ng;
        const route: g.gate.Route = if (sc.forwarded) .forwarded else .local;
        if (sc.stream) {
            ng.core.settle(&sc.ticket, route, status == .deferred and sc.cap.attached, sc.ticket.opened_ns);
            if (!sc.cap.attached) ng.core.streamClose(&sc.ticket, sc.ticket.opened_ns);
        } else {
            ng.core.settle(&sc.ticket, route, status == .ok or status == .deferred or status == .held, sc.ticket.opened_ns);
        }
    }

    // ------------------------------------------------------------ zui/1

    pub fn nativeHook(ng: *NodeGate) native.gate.Hook {
        return .{ .ctx = ng, .hello = nHello, .admit = nAdmit, .settle = nSettle, .stream_frames = nFrames, .stream_close = nClose };
    }

    fn now(ng: *NodeGate) u64 {
        return ng.core.cfg.clock.mono(ng.core.cfg.clock.ctx);
    }

    fn refusal(d: *const g.Deny) native.gate.Refusal {
        return .{
            // zui/1 has a code for each: 7 UNAUTHENTICATED, 8 PERMISSION_DENIED, 6 RATE_LIMITED
            .code = switch (d.code()) {
                .unauthenticated => .unauthenticated,
                .permission_denied => .permission_denied,
                .resource_exhausted => .rate_limited,
            },
            .message = d.message,
            .retry_after_ms = d.retry_after_ms,
        };
    }

    fn ticketOf(t: anytype) switch (@TypeOf(t)) {
        *native.gate.Ticket => *g.Ticket,
        *const native.gate.Ticket => *const g.Ticket,
        else => unreachable,
    } {
        return @ptrCast(@alignCast(&t.bytes));
    }

    fn nHello(ctx: *anyopaque, key: []const u8, peer: Io.net.IpAddress, may_wait: bool) native.gate.Hello {
        const ng = self(ctx);
        return switch (ng.core.checkKey(key, g.Ip.fromNet(peer), may_wait, ng.now())) {
            .ok => .ok,
            .wait => .wait,
            .deny => |d| .{ .deny = refusal(&d) },
        };
    }

    fn nAdmit(ctx: *anyopaque, key: []const u8, peer: Io.net.IpAddress, method: proto.Method, body: []const u8, may_wait: bool) native.gate.Verdict {
        const ng = self(ctx);
        const raw: u64 = @intFromEnum(method);
        const mid = if (raw < ng.zui.len) ng.zui[@intCast(raw)] else g.Methods.other;
        var items: ?u32 = null;
        if (ng.methods.kinds[mid] == .batch) {
            // both batch requests begin with the number of items (ULEB128)
            var r: proto.R = .{ .b = body };
            if (r.uleb()) |n| items = @intCast(@min(n, std.math.maxInt(u32))) else |_| {}
        }
        const c: g.Call = .{ .key = key, .peer = g.Ip.fromNet(peer), .method = mid, .items = items, .may_wait = may_wait };
        switch (ng.core.admit(&c, ng.now())) {
            .allow => |t| {
                var out: native.gate.Ticket = .{};
                ticketOf(&out).* = t;
                return .{ .allow = out };
            },
            .wait => return .wait,
            .deny => |d| return .{ .deny = refusal(&d) },
        }
    }

    fn nSettle(ctx: *anyopaque, t: *const native.gate.Ticket, ok: bool) void {
        const ng = self(ctx);
        const ticket = ticketOf(t);
        ng.core.settle(ticket, .local, ok, ticket.opened_ns);
    }

    fn nFrames(ctx: *anyopaque, t: *native.gate.Ticket, key: []const u8, frames: u32) ?native.gate.Refusal {
        const ng = self(ctx);
        const ticket = ticketOf(t);
        ng.core.streamMsgs(ticket, frames);
        if (ng.core.streamTick(ticket, key, ng.now())) |d| return refusal(&d);
        return null;
    }

    fn nClose(ctx: *anyopaque, t: *native.gate.Ticket) void {
        const ng = self(ctx);
        ng.core.streamClose(ticketOf(t), ng.now());
    }
};

test "countField1: the items of a batch request" {
    // requests: 3 x field 1 (len 2), read_mask: field 2
    const msg = [_]u8{ 0x0a, 2, 1, 2, 0x0a, 2, 3, 4, 0x12, 1, 9, 0x0a, 2, 5, 6 };
    try std.testing.expectEqual(@as(?u32, 3), countField1(&msg));
    try std.testing.expectEqual(@as(?u32, 0), countField1(""));
    try std.testing.expectEqual(@as(?u32, 0), countField1(&.{ 0x10, 0x96, 0x01 }));
    try std.testing.expectEqual(@as(?u32, null), countField1(&.{ 0x0a, 9, 1 })); // length runs past the end
    try std.testing.expectEqual(@as(?u32, null), countField1(&.{0x0b})); // a group
    try std.testing.expectEqual(@as(?u32, null), countField1(&.{ 0x0a, 0x80 })); // length cut short
}

/// The zui/1 method names the meter emits, as usage rows and as keys of `weights`: one per
/// method of the protocol (`native.proto.Method`), spelled `zui.1/<name>`. `hello` is never
/// charged or reported; an id outside the protocol is reported as `other`.
pub const zui_method_names = [_][]const u8{
    "zui.1/hello",
    "zui.1/get_object",
    "zui.1/batch_get_objects",
    "zui.1/get_checkpoint",
    "zui.1/get_transaction",
    "zui.1/batch_get_transactions",
    "zui.1/list_owned_objects",
    "zui.1/get_balance",
    "zui.1/list_balances",
    "zui.1/dry_run",
    "zui.1/submit_transaction",
    "zui.1/get_dictionary",
    "zui.1/get_epoch_proof",
    "zui.1/get_epoch_info",
    "zui.1/get_checkpoint_feed",
    "zui.1/subscribe",
    "zui.1/pair_relay",
};

test "gRPC method names: the full path with its package, for every method the edge routes" {
    const m = g.Methods.init(&method_defs);
    // every sui.rpc.v2 method the routing table knows has a row name of its own, which is its
    // gRPC path without the leading slash: `<package>.<Service>/<Method>`
    for (edge.route.paths) |e| {
        const id = m.id(e.path);
        try std.testing.expect(id != g.Methods.other);
        try std.testing.expectEqualStrings(e.path[1..], m.name_(id));
        // a query string or the bare name leads to the same row
        var qb: [128]u8 = undefined;
        try std.testing.expectEqual(id, m.id(h2.meta.pathOnly(try std.fmt.bufPrint(&qb, "{s}?x=1", .{e.path}))));
        try std.testing.expectEqual(id, m.id(e.path[1..]));
    }
    // no name in the table lacks its package (the service looks weights up by the full path)
    for (method_defs) |d| {
        const slash = std.mem.indexOfScalar(u8, d.name, '/').?;
        try std.testing.expect(std.mem.indexOfScalar(u8, d.name[0..slash], '.') != null);
        try std.testing.expect(d.name[0] != '/');
    }
    // a method without its package is not an alias of anything: it is "other"
    try std.testing.expectEqual(g.Methods.other, m.id("/TransactionExecutionService/ExecuteTransaction"));
    try std.testing.expectEqual(g.Methods.other, m.id("ExecuteTransaction"));
    try std.testing.expectEqualStrings("sui.rpc.v2.TransactionExecutionService/ExecuteTransaction", m.name_(m.id("/sui.rpc.v2.TransactionExecutionService/ExecuteTransaction")));
    try std.testing.expectEqual(g.methods.Kind.stream, m.kinds[m.id("/sui.rpc.v2.SubscriptionService/SubscribeTransactions")]);
}

test "zui/1 method names: exactly the protocol's methods, each with a row name of its own" {
    const m = g.Methods.init(&method_defs);
    const fields = @typeInfo(proto.Method).@"enum".field_names;
    try std.testing.expectEqual(fields.len, zui_method_names.len);
    inline for (fields, 0..) |name, i| {
        try std.testing.expectEqualStrings("zui.1/" ++ name, zui_method_names[i]);
        const id = m.id(zui_method_names[i]);
        try std.testing.expect(id != g.Methods.other);
        try std.testing.expectEqualStrings(zui_method_names[i], m.name_(id));
    }
    // no other "zui.1/" name is priced
    var n: usize = 0;
    for (method_defs) |d| n += @intFromBool(std.mem.startsWith(u8, d.name, "zui.1/"));
    try std.testing.expectEqual(zui_method_names.len, n);
    try std.testing.expectEqual(g.methods.Kind.free, m.kinds[m.id("zui.1/hello")]);
    try std.testing.expectEqual(g.methods.Kind.stream, m.kinds[m.id("zui.1/subscribe")]);
    try std.testing.expectEqual(g.methods.Kind.batch, m.kinds[m.id("zui.1/batch_get_transactions")]);
    try std.testing.expectEqual(g.Methods.other, m.id("zui.1/ping"));
}

test "flags: what --gate refuses before anything starts" {
    const ok: Settings = .{ .url = "https://gate.example/v1/gate", .token_file = "/x", .edge_id = "e1", .dir = "/y" };
    try std.testing.expect(check(&ok) == null);
    var s = ok;
    // plain http: only for a gate on this machine
    inline for (.{ "http://gate.example", "http://10.0.0.1:8080/v1", "http://127.0.0.1.gate.example/", "http://localhost.gate.example", "http://user@127.0.0.1/", "http://[2001:db8::1]:80/", "http://", "http:///x", "http://[::1]x/" }) |u| {
        s.url = u;
        try std.testing.expect(std.mem.indexOf(u8, check(&s).?, "--gate URL") != null);
    }
    inline for (.{ "http://127.0.0.1:38080/v1/gate", "http://127.9.9.9", "http://localhost:8080", "http://LOCALHOST/v1/gate/", "http://[::1]:8080/v1", "http://[::1]" }) |u| {
        s.url = u;
        try std.testing.expect(check(&s) == null);
    }
    s = ok;
    s.edge_id = "has space";
    try std.testing.expect(std.mem.indexOf(u8, check(&s).?, "--gate-edge-id") != null);
    s = ok;
    s.token_file = "";
    try std.testing.expect(std.mem.indexOf(u8, check(&s).?, "--gate-token-file") != null);
    // every zui/1 method has its own row name
    const m = g.Methods.init(&method_defs);
    try std.testing.expect(m.n < g.methods.max_methods);
    try std.testing.expect(m.id("zui.1/get_object") != g.Methods.other);
    try std.testing.expectEqual(g.methods.Kind.free, m.kinds[m.id("/sui.rpc.v2.LedgerService/GetServiceInfo")]);
    try std.testing.expectEqual(g.methods.Kind.stream, m.kinds[m.id("/sui.rpc.v2.SubscriptionService/SubscribeCheckpoints")]);
    try std.testing.expectEqual(g.methods.Kind.batch, m.kinds[m.id("zui.1/batch_get_objects")]);
}
