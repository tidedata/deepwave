//! deepwave-execute: the live ExecuteTransaction path outside the node (DROP-IN G10).
//!
//!   deepwave-execute probe   --upstream HOST:PORT[/plain]
//!       GetEpoch from the upstream fullnode, then open TLS to every validator and report.
//!   deepwave-execute serve   --upstream HOST:PORT[/plain] --listen ADDR [--passthrough] [--record FILE] [--no-local]
//!       sui.rpc.v2 ExecuteTransaction over h2c on ADDR, committee from the upstream (60 s refresh);
//!       already-executed transactions and address aliases come from the upstream (the node next to
//!       it) unless --no-local. --passthrough forwards every other unary call to the upstream
//!       unchanged; --record appends one JSON line per execute (the canary's audit trail).
//!   deepwave-execute compare --upstream HOST:PORT --key FILE --count N [--lanes K] [--out DIR] [--up-rps N] [--keep N] [--fund]
//!       TESTNET ONLY. Builds and signs N transactions (transfers, splits, Move calls incl. a shared
//!       Clock read and a kiosk listing with events), executes each through deepwave's driver AND the
//!       upstream fullnode (deepwave first, upstream first, or both at once, rotating), and compares the
//!       two ExecuteTransactionResponse messages byte for byte. Mismatches go to DIR.
//!
//!   deepwave-execute canary  --zui HOST:PORT[/plain] --reference HOST:PORT[/plain] --key FILE [--spend] [--count N]
//!       Mainnet canary (DROP-IN 5.7): refused-for-free checks, then with --spend tiny self-transfers
//!       sent to both nodes (deepwave first, reference first), resubmits, stale gas and the
//!       wait-for-checkpoint poll, every answer compared byte for byte (tools/execute/mainnet-canary.sh).
//!
//! The key file is a Sui keystore entry (base64 of flag 0 + 32-byte Ed25519 seed); it is never printed.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const rpc_exec = @import("rpc_exec");
const protocol = @import("protocol");
const serve = @import("serve");
const types = @import("types");
const bcs = @import("bcs");
const proto = serve.proto;
const live = rpc_exec.live;
const grpc = live.grpc_client;
const Upstream = live.upstream.Upstream;
const Path = live.validators.Path;
const path_names = std.meta.fieldNames(Path);
const handler = rpc_exec.driver.handler;
const Ed25519 = std.crypto.sign.Ed25519;
const Blake2b256 = std.crypto.hash.blake2.Blake2b256;

const path_get_epoch = "/sui.rpc.v2.LedgerService/GetEpoch";
const path_list_owned = "/sui.rpc.v2.StateService/ListOwnedObjects";
const path_execute = "/sui.rpc.v2.TransactionExecutionService/ExecuteTransaction";

const usage =
    \\deepwave-execute probe   --upstream HOST:PORT[/plain]
    \\deepwave-execute serve   --upstream HOST:PORT[/plain] --listen ADDR [--passthrough] [--record FILE] [--no-local]
    \\deepwave-execute compare --upstream HOST:PORT --key FILE --count N [--lanes K] [--out DIR] [--up-rps N] [--keep N] [--fund]   (testnet only)
    \\deepwave-execute sigcases --upstream HOST:PORT --key FILE [--out DIR]   (testnet: multisig/zkLogin/passkey texts)
    \\deepwave-execute canary --zui HOST:PORT[/plain] --reference HOST:PORT[/plain] --key FILE [--spend] [--count N] [--budget MIST] [--out DIR] [--wait-cp-s N]
    \\      the same tiny transactions through two nodes' ExecuteTransaction (deepwave and sui-node),
    \\      responses compared byte for byte; without --spend only checks both nodes refuse for free
    \\deepwave-execute recover --upstream HOST:PORT[/plain] --pending-tx-dir DIR [--seed-vectors] [--no-local] [--wait-s N]
    \\      resubmit what the pending-tx log holds (the node's restart path) and wait until it is empty;
    \\      --seed-vectors first writes the embedded testnet vectors (already executed) into the log
    \\  any mode: [--amp N] [--detail-acks N] [--no-latency-checks] [--trace-ms MS] [--pending-tx-dir DIR]
    \\
;

pub fn main(init: std.process.Init) !u8 {
    // Exit without unwinding: validator reader threads are detached and still hold the allocator.
    std.process.exit(try mainInner(init));
}

fn mainInner(init: std.process.Init) !u8 {
    // smp_allocator in every mode: the debug SafeAllocator never reuses memory, so a long compare
    // or serve grew past the Mac's 7 GB guard (8,570 transactions in)
    _ = init.gpa;
    const gpa = std.heap.smp_allocator;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        std.debug.print("{s}", .{usage});
        return 2;
    }
    var upstream: []const u8 = "";
    var listen: []const u8 = "127.0.0.1:9110";
    var key_path: []const u8 = "";
    var out_dir: []const u8 = "zig-out/execute-compare";
    var count: u64 = 10;
    var lanes: u32 = 8;
    var no_local = false;
    var passthrough = false;
    var record_path: ?[]const u8 = null;
    var amp: ?u64 = null;
    var detail_acks: ?u32 = null;
    var checks = true;
    var pending_dir: ?[]const u8 = null;
    var seed_vectors = false;
    var wait_s: u64 = 180;
    var count_set = false;
    var canary: CanaryOpts = .{ .zui = "", .reference = "", .key_path = "", .spend = false, .count = 1, .budget = 10_000_000, .out_dir = "zig-out/execute-canary", .wait_cp_s = 30 };
    var i: usize = 2;
    keep_left = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        const v = if (i + 1 < args.len) args[i + 1] else "";
        if (std.mem.eql(u8, a, "--passthrough")) {
            passthrough = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--record")) {
            record_path = v;
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, a, "--no-local")) {
            no_local = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--fund")) {
            fund = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--keep")) {
            keep_left = try std.fmt.parseInt(u32, v, 10);
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, a, "--amp")) {
            amp = try std.fmt.parseInt(u64, v, 10);
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, a, "--detail-acks")) {
            detail_acks = try std.fmt.parseInt(u32, v, 10);
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, a, "--pending-tx-dir")) {
            pending_dir = v;
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, a, "--seed-vectors")) {
            seed_vectors = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--wait-s")) {
            wait_s = try std.fmt.parseInt(u64, v, 10);
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, a, "--spend")) {
            canary.spend = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--zui") or std.mem.eql(u8, a, "--reference") or std.mem.eql(u8, a, "--budget") or std.mem.eql(u8, a, "--wait-cp-s")) {
            if (std.mem.eql(u8, a, "--zui")) canary.zui = v else if (std.mem.eql(u8, a, "--reference")) canary.reference = v else if (std.mem.eql(u8, a, "--budget")) {
                canary.budget = try std.fmt.parseInt(u64, v, 10);
            } else canary.wait_cp_s = try std.fmt.parseInt(u64, v, 10);
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, a, "--no-latency-checks")) {
            checks = false;
            continue;
        }
        if (std.mem.eql(u8, a, "--trace-ms")) {
            live.validators.trace_slow_ms = try std.fmt.parseInt(u64, v, 10);
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, a, "--up-rps")) {
            up_interval_ns = std.time.ns_per_s / try std.fmt.parseInt(u64, v, 10);
            up_rps_set = true;
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, a, "--upstream")) upstream = v else if (std.mem.eql(u8, a, "--listen")) listen = v else if (std.mem.eql(u8, a, "--key") or std.mem.eql(u8, a, "--body-hex")) key_path = v else if (std.mem.eql(u8, a, "--path")) out_dir = v else if (std.mem.eql(u8, a, "--out")) out_dir = v else if (std.mem.eql(u8, a, "--count")) {
            count = try std.fmt.parseInt(u64, v, 10);
            count_set = true;
        } else if (std.mem.eql(u8, a, "--lanes")) lanes = try std.fmt.parseInt(u32, v, 10) else {
            std.debug.print("unknown option {s}\n{s}", .{ a, usage });
            return 2;
        }
        i += 1;
    }
    if (std.mem.eql(u8, args[1], "call")) {
        // debugging aid: deepwave-execute call --upstream H:P --path /svc/Method --body-hex HEX [--count N]
        const e2 = parseUpstream(upstream) orelse return 2;
        grpc.trace_frames = true;
        const c2 = try grpc.Conn.open(gpa, io, e2);
        defer c2.release();
        const body = try arena.alloc(u8, key_path.len / 2);
        _ = try std.fmt.hexToBytes(body, key_path);
        var k: u64 = 0;
        while (k < count) : (k += 1) {
            const t0 = live.validators.monotonicNs(io);
            const r = try grpc.callBlocking(arena, c2, out_dir, body, 15_000);
            const ms = (live.validators.monotonicNs(io) - t0) / std.time.ns_per_ms;
            switch (r) {
                .ok => |b| std.debug.print("call {d}: ok {d} B in {d} ms\n", .{ k, b.len, ms }),
                .status => |st| std.debug.print("call {d}: status {d} {s} in {d} ms\n", .{ k, st.code, st.message, ms }),
            }
        }
        return 0;
    }
    if (std.mem.eql(u8, args[1], "canary")) {
        canary.key_path = key_path;
        if (count_set) canary.count = count;
        for (args) |x| if (std.mem.eql(u8, x, "--out")) {
            canary.out_dir = out_dir;
        };
        return canaryCmd(gpa, io, canary);
    }
    const ep = parseUpstream(upstream) orelse {
        std.debug.print("--upstream HOST:PORT[/plain] required\n", .{});
        return 2;
    };
    const up = try Upstream.init(gpa, io, ep);
    defer up.deinit();
    if (!up_rps_set) up_interval_ns = 0; // pace only when asked (a public fullnode's 429 limit)

    var ex = live.LiveExecutor.init(gpa, io);
    if (pending_dir) |d| {
        const l = try live.pending_log.PendingLog.open(gpa, io, d);
        if (seed_vectors) try seedVectors(arena, l);
        std.debug.print("pending-tx log {s}: {d} pending, {d} torn bytes dropped\n", .{ d, l.count(), l.torn_bytes });
        ex.pending = l;
    }
    if (amp) |x| ex.min_amplification = x;
    if (detail_acks) |x| ex.detail_acks = x;
    ex.latency_checks = checks and !std.mem.eql(u8, args[1], "probe");
    const epoch_body = try getEpoch(arena, up);
    const epoch = try ex.setEpoch(epoch_body);
    if (ex.latency_checks) {
        // the first latency check round ranks the committee before the first transaction
        const t0 = live.validators.monotonicNs(io);
        while (live.validators.monotonicNs(io) - t0 < 12 * std.time.ns_per_s) {
            try Io.sleep(io, .fromMilliseconds(250), .awake);
            if (ex.current.?.pool.measured() * 100 >= info_members(epoch_body) * 80) break;
        }
        std.debug.print("latency checks: {d} validators measured\n", .{ex.current.?.pool.measured()});
    }
    const info = try live.validators.parseEpoch(arena, epoch_body);
    std.debug.print("epoch {d}: {d} validators, rgp {d}\n", .{ epoch, info.committee.members.len, info.reference_gas_price });

    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "probe")) return probe(gpa, io, &info);
    if (!no_local) {
        const us = try attachUpstream(gpa, io, &ex, up);
        // early validation's validity and input checks: the epoch's protocol config and chain
        if (info.protocol_version != 0) if (chainId(arena, up)) |cid| {
            // the epoch facts follow the committee refresh (rgp and protocol version change at
            // epoch boundaries)
            us.chain_id = cid;
            us.chain = if (std.mem.containsAtLeast(u8, ep.host, 1, "testnet")) .testnet else .mainnet;
            us.ex = &ex;
            ex.live_objects.?.env = .{ .ctx = us, .get = UpstreamStore.getEnv };
        } else |_| std.debug.print("GetServiceInfo failed: early validation without validity checks\n", .{});
    }
    if (std.mem.eql(u8, cmd, "serve")) {
        try ex.recoverPending();
        return serveCmd(gpa, io, &ex, up, listen, passthrough, record_path);
    }
    if (std.mem.eql(u8, cmd, "recover")) return recoverCmd(io, &ex, wait_s);
    if (std.mem.eql(u8, cmd, "sigcases")) {
        if (!std.mem.containsAtLeast(u8, ep.host, 1, "testnet")) {
            std.debug.print("sigcases runs on testnet only\n", .{});
            return 2;
        }
        return sigCasesCmd(gpa, io, &ex, up, key_path, out_dir, epoch, info.protocol_version);
    }
    if (std.mem.eql(u8, cmd, "compare")) {
        if (!std.mem.endsWith(u8, ep.host, "testnet.sui.io") and !std.mem.containsAtLeast(u8, ep.host, 1, "testnet")) {
            std.debug.print("compare runs on testnet only (upstream host must be a testnet fullnode)\n", .{});
            return 2;
        }
        return compare(gpa, io, &ex, up, key_path, count, lanes, out_dir, info.reference_gas_price);
    }
    std.debug.print("{s}", .{usage});
    return 2;
}

fn parseUpstream(s: []const u8) ?grpc.Endpoint {
    var text = s;
    var plain = false;
    if (std.mem.endsWith(u8, text, "/plain")) {
        plain = true;
        text = text[0 .. text.len - 6];
    }
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return null;
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch return null;
    return .{ .host = text[0..colon], .port = port, .security = if (plain) .plain else .ca };
}

/// `GetServiceInfo.chain_id` (base58 digest of checkpoint 0).
fn chainId(arena: Allocator, up: *Upstream) ![32]u8 {
    return switch (try upCall(arena, up, "/sui.rpc.v2.LedgerService/GetServiceInfo", "", 15_000)) {
        .ok => |b| serve.b58.decode32(field(b, 1) orelse return error.Upstream) orelse error.Upstream,
        .status => error.Upstream,
    };
}

fn getEpoch(arena: Allocator, up: *Upstream) ![]const u8 {
    const req = try live.validators.getEpochRequest(arena);
    return switch (try upCall(arena, up, path_get_epoch, req, 15_000)) {
        .ok => |b| b,
        .status => |s| {
            std.debug.print("GetEpoch failed: {d} {s}\n", .{ s.code, s.message });
            return error.Upstream;
        },
    };
}

// ------------------------------------------------------------------------------------------
// probe

fn probe(gpa: Allocator, io: Io, info: *const live.validators.EpochInfo) !u8 {
    var pool = try live.validators.Pool.init(gpa, io, &info.committee);
    defer pool.deinit();
    // a WaitForEffects ping on every validator (consensus position ping: empty request answers
    // an error or a ping response; either proves TLS + h2 + the validator service)
    var ok: u32 = 0;
    var stake: u64 = 0;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for (info.committee.members, 0..) |m, idx| {
        const c = pool.get(@intCast(idx)) orelse {
            std.debug.print("  {s}: bad address {s}\n", .{ info.committee.displayName(@intCast(idx)), m.network_address });
            continue;
        };
        const t0 = live.validators.monotonicNs(io);
        const r = try grpc.callBlocking(arena, c, "/sui.validator.Validator/WaitForEffects", "", 10_000);
        const ms = (live.validators.monotonicNs(io) - t0) / std.time.ns_per_ms;
        switch (r) {
            .ok => |b| {
                ok += 1;
                stake += m.stake;
                std.debug.print("  {s} ({s}) stake {d}: ok {d} B in {d} ms\n", .{ info.committee.displayName(@intCast(idx)), m.network_address, m.stake, b.len, ms });
            },
            .status => |s| {
                // a gRPC status from the validator still proves the transport
                if (s.code != 14 and s.code != 4) {
                    ok += 1;
                    stake += m.stake;
                }
                std.debug.print("  {s} ({s}) stake {d}: status {d} \"{s}\" in {d} ms\n", .{ info.committee.displayName(@intCast(idx)), m.network_address, m.stake, s.code, s.message, ms });
            },
        }
    }
    std.debug.print("reachable: {d}/{d} validators, stake {d}/10000\n", .{ ok, info.committee.members.len, stake });
    return if (stake >= 6667) 0 else 1;
}

// ------------------------------------------------------------------------------------------
// upstream calls: a global request rate (public fullnodes answer HTTP 429 above their limit) and
// a retry after a 429

/// 0: no pacing (the default; sui-node on the same box answers at its own speed). `--up-rps N`
/// paces every upstream call (compare against a public fullnode).
var up_interval_ns: u64 = 0;
var up_rps_set = false;
/// `--keep N`: equal pairs still to dump (read and written under `Shared.mu`).
var keep_left: u32 = 0;
var up_mu: Io.Mutex = .init;
var up_next_ns: u64 = 0;

fn upCall(arena: Allocator, up: *Upstream, path: []const u8, body: []const u8, timeout_ms: u64) !grpc.Result {
    const io = up.io;
    var tries: u32 = 0;
    while (true) : (tries += 1) {
        if (up_interval_ns > 0) {
            // take the next slot
            up_mu.lockUncancelable(io);
            const now = live.validators.monotonicNs(io);
            const slot = @max(now, up_next_ns);
            up_next_ns = slot + up_interval_ns;
            up_mu.unlock(io);
            if (slot > now) try Io.sleep(io, .fromNanoseconds(@intCast(slot - now)), .awake);
        }
        const r = try up.call(arena, path, body, timeout_ms);
        // a loopback / h2c upstream (sui-node next to us) has no 429 limiter in front of it
        if (up.isLocal()) return r;
        const limited = switch (r) {
            .status => |st| st.code == 14 and std.mem.indexOf(u8, st.message, "429") != null,
            .ok => false,
        };
        if (!limited or tries >= 20) return r;
        try Io.sleep(io, .fromMilliseconds(@intCast(500 * @as(u64, @min(tries + 1, 8)))), .awake);
    }
}

// ------------------------------------------------------------------------------------------
// the upstream fullnode as the orchestrator's local store (a deepwave-execute next to sui-node: the
// node's own executed set answers duplicates and supplies address aliases, as in sui-node)

const path_get_transaction = "/sui.rpc.v2.LedgerService/GetTransaction";
const path_get_object = "/sui.rpc.v2.LedgerService/GetObject";

/// compare: set on a lane thread around a fresh transaction (not a resubmit or stale-gas kind), so
/// deepwave answers it through its own driver instead of reading the reference's effects back from
/// the reference (the reference may already have executed it in modes 1 and 2).
threadlocal var skip_upstream_lookups = false;

const UpstreamStore = struct {
    up: *Upstream,
    /// Alias lookups per signer, kept `alias_ttl_ns` (a fresh lookup bypasses them; see
    /// `usersig.AliasLookup`).
    mu: Io.Mutex = .init,
    io: Io,
    gpa: Allocator,
    alias_cache: std.AutoHashMapUnmanaged([32]u8, CachedAliases) = .empty,
    alias_ttl_ns: u64 = 10 * std.time.ns_per_s,
    ex: ?*live.LiveExecutor = null,
    chain_id: [32]u8 = @splat(0),
    chain: protocol.Chain = .mainnet,
    /// Packages read from the reference for event `json` (immutable per id).
    pkg_mu: Io.Mutex = .init,
    pkgs: std.AutoHashMapUnmanaged([32]u8, []const u8) = .empty,

    const CachedAliases = struct { at: u64, none: bool, set: []const [32]u8 };

    fn hexId(buf: *[66]u8, id: *const [32]u8) []const u8 {
        return std.fmt.bufPrint(buf, "0x{x}", .{id}) catch unreachable;
    }

    /// GetObject `["bcs"]` at `version` (null: latest). Null when NOT_FOUND or on any error.
    fn object(self: *UpstreamStore, arena: Allocator, id: *const [32]u8, version: ?u64) ?[]const u8 {
        var buf: [256]u8 = undefined;
        var w = proto.Writer.init(&buf);
        var hex: [66]u8 = undefined;
        w.string(1, hexId(&hex, id)) catch return null;
        if (version) |v| w.uint(2, v) catch return null;
        const m = w.begin(3, 16) catch return null;
        w.string(1, "bcs") catch return null;
        w.end(m) catch return null;
        const resp = switch (upCall(arena, self.up, path_get_object, w.bytesWritten(), 15_000) catch return null) {
            .ok => |b| b,
            .status => return null,
        };
        return field(field(field(resp, 1) orelse return null, 1) orelse return null, 2);
    }

    fn localEffects(self: *UpstreamStore) live.local.LocalEffects {
        return .{ .ctx = self, .get = getLocal };
    }

    fn getLocal(ctx: *anyopaque, arena: Allocator, req: *const handler.ExecuteRequest) ?rpc_exec.driver.driver.QuorumResponse {
        const self: *UpstreamStore = @ptrCast(@alignCast(ctx));
        if (skip_upstream_lookups) return null;
        var buf: [256]u8 = undefined;
        var w = proto.Writer.init(&buf);
        var b58: [serve.b58.max_len_32]u8 = undefined;
        w.string(1, serve.b58.encode32(&b58, &req.digest)) catch return null;
        const m = w.begin(2, 64) catch return null;
        w.string(1, "effects.bcs") catch return null;
        w.string(1, "events.bcs") catch return null;
        w.end(m) catch return null;
        const resp = switch (upCall(arena, self.up, path_get_transaction, w.bytesWritten(), 15_000) catch return null) {
            .ok => |b| b,
            .status => return null,
        };
        const t = field(resp, 1) orelse return null;
        const effects = field(field(field(t, 4) orelse return null, 1) orelse return null, 2) orelse return null;
        const events: ?[]const u8 = if (field(t, 5)) |ev| field(field(ev, 1) orelse return null, 2) else null;
        const Src = struct {
            fn obj(c: *anyopaque, a: Allocator, id: *const [32]u8, version: u64) ?[]const u8 {
                const us: *UpstreamStore = @ptrCast(@alignCast(c));
                return us.object(a, id, version);
            }
        };
        return live.local.quorumFromEffects(arena, effects, events, req, .{ .ctx = self, .get = Src.obj }) catch null;
    }

    fn liveObjects(self: *UpstreamStore) live.early.LiveObjects {
        return .{ .ctx = self, .get = getLive, .at = getAt, .latest = getLatest };
    }

    fn getLatest(ctx: *anyopaque, arena: Allocator, id: *const [32]u8) ?[]const u8 {
        const self: *UpstreamStore = @ptrCast(@alignCast(ctx));
        if (skip_upstream_lookups) return null;
        return self.object(arena, id, null);
    }

    fn makeRender(ctx: *anyopaque, arena: Allocator, objects: []const []const u8) ?*const serve.render_object.Ctx {
        return live.validators.RenderSource.make(arena, objects, ctx, getPackage);
    }

    fn getPackage(ctx: *anyopaque, arena: Allocator, id: *const [32]u8) ?[]const u8 {
        const self: *UpstreamStore = @ptrCast(@alignCast(ctx));
        self.pkg_mu.lockUncancelable(self.io);
        if (self.pkgs.get(id.*)) |b| {
            self.pkg_mu.unlock(self.io);
            return b;
        }
        self.pkg_mu.unlock(self.io);
        const raw = self.object(arena, id, null) orelse return null;
        if (raw.len == 0 or raw[0] != 1) return raw; // not a package: not cached
        const owned = self.gpa.dupe(u8, raw) catch return raw;
        self.pkg_mu.lockUncancelable(self.io);
        defer self.pkg_mu.unlock(self.io);
        if (self.pkgs.get(id.*)) |b| {
            self.gpa.free(owned);
            return b;
        }
        self.pkgs.put(self.gpa, id.*, owned) catch {
            self.gpa.free(owned);
            return raw;
        };
        return owned;
    }

    fn getEnv(ctx: *const anyopaque) ?rpc_exec.EpochEnv {
        const self: *const UpstreamStore = @ptrCast(@alignCast(ctx));
        const f = (self.ex orelse return null).epochFacts() orelse return null;
        if (f.protocol_version == 0) return null;
        const cfg = protocol.get(f.protocol_version, self.chain) catch return null;
        return .{ .chain_id = self.chain_id, .epoch = f.epoch, .pv = f.protocol_version, .cfg = cfg, .rgp = f.rgp, .epoch_start_ms = 0, .committee_size = f.size };
    }

    fn getAt(ctx: *anyopaque, arena: Allocator, id: *const [32]u8, version: u64) ?[]const u8 {
        const self: *UpstreamStore = @ptrCast(@alignCast(ctx));
        if (skip_upstream_lookups) return null;
        return self.object(arena, id, version);
    }

    fn getLive(ctx: *anyopaque, arena: Allocator, id: *const [32]u8) ?live.early.Live {
        const self: *UpstreamStore = @ptrCast(@alignCast(ctx));
        if (skip_upstream_lookups) return null;
        var buf: [256]u8 = undefined;
        var w = proto.Writer.init(&buf);
        var hex: [66]u8 = undefined;
        w.string(1, hexId(&hex, id)) catch return null;
        const m = w.begin(3, 32) catch return null;
        w.string(1, "bcs") catch return null;
        w.string(1, "digest") catch return null;
        w.end(m) catch return null;
        const resp = switch (upCall(arena, self.up, path_get_object, w.bytesWritten(), 15_000) catch return null) {
            .ok => |b| b,
            .status => return null,
        };
        const o = field(resp, 1) orelse return null;
        const raw = field(field(o, 1) orelse return null, 2) orelse return null;
        const d = serve.b58.decode32(field(o, 4) orelse return null) orelse return null;
        return live.early.liveOf(raw, d, arena);
    }

    fn aliasLookup(self: *UpstreamStore) live.usersig.AliasLookup {
        return .{ .ctx = self, .get = getAliases };
    }

    fn getAliases(ctx: *anyopaque, arena: Allocator, signer: *const [32]u8, fresh: bool) live.usersig.Aliases {
        const self: *UpstreamStore = @ptrCast(@alignCast(ctx));
        if (skip_upstream_lookups) return .none; // compare: fresh transactions race the reference
        const now = live.validators.monotonicNs(self.io);
        if (!fresh) {
            self.mu.lockUncancelable(self.io);
            defer self.mu.unlock(self.io);
            if (self.alias_cache.get(signer.*)) |hit| if (now -| hit.at < self.alias_ttl_ns) {
                return if (hit.none) .none else .{ .set = arena.dupe([32]u8, hit.set) catch return .unknown };
            };
        }
        const id = live.usersig.aliasesObjectId(signer);
        var buf: [256]u8 = undefined;
        var w = proto.Writer.init(&buf);
        var hex: [66]u8 = undefined;
        w.string(1, hexId(&hex, &id)) catch return .unknown;
        const m = w.begin(3, 16) catch return .unknown;
        w.string(1, "bcs") catch return .unknown;
        w.end(m) catch return .unknown;
        const result: live.usersig.Aliases = switch (upCall(arena, self.up, path_get_object, w.bytesWritten(), 15_000) catch return .unknown) {
            .status => |st| if (st.code == 5) .none else return .unknown,
            .ok => |resp| blk: {
                const raw = field(field(field(resp, 1) orelse return .unknown, 1) orelse return .unknown, 2) orelse return .unknown;
                const obj = bcs.decode(types.Object, arena, raw) catch return .unknown;
                break :blk switch (obj.data) {
                    .Move => |mo| if (live.usersig.parseAliases(arena, mo.contents)) |al| .{ .set = al } else return .unknown,
                    else => return .unknown,
                };
            },
        };
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        const owned: []const [32]u8 = switch (result) {
            .set => |x| self.gpa.dupe([32]u8, x) catch return result,
            else => &.{},
        };
        if (self.alias_cache.fetchRemove(signer.*)) |old| self.gpa.free(old.value.set);
        self.alias_cache.put(self.gpa, signer.*, .{ .at = now, .none = result == .none, .set = owned }) catch self.gpa.free(owned);
        return result;
    }
};

/// Turns on the orchestrator's pre-submission work over the upstream: signature verification
/// with address aliases, and answers for already-executed transactions.
fn attachUpstream(gpa: Allocator, io: Io, ex: *live.LiveExecutor, up: *Upstream) !*UpstreamStore {
    const us = try gpa.create(UpstreamStore);
    us.* = .{ .up = up, .io = io, .gpa = gpa };
    ex.local = us.localEffects();
    ex.sig_env = .{ .aliases = us.aliasLookup() };
    ex.live_objects = us.liveObjects();
    ex.render = .{ .ctx = us, .make = UpstreamStore.makeRender };
    return us;
}

// ------------------------------------------------------------------------------------------
// serve

/// `recover`: the restart path of the node's pending-tx log, then wait until the log is empty.
fn recoverCmd(io: Io, ex: *live.LiveExecutor, wait_s: u64) !u8 {
    const l = ex.pending orelse {
        std.debug.print("recover needs --pending-tx-dir\n", .{});
        return 2;
    };
    const t0 = live.validators.monotonicNs(io);
    try ex.recoverPending();
    while (l.count() != 0 and live.validators.monotonicNs(io) - t0 < wait_s * std.time.ns_per_s) try Io.sleep(io, .fromMilliseconds(50), .awake);
    const c = &ex.counters;
    std.debug.print("recover: {d} left in the log after {d} ms; recovered {d}, drives {d}, local {d}, retries started {d} (success {d}, retriable {d}, non-retriable {d}), log write errors {d}\n", .{
        l.count(),                              (live.validators.monotonicNs(io) - t0) / std.time.ns_per_ms,
        c.recovered.load(.monotonic),           c.drives.load(.monotonic),
        c.local_answers.load(.monotonic),       c.retry_started.load(.monotonic),
        c.retry_success.load(.monotonic),       c.retry_retriable.load(.monotonic),
        c.retry_non_retriable.load(.monotonic), l.write_errors.load(.monotonic),
    });
    return if (l.count() == 0) 0 else 1;
}

/// Writes the embedded testnet vectors' transactions (already executed on testnet) into the log,
/// without submitting them: `u32 len ++ request` then a response and an objects blob each.
fn seedVectors(arena: Allocator, l: *live.pending_log.PendingLog) !void {
    const vectors = @embedFile("testdata/local_vectors.bin");
    const Cap = struct {
        l: *live.pending_log.PendingLog,
        n: u32 = 0,
        fn run(ctx: *anyopaque, _: Allocator, req: *const handler.ExecuteRequest) Allocator.Error!rpc_exec.driver.driver.Outcome {
            const c: *@This() = @ptrCast(@alignCast(ctx));
            if (c.l.writeMaybe(&req.digest, .{ .envelope = req.envelope, .data_bcs = req.data_bcs, .signatures = req.signatures })) c.n += 1;
            return .{ .err = .TimeoutBeforeFinality };
        }
    };
    var cap: Cap = .{ .l = l };
    var at: usize = 0;
    while (at + 4 <= vectors.len) {
        var blobs: [3][]const u8 = undefined;
        for (&blobs) |*b| {
            const n = std.mem.readInt(u32, vectors[at..][0..4], .little);
            b.* = vectors[at + 4 ..][0..n];
            at += 4 + n;
        }
        _ = try handler.executeTransaction(arena, .{ .ctx = &cap, .executeFn = Cap.run }, blobs[0]);
    }
    std.debug.print("seeded {d} testnet transactions into the pending-tx log\n", .{cap.n});
}

fn serveCmd(gpa: Allocator, io: Io, ex: *live.LiveExecutor, up: *Upstream, listen: []const u8, passthrough: bool, record_path: ?[]const u8) !u8 {
    const H = struct {
        svc: live.node_exec.ExecuteService,
        up: *Upstream,
        gpa: Allocator,
        io: Io,
        passthrough: bool,
        record: ?Io.File,
        rec_off: u64 = 0,
        rec_mu: Io.Mutex = .init,

        fn call(ctx: *anyopaque, req: *const serve.h2.Request, rs: *serve.h2.ResponseStream) serve.h2.Status {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (std.mem.eql(u8, req.path, path_execute)) {
                const t0 = live.validators.monotonicNs(self.io);
                const st = self.svc.handler_().call(&self.svc, req, rs);
                if (self.record) |f| self.recordOne(f, req.body, st, rs.msg, (live.validators.monotonicNs(self.io) - t0) / std.time.ns_per_ms);
                return st;
            }
            if (!self.passthrough) return .unimplemented;
            // unary pass-through of every other method to the upstream, bytes unchanged
            var a = std.heap.ArenaAllocator.init(self.gpa);
            defer a.deinit();
            const r = self.up.call(a.allocator(), req.path, req.body, 60_000) catch return .internal;
            switch (r) {
                .ok => |b| {
                    rs.message(b) catch return .internal;
                    return .ok;
                },
                .status => |e| {
                    rs.setMessage(a.allocator().dupe(u8, e.message) catch "");
                    if (e.details.len > 0) rs.details(a.allocator().dupe(u8, e.details) catch "");
                    return if (e.code == 0 or e.code > 16) .internal else @enumFromInt(e.code);
                },
            }
        }

        /// One JSON line per ExecuteTransaction: time, digest, gRPC status, ms (the canary's audit trail).
        fn recordOne(self: *@This(), f: Io.File, body: []const u8, st: serve.h2.Status, msg: []const u8, ms: u64) void {
            const data = field(field(field(body, 1) orelse return, 1) orelse return, 2) orelse return;
            const d = types.digest.transactionDataDigest(data);
            var b58: [serve.b58.max_len_32]u8 = undefined;
            var line: [1024]u8 = undefined;
            const now_ms = @divTrunc(Io.Clock.real.now(self.io).nanoseconds, std.time.ns_per_ms);
            const text = std.fmt.bufPrint(&line, "{{\"ms\":{d},\"digest\":\"{s}\",\"code\":{d},\"latency_ms\":{d},\"message\":\"{s}\"}}\n", .{ now_ms, serve.b58.encode32(&b58, &d), @intFromEnum(st), ms, if (msg.len > 200) msg[0..200] else msg }) catch return;
            self.rec_mu.lockUncancelable(self.io);
            defer self.rec_mu.unlock(self.io);
            f.writePositionalAll(self.io, text, self.rec_off) catch return;
            self.rec_off += text.len;
        }
    };
    var record: ?Io.File = null;
    if (record_path) |rp| record = try Io.Dir.cwd().createFile(io, rp, .{ .truncate = false });
    var h: H = .{ .svc = .{ .gpa = gpa, .ex = ex.executor() }, .up = up, .gpa = gpa, .io = io, .passthrough = passthrough, .record = record };
    if (record) |f| h.rec_off = try f.length(io); // append
    const addr = try Io.net.IpAddress.parseLiteral(listen);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    var refresher: live.node_exec.EpochRefresher = .{ .gpa = gpa, .io = io, .ex = ex, .up = up, .label = "the upstream" };
    ex.on_drive_error = refresher.hook();
    try refresher.start();
    var stop = std.atomic.Value(bool).init(false);
    std.debug.print("serving ExecuteTransaction on {s}{s}\n", .{ listen, if (passthrough) " (other unary methods pass through to the upstream)" else "" });
    try serve.h2.serveBlocking(gpa, io, &server, .{}, .{ .ctx = &h, .call = H.call }, &stop);
    return 0;
}

// ------------------------------------------------------------------------------------------
// compare (testnet)

const ObjRef = struct { id: [32]u8, version: u64, digest: [32]u8, balance: u64 = 0 };

/// `compare --fund`: split the address balance into one fresh coin per lane even when enough coins
/// exist (a long compare needs more than the 1 SUI ones).
var fund = false;

const Shared = struct {
    gpa: Allocator,
    io: Io,
    ex: *live.LiveExecutor,
    up: *Upstream,
    kp: Ed25519.KeyPair,
    sender: [32]u8,
    rgp: u64,
    next: std.atomic.Value(u64) = .init(0),
    count: u64,
    out_dir: []const u8,
    mu: Io.Mutex = .init,
    equal: u64 = 0,
    differ: u64 = 0,
    failed: u64 = 0,
    out_of_gas: u64 = 0,
    by_kind: [kind_names.len][2]u64 = @splat(.{ 0, 0 }),
    /// Good / not good by the path that produced deepwave's reply, and the driven ones by mode.
    by_path: [path_names.len][2]u64 = @splat(.{ 0, 0 }),
    driven_by_mode: [3][2]u64 = @splat(.{ 0, 0 }),
    zui_ms: std.ArrayList(u64) = .empty,
    up_ms: std.ArrayList(u64) = .empty,
    /// Fresh transactions only: deepwave first through its driver (mode 0), the reference first (mode 1).
    zui_fresh_ms: std.ArrayList(u64) = .empty,
    up_fresh_ms: std.ArrayList(u64) = .empty,
};

const kind_names = [_][]const u8{ "transfer", "split", "clock", "coin_value", "kiosk_events", "bad_signature", "resubmit", "stale_gas", "price_too_high", "budget_too_high" };
const kind_bad_sig = 5;
const kind_resubmit = 6;
const kind_stale_gas = 7;
/// Early validation texts: `validity_check` (gas price above the protocol maximum) and
/// `check_transaction_input` (gas budget above `max_tx_gas`).
const kind_price_high = 8;
const kind_budget_high = 9;

/// buildTx overrides for the early-validation kinds.
threadlocal var tx_price: ?u64 = null;
threadlocal var tx_budget: ?u64 = null;

fn compare(gpa: Allocator, io: Io, ex: *live.LiveExecutor, up: *Upstream, key_path: []const u8, count: u64, lanes: u32, out_dir: []const u8, rgp: u64) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const kp = try loadKey(io, arena, key_path);
    var sender: [32]u8 = undefined;
    {
        var h = Blake2b256.init(.{});
        h.update(&.{0});
        h.update(&kp.public_key.toBytes());
        h.final(&sender);
    }
    std.debug.print("sender 0x{x}\n", .{&sender});
    var coins = try listCoins(arena, up, &sender);
    std.debug.print("{d} SUI coins\n", .{coins.len});
    if (coins.len < lanes or fund) {
        // The testnet faucet pays into the address balance (accumulator), not coin objects: turn
        // it into 1 SUI coins with one transaction that pays gas from the address balance too.
        if (try fundCoins(arena, io, ex, up, kp, &sender, rgp, if (fund) lanes else lanes - @as(u32, @intCast(coins.len)))) {
            var tries: u32 = 0;
            while (tries < 20) : (tries += 1) {
                coins = try listCoins(arena, up, &sender);
                if (coins.len >= lanes and !fund) break;
                if (fund and coins.len >= lanes and coins[0].balance >= 2_000_000_000) break;
                try Io.sleep(io, .fromMilliseconds(500), .awake);
            }
            std.debug.print("{d} SUI coins after funding\n", .{coins.len});
        }
    }
    if (coins.len == 0) return 1;
    try Io.Dir.cwd().createDirPath(io, out_dir);
    var sh: Shared = .{ .gpa = gpa, .io = io, .ex = ex, .up = up, .kp = kp, .sender = sender, .rgp = rgp, .count = count, .out_dir = out_dir };
    const n = @min(lanes, @as(u32, @intCast(coins.len)));
    const threads = try arena.alloc(std.Thread, n);
    for (threads, 0..) |*t, l| t.* = try std.Thread.spawn(.{ .stack_size = 8 << 20 }, lane, .{ &sh, coins[l], @as(u32, @intCast(l)) });
    for (threads) |t| t.join();
    std.mem.sort(u64, sh.zui_ms.items, {}, std.sort.asc(u64));
    std.mem.sort(u64, sh.up_ms.items, {}, std.sort.asc(u64));
    const total = sh.equal + sh.differ + sh.failed;
    std.debug.print("\n{{\"suite\":\"execute-testnet\",\"items\":{d},\"equal\":{d},\"differ\":{d},\"failed\":{d},\"lanes_out_of_gas\":{d}", .{ total, sh.equal, sh.differ, sh.failed, sh.out_of_gas });
    for (kind_names, sh.by_kind) |k, c| std.debug.print(",\"{s}\":[{d},{d}]", .{ k, c[0], c[1] });
    // per path: [good, not good]; "drive" is the G10 number (replies that went through deepwave's
    // driver to the validators, never rendered from the reference's own data)
    std.debug.print(",\"paths\":{{", .{});
    for (path_names, sh.by_path, 0..) |k, c, pi| std.debug.print("{s}\"{s}\":[{d},{d}]", .{ if (pi == 0) "" else ",", k, c[0], c[1] });
    std.debug.print("}},\"driven_equal\":{d},\"driven_by_mode\":[[{d},{d}],[{d},{d}],[{d},{d}]]", .{ sh.by_path[@intFromEnum(Path.drive)][0], sh.driven_by_mode[0][0], sh.driven_by_mode[0][1], sh.driven_by_mode[1][0], sh.driven_by_mode[1][1], sh.driven_by_mode[2][0], sh.driven_by_mode[2][1] });
    const ctr = &ex.counters;
    std.debug.print(",\"zui_drives\":{d},\"zui_local_answers\":{d},\"zui_joined\":{d},\"zui_bad_signatures\":{d},\"zui_retries\":{d},\"zui_retry_deduped\":{d},\"zui_early_rejections\":{d},\"upstream_reconnects\":{d}", .{ ctr.drives.load(.monotonic), ctr.local_answers.load(.monotonic), ctr.joined.load(.monotonic), ctr.bad_signatures.load(.monotonic), ctr.retry_started.load(.monotonic), ctr.retry_deduped.load(.monotonic), ctr.early_rejections.load(.monotonic), sh.up.reconnects.load(.monotonic) });
    std.debug.print(",\"zui_first_ms_p50\":{d},\"zui_first_ms_p99\":{d},\"upstream_first_ms_p50\":{d},\"upstream_first_ms_p99\":{d}}}\n", .{ pct(sh.zui_ms.items, 50), pct(sh.zui_ms.items, 99), pct(sh.up_ms.items, 50), pct(sh.up_ms.items, 99) });
    std.debug.print("{{\"fresh_zui_n\":{d},\"fresh_zui_ms\":[{d},{d},{d},{d},{d}],\"fresh_upstream_n\":{d},\"fresh_upstream_ms\":[{d},{d},{d},{d},{d}]}}\n", .{
        sh.zui_fresh_ms.items.len,  pm(sh.zui_fresh_ms.items, 500), pm(sh.zui_fresh_ms.items, 900), pm(sh.zui_fresh_ms.items, 990), pm(sh.zui_fresh_ms.items, 999), pm(sh.zui_fresh_ms.items, 1000),
        sh.up_fresh_ms.items.len,   pm(sh.up_fresh_ms.items, 500), pm(sh.up_fresh_ms.items, 900), pm(sh.up_fresh_ms.items, 990), pm(sh.up_fresh_ms.items, 999), pm(sh.up_fresh_ms.items, 1000),
    });
    sh.zui_ms.deinit(gpa);
    sh.up_ms.deinit(gpa);
    sh.zui_fresh_ms.deinit(gpa);
    sh.up_fresh_ms.deinit(gpa);
    return if (sh.differ == 0 and sh.failed == 0) 0 else 1;
}

fn info_members(epoch_body: []const u8) usize {
    var a = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer a.deinit();
    const info = live.validators.parseEpoch(a.allocator(), epoch_body) catch return 1;
    return info.committee.members.len;
}

fn pct(xs: []u64, p: u64) u64 {
    return pm(xs, p * 10);
}

/// The `p`-per-mille value (sorts `xs`).
fn pm(xs: []u64, p: u64) u64 {
    if (xs.len == 0) return 0;
    std.mem.sort(u64, xs, {}, std.sort.asc(u64));
    return xs[@min(xs.len - 1, xs.len * p / 1000)];
}

fn lane(sh: *Shared, coin0: ObjRef, lane_id: u32) void {
    var gas = coin0;
    var fails_in_row: u32 = 0;
    var last: Last = .{};
    defer last.deinit(sh.gpa);
    while (true) {
        const idx = sh.next.fetchAdd(1, .monotonic);
        if (idx >= sh.count) return;
        var arena_state = std.heap.ArenaAllocator.init(sh.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        // 37 is coprime to 100: every run of 100 consecutive transactions holds the whole mix
        var kind: u8 = switch ((idx * 37) % 100) {
            0...44 => 0,
            45...62 => 1,
            63...76 => 2,
            77...88 => 3,
            89...90 => 4,
            91...93 => kind_bad_sig,
            94 => kind_stale_gas,
            95 => kind_price_high,
            96 => kind_budget_high,
            else => kind_resubmit,
        };
        if ((kind == kind_resubmit or kind == kind_stale_gas) and last.body.len == 0) kind = 0;
        const r = one(sh, arena, &gas, &last, idx, kind) catch |e| blk: {
            if (e == error.LaneOutOfGas) {
                std.debug.print("[lane {d}] out of gas at tx {d}: lane stops (not counted)\n", .{ lane_id, idx });
                sh.mu.lockUncancelable(sh.io);
                sh.out_of_gas += 1;
                sh.mu.unlock(sh.io);
                return;
            }
            std.debug.print("[lane {d}] tx {d}: {s}\n", .{ lane_id, idx, @errorName(e) });
            break :blk false;
        };
        sh.mu.lockUncancelable(sh.io);
        if (r) sh.by_kind[kind][0] += 1 else sh.by_kind[kind][1] += 1;
        const done_n = sh.equal + sh.differ + sh.failed;
        sh.mu.unlock(sh.io);
        if (done_n % 250 == 0 and done_n > 0) std.debug.print("{d} done: {d} equal, {d} differ, {d} failed\n", .{ done_n, sh.equal, sh.differ, sh.failed });
        fails_in_row = if (r) 0 else fails_in_row + 1;
        if (fails_in_row >= 5) {
            std.debug.print("[lane {d}] stopping after 5 failures in a row\n", .{lane_id});
            return;
        }
    }
}

/// The lane's previous successful request (the `resubmit` kind sends it again).
const Last = struct {
    body: []u8 = &.{},
    /// The gas coin as the previous transaction used it (consumed since).
    gas: ?ObjRef = null,
    fn deinit(l: *Last, gpa: Allocator) void {
        gpa.free(l.body);
        l.* = .{};
    }
    fn set(l: *Last, gpa: Allocator, b: []const u8) void {
        const c = gpa.dupe(u8, b) catch return;
        gpa.free(l.body);
        l.body = c;
    }
};

/// One transaction through both paths. Returns true when the responses are equal.
fn one(sh: *Shared, arena: Allocator, gas: *ObjRef, last: *Last, idx: u64, kind: u8) !bool {
    const body = switch (kind) {
        kind_resubmit => try arena.dupe(u8, last.body),
        kind_stale_gas => blk: {
            // Both nodes must have applied the previous transaction before a stale-gas check is
            // comparable: the reference answers from its own synced state, and a reference still
            // a checkpoint behind passes the stale version on to the validators (whose answer
            // then differs from deepwave's local early rejection only by text). Wait for the
            // reference to hold the gas coin at the lane's current version.
            try waitUpstreamVersion(sh, arena, gas.*);
            // a split paying with the version of the gas coin the previous transaction consumed
            // (a split carries idx: a plain gas transfer could be byte-identical to the previous
            // transaction, which both nodes then answer as already executed)
            const data = try buildTx(arena, sh, last.gas.?, 1, idx);
            break :blk try executeRequest(arena, data, try sign(arena, sh.kp, data));
        },
        kind_bad_sig => blk: {
            // a transfer with a broken signature: a flipped bit (InvalidSignature), or a valid
            // signature from a key that is not the sender (SignerSignatureAbsent)
            const data = try buildTx(arena, sh, gas.*, 0, idx);
            if (idx % 2 == 0) {
                const s = try arena.dupe(u8, try sign(arena, sh.kp, data));
                s[1 + (idx % 64)] ^= 0x01;
                break :blk try executeRequest(arena, data, s);
            }
            var seed: [32]u8 = @splat(0x42);
            seed[0] = @truncate(idx);
            const other = Ed25519.KeyPair.generateDeterministic(seed) catch unreachable;
            break :blk try executeRequest(arena, data, try sign(arena, other, data));
        },
        kind_price_high, kind_budget_high => blk: {
            if (kind == kind_price_high) tx_price = 1_000_000_000_000 + idx else tx_budget = 60_000_000_000 + idx;
            defer {
                tx_price = null;
                tx_budget = null;
            }
            const data = try buildTx(arena, sh, gas.*, 1, idx);
            break :blk try executeRequest(arena, data, try sign(arena, sh.kp, data));
        },
        else => blk: {
            const data = try buildTx(arena, sh, gas.*, kind, idx);
            break :blk try executeRequest(arena, data, try sign(arena, sh.kp, data));
        },
    };
    const expect_error = kind == kind_bad_sig or kind == kind_stale_gas or kind == kind_price_high or kind == kind_budget_high;
    const gas_before = gas.*;
    // fresh transactions go through deepwave's driver even when the reference already executed them
    // (modes 1 and 2); only the resubmit and stale-gas kinds use the reference as deepwave's store
    skip_upstream_lookups = kind != kind_resubmit and kind != kind_stale_gas and kind != kind_budget_high and kind != kind_price_high;
    defer skip_upstream_lookups = false;
    var zpath: Path = .none;
    const mode = idx % 3; // 0 zui first, 1 upstream first, 2 both at once
    var zui_reply: rpc_exec.Reply = undefined;
    var up_reply: grpc.Result = undefined;
    const t0 = live.validators.monotonicNs(sh.io);
    var zui_ms: u64 = 0;
    var up_ms: u64 = 0;
    switch (mode) {
        0 => {
            zui_reply = try handler.executeTransaction(arena, sh.ex.executor(), body);
            zpath = live.validators.last_path;
            zui_ms = (live.validators.monotonicNs(sh.io) - t0) / std.time.ns_per_ms;
            up_reply = try upCall(arena, sh.up, path_execute, body, 120_000);
        },
        1 => {
            up_reply = try upCall(arena, sh.up, path_execute, body, 120_000);
            up_ms = (live.validators.monotonicNs(sh.io) - t0) / std.time.ns_per_ms;
            zui_reply = try handler.executeTransaction(arena, sh.ex.executor(), body);
            zpath = live.validators.last_path;
        },
        else => {
            const T = struct {
                fn run(a: Allocator, u: *Upstream, b: []const u8, out: *anyerror!grpc.Result) void {
                    out.* = upCall(a, u, path_execute, b, 120_000);
                }
            };
            // the thread gets its own arena (arenas are not thread-safe)
            var up_arena = std.heap.ArenaAllocator.init(sh.gpa);
            defer up_arena.deinit();
            var res: anyerror!grpc.Result = error.NotRun;
            const t = try std.Thread.spawn(.{}, T.run, .{ up_arena.allocator(), sh.up, body, &res });
            zui_reply = try handler.executeTransaction(arena, sh.ex.executor(), body);
            zpath = live.validators.last_path;
            t.join();
            up_reply = try copyResult(arena, try res);
        },
    }
    if (mode == 0 or mode == 1) {
        sh.mu.lockUncancelable(sh.io);
        if (mode == 0) try sh.zui_ms.append(sh.gpa, zui_ms) else try sh.up_ms.append(sh.gpa, up_ms);
        // fresh transactions only (both sides drive them through validators): the latency figure
        if (kind < kind_bad_sig) {
            if (mode == 0 and zpath == .drive) try sh.zui_fresh_ms.append(sh.gpa, zui_ms) else if (mode == 1) try sh.up_fresh_ms.append(sh.gpa, up_ms);
        }
        sh.mu.unlock(sh.io);
    }
    // update the lane's gas coin from whichever side has effects
    const zbytes: ?[]const u8 = switch (zui_reply) {
        .ok => |b| b,
        .err => null,
    };
    const ubytes: ?[]const u8 = switch (up_reply) {
        .ok => |b| b,
        .status => null,
    };
    if (kind != kind_resubmit and kind != kind_stale_gas) if (zbytes orelse ubytes) |b| if (gasFromResponse(arena, b, gas.id)) |g| {
        gas.* = g;
    };
    // The lane's coin ran dry: not a comparison (the reference rejects it from its own state
    // before submission; deepwave's compare run has no state of its own for fresh transactions).
    if (ubytes == null and !expect_error and std.mem.indexOf(u8, up_reply.status.message, "Balance of gas object") != null) return error.LaneOutOfGas;
    const equal = blk: {
        if (zbytes != null and ubytes != null) break :blk std.mem.eql(u8, zbytes.?, ubytes.?);
        if (zbytes == null and ubytes == null) {
            const ze = zui_reply.err;
            const us = up_reply.status;
            break :blk ze.code == us.code and std.mem.eql(u8, ze.message, us.message) and std.mem.eql(u8, ze.details, us.details);
        }
        break :blk false;
    };
    sh.mu.lockUncancelable(sh.io);
    defer sh.mu.unlock(sh.io);
    if (equal and zbytes != null and kind != kind_resubmit and kind != kind_stale_gas) {
        last.set(sh.gpa, body);
        last.gas = gas_before;
    }
    const good = equal and ((zbytes == null) == expect_error);
    sh.by_path[@intFromEnum(zpath)][if (good) 0 else 1] += 1;
    if (zpath == .drive) sh.driven_by_mode[mode][if (good) 0 else 1] += 1;
    if (equal) {
        if (good) sh.equal += 1 else sh.failed += 1;
    } else sh.differ += 1;
    if (good and zbytes != null and keep_left > 0 and kind != kind_resubmit) {
        // fixtures: equal pairs (the store-backed local path test renders from these)
        keep_left -= 1;
        var name_buf: [256]u8 = undefined;
        const base = try std.fmt.bufPrint(&name_buf, "{s}/keep_{d}_{s}", .{ sh.out_dir, idx, kind_names[kind] });
        try dump(sh.io, arena, base, ".req", body);
        try dump(sh.io, arena, base, ".up", ubytes.?);
        try dumpObjects(sh, arena, base, ubytes.?);
    }
    if (!good) {
        var name_buf: [256]u8 = undefined;
        const base = try std.fmt.bufPrint(&name_buf, "{s}/{d}_{s}_m{d}", .{ sh.out_dir, idx, kind_names[kind], mode });
        try dump(sh.io, arena, base, ".req", body);
        switch (zui_reply) {
            .ok => |b| try dump(sh.io, arena, base, ".zui", b),
            .err => |e| try dump(sh.io, arena, base, ".zui.err", try std.fmt.allocPrint(arena, "{d} {s}", .{ e.code, e.message })),
        }
        switch (up_reply) {
            .ok => |b| try dump(sh.io, arena, base, ".up", b),
            .status => |s| try dump(sh.io, arena, base, ".up.err", try std.fmt.allocPrint(arena, "{d} {s}", .{ s.code, s.message })),
        }
        std.debug.print("tx {d} ({s}, mode {d}, zui path {s}): {s}\n", .{ idx, kind_names[kind], mode, @tagName(zpath), if (equal) "both answered alike, not as expected" else "DIFFER" });
    }
    return good;
}

/// Polls the reference's GetObject until `want.id` is at `want.version` or later (5 s at most).
fn waitUpstreamVersion(sh: *Shared, arena: Allocator, want: ObjRef) !void {
    var buf: [256]u8 = undefined;
    var hex: [66]u8 = undefined;
    var tries: u32 = 0;
    while (tries < 50) : (tries += 1) {
        var w = proto.Writer.init(&buf);
        try w.string(1, std.fmt.bufPrint(&hex, "0x{x}", .{&want.id}) catch unreachable);
        const m = try w.begin(3, 16);
        try w.string(1, "version");
        try w.end(m);
        switch (try upCall(arena, sh.up, path_get_object, w.bytesWritten(), 15_000)) {
            .ok => |resp| if (field(resp, 1)) |o| {
                var r = proto.Reader.init(o);
                while (try r.next()) |f| if (f.number == 3 and try proto.Reader.varintOf(f) >= want.version) return;
            },
            .status => {},
        }
        try Io.sleep(sh.io, .fromMilliseconds(100), .awake);
    }
}

fn copyResult(arena: Allocator, r: grpc.Result) !grpc.Result {
    return switch (r) {
        .ok => |b| .{ .ok = try arena.dupe(u8, b) },
        .status => |s| .{ .status = .{ .code = s.code, .message = try arena.dupe(u8, s.message), .details = try arena.dupe(u8, s.details) } },
    };
}

/// `.objs` next to a kept pair: the input and output objects its effects name, as the node's
/// store holds them (`u32 le len ++ Object BCS` each), read from the upstream at their versions.
fn dumpObjects(sh: *Shared, arena: Allocator, base: []const u8, resp: []const u8) !void {
    const lo = sh.ex.live_objects orelse return;
    const t = field(resp, 1) orelse return;
    const effects = field(field(field(t, 4) orelse return, 1) orelse return, 2) orelse return;
    var req: handler.ExecuteRequest = undefined;
    req.include_events = false;
    req.include_input_objects = true;
    req.include_output_objects = true;
    const Src = struct {
        fn obj(c: *anyopaque, a: Allocator, id: *const [32]u8, version: u64) ?[]const u8 {
            const l: *const live.early.LiveObjects = @ptrCast(@alignCast(c));
            return l.at(l.ctx, a, id, version);
        }
    };
    var lo_copy = lo;
    const q = (try live.local.quorumFromEffects(arena, effects, null, &req, .{ .ctx = &lo_copy, .get = Src.obj })) orelse return;
    var out: std.ArrayList(u8) = .empty;
    for ([_][]const []const u8{ q.input_objects orelse &.{}, q.output_objects orelse &.{} }) |set| for (set) |o| {
        var l: [4]u8 = undefined;
        std.mem.writeInt(u32, &l, @intCast(o.len), .little);
        try out.appendSlice(arena, &l);
        try out.appendSlice(arena, o);
    };
    try dump(sh.io, arena, base, ".objs", out.items);
}

fn dump(io: Io, arena: Allocator, base: []const u8, ext: []const u8, bytes: []const u8) !void {
    const p = try std.fmt.allocPrint(arena, "{s}{s}", .{ base, ext });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = p, .data = bytes });
}

fn loadKey(io: Io, arena: Allocator, path: []const u8) !Ed25519.KeyPair {
    const text = std.mem.trim(u8, try Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(4096)), " \r\n\t\"[]");
    var raw: [33]u8 = undefined;
    const n = std.base64.standard.Decoder.calcSizeForSlice(text) catch return error.BadKey;
    if (n != 33) return error.BadKey;
    std.base64.standard.Decoder.decode(&raw, text) catch return error.BadKey;
    if (raw[0] != 0) return error.NotEd25519;
    return Ed25519.KeyPair.generateDeterministic(raw[1..33].*) catch error.BadKey;
}

fn listCoins(arena: Allocator, up: *Upstream, owner: *const [32]u8) ![]ObjRef {
    var buf = try arena.alloc(u8, 1024);
    var w = proto.Writer.init(buf[0..]);
    var hex: [66]u8 = undefined;
    _ = try std.fmt.bufPrint(&hex, "0x{x}", .{owner});
    try w.string(1, &hex);
    try w.uint(2, 1000);
    const m = try w.begin(4, 128);
    for ([_][]const u8{ "object_id", "version", "digest", "balance" }) |p| try w.string(1, p);
    try w.end(m);
    try w.string(5, "0x2::coin::Coin<0x2::sui::SUI>");
    const resp = switch (try upCall(arena, up, path_list_owned, w.bytesWritten(), 15_000)) {
        .ok => |b| b,
        .status => |s| {
            std.debug.print("ListOwnedObjects failed: {d} {s}\n", .{ s.code, s.message });
            return error.Upstream;
        },
    };
    var out: std.ArrayList(ObjRef) = .empty;
    var r = proto.Reader.init(resp);
    while (try r.next()) |f| if (f.number == 1) {
        var o: ObjRef = undefined;
        var bal: u64 = 0;
        var orr = proto.Reader.init(try proto.Reader.bytesOf(f));
        while (try orr.next()) |g| switch (g.number) {
            2 => o.id = try parseHex32(try proto.Reader.stringOf(g)),
            3 => o.version = try proto.Reader.varintOf(g),
            4 => o.digest = serve.b58.decode32(try proto.Reader.stringOf(g)) orelse return error.BadDigest,
            101 => bal = try proto.Reader.varintOf(g),
            else => {},
        };
        o.balance = bal;
        if (bal >= 200_000_000) try out.append(arena, o);
    };
    // largest first: lanes take the first coins
    std.mem.sort(ObjRef, out.items, {}, struct {
        fn gt(_: void, x: ObjRef, y: ObjRef) bool {
            return x.balance > y.balance;
        }
    }.gt);
    return out.items;
}

const path_get_balance = "/sui.rpc.v2.StateService/GetBalance";
const path_service_info = "/sui.rpc.v2.LedgerService/GetServiceInfo";

/// The sender's SUI address balance (Balance.address_balance, field 4).
fn addressBalance(arena: Allocator, up: *Upstream, owner: *const [32]u8) !u64 {
    var buf: [256]u8 = undefined;
    var w = proto.Writer.init(&buf);
    var hex: [66]u8 = undefined;
    _ = try std.fmt.bufPrint(&hex, "0x{x}", .{owner});
    try w.string(1, &hex);
    try w.string(2, "0x2::sui::SUI");
    const resp = switch (try upCall(arena, up, path_get_balance, w.bytesWritten(), 15_000)) {
        .ok => |b| b,
        .status => |st| {
            std.debug.print("GetBalance failed: {d} {s}\n", .{ st.code, st.message });
            return error.Upstream;
        },
    };
    const bal = field(resp, 1) orelse return 0;
    var r = proto.Reader.init(bal);
    while (try r.next()) |f| if (f.number == 4) return proto.Reader.varintOf(f);
    return 0;
}

/// GetServiceInfo: (chain id digest, epoch).
fn serviceInfo(arena: Allocator, up: *Upstream) !struct { chain: [32]u8, epoch: u64 } {
    const resp = switch (try upCall(arena, up, path_service_info, "", 15_000)) {
        .ok => |b| b,
        .status => return error.Upstream,
    };
    var chain: ?[32]u8 = null;
    var epoch: u64 = 0;
    var r = proto.Reader.init(resp);
    while (try r.next()) |f| switch (f.number) {
        1 => chain = serve.b58.decode32(try proto.Reader.stringOf(f)),
        3 => epoch = try proto.Reader.varintOf(f),
        else => {},
    };
    return .{ .chain = chain orelse return error.Upstream, .epoch = epoch };
}

/// One transaction, gas from the address balance (empty payment, ValidDuring expiration):
/// coin::redeem_funds<SUI>(FundsWithdrawal) -> SplitCoins into `n` coins of 1 SUI -> to sender.
/// Sent through deepwave's own driver (the address-balance path is part of what G10 covers).
fn fundCoins(arena: Allocator, io: Io, ex: *live.LiveExecutor, up: *Upstream, kp: Ed25519.KeyPair, sender: *const [32]u8, rgp: u64, want: u32) !bool {
    const ab = try addressBalance(arena, up, sender);
    const budget: u64 = 100_000_000;
    // even shares of the address balance (a long compare drains 1 SUI coins), 1 SUI at least
    const share = (ab -| budget) / (@as(u64, want) + 1);
    const per: u64 = @max(1_000_000_000, share / 100_000_000 * 100_000_000);
    if (ab < budget + 2 * per) {
        std.debug.print("address balance {d} MIST: too little to fund coins\n", .{ab});
        return false;
    }
    const n: u64 = @min(@as(u64, want), (ab - budget) / per - 1);
    const si = try serviceInfo(arena, up);
    std.debug.print("funding {d} coins of {d} MIST from the address balance ({d} MIST)\n", .{ n + 1, per, ab });
    var b: Bcs = .{ .a = arena };
    const sui = try structTag(arena, 2, "sui", "SUI", &.{});
    try b.byte(0); // TransactionData::V1
    try b.byte(0); // ProgrammableTransaction
    try b.uleb(3);
    // CallArg::FundsWithdrawal { MaxAmountU64((n + 1) SUI), Balance(SUI), Sender }
    try b.byte(2);
    try b.byte(0);
    try b.u64le((n + 1) * per);
    try b.byte(0);
    try b.bytes(sui);
    try b.byte(0);
    try b.pureU64(per);
    try b.pureAddr(sender);
    try b.uleb(3);
    try b.moveCall(2, "coin", "redeem_funds", &.{sui}, &.{.{ .input = 0 }});
    try b.byte(2); // SplitCoins(Result 0, [per; n])
    try b.arg(.{ .result = 0 });
    try b.uleb(n);
    for (0..n) |_| try b.arg(.{ .input = 1 });
    try b.byte(1); // TransferObjects([nested..., Result 0], sender)
    try b.uleb(n + 1);
    for (0..n) |k| try b.arg(.{ .nested = .{ 1, @intCast(k) } });
    try b.arg(.{ .result = 0 });
    try b.arg(.{ .input = 2 });
    try b.bytes(sender);
    try b.uleb(0); // GasData: no payment objects
    try b.bytes(sender);
    try b.u64le(rgp);
    try b.u64le(budget);
    // TransactionExpiration::ValidDuring { min_epoch, max_epoch, None, None, chain, nonce }
    try b.byte(2);
    try b.byte(1);
    try b.u64le(si.epoch);
    try b.byte(1);
    try b.u64le(si.epoch + 1);
    try b.byte(0);
    try b.byte(0);
    try b.digest(&si.chain); // ChainIdentifier(CheckpointDigest): a Digest, length-prefixed
    var nonce: [4]u8 = undefined;
    io.random(&nonce);
    try b.bytes(&nonce);
    _ = bcs.decode(types.TransactionData, arena, b.list.items) catch |e| {
        std.debug.print("funding tx does not decode ({s}): {x}\n", .{ @errorName(e), b.list.items });
        return e;
    };
    const sig = try sign(arena, kp, b.list.items);
    const body = try executeRequest(arena, b.list.items, sig);
    const r = try handler.executeTransaction(arena, ex.executor(), body);
    switch (r) {
        .ok => |resp| {
            const eff_bcs = field(field(field(field(resp, 1) orelse return false, 4) orelse return false, 1) orelse return false, 2) orelse return false;
            const eff = try bcs.decode(types.TransactionEffects, arena, eff_bcs);
            const ok = switch (eff) {
                .V2 => |v| v.status == .Success,
                else => false,
            };
            std.debug.print("funding transaction through zui: {s}\n", .{if (ok) "success" else "failed in execution"});
            return ok;
        },
        .err => |e| {
            std.debug.print("funding transaction through zui: {d} {s}\n", .{ e.code, e.message });
            return false;
        },
    }
}

fn parseHex32(s: []const u8) ![32]u8 {
    const t = if (std.mem.startsWith(u8, s, "0x")) s[2..] else s;
    var padded: [64]u8 = @splat('0');
    if (t.len > 64) return error.BadHex;
    @memcpy(padded[64 - t.len ..], t);
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, &padded);
    return out;
}

// ---- transaction building (BCS by hand: TransactionData::V1, ProgrammableTransaction) ----

const Bcs = struct {
    list: std.ArrayList(u8) = .empty,
    a: Allocator,
    fn byte(b: *Bcs, x: u8) !void {
        try b.list.append(b.a, x);
    }
    fn bytes(b: *Bcs, x: []const u8) !void {
        try b.list.appendSlice(b.a, x);
    }
    fn u64le(b: *Bcs, x: u64) !void {
        var t: [8]u8 = undefined;
        std.mem.writeInt(u64, &t, x, .little);
        try b.bytes(&t);
    }
    fn u16le(b: *Bcs, x: u16) !void {
        var t: [2]u8 = undefined;
        std.mem.writeInt(u16, &t, x, .little);
        try b.bytes(&t);
    }
    fn uleb(b: *Bcs, v0: usize) !void {
        var v = v0;
        while (v >= 0x80) : (v >>= 7) try b.byte(@as(u8, @truncate(v)) | 0x80);
        try b.byte(@truncate(v));
    }
    fn str(b: *Bcs, s: []const u8) !void {
        try b.uleb(s.len);
        try b.bytes(s);
    }
    fn digest(b: *Bcs, d: *const [32]u8) !void {
        try b.uleb(32);
        try b.bytes(d);
    }
    fn objRef(b: *Bcs, r: ObjRef) !void {
        try b.bytes(&r.id);
        try b.u64le(r.version);
        try b.digest(&r.digest);
    }
    fn addr(b: *Bcs, x: u8) !void {
        var t: [32]u8 = @splat(0);
        t[31] = x;
        try b.bytes(&t);
    }
    fn pureU64(b: *Bcs, x: u64) !void {
        try b.byte(0); // CallArg::Pure
        try b.uleb(8);
        try b.u64le(x);
    }
    fn pureAddr(b: *Bcs, a: *const [32]u8) !void {
        try b.byte(0);
        try b.uleb(32);
        try b.bytes(a);
    }
    fn arg(b: *Bcs, a: Arg) !void {
        switch (a) {
            .gas => try b.byte(0),
            .input => |x| {
                try b.byte(1);
                try b.u16le(x);
            },
            .result => |x| {
                try b.byte(2);
                try b.u16le(x);
            },
            .nested => |x| {
                try b.byte(3);
                try b.u16le(x[0]);
                try b.u16le(x[1]);
            },
        }
    }
    fn moveCall(b: *Bcs, pkg: u8, module: []const u8, func: []const u8, ty: []const []const u8, args: []const Arg) !void {
        try b.byte(0); // Command::MoveCall
        try b.addr(pkg);
        try b.str(module);
        try b.str(func);
        try b.uleb(ty.len);
        for (ty) |t| try b.bytes(t);
        try b.uleb(args.len);
        for (args) |a| try b.arg(a);
    }
};

const Arg = union(enum) { gas, input: u16, result: u16, nested: [2]u16 };

/// TypeInput::Struct { address 0x<pkg>, module, name, type_args }.
fn structTag(a: Allocator, pkg: u8, module: []const u8, name: []const u8, args: []const []const u8) ![]const u8 {
    var b: Bcs = .{ .a = a };
    try b.byte(7);
    try b.addr(pkg);
    try b.str(module);
    try b.str(name);
    try b.uleb(args.len);
    for (args) |x| try b.bytes(x);
    return b.list.items;
}

fn buildTx(a: Allocator, sh: *Shared, gas: ObjRef, kind: u8, idx: u64) ![]const u8 {
    var b: Bcs = .{ .a = a };
    try b.byte(0); // TransactionData::V1
    try b.byte(0); // TransactionKind::ProgrammableTransaction
    const sui = try structTag(a, 2, "sui", "SUI", &.{});
    const coin_sui = try structTag(a, 2, "coin", "Coin", &.{sui});
    switch (kind) {
        0 => { // TransferObjects([GasCoin], sender)
            try b.uleb(1);
            try b.pureAddr(&sh.sender);
            try b.uleb(1);
            try b.byte(1);
            try b.uleb(1);
            try b.arg(.gas);
            try b.arg(.{ .input = 0 });
        },
        1 => { // SplitCoins(GasCoin, [amount]) + TransferObjects([coin], sender)
            try b.uleb(2);
            try b.pureU64(1000 + idx % 1000);
            try b.pureAddr(&sh.sender);
            try b.uleb(2);
            try b.byte(2);
            try b.arg(.gas);
            try b.uleb(1);
            try b.arg(.{ .input = 0 });
            try b.byte(1);
            try b.uleb(1);
            try b.arg(.{ .nested = .{ 0, 0 } });
            try b.arg(.{ .input = 1 });
        },
        2 => { // 0x2::clock::timestamp_ms(&Clock): a shared (consensus) input
            try b.uleb(1);
            try b.byte(1); // CallArg::Object
            try b.byte(1); // ObjectArg::SharedObject
            try b.addr(6);
            try b.u64le(1);
            try b.byte(0); // Immutable
            try b.uleb(1);
            try b.moveCall(2, "clock", "timestamp_ms", &.{}, &.{.{ .input = 0 }});
        },
        3 => { // 0x2::coin::value<SUI>(&GasCoin)
            try b.uleb(0);
            try b.uleb(1);
            try b.moveCall(2, "coin", "value", &.{sui}, &.{.gas});
        },
        else => { // kiosk::new, place_and_list a split coin (ItemListed event), share, cap to sender
            try b.uleb(3);
            try b.pureU64(1000);
            try b.pureU64(1_000_000_000 + idx);
            try b.pureAddr(&sh.sender);
            try b.uleb(5);
            try b.moveCall(2, "kiosk", "new", &.{}, &.{});
            try b.byte(2); // SplitCoins
            try b.arg(.gas);
            try b.uleb(1);
            try b.arg(.{ .input = 0 });
            try b.moveCall(2, "kiosk", "place_and_list", &.{coin_sui}, &.{ .{ .nested = .{ 0, 0 } }, .{ .nested = .{ 0, 1 } }, .{ .nested = .{ 1, 0 } }, .{ .input = 1 } });
            try b.moveCall(2, "transfer", "public_share_object", &.{try structTag(a, 2, "kiosk", "Kiosk", &.{})}, &.{.{ .nested = .{ 0, 0 } }});
            try b.byte(1);
            try b.uleb(1);
            try b.arg(.{ .nested = .{ 0, 1 } });
            try b.arg(.{ .input = 2 });
        },
    }
    try b.bytes(&sh.sender);
    // GasData
    try b.uleb(1);
    try b.objRef(gas);
    try b.bytes(&sh.sender);
    try b.u64le(tx_price orelse sh.rgp);
    try b.u64le(tx_budget orelse if (kind == 4) 50_000_000 else 10_000_000);
    try b.byte(0); // TransactionExpiration::None
    // sanity: deepwave's own decoder must take it
    _ = try bcs.decode(types.TransactionData, a, b.list.items);
    return b.list.items;
}

/// Ed25519 over blake2b256(intent [0,0,0] || TransactionData): flag 0 || sig || pubkey.
fn sign(a: Allocator, kp: Ed25519.KeyPair, data: []const u8) ![]const u8 {
    var h = Blake2b256.init(.{});
    h.update(&.{ 0, 0, 0 });
    h.update(data);
    var d: [32]u8 = undefined;
    h.final(&d);
    const s = try kp.sign(&d, null);
    const out = try a.alloc(u8, 97);
    out[0] = 0;
    @memcpy(out[1..65], &s.toBytes());
    @memcpy(out[65..97], &kp.public_key.toBytes());
    return out;
}

/// ExecuteTransactionRequest { transaction { bcs { value } }, signatures [{ bcs { value } }], read_mask }.
fn executeRequest(a: Allocator, data: []const u8, sig: []const u8) ![]const u8 {
    const buf = try a.alloc(u8, data.len + sig.len + 512);
    var w = proto.Writer.init(buf);
    const t = try w.begin(1, data.len + 16);
    const tb = try w.begin(1, data.len + 8);
    try w.bytes(2, data);
    try w.end(tb);
    try w.end(t);
    const s = try w.begin(2, sig.len + 8);
    const sb = try w.begin(1, sig.len + 4);
    try w.bytes(2, sig);
    try w.end(sb);
    try w.end(s);
    const m = try w.begin(3, 256);
    for ([_][]const u8{ "digest", "transaction", "signatures", "effects", "events", "checkpoint", "timestamp", "balance_changes", "objects" }) |p| try w.string(1, p);
    try w.end(m);
    return w.bytesWritten();
}

/// The gas coin's new reference from ExecuteTransactionResponse.transaction.effects.bcs.
fn gasFromResponse(a: Allocator, resp: []const u8, gas_id: [32]u8) ?ObjRef {
    const eff_bcs = field(field(field(field(resp, 1) orelse return null, 4) orelse return null, 1) orelse return null, 2) orelse return null;
    const eff = bcs.decode(types.TransactionEffects, a, eff_bcs) catch return null;
    const v2 = switch (eff) {
        .V2 => |v| v,
        else => return null,
    };
    for (v2.changed_objects) |e| {
        if (!std.mem.eql(u8, &e.@"0".@"0".@"0", &gas_id)) continue;
        switch (e.@"1".output_state) {
            .ObjectWrite => |w| return .{ .id = gas_id, .version = v2.lamport_version.@"0", .digest = w.@"0".@"0".@"0" },
            else => return null,
        }
    }
    return null;
}

fn field(msg: []const u8, number: u32) ?[]const u8 {
    var r = proto.Reader.init(msg);
    while (r.next() catch return null) |f| if (f.number == number) return proto.Reader.bytesOf(f) catch null;
    return null;
}

// ------------------------------------------------------------------------------------------
// sigcases (testnet): multisig, zkLogin and passkey signatures, valid and broken, sent to deepwave
// and to the reference. Every case pays a gas price above the protocol maximum, so a valid
// signature meets validity_check's text and nothing executes. `--out DIR` gets
// sig_vectors.bin (the reference's answers, replayed by usersig's unit test).

const K1 = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const R1 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const usig = live.usersig.sig;

fn intentDigest(data: []const u8) [32]u8 {
    var h = Blake2b256.init(.{});
    h.update(&.{ 0, 0, 0 });
    h.update(data);
    var d: [32]u8 = undefined;
    h.final(&d);
    return d;
}

fn sigTx(a: Allocator, sender: *const [32]u8, gas: ObjRef, idx: u64) ![]const u8 {
    var b: Bcs = .{ .a = a };
    try b.byte(0);
    try b.byte(0);
    try b.uleb(1);
    try b.pureAddr(sender);
    try b.uleb(1);
    try b.byte(1);
    try b.uleb(1);
    try b.arg(.gas);
    try b.arg(.{ .input = 0 });
    try b.bytes(sender);
    try b.uleb(1);
    try b.objRef(gas);
    try b.bytes(sender);
    try b.u64le(1_000_000_000_000 + idx);
    try b.u64le(10_000_000);
    try b.byte(0);
    _ = try bcs.decode(types.TransactionData, a, b.list.items);
    return b.list.items;
}

fn lowS(comptime n: u256, rs: *[64]u8) void {
    const s = std.mem.readInt(u256, rs[32..64], .big);
    if (s > n / 2) std.mem.writeInt(u256, rs[32..64], n - s, .big);
}

fn k1Sign(kp: K1.KeyPair, msg: []const u8) [64]u8 {
    var out = (kp.sign(msg, null) catch unreachable).toBytes();
    lowS(std.crypto.ecc.Secp256k1.scalar.field_order, &out);
    return out;
}

fn r1Sign(kp: R1.KeyPair, msg: []const u8) [64]u8 {
    var out = (kp.sign(msg, null) catch unreachable).toBytes();
    lowS(std.crypto.ecc.P256.scalar.field_order, &out);
    return out;
}

fn edSign(kp: Ed25519.KeyPair, msg: []const u8) [64]u8 {
    return (kp.sign(msg, null) catch unreachable).toBytes();
}

fn addrOf(flag: u8, pk: []const u8) [32]u8 {
    var h = Blake2b256.init(.{});
    h.update(&.{flag});
    h.update(pk);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

const MsPk = struct { flag: u8, bytes: []const u8, w: u8 = 1 };
const MsSig = struct { tag: u8, bytes: []const u8 };

fn multisigBytes(a: Allocator, sigs: []const MsSig, bitmap: u16, pks: []const MsPk, threshold: u16) ![]const u8 {
    var b: Bcs = .{ .a = a };
    try b.byte(3);
    try b.uleb(sigs.len);
    for (sigs) |s| {
        try b.uleb(s.tag);
        if (s.tag <= 2) try b.bytes(s.bytes) else try b.str(s.bytes);
    }
    try b.u16le(bitmap);
    try b.uleb(pks.len);
    for (pks) |p| {
        try b.uleb(switch (p.flag) {
            5 => 3,
            6 => 4,
            else => p.flag,
        });
        if (p.flag == 5) try b.str(p.bytes) else try b.bytes(p.bytes);
        try b.byte(p.w);
    }
    try b.u16le(threshold);
    return b.list.items;
}

fn multisigAddr(pks: []const MsPk, threshold: u16) [32]u8 {
    var h = Blake2b256.init(.{});
    h.update(&.{3});
    var t: [2]u8 = undefined;
    std.mem.writeInt(u16, &t, threshold, .little);
    h.update(&t);
    for (pks) |p| {
        h.update(&.{p.flag});
        h.update(p.bytes);
        h.update(&.{p.w});
    }
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// flag 6 || BCS RawPasskeyAuthenticator over `challenge`.
fn passkeyBytes(a: Allocator, kp: R1.KeyPair, challenge: *const [32]u8, bad_sig: bool) ![]const u8 {
    var ad: [37]u8 = @splat(0x49);
    ad[32] = 0x05;
    @memset(ad[33..], 0);
    var ch: [43]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&ch, challenge);
    const cdj = try std.fmt.allocPrint(a, "{{\"type\":\"webauthn.get\",\"challenge\":\"{s}\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false}}", .{&ch});
    var cdh: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(cdj, &cdh, .{});
    const msg = try std.mem.concat(a, u8, &.{ &ad, &cdh });
    var s = r1Sign(kp, msg);
    if (bad_sig) s = r1Sign(kp, "something else");
    var b: Bcs = .{ .a = a };
    try b.byte(6);
    try b.str(&ad);
    try b.str(cdj);
    try b.uleb(98);
    try b.byte(2);
    try b.bytes(&s);
    try b.bytes(&kp.public_key.toCompressedSec1());
    return b.list.items;
}

const zk_seed = "20794848343242150000000000000000000000000000000000000000000000000000000000000";

/// How a synthetic zkLogin authenticator looks past its ephemeral signature.
const ZkShape = struct {
    /// The JWT header's kid: one the chain does not know ("JWK not found"), or a live Google kid
    /// (the proof stage runs).
    kid: []const u8 = "zui-sigcases",
    /// Proof points: (1, 1, 1) placeholders (not on the curve: `as_arkworks` fails), or the BN254
    /// generators (on the curve, in the subgroup: the Groth16 check fails).
    generators: bool = false,
};

const g1_gen = [3][]const u8{ "1", "2", "1" };
const g2_gen = [3][2][]const u8{
    .{ "10857046999023057135944570762232829481370756359578518086990519993285655852781", "11559732032986387107991004021392285783925812861821192530917403151452391805634" },
    .{ "8495653923123431417604973247489272438418190587263600148770280649306958101930", "4082367875863433681332203403145435568316851327593401208105741076214120093531" },
    .{ "1", "0" },
};

/// flag 5 || BCS ZkLoginAuthenticator (Google iss, placeholder proof) with an Ed25519 ephemeral
/// signature over `digest`.
fn zkBytes(a: Allocator, eph: Ed25519.KeyPair, digest: *const [32]u8, max_epoch: u64, bad_sig: bool) ![]const u8 {
    return zkBytesShape(a, eph, digest, max_epoch, bad_sig, .{});
}

fn zkBytesShape(a: Allocator, eph: Ed25519.KeyPair, digest: *const [32]u8, max_epoch: u64, bad_sig: bool, shape: ZkShape) ![]const u8 {
    var b: Bcs = .{ .a = a };
    try b.byte(5);
    try b.uleb(3);
    for (0..3) |i| try b.str(if (shape.generators) g1_gen[i] else "1");
    try b.uleb(3);
    for (0..3) |i| {
        try b.uleb(2);
        try b.str(if (shape.generators) g2_gen[i][0] else "1");
        try b.str(if (shape.generators) g2_gen[i][1] else "0");
    }
    try b.uleb(3);
    for (0..3) |i| try b.str(if (shape.generators) g1_gen[i] else "1");
    const claim = "\"iss\":\"https://accounts.google.com\",";
    var iss_b64: [48]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&iss_b64, claim);
    try b.str(&iss_b64);
    try b.byte(0);
    const hdr = try std.fmt.allocPrint(a, "{{\"alg\":\"RS256\",\"kid\":\"{s}\",\"typ\":\"JWT\"}}", .{shape.kid});
    const hdr_b64 = try a.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(hdr.len));
    _ = std.base64.url_safe_no_pad.Encoder.encode(hdr_b64, hdr);
    try b.str(hdr_b64);
    try b.str(zk_seed);
    try b.u64le(max_epoch);
    const s = edSign(eph, if (bad_sig) "something else" else digest);
    try b.uleb(97);
    try b.byte(0);
    try b.bytes(&s);
    try b.bytes(&eph.public_key.toBytes());
    return b.list.items;
}

/// The zkLogin address and its multisig public identifier (iss_len || iss || padded seed).
fn zkIdentity(a: Allocator, eph: Ed25519.KeyPair) !struct { addr: [32]u8, pk: []const u8 } {
    const any: [32]u8 = @splat(0);
    const bytes = try zkBytes(a, eph, &any, 1, false);
    var p: usig.user.Parsed = undefined;
    const scratch = try a.alloc(u8, usig.user.scratchLen(bytes.len));
    if (usig.user.parse(bytes, &p, scratch) != null) return error.ZkParse;
    const iss = "https://accounts.google.com";
    const pk = try a.alloc(u8, 1 + iss.len + 32);
    pk[0] = iss.len;
    @memcpy(pk[1 .. 1 + iss.len], iss);
    @memcpy(pk[1 + iss.len ..], &p.zklogin.auth.seed);
    return .{ .addr = p.zklogin.address(false), .pk = pk };
}

const SigCase = struct { name: []const u8, body: []const u8 };

/// `live_kid`: a Google kid in the chain's JWK set (null: the proof-stage cases are left out).
fn buildSigCases(a: Allocator, kp: Ed25519.KeyPair, funded: *const [32]u8, gas: ObjRef, epoch: u64, delta: u64, base_idx: u64, live_kid: ?[]const u8) ![]SigCase {
    var out: std.ArrayList(SigCase) = .empty;
    var idx: u64 = base_idx;
    var seed: [32]u8 = @splat(0x51);
    const ed = try Ed25519.KeyPair.generateDeterministic(seed);
    seed[0] = 0x52;
    const k1 = try K1.KeyPair.generateDeterministic(seed);
    seed[0] = 0x53;
    const r1 = try R1.KeyPair.generateDeterministic(seed);
    seed[0] = 0x54;
    const pkr = try R1.KeyPair.generateDeterministic(seed);
    seed[0] = 0x55;
    const eph = try Ed25519.KeyPair.generateDeterministic(seed);
    const ed_pk = ed.public_key.toBytes();
    const k1_pk = k1.public_key.toCompressedSec1();
    const r1_pk = r1.public_key.toCompressedSec1();
    const pk_pk = pkr.public_key.toCompressedSec1();
    const zid = try zkIdentity(a, eph);
    const other: [32]u8 = @splat(0x77);

    const Add = struct {
        fn f(l: *std.ArrayList(SigCase), al: Allocator, name: []const u8, data: []const u8, sigs: []const []const u8) !void {
            const buf = try al.alloc(u8, data.len + 64 * 1024);
            var w = proto.Writer.init(buf);
            const t = try w.begin(1, data.len + 16);
            const tb = try w.begin(1, data.len + 8);
            try w.bytes(2, data);
            try w.end(tb);
            try w.end(t);
            for (sigs) |sg| {
                const s = try w.begin(2, sg.len + 8);
                const sb = try w.begin(1, sg.len + 4);
                try w.bytes(2, sg);
                try w.end(sb);
                try w.end(s);
            }
            const m = try w.begin(3, 256);
            for ([_][]const u8{ "digest", "effects" }) |p| try w.string(1, p);
            try w.end(m);
            try l.append(al, .{ .name = name, .body = w.bytesWritten() });
        }
    }.f;

    // control: the funded Ed25519 key
    {
        idx += 1;
        const d = try sigTx(a, funded, gas, idx);
        try Add(&out, a, "ed25519_valid", d, &.{try sign(a, kp, d)});
    }
    // multisig: ed25519 + secp256k1 + secp256r1 (+ passkey + zkLogin), weights 1, threshold 2
    const pks3 = [_]MsPk{ .{ .flag = 0, .bytes = &ed_pk }, .{ .flag = 1, .bytes = &k1_pk }, .{ .flag = 2, .bytes = &r1_pk } };
    const ms3 = multisigAddr(&pks3, 2);
    const MsCase = struct { name: []const u8, which: []const u8 };
    const ms_cases = [_]MsCase{
        .{ .name = "multisig_valid_ed_k1", .which = "ek" },
        .{ .name = "multisig_valid_k1_r1", .which = "kr" },
        .{ .name = "multisig_valid_all", .which = "ekr" },
        .{ .name = "multisig_insufficient_weight", .which = "e" },
        .{ .name = "multisig_bad_ed25519", .which = "Ek" },
        .{ .name = "multisig_bad_k1", .which = "eK" },
        .{ .name = "multisig_bad_r1", .which = "eR" },
        .{ .name = "multisig_k1_s_out_of_range", .which = "eS" },
        .{ .name = "multisig_r1_zero_r", .which = "eZ" },
        .{ .name = "multisig_type_mismatch", .which = "eM" },
    };
    for (ms_cases) |c| {
        idx += 1;
        const d = try sigTx(a, &ms3, gas, idx);
        const dg = intentDigest(d);
        var sigs: std.ArrayList(MsSig) = .empty;
        var bitmap: u16 = 0;
        for (c.which) |ch| switch (ch) {
            'e' => {
                try sigs.append(a, .{ .tag = 0, .bytes = try a.dupe(u8, &edSign(ed, &dg)) });
                bitmap |= 1;
            },
            'E' => {
                const s = try a.dupe(u8, &edSign(ed, &dg));
                s[5] ^= 1;
                try sigs.append(a, .{ .tag = 0, .bytes = s });
                bitmap |= 1;
            },
            'k' => {
                try sigs.append(a, .{ .tag = 1, .bytes = try a.dupe(u8, &k1Sign(k1, &dg)) });
                bitmap |= 2;
            },
            'K' => {
                try sigs.append(a, .{ .tag = 1, .bytes = try a.dupe(u8, &k1Sign(k1, "other message")) });
                bitmap |= 2;
            },
            'S' => {
                const s = try a.dupe(u8, &k1Sign(k1, &dg));
                @memset(s[32..64], 0xff);
                try sigs.append(a, .{ .tag = 1, .bytes = s });
                bitmap |= 2;
            },
            'r' => {
                try sigs.append(a, .{ .tag = 2, .bytes = try a.dupe(u8, &r1Sign(r1, &dg)) });
                bitmap |= 4;
            },
            'R' => {
                try sigs.append(a, .{ .tag = 2, .bytes = try a.dupe(u8, &r1Sign(r1, "other message")) });
                bitmap |= 4;
            },
            'Z' => {
                const s = try a.dupe(u8, &r1Sign(r1, &dg));
                @memset(s[0..32], 0);
                try sigs.append(a, .{ .tag = 2, .bytes = s });
                bitmap |= 4;
            },
            'M' => { // an Ed25519 signature in the secp256k1 key's slot
                try sigs.append(a, .{ .tag = 0, .bytes = try a.dupe(u8, &edSign(ed, &dg)) });
                bitmap |= 2;
            },
            else => unreachable,
        };
        try Add(&out, a, c.name, d, &.{try multisigBytes(a, sigs.items, bitmap, &pks3, 2)});
    }
    // multisig signed by the right keys for another sender
    {
        idx += 1;
        const d = try sigTx(a, &other, gas, idx);
        const dg = intentDigest(d);
        const sigs = [_]MsSig{ .{ .tag = 0, .bytes = try a.dupe(u8, &edSign(ed, &dg)) }, .{ .tag = 1, .bytes = try a.dupe(u8, &k1Sign(k1, &dg)) } };
        try Add(&out, a, "multisig_wrong_sender", d, &.{try multisigBytes(a, &sigs, 3, &pks3, 2)});
    }
    // multisig with a passkey and a zkLogin member: ed25519 + passkey + zkLogin, threshold 2
    const pks_px = [_]MsPk{ .{ .flag = 0, .bytes = &ed_pk }, .{ .flag = 6, .bytes = &pk_pk }, .{ .flag = 5, .bytes = zid.pk } };
    const ms_px = multisigAddr(&pks_px, 2);
    const PxCase = struct { name: []const u8, which: []const u8 };
    const px_cases = [_]PxCase{
        .{ .name = "multisig_passkey_valid", .which = "ep" },
        .{ .name = "multisig_passkey_bad_challenge", .which = "eC" },
        .{ .name = "multisig_passkey_bad_sig", .which = "eP" },
        .{ .name = "multisig_zklogin_expired", .which = "eX" },
        .{ .name = "multisig_zklogin_epoch_too_large", .which = "eL" },
        .{ .name = "multisig_zklogin_bad_ephemeral", .which = "eB" },
        .{ .name = "multisig_zklogin_proof", .which = "ez" },
    };
    for (px_cases) |c| {
        idx += 1;
        const d = try sigTx(a, &ms_px, gas, idx);
        const dg = intentDigest(d);
        var sigs: std.ArrayList(MsSig) = .empty;
        var bitmap: u16 = 0;
        for (c.which) |ch| switch (ch) {
            'e' => {
                try sigs.append(a, .{ .tag = 0, .bytes = try a.dupe(u8, &edSign(ed, &dg)) });
                bitmap |= 1;
            },
            'p', 'C', 'P' => {
                var chal = dg;
                if (ch == 'C') chal[0] ^= 1;
                try sigs.append(a, .{ .tag = 4, .bytes = try passkeyBytes(a, pkr, &chal, ch == 'P') });
                bitmap |= 2;
            },
            'X', 'L', 'B', 'z' => {
                const me: u64 = switch (ch) {
                    'X' => epoch - 1,
                    'L' => epoch + delta + 1,
                    else => epoch + 1,
                };
                try sigs.append(a, .{ .tag = 3, .bytes = try zkBytes(a, eph, &dg, me, ch == 'B') });
                bitmap |= 4;
            },
            else => unreachable,
        };
        try Add(&out, a, c.name, d, &.{try multisigBytes(a, sigs.items, bitmap, &pks_px, 2)});
    }
    // a zkLogin public identifier that does not validate (iss length past the end)
    {
        const bad_zk = [_]u8{ 40, 'x', 'y' };
        const pks = [_]MsPk{ .{ .flag = 0, .bytes = &ed_pk }, .{ .flag = 5, .bytes = &bad_zk } };
        const addr = multisigAddr(&pks, 1);
        idx += 1;
        const d = try sigTx(a, &addr, gas, idx);
        const dg = intentDigest(d);
        const sigs = [_]MsSig{.{ .tag = 0, .bytes = try a.dupe(u8, &edSign(ed, &dg)) }};
        try Add(&out, a, "multisig_bad_zklogin_pk", d, &.{try multisigBytes(a, &sigs, 1, &pks, 1)});
    }
    // passkey
    const pk_addr = addrOf(6, &pk_pk);
    for ([_][]const u8{ "passkey_valid", "passkey_bad_challenge", "passkey_bad_sig", "passkey_wrong_sender" }, 0..) |name, k| {
        idx += 1;
        const d = try sigTx(a, if (k == 3) &other else &pk_addr, gas, idx);
        var chal = intentDigest(d);
        if (k == 1) chal[3] ^= 1;
        try Add(&out, a, name, d, &.{try passkeyBytes(a, pkr, &chal, k == 2)});
    }
    // zkLogin
    for ([_][]const u8{ "zklogin_expired", "zklogin_epoch_too_large", "zklogin_bad_ephemeral", "zklogin_wrong_sender", "zklogin_proof" }, 0..) |name, k| {
        idx += 1;
        const d = try sigTx(a, if (k == 3) &other else &zid.addr, gas, idx);
        const dg = intentDigest(d);
        const me: u64 = switch (k) {
            0 => epoch - 1,
            1 => epoch + delta + 1,
            else => epoch + 1,
        };
        try Add(&out, a, name, d, &.{try zkBytes(a, eph, &dg, me, k == 2)});
    }
    // zkLogin past the JWK lookup (a live Google kid): `as_arkworks` on placeholder points, then
    // Groth16 on the generators; top level and as a multisig member
    if (live_kid) |kid| {
        const shapes = [_]struct { name: []const u8, shape: ZkShape }{
            .{ .name = "zklogin_known_jwk_bad_points", .shape = .{ .kid = kid } },
            .{ .name = "zklogin_known_jwk_groth16", .shape = .{ .kid = kid, .generators = true } },
        };
        for (shapes) |c| {
            idx += 1;
            const d = try sigTx(a, &zid.addr, gas, idx);
            const dg = intentDigest(d);
            try Add(&out, a, c.name, d, &.{try zkBytesShape(a, eph, &dg, epoch + 1, false, c.shape)});
        }
        for (shapes) |c| {
            idx += 1;
            const d = try sigTx(a, &ms_px, gas, idx);
            const dg = intentDigest(d);
            const sigs = [_]MsSig{
                .{ .tag = 0, .bytes = try a.dupe(u8, &edSign(ed, &dg)) },
                .{ .tag = 3, .bytes = try zkBytesShape(a, eph, &dg, epoch + 1, false, c.shape) },
            };
            try Add(&out, a, try std.fmt.allocPrint(a, "multisig_{s}", .{c.name}), d, &.{try multisigBytes(a, &sigs, 1 | 4, &pks_px, 2)});
        }
    }
    // secp256k1 / secp256r1 singles (the existing path, as a control)
    {
        idx += 1;
        const addr = addrOf(1, &k1_pk);
        const d = try sigTx(a, &addr, gas, idx);
        const dg = intentDigest(d);
        var s: [98]u8 = undefined;
        s[0] = 1;
        @memcpy(s[1..65], &k1Sign(k1, "other message"));
        @memcpy(s[65..], &k1_pk);
        try Add(&out, a, "k1_bad_sig", d, &.{try a.dupe(u8, &s)});
        _ = dg;
    }
    return out.items;
}

fn sigCasesCmd(gpa: Allocator, io: Io, ex: *live.LiveExecutor, up: *Upstream, key_path: []const u8, out_dir: []const u8, epoch: u64, pv: u64) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const kp = try loadKey(io, a, key_path);
    var funded: [32]u8 = undefined;
    {
        var h = Blake2b256.init(.{});
        h.update(&.{0});
        h.update(&kp.public_key.toBytes());
        h.final(&funded);
    }
    const coins = try listCoins(a, up, &funded);
    if (coins.len == 0) {
        std.debug.print("no SUI coin for 0x{x}\n", .{&funded});
        return 1;
    }
    const cfg = protocol.get(pv, .testnet) catch return 1;
    const delta = cfg.feature_flags.zklogin_max_epoch_upper_bound_delta orelse 30;
    const now_s: u64 = @intCast(@divTrunc(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
    // a Google kid the chain knows (the proof-stage cases need one)
    const live_kid: ?[]const u8 = blk: {
        const lo = ex.live_objects orelse break :blk null;
        const latest = lo.latest orelse break :blk null;
        const Rd = struct {
            lo_ctx: *anyopaque,
            latest: *const fn (ctx: *anyopaque, arena: Allocator, id: *const [32]u8) ?[]const u8,
            arena: Allocator,
            fn live(ctx: *anyopaque, id: *const [32]u8) ?[]const u8 {
                const r: *@This() = @ptrCast(@alignCast(ctx));
                return r.latest(r.lo_ctx, r.arena, id);
            }
        };
        var rd: Rd = .{ .lo_ctx = lo.ctx, .latest = latest, .arena = a };
        const venv: serve.verifysig.Env = .{ .ctx = &rd, .liveObject = Rd.live };
        const set = serve.verifysig.chainJwks(a, &venv) catch break :blk null;
        for (set) |j| if (std.mem.eql(u8, j.iss, "https://accounts.google.com")) break :blk j.kid;
        break :blk null;
    };
    if (live_kid) |k| std.debug.print("live Google kid: {s}\n", .{k}) else std.debug.print("no live Google kid: proof-stage cases skipped\n", .{});
    const cases = try buildSigCases(a, kp, &funded, coins[0], epoch, delta, (now_s % 1_000_000) * 1000, live_kid);
    var vec: std.ArrayList(u8) = .empty;
    const putU = struct {
        fn f(l: *std.ArrayList(u8), al: Allocator, x: u64) !void {
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, x, .little);
            try l.appendSlice(al, &b);
        }
    }.f;
    const putB = struct {
        fn f(l: *std.ArrayList(u8), al: Allocator, x: []const u8) !void {
            var b: [4]u8 = undefined;
            std.mem.writeInt(u32, &b, @intCast(x.len), .little);
            try l.appendSlice(al, &b);
            try l.appendSlice(al, x);
        }
    }.f;
    try vec.appendSlice(a, "ZSV1");
    try putU(&vec, a, epoch);
    try putU(&vec, a, pv);
    try putU(&vec, a, cases.len);
    var equal: u32 = 0;
    var local: u32 = 0;
    var to_validators: u32 = 0;
    for (cases) |c| {
        const zr = try handler.executeTransaction(a, ex.executor(), c.body);
        const zpath = live.validators.last_path;
        const ur = try upCall(a, up, path_execute, c.body, 60_000);
        const eq = switch (zr) {
            .ok => |zb| switch (ur) {
                .ok => |ub| std.mem.eql(u8, zb, ub),
                .status => false,
            },
            .err => |ze| switch (ur) {
                .ok => false,
                .status => |us| ze.code == us.code and std.mem.eql(u8, ze.message, us.message) and std.mem.eql(u8, ze.details, us.details),
            },
        };
        if (eq) equal += 1;
        if (zpath == .signature) local += 1;
        if (zpath == .drive) to_validators += 1;
        std.debug.print("{s:<34} {s:<6} zui path {s}\n", .{ c.name, if (eq) "equal" else "DIFFER", @tagName(zpath) });
        const ztext = switch (zr) {
            .ok => "(effects)",
            .err => |e| e.message,
        };
        const utext = switch (ur) {
            .ok => "(effects)",
            .status => |s| s.message,
        };
        std.debug.print("    reference: {s}\n", .{utext});
        if (!eq) std.debug.print("    zui:       {s}\n", .{ztext});
        try putB(&vec, a, c.name);
        try putB(&vec, a, c.body);
        switch (ur) {
            .ok => |b| {
                try putU(&vec, a, 0);
                try putB(&vec, a, "");
                try putB(&vec, a, b);
            },
            .status => |s| {
                try putU(&vec, a, s.code);
                try putB(&vec, a, s.message);
                try putB(&vec, a, s.details);
            },
        }
    }
    // trailer: the live Google kid of the proof-stage cases (usersig's replay test puts it in its
    // JWK set)
    try putB(&vec, a, live_kid orelse "");
    try Io.Dir.cwd().createDirPath(io, out_dir);
    var name_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&name_buf, "{s}/sig_vectors.bin", .{out_dir});
    try dump(io, a, path, "", vec.items);
    std.debug.print("\n{{\"suite\":\"execute-sigcases\",\"epoch\":{d},\"protocol_version\":{d},\"items\":{d},\"equal\":{d},\"zui_local_signature\":{d},\"zui_to_validators\":{d}}}\n", .{ epoch, pv, cases.len, equal, local, to_validators });
    return if (equal == cases.len) 0 else 1;
}

// ------------------------------------------------------------------------------------------
// canary (DROP-IN 5.7): the same tiny transactions through deepwave and through sui-node, both
// as clients see them (their ExecuteTransaction endpoints), responses compared byte for byte.
//
//   deepwave-execute canary --zui HOST:PORT[/plain] --reference HOST:PORT[/plain] --key FILE
//                      [--spend] [--count N] [--budget MIST] [--out DIR] [--wait-cp-s N]
//
// Without --spend only checks that cost nothing run (both nodes refuse them before any
// validator sees them): a broken signature, a wrong signer, a gas price above the protocol
// maximum, a budget above max_tx_gas. With --spend, per round: a self-transfer of the gas coin
// sent to deepwave first then the same signed bytes to the reference, a second one the other way
// round, the second resent with the default read mask (both answer from their executed set),
// then a stale-gas check (the coin's previous version), and for both spent transactions the
// read-your-writes wait (`execute_transaction_and_wait_for_checkpoint`'s GetTransaction poll
// until `checkpoint` is set) on both nodes, the final GetTransaction answers compared too.
// Each spent transaction costs one self-transfer's gas (about 0.001 SUI at the reference price).
// The key file is read once and never printed; only the address is.

const CanaryOpts = struct {
    zui: []const u8,
    reference: []const u8,
    key_path: []const u8,
    spend: bool,
    count: u64,
    budget: u64,
    out_dir: []const u8,
    wait_cp_s: u64,
};

const Canary = struct {
    gpa: Allocator,
    io: Io,
    arena: Allocator,
    zui: *Upstream,
    reference: *Upstream,
    sh: Shared,
    out_dir: []const u8,
    equal: u32 = 0,
    differ: u32 = 0,
    unexpected: u32 = 0,
    zui_cp_ms: std.ArrayList(u64) = .empty,
    ref_cp_ms: std.ArrayList(u64) = .empty,

    const Side = struct { r: grpc.Result, ms: u64, done_ns: u64 };

    fn call(c: *Canary, up: *Upstream, path: []const u8, body: []const u8) !Side {
        const t0 = live.validators.monotonicNs(c.io);
        const r = try copyResult(c.arena, try upCall(c.arena, up, path, body, 120_000));
        const t1 = live.validators.monotonicNs(c.io);
        return .{ .r = r, .ms = (t1 - t0) / std.time.ns_per_ms, .done_ns = t1 };
    }

    fn same(a: grpc.Result, b: grpc.Result) bool {
        return switch (a) {
            .ok => |x| switch (b) {
                .ok => |y| std.mem.eql(u8, x, y),
                .status => false,
            },
            .status => |x| switch (b) {
                .ok => false,
                .status => |y| x.code == y.code and std.mem.eql(u8, x.message, y.message) and std.mem.eql(u8, x.details, y.details),
            },
        };
    }

    fn text(r: grpc.Result) []const u8 {
        return switch (r) {
            .ok => "(response)",
            .status => |s| s.message,
        };
    }

    /// Records one comparison; `want_ok`: the case should execute (else: be refused).
    fn record(c: *Canary, name: []const u8, body: []const u8, z: Side, u: Side, want_ok: bool) !bool {
        const eq = same(z.r, u.r);
        const as_expected = (z.r == .ok) == want_ok;
        if (eq and as_expected) c.equal += 1 else if (eq) c.unexpected += 1 else c.differ += 1;
        std.debug.print("{s:<34} {s:<10} zui {d:>6} ms  reference {d:>6} ms\n", .{ name, if (!eq) "DIFFER" else if (!as_expected) "UNEXPECTED" else "equal", z.ms, u.ms });
        if (z.r == .status or u.r == .status) std.debug.print("    reference: {s}\n", .{text(u.r)});
        if (!eq) std.debug.print("    zui:       {s}\n", .{text(z.r)});
        if (!eq or !as_expected) {
            try Io.Dir.cwd().createDirPath(c.io, c.out_dir);
            const base = try std.fmt.allocPrint(c.arena, "{s}/canary_{s}", .{ c.out_dir, name });
            try dump(c.io, c.arena, base, ".req", body);
            try c.dumpSide(base, ".zui", z.r);
            try c.dumpSide(base, ".ref", u.r);
        }
        return eq and as_expected;
    }

    fn dumpSide(c: *Canary, base: []const u8, ext: []const u8, r: grpc.Result) !void {
        switch (r) {
            .ok => |b| try dump(c.io, c.arena, base, ext, b),
            .status => |st| try dump(c.io, c.arena, base, try std.fmt.allocPrint(c.arena, "{s}.err", .{ext}), try std.fmt.allocPrint(c.arena, "{d} {s}", .{ st.code, st.message })),
        }
    }

    /// `body` to both endpoints in the given order (`zui_first`), compared.
    fn both(c: *Canary, name: []const u8, body: []const u8, zui_first: bool, want_ok: bool) !struct { z: Side, u: Side } {
        var z: Side = undefined;
        var u: Side = undefined;
        if (zui_first) {
            z = try c.call(c.zui, path_execute, body);
            u = try c.call(c.reference, path_execute, body);
        } else {
            u = try c.call(c.reference, path_execute, body);
            z = try c.call(c.zui, path_execute, body);
        }
        _ = try c.record(name, body, z, u, want_ok);
        return .{ .z = z, .u = u };
    }

    fn signed(c: *Canary, data: []const u8) ![]const u8 {
        return executeRequest(c.arena, data, try sign(c.arena, c.sh.kp, data));
    }

    /// GetTransaction(digest) with the canary's read mask, polled every 100 ms until the answer
    /// carries `checkpoint` (sui-rpc `wait_for_transaction` / `execute_transaction_and_wait_for_checkpoint`).
    fn waitCheckpoint(c: *Canary, up: *Upstream, digest: []const u8, since_ns: u64, limit_s: u64) !?struct { r: grpc.Result, ms: u64 } {
        var buf: [512]u8 = undefined;
        var w = proto.Writer.init(&buf);
        try w.string(1, digest);
        const m = try w.begin(2, 256);
        for ([_][]const u8{ "digest", "transaction", "signatures", "effects", "events", "checkpoint", "timestamp", "balance_changes", "objects" }) |p| try w.string(1, p);
        try w.end(m);
        const req = try c.arena.dupe(u8, w.bytesWritten());
        const deadline = since_ns + limit_s * std.time.ns_per_s;
        while (live.validators.monotonicNs(c.io) < deadline) {
            const r = try copyResult(c.arena, try upCall(c.arena, up, path_get_transaction, req, 15_000));
            switch (r) {
                .ok => |b| if (field(b, 1)) |tx| if (hasField(tx, 6)) {
                    return .{ .r = r, .ms = (live.validators.monotonicNs(c.io) -| since_ns) / std.time.ns_per_ms };
                },
                .status => {},
            }
            try Io.sleep(c.io, .fromMilliseconds(100), .awake);
        }
        return null;
    }

    fn checkpointed(c: *Canary, name: []const u8, data: []const u8, z_done: u64, u_done: u64, limit_s: u64) !void {
        var dbuf: [serve.b58.max_len_32]u8 = undefined;
        const dg = types.digest.transactionDataDigest(data);
        const digest = try c.arena.dupe(u8, serve.b58.encode32(&dbuf, &dg));
        const z = try c.waitCheckpoint(c.zui, digest, z_done, limit_s);
        const u = try c.waitCheckpoint(c.reference, digest, u_done, limit_s);
        const label = try std.fmt.allocPrint(c.arena, "{s}_checkpoint", .{name});
        if (z == null or u == null) {
            c.differ += 1;
            std.debug.print("{s:<34} TIMEOUT    zui {s}  reference {s} (no checkpoint within {d} s)\n", .{ label, if (z == null) "no" else "yes", if (u == null) "no" else "yes", limit_s });
            return;
        }
        try c.zui_cp_ms.append(c.gpa, z.?.ms);
        try c.ref_cp_ms.append(c.gpa, u.?.ms);
        _ = try c.record(label, data, .{ .r = z.?.r, .ms = z.?.ms, .done_ns = 0 }, .{ .r = u.?.r, .ms = u.?.ms, .done_ns = 0 }, true);
    }

    /// Polls GetObject on `up` until `id` is at `version` or later (10 s at most).
    fn waitVersion(c: *Canary, up: *Upstream, id: *const [32]u8, version: u64) !void {
        var buf: [256]u8 = undefined;
        var hex: [66]u8 = undefined;
        var tries: u32 = 0;
        while (tries < 100) : (tries += 1) {
            var w = proto.Writer.init(&buf);
            try w.string(1, std.fmt.bufPrint(&hex, "0x{x}", .{id}) catch unreachable);
            const m = try w.begin(3, 16);
            try w.string(1, "version");
            try w.end(m);
            switch (try upCall(c.arena, up, path_get_object, w.bytesWritten(), 15_000)) {
                .ok => |resp| if (field(resp, 1)) |o| {
                    var r = proto.Reader.init(o);
                    while (try r.next()) |f| if (f.number == 3 and try proto.Reader.varintOf(f) >= version) return;
                },
                .status => {},
            }
            try Io.sleep(c.io, .fromMilliseconds(100), .awake);
        }
    }
};

fn hasField(msg: []const u8, number: u32) bool {
    var r = proto.Reader.init(msg);
    while (r.next() catch return false) |f| if (f.number == number) return true;
    return false;
}

/// ExecuteTransactionRequest without a read_mask (the server default, `effects`).
fn executeRequestDefaultMask(a: Allocator, data: []const u8, sig: []const u8) ![]const u8 {
    const buf = try a.alloc(u8, data.len + sig.len + 64);
    var w = proto.Writer.init(buf);
    const t = try w.begin(1, data.len + 16);
    const tb = try w.begin(1, data.len + 8);
    try w.bytes(2, data);
    try w.end(tb);
    try w.end(t);
    const s = try w.begin(2, sig.len + 8);
    const sb = try w.begin(1, sig.len + 4);
    try w.bytes(2, sig);
    try w.end(sb);
    try w.end(s);
    return w.bytesWritten();
}

fn canaryCmd(gpa: Allocator, io: Io, o: CanaryOpts) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const zep = parseUpstream(o.zui) orelse {
        std.debug.print("--zui HOST:PORT[/plain] required\n", .{});
        return 2;
    };
    const rep = parseUpstream(o.reference) orelse {
        std.debug.print("--reference HOST:PORT[/plain] required\n", .{});
        return 2;
    };
    if (o.key_path.len == 0) {
        std.debug.print("--key FILE required (a Sui keystore entry; never printed)\n", .{});
        return 2;
    }
    const kp = loadKey(io, a, o.key_path) catch |e| {
        // the error name only: never the file's contents
        std.debug.print("cannot load the key file: {s}\n", .{@errorName(e)});
        return 2;
    };
    var sender: [32]u8 = undefined;
    {
        var h = Blake2b256.init(.{});
        h.update(&.{0});
        h.update(&kp.public_key.toBytes());
        h.final(&sender);
    }
    const zui = try Upstream.init(gpa, io, zep);
    defer zui.deinit();
    const reference = try Upstream.init(gpa, io, rep);
    defer reference.deinit();

    // both nodes on the same chain
    const zi = serviceInfo(a, zui) catch {
        std.debug.print("GetServiceInfo from zui ({s}) failed\n", .{o.zui});
        return 1;
    };
    const ri = serviceInfo(a, reference) catch {
        std.debug.print("GetServiceInfo from the reference ({s}) failed\n", .{o.reference});
        return 1;
    };
    if (!std.mem.eql(u8, &zi.chain, &ri.chain)) {
        std.debug.print("zui and the reference serve different chains\n", .{});
        return 1;
    }
    const mainnet_id = serve.b58.decode32("4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S").?;
    const chain_name = if (std.mem.eql(u8, &ri.chain, &mainnet_id)) "mainnet" else "not mainnet";
    const info = try live.validators.parseEpoch(a, try getEpoch(a, reference));
    std.debug.print("chain {s}, epoch {d} (zui {d}), rgp {d}, sender 0x{x}\n", .{ chain_name, ri.epoch, zi.epoch, info.reference_gas_price, &sender });
    const coins = try listCoins(a, reference, &sender);
    if (coins.len == 0) {
        std.debug.print("no SUI coin of at least 0.2 SUI for 0x{x}\n", .{&sender});
        return 1;
    }
    var gas = coins[0];
    std.debug.print("gas coin 0x{x} version {d}, balance {d} MIST\n", .{ &gas.id, gas.version, gas.balance });

    var c: Canary = .{
        .gpa = gpa,
        .io = io,
        .arena = a,
        .zui = zui,
        .reference = reference,
        .out_dir = o.out_dir,
        .sh = .{ .gpa = gpa, .io = io, .ex = undefined, .up = reference, .kp = kp, .sender = sender, .rgp = info.reference_gas_price, .count = 0, .out_dir = o.out_dir },
    };
    defer c.zui_cp_ms.deinit(gpa);
    defer c.ref_cp_ms.deinit(gpa);
    const sh = &c.sh;
    var idx: u64 = @intCast(@mod(@divTrunc(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_ms), 1_000_000) * 1000);

    // free checks: refused by both before any validator sees them
    {
        idx += 1;
        const data = try buildTx(a, sh, gas, 1, idx);
        const s = try a.dupe(u8, try sign(a, kp, data));
        s[7] ^= 0x01;
        _ = try c.both("bad_signature", try executeRequest(a, data, s), true, false);
    }
    {
        idx += 1;
        const data = try buildTx(a, sh, gas, 1, idx);
        var seed: [32]u8 = @splat(0x42);
        seed[0] = @truncate(idx);
        const other = Ed25519.KeyPair.generateDeterministic(seed) catch unreachable;
        _ = try c.both("wrong_signer", try executeRequest(a, data, try sign(a, other, data)), true, false);
    }
    {
        idx += 1;
        tx_price = 1_000_000_000_000 + idx;
        defer tx_price = null;
        const data = try buildTx(a, sh, gas, 1, idx);
        _ = try c.both("price_too_high", try c.signed(data), true, false);
    }
    {
        idx += 1;
        tx_budget = 60_000_000_000 + idx;
        defer tx_budget = null;
        const data = try buildTx(a, sh, gas, 1, idx);
        _ = try c.both("budget_too_high", try c.signed(data), true, false);
    }

    if (!o.spend) {
        std.debug.print("(no --spend: the gas-spending self-transfers were skipped)\n", .{});
    } else {
        var round: u64 = 0;
        while (round < o.count) : (round += 1) {
            tx_budget = o.budget;
            defer tx_budget = null;
            // 1. deepwave first, then the same bytes to the reference
            idx += 1;
            const data_a = try buildTx(a, sh, gas, 0, idx);
            const name_a = try std.fmt.allocPrint(a, "r{d}_transfer_zui_first", .{round});
            const ra = try c.both(name_a, try c.signed(data_a), true, true);
            const ga = (switch (ra.z.r) {
                .ok => |b| gasFromResponse(a, b, gas.id),
                .status => null,
            }) orelse (switch (ra.u.r) {
                .ok => |b| gasFromResponse(a, b, gas.id),
                .status => null,
            }) orelse {
                std.debug.print("no effects for the first transfer: stopping\n", .{});
                break;
            };
            gas = ga;
            // 2. the reference first (both must hold the coin's new version: early validation
            // reads each node's own state)
            try c.waitVersion(zui, &gas.id, gas.version);
            try c.waitVersion(reference, &gas.id, gas.version);
            idx += 1;
            const before_b = gas;
            const data_b = try buildTx(a, sh, gas, 0, idx);
            const name_b = try std.fmt.allocPrint(a, "r{d}_transfer_reference_first", .{round});
            const sig_b = try sign(a, kp, data_b);
            const rb = try c.both(name_b, try executeRequest(a, data_b, sig_b), false, true);
            const gb = (switch (rb.u.r) {
                .ok => |b| gasFromResponse(a, b, gas.id),
                .status => null,
            }) orelse (switch (rb.z.r) {
                .ok => |b| gasFromResponse(a, b, gas.id),
                .status => null,
            }) orelse {
                std.debug.print("no effects for the second transfer: stopping\n", .{});
                break;
            };
            gas = gb;
            // 3. the same transaction again with the default read mask (both: executed set)
            _ = try c.both(try std.fmt.allocPrint(a, "r{d}_resubmit_default_mask", .{round}), try executeRequestDefaultMask(a, data_b, sig_b), true, true);
            // 4. stale gas: the version the second transfer consumed
            try c.waitVersion(zui, &gas.id, gas.version);
            try c.waitVersion(reference, &gas.id, gas.version);
            idx += 1;
            {
                const data = try buildTx(a, sh, before_b, 1, idx);
                _ = try c.both(try std.fmt.allocPrint(a, "r{d}_stale_gas", .{round}), try c.signed(data), true, false);
            }
            // 5. read your writes: both transactions reach a checkpoint on both nodes
            try c.checkpointed(name_a, data_a, ra.z.done_ns, ra.u.done_ns, o.wait_cp_s);
            try c.checkpointed(name_b, data_b, rb.z.done_ns, rb.u.done_ns, o.wait_cp_s);
        }
    }
    const zc = c.zui_cp_ms.items;
    const rc = c.ref_cp_ms.items;
    std.mem.sort(u64, zc, {}, std.sort.asc(u64));
    std.mem.sort(u64, rc, {}, std.sort.asc(u64));
    std.debug.print("\n{{\"suite\":\"execute-canary\",\"chain\":\"{s}\",\"spend\":{},\"equal\":{d},\"differ\":{d},\"unexpected\":{d},\"zui_checkpoint_ms_max\":{d},\"reference_checkpoint_ms_max\":{d}}}\n", .{ chain_name, o.spend, c.equal, c.differ, c.unexpected, if (zc.len > 0) zc[zc.len - 1] else 0, if (rc.len > 0) rc[rc.len - 1] else 0 });
    return if (c.differ == 0 and c.unexpected == 0) 0 else 1;
}
