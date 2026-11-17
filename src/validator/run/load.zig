//! `deepwave-validator load`: a transaction load generator for a local committee started from Mysten
//! `sui genesis` output. Local test material only: it signs with the throwaway account keys of
//! that genesis (`sui.keystore`), never with a validator key, and refuses non-loopback addresses
//! unless `--allow-remote` is given.
//!
//! Every gas coin owned by a keystore account is one lane. A lane builds a TransactionData V1 PTB
//! (SplitCoins(GasCoin, [amount]) then TransferObjects([Result 0], recipient), recipient = the next
//! keystore account), signs it (Ed25519 over Blake2b256(intent [0,0,0] ++ BCS)), submits it with
//! `sui.validator.Validator/SubmitTransaction` (TLS 1.3, server name "sui", the validator's network
//! key from genesis pinned), then waits with `WaitForEffects` (with details) and takes the gas
//! coin's new version and digest from the effects. Validators are rotated per transaction; a
//! transport error or a rejection retries the same signed transaction on the next validator (an
//! already executed transaction answers with its effects), so a lane never loses its gas version
//! when a validator dies mid-call. A validator that failed is skipped for 2 s.
//!
//! Every 5 s: `load t=..s submitted executed failed rejected errors expired inflight p50 p99`,
//! window counts then totals. Exit 0 when at least one transaction executed.
const std = @import("std");
const Io = std.Io;
const bcs = @import("bcs");
const types = @import("types");
const sig = @import("sig");
const rpc_exec = @import("rpc_exec");
const seat = @import("../seat.zig");
const messages = @import("../messages.zig");

const Allocator = std.mem.Allocator;
const Blake2b256 = std.crypto.hash.blake2.Blake2b256;
const grpc = rpc_exec.live.grpc_client;
const wire = rpc_exec.driver.wire;
const service = "/sui.validator.Validator/";

pub const usage =
    \\deepwave-validator load --genesis-dir DIR --tps N --duration-s S [options]
    \\  --genesis-dir DIR     Mysten `sui genesis` output: genesis.blob and sui.keystore
    \\  --tps N               target submissions per second (all lanes together)
    \\  --duration-s S        run time
    \\  --validators A,B,..   host:port per validator in genesis order (default: genesis net addresses)
    \\  --max-lanes N         use at most N gas coins (default: all owned by keystore accounts)
    \\  --gas-price P         default 1000 (localnet reference gas price)
    \\  --budget B            default 50000000
    \\  --allow-remote        accept non-loopback validator addresses
    \\
;

// ------------------------------------------------------------------ transaction building

pub const ObjRef = struct { id: [32]u8, version: u64, digest: [32]u8 };

pub const Account = struct {
    kp: sig.ed25519.KeyPair,
    address: [32]u8,

    pub fn fromSeed(seed: *const [32]u8) Account {
        const kp = sig.ed25519.KeyPair.fromSeed(seed);
        return .{ .kp = kp, .address = edAddress(&kp.pk) };
    }
};

/// SuiAddress of an Ed25519 key: Blake2b256(flag 0x00 ++ pk).
pub fn edAddress(pk: *const [32]u8) [32]u8 {
    var h = Blake2b256.init(.{});
    h.update(&.{0});
    h.update(pk);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

pub const Built = struct {
    /// BCS `Transaction` (Envelope<SenderSignedData, EmptySignInfo>): what SubmitTransaction takes.
    tx_bcs: []const u8,
    /// BCS `TransactionData`.
    td_bcs: []const u8,
    /// TransactionDigest = Blake2b256("TransactionData::" ++ td_bcs).
    digest: [32]u8,
    /// Blake2b256(intent ++ td_bcs): what the user signature signs.
    signing_digest: [32]u8,
    /// GenericSignature bytes (flag 0, sig 64, pk 32).
    signature: []const u8,
};

pub const TransferOpts = struct { amount: u64 = 1000, price: u64 = 1000, budget: u64 = 50_000_000 };

/// split + transfer PTB paid by `gas`, signed by `from`.
pub fn buildTransfer(a: Allocator, from: *const Account, gas: ObjRef, recipient: [32]u8, o: TransferOpts) !Built {
    const inputs = try a.alloc(types.CallArg, 2);
    var amt: [8]u8 = undefined;
    std.mem.writeInt(u64, &amt, o.amount, .little);
    inputs[0] = .{ .Pure = try a.dupe(u8, &amt) };
    inputs[1] = .{ .Pure = try a.dupe(u8, &recipient) };
    const split_args = try a.alloc(types.Argument, 1);
    split_args[0] = .{ .Input = 0 };
    const objs = try a.alloc(types.Argument, 1);
    objs[0] = .{ .Result = 0 };
    const cmds = try a.alloc(types.Command, 2);
    cmds[0] = .{ .SplitCoins = .{ .GasCoin, split_args } };
    cmds[1] = .{ .TransferObjects = .{ objs, .{ .Input = 1 } } };
    const Pay = @typeInfo(@TypeOf(@as(types.GasData, undefined).payment)).pointer.child;
    const pay = try a.alloc(Pay, 1);
    pay[0] = .{ .{ .@"0" = .{ .@"0" = gas.id } }, .{ .@"0" = gas.version }, .{ .@"0" = .{ .@"0" = gas.digest } } };
    const td: types.TransactionData = .{ .V1 = .{
        .kind = .{ .ProgrammableTransaction = .{ .inputs = inputs, .commands = cmds } },
        .sender = .{ .@"0" = from.address },
        .gas_data = .{ .payment = pay, .owner = .{ .@"0" = from.address }, .price = o.price, .budget = o.budget },
        .expiration = .None,
    } };
    const td_bcs = try bcs.encodeAlloc(types.TransactionData, a, &td);
    const intent = types.Intent.sui(.transaction_data).bytes();
    var sd: [32]u8 = undefined;
    {
        var h = Blake2b256.init(.{});
        h.update(&intent);
        h.update(td_bcs);
        h.final(&sd);
    }
    const s = try a.alloc(u8, 1 + 64 + 32);
    s[0] = 0;
    s[1..65].* = from.kp.sign(&sd);
    s[65..97].* = from.kp.pk;
    const sigs = try a.alloc(types.GenericSignature, 1);
    sigs[0] = .{ .@"0" = s };
    const sst = try a.alloc(types.SenderSignedTransaction, 1);
    sst[0] = .{ .intent_message = .{ .intent = types.Intent.sui(.transaction_data), .value = td }, .tx_signatures = sigs };
    const tx: messages.Transaction = .{ .data = .{ .@"0" = .{ .items = sst } }, .auth_signature = .{} };
    return .{
        .tx_bcs = try bcs.encodeAlloc(messages.Transaction, a, &tx),
        .td_bcs = td_bcs,
        .digest = types.digest.transactionDataDigest(td_bcs),
        .signing_digest = sd,
        .signature = s,
    };
}

/// The gas coin's new reference from executed effects (V2: the gas object's change and the
/// lamport version), with the execution status.
pub fn gasAfter(arena: Allocator, effects: []const u8) ?struct { gas: ObjRef, success: bool } {
    const fx = bcs.decode(types.TransactionEffects, arena, effects) catch return null;
    const v2 = switch (fx) {
        .V2 => |v| v,
        .V1 => return null,
    };
    const idx = v2.gas_object_index orelse return null;
    if (idx >= v2.changed_objects.len) return null;
    const ch = v2.changed_objects[idx];
    const d = switch (ch[1].output_state) {
        .ObjectWrite => |w| w[0].@"0".@"0",
        else => return null,
    };
    return .{ .gas = .{ .id = ch[0].@"0".@"0", .version = v2.lamport_version.@"0", .digest = d }, .success = v2.status == .Success };
}

// ------------------------------------------------------------------ genesis inputs

/// `sui.keystore`: a JSON array of base64(flag ++ private key). Ed25519 (flag 0) entries only.
pub fn parseKeystore(a: Allocator, json: []const u8) ![]Account {
    const entries = try std.json.parseFromSliceLeaky([]const []const u8, a, json, .{});
    var out: std.ArrayList(Account) = .empty;
    for (entries) |e| {
        var raw: [64]u8 = undefined;
        const n = std.base64.standard.Decoder.calcSizeForSlice(e) catch continue;
        if (n != 33) continue;
        std.base64.standard.Decoder.decode(raw[0..n], e) catch continue;
        if (raw[0] != 0) continue;
        try out.append(a, Account.fromSeed(raw[1..33]));
    }
    return out.items;
}

pub const Coin = struct { owner: usize, ref: ObjRef, balance: u64 };

/// Gas coins of `genesis.blob` owned by one of `accounts` (same walk as seat.readGenesis).
pub fn genesisCoins(a: Allocator, blob: []const u8, accounts: []const Account) ![]Coin {
    var outer = bcs.Reader.init(blob);
    const n = try outer.length();
    const inner = try outer.bytes(n);
    var r = bcs.Reader.init(inner);
    try bcs.skip(types.CheckpointSummary, &r);
    try bcs.skip(types.AuthorityQuorumSignInfo, &r);
    try bcs.skip(types.CheckpointContents, &r);
    try bcs.skip(@FieldType(types.CheckpointTransaction, "transaction"), &r);
    try bcs.skip(types.TransactionEffects, &r);
    try bcs.skip(types.TransactionEvents, &r);
    const nobj = try r.length();
    var out: std.ArrayList(Coin) = .empty;
    var ar = std.heap.ArenaAllocator.init(a);
    defer ar.deinit();
    for (0..nobj) |_| {
        const st = r.at;
        try bcs.skip(types.Object, &r);
        const raw = inner[st..r.at];
        _ = ar.reset(.retain_capacity);
        const obj = bcs.decode(types.Object, ar.allocator(), raw) catch continue;
        const mv = switch (obj.data) {
            .Move => |m| m,
            else => continue,
        };
        if (mv.type_.@"0" != .GasCoin or mv.contents.len != 40) continue;
        const owner = switch (obj.owner) {
            .AddressOwner => |o| o.@"0",
            else => continue,
        };
        const who = for (accounts, 0..) |acc, i| {
            if (std.mem.eql(u8, &acc.address, &owner)) break i;
        } else continue;
        try out.append(a, .{ .owner = who, .balance = std.mem.readInt(u64, mv.contents[32..40], .little), .ref = .{
            .id = mv.contents[0..32].*,
            .version = mv.version.@"0",
            .digest = types.digest.objectDigest(raw),
        } });
    }
    return out.items;
}

// ------------------------------------------------------------------ the run

const Validator = struct {
    host: []const u8,
    port: u16,
    pk: [32]u8,
    down_until_ms: std.atomic.Value(i64) = .init(0),
};

const Stats = struct {
    submitted: std.atomic.Value(u64) = .init(0),
    executed: std.atomic.Value(u64) = .init(0),
    failed: std.atomic.Value(u64) = .init(0),
    rejected: std.atomic.Value(u64) = .init(0),
    errors: std.atomic.Value(u64) = .init(0),
    expired: std.atomic.Value(u64) = .init(0),
    inflight: std.atomic.Value(i64) = .init(0),
    stalled: std.atomic.Value(u32) = .init(0),
    mu: Io.Mutex = .init,
    window: std.ArrayList(u32) = .empty,
    all: std.ArrayList(u32) = .empty,
};

const Shared = struct {
    io: Io,
    validators: []Validator,
    accounts: []const Account,
    opts: TransferOpts,
    stop: std.atomic.Value(bool) = .init(false),
    stats: Stats = .{},
    pace_mu: Io.Mutex = .init,
    next_send_us: i64 = 0,
    interval_us: i64,
    t0_ms: i64,
    first_error: std.atomic.Value(bool) = .init(false),
};

fn nowMs(io: Io) i64 {
    return @intCast(@divTrunc(Io.Clock.awake.now(io).nanoseconds, std.time.ns_per_ms));
}

fn sleepMs(io: Io, ms: i64) void {
    if (ms <= 0) return;
    Io.sleep(io, .fromMilliseconds(@intCast(ms)), .awake) catch {};
}

/// Global pacing: one send slot per `interval`; never bursts after a stall.
fn takeSlot(s: *Shared) void {
    s.pace_mu.lockUncancelable(s.io);
    const now_us = nowMs(s.io) * 1000;
    const t = @max(s.next_send_us, now_us);
    s.next_send_us = t + s.interval_us;
    s.pace_mu.unlock(s.io);
    sleepMs(s.io, @divTrunc(t - now_us, 1000));
}

const Lane = struct {
    s: *Shared,
    id: usize,
    owner: usize,
    gas: ObjRef,
    conns: []?*grpc.Conn,
    next_v: usize,
    thread: ?std.Thread = null,

    fn conn(l: *Lane, vi: usize) ?*grpc.Conn {
        if (l.conns[vi]) |c| {
            if (!c.isDead()) return c;
            c.release();
            l.conns[vi] = null;
        }
        const v = &l.s.validators[vi];
        const c = grpc.Conn.open(std.heap.smp_allocator, l.s.io, .{ .host = v.host, .port = v.port, .security = .{ .pinned = v.pk } }) catch return null;
        l.conns[vi] = c;
        return c;
    }

    fn markDown(l: *Lane, vi: usize) void {
        if (l.conns[vi]) |c| c.release();
        l.conns[vi] = null;
        l.s.validators[vi].down_until_ms.store(nowMs(l.s.io) + 2000, .release);
    }

    fn pickValidator(l: *Lane) usize {
        const n = l.s.validators.len;
        const now = nowMs(l.s.io);
        for (0..n) |k| {
            const vi = (l.next_v + k) % n;
            if (l.s.validators[vi].down_until_ms.load(.acquire) <= now) {
                l.next_v = vi + 1;
                return vi;
            }
        }
        l.next_v += 1;
        return (l.next_v - 1) % n;
    }

    fn noteError(l: *Lane, what: []const u8, vi: usize, detail: []const u8) void {
        _ = l.s.stats.errors.fetchAdd(1, .monotonic);
        if (!l.s.first_error.swap(true, .acq_rel)) std.debug.print("load: first error: {s} on validator {d}: {s}\n", .{ what, vi, detail });
    }

    fn run(l: *Lane) void {
        var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
        defer arena.deinit();
        const s = l.s;
        const recipient = s.accounts[(l.owner + 1) % s.accounts.len].address;
        while (!s.stop.load(.acquire)) {
            _ = arena.reset(.retain_capacity);
            const a = arena.allocator();
            takeSlot(s);
            if (s.stop.load(.acquire)) break;
            const built = buildTransfer(a, &s.accounts[l.owner], l.gas, recipient, s.opts) catch {
                l.noteError("build", 0, "out of memory");
                continue;
            };
            _ = s.stats.submitted.fetchAdd(1, .monotonic);
            _ = s.stats.inflight.fetchAdd(1, .monotonic);
            const t_start = nowMs(s.io);
            const fx = l.drive(a, &built);
            _ = s.stats.inflight.fetchSub(1, .monotonic);
            const effects = fx orelse {
                // could not get effects in 64 attempts: the gas version is unknown from here on
                _ = s.stats.stalled.fetchAdd(1, .monotonic);
                std.debug.print("load: lane {d} stalled (gas {x} v{d})\n", .{ l.id, l.gas.id[0..4], l.gas.version });
                return;
            };
            const g = gasAfter(a, effects) orelse {
                l.noteError("effects", 0, "effects without a readable gas object");
                _ = s.stats.stalled.fetchAdd(1, .monotonic);
                return;
            };
            l.gas = g.gas;
            const lat: u32 = @intCast(@max(0, nowMs(s.io) - t_start));
            if (g.success) _ = s.stats.executed.fetchAdd(1, .monotonic) else _ = s.stats.failed.fetchAdd(1, .monotonic);
            s.stats.mu.lockUncancelable(s.io);
            s.stats.window.append(std.heap.smp_allocator, lat) catch {};
            s.stats.all.append(std.heap.smp_allocator, lat) catch {};
            s.stats.mu.unlock(s.io);
        }
    }

    /// Submits `b` until some validator returns its effects (bytes in `a`), or null after the
    /// attempt budget. Retries keep the same signed transaction, so they are idempotent.
    fn drive(l: *Lane, a: Allocator, b: *const Built) ?[]const u8 {
        const s = l.s;
        const req = wire.submitTxRequest(a, b.tx_bcs) catch return null;
        var attempt: u32 = 0;
        while (attempt < 64) : (attempt += 1) {
            if (attempt > 0) {
                if (s.stop.load(.acquire) and attempt > 8) return null;
                sleepMs(s.io, @min(@as(i64, 100) * attempt, 1000));
            }
            const vi = l.pickValidator();
            const c = l.conn(vi) orelse {
                l.noteError("connect", vi, "");
                l.markDown(vi);
                continue;
            };
            const res = grpc.callBlocking(a, c, service ++ "SubmitTransaction", req, 10_000) catch |e| {
                l.noteError("submit", vi, @errorName(e));
                l.markDown(vi);
                continue;
            };
            const body = switch (res) {
                .ok => |x| x,
                .status => |st| {
                    l.noteError("submit status", vi, st.message);
                    l.markDown(vi);
                    continue;
                },
            };
            const dec = wire.decodeSubmitTxResponse(a, body) catch return null;
            const r = switch (dec) {
                .ok => |x| x,
                .err => {
                    _ = s.stats.rejected.fetchAdd(1, .monotonic);
                    continue;
                },
            };
            var pos: ?wire.ConsensusPosition = null;
            switch (r) {
                .Executed => |e| if (e.details) |d| return d.effects,
                .Submitted => |sub| pos = sub.position,
                .Rejected => {
                    _ = s.stats.rejected.fetchAdd(1, .monotonic);
                    continue;
                },
            }
            const wreq = wire.waitForEffectsRequest(a, .{ .transaction_digest = b.digest, .consensus_position = pos, .include_details = true }) catch return null;
            const wres = grpc.callBlocking(a, c, service ++ "WaitForEffects", wreq, 30_000) catch |e| {
                l.noteError("wait", vi, @errorName(e));
                l.markDown(vi);
                continue;
            };
            const wbody = switch (wres) {
                .ok => |x| x,
                .status => |st| {
                    l.noteError("wait status", vi, st.message);
                    continue;
                },
            };
            const wdec = wire.decodeWaitForEffectsResponse(a, wbody) catch return null;
            switch (wdec) {
                .err => {
                    _ = s.stats.rejected.fetchAdd(1, .monotonic);
                    continue;
                },
                .ok => |w| switch (w) {
                    .Executed => |e| if (e.details) |d| return d.effects else continue,
                    .Rejected => {
                        _ = s.stats.rejected.fetchAdd(1, .monotonic);
                        continue;
                    },
                    .Expired => {
                        _ = s.stats.expired.fetchAdd(1, .monotonic);
                        continue;
                    },
                },
            }
        }
        return null;
    }
};

fn percentile(xs: []u32, p: u32) u32 {
    if (xs.len == 0) return 0;
    std.mem.sort(u32, xs, {}, std.sort.asc(u32));
    return xs[@min(xs.len - 1, xs.len * p / 100)];
}

const Snap = struct { sub: u64, exe: u64, fail: u64, rej: u64, err: u64, exp: u64 };

fn snap(st: *Stats) Snap {
    return .{ .sub = st.submitted.load(.monotonic), .exe = st.executed.load(.monotonic), .fail = st.failed.load(.monotonic), .rej = st.rejected.load(.monotonic), .err = st.errors.load(.monotonic), .exp = st.expired.load(.monotonic) };
}

fn isLoopback(host: []const u8) bool {
    return std.mem.startsWith(u8, host, "127.") or std.mem.eql(u8, host, "localhost") or std.mem.eql(u8, host, "::1");
}

pub fn main(gpa: Allocator, io: Io, args: []const []const u8) u8 {
    return mainInner(gpa, io, args) catch |e| {
        std.debug.print("deepwave-validator load: {s}\n", .{@errorName(e)});
        return 2;
    };
}

fn mainInner(gpa: Allocator, io: Io, args: []const []const u8) !u8 {
    var dir: ?[]const u8 = null;
    var tps: u32 = 0;
    var duration_s: u32 = 0;
    var addrs: ?[]const u8 = null;
    var max_lanes: usize = std.math.maxInt(usize);
    var allow_remote = false;
    var opts: TransferOpts = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const k = args[i];
        if (std.mem.eql(u8, k, "--allow-remote")) {
            allow_remote = true;
            continue;
        }
        if (i + 1 >= args.len) return bad();
        const v = args[i + 1];
        i += 1;
        if (std.mem.eql(u8, k, "--genesis-dir")) dir = v //
        else if (std.mem.eql(u8, k, "--tps")) tps = std.fmt.parseInt(u32, v, 10) catch return bad() //
        else if (std.mem.eql(u8, k, "--duration-s")) duration_s = std.fmt.parseInt(u32, v, 10) catch return bad() //
        else if (std.mem.eql(u8, k, "--validators")) addrs = v //
        else if (std.mem.eql(u8, k, "--max-lanes")) max_lanes = std.fmt.parseInt(usize, v, 10) catch return bad() //
        else if (std.mem.eql(u8, k, "--gas-price")) opts.price = std.fmt.parseInt(u64, v, 10) catch return bad() //
        else if (std.mem.eql(u8, k, "--budget")) opts.budget = std.fmt.parseInt(u64, v, 10) catch return bad() //
        else return bad();
    }
    const gdir = dir orelse return bad();
    if (tps == 0 or duration_s == 0) return bad();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cwd = Io.Dir.cwd();
    const blob = try cwd.readFileAlloc(io, try std.fmt.allocPrint(a, "{s}/genesis.blob", .{gdir}), a, .limited(1 << 30));
    const ks = try cwd.readFileAlloc(io, try std.fmt.allocPrint(a, "{s}/sui.keystore", .{gdir}), a, .limited(1 << 20));
    const accounts = try parseKeystore(a, ks);
    if (accounts.len == 0) {
        std.debug.print("load: no Ed25519 keys in sui.keystore\n", .{});
        return 2;
    }
    const info = try seat.readGenesis(a, blob);
    const vals = try a.alloc(Validator, info.validators.len);
    var addr_it = if (addrs) |s| std.mem.splitScalar(u8, s, ',') else null;
    for (info.validators, vals, 0..) |gv, *v, vi| {
        var host: []const u8 = undefined;
        var port: u16 = undefined;
        if (addr_it) |*it| {
            const hp = it.next() orelse {
                std.debug.print("load: --validators lists fewer than the {d} genesis validators\n", .{info.validators.len});
                return 2;
            };
            const c = std.mem.lastIndexOfScalar(u8, hp, ':') orelse return bad();
            host = hp[0..c];
            port = std.fmt.parseInt(u16, hp[c + 1 ..], 10) catch return bad();
        } else {
            const hp = rpc_exec.live.validators.parseMultiaddr(gv.net_address) orelse {
                std.debug.print("load: validator {d}: cannot parse net address {s}\n", .{ vi, gv.net_address });
                return 2;
            };
            host = try a.dupe(u8, hp.host);
            port = hp.port;
        }
        if (!allow_remote and !isLoopback(host)) {
            std.debug.print("load: refusing non-loopback validator address {s} (local committees only; --allow-remote)\n", .{host});
            return 2;
        }
        v.* = .{ .host = host, .port = port, .pk = gv.network_pubkey };
    }
    const coins = try genesisCoins(a, blob, accounts);
    var usable: std.ArrayList(Coin) = .empty;
    for (coins) |c| if (c.balance >= opts.budget * 4) try usable.append(a, c);
    if (usable.items.len == 0) {
        std.debug.print("load: no gas coins owned by keystore accounts in genesis.blob\n", .{});
        return 2;
    }
    const nl = @min(usable.items.len, max_lanes);

    var shared: Shared = .{ .io = io, .validators = vals, .accounts = accounts, .opts = opts, .interval_us = @max(1, @divTrunc(1_000_000, @as(i64, tps))), .t0_ms = nowMs(io) };
    shared.next_send_us = shared.t0_ms * 1000;
    std.debug.print("load: chain {s} epoch {d} protocol {d}, {d} validators, {d} accounts, {d} lanes, {d} tps for {d} s\n", .{ &info.chain_id, info.epoch, info.protocol_version, vals.len, accounts.len, nl, tps, duration_s });
    const lanes = try a.alloc(Lane, nl);
    for (lanes, 0..) |*l, li| {
        const conns = try a.alloc(?*grpc.Conn, vals.len);
        @memset(conns, null);
        l.* = .{ .s = &shared, .id = li, .owner = usable.items[li].owner, .gas = usable.items[li].ref, .conns = conns, .next_v = li % vals.len };
    }
    for (lanes) |*l| l.thread = std.Thread.spawn(.{ .stack_size = 16 << 20 }, Lane.run, .{l}) catch null;

    var prev: Snap = .{ .sub = 0, .exe = 0, .fail = 0, .rej = 0, .err = 0, .exp = 0 };
    const end_ms = shared.t0_ms + @as(i64, duration_s) * 1000;
    var next_report = shared.t0_ms + 5000;
    while (true) {
        const now = nowMs(io);
        const done = now >= end_ms;
        if (now >= next_report or done) {
            const cur = snap(&shared.stats);
            shared.stats.mu.lockUncancelable(io);
            const p50 = percentile(shared.stats.window.items, 50);
            const p99 = percentile(shared.stats.window.items, 99);
            shared.stats.window.clearRetainingCapacity();
            shared.stats.mu.unlock(io);
            std.debug.print("load t={d}s submitted={d} executed={d} failed={d} rejected={d} errors={d} expired={d} inflight={d} p50={d}ms p99={d}ms | total submitted={d} executed={d} rejected={d} errors={d} stalled_lanes={d}\n", .{
                @divTrunc(now - shared.t0_ms, 1000), cur.sub - prev.sub, cur.exe - prev.exe, cur.fail - prev.fail, cur.rej - prev.rej, cur.err - prev.err, cur.exp - prev.exp, shared.stats.inflight.load(.monotonic), p50, p99, cur.sub, cur.exe, cur.rej, cur.err, shared.stats.stalled.load(.monotonic),
            });
            prev = cur;
            next_report += 5000;
        }
        if (done) break;
        sleepMs(io, @min(250, end_ms - now));
    }
    shared.stop.store(true, .release);
    for (lanes) |*l| if (l.thread) |t| t.join();
    for (lanes) |*l| for (l.conns) |c| if (c) |cc| cc.release();
    const fin = snap(&shared.stats);
    const all = shared.stats.all.items;
    const secs = @as(f64, @floatFromInt(@max(1, nowMs(io) - shared.t0_ms))) / 1000.0;
    const p50 = percentile(all, 50);
    const p99 = percentile(all, 99);
    std.debug.print("load done: submitted={d} executed={d} failed={d} rejected={d} errors={d} expired={d} stalled_lanes={d} executed_tps={d:.1} p50={d}ms p99={d}ms\n", .{ fin.sub, fin.exe, fin.fail, fin.rej, fin.err, fin.exp, shared.stats.stalled.load(.monotonic), @as(f64, @floatFromInt(fin.exe)) / secs, p50, p99 });
    shared.stats.window.deinit(std.heap.smp_allocator);
    shared.stats.all.deinit(std.heap.smp_allocator);
    return if (fin.exe > 0) 0 else 1;
}

fn bad() u8 {
    std.debug.print("{s}", .{usage});
    return 2;
}

// ------------------------------------------------------------------ tests

test "load: transfer tx signs over the intent digest and its digest is TransactionData::" {
    var ar = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const seed: [32]u8 = @splat(0x11);
    const acc = Account.fromSeed(&seed);
    const to = Account.fromSeed(&@as([32]u8, @splat(0x22))).address;
    const gas: ObjRef = .{ .id = @splat(0xc0), .version = 7, .digest = @splat(0xd1) };
    const b = try buildTransfer(a, &acc, gas, to, .{ .amount = 5, .price = 1000, .budget = 2_000_000 });

    // digest rule: Blake2b256("TransactionData::" ++ BCS)
    var want: [32]u8 = undefined;
    var h = Blake2b256.init(.{});
    h.update("TransactionData::");
    h.update(b.td_bcs);
    h.final(&want);
    try std.testing.expectEqualSlices(u8, &want, &b.digest);

    // the signature verifies with src/crypto/sig (user signature path, sender address check)
    const env: sig.user.UserSigEnv = .{ .epoch = 0 };
    var scratch: [4096]u8 = undefined;
    const v = try sig.user.verifyUserSignatureDigest(&env, &b.signing_digest, &acc.address, b.signature, &scratch);
    try std.testing.expect(v == .valid);
    try std.testing.expect(sig.ed25519.verify(&acc.kp.pk, &b.signing_digest, b.signature[1..65]) == .valid);
    // a different sender does not verify
    const v2 = try sig.user.verifyUserSignatureDigest(&env, &b.signing_digest, &to, b.signature, &scratch);
    try std.testing.expect(v2 != .valid);

    // the envelope decodes back to the same TransactionData and the signing digest is intent ++ BCS
    const tx = try bcs.decode(messages.Transaction, a, b.tx_bcs);
    const sst = tx.data.@"0".items[0];
    const td_again = try bcs.encodeAlloc(types.TransactionData, a, &sst.intent_message.value);
    try std.testing.expectEqualSlices(u8, b.td_bcs, td_again);
    var sd: [32]u8 = undefined;
    var h2 = Blake2b256.init(.{});
    h2.update(&[_]u8{ 0, 0, 0 });
    h2.update(b.td_bcs);
    h2.final(&sd);
    try std.testing.expectEqualSlices(u8, &sd, &b.signing_digest);
    try std.testing.expectEqualSlices(u8, b.signature, sst.tx_signatures[0].@"0");
    const td = sst.intent_message.value.V1;
    try std.testing.expectEqualSlices(u8, &acc.address, &td.sender.@"0");
    try std.testing.expectEqual(@as(u64, 7), td.gas_data.payment[0][1].@"0");
    try std.testing.expectEqual(@as(usize, 2), td.kind.ProgrammableTransaction.commands.len);
}

test "load: keystore entries map to Ed25519 accounts" {
    var ar = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    var raw: [33]u8 = undefined;
    raw[0] = 0;
    @memset(raw[1..], 0x33);
    var b64: [44]u8 = undefined;
    const enc = std.base64.standard.Encoder.encode(&b64, &raw);
    var k1: [33]u8 = raw;
    k1[0] = 1; // secp256k1 entry: skipped
    var b64k1: [44]u8 = undefined;
    const enc1 = std.base64.standard.Encoder.encode(&b64k1, &k1);
    const json = try std.fmt.allocPrint(a, "[\"{s}\",\"{s}\"]", .{ enc, enc1 });
    const accs = try parseKeystore(a, json);
    try std.testing.expectEqual(@as(usize, 1), accs.len);
    const want = Account.fromSeed(raw[1..33]);
    try std.testing.expectEqualSlices(u8, &want.address, &accs[0].address);
}
