//! `deepwave-validator seat`: a deepwave consensus authority takes over one seat of a local committee that
//! Mysten's own tooling generated (`sui genesis`), next to Mysten sui-node validators. This is the
//! mixed-committee compatibility test of docs/VALIDATOR-MIXED-LOCALNET.md.
//!
//! Inputs are Mysten's files, unchanged:
//!   - the seat's validator.yaml (`keys.config`): the worker (consensus protocol), network and
//!     protocol (BLS) keys as `value:` or `path:`, the genesis location, the db path;
//!   - genesis.blob: the epoch 0 committee is read from the genesis system state exactly as
//!     sui-types `EpochStartSystemState::get_consensus_committee` builds it (address =
//!     primary_address, protocol key = worker key, network key, stake = voting power, hostname =
//!     name; sorted by the BLS protocol key), plus the protocol version, the epoch start time and
//!     the chain id (first 4 bytes of the genesis checkpoint digest).
//!
//! What runs is consensus only: the real Mysticeti core, network and LogStore of `consensus_net`
//! (`ConsensusAuthority`), with an accept-all transaction verifier (the seat never votes to reject),
//! no transactions of its own, and a commit sink that writes every committed sub-dag in the same
//! text form sui-core logs (`Received consensus output ...`, `CommittedSubDag` Display) plus a
//! full-digest line, so the commit sequences can be compared index by index.
//!
//! Safety: the gate runs first with `KeySource.localnet_config`. It is allowed only when the chain
//! is not mainnet or testnet and every genesis committee address (and every address of the yaml)
//! is loopback or private; the seat's keys must be a member of that genesis committee. The license
//! is bound to the genesis chain id. Blocks are signed only through `Signer` (round watermarks).
const std = @import("std");
const Io = std.Io;
const bcs = @import("bcs");
const types = @import("types");
const hash = @import("hash");
const consensus = @import("consensus");
const consensus_net = @import("consensus_net");
const gate = @import("gate.zig");
const signer_mod = @import("signer.zig");
const keys = @import("keys/root.zig");
const vnode = @import("node.zig");
const Reader = bcs.Reader;
const ctypes = consensus.types;

pub const usage =
    \\deepwave-validator seat --config FILE [--genesis FILE] [--db DIR] [--commits FILE] [--duration-s N]
    \\  --config FILE     the seat's validator.yaml written by Mysten's `sui genesis` (keys inline or as paths)
    \\  --genesis FILE    genesis.blob (default: the yaml's genesis-file-location)
    \\  --db DIR          zui consensus store and signer watermarks (default: <db-path>-zui)
    \\  --commits FILE    commit log (default: <db>/commits.log); one Mysten-format line and one full-digest line per commit
    \\  --duration-s N    stop after N seconds (default: run until SIGINT/SIGTERM)
    \\  --dry-run         gate, keys and committee only: print the seat's authority index and exit
    \\
;

pub const Error = error{ BadArguments, BadConfig, BadGenesis, Refused, NotAMember, Io, OutOfMemory, Startup };

// ------------------------------------------------------------------ genesis

pub const GenesisValidator = struct {
    protocol_pubkey: [96]u8,
    network_pubkey: [32]u8,
    worker_pubkey: [32]u8,
    name: []const u8,
    net_address: []const u8,
    p2p_address: []const u8,
    primary_address: []const u8,
    voting_power: u64,
};

pub const GenesisInfo = struct {
    chain_id: [8]u8,
    epoch: u64,
    protocol_version: u64,
    epoch_start_timestamp_ms: u64,
    /// Sorted by the BLS protocol key (the consensus AuthorityIndex order).
    validators: []GenesisValidator,
};

fn dynamicFieldId(parent: *const [32]u8, key_u64: u64) [32]u8 {
    var k: [8]u8 = undefined;
    std.mem.writeInt(u64, &k, key_u64, .little);
    var klen: [8]u8 = undefined;
    std.mem.writeInt(u64, &klen, 8, .little);
    return hash.blake2b256(&.{ &[_]u8{0xf0}, parent, &klen, &k, &[_]u8{2} });
}

fn vecBytes(r: *Reader) bcs.Error![]const u8 {
    const n = try r.length();
    return r.bytes(n);
}
fn skipOptVecBytes(r: *Reader) bcs.Error!void {
    switch (try r.int(u8)) {
        0 => {},
        1 => _ = try vecBytes(r),
        else => return error.InvalidEnumTag,
    }
}
fn skipOptU64(r: *Reader) bcs.Error!void {
    switch (try r.int(u8)) {
        0 => {},
        1 => _ = try r.bytes(8),
        else => return error.InvalidEnumTag,
    }
}

/// Reads `genesis.blob` (BCS `Vec<u8>` of the genesis: certified checkpoint 0, contents,
/// transaction, effects, events, objects). Memory from `arena`.
pub fn readGenesis(arena: std.mem.Allocator, blob: []const u8) Error!GenesisInfo {
    return readGenesisInner(arena, blob) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.BadGenesis,
    };
}

fn readGenesisInner(arena: std.mem.Allocator, blob: []const u8) !GenesisInfo {
    var outer = Reader.init(blob);
    const n = try outer.length();
    const inner = try outer.bytes(n);
    var r = Reader.init(inner);
    // chain id: the genesis checkpoint summary digest
    const s0 = r.at;
    try bcs.skip(types.CheckpointSummary, &r);
    const summary_bytes = inner[s0..r.at];
    const cp_digest = types.digest.checkpointSummaryDigest(summary_bytes);
    var chain_id: [8]u8 = undefined;
    _ = std.fmt.bufPrint(&chain_id, "{x}", .{cp_digest[0..4]}) catch unreachable;
    try bcs.skip(types.AuthorityQuorumSignInfo, &r);
    try bcs.skip(types.CheckpointContents, &r);
    try bcs.skip(@FieldType(types.CheckpointTransaction, "transaction"), &r);
    try bcs.skip(types.TransactionEffects, &r);
    try bcs.skip(types.TransactionEvents, &r);
    const nobj = try r.length();
    if (nobj > r.remaining()) return error.EndOfInput;
    const ObjView = bcs.View(types.Object);
    var five: [32]u8 = @splat(0);
    five[31] = 5;
    const ranges = try arena.alloc([]const u8, nobj);
    var want: ?[32]u8 = null;
    var version: u64 = 0;
    for (ranges) |*rg| {
        const st = r.at;
        try bcs.skip(types.Object, &r);
        rg.* = inner[st..r.at];
        const mv = (ObjView{ .bytes = rg.* }).field("data").payload("Move") orelse continue;
        const c = mv.field("contents").raw();
        if (c.len >= 40 and std.mem.eql(u8, c[0..32], &five)) {
            version = std.mem.readInt(u64, c[32..40], .little);
            want = dynamicFieldId(&five, version);
        }
    }
    const w = want orelse return error.NoSystemState;
    if (version != 1 and version != 2) return error.UnsupportedSystemState;
    const contents = for (ranges) |rg| {
        const mv = (ObjView{ .bytes = rg }).field("data").payload("Move") orelse continue;
        const c = mv.field("contents").raw();
        if (c.len >= 40 and std.mem.eql(u8, c[0..32], &w)) break c;
    } else return error.NoSystemState;

    var s = Reader.init(contents);
    _ = try s.bytes(32); // Field.id
    _ = try s.int(u64); // Field.name
    const epoch = try s.int(u64);
    const protocol_version = try s.int(u64);
    _ = try s.int(u64); // system_state_version
    _ = try s.int(u64); // validators.total_stake
    const nv = try s.length();
    if (nv > s.remaining()) return error.EndOfInput;
    const vals = try arena.alloc(GenesisValidator, nv);
    for (vals) |*v| {
        _ = try s.bytes(32); // sui_address
        const pk = try vecBytes(&s);
        const nk = try vecBytes(&s);
        const wk = try vecBytes(&s);
        if (pk.len != 96 or nk.len != 32 or wk.len != 32) return error.BadKey;
        v.protocol_pubkey = pk[0..96].*;
        v.network_pubkey = nk[0..32].*;
        v.worker_pubkey = wk[0..32].*;
        _ = try vecBytes(&s); // proof_of_possession
        v.name = try vecBytes(&s);
        _ = try vecBytes(&s); // description
        _ = try vecBytes(&s); // image_url
        _ = try vecBytes(&s); // project_url
        v.net_address = try vecBytes(&s);
        v.p2p_address = try vecBytes(&s);
        v.primary_address = try vecBytes(&s);
        _ = try vecBytes(&s); // worker_address
        for (0..8) |_| try skipOptVecBytes(&s); // next_epoch keys, proof and addresses
        _ = try s.bytes(40); // extra_fields
        v.voting_power = try s.int(u64);
        _ = try s.bytes(32); // operation_cap_id
        _ = try s.int(u64); // gas_price
        _ = try s.bytes(32); // StakingPoolV1.id
        try skipOptU64(&s);
        try skipOptU64(&s);
        _ = try s.bytes(8 * 3);
        _ = try s.bytes(40);
        _ = try s.bytes(8 * 3);
        _ = try s.bytes(40);
        _ = try s.bytes(8 * 4);
        _ = try s.bytes(40);
    }
    _ = try s.bytes(40); // pending_active_validators
    const nrem = try s.length();
    _ = try s.bytes(8 * nrem);
    _ = try s.bytes(40 * 3); // staking_pool_mappings, inactive_validators, validator_candidates
    const nrisk = try s.length();
    _ = try s.bytes(40 * nrisk);
    _ = try s.bytes(40); // validators.extra_fields
    _ = try s.bytes(16); // storage_fund
    // SystemParametersV1 has 7 u64 fields, V2 adds min_validator_count; then extra_fields
    _ = try s.bytes(8 * @as(usize, if (version == 2) 8 else 7) + 40);
    _ = try s.int(u64); // reference_gas_price
    const nrep = try s.length();
    for (0..nrep) |_| {
        _ = try s.bytes(32);
        const m = try s.length();
        _ = try s.bytes(32 * m);
    }
    _ = try s.bytes(8 * 4 + 2 + 40); // stake_subsidy
    _ = try s.int(u8); // safe_mode
    _ = try s.bytes(8 * 4);
    const start_ms = try s.int(u64);

    std.mem.sort(GenesisValidator, vals, {}, struct {
        fn lt(_: void, a: GenesisValidator, b: GenesisValidator) bool {
            return std.mem.lessThan(u8, &a.protocol_pubkey, &b.protocol_pubkey);
        }
    }.lt);
    return .{ .chain_id = chain_id, .epoch = epoch, .protocol_version = protocol_version, .epoch_start_timestamp_ms = start_ms, .validators = vals };
}

// ------------------------------------------------------------------ keys

fn keyText(gpa: std.mem.Allocator, io: Io, loc: ?keys.config.KeyLocation) Error![]u8 {
    const l = loc orelse return error.BadConfig;
    return switch (l) {
        .value => |v| gpa.dupe(u8, v) catch error.OutOfMemory,
        .path => |p| (keys.fsutil.readAll(gpa, io, p, 4096) catch return error.Io) orelse error.BadConfig,
    };
}

fn loadKeys(gpa: std.mem.Allocator, io: Io, c: *const keys.config.ValidatorConfig) Error!keys.material.KeySet {
    const pk = try keyText(gpa, io, c.protocol_key);
    defer {
        std.crypto.secureZero(u8, pk);
        gpa.free(pk);
    }
    const wk = try keyText(gpa, io, c.worker_key);
    defer {
        std.crypto.secureZero(u8, wk);
        gpa.free(wk);
    }
    const nk = try keyText(gpa, io, c.network_key);
    defer {
        std.crypto.secureZero(u8, nk);
        gpa.free(nk);
    }
    const authority = keys.material.decodeAuthorityFile(pk) catch return error.BadConfig;
    return .{
        .authority = authority,
        .authority_pk = authority.publicKey().toBytes(),
        .worker = keys.material.decodeEd25519File(wk) catch return error.BadConfig,
        .network = keys.material.decodeEd25519File(nk) catch return error.BadConfig,
        // sui-node never reads the account key on a validator (KeySet.account is null for
        // validator.yaml key sets, as in Signer.loadFiles)
        .account = null,
    };
}

// ------------------------------------------------------------------ the transaction side (consensus only)

const AcceptAll = struct {
    fn verifier() consensus.iface.TransactionVerifier {
        return .{ .ctx = @constCast(@ptrCast(&vt)), .vtable = &vt };
    }
    const vt: consensus.iface.TransactionVerifier.VTable = .{ .verify_batch = verifyBatch, .verify_and_vote_batch = vote };
    fn verifyBatch(_: *anyopaque, _: ctypes.BlockRef, _: []const ctypes.Transaction) consensus.iface.TransactionVerifier.VerifyError!void {}
    fn vote(_: *anyopaque, _: ctypes.BlockRef, _: []const ctypes.Transaction, _: []ctypes.TransactionIndex) consensus.iface.TransactionVerifier.VerifyError!usize {
        return 0;
    }
};

const NoTransactions = struct {
    fn source() consensus.iface.TransactionSource {
        return .{ .ctx = @constCast(@ptrCast(&vt)), .vtable = &vt };
    }
    const vt: consensus.iface.TransactionSource.VTable = .{ .next = next, .ack = ack };
    fn next(_: *anyopaque, _: []ctypes.Transaction, _: u64) usize {
        return 0;
    }
    fn ack(_: *anyopaque, _: ctypes.BlockRef) void {}
};

/// Writes each committed sub-dag as sui-core logs it plus a full-digest line.
const LogSink = struct {
    fd: std.c.fd_t,
    mu: std.atomic.Mutex = .unlocked,
    processed: std.atomic.Value(u64) = .init(0),
    commits: std.atomic.Value(u64) = .init(0),
    own_leaders: std.atomic.Value(u64) = .init(0),
    own_blocks_committed: std.atomic.Value(u64) = .init(0),
    leaders_by_author: [64]std.atomic.Value(u64) = @splat(.init(0)),
    own_index: ctypes.AuthorityIndex,
    buf: [1 << 16]u8 = undefined,

    fn sink(s: *LogSink) consensus.iface.CommitSink {
        return .{ .ctx = s, .vtable = &vt };
    }
    const vt: consensus.iface.CommitSink.VTable = .{ .push = push, .processed_through = processedThrough };

    fn b64(out: []u8, d: *const [32]u8) []const u8 {
        return std.base64.standard.Encoder.encode(out, d);
    }

    fn push(ctx: *anyopaque, sd: *const ctypes.CommittedSubDag) bool {
        const s: *LogSink = @ptrCast(@alignCast(ctx));
        while (!s.mu.tryLock()) std.atomic.spinLoopHint();
        defer s.mu.unlock();
        var w = std.Io.Writer.fixed(&s.buf);
        var e1: [44]u8 = undefined;
        var e2: [44]u8 = undefined;
        // CommittedSubDag Display (consensus/core/src/commit.rs): "{commit_ref}@{leader} [{blocks}])",
        // BlockRef "B{round}({author},{digest})" with AuthorityIndex Display "[i]"
        const cd = b64(&e1, &sd.commit_ref.digest);
        const ld = b64(&e2, &sd.leader.digest);
        w.print("MYSTEN C{d}({s})@B{d}([{d}],{s}) [", .{ sd.commit_ref.index, cd[0..4], sd.leader.round, sd.leader.author, ld[0..4] }) catch return false;
        var own_blocks: u64 = 0;
        for (sd.blocks, 0..) |b, i| {
            const r = b.reference();
            var e3: [44]u8 = undefined;
            const bd = b64(&e3, &r.digest);
            if (i != 0) w.writeAll(", ") catch return false;
            w.print("B{d}([{d}],{s})", .{ r.round, r.author, bd[0..4] }) catch return false;
            if (r.author == s.own_index) own_blocks += 1;
        }
        w.writeAll("])\n") catch return false;
        w.print("FULL index={d} digest={s} leader_round={d} leader_author={d} leader_digest={s} ts={d} blocks={d}\n", .{ sd.commit_ref.index, cd, sd.leader.round, sd.leader.author, ld, sd.timestamp_ms, sd.blocks.len }) catch return false;
        const out = w.buffered();
        var off: usize = 0;
        while (off < out.len) {
            const n = std.c.write(s.fd, out[off..].ptr, out.len - off);
            if (n <= 0) break;
            off += @intCast(n);
        }
        s.processed.store(sd.commit_ref.index, .release);
        _ = s.commits.fetchAdd(1, .monotonic);
        if (sd.leader.author == s.own_index) _ = s.own_leaders.fetchAdd(1, .monotonic);
        if (sd.leader.author < s.leaders_by_author.len) _ = s.leaders_by_author[sd.leader.author].fetchAdd(1, .monotonic);
        _ = s.own_blocks_committed.fetchAdd(own_blocks, .monotonic);
        return true;
    }
    fn processedThrough(ctx: *anyopaque) ctypes.CommitIndex {
        const s: *LogSink = @ptrCast(@alignCast(ctx));
        return @intCast(s.processed.load(.acquire));
    }
};

// ------------------------------------------------------------------ signals

var stop_flag: std.atomic.Value(bool) = .init(false);

fn onSignal(_: std.posix.SIG) callconv(.c) void {
    stop_flag.store(true, .release);
}

fn monoMs(io: Io) u64 {
    return @intCast(@divTrunc(Io.Clock.awake.now(io).toNanoseconds(), std.time.ns_per_ms));
}

// ------------------------------------------------------------------ the command

pub fn run(gpa: std.mem.Allocator, io: Io, args: []const []const u8) u8 {
    return runInner(gpa, io, args) catch |e| {
        std.debug.print("deepwave-validator seat: {s}\n", .{@errorName(e)});
        return switch (e) {
            error.Refused, error.NotAMember => 1,
            else => 2,
        };
    };
}

fn runInner(gpa: std.mem.Allocator, io: Io, args: []const []const u8) Error!u8 {
    var config_path: ?[]const u8 = null;
    var genesis_path: ?[]const u8 = null;
    var db_opt: ?[]const u8 = null;
    var commits_opt: ?[]const u8 = null;
    var duration_s: u64 = 0;
    var dry_run = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--dry-run")) {
            dry_run = true;
            continue;
        }
        if (i + 1 >= args.len) {
            std.debug.print("{s}", .{usage});
            return error.BadArguments;
        }
        i += 1;
        const v = args[i];
        if (std.mem.eql(u8, a, "--config")) config_path = v else if (std.mem.eql(u8, a, "--genesis")) genesis_path = v else if (std.mem.eql(u8, a, "--db")) db_opt = v else if (std.mem.eql(u8, a, "--commits")) commits_opt = v else if (std.mem.eql(u8, a, "--duration-s")) {
            duration_s = std.fmt.parseInt(u64, v, 10) catch return error.BadArguments;
        } else {
            std.debug.print("{s}", .{usage});
            return error.BadArguments;
        }
    }
    const cfg_path = config_path orelse {
        std.debug.print("{s}", .{usage});
        return error.BadArguments;
    };

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var loaded = keys.config.load(gpa, io, cfg_path) catch return error.BadConfig;
    defer loaded.deinit();
    const c = &loaded.cfg;
    for (c.unknown_keys) |k| std.debug.print("deepwave-validator seat: note: validator.yaml key {s} is not used here\n", .{k});
    const gpath = genesis_path orelse c.genesis_path orelse return error.BadConfig;
    const blob = (keys.fsutil.readAll(gpa, io, gpath, 256 << 20) catch return error.Io) orelse return error.BadConfig;
    defer gpa.free(blob);
    const g = try readGenesis(arena, blob);

    // the gate: chain id and every address of the genesis committee and of this yaml
    var addrs: std.ArrayList([]const u8) = .empty;
    for (g.validators) |v| {
        try appendAddr(arena, &addrs, v.primary_address);
        try appendAddr(arena, &addrs, v.net_address);
        try appendAddr(arena, &addrs, v.p2p_address);
    }
    for (c.addresses(arena) catch return error.OutOfMemory) |a| try appendAddr(arena, &addrs, a);
    const lic = switch (gate.decide(.{ .chain_id = &g.chain_id, .addresses = addrs.items, .key_source = .localnet_config })) {
        .allowed => |l| l,
        .refused => |r| {
            std.debug.print("deepwave-validator seat: {s}\n", .{r.text()});
            return error.Refused;
        },
    };

    var ks = try loadKeys(gpa, io, c);
    defer ks.wipe();
    var own: ?u32 = null;
    for (g.validators, 0..) |v, idx| {
        if (std.mem.eql(u8, &v.protocol_pubkey, &ks.authority_pk)) own = @intCast(idx);
    }
    const own_index = own orelse return error.NotAMember;
    const me = g.validators[own_index];
    if (!std.mem.eql(u8, &me.worker_pubkey, &ks.worker.public_key.toBytes()) or !std.mem.eql(u8, &me.network_pubkey, &ks.network.public_key.toBytes())) return error.NotAMember;

    // consensus context, as sui-core builds it for epoch 0
    const auths = try arena.alloc(consensus.committee.Authority, g.validators.len);
    for (g.validators, auths) |v, *au| au.* = .{
        .stake = v.voting_power,
        .address = v.primary_address,
        .hostname = v.name,
        .authority_name = &v.protocol_pubkey,
        .protocol_key = v.worker_pubkey,
        .network_key = v.network_pubkey,
    };
    const committee = consensus.Committee.init(g.epoch, auths) catch return error.BadGenesis;
    const pc = consensus.config.ProtocolConfig.fromProtocol(g.protocol_version, .unknown) catch {
        std.debug.print("deepwave-validator seat: protocol version {d} is not supported\n", .{g.protocol_version});
        return error.BadGenesis;
    };
    const db = if (db_opt) |d| d else try std.fmt.allocPrint(arena, "{s}-zui", .{std.mem.trimEnd(u8, c.db_path, "/")});
    const cons_dir = try std.fmt.allocPrint(arena, "{s}/consensus", .{db});
    var clock: consensus_net.testkit.RealClock = .{ .io = io };
    var params: consensus.config.Parameters = .{};
    params.db_path = cons_dir;
    const context = try arena.create(consensus.Context);
    context.* = .{
        .epoch_start_timestamp_ms = g.epoch_start_timestamp_ms,
        .own_index = own_index,
        .committee = committee,
        .parameters = params,
        .protocol_config = pc,
        .clock = clock.clock(),
    };

    std.debug.print("deepwave-validator seat: chain {s}, epoch {d}, protocol {d}, epoch start {d} ms, committee {d}, own index {d} ({s}), gate {s}\n", .{ &g.chain_id, g.epoch, g.protocol_version, g.epoch_start_timestamp_ms, g.validators.len, own_index, me.name, @tagName(lic.mode) });
    for (g.validators, 0..) |v, idx| {
        var hx: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&hx, "{x}", .{v.worker_pubkey}) catch unreachable;
        std.debug.print("  authority {d}: {s} stake {d} consensus {s} protocol key {s}...\n", .{ idx, v.name, v.voting_power, v.primary_address, hx[0..16] });
    }

    if (dry_run) {
        std.debug.print("seat-index {d}\n", .{own_index});
        return 0;
    }
    keys.fsutil.makePath(io, db) catch return error.Io;
    const signer = signer_mod.Signer.open(gpa, io, &lic, db, .{ .localnet_config = ks }) catch |e| {
        std.debug.print("deepwave-validator seat: signer: {s}\n", .{@errorName(e)});
        return if (e == error.Locked) error.Io else error.Refused;
    };
    defer signer.close();

    const commits_path = if (commits_opt) |p| p else try std.fmt.allocPrint(arena, "{s}/commits.log", .{db});
    // The commit log is this consumer's processed watermark, as sui-core's own DB is for Rust:
    // after a restart the core replays only the commits after the last one logged.
    const resume_from = lastLoggedCommit(gpa, io, commits_path);
    const cpz = try std.fmt.allocPrintSentinel(arena, "{s}", .{commits_path}, 0);
    const fd = std.c.open(cpz, .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true, .CLOEXEC = true }, @as(std.c.mode_t, 0o644));
    if (fd < 0) return error.Io;
    defer _ = std.c.close(fd);
    const sink = try gpa.create(LogSink);
    defer gpa.destroy(sink);
    sink.* = .{ .fd = fd, .own_index = own_index };
    sink.processed.store(resume_from, .release);
    if (resume_from != 0) std.debug.print("deepwave-validator seat: resuming after commit {d} (commit log)\n", .{resume_from});

    var net_seed = ks.network.secret_key.seed();
    defer std.crypto.secureZero(u8, &net_seed);
    const auth = consensus_net.authority_node.ConsensusAuthority.start(gpa, io, .{
        .context = context,
        .db_dir = cons_dir,
        .network_key_seed = &net_seed,
        .signer = vnode.blockSigner(signer),
        .tx_verifier = AcceptAll.verifier(),
        .tx_source = NoTransactions.source(),
        .commit_sink = sink.sink(),
    }) catch |e| {
        std.debug.print("deepwave-validator seat: consensus start: {s}\n", .{@errorName(e)});
        return error.Startup;
    };

    const act: std.posix.Sigaction = .{ .handler = .{ .handler = onSignal }, .mask = std.posix.sigemptyset(), .flags = std.posix.SA.RESTART };
    std.posix.sigaction(.INT, &act, null);
    std.posix.sigaction(.TERM, &act, null);
    const t0 = monoMs(io);
    var last_report: u64 = t0;
    while (!stop_flag.load(.acquire)) {
        var ts: std.c.timespec = .{ .sec = 0, .nsec = 200 * std.time.ns_per_ms };
        _ = std.c.nanosleep(&ts, &ts);
        const now = monoMs(io);
        if (now - last_report >= 5000) {
            last_report = now;
            report(auth, sink, now - t0);
        }
        if (duration_s != 0 and now - t0 >= duration_s * 1000) break;
    }
    report(auth, sink, monoMs(io) - t0);
    auth.stop();
    std.debug.print("deepwave-validator seat: stopped\n", .{});
    return 0;
}

/// Index of the last `FULL index=N` line of the commit log (0 when there is none).
fn lastLoggedCommit(gpa: std.mem.Allocator, io: Io, path: []const u8) u64 {
    const text = (keys.fsutil.readAll(gpa, io, path, 1 << 30) catch return 0) orelse return 0;
    defer gpa.free(text);
    var last: u64 = 0;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        const pre = "FULL index=";
        if (!std.mem.startsWith(u8, line, pre)) continue;
        const rest = line[pre.len..];
        const end = std.mem.indexOfScalar(u8, rest, ' ') orelse continue;
        last = @max(last, std.fmt.parseInt(u64, rest[0..end], 10) catch continue);
    }
    return last;
}

fn appendAddr(arena: std.mem.Allocator, list: *std.ArrayList([]const u8), a: []const u8) Error!void {
    if (a.len == 0) return;
    list.append(arena, a) catch return error.OutOfMemory;
}

fn report(auth: *consensus_net.authority_node.ConsensusAuthority, sink: *LogSink, elapsed_ms: u64) void {
    const st = auth.stats();
    std.debug.print("seat t={d}s commits={d} last_commit={d} own_leaders={d} own_blocks_committed={d} proposed_round={d} received={d} invalid={d} fetched={d} synced_batches={d} streamed={d} leaders_by_author=", .{
        elapsed_ms / 1000,
        sink.commits.load(.monotonic),
        sink.processed.load(.monotonic),
        sink.own_leaders.load(.monotonic),
        sink.own_blocks_committed.load(.monotonic),
        auth.lastProposedRound(),
        st.blocks_received.load(.monotonic),
        st.blocks_invalid.load(.monotonic),
        st.blocks_fetched.load(.monotonic),
        st.commit_batches_synced.load(.monotonic),
        st.blocks_streamed.load(.monotonic),
    });
    for (sink.leaders_by_author[0..8], 0..) |*x, k| std.debug.print("{s}{d}", .{ if (k == 0) "" else ",", x.load(.monotonic) });
    std.debug.print("\n", .{});
}

test "seat usage names the command" {
    try std.testing.expect(std.mem.indexOf(u8, usage, "deepwave-validator seat") != null);
}
