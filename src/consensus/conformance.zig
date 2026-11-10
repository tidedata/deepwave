//! Conformance suites of the consensus module (val-consensus-core), against vectors Mysten's Rust
//! produces (tools/truth/consensus/).
//!
//! - `consensus-block`: every block line of the vector file decodes, re-encodes to the same bytes
//!   and has the digest the commit lines refer to (BCS of Block/SignedBlock, Blake2b256 digest).
//! - `consensus-replay`: the same blocks, layer by layer, go through deepwave's Core as an observer
//!   (BlockManager, DagState, pipelined UniversalCommitter, Linearizer, leader schedule updates,
//!   CommitFinalizer); every linearized Commit of a step (digest, leader, timestamp, sub-dag block
//!   order) and the final leader swap table equal Rust's; the commits the CommitFinalizer releases
//!   per step and their rejected transactions equal those of Rust's CommitFinalizer; and the
//!   stake-based leader election equals rand 0.8's.
//! - `consensus-verify`: Rust's SignedBlockVerifier verdict (mainnet 141 limits) on signed blocks,
//!   valid and broken, equals deepwave's; accepted blocks re-sign to Rust's signature bytes; genesis
//!   digests of an epoch with a non-zero start time.
//! - `consensus-bcs`: BCS of fixed values (Block V1/V2/V3, SignedBlock with a real signature and its
//!   digest, Commit, BlockRef, CommitRef, MisbehaviorReport, BlockTransactionVotes,
//!   ReputationScores) and the BlockRef sort order.
//! - `consensus-swap`: LeaderSwapTable good/bad nodes (stake cutoffs, tie shuffles) and `swap`.
//!
//! Vectors: `$ZUI_CORPUS/consensus/replay.vec`, written by tools/truth/consensus/committer-vectors/run.sh
//! (format in zui_consensus_vectors.rs). A localnet capture (tools/truth/consensus/capture.sh) adds
//! `consensus-localnet` later (blocks and commits a real Mysten committee stored).
const std = @import("std");
const harness = @import("harness");
const types = @import("types.zig");
const digest_mod = @import("digest.zig");
const test_dag = @import("test_dag.zig");
const core_mod = @import("core.zig");
const leader_schedule = @import("leader_schedule.zig");
const verifier_mod = @import("verifier.zig");
const tracker_mod = @import("transaction_vote_tracker.zig");
const commit_finalizer = @import("commit_finalizer.zig");
const config = @import("config.zig");
const committee_mod = @import("committee.zig");
const bcs = @import("bcs");
const sig = @import("sig");

const Allocator = std.mem.Allocator;
const vector_path = "consensus/replay.vec";

pub const suites = [_]harness.Suite{
    .{ .name = "consensus-block", .lane = "val-consensus-core", .doc = "block lines of the Rust DAG vectors: BCS decode, re-encode and digest", .run = runBlock },
    .{ .name = "consensus-replay", .lane = "val-consensus-core", .doc = "Rust DAG vectors through Core: commits, sub-dag order, leader swap table, stake based election", .run = runReplay },
    .{ .name = "consensus-verify", .lane = "val-consensus-core", .doc = "Rust SignedBlockVerifier verdicts on signed blocks (mainnet 141 limits), genesis digests, block signatures", .run = runVerify },
    .{ .name = "consensus-bcs", .lane = "val-consensus-core", .doc = "BCS bytes of fixed consensus values (blocks V1/V2/V3, signed blocks, digests, commit, refs, votes, scores) and BlockRef order", .run = runBcs },
    .{ .name = "consensus-swap", .lane = "val-consensus-core", .doc = "LeaderSwapTable good/bad nodes and swap choices from Rust", .run = runSwap },
};

fn unhex(a: Allocator, s: []const u8) ![]u8 {
    const out = try a.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

fn hex32(s: []const u8) ![32]u8 {
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, s);
    return out;
}

fn loadVectors(ctx: *harness.Ctx) ?[]u8 {
    return ctx.readFile(vector_path, 1 << 31) catch |e| {
        ctx.skip(vector_path, @errorName(e));
        return null;
    };
}

fn runBlock(ctx: *harness.Ctx) anyerror!void {
    const text = loadVectors(ctx) orelse return;
    var scenario: []const u8 = "";
    var idx: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (ctx.done()) break;
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = it.next() orelse continue;
        if (std.mem.eql(u8, kind, "scenario")) {
            scenario = it.next() orelse "";
            idx = 0;
        } else if (std.mem.eql(u8, kind, "block")) {
            idx += 1;
            var name_buf: [96]u8 = undefined;
            const name = std.fmt.bufPrint(&name_buf, "{s}/block{d}", .{ scenario, idx }) catch "block";
            if (!ctx.selected(name)) continue;
            ctx.nextItem();
            const a = ctx.scratch();
            const bytes = unhex(a, it.next() orelse "") catch {
                ctx.fail(name, "bad hex", .{});
                continue;
            };
            const sb = digest_mod.decodeSignedBlock(a, bytes) catch |e| {
                ctx.fail(name, "decode failed: {s}", .{@errorName(e)});
                continue;
            };
            const re = digest_mod.serializeSignedBlock(a, &sb) catch {
                ctx.fail(name, "re-encode failed", .{});
                continue;
            };
            _ = ctx.expectBytes(name, "re-encoded block", bytes, re);
        }
    }
}

const Ev = struct {
    gpa: Allocator,
    ctx: *harness.Ctx,
    name: []const u8,
    fx: *test_dag.Fixture,
    noop: verifier_mod.NoopTransactionVerifier = .{},
    tracker: tracker_mod.TransactionVoteTracker,
    fin: commit_finalizer.CommitFinalizer,
    core: core_mod.Core,
};

fn runReplay(ctx: *harness.Ctx) anyerror!void {
    const text = loadVectors(ctx) orelse return;
    const gpa = ctx.gpa;
    var lines = std.mem.splitScalar(u8, text, '\n');

    var ev: ?*Ev = null;
    defer if (ev) |e| teardown(gpa, e);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var pending: std.ArrayList(types.VerifiedBlock) = .empty;
    var expected: std.ArrayList([]const u8) = .empty; // commit lines of the current step
    var step_no: usize = 0;
    var n_genesis: usize = 0;
    var genesis_expected: std.ArrayList([32]u8) = .empty;
    var skip_scenario = false;
    var lin_refs: std.ArrayList(types.CommitRef) = .empty;
    var finalized: usize = 0;
    var finalized_bad: usize = 0;

    while (lines.next()) |line| {
        if (ctx.done()) break;
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = it.next() orelse continue;

        if (std.mem.eql(u8, kind, "scenario")) {
            if (ev) |e| teardown(gpa, e);
            ev = null;
            _ = arena_state.reset(.retain_capacity);
            pending = .empty;
            expected = .empty;
            genesis_expected = .empty;
            lin_refs = .empty;
            finalized = 0;
            finalized_bad = 0;
            step_no = 0;
            n_genesis = 0;
            const name = try arena.dupe(u8, it.next() orelse "");
            skip_scenario = !ctx.selected(name);
            if (skip_scenario) continue;
            const n = try std.fmt.parseInt(usize, it.next().?, 10);
            const gc_depth = try std.fmt.parseInt(u32, it.next().?, 10);
            const shuffle = (try std.fmt.parseInt(u8, it.next().?, 10)) != 0;
            const leaders = try std.fmt.parseInt(usize, it.next().?, 10);
            const stakes = try parseStakes(arena, it.next(), n);
            const e = try gpa.create(Ev);
            e.* = undefined;
            e.gpa = gpa;
            e.ctx = ctx;
            e.name = name;
            e.fx = try test_dag.Fixture.init(gpa, .{
                .stakes = stakes,
                .own_index = null,
                .mode = .round_robin_test,
                .protocol = .{ .gc_depth = gc_depth, .transaction_voting_enabled = true, .num_leaders_per_round = leaders, .bad_nodes_stake_threshold = 30, .shuffle_commit_blocks = shuffle },
                .parameters = .{ .skip_equivocation_validation = true },
            });
            e.noop = .{};
            e.tracker = tracker_mod.TransactionVoteTracker.init(gpa, e.fx.context, e.fx.dag, e.noop.verifier());
            e.fin = commit_finalizer.CommitFinalizer.init(gpa, e.fx.context, e.fx.dag, &e.tracker);
            var out: core_mod.Output = .{};
            e.core = try core_mod.Core.recover(gpa, arena, .{
                .context = e.fx.context,
                .dag = e.fx.dag,
                .schedule = e.fx.schedule,
                .tracker = &e.tracker,
                .finalizer = &e.fin,
            }, &out);
            ev = e;
        } else if (skip_scenario or ev == null) {
            continue;
        } else if (std.mem.eql(u8, kind, "genesis")) {
            try genesis_expected.append(arena, try hex32(it.next().?));
            n_genesis += 1;
            if (n_genesis == ev.?.fx.dag.genesis.len) {
                var nb: [96]u8 = undefined;
                const item = std.fmt.bufPrint(&nb, "{s}/genesis", .{ev.?.name}) catch "genesis";
                ctx.nextItem();
                var c = ctx.check(item);
                for (ev.?.fx.dag.genesis, genesis_expected.items) |g, want| c.bytes("genesis block digest", &want, &g.digest);
                _ = c.finish();
            }
        } else if (std.mem.eql(u8, kind, "block")) {
            const bytes = try unhex(arena, it.next().?);
            const vb = try digest_mod.decodeVerifiedUnchecked(arena, bytes);
            try pending.append(arena, vb);
        } else if (std.mem.eql(u8, kind, "step")) {
            step_no += 1;
            expected = .empty;
            const e = ev.?;
            for (pending.items) |*b| try e.tracker.addVotedBlock(b, &.{});
            var scratch = std.heap.ArenaAllocator.init(gpa);
            defer scratch.deinit();
            var out: core_mod.Output = .{ .record_linearized = true };
            try e.core.addBlocks(scratch.allocator(), pending.items, &out);
            pending = .empty;
            // Rust's lines are the Linearizer's sub-dags of this step (CommitObserver input);
            // compare those. Finalized output may trail them (transactions wait for votes), so it
            // is checked against the linearized refs by index.
            const got = out.linearized.items;
            for (got) |*sd| try lin_refs.append(arena, sd.commit_ref);
            defer for (out.committed.items) |*f| f.deinit();
            for (out.committed.items) |*f| {
                const ref = f.sub_dag.commit_ref;
                finalized += 1;
                if (ref.index != finalized or ref.index > lin_refs.items.len or !std.mem.eql(u8, &lin_refs.items[ref.index - 1].digest, &ref.digest)) finalized_bad += 1;
            }
            const fin = out.committed.items;
            // The commit lines follow immediately; collect them, then compare.
            var k: usize = 0;
            while (lines.peek()) |peek| {
                var pit = std.mem.tokenizeScalar(u8, peek, ' ');
                const pk = pit.next() orelse {
                    _ = lines.next();
                    continue;
                };
                if (!std.mem.eql(u8, pk, "commit")) break;
                _ = lines.next();
                try compareCommit(ctx, e, peek, if (k < got.len) &got[k] else null);
                k += 1;
            }
            if (k != got.len) {
                var nb: [96]u8 = undefined;
                const item = std.fmt.bufPrint(&nb, "{s}/step{d}/count", .{ e.name, step_no }) catch "count";
                ctx.nextItem();
                ctx.fail(item, "expected {d} commits, got {d}", .{ k, got.len });
            }
            // Then the commits Rust's CommitFinalizer released in this step, with their rejected
            // transactions.
            var kf: usize = 0;
            while (lines.peek()) |peek| {
                var pit = std.mem.tokenizeScalar(u8, peek, ' ');
                const pk = pit.next() orelse {
                    _ = lines.next();
                    continue;
                };
                if (!std.mem.eql(u8, pk, "final")) break;
                _ = lines.next();
                try compareFinal(ctx, e, peek, if (kf < fin.len) &fin[kf].sub_dag else null);
                kf += 1;
            }
            if (kf != fin.len) {
                var nb: [96]u8 = undefined;
                const item = std.fmt.bufPrint(&nb, "{s}/step{d}/final-count", .{ e.name, step_no }) catch "count";
                ctx.nextItem();
                ctx.fail(item, "expected {d} finalized commits, got {d}", .{ kf, fin.len });
            }
        } else if (std.mem.eql(u8, kind, "swap")) {
            try compareSwap(ctx, ev.?, &it);
        } else if (std.mem.eql(u8, kind, "end")) {
            var nb: [96]u8 = undefined;
            const item = std.fmt.bufPrint(&nb, "{s}/finalized", .{ev.?.name}) catch "finalized";
            ctx.nextItem();
            var c = ctx.check(item);
            c.eql("finalized commits out of order or not equal to the linearized ones", @as(usize, 0), finalized_bad);
            c.eql("finalized commits beyond the linearized ones", true, finalized <= lin_refs.items.len);
            _ = c.finish();
            teardown(gpa, ev.?);
            ev = null;
        }
    }
    // Stake-based election lines come after the scenarios.
    try runElect(ctx, text);
}

fn teardown(gpa: Allocator, e: *Ev) void {
    e.core.deinit();
    e.fin.deinit();
    e.tracker.deinit();
    e.fx.deinit();
    gpa.destroy(e);
}

fn compareCommit(ctx: *harness.Ctx, e: *Ev, line: []const u8, got: ?*const types.CommittedSubDag) !void {
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    _ = it.next();
    const index = try std.fmt.parseInt(u32, it.next().?, 10);
    const digest = try hex32(it.next().?);
    const lr = try std.fmt.parseInt(u32, it.next().?, 10);
    const la = try std.fmt.parseInt(u32, it.next().?, 10);
    const ts = try std.fmt.parseInt(u64, it.next().?, 10);
    const nb = try std.fmt.parseInt(usize, it.next().?, 10);
    var nbuf: [96]u8 = undefined;
    const item = std.fmt.bufPrint(&nbuf, "{s}/commit{d}", .{ e.name, index }) catch "commit";
    ctx.nextItem();
    var c = ctx.check(item);
    if (got) |g| {
        c.eql("commit index", index, g.commit_ref.index);
        c.bytes("commit digest", &digest, &g.commit_ref.digest);
        c.eql("leader round", lr, g.leader.round);
        c.eql("leader author", la, g.leader.author);
        c.eql("timestamp", ts, g.timestamp_ms);
        c.eql("sub-dag block count", nb, g.blocks.len);
        var k: usize = 0;
        while (it.next()) |h| : (k += 1) {
            const want = try hex32(h);
            if (k >= g.blocks.len) break;
            c.bytes("sub-dag block digest", &want, &g.blocks[k].digest);
        }
    } else c.eql("commit present", true, false);
    _ = c.finish();
}

fn compareFinal(ctx: *harness.Ctx, e: *Ev, line: []const u8, got: ?*const types.CommittedSubDag) !void {
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    _ = it.next();
    const index = try std.fmt.parseInt(u32, it.next().?, 10);
    const digest = try hex32(it.next().?);
    var nbuf: [96]u8 = undefined;
    const item = std.fmt.bufPrint(&nbuf, "{s}/final{d}", .{ e.name, index }) catch "final";
    ctx.nextItem();
    const a = ctx.scratch();
    var c = ctx.check(item);
    if (got) |g| {
        c.eql("finalized commit index", index, g.commit_ref.index);
        c.bytes("finalized commit digest", &digest, &g.commit_ref.digest);
        var k: usize = 0;
        while (it.next()) |tok| : (k += 1) {
            const colon = std.mem.indexOfScalar(u8, tok, ':') orelse return error.BadVector;
            const ref = try bcs.decode(types.BlockRef, a, try unhex(a, tok[0..colon]));
            const idx = try parseCsv(a, tok[colon + 1 ..], u16);
            if (k >= g.rejected_transactions_by_block.len) {
                c.failf("rejected block {d} missing", .{k});
                break;
            }
            const r = g.rejected_transactions_by_block[k];
            c.eql("rejected block ref", true, ref.eql(r.block));
            c.bytes("rejected indices", std.mem.sliceAsBytes(idx), std.mem.sliceAsBytes(r.indices));
        }
        c.eql("blocks with rejected transactions", k, g.rejected_transactions_by_block.len);
    } else c.eql("finalized commit present", true, false);
    _ = c.finish();
}

fn parseCsv(a: Allocator, s: []const u8, comptime T: type) ![]T {
    var out: std.ArrayList(T) = .empty;
    if (s.len == 0) return out.items;
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |p| try out.append(a, try std.fmt.parseInt(T, p, 10));
    return out.items;
}

fn compareSwap(ctx: *harness.Ctx, e: *Ev, it: *std.mem.TokenIterator(u8, .scalar)) !void {
    const a = ctx.scratch();
    ctx.nextItem();
    const start = try std.fmt.parseInt(u32, it.next().?, 10);
    const end_ex = try std.fmt.parseInt(u32, it.next().?, 10);
    var good: []u32 = &.{};
    var bad: []u32 = &.{};
    var scores: []u64 = &.{};
    while (it.next()) |tok| {
        const eq = std.mem.indexOfScalar(u8, tok, '=') orelse continue;
        const key = tok[0..eq];
        const val = tok[eq + 1 ..];
        if (std.mem.eql(u8, key, "good")) good = try parseCsv(a, val, u32);
        if (std.mem.eql(u8, key, "bad")) bad = try parseCsv(a, val, u32);
        if (std.mem.eql(u8, key, "scores")) scores = try parseCsv(a, val, u64);
    }
    var nb: [96]u8 = undefined;
    const item = std.fmt.bufPrint(&nb, "{s}/swap-table", .{e.name}) catch "swap";
    var c = ctx.check(item);
    const t = &e.fx.schedule.swap_table;
    const r = t.reputation_scores.commit_range;
    c.eql("range start", start, r.start);
    c.eql("range end", end_ex, r.end_exclusive);
    c.bytes("good nodes", std.mem.sliceAsBytes(good), std.mem.sliceAsBytes(t.good_nodes));
    c.bytes("bad nodes", std.mem.sliceAsBytes(bad), std.mem.sliceAsBytes(t.bad_nodes));
    c.bytes("scores", std.mem.sliceAsBytes(scores), std.mem.sliceAsBytes(t.reputation_scores.scores_per_authority));
    _ = c.finish();
}

/// Optional stakes CSV of a scenario or elect line; absent means equal stakes of 1.
fn parseStakes(a: Allocator, csv: ?[]const u8, n: usize) ![]u64 {
    const out = try a.alloc(u64, n);
    const text = csv orelse {
        @memset(out, 1);
        return out;
    };
    var parts = std.mem.splitScalar(u8, text, ',');
    var i: usize = 0;
    while (parts.next()) |p| : (i += 1) {
        if (i >= n) return error.BadStakes;
        out[i] = try std.fmt.parseInt(u64, p, 10);
    }
    if (i != n) return error.BadStakes;
    return out;
}

fn runElect(ctx: *harness.Ctx, text: []const u8) !void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var cached_n: usize = 0;
    var cached_stakes: []u64 = try ctx.gpa.alloc(u64, 0);
    var fx: ?*test_dag.Fixture = null;
    defer {
        if (fx) |f| f.deinit();
        ctx.gpa.free(cached_stakes);
    }
    while (lines.next()) |line| {
        if (ctx.done()) break;
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = it.next() orelse continue;
        if (!std.mem.eql(u8, kind, "elect")) continue;
        const n = try std.fmt.parseInt(usize, it.next().?, 10);
        const round = try std.fmt.parseInt(u32, it.next().?, 10);
        const offset = try std.fmt.parseInt(u32, it.next().?, 10);
        const want = try std.fmt.parseInt(u32, it.next().?, 10);
        const stakes = try parseStakes(ctx.scratch(), it.next(), n);
        if (fx == null or cached_n != n or !std.mem.eql(u64, cached_stakes, stakes)) {
            if (fx) |f| f.deinit();
            fx = null;
            ctx.gpa.free(cached_stakes);
            cached_stakes = try ctx.gpa.dupe(u64, stakes);
            fx = try test_dag.Fixture.init(ctx.gpa, .{ .stakes = cached_stakes, .mode = .stake_based });
            cached_n = n;
        }
        var nb: [64]u8 = undefined;
        const item = std.fmt.bufPrint(&nb, "elect/n{d}/r{d}/o{d}/s{x}", .{ n, round, offset, std.hash.Wyhash.hash(0, std.mem.sliceAsBytes(stakes)) & 0xffff }) catch "elect";
        if (!ctx.selected(item)) continue;
        ctx.nextItem();
        const got = try fx.?.schedule.electLeaderStakeBased(round, offset);
        var c = ctx.check(item);
        c.eql("elected authority", want, got);
        _ = c.finish();
    }
}

// ---------------------------------------------------------------- consensus-verify

/// Rust ConsensusError variant name (as the vector writes it) of a deepwave verdict.
fn rustVerdictName(v: @import("error.zig").BlockVerdict) []const u8 {
    return switch (v) {
        .ok => "ok",
        .reject => |r| switch (r) {
            .wrong_epoch => "WrongEpoch",
            .genesis_block => "UnexpectedGenesisBlock",
            .invalid_authority_index => "InvalidAuthorityIndex",
            .malformed_signature => "MalformedSignature",
            .signature_verification_failure => "SignatureVerificationFailure",
            .too_many_ancestors => "TooManyAncestors",
            .insufficient_parent_stake => "InsufficientParentStakes",
            .invalid_ancestor_position => "InvalidAncestorPosition",
            .invalid_ancestor_round => "InvalidAncestorRound",
            .duplicated_ancestors_authority => "DuplicatedAncestorsAuthority",
            .invalid_genesis_ancestor => "InvalidGenesisAncestor",
            .transaction_too_large => "TransactionTooLarge",
            .too_many_transactions => "TooManyTransactions",
            .too_many_transaction_bytes => "TooManyTransactionBytes",
            .invalid_transaction => "InvalidTransaction",
            .invalid_transaction_votes => "InvalidTransactionVotes",
            .too_many_commit_votes => "TooManyCommitVotes",
            .invalid_misbehavior_report => "InvalidMisbehaviorReport",
            .malformed_block => "malformed",
            .unexpected_block_version => "UnexpectedBlockVersion",
            .invalid_transaction_votes_cutoff => "InvalidTransactionVotesCutoff",
        },
    };
}

fn seedOf(i: usize) [32]u8 {
    return @splat(@intCast(i + 1));
}

fn runVerify(ctx: *harness.Ctx) anyerror!void {
    const text = loadVectors(ctx) orelse return;
    const gpa = ctx.gpa;
    var fx: ?*test_dag.Fixture = null;
    defer if (fx) |f| f.deinit();
    var stakes_buf: std.ArrayList(u64) = .empty;
    defer stakes_buf.deinit(gpa);
    var gen_idx: usize = 0;
    var noop: verifier_mod.NoopTransactionVerifier = .{};
    const votes = try gpa.alloc(types.TransactionIndex, 4096);
    defer gpa.free(votes);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (ctx.done()) break;
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = it.next() orelse continue;
        if (std.mem.eql(u8, kind, "vcommittee")) {
            const epoch = try std.fmt.parseInt(u64, it.next().?, 10);
            const start_ms = try std.fmt.parseInt(u64, it.next().?, 10);
            stakes_buf.clearRetainingCapacity();
            var parts = std.mem.splitScalar(u8, it.next().?, ',');
            while (parts.next()) |p| try stakes_buf.append(gpa, try std.fmt.parseInt(u64, p, 10));
            if (fx) |f| f.deinit();
            // The mainnet 141 consensus config, through deepwave's protocol tables.
            const pc = try config.ProtocolConfig.fromProtocol(141, .mainnet);
            fx = try test_dag.Fixture.init(gpa, .{ .stakes = stakes_buf.items, .epoch = epoch, .epoch_start_ms = start_ms, .protocol = pc, .own_index = null });
            for (fx.?.authorities, 0..) |*a, i| {
                const seed = seedOf(i);
                a.protocol_key = sig.ed25519.KeyPair.fromSeed(&seed).pk;
            }
            gen_idx = 0;
        } else if (std.mem.eql(u8, kind, "vgenesis")) {
            const f = fx orelse continue;
            const want = try hex32(it.next().?);
            ctx.nextItem();
            var nb: [64]u8 = undefined;
            const item = std.fmt.bufPrint(&nb, "verify/genesis{d}", .{gen_idx}) catch "genesis";
            var c = ctx.check(item);
            if (gen_idx < f.dag.genesis.len) c.bytes("genesis digest", &want, &f.dag.genesis[gen_idx].digest) else c.failf("more genesis lines than authorities", .{});
            _ = c.finish();
            gen_idx += 1;
        } else if (std.mem.eql(u8, kind, "verify")) {
            const f = fx orelse continue;
            const name = it.next().?;
            const want = it.next().?;
            var nb: [96]u8 = undefined;
            const item = std.fmt.bufPrint(&nb, "verify/{s}", .{name}) catch "verify";
            if (!ctx.selected(item)) continue;
            ctx.nextItem();
            const a = ctx.scratch();
            const bytes = try unhex(a, it.next().?);
            const v = verifier_mod.SignedBlockVerifier.init(f.context, noop.verifier(), f.genesisRefs());
            var out: types.VerifiedBlock = undefined;
            var nv: usize = 0;
            const verdict = try v.verifyAndVote(a, bytes, &out, votes, &nv);
            var c = ctx.check(item);
            c.text("verdict", want, rustVerdictName(verdict));
            if (verdict == .ok) {
                c.bytes("digest", &digest_mod.blockDigest(bytes), &out.digest);
                // Deterministic Ed25519: re-signing the signing message must give Rust's signature.
                const author = out.block.inner.author();
                const msg = try digest_mod.blockSigningMessage(a, &out.block.inner);
                const seed = seedOf(author);
                const s2 = sig.ed25519.sign(&seed, &msg);
                c.bytes("signature", out.block.signature, &s2);
                const re = try digest_mod.serializeSignedBlock(a, &out.block);
                c.bytes("re-encoded block", bytes, re);
            }
            _ = c.finish();
        }
    }
}

// ---------------------------------------------------------------- consensus-bcs

fn runBcs(ctx: *harness.Ctx) anyerror!void {
    const text = loadVectors(ctx) orelse return;
    const br: types.BlockRef = .{ .round = 0x0102_0304, .author = 5, .digest = @splat(0xab) };
    const cr: types.CommitRef = .{ .index = 0x0a0b_0c0d, .digest = @splat(0xcd) };
    const mr: types.MisbehaviorReport = .{ .target = 3, .proof = .{ .InvalidBlock = br } };
    const tv: types.BlockTransactionVotes = .{ .block_ref = br, .rejects = &.{ 0, 7, 300 } };
    const commit_blocks = [_]types.BlockRef{ .{ .round = 7, .author = 1, .digest = @splat(1) }, .{ .round = 8, .author = 0, .digest = @splat(2) }, br };
    const commit: types.Commit = .{ .V1 = .{ .index = 42, .previous_digest = @splat(0x11), .timestamp_ms = 1_700_000_000_999, .leader = br, .blocks = &commit_blocks } };
    const anc = [_]types.BlockRef{ br, .{ .round = 9, .author = 2, .digest = @splat(3) } };
    const txs = [_]types.Transaction{ .{ .data = "" }, .{ .data = &.{ 1, 2, 3 } } };
    const cvotes = [_]types.CommitVote{cr};
    const tvs = [_]types.BlockTransactionVotes{tv};
    const mrs = [_]types.MisbehaviorReport{mr};
    const b1: types.Block = .{ .V1 = .{ .epoch = 3, .round = 10, .author = 5, .timestamp_ms = 99, .ancestors = &anc, .transactions = &txs, .commit_votes = &cvotes, .misbehavior_reports = &mrs } };
    const b2: types.Block = .{ .V2 = .{ .epoch = 3, .round = 10, .author = 5, .timestamp_ms = 99, .ancestors = &anc, .transactions = &txs, .transaction_votes = &tvs, .commit_votes = &cvotes, .misbehavior_reports = &.{} } };
    const b3: types.Block = .{ .V3 = .{ .epoch = 3, .round = 10, .author = 5, .timestamp_ms = 99, .ancestors = &anc, .transactions = &txs, .transaction_votes = &tvs, .transaction_votes_cutoff_round = 4, .commit_votes = &cvotes, .misbehavior_reports = &.{} } };
    const scores: types.ReputationScores = .{ .scores_per_authority = &.{ 5, 0, std.math.maxInt(u64) }, .commit_range = types.CommitRange.inclusive(301, 600) };
    const sign_seed = seedOf(5);

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (ctx.done()) break;
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = it.next() orelse continue;
        if (std.mem.eql(u8, kind, "order")) {
            ctx.nextItem();
            const a = ctx.scratch();
            var refs: std.ArrayList(types.BlockRef) = .empty;
            while (it.next()) |h| try refs.append(a, try bcs.decode(types.BlockRef, a, try unhex(a, h)));
            const sorted = try a.dupe(types.BlockRef, refs.items);
            std.mem.reverse(types.BlockRef, sorted);
            std.sort.block(types.BlockRef, sorted, {}, struct {
                fn lt(_: void, x: types.BlockRef, y: types.BlockRef) bool {
                    return x.order(y) == .lt;
                }
            }.lt);
            var c = ctx.check("bcs/blockref-order");
            c.eql("ref count", @as(usize, 64), refs.items.len);
            c.bytes("BlockRef order", std.mem.sliceAsBytes(refs.items), std.mem.sliceAsBytes(sorted));
            _ = c.finish();
            continue;
        }
        if (!std.mem.eql(u8, kind, "bcs")) continue;
        const what = it.next().?;
        var nb: [64]u8 = undefined;
        const item = std.fmt.bufPrint(&nb, "bcs/{s}", .{what}) catch "bcs";
        if (!ctx.selected(item)) continue;
        ctx.nextItem();
        const a = ctx.scratch();
        const want = try unhex(a, it.next().?);
        const got: []const u8 = blk: {
            if (std.mem.eql(u8, what, "blockref")) break :blk try bcs.encodeAlloc(types.BlockRef, a, &br);
            if (std.mem.eql(u8, what, "commitref")) break :blk try bcs.encodeAlloc(types.CommitRef, a, &cr);
            if (std.mem.eql(u8, what, "misbehavior")) break :blk try bcs.encodeAlloc(types.MisbehaviorReport, a, &mr);
            if (std.mem.eql(u8, what, "txvotes")) break :blk try bcs.encodeAlloc(types.BlockTransactionVotes, a, &tv);
            if (std.mem.eql(u8, what, "commit")) break :blk try bcs.encodeAlloc(types.Commit, a, &commit);
            if (std.mem.eql(u8, what, "scores")) break :blk try bcs.encodeAlloc(types.ReputationScores, a, &scores);
            const kinds = [_][]const u8{ "blockv1", "blockv2", "blockv3" };
            const blocks = [_]*const types.Block{ &b1, &b2, &b3 };
            for (kinds, blocks) |k, b| {
                if (std.mem.eql(u8, what, k)) break :blk try bcs.encodeAlloc(types.Block, a, b);
                const signed = std.mem.startsWith(u8, what, "signed-") and std.mem.eql(u8, what[7..], k);
                const dig = std.mem.startsWith(u8, what, "digest-") and std.mem.eql(u8, what[7..], k);
                if (signed or dig) {
                    const msg = try digest_mod.blockSigningMessage(a, b);
                    const s2 = try a.dupe(u8, &sig.ed25519.sign(&sign_seed, &msg));
                    const ser = try digest_mod.serializeSignedBlock(a, &.{ .inner = b.*, .signature = s2 });
                    if (signed) break :blk ser;
                    break :blk try a.dupe(u8, &digest_mod.blockDigest(ser));
                }
            }
            ctx.fail(item, "unknown bcs kind", .{});
            continue;
        };
        _ = ctx.expectBytes(item, what, want, got);
    }
}

// ---------------------------------------------------------------- consensus-swap

fn runSwap(ctx: *harness.Ctx) anyerror!void {
    const text = loadVectors(ctx) orelse return;
    const gpa = ctx.gpa;
    var table: leader_schedule.LeaderSwapTable = .{};
    defer table.deinit(gpa);
    var auths: std.ArrayList(committee_mod.Authority) = .empty;
    defer auths.deinit(gpa);
    var committee: ?committee_mod.Committee = null;
    var case_no: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (ctx.done()) break;
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = it.next() orelse continue;
        if (std.mem.eql(u8, kind, "swaptable")) {
            case_no += 1;
            ctx.nextItem();
            const a = ctx.scratch();
            const commit_index = try std.fmt.parseInt(u32, it.next().?, 10);
            const threshold = try std.fmt.parseInt(u64, it.next().?, 10);
            var stakes: []u64 = &.{};
            var scores: []u64 = &.{};
            var good: []u32 = &.{};
            var bad: []u32 = &.{};
            while (it.next()) |tok| {
                const eq = std.mem.indexOfScalar(u8, tok, '=') orelse continue;
                const key = tok[0..eq];
                const val = tok[eq + 1 ..];
                if (std.mem.eql(u8, key, "stakes")) stakes = try parseCsv(a, val, u64);
                if (std.mem.eql(u8, key, "scores")) scores = try parseCsv(a, val, u64);
                if (std.mem.eql(u8, key, "good")) good = try parseCsv(a, val, u32);
                if (std.mem.eql(u8, key, "bad")) bad = try parseCsv(a, val, u32);
            }
            auths.clearRetainingCapacity();
            for (stakes) |st| try auths.append(gpa, .{ .stake = st, .address = "", .hostname = "", .authority_name = "", .protocol_key = @splat(0), .network_key = @splat(0) });
            committee = try committee_mod.Committee.init(0, auths.items);
            table.deinit(gpa);
            const range = types.CommitRange.inclusive(commit_index -| 299, commit_index);
            table = try leader_schedule.LeaderSwapTable.init(gpa, &committee.?, threshold, commit_index, .{ .scores_per_authority = scores, .commit_range = range });
            var nb: [64]u8 = undefined;
            const item = std.fmt.bufPrint(&nb, "swap/case{d}/table", .{case_no}) catch "swap";
            var c = ctx.check(item);
            c.bytes("good nodes", std.mem.sliceAsBytes(good), std.mem.sliceAsBytes(table.good_nodes));
            c.bytes("bad nodes", std.mem.sliceAsBytes(bad), std.mem.sliceAsBytes(table.bad_nodes));
            _ = c.finish();
        } else if (std.mem.eql(u8, kind, "swapsel")) {
            if (committee == null) continue;
            const leader = try std.fmt.parseInt(u32, it.next().?, 10);
            const round = try std.fmt.parseInt(u32, it.next().?, 10);
            const want_s = it.next().?;
            const want: ?u32 = if (std.mem.eql(u8, want_s, "-")) null else try std.fmt.parseInt(u32, want_s, 10);
            var nb: [64]u8 = undefined;
            const item = std.fmt.bufPrint(&nb, "swap/case{d}/l{d}/r{d}", .{ case_no, leader, round }) catch "swapsel";
            if (!ctx.selected(item)) continue;
            ctx.nextItem();
            // Rust panics on a bad leader without good nodes; the vector writes "-" for it.
            const got: ?u32 = table.swap(leader, round, 0) catch |e| switch (e) {
                error.Invariant => if (table.good_nodes.len == 0) null else return e,
                else => return e,
            };
            var c = ctx.check(item);
            c.eql("swapped leader", want, got);
            _ = c.finish();
        }
    }
}

// ---------------------------------------------------------------- self-check of the suite plumbing

/// Writes a vector file in the Rust tool's format from deepwave's own components (a reference loop that
/// mirrors `Harness::try_commit` in tools/truth/consensus/committer-vectors/zui_consensus_vectors.rs).
/// Used by the unit test below to prove the parser and comparer; real conformance uses Rust's file.
pub fn selfVector(gpa: Allocator, n: usize, rounds: u32) ![]u8 {
    const stakes = try gpa.alloc(u64, n);
    defer gpa.free(stakes);
    @memset(stakes, 1);
    const fx = try test_dag.Fixture.init(gpa, .{
        .stakes = stakes,
        .own_index = null,
        .protocol = .{ .gc_depth = 60, .transaction_voting_enabled = true, .num_leaders_per_round = 1, .bad_nodes_stake_threshold = 30, .shuffle_commit_blocks = true },
        .parameters = .{ .skip_equivocation_validation = true },
    });
    defer fx.deinit();
    var w: std.ArrayList(u8) = .empty;
    errdefer w.deinit(gpa);
    const a = fx.arena();
    try w.print(gpa, "scenario self{d} {d} 60 1 1\n", .{ n, n });
    for (fx.dag.genesis) |g| try w.print(gpa, "genesis {x}\n", .{g.digest});

    const committer = try fx.committer();
    var lin = fx.linearizer();
    var last_decided = fx.dag.lastCommitLeader();
    var prev: []const types.BlockRef = fx.genesisRefs();
    var r: u32 = 1;
    while (r <= rounds) : (r += 1) {
        const layer = try fx.fullLayers(r, r, prev);
        for (layer) |ref| try w.print(gpa, "block {x}\n", .{fx.dag.getBlock(ref).?.serialized});
        prev = layer;
        try w.appendSlice(gpa, "step\n");
        while (true) {
            var until = try fx.schedule.commitsUntilLeaderScheduleUpdate(fx.dag);
            if (until == 0) {
                try fx.schedule.updateLeaderScheduleV2(fx.dag);
                until = try fx.schedule.commitsUntilLeaderScheduleUpdate(fx.dag);
            }
            const d = try committer.tryDecide(a, last_decided);
            const decided = if (d.len >= until) d[0..until] else d;
            if (decided.len == 0) break;
            last_decided = switch (decided[decided.len - 1]) {
                .commit => |c| .{ .round = c.block.block.inner.round(), .authority = c.block.block.inner.author() },
                .skip => |s| s,
            };
            var leaders: std.ArrayList(*const types.VerifiedBlock) = .empty;
            for (decided) |x| switch (x) {
                .commit => |c| try leaders.append(a, c.block),
                .skip => {},
            };
            if (leaders.items.len == 0) break;
            const subs = try lin.handleCommit(a, leaders.items);
            for (subs) |*s| {
                try fx.dag.addScoringSubdag(s);
                try w.print(gpa, "commit {d} {x} {d} {d} {d} {d}", .{ s.commit_ref.index, s.commit_ref.digest, s.leader.round, s.leader.author, s.timestamp_ms, s.blocks.len });
                for (s.blocks) |b| try w.print(gpa, " {x}", .{b.digest});
                try w.append(gpa, '\n');
            }
            // The blocks carry no reject votes, so the finalizer releases each commit directly.
            for (subs) |*s| try w.print(gpa, "final {d} {x}\n", .{ s.commit_ref.index, s.commit_ref.digest });
        }
    }
    const t = &fx.schedule.swap_table;
    const range = t.reputation_scores.commit_range;
    try w.print(gpa, "swap {d} {d} good=", .{ range.start, range.end_exclusive });
    for (t.good_nodes, 0..) |x, i| try w.print(gpa, "{s}{d}", .{ if (i > 0) "," else "", x });
    try w.appendSlice(gpa, " bad=");
    for (t.bad_nodes, 0..) |x, i| try w.print(gpa, "{s}{d}", .{ if (i > 0) "," else "", x });
    try w.appendSlice(gpa, " scores=");
    for (t.reputation_scores.scores_per_authority, 0..) |x, i| try w.print(gpa, "{s}{d}", .{ if (i > 0) "," else "", x });
    try w.appendSlice(gpa, "\nend\n");
    return w.toOwnedSlice(gpa);
}

test "consensus-replay and consensus-block run clean on a vector written by zui itself" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "consensus");
    const text = try selfVector(gpa, 4, 330); // crosses the first leader schedule update (commit 300)
    defer gpa.free(text);
    {
        const f = try tmp.dir.createFile(io, vector_path, .{});
        defer f.close(io);
        try f.writePositionalAll(io, text, 0);
    }
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var out_buf: [4096]u8 = undefined;
    var err_buf: [4096]u8 = undefined;
    var out_w = std.Io.Writer.fixed(&out_buf);
    var err_w = std.Io.Writer.fixed(&err_buf);
    var shared: harness.Shared = .{};
    for (suites[0..2]) |*s| {
        shared = .{};
        var ctx: harness.Ctx = .{
            .gpa = gpa,
            .arena = &arena,
            .io = io,
            .corpus = tmp.dir,
            .corpus_path = "",
            .suite = s,
            .opts = .{},
            .stderr = &err_w,
            .stdout = &out_w,
            .shared = &shared,
        };
        try s.run(&ctx);
        if (ctx.stats.failed != 0 or ctx.stats.skipped != 0) std.debug.print("{s}\n", .{err_buf[0..err_w.end]});
        try std.testing.expectEqual(@as(u64, 0), ctx.stats.failed);
        try std.testing.expectEqual(@as(u64, 0), ctx.stats.skipped);
        try std.testing.expect(ctx.stats.passed > 300);
    }
}
