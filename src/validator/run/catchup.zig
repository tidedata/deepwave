//! Checkpoint catch-up over Sui state sync: a seat that was down or cut off when its epoch
//! ended cannot finish that epoch through consensus (the others dropped the epoch's DAG at the
//! switch), so it fetches the certified checkpoints it is missing from its peers' `sui.StateSync`
//! service (run/state_sync.zig: sui-node and deepwave seats alike), checks them, executes their
//! transactions and applies them whole, epoch by epoch, the way sui-node's state sync and
//! checkpoint executor bring a lagging validator up.
//!
//! Client: `GetCheckpointAvailability` on every committee peer on our chain (genesis summary
//! checked once per peer) for the best height; per checkpoint `GetCheckpointSummary
//! (BySequenceNumber)` then `GetCheckpointContentsV2(content digest)`.
//!
//! Checks, per checkpoint, in order: chain step (sequence, previous digest, epoch step only
//! after an end-of-epoch checkpoint), the certificate against that epoch's committee (BLS quorum,
//! `checkpoint.verifyCertifiedSummary`), the contents rebuilt from the full contents
//! (`node.p2p_exec.splitFull`: transaction digests from the transaction data, effects digests,
//! signatures a permutation of the certified ones) hash to the summary's content digest, and
//! each effects names its transaction. Then each transaction this seat already executed must
//! have the certified effects digest (else: fork, halt); a new one is executed here with the
//! input versions its certified effects name (`Runner.runCertified`, as the checkpoint executor
//! does) and must produce exactly the certified effects (else: halt). The running state root is
//! advanced and, at an epoch end, compared with the committed ECMH root (else: fork). The
//! checkpoint is stored as built and certified last, so a crash in between replays it
//! idempotently.
//!
//! Only whole epochs are applied: checkpoints of an epoch the peers are still running are left to
//! consensus (commit sync replays the running epoch's DAG).
const std = @import("std");
const Io = std.Io;
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const checkpoint = @import("checkpoint");
const node = @import("node");
const serve = @import("serve");
const checkpoints = @import("../checkpoints/root.zig");
const exec_store = @import("exec_store.zig");
const ckpt_store = @import("ckpt_store.zig");
const runner_mod = @import("runner.zig");
const state_sync = @import("state_sync.zig");

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const ev = checkpoints.effects_view;
const state_acc = checkpoints.state_acc;
const create = checkpoints.create;
const tdigest = types.digest;
const px = node.p2p_exec;
const log = std.log.scoped(.catchup);

const Certified = types.hand.Envelope(types.CheckpointSummary, types.AuthorityQuorumSignInfo);

pub const RgpSink = struct {
    ctx: *anyopaque,
    f: *const fn (ctx: *anyopaque, epoch: u64, rgp: u64) anyerror!void,
};

pub const Error = error{ OutOfMemory, Malformed, Unverified, Fork, Store, NoCommittee, UnsupportedProtocol, Execution };

/// Splits BCS(CertifiedCheckpointSummary) into the decoded summary, its BCS and the signature BCS.
pub const Split = struct { summary: types.CheckpointSummary, summary_bcs: []const u8, sig_bcs: []const u8, digest: [32]u8 };

pub fn split(arena: Allocator, certified: []const u8) Error!Split {
    const c = bcs.decode(Certified, arena, certified) catch return error.Malformed;
    const sb = bcs.encodeAlloc(types.CheckpointSummary, arena, &c.data) catch return error.OutOfMemory;
    if (!std.mem.startsWith(u8, certified, sb)) return error.Malformed;
    return .{ .summary = c.data, .summary_bcs = sb, .sig_bcs = certified[sb.len..], .digest = tdigest.checkpointSummaryDigest(sb) };
}

fn rootCommitment(eoe: *const types.EndOfEpochData) ?[32]u8 {
    for (eoe.epochCommitments) |c| switch (c) {
        .ECMHLiveObjectSetDigest => |d| return d.digest.@"0",
        else => {},
    };
    return null;
}

// ------------------------------------------------------------------ apply

pub const Applier = struct {
    gpa: Allocator,
    ckpt: *ckpt_store.CkptStore,
    exec: *exec_store.ExecStore,
    /// Executes what this seat has not (its own runner: the epoch's runs on another thread).
    runner: *runner_mod.Runner,
    arena: std.heap.ArenaAllocator,
    committee: ?checkpoint.Committee = null,
    cfg: ?*const protocol.ProtocolConfig = null,
    prev: struct { seq: u64, digest: [32]u8, epoch: u64, eoe: bool },
    running: state_acc.RunningRoot,
    /// Told each epoch's reference gas price as an applied end of epoch moves the system state
    /// into it (the runtime keeps it per epoch: an epoch whose ChangeEpoch already ran starts
    /// from that record, run/runtime.zig).
    rgp_sink: ?RgpSink = null,
    /// The runner's context was set for `runner.ctx.epoch` (`epochCtx`).
    ctx_set: bool = false,
    /// Results, for the log and the epoch switch.
    applied: u64 = 0,
    committed_txs: u64 = 0,
    /// Of `committed_txs`, those executed here (the rest were already in the exec store).
    executed_txs: u64 = 0,
    skipped_txs: u64 = 0,
    first_seq: ?u64 = null,
    /// End-of-epoch checkpoints applied, in order.
    eoes: std.ArrayList(u64) = .empty,

    pub const Known = struct { epoch: u64, members: []const checkpoint.Member, cfg: *const protocol.ProtocolConfig };

    /// From the store's highest certified checkpoint. `known` is the committee of the epoch that
    /// checkpoint belongs to (unused when it ends its epoch: the next committee is in it).
    pub fn init(gpa: Allocator, ck: *ckpt_store.CkptStore, ex: *exec_store.ExecStore, runner: *runner_mod.Runner, known: ?Known) Error!Applier {
        var ap: Applier = .{ .gpa = gpa, .ckpt = ck, .exec = ex, .runner = runner, .arena = .init(gpa), .prev = undefined, .running = .{} };
        errdefer ap.arena.deinit();
        const a = ap.arena.allocator();
        const h = ck.highestCertified() orelse return error.Store;
        const s = try split(a, ck.certifiedBytes(h) orelse return error.Store);
        const eoe = s.summary.end_of_epoch_data != null;
        ap.prev = .{ .seq = h, .digest = s.digest, .epoch = s.summary.epoch, .eoe = eoe };
        if (eoe) {
            try ap.nextEpoch(s.summary_bcs, &s.summary);
        } else if (known) |k| {
            if (k.epoch != s.summary.epoch) return error.NoCommittee;
            ap.committee = checkpoint.Committee.init(a, k.epoch, k.members) catch return error.NoCommittee;
            ap.cfg = k.cfg;
        } else return error.NoCommittee;
        const rr = ck.store().runningRoot() orelse return error.Store;
        ap.running = state_acc.RunningRoot.restore(&rr.root, rr.seq) orelse return error.Store;
        return ap;
    }

    pub fn deinit(ap: *Applier) void {
        ap.eoes.deinit(ap.gpa);
        ap.arena.deinit();
    }

    fn nextEpoch(ap: *Applier, summary_bcs: []const u8, s: *const types.CheckpointSummary) Error!void {
        const a = ap.arena.allocator();
        const parsed = checkpoint.Summary.parse(summary_bcs) catch return error.Malformed;
        ap.committee = checkpoint.nextCommittee(a, parsed) catch return error.Malformed;
        const pv = s.end_of_epoch_data.?.nextEpochProtocolVersion.@"0";
        ap.cfg = protocol.get(pv, .unknown) catch return error.UnsupportedProtocol;
    }

    /// The epoch the next checkpoint belongs to.
    pub fn nextEpochNumber(ap: *const Applier) u64 {
        return if (ap.prev.eoe) ap.prev.epoch + 1 else ap.prev.epoch;
    }

    /// The runner's epoch context for checkpoints of `epoch`, from the system state the exec
    /// store holds (the previous epoch's ChangeEpoch moved it there).
    fn epochCtx(ap: *Applier, epoch: u64) Error!void {
        if (ap.runner.ctx.epoch == epoch and ap.ctx_set) return;
        const st = systemState(ap.exec) orelse return error.Store;
        const sum = serve.sysstate.summary(st) catch return error.Store;
        if (sum.epoch != epoch) {
            log.err("checkpoint of epoch {d}: the exec store's system state is at epoch {d}", .{ epoch, sum.epoch });
            return error.Store;
        }
        const cfg = protocol.get(sum.protocol_version, .unknown) catch return error.UnsupportedProtocol;
        var c = ap.runner.ctx;
        c.cfg = cfg;
        c.epoch = epoch;
        c.epoch_start_ms = sum.epoch_start_timestamp_ms;
        c.rgp = sum.reference_gas_price;
        if (ap.committee) |*cm| c.committee_size = @intCast(cm.members.len);
        ap.runner.setEpoch(c);
        ap.ctx_set = true;
    }

    fn bad(seq: u64, comptime why: []const u8) Error {
        log.warn("checkpoint {d}: " ++ why, .{seq});
        return error.Unverified;
    }

    /// Verifies and applies checkpoint `prev.seq + 1` from its certified summary and its
    /// `VersionedFullCheckpointContents`.
    pub fn apply(ap: *Applier, scratch: Allocator, certified: []const u8, full_raw: []const u8) Error!void {
        const sp = try split(scratch, certified);
        const s = &sp.summary;
        const q = s.sequence_number;
        // 1: chain step
        if (q != ap.prev.seq + 1) return bad(q, "sequence");
        const pd = s.previous_digest orelse return bad(q, "no previous digest");
        if (!std.mem.eql(u8, &pd.@"0".@"0", &ap.prev.digest)) return bad(q, "previous digest");
        if (s.epoch != ap.nextEpochNumber()) return bad(q, "epoch step");
        // 2: certificate
        const committee = &(ap.committee orelse return error.NoCommittee);
        const verdict = checkpoint.verifyCertifiedSummary(committee, .{ .summary = sp.summary_bcs, .sig = sp.sig_bcs });
        if (!verdict.isOk()) {
            log.warn("checkpoint {d}: certificate rejected: {s}", .{ q, @tagName(verdict) });
            return error.Unverified;
        }
        // 3: contents (transaction and effects digests, signatures)
        const full = px.splitFullWith(scratch, full_raw, false) catch |e| {
            if (e == error.OutOfMemory) return error.OutOfMemory;
            log.warn("checkpoint {d}: full contents: {s} ({d} bytes, tag {d})", .{ q, @errorName(e), full_raw.len, if (full_raw.len > 0) full_raw[0] else 0 });
            return error.Unverified;
        };
        if (!std.mem.eql(u8, &tdigest.checkpointContentsDigest(full.contents), &s.content_digest.@"0".@"0")) return bad(q, "contents digest");
        if (full.mismatched != 0) log.info("checkpoint {d}: {d} transactions carry signatures other than the contents' (not covered by any digest)", .{ q, full.mismatched });
        const views = try scratch.alloc(ev.View, full.txs.len);
        const tds = try scratch.alloc([]const u8, full.txs.len);
        for (full.txs, views, tds) |t, *v, *td| {
            td.* = px.txDataOf(t.tx) catch return bad(q, "transaction envelope");
            v.* = ev.View.parse(scratch, t.effects) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else bad(q, "effects decode");
            if (!std.mem.eql(u8, &v.tx, &tdigest.transactionDataDigest(td.*))) return bad(q, "effects name another transaction");
        }
        // 4: execute (what is already executed must match)
        for (views, tds) |*v, td| {
            if (ap.exec.executed(&v.tx)) |have| {
                if (!std.mem.eql(u8, &have.effects_digest, &v.digest)) {
                    log.err("FORK: checkpoint {d} transaction {x}: local effects {x}, certified {x}", .{ s.sequence_number, v.tx, have.effects_digest, v.digest });
                    return error.Fork;
                }
                ap.skipped_txs += 1;
                continue;
            }
            const fx = switch (v.fx) {
                .V2 => |*x| x,
                .V1 => return error.UnsupportedProtocol,
            };
            try ap.epochCtx(s.epoch);
            const got = ap.runner.runCertified(scratch, td, v.tx, fx) catch |e| {
                log.err("checkpoint {d} transaction {x}: execution failed: {s} ({s})", .{ s.sequence_number, v.tx, @errorName(e), ap.runner.lastError() });
                return if (e == error.OutOfMemory) error.OutOfMemory else error.Execution;
            };
            if (!std.mem.eql(u8, &got.effects_digest, &v.digest)) {
                log.err("checkpoint {d} transaction {x}: executed effects {x}, certified {x}", .{ s.sequence_number, v.tx, got.effects_digest, v.digest });
                return error.Execution;
            }
            ap.committed_txs += 1;
            ap.executed_txs += 1;
        }
        // 5: state root
        const seq = s.sequence_number;
        const last = ap.running.last_seq orelse return error.Store;
        if (seq > last) {
            const acc = state_acc.accumulateEffects(scratch, ap.cfg.?, views) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.UnsupportedProtocol;
            ap.running.apply(seq, &acc) catch return error.Store;
            ap.ckpt.putRunningRoot(.{ .root = ap.running.root.toBytes(), .seq = seq }) catch return error.Store;
        }
        if (s.end_of_epoch_data) |*eoe| if (rootCommitment(eoe)) |want| if (ap.running.last_seq.? == seq) {
            const have = ap.running.epochDigest();
            if (!std.mem.eql(u8, &have, &want)) {
                log.err("FORK: checkpoint {d} ends epoch {d}: state root {x}, certified {x}", .{ seq, s.epoch, have, want });
                return error.Fork;
            }
        };
        // 6: checkpoint stores (certified last: a crash before it replays this checkpoint)
        const st = ap.ckpt.store();
        if (st.locallyComputedDigest(seq)) |mine| {
            if (!std.mem.eql(u8, &mine, &sp.digest)) {
                log.err("FORK: checkpoint {d}: built {x}, certified {x}", .{ seq, mine, sp.digest });
                st.recordFork(seq, mine, sp.digest);
                return error.Fork;
            }
        } else {
            const lb = create.LastBuilt.fromSummary(s, sp.digest, null);
            st.putBuilt(seq, 0, lb, sp.summary_bcs, full.contents) catch return error.Store;
        }
        const cur = st.lastBuilt();
        if (cur == null or cur.?.seq < seq) st.setLastBuilt(create.LastBuilt.fromSummary(s, sp.digest, null)) catch return error.Store;
        ap.ckpt.putCertified(seq, sp.digest, certified) catch return error.Store;

        if (ap.first_seq == null) ap.first_seq = seq;
        ap.applied += 1;
        ap.prev = .{ .seq = seq, .digest = sp.digest, .epoch = s.epoch, .eoe = s.end_of_epoch_data != null };
        if (s.end_of_epoch_data != null) {
            try ap.nextEpoch(sp.summary_bcs, s);
            try ap.eoes.append(ap.gpa, seq);
            if (ap.rgp_sink) |rs| {
                const st_now = systemState(ap.exec) orelse return error.Store;
                const sum = serve.sysstate.summary(st_now) catch return error.Store;
                if (sum.epoch != s.epoch + 1) return error.Store;
                rs.f(rs.ctx, sum.epoch, sum.reference_gas_price) catch return error.Store;
            }
        }
    }
};

// ------------------------------------------------------------------ client

/// The system state object as the exec store holds it (run/runtime.zig `systemState`).
pub fn systemState(st: *exec_store.ExecStore) ?serve.sysstate.State {
    const hash = @import("hash");
    const exec = @import("exec");
    const sys_id: [32]u8 = runner_mod.objectId(5);
    const wrapper = st.latest(&sys_id) orelse return null;
    const wv = exec.objects.ObjectView.parse(wrapper) catch return null;
    const version = serve.sysstate.wrapperVersion(wv.contents()) orelse return null;
    var k: [8]u8 = undefined;
    std.mem.writeInt(u64, &k, version, .little);
    var klen: [8]u8 = undefined;
    std.mem.writeInt(u64, &klen, 8, .little);
    const field = hash.blake2b256(&.{ &[_]u8{0xf0}, &sys_id, &klen, &k, &[_]u8{2} });
    const inner = st.latest(&field) orelse return null;
    const iv = exec.objects.ObjectView.parse(inner) catch return null;
    return .{ .version = version, .inner = serve.sysstate.innerOfField(iv.contents()) orelse return null };
}

pub const Fetched = struct { certified: []const u8, full: []const u8 };

pub const Client = struct {
    svc: *state_sync.Service,

    pub fn init(svc: *state_sync.Service) Client {
        return .{ .svc = svc };
    }

    fn peerCount(c: *const Client) usize {
        return c.svc.opts.p2p.peerCount();
    }

    /// Summary and full contents of checkpoint `seq` from peer `i`.
    pub fn fetch(c: *Client, arena: Allocator, i: usize, seq: u64) ?Fetched {
        const cert = c.svc.summary(arena, i, seq) orelse return null;
        const sp = split(arena, cert) catch return null;
        const full = c.svc.contentsV2(arena, i, sp.summary.content_digest.@"0".@"0") orelse return null;
        return .{ .certified = cert, .full = full };
    }

    pub const Best = struct { peer: usize, seq: u64, epoch: u64, eoe: bool };

    /// The peer on our chain with the highest synced checkpoint (its epoch, and whether it ends
    /// it).
    pub fn best(c: *Client, arena: Allocator) ?Best {
        var out: ?Best = null;
        for (0..c.peerCount()) |i| {
            const h = c.svc.latest(arena, i) orelse continue;
            const sp = split(arena, h.cert) catch continue;
            if (out == null or h.seq > out.?.seq) out = .{ .peer = i, .seq = h.seq, .epoch = sp.summary.epoch, .eoe = sp.summary.end_of_epoch_data != null };
        }
        return out;
    }

    /// The last epoch the peers have finished, given the best peer.
    pub fn finishedEpoch(b: Best) ?u64 {
        if (b.eoe) return b.epoch;
        return if (b.epoch == 0) null else b.epoch - 1;
    }

    /// Checkpoints fetched ahead of the one being applied (sui-node downloads contents
    /// concurrently too, `checkpoint_content_download_concurrency`).
    pub const window: usize = 16;

    const Slot = struct {
        arena: std.heap.ArenaAllocator,
        seq: u64 = 0,
        peer: usize = 0,
        got: ?Fetched = null,
    };

    fn fetchSlot(c: *Client, slot: *Slot) void {
        _ = slot.arena.reset(.retain_capacity);
        slot.got = c.fetch(slot.arena.allocator(), slot.peer, slot.seq);
    }

    /// Fetches and applies every checkpoint after the applier's position through the end of the
    /// last epoch the best peer finished, `window` checkpoints fetched at a time across the
    /// peers. Stops early on `stop`. Fork and execution failures are returned as errors.
    pub fn run(c: *Client, ap: *Applier, b: Best, stop: *const Atomic(bool)) Error!void {
        const through = finishedEpoch(b) orelse return;
        var scratch = std.heap.ArenaAllocator.init(ap.gpa);
        defer scratch.deinit();
        const n = c.peerCount();
        var slots: [window]Slot = undefined;
        for (&slots) |*sl| sl.* = .{ .arena = .init(ap.gpa) };
        defer for (&slots) |*sl| sl.arena.deinit();
        var threads: [window]?std.Thread = @splat(null);
        var failures: u32 = 0;
        var pi = b.peer;
        while (!stop.load(.acquire) and ap.prev.seq < b.seq) {
            if (ap.nextEpochNumber() > through) return;
            // fetch the window, spreading it over the peers on our chain
            const first = ap.prev.seq + 1;
            const k: usize = @intCast(@min(@as(u64, window), b.seq - ap.prev.seq));
            var peer = pi;
            for (slots[0..k], threads[0..k], 0..) |*sl, *t, x| {
                sl.seq = first + x;
                // the next peer that has it (else the best one)
                var tries: usize = 0;
                while (tries < n and (c.svc.opts.p2p.isSelf(peer) or c.svc.heightOf(peer) < sl.seq)) : (tries += 1) peer = (peer + 1) % n;
                if (tries == n) peer = b.peer;
                sl.peer = peer;
                sl.got = null;
                peer = (peer + 1) % n;
                t.* = std.Thread.spawn(.{ .stack_size = 1 << 20 }, fetchSlot, .{ c, sl }) catch null;
                if (t.* == null) fetchSlot(c, sl);
            }
            for (threads[0..k]) |*t| if (t.*) |th| {
                th.join();
                t.* = null;
            };
            // apply in order; a gap or a rejected checkpoint ends the window
            for (slots[0..k]) |*sl| {
                if (stop.load(.acquire) or ap.nextEpochNumber() > through) return;
                _ = scratch.reset(.retain_capacity);
                const d = sl.got orelse {
                    failures += 1;
                    if (failures > 3 * n) return error.Unverified;
                    pi = (sl.peer + 1) % n;
                    break;
                };
                ap.apply(scratch.allocator(), d.certified, d.full) catch |e| switch (e) {
                    error.Unverified, error.Malformed => {
                        log.warn("checkpoint {d} from peer {d}: {s}; trying another peer", .{ sl.seq, sl.peer, @errorName(e) });
                        failures += 1;
                        if (failures > 3 * n) return e;
                        pi = (sl.peer + 1) % n;
                        break;
                    },
                    else => return e,
                };
                failures = 0;
            }
        }
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

test "catchup: finishedEpoch" {
    try testing.expectEqual(@as(?u64, 3), Client.finishedEpoch(.{ .peer = 0, .seq = 9, .epoch = 3, .eoe = true }));
    try testing.expectEqual(@as(?u64, 2), Client.finishedEpoch(.{ .peer = 0, .seq = 9, .epoch = 3, .eoe = false }));
    try testing.expectEqual(@as(?u64, null), Client.finishedEpoch(.{ .peer = 0, .seq = 9, .epoch = 0, .eoe = false }));
}
