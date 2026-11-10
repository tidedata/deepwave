//! `--tiles`: the p2p checkpoint tip path as a pipeline of pinned tiles on shared-memory rings
//! (ARCHITECTURE.md 7.1), replacing p2p.zig's single exec thread. The peer
//! threads (net) and the slot table they fill are unchanged; what runs after a checkpoint's
//! contents arrive is five tiles, one thread each, joined by flow-controlled rings (rt/tile.zig):
//!
//!   ingest -> verify -> exec -> store -> notify
//!
//!   ingest  picks the next checkpoints whose summary and contents are in their slots, in order,
//!           and queues them (the only tile that takes p.lock, and only when the slot table moved).
//!   verify  decodes the summary and splits the contents, checks the contents digest (the BCS
//!           and hashing work), with a per-frag scratch arena.
//!   exec    chain link against the store (or the previous checkpoint's uncommitted writes), the
//!           transactions on p2p_exec.zig, owner of `p.parent` and the exec worker pool.
//!   store   claims the checkpoint with the fetcher and writes the spool.
//!   notify  tells the follower (arrival, delivered), accounts, returns the slot and runs the
//!           housekeeping the exec thread ran (p2p-only retries, active-set election).
//!
//! One message per checkpoint travels the pipeline: `Msg` in a table of `depth` entries indexed
//! by the frag number; a tile writes only its own fields after receiving the frag, the ring's
//! release/acquire hand-off orders the rest. Credits come from the last tile's progress word
//! (ingest cannot reuse a message before notify finished it), so no ring ever overruns. Payloads
//! are not copied: summary and contents stay in the slot (owned by it until notify releases it),
//! the transactions' output lives in the exec tile's per-frag arena until the frag is complete.
//!
//! Behaviour is the exec thread's: same checks, same fallbacks and reasons (a bad contents
//! digest is reported after the chain-link check, as there, because exec holds the deferred
//! reason), same p2p-only retry hooks (run on the notify tile, which is the only tile that
//! touches p2p_only.State). Off by default (`--tiles`).
const std = @import("std");
const rt = @import("rt");
const bcs = @import("bcs");
const hash = @import("hash");
const types = @import("types");
const p2p = @import("p2p.zig");
const px = @import("p2p_exec.zig");
const source = @import("source.zig");
const only_mod = @import("p2p_only.zig");
const tile = rt.tile;

/// Frags in flight (a power of two): messages, ring lines and per-frag arenas.
pub const depth = 8;

/// `requeue`: the frag's predecessor never built (it fell back), so this one cannot chain; it
/// leaves the pipeline untouched (notify only clears `queued`) and ingest picks it up again
/// behind the retry of the predecessor.
const Verdict = enum { ok, late, fallback, requeue };

pub const Msg = struct {
    seq: u64 = 0,
    slot: *p2p.Slot = undefined,
    serial: bool = false,
    verdict: Verdict = .ok,
    why: []const u8 = "",
    outcome: p2p.Outcome = .none,
    // verify
    summary: types.CheckpointSummary = undefined,
    summary_len: usize = 0,
    fc: px.FullContents = undefined,
    /// A contents problem found by verify, reported by exec after the chain link check.
    bad_contents: ?[]const u8 = null,
    // exec
    blob: []const u8 = &.{},
    aux: []const u8 = &.{},
    built: bool = false,
    exec0_ms: u64 = 0,
    exec1_ms: u64 = 0,
    ntx: u32 = 0,
    parent_used: bool = false,
    // store
    spooled: bool = false,
    spool_ms: u64 = 0,
    /// When ingest queued it (ns, monotonic).
    t_in_ns: u64 = 0,
};

pub const Pipeline = struct {
    p: *p2p.P2p,
    gpa: std.mem.Allocator,
    msgs: [depth]Msg = @splat(.{}),
    arenas_v: [depth]std.heap.ArenaAllocator,
    arenas_e: [depth]std.heap.ArenaAllocator,
    l_ingest: tile.Link = undefined,
    l_verify: tile.Link = undefined,
    l_exec: tile.Link = undefined,
    l_store: tile.Link = undefined,
    rx_verify: tile.Rx = undefined,
    rx_exec: tile.Rx = undefined,
    rx_store: tile.Rx = undefined,
    rx_notify: tile.Rx = undefined,
    readers_ingest: [2]*const rt.ring.Fseq = undefined,
    readers_verify: [1]*const rt.ring.Fseq = undefined,
    readers_exec: [1]*const rt.ring.Fseq = undefined,
    readers_store: [1]*const rt.ring.Fseq = undefined,
    c_ingest: Ingest = undefined,
    c_verify: Verify = undefined,
    c_exec: Exec = undefined,
    c_store: Store = undefined,
    c_notify: Notify = undefined,
    t: [5]tile.Tile = undefined,
    tile_ptrs: [5]*tile.Tile = undefined,
    group: tile.Group = undefined,
    /// Ingest queued to notify done, per checkpoint.
    e2e: tile.Metrics = .{},
    stopped: bool = false,

    const names = [5][]const u8{ "tile-ingest", "tile-verify", "tile-exec", "tile-store", "tile-notify" };

    pub fn create(p: *p2p.P2p) !*Pipeline {
        const gpa = p.gpa;
        const pl = try gpa.create(Pipeline);
        errdefer gpa.destroy(pl);
        pl.* = .{ .p = p, .gpa = gpa, .arenas_v = undefined, .arenas_e = undefined };
        for (&pl.arenas_v) |*a| a.* = .init(gpa);
        for (&pl.arenas_e) |*a| a.* = .init(gpa);
        pl.rx_verify = .{ .link = &pl.l_ingest };
        pl.rx_exec = .{ .link = &pl.l_verify };
        pl.rx_store = .{ .link = &pl.l_exec };
        pl.rx_notify = .{ .link = &pl.l_store };
        // Ingest is limited by verify (its ring) and by notify (the message table).
        pl.readers_ingest = .{ &pl.rx_verify.fseq, &pl.rx_notify.fseq };
        pl.readers_verify = .{&pl.rx_exec.fseq};
        pl.readers_exec = .{&pl.rx_store.fseq};
        pl.readers_store = .{&pl.rx_notify.fseq};
        pl.l_ingest = try tile.Link.init(gpa, depth, &pl.readers_ingest);
        errdefer pl.l_ingest.deinit();
        pl.l_verify = try tile.Link.init(gpa, depth, &pl.readers_verify);
        errdefer pl.l_verify.deinit();
        pl.l_exec = try tile.Link.init(gpa, depth, &pl.readers_exec);
        errdefer pl.l_exec.deinit();
        pl.l_store = try tile.Link.init(gpa, depth, &pl.readers_store);
        pl.c_ingest = .{ .pl = pl };
        pl.c_verify = .{ .pl = pl };
        pl.c_exec = .{ .pl = pl };
        pl.c_store = .{ .pl = pl };
        pl.c_notify = .{ .pl = pl };
        const ctxs = [5]*anyopaque{ &pl.c_ingest, &pl.c_verify, &pl.c_exec, &pl.c_store, &pl.c_notify };
        const steps = [5]*const fn (*anyopaque) tile.Step{ Ingest.step, Verify.step, Exec.step, Store.step, Notify.step };
        for (0..5) |i| {
            pl.t[i] = .{
                .cfg = .{
                    .name = names[i],
                    .cpu = if (i < p.tile_cpus.len) p.tile_cpus[i] else null,
                    .spin = if (p.tile_spin) std.math.maxInt(u32) else 2000,
                    .stack_size = 64 << 20,
                },
                .ctx = ctxs[i],
                .step = steps[i],
            };
            pl.tile_ptrs[i] = &pl.t[i];
        }
        pl.group = .{ .tiles = &pl.tile_ptrs };
        return pl;
    }

    pub fn start(pl: *Pipeline) !void {
        try pl.group.start();
        std.log.info("tiles: ingest, verify, exec, store, notify running (depth {d}, spin {s}, cpus {any})", .{ depth, if (pl.p.tile_spin) "always" else "then sleep", pl.p.tile_cpus });
    }

    /// Stops and joins the tiles and logs their load. Idempotent.
    pub fn stop(pl: *Pipeline) void {
        if (pl.stopped) return;
        pl.stopped = true;
        pl.group.stop();
        pl.report();
    }

    pub fn destroy(pl: *Pipeline) void {
        pl.stop();
        pl.l_ingest.deinit();
        pl.l_verify.deinit();
        pl.l_exec.deinit();
        pl.l_store.deinit();
        for (&pl.arenas_v) |*a| a.deinit();
        for (&pl.arenas_e) |*a| a.deinit();
        pl.gpa.destroy(pl);
    }

    pub fn report(pl: *Pipeline) void {
        for (&pl.t) |*t| {
            const m = &t.metrics;
            const busy = m.busy_ns.load(.monotonic);
            const idle = m.idle_ns.load(.monotonic);
            const tot = @max(busy + idle, 1);
            std.log.info("tile {s}: {d} frags, busy {d:.1}%, step p50 <= {d} us, p99 <= {d} us, max {d} us, pinned {}", .{
                t.cfg.name,
                m.frags.load(.monotonic),
                @as(f64, @floatFromInt(busy)) * 100.0 / @as(f64, @floatFromInt(tot)),
                m.quantileNs(0.5) / 1000,
                m.quantileNs(0.99) / 1000,
                m.max_step_ns.load(.monotonic) / 1000,
                t.pinned.load(.acquire),
            });
        }
        std.log.info("tiles: queued to done p50 <= {d} us, p99 <= {d} us, max {d} us ({d} checkpoints)", .{
            pl.e2e.quantileNs(0.5) / 1000,
            pl.e2e.quantileNs(0.99) / 1000,
            pl.e2e.max_step_ns.load(.monotonic) / 1000,
            pl.e2e.busy_steps.load(.monotonic),
        });
    }
};

fn self(comptime T: type, ctx: *anyopaque) *T {
    return @ptrCast(@alignCast(ctx));
}

// ------------------------------------------------------------------------------------ ingest

pub const Ingest = struct {
    pl: *Pipeline,
    seen_gen: u64 = std.math.maxInt(u64),
    last_scan_ns: u64 = 0,

    /// The slot table's next buildable checkpoints in order: from the follower's next one up,
    /// skipping those already queued or finished, stopping at the first without contents.
    fn step(ctx: *anyopaque) tile.Step {
        const c = self(Ingest, ctx);
        const pl = c.pl;
        const p = pl.p;
        if (!pl.l_ingest.canPublish()) return .idle;
        const now = tile.nowNs();
        const gen = p.ready_gen.load(.acquire);
        if (gen == c.seen_gen and now -| c.last_scan_ns < std.time.ns_per_ms) return .idle;
        c.seen_gen = gen;
        c.last_scan_ns = now;
        const lo = p.fetcher.applied_next.load(.acquire);
        var found: ?*p2p.Slot = null;
        var serial = false;
        {
            p.lock.lockUncancelable(p.io);
            defer p.lock.unlock(p.io);
            var s = lo;
            while (s < lo + depth) : (s += 1) {
                const slot = &p.slots[s % p2p.ring];
                if (slot.seq != s) break;
                // Behind a checkpoint that fell back (held for a retry or for another source) a
                // build cannot chain: wait, as the exec thread did, for it to be released.
                if (s > lo) {
                    const prev = &p.slots[(s - 1) % p2p.ring];
                    if (prev.seq == s - 1 and prev.done and prev.outcome == .fallback) break;
                }
                if (slot.done or slot.queued) continue;
                if (slot.state == .ready) {
                    slot.queued = true;
                    serial = slot.serial;
                    found = slot;
                }
                break;
            }
        }
        const slot = found orelse return .idle;
        const n = pl.l_ingest.tx_seq;
        const m = &pl.msgs[n % depth];
        m.* = .{ .seq = slot.seq, .slot = slot, .serial = serial, .t_in_ns = now };
        _ = pl.l_ingest.publish(slot.seq, @intCast(n % depth), 0);
        pl.t[0].metrics.frag();
        c.seen_gen = std.math.maxInt(u64); // more may be queued behind it: look again at once
        return .busy;
    }
};

// ------------------------------------------------------------------------------------ verify

pub const Verify = struct {
    pl: *Pipeline,

    fn step(ctx: *anyopaque) tile.Step {
        const c = self(Verify, ctx);
        const pl = c.pl;
        var f: tile.FragMeta = undefined;
        if (!pl.rx_verify.peek(&f)) return .idle;
        if (!pl.l_verify.canPublish()) return .idle;
        const m = &pl.msgs[f.chunk];
        const arena = &pl.arenas_v[f.chunk];
        _ = arena.reset(.retain_capacity);
        verifyOne(pl.p, arena.allocator(), m);
        _ = pl.l_verify.publish(f.sig, f.chunk, 0);
        pl.rx_verify.done();
        pl.t[1].metrics.frag();
        return .busy;
    }

    fn fail(m: *Msg, why: []const u8) void {
        m.verdict = .fallback;
        m.why = why;
    }

    fn verifyOne(p: *p2p.P2p, a: std.mem.Allocator, m: *Msg) void {
        if (!p.fetcher.wants(m.seq)) {
            m.verdict = .late;
            return;
        }
        const slot = m.slot;
        const cert = slot.cert;
        var r = bcs.Reader.init(cert);
        bcs.skip(types.CheckpointSummary, &r) catch return fail(m, "summary does not parse");
        m.summary = bcs.decode(types.CheckpointSummary, a, cert[0..r.pos()]) catch return fail(m, "summary does not parse");
        m.summary_len = r.pos();
        // Contents problems wait for the chain link check in exec (the exec thread's order).
        const full_raw = slot.full;
        if (full_raw.len == 0 or full_raw[0] > 1) {
            m.bad_contents = "contents do not parse";
            return;
        }
        m.fc = px.splitFull(a, full_raw) catch {
            m.bad_contents = "contents do not parse";
            return;
        };
        const cd = hash.blake2b256(&.{ "CheckpointContents::", m.fc.contents });
        if (!std.mem.eql(u8, &cd, &m.summary.content_digest.@"0".@"0")) m.bad_contents = "contents digest differs";
    }
};

// ------------------------------------------------------------------------------------ exec

pub const Exec = struct {
    pl: *Pipeline,
    /// Frag number whose scratch arena was reset (an attempt that must wait is made again).
    begun: u64 = std.math.maxInt(u64),
    /// Frag number that built `p.parent` (its writes live in that frag's arena).
    parent_n: u64 = 0,
    /// The last frag that passed exec: its checkpoint, and whether the next one can still wait
    /// for it (built, or left to another source). Otherwise the next one is requeued.
    prev_seq: u64 = std.math.maxInt(u64),
    prev_ok: bool = false,

    fn step(ctx: *anyopaque) tile.Step {
        const c = self(Exec, ctx);
        const pl = c.pl;
        var f: tile.FragMeta = undefined;
        if (!pl.rx_exec.peek(&f)) return .idle;
        if (!pl.l_exec.canPublish()) return .idle;
        const m = &pl.msgs[f.chunk];
        if (m.verdict == .ok and !c.build(m, pl.rx_exec.seq, f.chunk)) {
            if (!c.orphaned(m.seq)) return .idle; // wait: try again
            m.verdict = .requeue;
        }
        c.prev_seq = m.seq;
        c.prev_ok = switch (m.verdict) {
            .ok => m.built,
            .late => true,
            .fallback, .requeue => false,
        };
        _ = pl.l_exec.publish(f.sig, f.chunk, 0);
        pl.rx_exec.done();
        pl.t[2].metrics.frag();
        return .busy;
    }

    /// A frag that could not chain will never be able to when its predecessor passed exec without
    /// building and without another source taking it (or is not the frag just before it).
    fn orphaned(c: *Exec, seq: u64) bool {
        return !(c.prev_seq +% 1 == seq and c.prev_ok);
    }

    fn failTrue(m: *Msg, why: []const u8) bool {
        m.verdict = .fallback;
        m.why = why;
        m.outcome = .fallback;
        return true;
    }

    /// Builds checkpoint `m.seq`. False: the store does not show the previous checkpoint yet
    /// (and its writes are not in hand), nothing was consumed, call again.
    fn build(c: *Exec, m: *Msg, n: u64, idx: u32) bool {
        const pl = c.pl;
        const p = pl.p;
        if (!p.fetcher.wants(m.seq)) {
            m.verdict = .late;
            return true;
        }
        if (c.begun != n) {
            // The previous checkpoint's writes live in its frag's arena: gone once that is reused.
            if (p.parent != null and n -% c.parent_n >= depth) p.parent = null;
            _ = pl.arenas_e[idx].reset(.retain_capacity);
            c.begun = n;
        }
        const a = pl.arenas_e[idx].allocator();
        const seq = m.seq;
        const t0 = source.nowNs();
        var snap = p.st.snapshot();
        defer snap.release();
        const hi = snap.highestCommitted() orelse return false;
        var parent: ?*const px.Layer = null;
        var prev_digest: [32]u8 = undefined;
        if (hi + 1 == seq) {
            const prev = snap.checkpoint(seq - 1) orelse return failTrue(m, "previous checkpoint not stored");
            var pr = bcs.Reader.init(prev.summary_cert);
            bcs.skip(types.CheckpointSummary, &pr) catch return failTrue(m, "stored summary does not parse");
            prev_digest = hash.blake2b256(&.{ "CheckpointSummary::", prev.summary_cert[0..pr.pos()] });
        } else if (hi + 2 == seq and p.parent != null and p.parent.?.seq + 1 == seq) {
            parent = &p.parent.?.layer;
            prev_digest = p.parent.?.digest;
        } else return false;
        const summary = &m.summary;
        const link = summary.previous_digest orelse return failTrue(m, "no previous digest");
        if (!std.mem.eql(u8, &link.@"0".@"0", &prev_digest)) {
            _ = p.stats.rejected_link.fetchAdd(1, .monotonic);
            return failTrue(m, "chain link differs");
        }
        if (m.bad_contents) |why| return failTrue(m, why);
        const params = p.hooks.params(p.hooks.ctx, summary.epoch) orelse
            if (parent != null) return false else return failTrue(m, "epoch parameters unknown");
        m.exec0_ms = source.wallMs();
        m.parent_used = parent != null;
        m.ntx = @intCast(m.fc.txs.len);
        const slot = m.slot;
        const res = px.run(p.gpa, a, &snap, &p.pkg_src, params, summary.epoch, slot.cert, m.fc.contents, m.fc.txs, &p.exec_stats, parent, if (m.serial) null else &p.pool) catch |e| return failTrue(m, @errorName(e));
        p.stats.reruns.store(p.pool.reruns.load(.monotonic), .monotonic);
        m.exec1_ms = source.wallMs();
        _ = p.stats.exec_ns.fetchAdd(source.nowNs() - t0, .monotonic);
        _ = p.stats.txs.fetchAdd(m.fc.txs.len, .monotonic);
        switch (res) {
            .fallback => |why| return failTrue(m, why),
            .ok => |o| {
                _ = p.stats.built.fetchAdd(1, .monotonic);
                if (parent != null) _ = p.stats.pipelined.fetchAdd(1, .monotonic);
                p.parent = .{ .seq = seq, .digest = hash.blake2b256(&.{ "CheckpointSummary::", slot.cert[0..m.summary_len] }), .layer = o.layer };
                c.parent_n = n;
                m.blob = o.blob;
                m.aux = o.aux;
                m.built = true;
                return true;
            },
        }
    }
};

// ------------------------------------------------------------------------------------ store

pub const Store = struct {
    pl: *Pipeline,

    fn step(ctx: *anyopaque) tile.Step {
        const c = self(Store, ctx);
        const pl = c.pl;
        const p = pl.p;
        var f: tile.FragMeta = undefined;
        if (!pl.rx_store.peek(&f)) return .idle;
        if (!pl.l_store.canPublish()) return .idle;
        const m = &pl.msgs[f.chunk];
        if (m.verdict == .ok and m.built) {
            if (!p.fetcher.markDone(m.seq)) {
                m.outcome = .lost;
                _ = p.stats.lost_race.fetchAdd(1, .monotonic);
            } else if (p.fetcher.writeSpoolBuilt(m.seq, m.blob, m.aux)) |_| {
                m.spooled = true;
                m.spool_ms = source.wallMs();
            } else |_| {
                p.fetcher.unmarkDone(m.seq);
                m.verdict = .fallback;
                m.why = "spool write";
                m.outcome = .fallback;
            }
        }
        _ = pl.l_store.publish(f.sig, f.chunk, 0);
        pl.rx_store.done();
        pl.t[3].metrics.frag();
        return .busy;
    }
};

// ------------------------------------------------------------------------------------ notify

pub const Notify = struct {
    pl: *Pipeline,

    fn step(ctx: *anyopaque) tile.Step {
        const c = self(Notify, ctx);
        const pl = c.pl;
        const p = pl.p;
        // The exec thread's housekeeping, here because this tile owns the p2p-only state.
        if (p.p2p_only) only_mod.tick(p);
        p.maybeElect(source.wallMs());
        var f: tile.FragMeta = undefined;
        if (!pl.rx_notify.peek(&f)) return .idle;
        const m = &pl.msgs[f.chunk];
        finish(p, m);
        pl.e2e.noteStep(tile.nowNs() -| m.t_in_ns);
        pl.rx_notify.done(); // returns the message to ingest
        _ = p.ready_gen.fetchAdd(1, .release);
        pl.t[4].metrics.frag();
        return .busy;
    }

    fn finish(p: *p2p.P2p, m: *Msg) void {
        const seq = m.seq;
        const slot = m.slot;
        if (m.verdict == .requeue) {
            p.lock.lockUncancelable(p.io);
            defer p.lock.unlock(p.io);
            if (slot.seq == seq) slot.queued = false;
            return;
        }
        // The slot may have been recycled for a later checkpoint while this frag was in flight:
        // its fields are written (and read) only while it still holds `seq`.
        var seen_ms: u64 = 0;
        var timestamp_ms: u64 = 0;
        {
            p.lock.lockUncancelable(p.io);
            defer p.lock.unlock(p.io);
            if (slot.seq == seq) {
                slot.exec0_ms = m.exec0_ms;
                slot.exec1_ms = m.exec1_ms;
                slot.ntx = m.ntx;
                slot.parent = m.parent_used;
                seen_ms = slot.seen_ms;
                timestamp_ms = slot.timestamp_ms;
            }
        }
        // In frag order, as the exec thread had it: a build ends the fallback streak.
        if (m.verdict == .ok and m.built and p.fallback_streak.swap(0, .monotonic) >= p.pause_after and p.pause_after != 0 and !p.p2p_only)
            std.log.info("p2p: checkpoint {d} built; contents fetched for every checkpoint again", .{seq});
        var outcome: p2p.Outcome = .none;
        var delivered = false;
        var fell_back = false;
        switch (m.verdict) {
            .late => {
                outcome = .late;
                _ = p.stats.late.fetchAdd(1, .monotonic);
            },
            .fallback => {
                outcome = m.outcome;
                p.fallback(m.why);
                fell_back = true;
            },
            .ok => if (m.spooled) {
                p.fetcher.noteArrival(seq);
                p.fetcher.noteSeen(seq, .p2p_built);
                p.fetcher.delivered(seq);
                outcome = .delivered;
                delivered = true;
                _ = p.stats.delivered.fetchAdd(1, .monotonic);
                _ = p.stats.build_ms_sum.fetchAdd(m.spool_ms -| seen_ms, .monotonic);
                _ = p.stats.spool_ms_sum.fetchAdd(m.spool_ms -| timestamp_ms, .monotonic);
            } else {
                outcome = .lost;
            },
            .requeue => unreachable,
        }
        {
            p.lock.lockUncancelable(p.io);
            defer p.lock.unlock(p.io);
            if (slot.seq == seq) {
                slot.outcome = outcome;
                if (delivered) slot.spool_ms = m.spool_ms;
            }
        }
        if (delivered and p.p2p_only) only_mod.onDelivered(p, seq);
        if (p.p2p_only and fell_back) {
            // Nothing else delivers it: retry here (p2p_only.zig), never leave it.
            only_mod.onFallback(p, seq, p.last_reason);
            p.lock.lockUncancelable(p.io);
            if (slot.seq == seq) slot.queued = false;
            p.lock.unlock(p.io);
            return;
        }
        p.lock.lockUncancelable(p.io);
        defer p.lock.unlock(p.io);
        if (slot.seq == seq) {
            slot.done = true;
            p.gpa.free(slot.full);
            slot.full = &.{};
            slot.queued = false;
        }
    }
};

// ------------------------------------------------------------------------------------ tests

/// Ingest's next frag: the checkpoint it queued (null when it queued none).
fn ingestNext(pl: *Pipeline) ?u64 {
    pl.c_ingest.seen_gen = std.math.maxInt(u64);
    const n = pl.l_ingest.tx_seq;
    if (Ingest.step(&pl.c_ingest) != .busy) return null;
    return pl.msgs[n % depth].seq;
}

fn readySlot(rig: *p2p.TestRig, seq: u64) !*p2p.Slot {
    try rig.seen(seq, 10);
    const slot = &rig.p.slots[seq % p2p.ring];
    slot.state = .ready;
    slot.full = try rig.p.gpa.dupe(u8, "full");
    return slot;
}

test "tiles: a fallback with the next checkpoints already queued; they leave, the retry goes first, then they follow" {
    const t = std.testing;
    var rig: p2p.TestRig = undefined;
    try rig.init(100);
    defer rig.deinit();
    rig.p.p2p_only = true;
    const pl = try Pipeline.create(&rig.p);
    defer pl.destroy();
    const s100 = try readySlot(&rig, 100);
    const s101 = try readySlot(&rig, 101);
    const s102 = try readySlot(&rig, 102);
    try t.expectEqual(@as(?u64, 100), ingestNext(pl));
    try t.expectEqual(@as(?u64, 101), ingestNext(pl));
    try t.expectEqual(@as(?u64, 102), ingestNext(pl));
    try t.expectEqual(@as(?u64, null), ingestNext(pl));
    try t.expect(s100.queued and s101.queued and s102.queued);

    // 100 falls back (held for the retry); exec, seeing 101 and 102 cannot chain, requeues them.
    var ex: Exec = .{ .pl = pl };
    pl.msgs[0].verdict = .fallback;
    pl.msgs[0].why = "ptb: Unsupported";
    pl.msgs[0].outcome = .fallback;
    ex.prev_seq = 100;
    ex.prev_ok = false;
    try t.expect(ex.orphaned(101));
    pl.msgs[1].verdict = .requeue;
    ex.prev_seq = 101;
    try t.expect(ex.orphaned(102));
    pl.msgs[2].verdict = .requeue;
    Notify.finish(&rig.p, &pl.msgs[0]);
    Notify.finish(&rig.p, &pl.msgs[1]);
    Notify.finish(&rig.p, &pl.msgs[2]);
    try t.expect(s100.done and !s100.queued and s100.outcome == .fallback);
    try t.expect(!s101.queued and !s102.queued and !s101.done);
    // Held: nothing is queued past it.
    try t.expectEqual(@as(?u64, null), ingestNext(pl));
    // Released after the backoff: the retry first, then the two behind it.
    s100.done = false;
    try t.expectEqual(@as(?u64, 100), ingestNext(pl));
    try t.expectEqual(@as(?u64, 101), ingestNext(pl));
    try t.expectEqual(@as(?u64, 102), ingestNext(pl));
}

test "tiles: a frag chains on a built or late predecessor and waits, any other is requeued" {
    const t = std.testing;
    var rig: p2p.TestRig = undefined;
    try rig.init(100);
    defer rig.deinit();
    const pl = try Pipeline.create(&rig.p);
    defer pl.destroy();
    var ex: Exec = .{ .pl = pl };
    try t.expect(ex.orphaned(100)); // nothing before it
    ex.prev_seq = 100;
    ex.prev_ok = true; // built, or left to another source
    try t.expect(!ex.orphaned(101));
    try t.expect(ex.orphaned(102)); // a gap
}

test "tiles: a late frag is accounted and the slot released; a delivered one is delivered and the streak ends" {
    const t = std.testing;
    var rig: p2p.TestRig = undefined;
    try rig.init(100);
    defer rig.deinit();
    const pl = try Pipeline.create(&rig.p);
    defer pl.destroy();
    const s100 = try readySlot(&rig, 100);
    const s101 = try readySlot(&rig, 101);
    try t.expectEqual(@as(?u64, 100), ingestNext(pl));
    try t.expectEqual(@as(?u64, 101), ingestNext(pl));
    pl.msgs[0].verdict = .late;
    Notify.finish(&rig.p, &pl.msgs[0]);
    try t.expect(s100.done and !s100.queued and s100.outcome == .late);
    try t.expectEqual(@as(u64, 1), rig.p.stats.late.load(.monotonic));
    // delivered: spooled and built
    rig.p.fallback_streak.store(3, .monotonic);
    pl.msgs[1].built = true;
    pl.msgs[1].spooled = true;
    pl.msgs[1].spool_ms = source.wallMs();
    Notify.finish(&rig.p, &pl.msgs[1]);
    try t.expect(s101.done and s101.outcome == .delivered);
    try t.expectEqual(@as(u32, 0), rig.p.fallback_streak.load(.monotonic));
    try t.expectEqual(@as(u64, 1), rig.p.stats.delivered.load(.monotonic));
}

test "tiles: a frag whose slot was recycled does not touch the new occupant" {
    const t = std.testing;
    var rig: p2p.TestRig = undefined;
    try rig.init(100);
    defer rig.deinit();
    const pl = try Pipeline.create(&rig.p);
    defer pl.destroy();
    const s100 = try readySlot(&rig, 100);
    try t.expectEqual(@as(?u64, 100), ingestNext(pl));
    // Another source committed 100; the slot now holds 100 + ring.
    try rig.seen(100 + p2p.ring, 10);
    pl.msgs[0].verdict = .ok;
    pl.msgs[0].built = true;
    pl.msgs[0].exec1_ms = 777;
    pl.msgs[0].ntx = 9;
    Notify.finish(&rig.p, &pl.msgs[0]);
    try t.expectEqual(@as(u64, 100 + p2p.ring), s100.seq);
    try t.expect(s100.ntx != 9 and s100.exec1_ms != 777 and !s100.done and s100.outcome == .none);
}
