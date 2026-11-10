//! `deepwave history-bench`: feeds mainnet checkpoints from the public archive (or a checkpoint
//! directory) straight into a ledger-history index on disk and reports, every `--every`
//! checkpoints, the rate, the process's anonymous memory (RssAnon) and the index's heap bytes;
//! at the end it closes and reopens the index and reports the open time. A rerun on the same
//! `--dir` resumes after the index's tip (kill -9 tests: kill it, rerun, the open must succeed
//! and the tip must be at least the last reported checkpoint).
//!
//!   deepwave history-bench --dir D --from SEQ --count N [--fetchers K] [--source http[:URL] | dir:PATH]
//!       [--every N] [--keep N] [--network mainnet|testnet] [--reopen-only]
const std = @import("std");
const Io = std.Io;
const lhist = @import("history");
const source = @import("source.zig");
const http = @import("http.zig");
const network = @import("network.zig");
const nowNs = source.nowNs;

fn rssAnonKb(io: Io) u64 {
    if (@import("builtin").os.tag != .linux) return 0;
    var buf: [8192]u8 = undefined;
    const txt = Io.Dir.cwd().readFile(io, "/proc/self/status", &buf) catch return 0;
    var it = std.mem.splitScalar(u8, txt, '\n');
    while (it.next()) |l| if (std.mem.startsWith(u8, l, "RssAnon:")) {
        var f = std.mem.tokenizeAny(u8, l[8..], " \tkB");
        return std.fmt.parseInt(u64, f.next() orelse return 0, 10) catch 0;
    };
    return 0;
}

const Slot = struct {
    state: std.atomic.Value(u64) = .init(0),
    blob: std.ArrayList(u8) = .empty,
    sc: source.Scratch,
};

const Shared = struct {
    gpa: std.mem.Allocator,
    src: *const source.Source,
    from: u64,
    end: u64,
    next: std.atomic.Value(u64),
    consumed: std.atomic.Value(u64),
    slots: []Slot,
    stop: std.atomic.Value(bool) = .init(false),
    failed: std.atomic.Value(u64) = .init(0),

    fn worker(s: *Shared, io: Io) void {
        var sc = source.Scratch.init(s.gpa);
        defer sc.deinit(s.gpa);
        while (!s.stop.load(.acquire)) {
            const seq = s.next.fetchAdd(1, .monotonic);
            if (seq >= s.end) return;
            while (seq >= s.consumed.load(.acquire) + s.slots.len) {
                if (s.stop.load(.acquire)) return;
                io.sleep(.fromMicroseconds(200), .awake) catch {};
            }
            const slot = &s.slots[@intCast((seq - s.from) % s.slots.len)];
            slot.blob.clearRetainingCapacity();
            var tries: u32 = 0;
            while (true) : (tries += 1) {
                const r = s.src.fetch(&sc, seq, &slot.blob) catch |e| {
                    if (tries < 20) {
                        io.sleep(.fromMilliseconds(200), .awake) catch {};
                        continue;
                    }
                    std.log.err("history-bench: fetch {d}: {s}", .{ seq, @errorName(e) });
                    s.failed.store(seq + 1, .release);
                    s.stop.store(true, .release);
                    return;
                };
                if (r == .missing) {
                    if (tries < 20) {
                        io.sleep(.fromMilliseconds(500), .awake) catch {};
                        continue;
                    }
                    s.failed.store(seq + 1, .release);
                    s.stop.store(true, .release);
                    return;
                }
                break;
            }
            slot.state.store(seq + 1, .release);
        }
    }
};

/// `buckets()` latency for hot keys (the Clock as affected object, the framework as move call
/// package and event emitter): every bucket of the window, cold then warm.
fn bucketTimes(ix: *lhist.Index) void {
    var clock: [33]u8 = @splat(0);
    clock[0] = @intFromEnum(lhist.Dim.affected_object);
    clock[32] = 6;
    var fw: [33]u8 = @splat(0);
    fw[0] = @intFromEnum(lhist.Dim.move_call);
    fw[32] = 2;
    var emit: [33]u8 = @splat(0);
    emit[0] = @intFromEnum(lhist.Dim.emit_module);
    emit[32] = 2;
    const cases = [_]struct { []const u8, lhist.Space, []const u8 }{ .{ "clock tx", .tx, &clock }, .{ "0x2 call tx", .tx, &fw }, .{ "0x2 emit event", .event, &emit }, .{ "0x2 emit tx", .tx, &emit } };
    for (cases) |c| for (0..2) |round| {
        var r = ix.reader();
        defer r.release();
        const t0 = nowNs();
        const bs = r.buckets(c[1], c[2]);
        const us = (nowNs() - t0) / 1000;
        var bits: u64 = 0;
        for (bs) |b| bits += b.bits.len;
        std.debug.print("history-bench: buckets {s} ({s}): {d} buckets, {d} bits, {d} us\n", .{ c[0], if (round == 0) "cold" else "warm", bs.len, bits, us });
    };
}

pub fn run(gpa: std.mem.Allocator, io: Io, args: []const []const u8) !u8 {
    var dir: ?[]const u8 = null;
    var from: u64 = 0;
    var count: u64 = 10_000;
    var fetchers: usize = 32;
    var every: u64 = 10_000;
    var keep: ?u64 = null;
    var src_spec: []const u8 = "http";
    var net: network.Network = .mainnet;
    var reopen_only = false;
    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        const v = if (i + 1 < args.len) args[i + 1] else "";
        if (std.mem.eql(u8, a, "--reopen-only")) {
            reopen_only = true;
            continue;
        }
        i += 1;
        if (std.mem.eql(u8, a, "--dir")) dir = v else if (std.mem.eql(u8, a, "--from")) from = try std.fmt.parseInt(u64, v, 10) else if (std.mem.eql(u8, a, "--count")) count = try std.fmt.parseInt(u64, v, 10) else if (std.mem.eql(u8, a, "--fetchers")) fetchers = try std.fmt.parseInt(usize, v, 10) else if (std.mem.eql(u8, a, "--every")) every = try std.fmt.parseInt(u64, v, 10) else if (std.mem.eql(u8, a, "--keep")) keep = try std.fmt.parseInt(u64, v, 10) else if (std.mem.eql(u8, a, "--source")) src_spec = v else if (std.mem.eql(u8, a, "--network")) net = network.Network.parse(v) orelse return error.BadArgs else {
            std.debug.print("history-bench: unknown flag {s}\n", .{a});
            return 2;
        }
    }
    const d = dir orelse {
        std.debug.print("history-bench --dir D --from SEQ --count N [--fetchers K] [--source http[:URL]|dir:PATH] [--every N] [--keep N] [--reopen-only]\n", .{});
        return 2;
    };
    const t_open = nowNs();
    var ix = try lhist.Index.init(gpa, io, d);
    const open_ms = (nowNs() - t_open) / std.time.ns_per_ms;
    std.debug.print("history-bench: open {d} ms, indexed {?d}..{?d}, segments {d}, heap {d} MiB, anon {d} MiB\n", .{ open_ms, ix.indexedLo(), ix.indexedHi(), ix.segmentCount(), ix.memoryBytes() >> 20, rssAnonKb(io) >> 10 });
    if (reopen_only) {
        ix.deinit();
        return 0;
    }
    const start = if (ix.indexedHi()) |hi| @max(from, hi + 1) else from;
    const end = from + count;

    var pub_src: ?http.Public = null;
    defer if (pub_src) |*p| p.deinit();
    var src_dir: ?Io.Dir = null;
    defer if (src_dir) |x| x.close(io);
    var src: source.Source = .{ .gpa = gpa, .io = io, .kind = .none };
    if (std.mem.startsWith(u8, src_spec, "dir:")) {
        src_dir = try Io.Dir.cwd().openDir(io, src_spec[4..], .{});
        src.kind = .{ .dir = src_dir.? };
    } else {
        const base = if (std.mem.startsWith(u8, src_spec, "http:")) src_spec[5..] else net.params().bucket_url;
        pub_src = http.Public.init(gpa, io, base);
        src.kind = .{ .http = &pub_src.? };
    }
    const slots = try gpa.alloc(Slot, @max(64, fetchers * 4));
    defer {
        for (slots) |*s| {
            s.blob.deinit(gpa);
            s.sc.deinit(gpa);
        }
        gpa.free(slots);
    }
    for (slots) |*s| s.* = .{ .sc = source.Scratch.init(gpa) };
    var sh: Shared = .{ .gpa = gpa, .src = &src, .from = start, .end = end, .next = .init(start), .consumed = .init(start), .slots = slots };
    var threads: std.ArrayList(std.Thread) = .empty;
    defer threads.deinit(gpa);
    if (start < end) for (0..fetchers) |_| try threads.append(gpa, try std.Thread.spawn(.{}, Shared.worker, .{ &sh, io }));

    const t0 = nowNs();
    var t_last = t0;
    var n_last: u64 = 0;
    var done: u64 = 0;
    var peak_anon: u64 = 0;
    var seq = start;
    var rc: u8 = 0;
    while (seq < end) : (seq += 1) {
        const slot = &slots[@intCast((seq - start) % slots.len)];
        while (slot.state.load(.acquire) != seq + 1) {
            if (sh.stop.load(.acquire) and slot.state.load(.acquire) != seq + 1) {
                std.debug.print("history-bench: fetch failed at {d}\n", .{sh.failed.load(.acquire) -| 1});
                rc = 1;
                break;
            }
            io.sleep(.fromMicroseconds(100), .awake) catch {};
        }
        if (rc != 0) break;
        ix.addCheckpoint(seq, slot.blob.items) catch |e| {
            std.debug.print("history-bench: index {d}: {s}\n", .{ seq, @errorName(e) });
            rc = 1;
            break;
        };
        ix.publish(seq);
        slot.state.store(0, .release);
        sh.consumed.store(seq + 1, .release);
        done += 1;
        if (done % every == 0 or seq + 1 == end) {
            if (keep) |k| if (seq + 1 > k) ix.pruneBelow(seq + 1 - k);
            const now = nowNs();
            const anon = rssAnonKb(io) >> 10;
            peak_anon = @max(peak_anon, anon);
            const rate = @as(f64, @floatFromInt(done - n_last)) / (@as(f64, @floatFromInt(now - t_last)) / 1e9);
            std.debug.print("history-bench: at {d} done {d} {d:.0} cp/s txs {d} segments {d} heap {d} MiB anon {d} MiB\n", .{ seq, done, rate, ix.txCount(), ix.segmentCount(), ix.memoryBytes() >> 20, anon });
            t_last = now;
            n_last = done;
        }
    }
    sh.stop.store(true, .release);
    for (threads.items) |t| t.join();
    const secs = @as(f64, @floatFromInt(nowNs() - t0)) / 1e9;
    std.debug.print("history-bench: indexed {d} checkpoints in {d:.0} s ({d:.0} cp/s), tip {?d}, peak anon {d} MiB\n", .{ done, secs, @as(f64, @floatFromInt(done)) / @max(secs, 1e-9), ix.indexedHi(), peak_anon });
    // A sample read on the newest checkpoint.
    {
        var r = ix.reader();
        defer r.release();
        if (r.range()) |rg| if (r.checkpointTxs(rg.hi)) |t| if (t.count > 0) {
            const row = r.txRow(t.first).?;
            const t1 = nowNs();
            const got = r.txSeqOfDigest(&row.digest);
            std.debug.print("history-bench: range {d}..{d}; digest lookup {?d} in {d} us\n", .{ rg.lo, rg.hi, got, (nowNs() - t1) / 1000 });
        };
    }
    ix.deinit();
    const t_re = nowNs();
    ix = try lhist.Index.init(gpa, io, d);
    std.debug.print("history-bench: reopen {d} ms, indexed {?d}..{?d}, segments {d}, heap {d} MiB, anon {d} MiB\n", .{ (nowNs() - t_re) / std.time.ns_per_ms, ix.indexedLo(), ix.indexedHi(), ix.segmentCount(), ix.memoryBytes() >> 20, rssAnonKb(io) >> 10 });
    bucketTimes(ix);
    ix.deinit();
    return rc;
}
