//! Where the follower's ordered thread spends a checkpoint (lane catchup-io): wall time and major
//! page faults (blocking reads through a mapping) per stage, from the thread's own counters
//! (getrusage RUSAGE_THREAD on Linux; time only elsewhere). The status line prints the
//! per-checkpoint averages of the last interval, so a catch-up that is bound by queue-depth-1
//! faults names the stage that takes them.
//!
//! `mark(stage)` charges everything since the previous mark to `stage`. Writer: the ordered
//! thread only. Reader: the status loop (`take`), through atomics.
const std = @import("std");
const builtin = @import("builtin");
const Atomic = std.atomic.Value(u64);

pub const Stage = enum(u8) {
    /// Between checkpoints: the follower waiting for the next checked one, chain checks.
    wait,
    retention,
    clean,
    /// StateService index changes (`index.feed.Feed.prepare`).
    ix_prepare,
    ledger,
    rpc,
    /// The rest of on_checkpoint (latency rings, executor submit, end of epoch).
    misc,
    /// The follower's batch: checkpoint, transactions, puts and removes (live-table lookups).
    apply,
    history,
    state_hash,
    commit,
    /// on_committed: index publish, snapshot start.
    publish,
};
const n_stages = std.enums.values(Stage).len;

pub const Prof = struct {
    flt: [n_stages]Atomic = @splat(.init(0)),
    ns: [n_stages]Atomic = @splat(.init(0)),
    cps: Atomic = .init(0),
    // ordered thread only
    last_flt: u64 = 0,
    last_ns: u64 = 0,
    started: bool = false,
    // status loop only
    prev_flt: [n_stages]u64 = @splat(0),
    prev_ns: [n_stages]u64 = @splat(0),
    prev_cps: u64 = 0,

    pub fn mark(p: *Prof, st: Stage) void {
        const f = majflt();
        const t = nowNs();
        if (p.started) {
            _ = p.flt[@intFromEnum(st)].fetchAdd(f -| p.last_flt, .monotonic);
            _ = p.ns[@intFromEnum(st)].fetchAdd(t -| p.last_ns, .monotonic);
        }
        p.started = true;
        p.last_flt = f;
        p.last_ns = t;
    }

    pub fn checkpoint(p: *Prof) void {
        _ = p.cps.fetchAdd(1, .monotonic);
    }

    /// Writes " | ordered thread per cp (major faults/us): stage f/us ..." for the interval since
    /// the last call (stages with neither faults nor time left out).
    pub fn take(p: *Prof, w: anytype) void {
        const cps = p.cps.load(.monotonic);
        const d = cps -| p.prev_cps;
        p.prev_cps = cps;
        var fl: [n_stages]u64 = undefined;
        var ns: [n_stages]u64 = undefined;
        var tf: u64 = 0;
        for (0..n_stages) |i| {
            const f = p.flt[i].load(.monotonic);
            const t = p.ns[i].load(.monotonic);
            fl[i] = f -| p.prev_flt[i];
            ns[i] = t -| p.prev_ns[i];
            p.prev_flt[i] = f;
            p.prev_ns[i] = t;
            tf += fl[i];
        }
        if (d == 0) return;
        w.print(" | ordered thread per cp (major faults/us): total {d}/", .{tf / d}) catch {};
        var tns: u64 = 0;
        for (ns) |x| tns += x;
        w.print("{d}", .{tns / d / 1000}) catch {};
        for (0..n_stages) |i| {
            if (fl[i] / d == 0 and ns[i] / d < 20_000) continue;
            w.print(" {s} {d}/{d}", .{ @tagName(@as(Stage, @enumFromInt(i))), fl[i] / d, ns[i] / d / 1000 }) catch {};
        }
    }
};

/// Major faults of the calling thread (0 off Linux).
pub fn majflt() u64 {
    if (builtin.os.tag != .linux) return 0;
    const linux = std.os.linux;
    var ru: linux.rusage = undefined;
    if (linux.errno(linux.getrusage(1, &ru)) != .SUCCESS) return 0; // RUSAGE_THREAD
    return @intCast(ru.majflt);
}

fn nowNs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

test "stageprof: charges intervals to stages and prints per-checkpoint averages" {
    var p: Prof = .{};
    p.mark(.wait);
    p.mark(.apply);
    p.checkpoint();
    var buf: [512]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    p.take(&w);
    try std.testing.expect(std.mem.startsWith(u8, w.buffered(), " | ordered thread per cp"));
    w = std.Io.Writer.fixed(&buf);
    p.take(&w); // no checkpoint since: nothing
    try std.testing.expectEqual(@as(usize, 0), w.buffered().len);
}
