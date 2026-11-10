//! Tile rings: a single-producer broadcast ring of 32-byte fragment descriptors (mcache), a payload
//! arena of 64-byte chunks (dcache) and credit-based flow control from consumer sequence words
//! (fseq + fctl). ARCHITECTURE.md 7.2.
//!
//! Design:
//!   - A descriptor is one half cache line: seq, sig (an application tag consumers filter on
//!     without touching the payload), chunk, sz, ctl, tsorig, tspub. Line = seq & (depth - 1).
//!   - The producer never waits on a lock and never learns who reads: it stores seq - 1 into the
//!     line (the line is "being written"), the fields, then seq. A consumer loads seq, copies the
//!     line, loads seq again; equal and == expected means a whole descriptor. Ahead of expected
//!     means the producer lapped it (overrun), behind means nothing new yet.
//!   - Payloads are written once into the arena and read in place. A consumer that reads a
//!     payload checks the line's seq again afterwards (speculative read): if the producer lapped
//!     it meanwhile, the bytes may be torn and the frag is dropped as an overrun.
//!   - Reliable consumers publish how far they got in their own cache-line-padded seq word; the
//!     producer computes credits (how many frags it may publish without lapping the slowest
//!     reliable consumer) from those words only now and then, not per frag.
//! No locks, no allocation and no syscalls on the data path. Memory is caller-provided, so the
//! same structures can later live in a shared-memory workspace.
const std = @import("std");
const builtin = @import("builtin");

pub const cache_line = std.atomic.cache_line;

/// One descriptor, 32 bytes. All fields are accessed atomically (relaxed loads and stores
/// compile to plain moves on x86-64 and aarch64), so a racing read is defined, only stale.
pub const FragMeta = extern struct {
    seq: u64,
    sig: u64,
    chunk: u32,
    sz: u16,
    ctl: u16,
    tsorig: u32,
    tspub: u32,

    comptime {
        std.debug.assert(@sizeOf(FragMeta) == 32);
    }
};

pub const ctl_som: u16 = 1; // start of message
pub const ctl_eom: u16 = 2; // end of message
pub const ctl_err: u16 = 4;

/// Wrapping sequence comparison: > 0 when a is after b.
pub inline fn seqDiff(a: u64, b: u64) i64 {
    return @bitCast(a -% b);
}

pub const Mcache = struct {
    lines: []align(64) FragMeta,
    mask: u64,

    /// `lines.len` must be a power of two. Every line starts as "never published" relative to
    /// seq0: a consumer starting at seq0 or later waits cleanly instead of seeing an overrun.
    pub fn init(lines: []align(64) FragMeta, seq0: u64) Mcache {
        std.debug.assert(lines.len >= 2 and std.math.isPowerOfTwo(lines.len));
        const n: u64 = lines.len;
        for (lines) |*l| l.* = .{ .seq = 0, .sig = 0, .chunk = 0, .sz = 0, .ctl = ctl_som | ctl_eom | ctl_err, .tsorig = 0, .tspub = 0 };
        // Line s & mask holds s - depth (one lap behind) for s in [seq0, seq0 + depth).
        var i: u64 = 0;
        while (i < n) : (i += 1) {
            const s = seq0 +% i;
            lines[@intCast(s & (n - 1))].seq = s -% n;
        }
        return .{ .lines = lines, .mask = n - 1 };
    }

    pub inline fn depth(m: *const Mcache) u64 {
        return m.mask + 1;
    }

    inline fn line(m: *const Mcache, seq: u64) *FragMeta {
        return &m.lines[@intCast(seq & m.mask)];
    }

    /// Publish frag `seq` (the producer's next sequence number).
    pub inline fn publish(m: *const Mcache, seq: u64, sig: u64, chunk: u32, sz: u16, ctl: u16, tsorig: u32, tspub: u32) void {
        const l = m.line(seq);
        @atomicStore(u64, &l.seq, seq -% 1, .monotonic);
        // Release on each field keeps the "being written" mark ahead of the new contents (a
        // store-store order; free on x86-64, stlr on aarch64).
        @atomicStore(u64, &l.sig, sig, .release);
        @atomicStore(u32, &l.chunk, chunk, .release);
        @atomicStore(u16, &l.sz, sz, .release);
        @atomicStore(u16, &l.ctl, ctl, .release);
        @atomicStore(u32, &l.tsorig, tsorig, .release);
        @atomicStore(u32, &l.tspub, tspub, .release);
        @atomicStore(u64, &l.seq, seq, .release);
    }

    pub const Poll = union(enum) {
        /// `out` holds frag `seq`.
        ready,
        /// The producer has not published `seq` yet.
        empty,
        /// The producer lapped the consumer: the line now holds this later seq.
        overrun: u64,
    };

    /// One non-blocking look at frag `seq`.
    pub inline fn poll(m: *const Mcache, seq: u64, out: *FragMeta) Poll {
        const l = m.line(seq);
        const s0 = @atomicLoad(u64, &l.seq, .acquire);
        out.sig = @atomicLoad(u64, &l.sig, .monotonic);
        out.chunk = @atomicLoad(u32, &l.chunk, .monotonic);
        out.sz = @atomicLoad(u16, &l.sz, .monotonic);
        out.ctl = @atomicLoad(u16, &l.ctl, .monotonic);
        out.tsorig = @atomicLoad(u32, &l.tsorig, .monotonic);
        out.tspub = @atomicLoad(u32, &l.tspub, .acquire); // orders the loads above before s1
        const s1 = @atomicLoad(u64, &l.seq, .monotonic);
        out.seq = s0;
        const d = seqDiff(s0, seq);
        if (s0 == s1 and d == 0) return .ready;
        if (d < 0) return .empty;
        if (s0 != s1) return if (seqDiff(s1, seq) > 0) .{ .overrun = s1 } else .empty;
        return .{ .overrun = s0 };
    }

    /// After reading a payload in place: true iff the producer has not lapped `seq` meanwhile.
    pub inline fn stillValid(m: *const Mcache, seq: u64) bool {
        return @atomicLoad(u64, &m.line(seq).seq, .acquire) == seq;
    }
};

/// Payload arena in 64-byte chunks. Chunk numbers are relative to `base`, so they stay valid
/// across processes that map the arena at different addresses.
pub const Dcache = struct {
    base: [*]align(64) u8,
    chunk0: u32,
    /// Highest chunk a frag may start at (data_len / 64 - chunks of one max-size frag).
    wmark: u32,

    pub const chunk_sz = 64;

    /// `data` must hold at least `depth + 1` frags of `mtu` bytes so a payload is not reused
    /// before its descriptor is lapped.
    pub fn init(data: []align(64) u8, mtu: usize) Dcache {
        const chunks: u32 = @intCast(data.len / chunk_sz);
        const per = chunksFor(mtu);
        std.debug.assert(chunks >= per);
        return .{ .base = data.ptr, .chunk0 = 0, .wmark = chunks - per };
    }

    pub inline fn chunksFor(sz: usize) u32 {
        return @intCast((sz + chunk_sz - 1) / chunk_sz);
    }

    /// Footprint for depth descriptors of mtu bytes.
    pub fn dataSize(mtu: usize, depth: usize) usize {
        return (depth + 1) * @as(usize, chunksFor(mtu)) * chunk_sz;
    }

    pub inline fn ptr(d: *const Dcache, chunk: u32) [*]align(64) u8 {
        return @alignCast(d.base + @as(usize, chunk) * chunk_sz);
    }

    /// The chunk after a frag of `sz` bytes at `chunk`, wrapping to chunk0 past the watermark.
    pub inline fn next(d: *const Dcache, chunk: u32, sz: usize) u32 {
        const n = chunk + chunksFor(sz);
        return if (n > d.wmark) d.chunk0 else n;
    }
};

/// A consumer's progress word, alone on its cache line pair.
pub const Fseq = struct {
    seq: u64 align(2 * cache_line) = 0,
    _pad: [2 * cache_line - 8]u8 = undefined,

    pub inline fn update(f: *Fseq, seq: u64) void {
        @atomicStore(u64, &f.seq, seq, .release);
    }
    pub inline fn query(f: *const Fseq) u64 {
        return @atomicLoad(u64, &f.seq, .acquire);
    }
};

/// Producer-side flow control: credits = depth - (tx_seq - slowest reliable rx seq).
/// The producer refreshes credits only when it runs out, so the consumers' words are read once
/// per refresh, not once per frag.
pub const Fctl = struct {
    rx: []const *const Fseq,
    depth: u64,
    credits: u64 = 0,

    pub inline fn refresh(f: *Fctl, tx_seq: u64) u64 {
        var slowest: u64 = std.math.maxInt(u64);
        for (f.rx) |r| {
            const lag: u64 = @intCast(@max(0, seqDiff(tx_seq, r.query())));
            slowest = @min(slowest, f.depth -| lag);
        }
        f.credits = if (f.rx.len == 0) f.depth else slowest;
        return f.credits;
    }
};

// ---------------------------------------------------------------------------------------------
// Tests

const testing = std.testing;

test "ring: publish and poll, empty, overrun" {
    var lines: [8]FragMeta align(64) = undefined;
    const m = Mcache.init(&lines, 100);
    var out: FragMeta = undefined;
    try testing.expect(m.poll(100, &out) == .empty);
    for (100..105) |s| m.publish(s, s * 3, @intCast(s), 7, ctl_som | ctl_eom, 0, 0);
    for (100..105) |s| {
        try testing.expect(m.poll(s, &out) == .ready);
        try testing.expectEqual(@as(u64, s * 3), out.sig);
    }
    try testing.expect(m.poll(105, &out) == .empty);
    // lap the ring: seq 100 is overwritten by 108
    for (105..112) |s| m.publish(s, 0, 0, 0, 0, 0, 0);
    switch (m.poll(100, &out)) {
        .overrun => |s| try testing.expectEqual(@as(u64, 108), s),
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(!m.stillValid(100));
}

test "ring: wrapping sequence numbers" {
    var lines: [4]FragMeta align(64) = undefined;
    const seq0: u64 = std.math.maxInt(u64) - 1;
    const m = Mcache.init(&lines, seq0);
    var out: FragMeta = undefined;
    var s = seq0;
    for (0..6) |i| {
        try testing.expect(m.poll(s, &out) == .empty);
        m.publish(s, i, 0, 0, 0, 0, 0);
        try testing.expect(m.poll(s, &out) == .ready);
        s +%= 1;
    }
}

const Pair = struct {
    m: Mcache,
    d: Dcache,
    fs: Fseq = .{},
};

fn producer(p: *Pair, n: u64) void {
    const rx = [_]*const Fseq{&p.fs};
    var fc: Fctl = .{ .rx = &rx, .depth = p.m.depth() };
    var chunk = p.d.chunk0;
    var seq: u64 = 0;
    while (seq < n) {
        if (fc.credits == 0) {
            if (fc.refresh(seq) == 0) {
                std.atomic.spinLoopHint();
                continue;
            }
        }
        const sz: u16 = @intCast(9 + seq % 119);
        const dst = p.d.ptr(chunk);
        std.mem.writeInt(u64, dst[0..8], seq ^ 0x9e3779b97f4a7c15, .little);
        @memset(dst[8..sz], @truncate(seq));
        p.m.publish(seq, seq, chunk, sz, ctl_som | ctl_eom, 0, 0);
        chunk = p.d.next(chunk, sz);
        seq += 1;
        fc.credits -= 1;
    }
}

test "ring: reliable consumer with flow control sees every frag intact" {
    var lines: [64]FragMeta align(64) = undefined;
    const mtu = 128;
    var data: [Dcache.dataSize(mtu, 64)]u8 align(64) = undefined;
    var p: Pair = .{ .m = Mcache.init(&lines, 0), .d = Dcache.init(&data, mtu) };
    const n: u64 = 200_000;
    const t = try std.Thread.spawn(.{}, producer, .{ &p, n });
    var out: FragMeta = undefined;
    var seq: u64 = 0;
    while (seq < n) {
        switch (p.m.poll(seq, &out)) {
            .empty => std.atomic.spinLoopHint(),
            .overrun => return error.TestUnexpectedResult, // flow control forbids it
            .ready => {
                const src = p.d.ptr(out.chunk);
                try testing.expectEqual(seq ^ 0x9e3779b97f4a7c15, std.mem.readInt(u64, src[0..8], .little));
                try testing.expectEqual(@as(u8, @truncate(seq)), src[out.sz - 1]);
                seq += 1;
                if (seq % 16 == 0) p.fs.update(seq);
            },
        }
    }
    t.join();
}

// ---------------------------------------------------------------------------------------------
// Bench (ZUI_RING_BENCH=1 ./zig build test -Dlane=rt -Doptimize=ReleaseFast): one-hop latency
// over a ping-pong of two rings, and streaming throughput, against a Mutex + Condition queue
// (what deepwave threads use to hand work over today, e.g. src/node/execute.zig).

fn nowNs() i128 {
    return std.Io.Timestamp.now(std.testing.io, .awake).nanoseconds;
}

fn benchOn() bool {
    const v = std.c.getenv("ZUI_RING_BENCH") orelse return false;
    return v[0] == '1';
}

fn pin(cpu: usize) void {
    if (builtin.os.tag != .linux) return;
    var set: std.os.linux.cpu_set_t = @splat(0);
    set[cpu / @bitSizeOf(usize)] |= @as(usize, 1) << @intCast(cpu % @bitSizeOf(usize));
    std.os.linux.sched_setaffinity(0, &set) catch {};
}

fn cpuArg(name: [*:0]const u8, default: usize) usize {
    const v = std.c.getenv(name) orelse return default;
    return std.fmt.parseInt(usize, std.mem.span(v), 10) catch default;
}

const PingPong = struct {
    a: Mcache,
    b: Mcache,
};

fn echo(pp: *PingPong, n: u64, cpu: usize) void {
    pin(cpu);
    var out: FragMeta = undefined;
    var seq: u64 = 0;
    while (seq < n) {
        if (pp.a.poll(seq, &out) == .ready) {
            pp.b.publish(seq, out.sig, 0, 0, 0, 0, 0);
            seq += 1;
        } else std.atomic.spinLoopHint();
    }
}

const LockQueue = struct {
    mu: std.Io.Mutex = .init,
    cv: std.Io.Condition = .init,
    buf: [64]u64 = undefined,
    head: u64 = 0,
    tail: u64 = 0,

    fn push(q: *LockQueue, v: u64) void {
        const io = std.testing.io;
        q.mu.lockUncancelable(io);
        defer q.mu.unlock(io);
        while (q.tail - q.head == q.buf.len) q.cv.waitUncancelable(io, &q.mu);
        q.buf[q.tail % q.buf.len] = v;
        q.tail += 1;
        q.cv.broadcast(io);
    }
    fn pop(q: *LockQueue) u64 {
        const io = std.testing.io;
        q.mu.lockUncancelable(io);
        defer q.mu.unlock(io);
        while (q.tail == q.head) q.cv.waitUncancelable(io, &q.mu);
        const v = q.buf[q.head % q.buf.len];
        q.head += 1;
        q.cv.broadcast(io);
        return v;
    }
};

fn lockEcho(a: *LockQueue, b: *LockQueue, n: u64, cpu: usize) void {
    pin(cpu);
    for (0..n) |_| b.push(a.pop());
}

fn lockStream(q: *LockQueue, n: u64, cpu: usize) void {
    pin(cpu);
    for (0..n) |i| q.push(i);
}

fn ringStream(p: *Pair, n: u64, cpu: usize) void {
    pin(cpu);
    producer(p, n);
}

test "ring: bench (ZUI_RING_BENCH=1)" {
    if (!benchOn()) return;
    const c0 = cpuArg("ZUI_RING_CPU0", 2);
    const c1 = cpuArg("ZUI_RING_CPU1", 3);
    pin(c0);
    const n: u64 = 2_000_000;
    // ring ping-pong
    {
        var la: [256]FragMeta align(64) = undefined;
        var lb: [256]FragMeta align(64) = undefined;
        var pp: PingPong = .{ .a = Mcache.init(&la, 0), .b = Mcache.init(&lb, 0) };
        const t = try std.Thread.spawn(.{}, echo, .{ &pp, n, c1 });
        var out: FragMeta = undefined;
        const t0 = nowNs();
        var seq: u64 = 0;
        while (seq < n) : (seq += 1) {
            pp.a.publish(seq, seq, 0, 0, 0, 0, 0);
            while (pp.b.poll(seq, &out) != .ready) std.atomic.spinLoopHint();
        }
        const dt: f64 = @floatFromInt(nowNs() - t0);
        t.join();
        std.debug.print("ring_bench ring one-hop latency {d:.1} ns (ping-pong / 2, cpus {d},{d})\n", .{ dt / @as(f64, @floatFromInt(2 * n)), c0, c1 });
    }
    // lock queue ping-pong
    {
        var a: LockQueue = .{};
        var b: LockQueue = .{};
        const m = n / 10;
        const t = try std.Thread.spawn(.{}, lockEcho, .{ &a, &b, m, c1 });
        const t0 = nowNs();
        for (0..m) |i| {
            a.push(i);
            _ = b.pop();
        }
        const dt: f64 = @floatFromInt(nowNs() - t0);
        t.join();
        std.debug.print("ring_bench mutex+condvar one-hop latency {d:.1} ns\n", .{dt / @as(f64, @floatFromInt(2 * m))});
    }
    // ring streaming with 8..127 byte payloads, flow controlled
    {
        var lines: [1024]FragMeta align(64) = undefined;
        const mtu = 128;
        const data = try testing.allocator.alignedAlloc(u8, .@"64", Dcache.dataSize(mtu, 1024));
        defer testing.allocator.free(data);
        var p: Pair = .{ .m = Mcache.init(&lines, 0), .d = Dcache.init(data, mtu) };
        const t = try std.Thread.spawn(.{}, ringStream, .{ &p, n * 5, c1 });
        var out: FragMeta = undefined;
        var seq: u64 = 0;
        var sum: u64 = 0;
        const t0 = nowNs();
        while (seq < n * 5) {
            if (p.m.poll(seq, &out) == .ready) {
                sum +%= std.mem.readInt(u64, p.d.ptr(out.chunk)[0..8], .little);
                seq += 1;
                if (seq % 64 == 0) p.fs.update(seq);
            } else std.atomic.spinLoopHint();
        }
        const dt: f64 = @floatFromInt(nowNs() - t0);
        t.join();
        std.debug.print("ring_bench ring stream {d:.2} ns/frag ({d:.1} M frags/s, sum {x})\n", .{ dt / @as(f64, @floatFromInt(n * 5)), @as(f64, @floatFromInt(n * 5)) * 1e3 / dt, sum });
    }
    // lock queue streaming
    {
        var q: LockQueue = .{};
        const t = try std.Thread.spawn(.{}, lockStream, .{ &q, n, c1 });
        const t0 = nowNs();
        var sum: u64 = 0;
        for (0..n) |_| sum +%= q.pop();
        const dt: f64 = @floatFromInt(nowNs() - t0);
        t.join();
        std.debug.print("ring_bench mutex+condvar stream {d:.2} ns/item (sum {x})\n", .{ dt / @as(f64, @floatFromInt(n)), sum });
    }
}
