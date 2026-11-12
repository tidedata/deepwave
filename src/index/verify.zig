//! verify: is a node's StateService index right? (`deepwave-tool verify-index`)
//!
//! The index is a function of the live object set only (root.zig), so the check builds a second
//! one from the store's live set and compares every row:
//!
//! 1. The serving index (`<node dir>/state-index`) is opened read-only (`lsm.Options.read_only`:
//!    nothing in it is created, removed or written) and its durable watermark W is read: the
//!    checkpoint its rows on disk are at.
//! 2. A second index is built in a scratch directory from the live set as of W, by the path a
//!    node without a restore image builds from (`store.LiveScan`, then the partitioned bulk
//!    build, bulk.zig). After a clean stop W is the store tip and the scan is the live table as
//!    it is. After an unclean stop W is below the tip and the scan resolves every object to the
//!    version live at W through the records' previous-version links (what `deepwave-tool state-hash`
//!    and the snapshot writer do for an epoch end), so both sides are at the same checkpoint
//!    and no stored checkpoint is replayed. None of this reads an object by (id, version), the
//!    lookup whose failure left stale rows (`feed.changesFromStore`, missing_old).
//! 3. Both indexes are walked in key order and every row compared: owner rows (owner, type,
//!    object id -> version), balance rows (owner, coin type -> coin and address sums) and the
//!    coin wrapper rows. A row only in the serving index is stale, one only in the scratch
//!    build is missing.
//!
//! Needs: the node stopped (the caller holds `node/LOCK` and has opened the store); private
//! memory of 8 bytes per live-table entry for the scan (about 6 GiB on mainnet) plus the build
//! budget plus the store's decoded-chunk cache and what the open store and serving index hold
//! (`memoryNeed`: 8.2 GiB plus that base on mainnet, printed before the build;
//! the resident size reads far higher, by the mapped store files, which are page cache the
//! kernel takes back; the check prints both, `MemWatch`); scratch disk for one more index, and more while the
//! build's row files and its first tables exist together (the check asks for twice the serving
//! index plus 1 GiB free and refuses below that); time of one index build from the live table
//! plus one sequential read of both indexes.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const serve = @import("serve");
const index = @import("root.zig");
const lsm = @import("lsm.zig");

const typestr = serve.typestr;

/// Examples kept (and printed) per kind of difference.
pub const max_examples = 20;

/// The scratch index goes into this directory under the caller's scratch directory.
pub const scratch_sub = "verify-index";

pub const Class = enum(u8) {
    owner_stale,
    owner_missing,
    owner_version,
    balance_stale,
    balance_missing,
    balance_differs,
    coin_stale,
    coin_missing,

    pub fn title(c: Class) []const u8 {
        return switch (c) {
            .owner_stale => "owner rows only in the serving index (stale)",
            .owner_missing => "owner rows only in the scratch build (missing)",
            .owner_version => "owner rows with another version",
            .balance_stale => "balance rows only in the serving index (stale)",
            .balance_missing => "balance rows only in the scratch build (missing)",
            .balance_differs => "balance rows that differ",
            .coin_stale => "coin wrapper rows only in the serving index (stale)",
            .coin_missing => "coin wrapper rows only in the scratch build (missing)",
        };
    }
};
pub const n_classes = @intFromEnum(Class.coin_missing) + 1;

/// One differing row: its index key and the value on each side (null: no such row there).
pub const Example = struct { key: []const u8, serving: ?lsm.Val, scratch: ?lsm.Val };

/// Distinct (owner, type) pairs kept for the affected list (the rest are only counted).
pub const max_affected = 100_000;

pub const Diff = struct {
    arena: std.heap.ArenaAllocator,
    /// Distinct keys seen (the union of both indexes), and the rows of each side.
    compared: u64 = 0,
    serving_rows: u64 = 0,
    scratch_rows: u64 = 0,
    /// Balance rows of the serving index that sum to zero and are kept (a coin type emptied by
    /// an applied checkpoint stays listed until a bottom merge drops the row, as sui-node keeps
    /// it until a compaction). A build from a live set has none, and they are not differences:
    /// counted here, in none of the numbers above.
    held_zero: u64 = 0,
    counts: [n_classes]u64 = @splat(0),
    examples: [n_classes]std.ArrayList(Example) = @splat(.empty),
    /// Every (owner, type) with a differing owner row and every (owner, coin type) with a
    /// differing balance row, once each, in key order: `table || kind? || owner || bcs(type)`
    /// (the row's key without what follows the type). The first `max_affected` are kept.
    affected: std.ArrayList([]const u8) = .empty,
    affected_total: u64 = 0,
    last_affected: std.ArrayList(u8) = .empty,

    pub fn init(gpa: Allocator) Diff {
        return .{ .arena = .init(gpa) };
    }

    pub fn deinit(d: *Diff) void {
        d.arena.deinit();
    }

    pub fn count(d: *const Diff, c: Class) u64 {
        return d.counts[@intFromEnum(c)];
    }

    pub fn examplesOf(d: *const Diff, c: Class) []const Example {
        return d.examples[@intFromEnum(c)].items;
    }

    pub fn stale(d: *const Diff) u64 {
        return d.count(.owner_stale) + d.count(.balance_stale) + d.count(.coin_stale);
    }

    pub fn missing(d: *const Diff) u64 {
        return d.count(.owner_missing) + d.count(.balance_missing) + d.count(.coin_missing);
    }

    pub fn differing(d: *const Diff) u64 {
        return d.count(.owner_version) + d.count(.balance_differs);
    }

    pub fn identical(d: *const Diff) bool {
        return d.stale() + d.missing() + d.differing() == 0;
    }

    /// The part of a differing row's key that names its owner and type (null: a coin wrapper
    /// row, which has no owner, or a key that does not parse).
    fn affectedKey(key: []const u8) ?[]const u8 {
        if (key.len == 0) return null;
        if (key[0] == @intFromEnum(index.Table.balance)) return if (key.len > 33) key else null;
        if (key[0] != @intFromEnum(index.Table.owner) or key.len <= 34) return null;
        const row = splitOwner(key[34..]) orelse return null;
        return key[0 .. 34 + row.ty_bcs.len];
    }

    fn note(d: *Diff, c: Class, key: []const u8, serving: ?lsm.Val, scratch: ?lsm.Val) !void {
        const i = @intFromEnum(c);
        d.counts[i] += 1;
        // differences come in key order, so the rows of one (owner, type) follow each other
        if (affectedKey(key)) |ak| if (!std.mem.eql(u8, ak, d.last_affected.items)) {
            const a = d.arena.allocator();
            d.last_affected.clearRetainingCapacity();
            try d.last_affected.appendSlice(a, ak);
            d.affected_total += 1;
            if (d.affected.items.len < max_affected) try d.affected.append(a, try a.dupe(u8, ak));
        };
        if (d.examples[i].items.len >= max_examples) return;
        const a = d.arena.allocator();
        try d.examples[i].append(a, .{ .key = try a.dupe(u8, key), .serving = serving, .scratch = scratch });
    }

    /// The counts, then the first `max_examples` rows of every kind of difference.
    pub fn print(d: *const Diff, w: *std.Io.Writer) !void {
        try w.print("rows compared: {d} (serving index {d}, scratch build {d})\n", .{ d.compared, d.serving_rows, d.scratch_rows });
        if (d.held_zero != 0) try w.print("balance rows emptied to zero that the serving index keeps until a bottom merge (not differences, not compared): {d}\n", .{d.held_zero});
        for (0..n_classes) |i| {
            const c: Class = @enumFromInt(i);
            try w.print("{s}: {d}\n", .{ c.title(), d.counts[i] });
        }
        var arena_state = std.heap.ArenaAllocator.init(d.arena.child_allocator);
        defer arena_state.deinit();
        for (0..n_classes) |i| {
            const c: Class = @enumFromInt(i);
            const ex = d.examples[i].items;
            if (ex.len == 0) continue;
            try w.print("\n{s}, first {d} of {d}:\n", .{ c.title(), ex.len, d.counts[i] });
            for (ex) |e| {
                _ = arena_state.reset(.retain_capacity);
                try printExample(arena_state.allocator(), w, c, e);
            }
        }
    }

    /// The affected list for a script, one line per (owner, type), tab separated:
    /// `affected <list> <owner> <type>`. `<list>` says which listing of that owner is wrong:
    /// `owned` (objects of an address, the type is the object type), `fields` (objects under
    /// a parent object) or `balance` (the type is the coin type). Nothing when nothing differs.
    pub fn printAffected(d: *const Diff, w: *std.Io.Writer) !void {
        if (d.affected_total == 0) return;
        try w.print("\nowners affected: {d} (owner, type) pairs", .{d.affected_total});
        if (d.affected_total > d.affected.items.len) try w.print(", the first {d} listed", .{d.affected.items.len});
        try w.writeAll("; lines start with \"affected\", tab separated: list, owner, type\n");
        var arena_state = std.heap.ArenaAllocator.init(d.arena.child_allocator);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        for (d.affected.items) |k| {
            _ = arena_state.reset(.retain_capacity);
            if (k[0] == @intFromEnum(index.Table.balance)) {
                try w.print("affected\tbalance\t0x{x}\t{s}\n", .{ k[1..33], typeText(a, k[33..]) });
            } else {
                const list: []const u8 = if (k[1] == @intFromEnum(index.Kind.object)) "fields" else "owned";
                try w.print("affected\t{s}\t0x{x}\t{s}\n", .{ list, k[2..34], structText(a, k[34..]) });
            }
        }
    }
};

fn classOf(key: []const u8, serving: bool, both: bool) Class {
    const table: u8 = if (key.len > 0) key[0] else 2;
    return switch (table) {
        @intFromEnum(index.Table.owner) => if (both) .owner_version else if (serving) .owner_stale else .owner_missing,
        @intFromEnum(index.Table.balance) => if (both) .balance_differs else if (serving) .balance_stale else .balance_missing,
        // the coin table; a row of both sides there is the same row (it has no value)
        else => if (serving) .coin_stale else .coin_missing,
    };
}

/// Whether a key both indexes hold has the same value in both.
fn sameValue(key: []const u8, a: lsm.Val, b: lsm.Val) bool {
    const table: u8 = if (key.len > 0) key[0] else 2;
    if (table == @intFromEnum(index.Table.balance)) {
        const x = a.pair();
        const y = b.pair();
        return x[0] == y[0] and x[1] == y[1];
    }
    if (table == @intFromEnum(index.Table.owner)) return std.mem.eql(u8, a.bytes(), b.bytes());
    return true;
}

/// A balance row whose sums are zero: readers of the index see it (ListBalances lists the coin
/// type with a zero balance) until a merge into the bottom of the tree drops it.
fn heldZero(key: []const u8, v: lsm.Val) bool {
    return key.len > 0 and key[0] == @intFromEnum(index.Table.balance) and v.zeroSum();
}

/// Rows walked so far (a progress line reads it from another thread).
pub const Progress = struct { rows: std.atomic.Value(u64) = .init(0) };

/// Compares every live row of `serving` with `scratch` (both walked once in key order; nothing
/// is written to either) and records the differences in `d`.
pub fn diffDbs(gpa: Allocator, serving: *const lsm.Db, scratch: *const lsm.Db, d: *Diff, progress: ?*Progress) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var x = try serving.iter(a, "");
    var y = try scratch.iter(a, "");
    // an entry's key is valid until its own iterator's next call
    var ex = try x.next();
    var ey = try y.next();
    while (ex != null or ey != null) {
        const ord: std.math.Order = if (ex == null) .gt else if (ey == null) .lt else std.mem.order(u8, ex.?.key, ey.?.key);
        // a kept zero balance row the build does not have: the serving index's own, not stale
        if (ord == .lt and heldZero(ex.?.key, ex.?.val)) {
            d.held_zero += 1;
            ex = try x.next();
            continue;
        }
        d.compared += 1;
        if (progress) |p| if (d.compared & 0xffff == 0) p.rows.store(d.compared, .monotonic);
        switch (ord) {
            .lt => {
                const e = ex.?;
                d.serving_rows += 1;
                try d.note(classOf(e.key, true, false), e.key, e.val, null);
                ex = try x.next();
            },
            .gt => {
                const e = ey.?;
                d.scratch_rows += 1;
                try d.note(classOf(e.key, false, false), e.key, null, e.val);
                ey = try y.next();
            },
            .eq => {
                const e = ex.?;
                const g = ey.?;
                d.serving_rows += 1;
                d.scratch_rows += 1;
                if (!sameValue(e.key, e.val, g.val)) try d.note(classOf(e.key, true, true), e.key, e.val, g.val);
                ex = try x.next();
                ey = try y.next();
            },
        }
    }
    if (progress) |p| p.rows.store(d.compared, .monotonic);
}

// ---------------------------------------------------------------------------- examples

fn tagText(a: Allocator, t: types.TypeTag) []const u8 {
    var cap: usize = 256;
    while (cap <= 1 << 20) : (cap *= 4) {
        const buf = a.alloc(u8, cap) catch return "?";
        var o: typestr.Out = .{ .buf = buf };
        typestr.typeTag(&o, t) catch continue;
        return o.str();
    }
    return "?";
}

fn hexText(a: Allocator, b: []const u8) []const u8 {
    return std.fmt.allocPrint(a, "bcs {x}", .{b}) catch "?";
}

/// The canonical string of a BCS StructTag (an owner row's type), or its bytes in hex.
fn structText(a: Allocator, ty_bcs: []const u8) []const u8 {
    const t = bcs.decode(types.StructTag, a, ty_bcs) catch return hexText(a, ty_bcs);
    return tagText(a, .{ .@"struct" = t });
}

/// The canonical string of a BCS TypeTag (a coin type), or its bytes in hex.
fn typeText(a: Allocator, tag_bcs: []const u8) []const u8 {
    const t = bcs.decode(types.TypeTag, a, tag_bcs) catch return hexText(a, tag_bcs);
    return tagText(a, t);
}

/// An owner-index suffix split into type, coin balance and object id; null if it is not one.
fn splitOwner(suffix: []const u8) ?index.OwnerRow {
    var r = bcs.Reader.init(suffix);
    bcs.skip(types.StructTag, &r) catch return null;
    const tl = r.pos();
    if (tl >= suffix.len) return null;
    const rest: usize = if (suffix[tl] == 1) 1 + 8 + 32 else 1 + 32;
    if (suffix.len != tl + rest) return null;
    return index.splitOwnerSuffix(suffix) catch null;
}

fn printExample(a: Allocator, w: *std.Io.Writer, c: Class, e: Example) !void {
    const key = e.key;
    switch (c) {
        .owner_stale, .owner_missing, .owner_version => {
            const row = if (key.len > 34) splitOwner(key[34..]) else null;
            const o = row orelse return w.print("  key {x}\n", .{key});
            const kind: []const u8 = if (key[1] == @intFromEnum(index.Kind.object)) "parent object" else "address";
            try w.print("  owner 0x{x} ({s}) type {s} object 0x{x}", .{ key[2..34], kind, structText(a, o.ty_bcs), o.id });
            if (o.balance) |b| try w.print(" coin balance {d}", .{b});
            if (c == .owner_version) {
                try w.print(" version: serving {d}, scratch {d}\n", .{ e.serving.?.version(), e.scratch.?.version() });
            } else {
                const v = if (e.serving) |s| s else e.scratch.?;
                try w.print(" version {d}\n", .{v.version()});
            }
        },
        .balance_stale, .balance_missing, .balance_differs => {
            if (key.len < 34) return w.print("  key {x}\n", .{key});
            try w.print("  owner 0x{x} coin type {s}:", .{ key[1..33], typeText(a, key[33..]) });
            if (e.serving) |s| {
                const p = s.pair();
                try w.print(" serving coins {d} address balance {d}", .{ p[0], p[1] });
            }
            if (e.serving != null and e.scratch != null) try w.writeAll(",");
            if (e.scratch) |s| {
                const p = s.pair();
                try w.print(" scratch coins {d} address balance {d}", .{ p[0], p[1] });
            }
            try w.writeAll("\n");
        },
        .coin_stale, .coin_missing => {
            if (key.len < 2 + 32) return w.print("  key {x}\n", .{key});
            const what: []const u8 = switch (key[1]) {
                @intFromEnum(index.CoinWrapper.metadata) => "CoinMetadata",
                @intFromEnum(index.CoinWrapper.treasury) => "TreasuryCap",
                @intFromEnum(index.CoinWrapper.regulated) => "RegulatedCoinMetadata",
                else => "wrapper",
            };
            try w.print("  {s} of coin type {s} object 0x{x}\n", .{ what, typeText(a, key[2 .. key.len - 32]), key[key.len - 32 ..] });
        },
    }
}

// ---------------------------------------------------------------------------- free space

const StatVfs = switch (builtin.os.tag) {
    .linux => extern struct {
        f_bsize: c_ulong,
        f_frsize: c_ulong,
        f_blocks: u64,
        f_bfree: u64,
        f_bavail: u64,
        f_files: u64,
        f_ffree: u64,
        f_favail: u64,
        f_fsid: c_ulong,
        f_flag: c_ulong,
        f_namemax: c_ulong,
        spare: [6]c_int,
        /// Room beyond the libc's struct, whatever it appends.
        pad: [128]u8,
    },
    else => extern struct {
        f_bsize: c_ulong,
        f_frsize: c_ulong,
        f_blocks: c_uint,
        f_bfree: c_uint,
        f_bavail: c_uint,
        f_files: c_uint,
        f_ffree: c_uint,
        f_favail: c_uint,
        f_fsid: c_ulong,
        f_flag: c_ulong,
        f_namemax: c_ulong,
        pad: [128]u8,
    },
};
extern "c" fn statvfs(path: [*:0]const u8, buf: *StatVfs) c_int;

/// Bytes an unprivileged process can still write under `path` (statvfs: 64-bit Linux and macOS).
pub fn freeBytes(path: []const u8) !u64 {
    if (builtin.os.tag != .linux and !builtin.os.tag.isDarwin()) return error.Unsupported;
    if (@sizeOf(c_ulong) != 8) return error.Unsupported;
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const z = std.fmt.bufPrintSentinel(&pb, "{s}", .{path}, 0) catch return error.NameTooLong;
    var sv: StatVfs = undefined;
    if (statvfs(z, &sv) != 0) return error.StatFailed;
    const unit: u64 = if (sv.f_frsize != 0) sv.f_frsize else sv.f_bsize;
    return @as(u64, sv.f_bavail) *| unit;
}

// ---------------------------------------------------------------------------- memory

/// Resident memory of this process by kind (kB, Linux /proc/self/status). `anon` is private
/// memory (what the check needs); `file` is pages of mapped files (the live table, the runs and
/// uncompressed segments: clean page cache the kernel reclaims under pressure, counted in the
/// resident size all the same). `hwm` is the kernel's peak of the total.
pub const Rss = struct { anon_kb: u64 = 0, file_kb: u64 = 0, shmem_kb: u64 = 0, hwm_kb: u64 = 0 };

fn kbOf(s: []const u8) u64 {
    const t = std.mem.trim(u8, s, " \t");
    const end = std.mem.indexOfScalar(u8, t, ' ') orelse t.len;
    return std.fmt.parseInt(u64, t[0..end], 10) catch 0;
}

/// The RssAnon, RssFile, RssShmem and VmHWM lines of a /proc/<pid>/status text.
pub fn parseStatus(text: []const u8) Rss {
    var m: Rss = .{};
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, "RssAnon:")) m.anon_kb = kbOf(line["RssAnon:".len..]);
        if (std.mem.startsWith(u8, line, "RssFile:")) m.file_kb = kbOf(line["RssFile:".len..]);
        if (std.mem.startsWith(u8, line, "RssShmem:")) m.shmem_kb = kbOf(line["RssShmem:".len..]);
        if (std.mem.startsWith(u8, line, "VmHWM:")) m.hwm_kb = kbOf(line["VmHWM:".len..]);
    }
    return m;
}

/// This process's resident memory now (null: not Linux, or /proc is not there).
pub fn readRss() ?Rss {
    if (builtin.os.tag != .linux) return null;
    const fd = std.c.open("/proc/self/status", .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    if (fd < 0) return null;
    defer _ = std.c.close(fd);
    var buf: [8192]u8 = undefined;
    var n: usize = 0;
    while (n < buf.len) {
        const r = std.c.read(fd, buf[n..].ptr, buf.len - n);
        if (r <= 0) break;
        n += @intCast(r);
    }
    return parseStatus(buf[0..n]);
}

/// The MemAvailable line of a /proc/meminfo text, in bytes (null: not there).
pub fn parseMemAvailable(text: []const u8) ?u64 {
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, "MemAvailable:")) return kbOf(line["MemAvailable:".len..]) << 10;
    }
    return null;
}

/// Memory this machine can still give a process without swapping (Linux MemAvailable: free
/// plus reclaimable page cache; null elsewhere). A cgroup limit below it is not seen.
pub fn availableMemory() ?u64 {
    if (builtin.os.tag != .linux) return null;
    const fd = std.c.open("/proc/meminfo", .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    if (fd < 0) return null;
    defer _ = std.c.close(fd);
    var buf: [4096]u8 = undefined;
    var n: usize = 0;
    while (n < buf.len) {
        const r = std.c.read(fd, buf[n..].ptr, buf.len - n);
        if (r <= 0) break;
        n += @intCast(r);
    }
    return parseMemAvailable(buf[0..n]);
}

/// The peaks of the anonymous and the file-backed resident size while the check runs: the
/// kernel keeps a peak of the total only (VmHWM), so a thread samples the two once a second.
const MemWatch = struct {
    anon_kb: std.atomic.Value(u64) = .init(0),
    file_kb: std.atomic.Value(u64) = .init(0),
    done: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,

    fn sample(m: *MemWatch) ?Rss {
        const r = readRss() orelse return null;
        if (r.anon_kb > m.anon_kb.load(.monotonic)) m.anon_kb.store(r.anon_kb, .monotonic);
        if (r.file_kb + r.shmem_kb > m.file_kb.load(.monotonic)) m.file_kb.store(r.file_kb + r.shmem_kb, .monotonic);
        return r;
    }

    fn start(m: *MemWatch) void {
        if (builtin.is_test or builtin.os.tag != .linux) return;
        m.thread = std.Thread.spawn(.{}, main, .{m}) catch null;
    }

    fn stop(m: *MemWatch) void {
        m.done.store(true, .release);
        if (m.thread) |th| th.join();
        m.thread = null;
    }

    fn main(m: *MemWatch) void {
        var n: u64 = 0;
        while (!m.done.load(.acquire)) : (n += 1) {
            const ts: std.posix.timespec = .{ .sec = 0, .nsec = 200 * std.time.ns_per_ms };
            _ = std.c.nanosleep(&ts, null);
            if (n % 5 == 0) _ = m.sample();
        }
    }
};

/// Allowance, where the process cannot measure itself, for what the open store holds besides
/// its memtables (per-segment chunk directories and history dictionaries, its batch map).
const store_other_mem: u64 = 256 << 20;

// ---------------------------------------------------------------------------- the check

pub const Outcome = enum(u8) {
    /// Every row of the serving index equals the scratch build's.
    identical = 0,
    different = 1,
    /// Nothing was compared: no index, an unfinished build, a watermark the store cannot give
    /// the live set of, a scratch directory in use, or too little scratch space.
    cannot_check = 3,
};

pub const Options = struct {
    /// The node's serving index (`<node dir>/state-index`). Opened read-only.
    state_dir: []const u8,
    /// A directory of the operator's; the second index is built in `<scratch>/verify-index`
    /// (which must not exist or be empty) and removed afterwards.
    scratch: []const u8,
    /// Build threads (0: one per CPU, at most 32) and the build's memory budget.
    threads: usize = 0,
    build_mem_bytes: usize = 2 << 30,
    /// Leave the scratch index where it is (to look at it).
    keep_scratch: bool = false,
    /// Tests: the free space of the scratch directory.
    free_override: ?u64 = null,
    /// Tests: the machine's available memory.
    mem_override: ?u64 = null,
};

pub const Result = struct {
    outcome: Outcome,
    /// The serving index's durable watermark and the store's tip.
    watermark: ?u64 = null,
    tip: ?u64 = null,
    /// Live objects the scratch index was built from.
    objects: u64 = 0,
    /// The store's last close was clean (`lastStop`).
    clean_stop: bool = false,
    /// The private memory the check said it needs (`memoryNeed`; 0: it stopped before that).
    mem_need: u64 = 0,
    diff: ?Diff = null,

    pub fn deinit(r: *Result) void {
        if (r.diff) |*d| d.deinit();
    }
};

/// How the last process that had the store open left it, from what this open found: clean
/// when the live table was marked closed cleanly and recovery replayed and cut nothing (what a
/// stopped node's clean stop leaves, node edge_stop_tests). That process is the node unless a
/// deepwave-tool command that closes the store (info, prune, db-checkpoint, ...) ran since.
pub fn lastStop(st: *const store.Store) struct { clean: bool, marked_clean: bool, replayed_groups: u64, truncated_bytes: u64, rebuilt: bool } {
    const x = &st.stats;
    return .{
        .clean = x.open_clean and x.replayed_groups == 0 and x.truncated_bytes == 0 and !x.rebuilt_index,
        .marked_clean = x.open_clean,
        .replayed_groups = x.replayed_groups,
        .truncated_bytes = x.truncated_bytes,
        .rebuilt = x.rebuilt_index,
    };
}

/// The scratch space the check wants free before it starts: twice the serving index (the
/// build's row files, then its tables, bulk.zig) plus 1 GiB.
pub fn scratchNeed(serving_bytes: u64) u64 {
    return 2 * serving_bytes + (1 << 30);
}

/// The private (anonymous) memory the check needs at its peak, the end of the read: `base`
/// (what the process holds once the store and the serving index are open: the store's
/// memtables, chunk directories and history dictionaries, the serving index's block index),
/// 8 bytes per live-table entry (live objects and tombstones) for the scan's sorted
/// locations, the build budget (the lanes while it reads; the sorters after, when the scan's
/// part is gone), and the chunk cache. Each build thread adds one decoded chunk and one
/// compression context (under 1 MiB). Mainnet, 775M entries, 2 GiB, 256 MiB: 8.2 GiB + base.
pub fn memoryNeed(entries: u64, build_mem: u64, cache_mem: u64, base: u64) u64 {
    return entries * 8 + build_mem + cache_mem + base;
}

fn nowMs() u64 {
    return lsm.nowMs();
}

/// The live set as of the scan's checkpoint, part by part, for the bulk build.
const ScanSource = struct {
    sc: *store.LiveScan,
    objects: std.atomic.Value(u64) = .init(0),
    /// Guards the scan against its release (the progress line reads it from another thread).
    lock: lsm.SpinLock = .{},
    released: bool = false,

    const Part = struct {
        sink: lsm.Sink,
        n: u64 = 0,
        fn each(p: *Part, o: store.LiveIter.Item) anyerror!void {
            p.n += 1;
            try p.sink.f(p.sink.ctx, &o.id, o.version, o.bytes);
        }
    };

    fn walk(ctx: *anyopaque, part: u32, parts: u32, sink: lsm.Sink) anyerror!void {
        const s: *ScanSource = @ptrCast(@alignCast(ctx));
        var p: Part = .{ .sink = sink };
        try s.sc.walkPart(part, parts, &p, Part.each);
        _ = s.objects.fetchAdd(p.n, .monotonic);
    }

    /// `lsm.Source.release`: every row is read. The scan's locations (8 bytes a live-table
    /// entry) go before the build sorts, so the sort runs in the budget alone.
    fn release(ctx: *anyopaque) void {
        const s: *ScanSource = @ptrCast(@alignCast(ctx));
        s.drop();
    }

    fn drop(s: *ScanSource) void {
        s.lock.lock();
        defer s.lock.unlock();
        if (s.released) return;
        s.released = true;
        s.sc.deinit();
    }

    /// Entries read and in all (null: the read is over).
    fn progress(s: *ScanSource) ?[2]u64 {
        s.lock.lock();
        defer s.lock.unlock();
        if (s.released) return null;
        return .{ s.sc.scanned.load(.monotonic), s.sc.total() };
    }
};

/// A line on stderr every 10 s while the scratch build (`scan` set) or the comparison runs.
/// Stopped (joined) before what it reads goes away.
const Ticker = struct {
    scan: ?*ScanSource = null,
    rows: Progress = .{},
    done: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,
    t0: u64 = 0,

    fn start(t: *Ticker) void {
        t.t0 = nowMs();
        if (builtin.is_test) return;
        t.thread = std.Thread.spawn(.{}, main, .{t}) catch null;
    }

    fn stop(t: *Ticker) void {
        t.done.store(true, .release);
        if (t.thread) |th| th.join();
        t.thread = null;
    }

    fn main(t: *Ticker) void {
        var n: u64 = 0;
        while (!t.done.load(.acquire)) {
            const ts: std.posix.timespec = .{ .sec = 0, .nsec = 200 * std.time.ns_per_ms };
            _ = std.c.nanosleep(&ts, null);
            n += 1;
            if (n % 50 != 0) continue;
            const s = (nowMs() - t.t0) / 1000;
            if (t.scan) |src| {
                if (src.progress()) |p| {
                    std.debug.print("verify-index: scratch build: {d} of {d} live-table entries read, {d} s\n", .{ p[0], p[1], s });
                } else std.debug.print("verify-index: scratch build: rows read, sorting and writing the tables, {d} s\n", .{s});
            } else std.debug.print("verify-index: {d} rows compared, {d} s\n", .{ t.rows.rows.load(.monotonic), s });
        }
    }
};

fn dirInUse(io: std.Io, path: []const u8) !bool {
    var d = std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch |e| switch (e) {
        error.FileNotFound => return false,
        else => return e,
    };
    defer d.close(io);
    var it = d.iterate();
    return (try it.next(io)) != null;
}

/// Checks the serving index under `opts.state_dir` against the live set of `st` (the node's
/// store, opened by the caller, who holds the node directory's lock: the node is stopped).
/// Writes what it finds to `w`; the store and the serving index are only read.
pub fn run(gpa: Allocator, io: std.Io, st: *store.Store, opts: Options, w: *std.Io.Writer) !Result {
    var path_arena = std.heap.ArenaAllocator.init(gpa);
    defer path_arena.deinit();
    const pa = path_arena.allocator();
    const cwd = std.Io.Dir.cwd();

    // 1. The serving index, read-only.
    cwd.access(io, try std.fs.path.join(pa, &.{ opts.state_dir, "meta" }), .{}) catch {
        try w.print("no state index at {s} (a node run with --no-indexes, or one that never built it)\nverdict: NOT CHECKED\n", .{opts.state_dir});
        return .{ .outcome = .cannot_check };
    };
    const serving = index.Index.open(gpa, io, opts.state_dir, .{ .read_only = true, .sync = .none }) catch |e| {
        try w.print("the state index at {s} does not open: {s}\nverdict: NOT CHECKED\n", .{ opts.state_dir, @errorName(e) });
        return .{ .outcome = .cannot_check };
    };
    defer {
        serving.deinit();
        gpa.destroy(serving);
    }
    var snap = st.snapshot();
    const tip = snap.highestCommitted();
    const lowest = snap.lowestAvailable();
    snap.release();
    var res: Result = .{ .outcome = .cannot_check, .watermark = serving.db.watermark(), .tip = tip };
    const serving_bytes = serving.db.diskBytes();
    const ls = lastStop(st);
    res.clean_stop = ls.clean;
    if (ls.clean) {
        try w.writeAll("last stop: clean (the store was closed cleanly: nothing replayed or cut at this open)\n");
    } else try w.print("last stop: NOT clean (live table {s}, {d} commit groups replayed at this open, {d} bytes of torn tail cut{s})\n", .{
        if (ls.marked_clean) "marked closed cleanly" else "not marked closed cleanly", ls.replayed_groups, ls.truncated_bytes, if (ls.rebuilt) ", live table rebuilt from the logs" else "",
    });
    try w.print("serving index: {s}, watermark {?d}, {d} runs, {d} MiB on disk; store tip {?d}\n", .{ opts.state_dir, res.watermark, serving.db.runs.items.len, serving_bytes >> 20, tip });
    if (serving.db.buildPending() != null) {
        try w.writeAll("the state index holds an unfinished build (the node resumes it at its next start): nothing to compare yet\nverdict: NOT CHECKED\n");
        return res;
    }
    const wm = res.watermark orelse {
        try w.writeAll("the state index has no watermark (never built): nothing to compare\nverdict: NOT CHECKED\n");
        return res;
    };
    const top = tip orelse {
        try w.writeAll("the store is empty: nothing to compare\nverdict: NOT CHECKED\n");
        return res;
    };
    if (wm > top) {
        try w.print("the state index is ahead of the store (watermark {d}, store tip {d}): the node rebuilds it at its next start\nverdict: NOT CHECKED\n", .{ wm, top });
        return res;
    }
    if (wm < top) {
        // The live set as of W needs every version that was live at W: those superseded
        // after W are still in the store while the object floor and the stored checkpoints
        // have not passed W.
        const obj_floor = st.obj_floor.load(.acquire);
        const low = lowest orelse top;
        if (wm + 1 < obj_floor or wm + 1 < low) {
            try w.print("the state index is at checkpoint {d}, below what the store still holds (object floor {d}, lowest available checkpoint {d}): the live set as of {d} cannot be read, and the node rebuilds the index at its next start\nverdict: NOT CHECKED\n", .{ wm, obj_floor, low, wm });
            return res;
        }
        try w.print("the state index is {d} checkpoints behind the store (it was not level when the node stopped): comparing it as it is on disk, at checkpoint {d}; the node replays {d}..{d} at its next start\n", .{ top - wm, wm, wm + 1, top });
    }

    // 2. What the scratch build needs.
    const entries = st.liveSlots().used;
    const scan_mem = entries * 8;
    const need = scratchNeed(serving_bytes);
    try cwd.createDirPath(io, opts.scratch);
    const free: u64 = if (opts.free_override) |f| f else freeBytes(opts.scratch) catch |e| {
        try w.print("free space of {s} is not known ({s})\nverdict: NOT CHECKED\n", .{ opts.scratch, @errorName(e) });
        return res;
    };
    const build_mem: u64 = opts.build_mem_bytes;
    const cache_mem: u64 = st.cfg.cache_bytes;
    const table_bytes = st.liveSlots().pages * 4096;
    var watch: MemWatch = .{};
    defer watch.stop();
    // What is held already, with the store and the serving index open: measured where the
    // kernel says (the first full-size runs held about 1 GB more than an estimate that
    // counted the scan, the budget and the cache alone), else added up.
    const memtables = st.indexMemory().memtables;
    const serving_mem = serving.db.indexMemory();
    const now = if (builtin.is_test) null else watch.sample();
    const base: u64 = if (now) |r| r.anon_kb << 10 else memtables + serving_mem + store_other_mem;
    const mem_need = memoryNeed(entries, build_mem, cache_mem, base);
    res.mem_need = mem_need;
    try w.print("needs: about {d} MiB of private memory at its peak, the end of the read: {d} MiB held now ({s}: the store's memtables {d} MiB, the serving index's block index {d} MiB, the rest the store's chunk directories and history dictionaries), {d} MiB for the scan (8 bytes for each of {d} live-table entries, freed before the sort), {d} MiB build budget, up to {d} MiB of decoded store chunks\n", .{
        mem_need >> 20, base >> 20, if (now != null) "RssAnon" else "estimated", memtables >> 20, serving_mem >> 20, scan_mem >> 20, entries, build_mem >> 20, cache_mem >> 20,
    });
    try w.print("needs {d} MiB of scratch disk (twice the serving index plus 1 GiB); {s} has {d} MiB free\n", .{ need >> 20, opts.scratch, free >> 20 });
    try w.print("the resident size (RSS) will read higher than the private memory: the live table ({d} MiB) and any uncompressed segments are mapped files, and the pages read from them count as resident though they are page cache the kernel takes back\n", .{table_bytes >> 20});
    if (now) |r| try w.print("memory at start: private (RssAnon) {d} MiB, mapped files (RssFile) {d} MiB\n", .{ r.anon_kb >> 10, (r.file_kb + r.shmem_kb) >> 10 });
    if (opts.mem_override orelse availableMemory()) |avail| {
        try w.print("available memory: {d} MiB\n", .{avail >> 20});
        // MemAvailable does not count what this process holds already
        if (avail < mem_need - base) {
            try w.print("not enough memory: {d} MiB available, about {d} MiB more needed than is held now (a smaller --build-mem-mb lowers it by that much; the scan's {d} MiB cannot shrink)\nverdict: NOT CHECKED\n", .{ avail >> 20, (mem_need - base) >> 20, scan_mem >> 20 });
            return res;
        }
    }
    if (free < need) {
        try w.print("not enough scratch space: {d} MiB free in {s}, {d} MiB needed\nverdict: NOT CHECKED\n", .{ free >> 20, opts.scratch, need >> 20 });
        return res;
    }
    const scratch_dir = try std.fs.path.join(pa, &.{ opts.scratch, scratch_sub });
    if (try dirInUse(io, scratch_dir)) {
        try w.print("{s} is not empty (an earlier run that was cut off?): remove it and run again\nverdict: NOT CHECKED\n", .{scratch_dir});
        return res;
    }
    try w.flush();

    // 3. The second index, from the live set as of the serving index's watermark.
    const t0 = nowMs();
    const scratch = index.Index.open(gpa, io, scratch_dir, .{ .build_threads = opts.threads, .build_mem_bytes = opts.build_mem_bytes, .sync = .none }) catch |e| {
        cwd.deleteTree(io, scratch_dir) catch {};
        return e;
    };
    defer {
        scratch.deinit();
        gpa.destroy(scratch);
        if (!opts.keep_scratch) cwd.deleteTree(io, scratch_dir) catch |e| std.log.warn("verify-index: could not remove {s}: {s}", .{ scratch_dir, @errorName(e) });
    }
    var rows: u64 = 0;
    {
        // versions superseded after the watermark must stay while the scan follows them
        st.agePause(true);
        defer st.agePause(false);
        watch.start();
        var sc = try store.LiveScan.init(gpa, st, wm + 1);
        var src: ScanSource = .{ .sc = &sc };
        defer src.drop();
        var ticker: Ticker = .{ .scan = &src };
        ticker.start();
        defer ticker.stop();
        const rep = try lsm.Builder.runFrom(&scratch.db, .{ .ctx = &src, .at = wm, .walk = ScanSource.walk, .release = ScanSource.release }, index.rowsOf);
        std.log.info("verify-index: build memory: lanes of {d} walkers {d} MiB, {d} sort workers at most {d} MiB, budget {d} MiB", .{ rep.walkers, rep.lane_bytes >> 20, rep.sort_workers, rep.sort_bytes >> 20, opts.build_mem_bytes >> 20 });
        res.objects = src.objects.load(.monotonic);
        rows = rep.entries;
    }
    const t1 = nowMs();
    try w.print("scratch build: {d} live objects as of checkpoint {d}, {d} rows, {d} MiB on disk, {d} s\n", .{ res.objects, wm, rows, scratch.db.diskBytes() >> 20, (t1 - t0) / 1000 });
    try w.flush();

    // 4. Every row of both.
    var d = Diff.init(gpa);
    errdefer d.deinit();
    {
        var ticker: Ticker = .{};
        ticker.start();
        defer ticker.stop();
        try diffDbs(gpa, &serving.db, &scratch.db, &d, &ticker.rows);
    }
    try d.print(w);
    watch.stop();
    if (watch.sample()) |r| try w.print("\nmemory peak: private (RssAnon) {d} MiB, mapped files (RssFile, reclaimable page cache) {d} MiB, sampled once a second; resident total (VmHWM) {d} MiB\n", .{
        watch.anon_kb.load(.monotonic) >> 10, watch.file_kb.load(.monotonic) >> 10, r.hwm_kb >> 10,
    });
    const secs = (nowMs() - t1) / 1000;
    if (d.identical()) {
        try w.print("verdict: IDENTICAL: the state index at checkpoint {d} equals a build from the store's live set ({d} rows compared in {d} s)\n", .{ wm, d.compared, secs });
        res.outcome = .identical;
    } else {
        try d.printAffected(w);
        try w.print("verdict: DIFFERENT: the state index at checkpoint {d} has {d} stale, {d} missing and {d} differing rows against a build from the store's live set ({d} rows compared in {d} s)\n", .{ wm, d.stale(), d.missing(), d.differing(), d.compared, secs });
        res.outcome = .different;
    }
    res.diff = d;
    return res;
}
