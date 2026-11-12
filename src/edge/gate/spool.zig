//! The usage spool (docs/GATE.md "Durability"): every usage counter a node has not had
//! acknowledged by its gate, in memory and journalled to one file in `--gate-dir`.
//!
//! State, oldest first:
//! - `sealed`: at most one batch that has an id and an exact body. It is the only thing ever
//!   sent, and it is sent again with the same id and the same bytes until the gate answers 2xx;
//! - `windows`: closed five-second windows of rows not yet sealed;
//! - `acc`: the window still being counted.
//!
//! The file is an append-only log of checksummed records (delta, cut, window, seal, ack). The
//! meter appends one delta a second and syncs, so a crash loses at most that second; a seal is
//! synced before its first send, so a restart sends the same batch id with the same body. A
//! record that does not check out ends the replay and the file is cut there (a torn tail). The
//! log is rewritten from memory when it holds more dead records than live state.
//!
//! The cap (64 MiB of live state): at the cap the two oldest windows are merged, rows summed by
//! (key id or prefix, method), until it fits. Past that, keyless rows fold into one catch-all
//! prefix per family, and only then are new keyed rows refused (counted, logged by the caller).
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const contract = @import("contract.zig");
const Counters = contract.Counters;

pub const default_cap: u64 = 64 << 20;
pub const file_name = "usage.spool";
pub const tmp_name = "usage.spool.tmp";
const magic = "ZGSPOOL1";

const rec_delta: u8 = 1;
const rec_cut: u8 = 2;
const rec_window: u8 = 3;
const rec_seal: u8 = 4;
const rec_ack: u8 = 5;

/// Rows by `subject \x00 method` (the key is owned), in insertion order.
pub const Rows = std.StringArrayHashMapUnmanaged(Counters);

pub const Window = struct {
    from_ms: u64,
    to_ms: u64,
    rows: Rows = .empty,
};

pub const Sealed = struct {
    id: []u8,
    body: []u8,
    rows: u32,
};

pub const Stats = struct {
    /// Windows merged at the cap, keyless rows folded into a catch-all, rows refused.
    merges: u64 = 0,
    collapsed_rows: u64 = 0,
    dropped_rows: u64 = 0,
    dropped_units: u64 = 0,
    rewrites: u64 = 0,
    /// Bytes cut off the file at open (a torn or damaged tail).
    torn_bytes: u64 = 0,
    replayed: u64 = 0,
    write_errors: u64 = 0,
};

pub const catch_all_v4 = "i0.0.0.0/0";
pub const catch_all_v6 = "i::/0";

fn rowCost(key: []const u8) u64 {
    return key.len + 16;
}

pub fn splitKey(key: []const u8) struct { subject: []const u8, method: []const u8 } {
    const z = std.mem.indexOfScalar(u8, key, 0) orelse return .{ .subject = key, .method = "" };
    return .{ .subject = key[0..z], .method = key[z + 1 ..] };
}

fn putUleb(out: *std.ArrayList(u8), gpa: Allocator, v: u64) !void {
    var x = v;
    while (x >= 0x80) {
        try out.append(gpa, @as(u8, @truncate(x)) | 0x80);
        x >>= 7;
    }
    try out.append(gpa, @intCast(x));
}

const Reader = struct {
    b: []const u8,
    p: usize = 0,

    fn uleb(r: *Reader) !u64 {
        var v: u64 = 0;
        var shift: u7 = 0;
        while (true) {
            if (r.p >= r.b.len or shift > 63) return error.Corrupt;
            const x = r.b[r.p];
            r.p += 1;
            v |= @as(u64, x & 0x7f) << @intCast(shift);
            if (x & 0x80 == 0) return v;
            shift += 7;
        }
    }
    fn bytes(r: *Reader) ![]const u8 {
        const n = try r.uleb();
        if (n > r.b.len - r.p) return error.Corrupt;
        defer r.p += @intCast(n);
        return r.b[r.p..][0..@intCast(n)];
    }
};

pub const Spool = struct {
    gpa: Allocator,
    io: Io,
    dir: ?Io.Dir,
    file: ?Io.File = null,
    end: u64 = 0,
    cap: u64 = default_cap,
    acc: Rows = .empty,
    acc_from_ms: u64 = 0,
    acc_to_ms: u64 = 0,
    windows: std.ArrayList(Window) = .empty,
    sealed: ?Sealed = null,
    /// Size of the live state (rows by their key length, the sealed body).
    live: u64 = 0,
    stats: Stats = .{},
    scratch: std.ArrayList(u8) = .empty,

    /// Opens the spool of `dir` (null: memory only) and replays what a previous run left.
    pub fn open(gpa: Allocator, io: Io, dir: ?Io.Dir, cap: u64) !Spool {
        var s: Spool = .{ .gpa = gpa, .io = io, .dir = dir, .cap = cap };
        errdefer s.deinit();
        const d = dir orelse return s;
        // a rewrite a crash stopped before its rename: the log is still the old one
        d.deleteFile(io, tmp_name) catch {};
        const data = d.readFileAlloc(io, file_name, gpa, .limited(1 << 30)) catch |e| switch (e) {
            error.FileNotFound => try gpa.dupe(u8, ""),
            else => return e,
        };
        defer gpa.free(data);
        const good = s.replay(data);
        const f = try d.createFile(io, file_name, .{ .read = true, .truncate = false });
        s.file = f;
        if (good < magic.len) {
            try f.setLength(io, 0);
            try f.writePositionalAll(io, magic, 0);
            try f.sync(io);
            s.stats.torn_bytes = data.len;
            s.end = magic.len;
        } else {
            if (good < data.len) {
                s.stats.torn_bytes = data.len - good;
                try f.setLength(io, good);
                try f.sync(io);
            }
            s.end = good;
        }
        return s;
    }

    pub fn deinit(s: *Spool) void {
        if (s.file) |f| f.close(s.io);
        s.file = null;
        s.freeRows(&s.acc);
        for (s.windows.items) |*w| s.freeRows(&w.rows);
        s.windows.deinit(s.gpa);
        if (s.sealed) |b| {
            s.gpa.free(b.id);
            s.gpa.free(b.body);
        }
        s.sealed = null;
        s.scratch.deinit(s.gpa);
    }

    fn freeRows(s: *Spool, rows: *Rows) void {
        for (rows.keys()) |k| s.gpa.free(k);
        rows.deinit(s.gpa);
        rows.* = .empty;
    }

    // ------------------------------------------------------------ state changes

    fn addRow(s: *Spool, rows: *Rows, key: []const u8, c: Counters) !void {
        const gop = try rows.getOrPut(s.gpa, key);
        if (gop.found_existing) {
            gop.value_ptr.add(c);
            return;
        }
        gop.key_ptr.* = s.gpa.dupe(u8, key) catch |e| {
            rows.swapRemoveAt(gop.index);
            return e;
        };
        gop.value_ptr.* = c;
        s.live += rowCost(key);
    }

    /// Adds one second's counters to the window being counted and journals them. `rows[].subject`
    /// is `k<key id>` or `i<prefix>`.
    pub fn addDelta(s: *Spool, rows: []const contract.Row, from_ms: u64, to_ms: u64) !void {
        if (rows.len == 0) return;
        var kb: std.ArrayList(u8) = .empty;
        defer kb.deinit(s.gpa);
        s.scratch.clearRetainingCapacity();
        try putUleb(&s.scratch, s.gpa, from_ms);
        try putUleb(&s.scratch, s.gpa, to_ms);
        const count_at = s.scratch.items.len;
        // the row count is patched in below as a fixed 5-byte uleb
        try s.scratch.appendSlice(s.gpa, &.{ 0x80, 0x80, 0x80, 0x80, 0x00 });
        var written: u32 = 0;
        const full = s.live >= s.cap;
        const was_empty = s.acc.count() == 0;
        for (rows) |r| {
            if (r.c.zero()) continue;
            kb.clearRetainingCapacity();
            try kb.appendSlice(s.gpa, r.subject);
            try kb.append(s.gpa, 0);
            try kb.appendSlice(s.gpa, r.method);
            if (full and !s.acc.contains(kb.items)) {
                // at the cap with everything merged: a keyless row folds into the catch-all of its
                // family, a keyed row has nowhere to go
                if (r.subject.len > 0 and r.subject[0] == 'i') {
                    kb.clearRetainingCapacity();
                    try kb.appendSlice(s.gpa, if (std.mem.indexOfScalar(u8, r.subject, ':') != null) catch_all_v6 else catch_all_v4);
                    try kb.append(s.gpa, 0);
                    try kb.appendSlice(s.gpa, r.method);
                    s.stats.collapsed_rows += 1;
                } else {
                    s.stats.dropped_rows += 1;
                    s.stats.dropped_units +|= r.c.units;
                    continue;
                }
            }
            try s.addRow(&s.acc, kb.items, r.c);
            try encodeRow(&s.scratch, s.gpa, kb.items, r.c);
            written += 1;
        }
        s.acc_from_ms = if (was_empty or s.acc_from_ms == 0) from_ms else @min(s.acc_from_ms, from_ms);
        s.acc_to_ms = @max(@max(s.acc_to_ms, to_ms), s.acc_from_ms);
        if (written == 0) return;
        var n = written;
        for (s.scratch.items[count_at..][0..4]) |*b| {
            b.* = @as(u8, @truncate(n)) | 0x80;
            n >>= 7;
        }
        s.scratch.items[count_at + 4] = @intCast(n);
        s.append(rec_delta, s.scratch.items);
    }

    /// Closes the window being counted. Nothing happens when it is empty.
    pub fn cut(s: *Spool) !void {
        if (s.acc.count() == 0) return;
        try s.windows.append(s.gpa, .{ .from_ms = s.acc_from_ms, .to_ms = s.acc_to_ms, .rows = s.acc });
        s.acc = .empty;
        s.acc_from_ms = s.acc_to_ms;
        s.append(rec_cut, "");
    }

    /// Makes the next batch (at most `contract.max_batch_rows` rows of the oldest window) when
    /// none is waiting: id `<edge>-<boot>-<counter>`, the body exactly as it will be posted,
    /// journalled and synced before the caller sends it. True when a batch is waiting.
    pub fn seal(s: *Spool, edge: []const u8, boot: []const u8, counter: *u64) !bool {
        if (s.sealed != null) return true;
        while (s.windows.items.len > 0 and s.windows.items[0].rows.count() == 0) {
            var w = s.windows.orderedRemove(0);
            w.rows.deinit(s.gpa);
        }
        if (s.windows.items.len == 0) return false;
        const w = &s.windows.items[0];
        const total = w.rows.count();
        const take: usize = @min(total, contract.max_batch_rows);
        var idb: [contract.max_edge_id_len + 64]u8 = undefined;
        const id = try std.fmt.bufPrint(&idb, "{s}-{s}-{d}", .{ edge, boot, counter.* });
        var body: std.ArrayList(u8) = .empty;
        errdefer body.deinit(s.gpa);
        try contract.usageHead(&body, s.gpa, edge, id, w.from_ms, w.to_ms);
        const keys = w.rows.keys()[total - take ..];
        const vals = w.rows.values()[total - take ..];
        for (keys, vals, 0..) |k, v, i| {
            const sk = splitKey(k);
            try contract.usageRow(&body, s.gpa, i == 0, .{ .subject = sk.subject, .method = sk.method, .c = v });
        }
        try contract.usageTail(&body, s.gpa);
        const id_owned = try s.gpa.dupe(u8, id);
        errdefer s.gpa.free(id_owned);
        const body_owned = try body.toOwnedSlice(s.gpa);
        counter.* += 1;
        s.popRows(w, take);
        s.sealed = .{ .id = id_owned, .body = body_owned, .rows = @intCast(take) };
        s.live += id_owned.len + body_owned.len;
        s.scratch.clearRetainingCapacity();
        try putUleb(&s.scratch, s.gpa, take);
        try putUleb(&s.scratch, s.gpa, id_owned.len);
        try s.scratch.appendSlice(s.gpa, id_owned);
        try putUleb(&s.scratch, s.gpa, body_owned.len);
        try s.scratch.appendSlice(s.gpa, body_owned);
        s.append(rec_seal, s.scratch.items);
        s.sync();
        return true;
    }

    fn popRows(s: *Spool, w: *Window, take: usize) void {
        const total = w.rows.count();
        for (w.rows.keys()[total - take ..]) |k| {
            s.live -|= rowCost(k);
            s.gpa.free(k);
        }
        w.rows.shrinkRetainingCapacity(total - take);
        if (w.rows.count() == 0 and s.windows.items.len > 0 and w == &s.windows.items[0]) {
            var gone = s.windows.orderedRemove(0);
            gone.rows.deinit(s.gpa);
        }
    }

    /// The gate acknowledged the sealed batch.
    pub fn ack(s: *Spool) void {
        const b = s.sealed orelse return;
        s.scratch.clearRetainingCapacity();
        putUleb(&s.scratch, s.gpa, b.id.len) catch {};
        s.scratch.appendSlice(s.gpa, b.id) catch {};
        s.append(rec_ack, s.scratch.items);
        s.dropSealed();
    }

    fn dropSealed(s: *Spool) void {
        const b = s.sealed orelse return;
        s.live -|= b.id.len + b.body.len;
        s.gpa.free(b.id);
        s.gpa.free(b.body);
        s.sealed = null;
    }

    /// Rows waiting (not counting the sealed batch).
    pub fn pendingRows(s: *const Spool) u64 {
        var n: u64 = s.acc.count();
        for (s.windows.items) |*w| n += w.rows.count();
        return n;
    }

    /// The sum of every counter still held, the sealed batch excluded (tests).
    pub fn totals(s: *const Spool) Counters {
        var t: Counters = .{};
        for (s.acc.values()) |v| t.add(v);
        for (s.windows.items) |*w| for (w.rows.values()) |v| t.add(v);
        return t;
    }

    // ------------------------------------------------------------ the cap

    fn mergeOldest(s: *Spool) !void {
        // room first, so the merge itself cannot fail half way
        try s.windows.items[0].rows.ensureUnusedCapacity(s.gpa, s.windows.items[1].rows.count());
        var from = s.windows.orderedRemove(1);
        defer from.rows.deinit(s.gpa);
        const into = &s.windows.items[0];
        into.from_ms = @min(into.from_ms, from.from_ms);
        into.to_ms = @max(into.to_ms, from.to_ms);
        for (from.rows.keys(), from.rows.values()) |k, v| {
            const gop = into.rows.getOrPutAssumeCapacity(k);
            if (gop.found_existing) {
                gop.value_ptr.add(v);
                s.live -|= rowCost(k);
                s.gpa.free(k);
            } else {
                gop.key_ptr.* = k;
                gop.value_ptr.* = v;
            }
        }
        s.stats.merges += 1;
    }

    fn collapse(s: *Spool, rows: *Rows) !void {
        var out: Rows = .empty;
        errdefer out.deinit(s.gpa);
        var kb: std.ArrayList(u8) = .empty;
        defer kb.deinit(s.gpa);
        var live: u64 = 0;
        for (rows.keys(), rows.values()) |k, v| {
            const sk = splitKey(k);
            const keyless = sk.subject.len > 0 and sk.subject[0] == 'i';
            const all = if (std.mem.indexOfScalar(u8, sk.subject, ':') != null) catch_all_v6 else catch_all_v4;
            if (!keyless or std.mem.eql(u8, sk.subject, all)) {
                const gop = try out.getOrPut(s.gpa, k);
                if (gop.found_existing) gop.value_ptr.add(v) else {
                    gop.value_ptr.* = v;
                    live += rowCost(k);
                }
                continue;
            }
            kb.clearRetainingCapacity();
            try kb.appendSlice(s.gpa, all);
            try kb.append(s.gpa, 0);
            try kb.appendSlice(s.gpa, sk.method);
            const gop = try out.getOrPut(s.gpa, kb.items);
            if (gop.found_existing) gop.value_ptr.add(v) else {
                gop.key_ptr.* = try s.gpa.dupe(u8, kb.items);
                gop.value_ptr.* = v;
                live += rowCost(kb.items);
            }
            s.stats.collapsed_rows += 1;
        }
        // keys that moved over are owned by `out` now; free the ones that were folded away
        var old: u64 = 0;
        for (rows.keys()) |k| {
            old += rowCost(k);
            const kept = out.getKey(k);
            if (kept == null or kept.?.ptr != k.ptr) s.gpa.free(k);
        }
        rows.deinit(s.gpa);
        rows.* = out;
        s.live = s.live - @min(s.live, old) + live;
    }

    /// Brings the live state under the cap (merge the oldest windows, then fold keyless rows)
    /// and rewrites the log when it is mostly dead records. Call after a tick.
    pub fn enforce(s: *Spool) void {
        var changed = false;
        while (s.live > s.cap and s.windows.items.len >= 2) {
            s.mergeOldest() catch break;
            changed = true;
        }
        if (s.live > s.cap) {
            for (s.windows.items) |*w| s.collapse(&w.rows) catch {};
            s.collapse(&s.acc) catch {};
            changed = true;
        }
        if (s.file == null) return;
        if (changed or s.end > @max(2 * s.live + (256 << 10), 1 << 20)) s.rewrite() catch |e| {
            s.stats.write_errors += 1;
            std.log.warn("gate: usage spool rewrite failed: {s}", .{@errorName(e)});
        };
    }

    // ------------------------------------------------------------ the log

    fn encodeRow(out: *std.ArrayList(u8), gpa: Allocator, key: []const u8, c: Counters) !void {
        try putUleb(out, gpa, key.len);
        try out.appendSlice(gpa, key);
        inline for (.{ c.local, c.forwarded, c.units, c.limited, c.stream_msgs }) |v| try putUleb(out, gpa, v);
    }

    fn frame(out: *std.ArrayList(u8), gpa: Allocator, kind: u8, payload: []const u8) !void {
        var hdr: [9]u8 = undefined;
        std.mem.writeInt(u32, hdr[0..4], @intCast(payload.len + 1), .little);
        var crc = std.hash.Crc32.init();
        crc.update(&.{kind});
        crc.update(payload);
        std.mem.writeInt(u32, hdr[4..8], crc.final(), .little);
        hdr[8] = kind;
        try out.appendSlice(gpa, &hdr);
        try out.appendSlice(gpa, payload);
    }

    fn append(s: *Spool, kind: u8, payload: []const u8) void {
        const f = s.file orelse return;
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(s.gpa);
        frame(&buf, s.gpa, kind, payload) catch {
            s.stats.write_errors += 1;
            return;
        };
        f.writePositionalAll(s.io, buf.items, s.end) catch {
            s.stats.write_errors += 1;
            return;
        };
        s.end += buf.items.len;
    }

    pub fn sync(s: *Spool) void {
        const f = s.file orelse return;
        f.sync(s.io) catch {
            s.stats.write_errors += 1;
        };
    }

    fn encodeWindow(s: *Spool, out: *std.ArrayList(u8), kind: u8, from_ms: u64, to_ms: u64, rows: *const Rows) !void {
        s.scratch.clearRetainingCapacity();
        try putUleb(&s.scratch, s.gpa, from_ms);
        try putUleb(&s.scratch, s.gpa, to_ms);
        try putUleb(&s.scratch, s.gpa, rows.count());
        for (rows.keys(), rows.values()) |k, v| try encodeRow(&s.scratch, s.gpa, k, v);
        try frame(out, s.gpa, kind, s.scratch.items);
    }

    /// Writes the live state as a new log (temporary file, sync, rename): a crash leaves the old
    /// log or the new one, whole.
    fn rewrite(s: *Spool) !void {
        const d = s.dir orelse return;
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(s.gpa);
        var end: u64 = 0;
        {
            const f = try d.createFile(s.io, tmp_name, .{ .truncate = true });
            defer f.close(s.io);
            try buf.appendSlice(s.gpa, magic);
            if (s.sealed) |b| {
                s.scratch.clearRetainingCapacity();
                try putUleb(&s.scratch, s.gpa, 0);
                try putUleb(&s.scratch, s.gpa, b.id.len);
                try s.scratch.appendSlice(s.gpa, b.id);
                try putUleb(&s.scratch, s.gpa, b.body.len);
                try s.scratch.appendSlice(s.gpa, b.body);
                try frame(&buf, s.gpa, rec_seal, s.scratch.items);
            }
            for (s.windows.items) |*w| {
                try s.encodeWindow(&buf, rec_window, w.from_ms, w.to_ms, &w.rows);
                if (buf.items.len < 1 << 20) continue;
                try f.writePositionalAll(s.io, buf.items, end);
                end += buf.items.len;
                buf.clearRetainingCapacity();
            }
            if (s.acc.count() > 0) try s.encodeWindow(&buf, rec_delta, s.acc_from_ms, s.acc_to_ms, &s.acc);
            try f.writePositionalAll(s.io, buf.items, end);
            end += buf.items.len;
            try f.sync(s.io);
        }
        try d.rename(tmp_name, d, file_name, s.io);
        const nf = try d.createFile(s.io, file_name, .{ .read = true, .truncate = false });
        if (s.file) |old| old.close(s.io);
        s.file = nf;
        s.end = end;
        s.stats.rewrites += 1;
    }

    fn readRows(s: *Spool, r: *Reader, rows: *Rows) !void {
        const n = try r.uleb();
        var i: u64 = 0;
        while (i < n) : (i += 1) {
            const key = try r.bytes();
            var c: Counters = .{};
            inline for (.{ "local", "forwarded", "units", "limited", "stream_msgs" }) |f| @field(c, f) = try r.uleb();
            try s.addRow(rows, key, c);
        }
        if (r.p != r.b.len) return error.Corrupt;
    }

    fn apply(s: *Spool, kind: u8, payload: []const u8) !void {
        var r: Reader = .{ .b = payload };
        switch (kind) {
            rec_delta => {
                const from = try r.uleb();
                const to = try r.uleb();
                const was_empty = s.acc.count() == 0;
                try s.readRows(&r, &s.acc);
                s.acc_from_ms = if (was_empty or s.acc_from_ms == 0) from else @min(s.acc_from_ms, from);
                s.acc_to_ms = @max(@max(s.acc_to_ms, to), s.acc_from_ms);
            },
            rec_cut => {
                if (s.acc.count() == 0) return;
                try s.windows.append(s.gpa, .{ .from_ms = s.acc_from_ms, .to_ms = s.acc_to_ms, .rows = s.acc });
                s.acc = .empty;
                s.acc_from_ms = s.acc_to_ms;
            },
            rec_window => {
                var w: Window = .{ .from_ms = try r.uleb(), .to_ms = try r.uleb() };
                errdefer s.freeRows(&w.rows);
                try s.readRows(&r, &w.rows);
                try s.windows.append(s.gpa, w);
            },
            rec_seal => {
                const take = try r.uleb();
                const id = try r.bytes();
                const body = try r.bytes();
                if (r.p != r.b.len or s.sealed != null) return error.Corrupt;
                if (take > 0) {
                    if (s.windows.items.len == 0 or s.windows.items[0].rows.count() < take) return error.Corrupt;
                    s.popRows(&s.windows.items[0], @intCast(take));
                }
                const id_owned = try s.gpa.dupe(u8, id);
                errdefer s.gpa.free(id_owned);
                s.sealed = .{ .id = id_owned, .body = try s.gpa.dupe(u8, body), .rows = @intCast(take) };
                s.live += id.len + body.len;
            },
            rec_ack => {
                const id = try r.bytes();
                const b = s.sealed orelse return error.Corrupt;
                if (!std.mem.eql(u8, b.id, id)) return error.Corrupt;
                s.dropSealed();
            },
            else => return error.Corrupt,
        }
    }

    /// Applies every whole record of `data`. Returns how many bytes were good.
    fn replay(s: *Spool, data: []const u8) usize {
        if (data.len < magic.len or !std.mem.eql(u8, data[0..magic.len], magic)) return 0;
        var p: usize = magic.len;
        while (data.len - p >= 9) {
            const len = std.mem.readInt(u32, data[p..][0..4], .little);
            if (len == 0 or len > data.len - p - 8) break;
            const body = data[p + 8 ..][0..len];
            if (std.hash.Crc32.hash(body) != std.mem.readInt(u32, data[p + 4 ..][0..4], .little)) break;
            s.apply(body[0], body[1..]) catch break;
            p += 8 + len;
            s.stats.replayed += 1;
        }
        return p;
    }
};

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn row(subject: []const u8, method: []const u8, local: u64, units: u64) contract.Row {
    return .{ .subject = subject, .method = method, .c = .{ .local = local, .units = units } };
}

test "spool: deltas, a cut, a sealed batch with a stable id and body, an ack" {
    const gpa = testing.allocator;
    var s = try Spool.open(gpa, testing.io, null, default_cap);
    defer s.deinit();
    try s.addDelta(&.{ row("kkid_a", "a.A/Get", 3, 3), row("i203.0.113.0/24", "a.A/Get", 1, 1) }, 1000, 2000);
    try s.addDelta(&.{row("kkid_a", "a.A/Get", 2, 2)}, 2000, 3000);
    try testing.expectEqual(@as(u64, 2), s.pendingRows());
    try testing.expectEqual(@as(u64, 5), s.acc.get("kkid_a\x00a.A/Get").?.local);
    var counter: u64 = 7;
    // nothing to seal until a window is closed
    try testing.expect(!try s.seal("e1", "b00t", &counter));
    try s.cut();
    try testing.expect(try s.seal("e1", "b00t", &counter));
    try testing.expectEqualStrings("e1-b00t-7", s.sealed.?.id);
    try testing.expectEqualStrings(
        "{\"edge\":\"e1\",\"batch_id\":\"e1-b00t-7\",\"from_ms\":1000,\"to_ms\":3000,\"rows\":[" ++
            "{\"key_id\":\"kid_a\",\"method\":\"a.A/Get\",\"local\":5,\"forwarded\":0,\"units\":5,\"limited\":0,\"stream_msgs\":0}," ++
            "{\"key_id\":null,\"ip_prefix\":\"203.0.113.0/24\",\"method\":\"a.A/Get\",\"local\":1,\"forwarded\":0,\"units\":1,\"limited\":0,\"stream_msgs\":0}]}",
        s.sealed.?.body,
    );
    // sealing again changes nothing: the same batch waits
    const body_ptr = s.sealed.?.body.ptr;
    try testing.expect(try s.seal("e1", "b00t", &counter));
    try testing.expectEqual(body_ptr, s.sealed.?.body.ptr);
    try testing.expectEqual(@as(u64, 8), counter);
    s.ack();
    try testing.expect(s.sealed == null);
    try testing.expectEqual(@as(u64, 0), s.live);
    try testing.expect(!try s.seal("e1", "b00t", &counter));
    // rows that are all zero are not kept
    try s.addDelta(&.{row("kkid_a", "a.A/Get", 0, 0)}, 3000, 4000);
    try testing.expectEqual(@as(u64, 0), s.pendingRows());
}

test "spool: at most 1,000 rows a batch" {
    const gpa = testing.allocator;
    var s = try Spool.open(gpa, testing.io, null, default_cap);
    defer s.deinit();
    var names: [2500][16]u8 = undefined;
    var rows: [2500]contract.Row = undefined;
    for (&rows, 0..) |*r, i| r.* = row(std.fmt.bufPrint(&names[i], "kkid_{d}", .{i}) catch unreachable, "a.A/Get", 1, 2);
    try s.addDelta(&rows, 10, 20);
    try s.cut();
    var counter: u64 = 0;
    var sizes: [3]u32 = undefined;
    var units: u64 = 0;
    for (&sizes) |*n| {
        try testing.expect(try s.seal("e1", "b", &counter));
        n.* = s.sealed.?.rows;
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const v = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), s.sealed.?.body, .{});
        try testing.expectEqual(@as(usize, n.*), v.object.get("rows").?.array.items.len);
        for (v.object.get("rows").?.array.items) |r| units += @intCast(r.object.get("units").?.integer);
        s.ack();
    }
    try testing.expectEqualSlices(u32, &.{ 1000, 1000, 500 }, &sizes);
    try testing.expectEqual(@as(u64, 5000), units);
    try testing.expect(!try s.seal("e1", "b", &counter));
}

fn reopen(gpa: Allocator, dir: Io.Dir, cap: u64) !Spool {
    return Spool.open(gpa, testing.io, dir, cap);
}

test "spool: a restart finds the unsent batch with the same id and body, and the rest of the rows" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var counter: u64 = 3;
    var want_body: []u8 = &.{};
    defer gpa.free(want_body);
    {
        var s = try reopen(gpa, tmp.dir, default_cap);
        defer s.deinit();
        try s.addDelta(&.{ row("kkid_a", "a.A/Get", 3, 3), row("kkid_b", "a.A/Get", 4, 8) }, 1000, 2000);
        try s.cut();
        try s.addDelta(&.{row("kkid_a", "a.A/Put", 1, 10)}, 2000, 3000);
        try s.cut();
        try s.addDelta(&.{row("i2001:db8:1::/48", "a.A/Get", 6, 6)}, 3000, 4000);
        try testing.expect(try s.seal("e1", "boot1", &counter));
        want_body = try gpa.dupe(u8, s.sealed.?.body);
        s.sync();
        // no clean stop: the process is gone here
    }
    {
        var s = try reopen(gpa, tmp.dir, default_cap);
        defer s.deinit();
        try testing.expectEqualStrings("e1-boot1-3", s.sealed.?.id);
        try testing.expectEqualStrings(want_body, s.sealed.?.body);
        try testing.expectEqual(@as(usize, 1), s.windows.items.len);
        try testing.expectEqual(@as(u64, 10), s.windows.items[0].rows.get("kkid_a\x00a.A/Put").?.units);
        try testing.expectEqual(@as(u64, 6), s.acc.get("i2001:db8:1::/48\x00a.A/Get").?.local);
        try testing.expectEqual(@as(u64, 3000), s.acc_from_ms);
        try testing.expectEqual(@as(u64, 4000), s.acc_to_ms);
        try testing.expectEqual(@as(u64, 0), s.stats.torn_bytes);
        // the new boot acknowledges the old batch and goes on with its own ids
        s.ack();
        var c2: u64 = 0;
        try testing.expect(try s.seal("e1", "boot2", &c2));
        try testing.expectEqualStrings("e1-boot2-0", s.sealed.?.id);
    }
    {
        // and the ack is durable too
        var s = try reopen(gpa, tmp.dir, default_cap);
        defer s.deinit();
        try testing.expectEqualStrings("e1-boot2-0", s.sealed.?.id);
        try testing.expectEqual(@as(usize, 0), s.windows.items.len);
        try testing.expectEqual(@as(u64, 1), s.pendingRows());
    }
}

test "spool: a torn tail after a crash is cut off, everything before it is kept" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    var good_len: u64 = 0;
    {
        var s = try reopen(gpa, tmp.dir, default_cap);
        defer s.deinit();
        try s.addDelta(&.{row("kkid_a", "a.A/Get", 3, 3)}, 1000, 2000);
        try s.addDelta(&.{row("kkid_a", "a.A/Get", 4, 4)}, 2000, 3000);
        good_len = s.end;
        try s.addDelta(&.{row("kkid_b", "a.A/Get", 50, 50)}, 3000, 4000);
        s.sync();
    }
    const whole = try tmp.dir.readFileAlloc(io, file_name, gpa, .unlimited);
    defer gpa.free(whole);
    // every way the last record can be torn: cut anywhere inside it
    var cut_at: usize = @intCast(good_len + 1);
    while (cut_at < whole.len) : (cut_at += 1) {
        try tmp.dir.writeFile(io, .{ .sub_path = file_name, .data = whole[0..cut_at] });
        var s = try reopen(gpa, tmp.dir, default_cap);
        defer s.deinit();
        try testing.expectEqual(@as(u64, 7), s.acc.get("kkid_a\x00a.A/Get").?.local);
        try testing.expect(s.acc.get("kkid_b\x00a.A/Get") == null);
        try testing.expectEqual(@as(u64, cut_at - good_len), s.stats.torn_bytes);
        try testing.expectEqual(good_len, s.end);
    }
    // a flipped bit in the last record: the checksum catches it
    {
        const bad = try gpa.dupe(u8, whole);
        defer gpa.free(bad);
        bad[bad.len - 3] ^= 0x10;
        try tmp.dir.writeFile(io, .{ .sub_path = file_name, .data = bad });
        var s = try reopen(gpa, tmp.dir, default_cap);
        defer s.deinit();
        try testing.expectEqual(@as(u64, 7), s.acc.get("kkid_a\x00a.A/Get").?.local);
        try testing.expect(s.acc.get("kkid_b\x00a.A/Get") == null);
        // the file was cut at the damage, and new records follow the good ones
        try s.addDelta(&.{row("kkid_c", "a.A/Get", 1, 1)}, 4000, 5000);
        s.sync();
    }
    {
        var s = try reopen(gpa, tmp.dir, default_cap);
        defer s.deinit();
        try testing.expectEqual(@as(u64, 1), s.acc.get("kkid_c\x00a.A/Get").?.local);
        try testing.expectEqual(@as(u64, 0), s.stats.torn_bytes);
    }
    // a file that is not a spool at all starts empty
    try tmp.dir.writeFile(io, .{ .sub_path = file_name, .data = "garbage that is not a spool" });
    var s = try reopen(gpa, tmp.dir, default_cap);
    defer s.deinit();
    try testing.expectEqual(@as(u64, 0), s.pendingRows());
    try testing.expectEqual(@as(u64, magic.len), s.end);
}

test "spool: at the cap the oldest windows merge by (subject, method); nothing is lost" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // 40 keys a window, the same keys every window: about 1.3 KiB of rows a window
    const cap: u64 = 4 << 10;
    var s = try reopen(gpa, tmp.dir, cap);
    defer s.deinit();
    var names: [40][16]u8 = undefined;
    var rows: [40]contract.Row = undefined;
    for (&rows, 0..) |*r, i| r.* = row(std.fmt.bufPrint(&names[i], "kkid_{d:0>3}", .{i}) catch unreachable, "a.A/Get", 1, 2);
    var w: u64 = 0;
    while (w < 50) : (w += 1) {
        try s.addDelta(&rows, 1000 * w, 1000 * (w + 1));
        try s.cut();
        s.enforce();
        try testing.expect(s.live <= cap);
    }
    try testing.expect(s.stats.merges > 0);
    try testing.expectEqual(@as(u64, 0), s.stats.dropped_rows);
    try testing.expectEqual(@as(u64, 0), s.stats.collapsed_rows);
    // every call and unit is still there, and the oldest window spans what was merged into it
    const t = s.totals();
    try testing.expectEqual(@as(u64, 50 * 40), t.local);
    try testing.expectEqual(@as(u64, 50 * 40 * 2), t.units);
    try testing.expectEqual(@as(u64, 0), s.windows.items[0].from_ms);
    try testing.expect(s.windows.items[0].rows.get("kkid_007\x00a.A/Get").?.local > 1);
    try testing.expect(s.stats.rewrites > 0);
    // the merged state is what a restart reads back
    const before = s.totals();
    const nwin = s.windows.items.len;
    s.sync();
    var again = try reopen(gpa, tmp.dir, cap);
    defer again.deinit();
    try testing.expectEqual(before, again.totals());
    try testing.expectEqual(nwin, again.windows.items.len);
    try testing.expectEqual(@as(u64, 0), again.stats.torn_bytes);
}

test "spool: past merging, keyless rows fold into a catch-all and keyed rows are counted as refused" {
    const gpa = testing.allocator;
    const cap: u64 = 2 << 10;
    var s = try Spool.open(gpa, testing.io, null, cap);
    defer s.deinit();
    var nb: [32]u8 = undefined;
    // distinct prefixes without end: an address flood
    var i: u32 = 0;
    while (i < 2000) : (i += 1) {
        const subj = std.fmt.bufPrint(&nb, "i10.{d}.{d}.0/24", .{ i / 256, i % 256 }) catch unreachable;
        try s.addDelta(&.{row(subj, "a.A/Get", 1, 1)}, i, i + 1);
        if (i % 10 == 9) try s.cut();
        s.enforce();
    }
    try testing.expect(s.live <= cap + 128);
    try testing.expect(s.stats.collapsed_rows > 0);
    try testing.expectEqual(@as(u64, 2000), s.totals().local);
    var found = false;
    for (s.windows.items) |*w| {
        if (w.rows.get(catch_all_v4 ++ "\x00a.A/Get")) |c| found = found or c.local > 0;
    }
    try testing.expect(found or s.acc.get(catch_all_v4 ++ "\x00a.A/Get") != null);
    // distinct keys without end cannot be folded: counted, never silently gone
    const units_before = s.totals().units;
    i = 0;
    while (i < 2000) : (i += 1) {
        const subj = std.fmt.bufPrint(&nb, "kkid_{d}", .{i}) catch unreachable;
        try s.addDelta(&.{row(subj, "a.A/Get", 1, 3)}, 5000 + i, 5001 + i);
        s.enforce();
    }
    try testing.expect(s.stats.dropped_rows > 0);
    try testing.expectEqual(units_before + 3 * 2000, s.totals().units + s.stats.dropped_units);
}

test "spool: the default cap is 64 MiB and holds for windows of the same rows" {
    try testing.expectEqual(@as(u64, 64 << 20), default_cap);
    // (the general-purpose allocator: 1.4 million rows through the leak checker take too long)
    const gpa = std.heap.smp_allocator;
    var s = try Spool.open(gpa, testing.io, null, default_cap);
    defer s.deinit();
    // 20,000 rows a window of about 1.2 MiB: the cap is reached after some 55 windows
    const n = 20_000;
    const names = try gpa.alloc([44]u8, n);
    defer gpa.free(names);
    const rows = try gpa.alloc(contract.Row, n);
    defer gpa.free(rows);
    for (rows, 0..) |*r, i| r.* = row(std.fmt.bufPrint(&names[i], "kkid_{d:0>36}", .{i}) catch unreachable, "a.A/Get", 1, 1);
    var w: u64 = 0;
    while (w < 70) : (w += 1) {
        try s.addDelta(rows, 1000 * w, 1000 * (w + 1));
        try s.cut();
        s.enforce();
        try testing.expect(s.live <= default_cap);
    }
    try testing.expect(s.stats.merges >= 10);
    try testing.expectEqual(@as(u64, 70 * n), s.totals().local);
    try testing.expectEqual(@as(u64, 0), s.stats.dropped_rows);
}
