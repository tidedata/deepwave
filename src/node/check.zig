//! Offline check of a node's store against the checkpoint blobs it was built from (crash tests,
//! after a run). For every checkpoint in [from, to]:
//!   * the stored certified summary and contents equal the blob's bytes;
//!   * every transaction is found by digest with the same data, effects and events bytes and the
//!     right checkpoint number;
//!   * every output object version reads back (`objectAt`) with the blob's bytes.
//! Then the live state: for every object id the window touched, `latest` equals the net effect of
//! the window (last put: that version and bytes; last removal: a tombstone of that version and kind).
//! Nothing outside the window is assumed (the store may hold history from before `from`).
//! Read sets (history.zig): every modified input in the blob, and, when the source has the
//! checkpoint's aux record (archive protos, or a spool kept with `--keep-spool`), every other
//! object of the archive's object set reads back by (id, version) with the same bytes, and each
//! transaction's stored loaded runtime object list equals the archive's.
const std = @import("std");
const Io = std.Io;
const store = @import("store");
const types = @import("types");
const sync = @import("sync");
const source_mod = @import("source.zig");
const convert = @import("convert.zig");
const history = @import("history.zig");
const exec = @import("exec");
/// The codec a check opens the store with: compact records parse only through it.
pub const store_codec = exec.objects.store_codec;

pub const Report = struct {
    checkpoints: u64 = 0,
    transactions: u64 = 0,
    objects: u64 = 0,
    live_checked: u64 = 0,
    /// Read-set object versions and loaded runtime object lists compared.
    read_set_objects: u64 = 0,
    loaded_lists: u64 = 0,
    /// Checkpoints whose source had no aux record (only the blob's own inputs were checked).
    no_aux: u64 = 0,
    failures: u64 = 0,
};

const Last = union(enum) { put: struct { version: u64, digest: [32]u8 }, removed: struct { version: u64, kind: u8, before_records: bool = false } };

pub fn run(gpa: std.mem.Allocator, io: Io, st: *store.Store, src: *const source_mod.Source, from: u64, to: u64) !Report {
    return runOpts(gpa, io, st, src, from, to, .{});
}

pub const Options = struct {
    read_sets: bool = true,
    /// Checkpoints below this are not expected as records (a store started from a formal
    /// snapshot at `records_from - 1`): they only feed the expected live state, and an id whose
    /// last change before it is a removal may be absent (snapshots carry no tombstones).
    records_from: u64 = 0,
};

pub fn runOpts(gpa: std.mem.Allocator, io: Io, st: *store.Store, src: *const source_mod.Source, from: u64, to: u64, opts: Options) !Report {
    var rep: Report = .{};
    var snap = st.snapshot();
    defer snap.release();
    const hc = snap.highestCommitted() orelse return error.EmptyStore;
    if (hc < to) {
        std.log.err("store committed up to {d}, check wants {d}", .{ hc, to });
        return error.StoreBehind;
    }
    var sc = source_mod.Scratch.init(gpa);
    defer sc.deinit(gpa);
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var last: std.AutoHashMapUnmanaged([32]u8, Last) = .empty;
    defer last.deinit(gpa);
    _ = io;

    var seq = from;
    while (seq <= to) : (seq += 1) {
        _ = arena.reset(.retain_capacity);
        if (try src.fetch(&sc, seq, &blob) != .ok) return error.SourceMissing;
        const b = blob.items;
        try types.indexCheckpointData(b, &idx);
        const checked = switch (try sync.verify.check(arena.allocator(), b, &idx)) {
            .ok => |c| c,
            .bad => return error.BadBlob,
        };
        if (seq < opts.records_from) {
            for (checked.txs) |plan| {
                for (plan.puts) |p| try last.put(gpa, p.id.*, .{ .put = .{ .version = p.version, .digest = p.digest } });
                for (plan.removes) |r| try last.put(gpa, r.id, .{ .removed = .{ .version = r.version, .kind = r.kind, .before_records = true } });
            }
            continue;
        }
        rep.checkpoints += 1;
        const rec = (try snap.checkpointChecked(seq)) orelse {
            fail(&rep, seq, "checkpoint missing", .{});
            continue;
        };
        const want_cert = b[idx.summary.o .. idx.sig.o + idx.sig.n];
        if (!std.mem.eql(u8, rec.summary_cert, want_cert)) fail(&rep, seq, "summary/certificate bytes differ", .{});
        if (!std.mem.eql(u8, rec.contents, idx.contents.slice(b))) fail(&rep, seq, "contents bytes differ", .{});
        for (checked.txs, 0..) |plan, i| {
            rep.transactions += 1;
            const t = idx.txAt(i);
            const tr = (try snap.transactionChecked(plan.tx_digest)) orelse {
                fail(&rep, seq, "tx {d} missing", .{i});
                continue;
            };
            if (tr.checkpoint != seq) fail(&rep, seq, "tx {d} recorded in checkpoint {d}", .{ i, tr.checkpoint });
            if (!std.mem.eql(u8, tr.tx, t.transaction.slice(b))) fail(&rep, seq, "tx {d} envelope differs", .{i});
            if (!std.mem.eql(u8, tr.effects, t.effects.slice(b))) fail(&rep, seq, "tx {d} effects differ", .{i});
            if (!std.mem.eql(u8, tr.effects_digest, &plan.effects_digest)) fail(&rep, seq, "tx {d} effects digest differs", .{i});
            const want_ev: ?[]const u8 = if (t.events) |ev| ev.slice(b) else null;
            if ((want_ev == null) != (tr.events == null) or (want_ev != null and !std.mem.eql(u8, want_ev.?, tr.events.?))) fail(&rep, seq, "tx {d} events differ", .{i});
            for (plan.puts) |p| {
                rep.objects += 1;
                const got = (try readObj(&rep, &snap, seq, p.id, p.version)) orelse {
                    fail(&rep, seq, "object version missing (tx {d})", .{i});
                    continue;
                };
                if (!std.mem.eql(u8, got.bytes, idx.objs[p.index].slice(b))) fail(&rep, seq, "object bytes differ (tx {d})", .{i});
                try last.put(gpa, p.id.*, .{ .put = .{ .version = p.version, .digest = p.digest } });
            }
            for (plan.removes) |r| try last.put(gpa, r.id, .{ .removed = .{ .version = r.version, .kind = r.kind } });
            if (opts.read_sets) for (idx.objs[t.in_first..][0..t.in_count]) |r| try readBack(&rep, &snap, seq, r.slice(b));
        }
        if (opts.read_sets) {
            if (sc.aux.items.len == 0) {
                rep.no_aux += 1;
            } else {
                const aux = convert.Aux.parse(arena.allocator(), sc.aux.items) catch {
                    fail(&rep, seq, "aux record does not parse", .{});
                    continue;
                };
                if (aux.loaded.len != checked.txs.len) fail(&rep, seq, "aux transaction count differs", .{});
                for (aux.objects) |raw| try readBack(&rep, &snap, seq, raw);
                for (aux.loaded, checked.txs[0..@min(aux.loaded.len, checked.txs.len)]) |want, plan| {
                    rep.loaded_lists += 1;
                    const got = history.loadedList(history.LoadedEntry, &snap, plan.tx_digest);
                    if (got.len != want.len) {
                        fail(&rep, seq, "loaded runtime object list has {d} entries, archive {d}", .{ got.len, want.len });
                        continue;
                    }
                    for (got, want) |g, w| if (g.version != w.version or !std.mem.eql(u8, &g.id, &w.id)) fail(&rep, seq, "loaded runtime object list differs", .{});
                }
            }
        }
        if (seq % 1000 == 0) std.log.info("check: through {d}", .{seq});
    }
    // Live state of every touched id at the end of the window (only when the store ends there).
    if (hc == to) {
        var it = last.iterator();
        while (it.next()) |e| {
            rep.live_checked += 1;
            const got = try snap.latest(e.key_ptr);
            switch (e.value_ptr.*) {
                .put => |p| {
                    const g = got orelse {
                        fail(&rep, to, "live object missing", .{});
                        continue;
                    };
                    switch (g) {
                        .live => |o| if (o.version != p.version or !std.mem.eql(u8, &o.digest, &p.digest)) fail(&rep, to, "live version/digest differs", .{}),
                        .removed => fail(&rep, to, "live object is a tombstone", .{}),
                    }
                },
                .removed => |r| {
                    const g = got orelse {
                        if (!r.before_records) fail(&rep, to, "tombstone missing", .{});
                        continue;
                    };
                    switch (g) {
                        .live => fail(&rep, to, "removed object is live", .{}),
                        .removed => |t| {
                            // Store kinds: deleted (also unwrapped_then_deleted) or wrapped.
                            const want_kind: store.RemoveKind = if (r.kind == 1) .wrapped else .deleted;
                            if (t.version != r.version or t.kind != want_kind) fail(&rep, to, "tombstone differs", .{});
                        },
                    }
                },
            }
        }
    }
    return rep;
}

/// An object version of the checkpoint's read set must read back with the same bytes.
fn readBack(rep: *Report, snap: *const store.Snapshot, seq: u64, raw: []const u8) !void {
    rep.read_set_objects += 1;
    const k = exec.objects.keyOf(raw) catch return fail(rep, seq, "read-set object does not parse", .{});
    const got = (try readObj(rep, snap, seq, &k.id, k.version)) orelse return fail(rep, seq, "read-set object {x} version {d} missing", .{ &k.id, k.version });
    if (!std.mem.eql(u8, got.bytes, raw)) fail(rep, seq, "read-set object {x} version {d} bytes differ", .{ &k.id, k.version });
}

/// objectAtChecked, but a Corrupt read is a failure naming the version and its index candidates
/// (the check goes on) instead of ending the check.
fn readObj(rep: *Report, snap: *const store.Snapshot, seq: u64, id: *const [32]u8, version: u64) !?store.ObjectRef {
    return snap.objectAtChecked(id, version) catch |e| switch (e) {
        error.Corrupt => {
            const first = rep.failures < 20;
            fail(rep, seq, "object {x} version {d}: Corrupt", .{ id, version });
            if (first) snap.explainVersion(id, version);
            return null;
        },
        else => return e,
    };
}

fn fail(rep: *Report, seq: u64, comptime fmt: []const u8, args: anytype) void {
    rep.failures += 1;
    if (rep.failures <= 20) std.log.err("check {d}: " ++ fmt, .{seq} ++ args);
}
