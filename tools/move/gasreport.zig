//! Ecosystem gas report: per package, function and object type, the real gas
//! and storage spend of the transactions in a checkpoint range of a deepwave store.
//!
//! Attribution:
//! - Computation cost of a programmable transaction is split evenly over its MoveCall commands
//!   (a transaction with one call is exact; `solo_*` columns count only those).
//! - Storage cost is split over the objects the transaction wrote, by their BCS size, and each
//!   share goes to the object's Move type (and so to the type's package). Storage rebate is split
//!   over the objects the transaction consumed (input versions), by their old size.
//! - Package ids are folded to the package's original id, so every upgrade of a package counts as one.
const std = @import("std");
const common = @import("common.zig");
const bcs = @import("bcs");
const types = @import("types");
const node = @import("node");
const exec = @import("exec");

const Allocator = std.mem.Allocator;
const Id = common.Id;
const store = node.store;

pub const FnStat = struct {
    package: Id,
    module: []const u8,
    function: []const u8,
    calls: u64 = 0,
    txs: u64 = 0,
    failed_txs: u64 = 0,
    /// Computation cost share in MIST (sum over the transactions this function is called in).
    computation: u64 = 0,
    max_tx_computation: u64 = 0,
    solo_txs: u64 = 0,
    solo_computation: u64 = 0,
};

pub const TypeStat = struct {
    package: Id,
    name: []const u8,
    writes: u64 = 0,
    creates: u64 = 0,
    deletes: u64 = 0,
    bytes_written: u64 = 0,
    max_size: u64 = 0,
    storage_cost: u64 = 0,
    rebate: u64 = 0,
};

pub const PkgStat = struct {
    package: Id,
    calls: u64 = 0,
    txs: u64 = 0,
    computation: u64 = 0,
    storage_cost: u64 = 0,
    rebate: u64 = 0,
    failed_txs: u64 = 0,
};

pub const TopTx = struct { computation: u64, storage: u64, rebate: u64, digest: Id, calls: u32, checkpoint: u64 };

pub const Report = struct {
    arena: Allocator,
    from: u64 = 0,
    to: u64 = 0,
    checkpoints: u64 = 0,
    txs: u64 = 0,
    ptb_txs: u64 = 0,
    move_txs: u64 = 0,
    system_txs: u64 = 0,
    failed_txs: u64 = 0,
    undecodable: u64 = 0,
    computation: u128 = 0,
    storage_cost: u128 = 0,
    rebate: u128 = 0,
    non_refundable: u128 = 0,
    fns: std.StringArrayHashMapUnmanaged(FnStat) = .empty,
    tys: std.StringArrayHashMapUnmanaged(TypeStat) = .empty,
    pkgs: std.AutoArrayHashMapUnmanaged(Id, PkgStat) = .empty,
    top: std.ArrayList(TopTx) = .empty,
    top_n: usize = 20,

    fn pkgStat(r: *Report, id: Id) !*PkgStat {
        const g = try r.pkgs.getOrPut(r.arena, id);
        if (!g.found_existing) g.value_ptr.* = .{ .package = id };
        return g.value_ptr;
    }

    fn noteTop(r: *Report, t: TopTx) !void {
        if (r.top.items.len < r.top_n) {
            try r.top.append(r.arena, t);
        } else {
            var min_i: usize = 0;
            for (r.top.items, 0..) |x, i| if (x.computation < r.top.items[min_i].computation) {
                min_i = i;
            };
            if (r.top.items[min_i].computation >= t.computation) return;
            r.top.items[min_i] = t;
        }
    }
};

const CallKey = struct { pkg: Id, module: []const u8, function: []const u8 };

/// Folds one transaction into the report. `tmp` holds the decoded transaction (reset by the caller).
pub fn addTransaction(r: *Report, tmp: Allocator, snap: *const store.Snapshot, oc: *common.OriginCache, t: store.TransactionRecord) !void {
    r.txs += 1;
    const td = bcs.decode(types.TransactionData, tmp, t.tx) catch {
        r.undecodable += 1;
        return;
    };
    const v1 = td.V1;
    const eff = bcs.decode(types.TransactionEffects, tmp, t.effects) catch {
        r.undecodable += 1;
        return;
    };
    const gas: types.GasCostSummary, const ok: bool = switch (eff) {
        .V1 => |e| .{ e.gas_used, e.status == .Success },
        .V2 => |e| .{ e.gas_used, e.status == .Success },
    };
    r.computation += gas.computationCost;
    r.storage_cost += gas.storageCost;
    r.rebate += gas.storageRebate;
    r.non_refundable += gas.nonRefundableStorageFee;
    if (!ok) r.failed_txs += 1;

    const ptb = switch (v1.kind) {
        .ProgrammableTransaction => |p| p,
        else => {
            r.system_txs += 1;
            return;
        },
    };
    r.ptb_txs += 1;

    // MoveCall commands
    var calls: std.ArrayList(CallKey) = .empty;
    for (ptb.commands) |c| switch (c) {
        .MoveCall => |mc| {
            const orig = oc.original(&mc.package.@"0".@"0");
            try calls.append(tmp, .{ .pkg = orig, .module = mc.module.@"0", .function = mc.function.@"0" });
        },
        else => {},
    };
    const ncalls: u64 = calls.items.len;
    var seen_pkgs: std.ArrayList(Id) = .empty;
    if (ncalls > 0) {
        r.move_txs += 1;
        const share = gas.computationCost / ncalls;
        var extra = gas.computationCost - share * ncalls;
        var seen_fns: std.ArrayList([]const u8) = .empty;
        for (calls.items) |c| {
            const keytxt = try std.fmt.allocPrint(tmp, "{x}::{s}::{s}", .{ &c.pkg, c.module, c.function });
            const g = try r.fns.getOrPut(r.arena, keytxt);
            if (!g.found_existing) {
                g.key_ptr.* = try r.arena.dupe(u8, keytxt);
                g.value_ptr.* = .{ .package = c.pkg, .module = try r.arena.dupe(u8, c.module), .function = try r.arena.dupe(u8, c.function) };
            }
            const fs = g.value_ptr;
            fs.calls += 1;
            const this_share = share + extra;
            fs.computation += this_share;
            extra = 0;
            var first = true;
            for (seen_fns.items) |s| if (std.mem.eql(u8, s, keytxt)) {
                first = false;
            };
            if (first) {
                try seen_fns.append(tmp, keytxt);
                fs.txs += 1;
                if (!ok) fs.failed_txs += 1;
                if (gas.computationCost > fs.max_tx_computation) fs.max_tx_computation = gas.computationCost;
                if (ncalls == 1) {
                    fs.solo_txs += 1;
                    fs.solo_computation += gas.computationCost;
                }
            }
            const ps = try r.pkgStat(c.pkg);
            ps.calls += 1;
            ps.computation += this_share;
            var pfirst = true;
            for (seen_pkgs.items) |s| if (std.mem.eql(u8, &s, &c.pkg)) {
                pfirst = false;
            };
            if (pfirst) {
                try seen_pkgs.append(tmp, c.pkg);
                ps.txs += 1;
                if (!ok) ps.failed_txs += 1;
            }
        }
    }

    // storage attribution over the changed objects (effects V2)
    var checkpoint_hint = t.checkpoint;
    _ = &checkpoint_hint;
    switch (eff) {
        .V2 => |e| try attributeStorage(r, tmp, snap, oc, e, gas),
        .V1 => {},
    }
    try r.noteTop(.{ .computation = gas.computationCost, .storage = gas.storageCost, .rebate = gas.storageRebate, .digest = t.digest.*, .calls = @intCast(ncalls), .checkpoint = t.checkpoint });
}

const Touch = struct { ty: []const u8, pkg: Id, new_bytes: u64, old_bytes: u64, create: bool, delete: bool };

fn typeOfObject(tmp: Allocator, raw: []const u8) ?struct { name: []const u8, pkg: Id } {
    var rd = bcs.Reader.init(raw);
    const tag = rd.uleb32() catch return null;
    if (tag == 1) return .{ .name = "<package>", .pkg = @splat(0) };
    if (tag != 0) return null;
    const mt = bcs.decodeFrom(types.MoveObjectType, tmp, &rd) catch return null;
    const name = common.objectTypeName(tmp, mt) catch return null;
    return .{ .name = name, .pkg = common.objectTypeAddress(mt) orelse @splat(0) };
}

fn attributeStorage(r: *Report, tmp: Allocator, snap: *const store.Snapshot, oc: *common.OriginCache, e: types.TransactionEffectsV2, gas: types.GasCostSummary) !void {
    const lamport = e.lamport_version.@"0";
    var touches: std.ArrayList(Touch) = .empty;
    var total_new: u64 = 0;
    var total_old: u64 = 0;
    for (e.changed_objects) |co| {
        const id: Id = co[0].@"0".@"0";
        const ch = co[1];
        var new_bytes: u64 = 0;
        var old_bytes: u64 = 0;
        var ty: ?[]const u8 = null;
        var tpkg: Id = @splat(0);
        var create = false;
        var delete = false;
        switch (ch.input_state) {
            .NotExist => create = true,
            .Exist => |x| {
                if (snap.objectAt(&id, x[0][0].@"0")) |old| {
                    old_bytes = old.len;
                    if (typeOfObject(tmp, old)) |t| {
                        ty = t.name;
                        tpkg = oc.original(&t.pkg);
                    }
                }
            },
        }
        switch (ch.output_state) {
            .ObjectWrite => {
                if (snap.objectAt(&id, lamport)) |nw| {
                    new_bytes = nw.len;
                    if (typeOfObject(tmp, nw)) |t| {
                        ty = t.name;
                        tpkg = oc.original(&t.pkg);
                    }
                }
            },
            .PackageWrite => {
                ty = "<package>";
                if (snap.objectAt(&id, lamport)) |nw| new_bytes = nw.len;
            },
            // an output that is gone without a Deleted id operation was wrapped, not deleted
            .NotExist => delete = ch.id_operation == .Deleted,
            else => {},
        }
        const name = ty orelse continue;
        total_new += new_bytes;
        total_old += old_bytes;
        try touches.append(tmp, .{ .ty = name, .pkg = tpkg, .new_bytes = new_bytes, .old_bytes = old_bytes, .create = create, .delete = delete });
    }
    for (touches.items) |t| {
        const g = try r.tys.getOrPut(r.arena, t.ty);
        if (!g.found_existing) {
            g.key_ptr.* = try r.arena.dupe(u8, t.ty);
            g.value_ptr.* = .{ .package = t.pkg, .name = g.key_ptr.* };
        }
        const ts = g.value_ptr;
        if (t.new_bytes > 0) {
            ts.writes += 1;
            ts.bytes_written += t.new_bytes;
            if (t.new_bytes > ts.max_size) ts.max_size = t.new_bytes;
        }
        if (t.create) ts.creates += 1;
        if (t.delete) ts.deletes += 1;
        var st_share: u64 = 0;
        var rb_share: u64 = 0;
        if (total_new > 0) st_share = @intCast(@as(u128, gas.storageCost) * t.new_bytes / total_new);
        if (total_old > 0) rb_share = @intCast(@as(u128, gas.storageRebate) * t.old_bytes / total_old);
        ts.storage_cost += st_share;
        ts.rebate += rb_share;
        if (!std.mem.eql(u8, &t.pkg, &(@as(Id, @splat(0))))) {
            const ps = try r.pkgStat(t.pkg);
            ps.storage_cost += st_share;
            ps.rebate += rb_share;
        }
    }
}

/// Scans checkpoints [from, to] of `snap` into a report.
pub fn scan(gpa: Allocator, arena: Allocator, snap: *const store.Snapshot, from: u64, to: u64, top_n: usize) !Report {
    var r: Report = .{ .arena = arena, .from = from, .to = to, .top_n = top_n };
    var oc: common.OriginCache = .{ .arena = arena, .snap = snap };
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    var seq = from;
    while (seq <= to) : (seq += 1) {
        _ = tmp.reset(.retain_capacity);
        const a = tmp.allocator();
        const rec = (snap.checkpointChecked(seq) catch continue) orelse continue;
        r.checkpoints += 1;
        const contents = bcs.decode(types.CheckpointContents, a, rec.contents) catch continue;
        const n = switch (contents) {
            .V1 => |v| v.transactions.len,
            .V2 => |v| v.transactions.len,
        };
        for (0..n) |i| {
            const dg: *const Id = switch (contents) {
                .V1 => |v| &v.transactions[i].transaction.@"0".@"0",
                .V2 => |v| &v.transactions[i].digest.transaction.@"0".@"0",
            };
            const t = (snap.transactionChecked(dg) catch continue) orelse continue;
            // per-transaction scratch so one big checkpoint does not grow the arena
            var tx_tmp: std.heap.ArenaAllocator = .init(gpa);
            defer tx_tmp.deinit();
            try addTransaction(&r, tx_tmp.allocator(), snap, &oc, t);
        }
    }
    return r;
}

fn lessFn(_: void, a: FnStat, b: FnStat) bool {
    return a.computation > b.computation;
}
fn lessTy(_: void, a: TypeStat, b: TypeStat) bool {
    return a.storage_cost + a.rebate > b.storage_cost + b.rebate;
}
fn lessPkg(_: void, a: PkgStat, b: PkgStat) bool {
    return netOf(a) > netOf(b);
}
fn netOf(p: PkgStat) u128 {
    return @as(u128, p.computation) + p.storage_cost;
}
fn lessTop(_: void, a: TopTx, b: TopTx) bool {
    return a.computation > b.computation;
}

pub const Format = common.Format;
pub const Table = enum { packages, functions, types, txs };

/// Writes the report. JSON: everything; CSV: one table.
pub fn write(w: *std.Io.Writer, arena: Allocator, r: *Report, fmt: Format, table: Table, limit: usize) !void {
    const fns = try arena.dupe(FnStat, r.fns.values());
    std.mem.sort(FnStat, fns, {}, lessFn);
    const tys = try arena.dupe(TypeStat, r.tys.values());
    std.mem.sort(TypeStat, tys, {}, lessTy);
    const pkgs = try arena.dupe(PkgStat, r.pkgs.values());
    std.mem.sort(PkgStat, pkgs, {}, lessPkg);
    std.mem.sort(TopTx, r.top.items, {}, lessTop);
    switch (fmt) {
        .json => {
            var j: common.Json = .{ .w = w };
            try j.beginObj();
            try j.objIn("range");
            try j.int("from", r.from);
            try j.int("to", r.to);
            try j.int("checkpoints", r.checkpoints);
            try j.endObj();
            try j.objIn("totals");
            try j.int("transactions", r.txs);
            try j.int("programmable", r.ptb_txs);
            try j.int("with_move_calls", r.move_txs);
            try j.int("system", r.system_txs);
            try j.int("failed", r.failed_txs);
            try j.int("undecodable", r.undecodable);
            try j.int("computation_mist", r.computation);
            try j.int("storage_cost_mist", r.storage_cost);
            try j.int("storage_rebate_mist", r.rebate);
            try j.int("non_refundable_mist", r.non_refundable);
            try j.endObj();
            try j.arrIn("packages");
            for (pkgs[0..@min(limit, pkgs.len)]) |p| try writePkgJson(&j, arena, p);
            try j.endArr();
            try j.arrIn("functions");
            for (fns[0..@min(limit, fns.len)]) |f| try writeFnJson(&j, arena, f);
            try j.endArr();
            try j.arrIn("types");
            for (tys[0..@min(limit, tys.len)]) |t| try writeTyJson(&j, arena, t);
            try j.endArr();
            try j.arrIn("costliest_transactions");
            for (r.top.items) |t| {
                try j.beginObj();
                try j.str("digest", try b58(arena, &t.digest));
                try j.int("checkpoint", t.checkpoint);
                try j.int("move_calls", t.calls);
                try j.int("computation_mist", t.computation);
                try j.int("storage_cost_mist", t.storage);
                try j.int("storage_rebate_mist", t.rebate);
                try j.endObj();
            }
            try j.endArr();
            try j.endObj();
            try w.writeByte('\n');
        },
        .csv => switch (table) {
            .functions => {
                try w.writeAll("package,module,function,calls,txs,failed_txs,computation_mist,avg_computation_per_call,max_tx_computation,solo_txs,solo_avg_computation\n");
                for (fns[0..@min(limit, fns.len)]) |f| {
                    try w.print("{s},", .{try common.hexId(arena, &f.package)});
                    try common.csvStr(w, f.module);
                    try w.writeByte(',');
                    try common.csvStr(w, f.function);
                    try w.print(",{d},{d},{d},{d},{d},{d},{d},{d}\n", .{ f.calls, f.txs, f.failed_txs, f.computation, div(f.computation, f.calls), f.max_tx_computation, f.solo_txs, div(f.solo_computation, f.solo_txs) });
                }
            },
            .packages => {
                try w.writeAll("package,calls,txs,failed_txs,computation_mist,storage_cost_mist,storage_rebate_mist,net_mist\n");
                for (pkgs[0..@min(limit, pkgs.len)]) |p| {
                    const net: i128 = @as(i128, p.computation) + p.storage_cost - p.rebate;
                    try w.print("{s},{d},{d},{d},{d},{d},{d},{d}\n", .{ try common.hexId(arena, &p.package), p.calls, p.txs, p.failed_txs, p.computation, p.storage_cost, p.rebate, net });
                }
            },
            .types => {
                try w.writeAll("type,package,writes,creates,deletes,bytes_written,max_size,storage_cost_mist,storage_rebate_mist\n");
                for (tys[0..@min(limit, tys.len)]) |t| {
                    try common.csvStr(w, t.name);
                    try w.print(",{s},{d},{d},{d},{d},{d},{d},{d}\n", .{ try common.hexId(arena, &t.package), t.writes, t.creates, t.deletes, t.bytes_written, t.max_size, t.storage_cost, t.rebate });
                }
            },
            .txs => {
                try w.writeAll("digest,checkpoint,move_calls,computation_mist,storage_cost_mist,storage_rebate_mist\n");
                for (r.top.items) |t| try w.print("{s},{d},{d},{d},{d},{d}\n", .{ try b58(arena, &t.digest), t.checkpoint, t.calls, t.computation, t.storage, t.rebate });
            },
        },
    }
}

fn div(a: u64, b: u64) u64 {
    return if (b == 0) 0 else a / b;
}

fn b58(arena: Allocator, id: *const Id) ![]const u8 {
    const serve = @import("serve");
    const buf = try arena.alloc(u8, serve.b58.max_len_32);
    return try arena.dupe(u8, serve.b58.encode32(buf[0..serve.b58.max_len_32], id));
}

fn writePkgJson(j: *common.Json, arena: Allocator, p: PkgStat) !void {
    try j.beginObj();
    try j.str("package", try common.hexId(arena, &p.package));
    try j.int("calls", p.calls);
    try j.int("transactions", p.txs);
    try j.int("failed_transactions", p.failed_txs);
    try j.int("computation_mist", p.computation);
    try j.int("storage_cost_mist", p.storage_cost);
    try j.int("storage_rebate_mist", p.rebate);
    try j.int("net_mist", @as(i128, p.computation) + p.storage_cost - p.rebate);
    try j.endObj();
}

fn writeFnJson(j: *common.Json, arena: Allocator, f: FnStat) !void {
    try j.beginObj();
    try j.str("package", try common.hexId(arena, &f.package));
    try j.str("module", f.module);
    try j.str("function", f.function);
    try j.int("calls", f.calls);
    try j.int("transactions", f.txs);
    try j.int("failed_transactions", f.failed_txs);
    try j.int("computation_mist", f.computation);
    try j.int("avg_computation_per_call_mist", div(f.computation, f.calls));
    try j.int("max_transaction_computation_mist", f.max_tx_computation);
    try j.int("solo_transactions", f.solo_txs);
    try j.int("solo_avg_computation_mist", div(f.solo_computation, f.solo_txs));
    try j.endObj();
}

fn writeTyJson(j: *common.Json, arena: Allocator, t: TypeStat) !void {
    try j.beginObj();
    try j.str("type", t.name);
    try j.str("package", try common.hexId(arena, &t.package));
    try j.int("writes", t.writes);
    try j.int("creates", t.creates);
    try j.int("deletes", t.deletes);
    try j.int("bytes_written", t.bytes_written);
    try j.int("avg_size", div(t.bytes_written, t.writes));
    try j.int("max_size", t.max_size);
    try j.int("storage_cost_mist", t.storage_cost);
    try j.int("storage_rebate_mist", t.rebate);
    try j.endObj();
}
