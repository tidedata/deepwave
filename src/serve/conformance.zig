//! Conformance suites of the serve lane (CONTRACTS.md section 3.3).
//!
//! `grpc-v2`: for every record in `$ZUI_CORPUS/vectors/grpc-v2/<seq>.rec.zst` (made by
//! `tools/truth/serve` with Mysten's own conversions) renders the same request from
//! `chk/<seq>.chk` and compares the response bytes. Items are `ckpt/<seq>/m<mask>`; a mask
//! that also selects `transactions` or `objects` is split into the head part (all but transactions) and
//! the parts not yet rendered, which are counted as skips until they are.
const std = @import("std");
const harness = @import("harness");
const bcs = @import("bcs");
const types = @import("types");
const proto = @import("proto.zig");
const mask = @import("mask.zig");
const ledger = @import("ledger.zig");
const render_tx = @import("render_tx.zig");
const store = @import("store");
const service = @import("service.zig");
const loopback = @import("loopback.zig");
const objset = @import("objset.zig");
const txobjects = @import("txobjects.zig");
const status = @import("status.zig");
const b58 = @import("b58.zig");
const typestr = @import("typestr.zig");
const exec_error = @import("exec_error.zig");
const render_checkpoint = @import("render_checkpoint.zig");
const render_object = @import("render_object.zig");
const movepkg = @import("movepkg.zig");

pub const suites = [_]harness.Suite{
    .{ .name = "verifysig", .lane = "serve", .doc = "SignatureVerificationService.VerifySignature: grpc-status, grpc-message, details and response bytes equal sui-node 1.83.1 on recorded signatures", .run = runVerifysig },
    .{ .name = "grpc-v2", .lane = "serve", .doc = "response bytes for the request corpus equal sui-node 1.83.1", .run = runGrpc, .bench = benchRender, .baselines = &.{
        .{ .name = "render-checkpoint", .argv = &.{ "{release}/zui-serve-truth", "bench", "render" } },
        .{ .name = "package-member-cached-pkg", .argv = &.{ "{release}/zui-serve-truth", "bench", "pkg" } },
        .{ .name = "package-member-parse", .argv = &.{ "{release}/zui-serve-truth", "bench", "pkg" } },
    } },
    .{ .name = "epoch-pkg", .lane = "epoch-pkg", .doc = "GetEpoch, package versions and SuiNS answers equal sui-node 1.83.1's recorded ones", .run = @import("conformance_epochpkg.zig").run },
    .{ .name = "render-json", .lane = "serve", .doc = "object json/display/OBJ_MASK and checkpoint event json equal sui-node 1.83.1", .run = @import("conformance_render.zig").run },
    .{ .name = "rpc-events", .lane = "serve", .doc = "SubscribeEvents and filtered ListCheckpoints over a socket equal sui-node 1.83.1's localnet captures (src/serve/vectors/rpc-surface)", .run = @import("conformance_rpcevents.zig").run },
    .{ .name = "rpc-proof", .lane = "serve", .doc = "ProofService.GetCheckpointObjectProof over a socket equals sui-node 1.83.1's localnet captures (src/serve/vectors/rpc-surface/proof)", .run = @import("conformance_proof.zig").run },
};

/// Must equal BENCH_MASK in tools/truth/serve/src/main.rs.
const bench_mask = "sequence_number,digest,summary,signature,transactions.digest,transactions.transaction.bcs,transactions.transaction.digest,transactions.transaction.sender,transactions.transaction.gas_payment,transactions.transaction.expiration,transactions.transaction.kind,transactions.signatures.bcs,transactions.signatures.scheme,transactions.effects.bcs,transactions.effects.digest,transactions.effects.epoch,transactions.effects.gas_used,transactions.effects.changed_objects,transactions.effects.dependencies,transactions.events.bcs,transactions.events.digest,transactions.checkpoint,transactions.timestamp,transactions.balance_changes";

const BenchState = struct {
    ctx: *harness.Ctx,
    blobs: []const []const u8,
    idx: *types.index.CheckpointIndex,
    m: mask.Mask,
    out: []u8,
    skipped_txs: u64 = 0,
    bytes: u64 = 0,
};

fn benchPass(st: *BenchState) !void {
    st.bytes = 0;
    st.skipped_txs = 0;
    var arena_state = std.heap.ArenaAllocator.init(st.ctx.gpa);
    defer arena_state.deinit();
    for (st.blobs) |blob| {
        _ = arena_state.reset(.retain_capacity);
        const arena = arena_state.allocator();
        try types.index.indexCheckpointData(blob, st.idx);
        const idx = st.idx;
        const cert_bytes = blob[idx.summary.o..][0 .. idx.summary.n + idx.sig.n];
        const raw_objects = try arena.alloc([]const u8, idx.obj_total);
        for (idx.objs[0..idx.obj_total], raw_objects) |o, *dst| dst.* = o.slice(blob);
        const txs = try arena.alloc(render_tx.Input, idx.tx_count);
        for (idx.txs[0..idx.tx_count], txs) |t, *dst| {
            const sigs = try arena.alloc([]const u8, t.sig_count);
            for (idx.sigs[t.sig_first..][0..t.sig_count], sigs) |sr, *sd| {
                var rd = bcs.Reader.init(sr.slice(blob));
                sd.* = try rd.bytes(try rd.length());
            }
            dst.* = .{ .transaction = t.data.slice(blob), .signatures = sigs, .effects = t.effects.slice(blob), .events = if (t.events) |e| e.slice(blob) else null };
        }
        var w = proto.Writer.init(st.out);
        ledger.getCheckpoint(arena, &w, st.m, cert_bytes, idx.contents.slice(blob), raw_objects, txs) catch |e| switch (e) {
            error.Unsupported => {
                st.skipped_txs += idx.tx_count;
                continue;
            },
            else => return e,
        };
        st.bytes += w.len;
    }
}

/// BCS CheckpointData bytes in memory -> GetCheckpointResponse bytes (validation pass, decode,
/// render), against the same path in Rust (decode, convert, merge, prost encode).
fn benchRender(ctx: *harness.Ctx) !void {
    const names = ctx.benchInputs();
    const blobs = try ctx.gpa.alloc([]const u8, names.len);
    defer {
        for (blobs) |b| ctx.gpa.free(b);
        ctx.gpa.free(blobs);
    }
    var total_txs: u64 = 0;
    var idx = try types.index.CheckpointIndex.init(ctx.gpa);
    defer idx.deinit(ctx.gpa);
    for (names, blobs) |n, *b| {
        b.* = try ctx.corpus.readFileAlloc(ctx.io, n, ctx.gpa, .limited(max_blob));
        try types.index.indexCheckpointData(b.*, &idx);
        total_txs += idx.tx_count;
    }
    var tree = try mask.Tree.parse(ctx.gpa, bench_mask);
    defer tree.deinit(ctx.gpa);
    const out = try ctx.gpa.alloc(u8, 256 << 20);
    defer ctx.gpa.free(out);
    var st: BenchState = .{ .ctx = ctx, .blobs = blobs, .idx = &idx, .m = tree.mask(), .out = out };
    try ctx.benchPasses("render-checkpoint", "tx", total_txs, &st, benchPass);
    try benchPackages(ctx);
    try ctx.stderr.print("render-checkpoint: {d} bytes of response per pass; {d} of {d} transactions sit in checkpoints the renderer skips (Unsupported)\n", .{ st.bytes, st.skipped_txs, total_txs });
}

const parse_stride = 50; // must equal PARSE_STRIDE in tools/truth/serve/src/main.rs
const PkgBench = struct {
    pkgs: []const movepkg.Package,
    objs: []const []const u8,
    items: []const []const Item,
    out: []u8,
    reparse: bool,
    arena: std.mem.Allocator,
    const Item = struct { kind: u8, module: []const u8, name: []const u8 };
};

fn benchPkgPass(st: *PkgBench) !void {
    for (st.pkgs, st.objs, st.items) |*pk, raw, items| {
        var p = pk.*;
        var tmp = std.heap.ArenaAllocator.init(st.arena);
        defer tmp.deinit();
        if (!st.reparse) {} else {
            // one parse per timed request, every parse_stride-th request of the package
            var i: usize = 0;
            while (i < items.len) : (i += parse_stride) {
                var tmp2 = std.heap.ArenaAllocator.init(st.arena);
                defer tmp2.deinit();
                try movepkg.read(tmp2.allocator(), raw, &p);
                var w = proto.Writer.init(st.out);
                const it = items[i];
                if (it.kind == 2) try movepkg.writeDatatypeResponse(tmp2.allocator(), &w, &p, it.module, it.name) else try movepkg.writeFunctionResponse(tmp2.allocator(), &w, &p, it.module, it.name);
                std.mem.doNotOptimizeAway(w.len);
            }
            continue;
        }
        for (items) |it| {
            var w = proto.Writer.init(st.out);
            if (it.kind == 2) try movepkg.writeDatatypeResponse(tmp.allocator(), &w, &p, it.module, it.name) else try movepkg.writeFunctionResponse(tmp.allocator(), &w, &p, it.module, it.name);
            std.mem.doNotOptimizeAway(w.len);
        }
    }
}

/// GetDatatype / GetFunction over every package record of the pkg vectors: "package-member" is the
/// cached path (the parsed package is held), "package-member-parse" parses the object per request.
fn benchPackages(ctx: *harness.Ctx) !void {
    const names = try ctx.listFiles(pkg_dir, ".pkg.zst");
    defer ctx.freeNames(names);
    var arena_state = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var pkgs = std.ArrayList(movepkg.Package).empty;
    var objs = std.ArrayList([]const u8).empty;
    var items = std.ArrayList([]const PkgBench.Item).empty;
    var units: u64 = 0;
    for (names) |name| {
        var nb: [160]u8 = undefined;
        const z = try ctx.corpus.readFileAlloc(ctx.io, try std.fmt.bufPrint(&nb, pkg_dir ++ "/{s}", .{name}), arena, .limited(max_blob));
        const rec = try harness.decompressZstd(arena, z, max_blob);
        const olen = std.mem.readInt(u32, rec[0..4], .little);
        const raw = rec[4..][0..olen];
        var pkg: movepkg.Package = undefined;
        movepkg.read(arena, raw, &pkg) catch continue;
        var list = std.ArrayList(PkgBench.Item).empty;
        var pos: usize = 4 + olen;
        while (pos < rec.len) {
            const kind = rec[pos];
            const ml = std.mem.readInt(u16, rec[pos + 1 ..][0..2], .little);
            const mod = rec[pos + 3 ..][0..ml];
            pos += 3 + ml;
            const nl = std.mem.readInt(u16, rec[pos..][0..2], .little);
            const nm = rec[pos + 2 ..][0..nl];
            pos += 2 + nl;
            const st_byte = rec[pos];
            const blen = std.mem.readInt(u32, rec[pos + 1 ..][0..4], .little);
            pos += 5 + blen;
            if (st_byte == 0 and kind >= 2 and !std.mem.startsWith(u8, nm, "NoSuch") and !std.mem.eql(u8, nm, "no_such_fn") and !std.mem.eql(u8, mod, "no_such_module")) {
                try list.append(arena, .{ .kind = kind, .module = mod, .name = nm });
                units += 1;
            }
        }
        try pkgs.append(arena, pkg);
        try objs.append(arena, raw);
        try items.append(arena, list.items);
    }
    const out = try arena.alloc(u8, 1 << 22);
    var st: PkgBench = .{ .pkgs = pkgs.items, .objs = objs.items, .items = items.items, .out = out, .reparse = false, .arena = arena };
    try ctx.benchPasses("package-member-cached-pkg", "request", units, &st, benchPkgPass);
    st.reparse = true;
    var n_parse: u64 = 0;
    for (items.items) |l| n_parse += (l.len + parse_stride - 1) / parse_stride;
    try ctx.benchPasses("package-member-parse", "request", n_parse, &st, benchPkgPass);
}

const max_blob = 1 << 30;
const rec_dir = "vectors/grpc-v2";
/// Round 4 truth: records of the checkpoints that were only lossy `.chk` before, regenerated from
/// the full-object-set archive proto (`binpb-r4/`). A record under `<dir>-r4/` replaces the one
/// under `<dir>/`; main keeps reading the old files.
fn readRec(ctx: *harness.Ctx, comptime dir: []const u8, name: []const u8) ![]u8 {
    var nb: [160]u8 = undefined;
    if (ctx.readZstd(try std.fmt.bufPrint(&nb, dir ++ "-r4/{s}", .{name}), max_blob)) |r| return r else |e| if (e != error.FileNotFound) return e;
    return ctx.readZstd(try std.fmt.bufPrint(&nb, dir ++ "/{s}", .{name}), max_blob);
}
const tx_dir = "vectors/grpc-v2-tx";
const misc_dir = "vectors/grpc-v2-misc";

fn runGrpc(ctx: *harness.Ctx) !void {
    const masks_txt = try ctx.corpus.readFileAlloc(ctx.io, rec_dir ++ "/masks.txt", ctx.gpa, .limited(1 << 20));
    defer ctx.gpa.free(masks_txt);
    try ctx.forEachFile(rec_dir, ".rec.zst", masks_txt, runOne);
    const txmasks = try ctx.corpus.readFileAlloc(ctx.io, tx_dir ++ "/masks.txt", ctx.gpa, .limited(1 << 20));
    defer ctx.gpa.free(txmasks);
    const objmasks = try ctx.corpus.readFileAlloc(ctx.io, tx_dir ++ "/masks-obj.txt", ctx.gpa, .limited(1 << 20));
    defer ctx.gpa.free(objmasks);
    // The e2e pass ingests the whole corpus into a store first: skip it for a narrowed run
    // unless the filter names it.
    if (ctx.opts.filter == null or std.mem.indexOf(u8, ctx.opts.filter.?, "e2e") != null) try runE2e(ctx, masks_txt, txmasks, objmasks);
    try runStatus(ctx);
    try runPackages(ctx);
    try runExecStatus(ctx);
    const both = [2][]const u8{ txmasks, objmasks };
    try ctx.forEachFile(tx_dir, ".rec.zst", &both, runTx);
    const n = unsupported.load(.monotonic);
    if (n > 0) {
        // Summary only (each such item was already recorded as a skip or a failure).
        ctx.stderr.print("grpc-v2: {d} items hit fields not ported yet; by mask:", .{n}) catch {};
        for (by_mask, 0..) |c, i| if (c.load(.monotonic) > 0) ctx.stderr.print(" m{d}={d}", .{ i, c.load(.monotonic) }) catch {};
        ctx.stderr.print("\n", .{}) catch {};
        ctx.stderr.flush() catch {};
    }
}

var unsupported: std.atomic.Value(u64) = .init(0);
var unsupported_head: std.atomic.Value(u64) = .init(0);
var by_mask: [16]std.atomic.Value(u64) = @splat(.init(0));

/// One corpus checkpoint in the form the renderers take (all slices live in the item's scratch).
const Loaded = struct {
    cert_bytes: []const u8,
    contents_bytes: []const u8,
    raw_objects: []const []const u8,
    txs: []render_tx.Input,
};

/// `chk/<seq>.chk` plus, when the corpus keeps it, the archive proto's object set and
/// unchanged_loaded_runtime_objects (the .chk form drops them).
fn chkSigs(arena: std.mem.Allocator, idx: *const types.index.CheckpointIndex, t: anytype, blob: []const u8) ![]const []const u8 {
    const sigs = try arena.alloc([]const u8, t.sig_count);
    for (idx.sigs[t.sig_first..][0..t.sig_count], sigs) |sr, *sd| {
        const raw = sr.slice(blob);
        var rd = bcs.Reader.init(raw);
        const n = try rd.length();
        sd.* = try rd.bytes(n);
    }
    return sigs;
}

fn loadChk(ctx: *harness.Ctx, arena: std.mem.Allocator, seq: u64) !Loaded {
    var nb: [160]u8 = undefined;
    const blob = try ctx.readFile(try std.fmt.bufPrint(&nb, "chk/{d}.chk", .{seq}), max_blob);
    if (blob.len == 0 or blob[0] != 1) return error.BadBlob;
    var idx = try types.index.CheckpointIndex.init(ctx.gpa);
    defer idx.deinit(ctx.gpa);
    try types.index.indexCheckpointData(blob, &idx);
    const chk_objects = try arena.alloc([]const u8, idx.obj_total);
    for (idx.objs[0..idx.obj_total], chk_objects) |o, *dst| dst.* = o.slice(blob);
    const txs = try arena.alloc(render_tx.Input, idx.tx_count);
    const arch = try loadArchive(ctx, arena, seq, idx.tx_count);
    for (idx.txs[0..idx.tx_count], txs, 0..) |t, *dst, ti| {
        const sigs = if (arch) |a| (if (a.sigs.len > 0) a.sigs[ti] else try chkSigs(arena, &idx, t, blob)) else try chkSigs(arena, &idx, t, blob);
        dst.* = .{ .transaction = t.data.slice(blob), .signatures = sigs, .effects = t.effects.slice(blob), .events = if (t.events) |e| e.slice(blob) else null, .loaded = if (arch) |a| a.loaded[ti] else &.{} };
    }
    return .{
        .cert_bytes = if (arch) |a| (a.cert orelse blob[idx.summary.o..][0 .. idx.summary.n + idx.sig.n]) else blob[idx.summary.o..][0 .. idx.summary.n + idx.sig.n],
        .contents_bytes = if (arch) |a| (a.contents orelse idx.contents.slice(blob)) else idx.contents.slice(blob),
        .raw_objects = if (arch) |a| a.objects else chk_objects,
        .txs = txs,
    };
}

fn runOne(masks_txt: []const u8, ctx: *harness.Ctx, name: []const u8) !void {
    const seq = harness.leadingNumber(name) orelse return;
    const rec = try readRec(ctx, rec_dir, name);
    const arena = ctx.scratch();
    const ld = try loadChk(ctx, arena, seq);
    const cert_bytes = ld.cert_bytes;
    const contents_bytes = ld.contents_bytes;
    const raw_objects = ld.raw_objects;
    const txs = ld.txs;

    var pos: usize = 0;
    while (pos < rec.len) {
        const kind = rec[pos];
        const mask_id = rec[pos + 1];
        const len = std.mem.readInt(u32, rec[pos + 2 ..][0..4], .little);
        const expected = rec[pos + 6 ..][0..len];
        pos += 6 + len;
        var ib: [64]u8 = undefined;
        const item = try std.fmt.bufPrint(&ib, "ckpt/{d}/m{d}", .{ seq, mask_id });
        if (kind != 1) continue;
        if (!ctx.selected(item)) continue;

        var lines = std.mem.splitScalar(u8, masks_txt, '\n');
        var mask_str: []const u8 = "";
        var i: usize = 0;
        while (lines.next()) |l| : (i += 1) if (i == mask_id) {
            mask_str = l;
            break;
        };
        var tree = try mask.Tree.parse(arena, mask_str);
        const m = tree.mask();
        const out = try arena.alloc(u8, expected.len + (1 << 20));
        var w = proto.Writer.init(out);
        const res = ledger.getCheckpoint(arena, &w, m, cert_bytes, contents_bytes, raw_objects, txs);
        var c = ctx.check(item);
        if (res) |_| {
            c.bytes("GetCheckpointResponse", expected, w.bytesWritten());
            if (!c.ok()) dumpPair(ctx, item, expected, w.bytesWritten());
        } else |e| if (e == error.Unsupported) {
            // A field the renderer does not port yet: the rest of the response is still compared
            // (a mismatch there fails the item), but the item itself is a skip, never a pass.
            var w2 = proto.Writer.init(out);
            if (ledger.getCheckpoint(arena, &w2, m, cert_bytes, contents_bytes, raw_objects, &.{})) |_| {
                const head = try headOnly(arena, expected, true);
                c.bytes("GetCheckpointResponse without transactions", head, w2.bytesWritten());
                _ = unsupported.fetchAdd(1, .monotonic);
                _ = by_mask[mask_id & 15].fetchAdd(1, .monotonic);
                if (c.ok()) {
                    ctx.skip(item, "transactions use a field not ported yet (only the other fields were compared)");
                    continue;
                }
            } else |e2| {
                if (e2 != error.Unsupported) return e2;
                _ = unsupported_head.fetchAdd(1, .monotonic);
                ctx.skip(item, "contents/summary field not ported (zkLogin or legacy multisig signature)");
                continue;
            }
        } else c.failf("render error {s}", .{@errorName(e)});
        _ = c.finish();
    }
}

/// Test provider for service.LoadedSource: transaction digest to its loaded runtime objects, as the
/// archive proto records them (the storage lane's per-transaction list stands in here).
const LoadedMap = struct {
    gpa: std.mem.Allocator,
    map: std.AutoHashMapUnmanaged([32]u8, []const objset.Ref) = .empty,
    fn put(m: *LoadedMap, dg: *const [32]u8, l: []const objset.Ref) !void {
        if (l.len == 0) return;
        try m.map.put(m.gpa, dg.*, try m.gpa.dupe(objset.Ref, l));
    }
    fn deinit(m: *LoadedMap) void {
        var it = m.map.valueIterator();
        while (it.next()) |v| m.gpa.free(v.*);
        m.map.deinit(m.gpa);
    }
    fn get(ctx: *const anyopaque, _: *const store.Snapshot, dg: *const [32]u8, _: u64) []const objset.Ref {
        const m: *const LoadedMap = @ptrCast(@alignCast(ctx));
        return m.map.get(dg.*) orelse &.{};
    }
    fn source(m: *const LoadedMap) service.LoadedSource {
        return .{ .ctx = m, .get = get };
    }
};

const Archive = struct { objects: []const []const u8, loaded: []const []const objset.Ref, cert: ?[]const u8, contents: ?[]const u8, sigs: []const []const []const u8 };

/// `binpb-done/<seq>.binpb.zst`: a sui.rpc.v2 Checkpoint proto as the archive stores it. Returns
/// its object set (BCS) and each transaction's unchanged_loaded_runtime_objects.
fn loadArchive(ctx: *harness.Ctx, arena: std.mem.Allocator, seq: u64, tx_count: usize) !?Archive {
    var nb: [96]u8 = undefined;
    const dec = ctx.readZstd(try std.fmt.bufPrint(&nb, "binpb-done/{d}.binpb.zst", .{seq}), max_blob) catch |e| switch (e) {
        error.FileNotFound => ctx.readZstd(try std.fmt.bufPrint(&nb, "binpb-r4/{d}.binpb.zst", .{seq}), max_blob) catch |e2| switch (e2) {
            error.FileNotFound => return null,
            else => return e2,
        },
        else => return e,
    };
    var objects = std.ArrayList([]const u8).empty;
    const loaded = try arena.alloc([]const objset.Ref, tx_count);
    @memset(loaded, &.{});
    var contents: ?[]const u8 = null;
    var sigs: []const []const []const u8 = &.{};
    var rd = proto.Reader.init(dec);
    var ti: usize = 0;
    var summary: ?[]const u8 = null;
    var sig_epoch: u64 = 0;
    var sig_bytes: ?[]const u8 = null;
    var bitmap: []const u8 = &.{};
    while (try rd.next()) |f| {
        if (f.number == 5) {
            var sr = proto.Reader.init(f.data);
            while (try sr.next()) |sf| if (sf.number == 1) {
                var br = proto.Reader.init(sf.data);
                while (try br.next()) |vf| if (vf.number == 2) {
                    contents = vf.data;
                };
            };
        } else if (f.number == 3) {
            var sr = proto.Reader.init(f.data);
            while (try sr.next()) |sf| if (sf.number == 1) {
                var br = proto.Reader.init(sf.data);
                while (try br.next()) |vf| if (vf.number == 2) {
                    summary = vf.data;
                };
            };
        } else if (f.number == 4) {
            var sr = proto.Reader.init(f.data);
            while (try sr.next()) |sf| switch (sf.number) {
                1 => sig_epoch = sf.varint,
                2 => sig_bytes = sf.data,
                3 => bitmap = sf.data,
                else => {},
            };
        } else if (f.number == 7) {
            var sr = proto.Reader.init(f.data);
            while (try sr.next()) |of| if (of.number == 1) {
                var or_ = proto.Reader.init(of.data);
                while (try or_.next()) |bf| if (bf.number == 1) {
                    var br = proto.Reader.init(bf.data);
                    while (try br.next()) |vf| if (vf.number == 2) try objects.append(arena, vf.data);
                };
            };
        } else if (f.number == 6) {
            if (ti >= tx_count) return error.TxCountMismatch;
            var list = std.ArrayList(objset.Ref).empty;
            var tr = proto.Reader.init(f.data);
            while (try tr.next()) |tf| if (tf.number == 4) {
                var er = proto.Reader.init(tf.data);
                while (try er.next()) |ef| if (ef.number == 15) {
                    var ref: objset.Ref = .{ .id = undefined, .version = 0 };
                    var orr = proto.Reader.init(ef.data);
                    while (try orr.next()) |rf| switch (rf.number) {
                        1 => _ = try std.fmt.hexToBytes(&ref.id, rf.data[2..]),
                        2 => ref.version = rf.varint,
                        else => {},
                    };
                    try list.append(arena, ref);
                };
            };
            loaded[ti] = list.items;
            ti += 1;
        }
    }
    if (ti != tx_count) return error.TxCountMismatch;
    // the archive's own certified summary: BCS(summary) ++ BCS(AuthorityQuorumSignInfo). Its
    // aggregate signature can differ from the .chk file's (another valid quorum certificate).
    var cert: ?[]const u8 = null;
    if (summary != null and sig_bytes != null and sig_bytes.?.len == 48) {
        var out = std.ArrayList(u8).empty;
        try out.appendSlice(arena, summary.?);
        var eb: [8]u8 = undefined;
        std.mem.writeInt(u64, &eb, sig_epoch, .little);
        try out.appendSlice(arena, &eb);
        try out.appendSlice(arena, sig_bytes.?);
        var lb: [10]u8 = undefined;
        var wl = proto.Writer.init(&lb);
        try wl.varint(bitmap.len);
        try out.appendSlice(arena, wl.bytesWritten());
        try out.appendSlice(arena, bitmap);
        cert = out.items;
    }
    // User signatures live in the contents (rpc_proto_conversions TryFrom<&Checkpoint> zips them
    // over the transactions; the archive transactions carry none).
    if (contents) |cbytes| {
        const cc = try bcs.decode(types.CheckpointContents, arena, cbytes);
        const out = try arena.alloc([]const []const u8, tx_count);
        switch (cc) {
            .V1 => |v| {
                if (v.user_signatures.len != tx_count) return error.TxCountMismatch;
                for (v.user_signatures, out) |l, *o| {
                    const x = try arena.alloc([]const u8, l.len);
                    for (l, x) |g, *d| d.* = g.@"0";
                    o.* = x;
                }
            },
            .V2 => |v| {
                if (v.transactions.len != tx_count) return error.TxCountMismatch;
                for (v.transactions, out) |t, *o| {
                    const x = try arena.alloc([]const u8, t.user_signatures.len);
                    for (t.user_signatures, x) |g, *d| d.* = g.@"0".@"0";
                    o.* = x;
                }
            },
        }
        sigs = out;
    }
    return .{ .objects = objects.items, .loaded = loaded, .cert = cert, .contents = contents, .sigs = sigs };
}

fn maskLine(txt: []const u8, id: usize) []const u8 {
    var lines = std.mem.splitScalar(u8, txt, '\n');
    var i: usize = 0;
    while (lines.next()) |l| : (i += 1) if (i == id) return l;
    return "";
}

fn objLess(_: void, a: []const u8, b: []const u8) bool {
    const ka = objset.headKey(a) catch return false;
    const kb = objset.headKey(b) catch return false;
    const o = std.mem.order(u8, ka[0..32], kb[0..32]);
    return if (o == .eq) std.mem.readInt(u64, ka[32..40], .little) < std.mem.readInt(u64, kb[32..40], .little) else o == .lt;
}

/// `vectors/grpc-v2-tx`: GetTransaction (kind 2) and GetObject (kind 3) responses, rendered the
/// way the service renders them from the checkpoint's transactions and object set.
fn runTx(masks: *const [2][]const u8, ctx: *harness.Ctx, name: []const u8) !void {
    const seq = harness.leadingNumber(name) orelse return;
    const rec = try readRec(ctx, tx_dir, name);
    const arena = ctx.scratch();
    const ld = try loadChk(ctx, arena, seq);
    const cert = try render_checkpoint.Cert.parse(arena, ld.cert_bytes);
    // the checkpoint's object set: sorted by key, duplicates collapsed
    const sorted = try arena.dupe([]const u8, ld.raw_objects);
    std.mem.sort([]const u8, sorted, {}, objLess);
    var uniq = std.ArrayList([]const u8).empty;
    for (sorted) |raw| {
        if (uniq.items.len > 0 and !objLess({}, uniq.items[uniq.items.len - 1], raw)) continue;
        try uniq.append(arena, raw);
    }
    var have: std.AutoHashMapUnmanaged(objset.Key, []const u8) = .empty;
    for (uniq.items) |raw| try have.put(arena, try objset.headKey(raw), raw);
    var pos: usize = 0;
    while (pos < rec.len) {
        const kind = rec[pos];
        const mask_id = rec[pos + 1];
        const index = std.mem.readInt(u32, rec[pos + 2 ..][0..4], .little);
        const len = std.mem.readInt(u32, rec[pos + 6 ..][0..4], .little);
        const expected = rec[pos + 10 ..][0..len];
        pos += 10 + len;
        var ib: [64]u8 = undefined;
        const item = try std.fmt.bufPrint(&ib, "{s}/{d}/{d}/m{d}", .{ if (kind == 2) "tx" else "obj", seq, index, mask_id });
        if (!ctx.selected(item)) continue;
        const out = try arena.alloc(u8, expected.len + (1 << 20));
        var w = proto.Writer.init(out);
        var c = ctx.check(item);
        if (kind == 2) {
            var tree = try mask.Tree.parse(arena, maskLine(masks[0], mask_id));
            const t = ld.txs[index];
            const sp_td = try bcs.decode(types.TransactionData, arena, t.transaction);
            const eff = try bcs.decode(types.TransactionEffects, arena, t.effects);
            var tx_raws = std.ArrayList([]const u8).empty;
            const m = tree.mask();
            const needs_set = m.contains("balance_changes") or m.contains("effects") or m.contains("objects");
            for (if (needs_set) try txobjects.keys(arena, sp_td, eff, t.loaded) else &[_]objset.Ref{}) |k| {
                try tx_raws.append(arena, have.get(objset.key(&k.id, k.version)) orelse {
                    c.failf("object {x} v{d} of the transaction's object set is not in the checkpoint's", .{ k.id, k.version });
                    break;
                });
            }
            if (!c.ok()) {
                _ = c.finish();
                continue;
            }
            const mm = try w.begin(1, 4096);
            ledger.writeExecutedBody(arena, &w, tree.mask(), t, cert.summary.sequence_number, cert.summary.timestamp_ms, tx_raws.items) catch |e| {
                if (e == error.Unsupported) {
                    ctx.skip(item, "field not ported");
                    continue;
                }
                return e;
            };
            try w.end(mm);
        } else {
            var tree = try mask.Tree.parse(arena, maskLine(masks[1], mask_id));
            const mm = try w.begin(1, 4096);
            try render_object.writeObject(arena, &w, tree.mask(), uniq.items[index]);
            try w.end(mm);
        }
        c.bytes(if (kind == 2) "GetTransactionResponse" else "GetObjectResponse", expected, w.bytesWritten());
        if (!c.ok()) dumpPair(ctx, item, expected, w.bytesWritten());
        _ = c.finish();
    }
}

/// `vectors/grpc-v2-misc/exec-status.bin`: every ExecutionErrorKind (synthetic values) through
/// Mysten's `From<ExecutionStatus>`, including the Rust `Debug` text of the description.
fn runExecStatus(ctx: *harness.Ctx) !void {
    const data = try ctx.readFile(misc_dir ++ "/exec-status.bin", max_blob);
    const arena = ctx.scratch();
    var pos: usize = 0;
    var n: usize = 0;
    while (pos < data.len) : (n += 1) {
        const bl = std.mem.readInt(u32, data[pos..][0..4], .little);
        const b = data[pos + 4 ..][0..bl];
        pos += 4 + bl;
        const pl = std.mem.readInt(u32, data[pos..][0..4], .little);
        const expected = data[pos + 4 ..][0..pl];
        pos += 4 + pl;
        var ib: [48]u8 = undefined;
        const item = try std.fmt.bufPrint(&ib, "exec-status/{d}", .{n});
        if (!ctx.selected(item)) continue;
        const st = try bcs.decode(types.ExecutionStatus, arena, b);
        const out = try arena.alloc(u8, expected.len + 4096);
        var w = proto.Writer.init(out);
        try exec_error.writeStatus(arena, &w, 4, st);
        _ = ctx.expectBytes(item, "ExecutionStatus", expected, w.bytesWritten());
    }
}

/// `vectors/grpc-v2-misc/status-r3.txt` (`zui-serve-truth status`; main before this branch reads `status.txt`): request handling as sui-rpc-api
/// does it on an empty store (validation order, prost merging, sui-sdk-types digest and address
/// parsing, not-found texts, batch limits and per-item errors). Each request goes over loopback
/// HTTP/2 to the service on an empty store; the gRPC code, `grpc-message` and
/// `grpc-status-details-bin` (or, for code 0, the response message) must equal the truth.
fn runStatus(ctx: *harness.Ctx) !void {
    const txt = try ctx.corpus.readFileAlloc(ctx.io, misc_dir ++ "/status-r3.txt", ctx.gpa, .limited(1 << 24));
    defer ctx.gpa.free(txt);
    const gpa = ctx.gpa;
    const dir = try sessionDir(gpa, ctx, "status-store");
    defer gpa.free(dir);
    std.Io.Dir.cwd().deleteTree(ctx.io, dir) catch {};
    defer std.Io.Dir.cwd().deleteTree(ctx.io, dir) catch {};
    var cfg: store.Config = .{ .dir = dir, .max_live_objects = 1 << 10, .max_object_versions = 1 << 10, .max_transactions = 1 << 10, .max_checkpoints = 1 << 6, .max_batch_bytes = 1 << 20, .max_batch_objects = 1 << 10, .max_segments = 16, .segment_reserve = 1 << 20, .seed = 7 };
    var h = try store.openDir(gpa, ctx.io, &cfg, .{ .sync = .none });
    defer {
        h.store.deinit();
        h.io.deinit();
    }
    var svc: service.Service = .{ .gpa = gpa, .store = h.store, .chain_id = @splat(0), .json = false, .display = false };
    defer svc.deinit();
    const handler = svc.handler();
    const arena = ctx.scratch();
    var lines = std.mem.splitScalar(u8, txt, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var cols = std.mem.splitScalar(u8, line, '\t');
        const name = cols.next() orelse return error.BadVector;
        const method = cols.next() orelse return error.BadVector;
        const req_hex = cols.next() orelse return error.BadVector;
        const code_text = cols.next() orelse return error.BadVector;
        const exp_hex = cols.next() orelse return error.BadVector;
        // "decode": a request prost rejects; tonic answers Status::internal(text) with no details
        const is_decode = if (cols.next()) |t| std.mem.eql(u8, t, "decode") else false;
        var ib: [96]u8 = undefined;
        const item = try std.fmt.bufPrint(&ib, "status/{s}", .{name});
        if (!ctx.selected(item)) continue;
        const req = try arena.alloc(u8, req_hex.len / 2);
        _ = try std.fmt.hexToBytes(req, req_hex);
        const expected = try arena.alloc(u8, exp_hex.len / 2);
        _ = try std.fmt.hexToBytes(expected, exp_hex);
        const code = try std.fmt.parseInt(u8, code_text, 10);
        const path = if (std.mem.indexOfScalar(u8, method, '/') != null)
            try std.fmt.allocPrint(arena, "/sui.rpc.v2.{s}", .{method})
        else
            try std.fmt.allocPrint(arena, "/sui.rpc.v2.LedgerService/{s}", .{method});
        const reply = try loopback.unary(arena, handler, path, req);
        var c = ctx.check(item);
        if (reply.status != code) {
            c.failf("grpc-status {d} ({s}), expected {d}", .{ reply.status, reply.grpc_message, code });
        } else if (is_decode) {
            c.bytes("grpc-message", expected, reply.grpc_message);
            c.bytes("grpc-status-details-bin (none)", "", reply.details);
        } else if (code == 0) {
            c.bytes("response message", expected, reply.message);
        } else {
            c.bytes("grpc-status-details-bin", expected, reply.details);
            // google.rpc.Status.message (field 2) is also the grpc-message
            var want_msg: []const u8 = "";
            var rd = proto.Reader.init(expected);
            while (try rd.next()) |f| if (f.number == 2) {
                want_msg = f.data;
            };
            c.bytes("grpc-message", want_msg, reply.grpc_message);
        }
        _ = c.finish();
    }
}

const pkg_dir = "vectors/grpc-v2-pkg";

/// A scratch store directory private to this process: two runs of the suite (or another agent's
/// cleanup of `sessions/serve`) must not delete each other's stores.
fn sessionDir(gpa: std.mem.Allocator, ctx: *harness.Ctx, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(gpa, "{s}/sessions/serve/{d}-{s}", .{ ctx.corpus_path, std.c.getpid(), name });
}

const PkgState = struct { handler: @import("h2/root.zig").Handler, live: *const std.StringHashMapUnmanaged(void) };

/// MovePackageService against the `grpc-v2-pkg` records (Mysten's `get_package_response`,
/// `get_datatype_response`, `get_function_response` over the package objects of the corpus):
/// every record is rendered straight from the object bytes; the package versions the store holds
/// (the highest version of each id) are also asked through loopback HTTP/2.
fn runPackages(ctx: *harness.Ctx) !void {
    const gpa = ctx.gpa;
    const names = try ctx.listFiles(pkg_dir, ".pkg.zst");
    defer ctx.freeNames(names);
    // highest version per package id
    var best: std.StringHashMapUnmanaged(u64) = .empty;
    defer best.deinit(gpa);
    for (names) |n| {
        const dash = std.mem.indexOfScalar(u8, n, '-') orelse continue;
        const ver = std.fmt.parseInt(u64, n[dash + 1 ..][0 .. std.mem.indexOf(u8, n[dash + 1 ..], ".") orelse continue], 10) catch continue;
        const e = try best.getOrPut(gpa, n[0..dash]);
        if (!e.found_existing or e.value_ptr.* < ver) e.value_ptr.* = ver;
    }
    const dir = try sessionDir(gpa, ctx, "pkg-store");
    defer gpa.free(dir);
    std.Io.Dir.cwd().deleteTree(ctx.io, dir) catch {};
    defer std.Io.Dir.cwd().deleteTree(ctx.io, dir) catch {};
    var cfg: store.Config = .{ .dir = dir, .max_live_objects = 1 << 12, .max_object_versions = 1 << 12, .max_transactions = 1 << 10, .max_checkpoints = 1 << 6, .max_batch_bytes = 1 << 27, .max_batch_objects = 1 << 12, .max_segments = 16, .segment_reserve = 1 << 26, .seed = 7 };
    var h = try store.openDir(gpa, ctx.io, &cfg, .{ .sync = .none });
    defer {
        h.store.deinit();
        h.io.deinit();
    }
    var live: std.StringHashMapUnmanaged(void) = .empty;
    defer live.deinit(gpa);
    {
        const b = try h.store.begin(1, 0);
        for (names) |n| {
            const dash = std.mem.indexOfScalar(u8, n, '-') orelse continue;
            const ver = std.fmt.parseInt(u64, n[dash + 1 ..][0 .. std.mem.indexOf(u8, n[dash + 1 ..], ".") orelse continue], 10) catch continue;
            if (best.get(n[0..dash]).? != ver) continue;
            const rec = try ctx.readZstd(try std.fmt.allocPrint(ctx.scratch(), pkg_dir ++ "/{s}", .{n}), max_blob);
            const olen = std.mem.readInt(u32, rec[0..4], .little);
            const raw = rec[4..][0..olen];
            var id: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&id, n[0..dash]);
            try b.putObject(&id, ver, &types.digest.objectDigest(raw), raw);
            try live.put(gpa, n, {});
        }
        const np = try ctx.listFiles(pkg_dir, ".rec");
        defer ctx.freeNames(np);
        for (np) |n| {
            const rec = try ctx.readFile(try std.fmt.allocPrint(ctx.scratch(), pkg_dir ++ "/{s}", .{n}), max_blob);
            const raw = rec[4..][0..std.mem.readInt(u32, rec[0..4], .little)];
            const obj = try bcs.decode(types.Object, ctx.scratch(), raw);
            const mo = obj.data.Move;
            try b.putObject(mo.contents[0..32], mo.version.@"0", &types.digest.objectDigest(raw), raw);
        }
        try b.checkpoint("summary", "contents");
        try h.store.commit(b);
    }
    var svc: service.Service = .{ .gpa = gpa, .store = h.store, .chain_id = @splat(0), .json = false, .display = false };
    defer svc.deinit();
    var st: PkgState = .{ .handler = svc.handler(), .live = &live };
    try ctx.forEachName(names, &st, pkgOne);
    try pkgNotPackage(ctx, st.handler);
}

fn pkgOne(st: *const PkgState, ctx: *harness.Ctx, name: []const u8) !void {
    const arena = ctx.scratch();
    var nb: [160]u8 = undefined;
    const rec = try ctx.readZstd(try std.fmt.bufPrint(&nb, pkg_dir ++ "/{s}", .{name}), max_blob);
    const olen = std.mem.readInt(u32, rec[0..4], .little);
    const raw = rec[4..][0..olen];
    const stem = name[0 .. name.len - ".pkg.zst".len];
    const is_live = st.live.contains(name);
    var id_text: [66]u8 = undefined;
    {
        var idb: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&idb, stem[0..64]);
        var o: typestr.Out = .{ .buf = &id_text };
        try o.address(&idb);
    }
    var pkg: movepkg.Package = undefined;
    const readres = movepkg.read(arena, raw, &pkg);
    var pos: usize = 4 + olen;
    while (pos < rec.len) {
        const kind = rec[pos];
        const ml = std.mem.readInt(u16, rec[pos + 1 ..][0..2], .little);
        const mod = rec[pos + 3 ..][0..ml];
        pos += 3 + ml;
        const nl = std.mem.readInt(u16, rec[pos..][0..2], .little);
        const nm = rec[pos + 2 ..][0..nl];
        pos += 2 + nl;
        const st_byte = rec[pos];
        const blen = std.mem.readInt(u32, rec[pos + 1 ..][0..4], .little);
        const expected = rec[pos + 5 ..][0..blen];
        pos += 5 + blen;
        var ib: [320]u8 = undefined;
        const item = try std.fmt.bufPrint(&ib, "pkg/{s}/{d}/{s}/{s}", .{ stem, kind, mod, nm });
        if (!ctx.selected(item)) continue;
        var c = ctx.check(item);
        // direct: the renderer on the object bytes
        var direct_err: ?[]const u8 = null;
        var actual: []const u8 = "";
        if (readres) |_| {
            const buf = try arena.alloc(u8, @max(blen * 2, 1 << 16));
            var w = proto.Writer.init(buf);
            const r = switch (kind) {
                1 => movepkg.writePackage(arena, &w, &pkg),
                2 => movepkg.writeDatatypeResponse(arena, &w, &pkg, mod, nm),
                else => movepkg.writeFunctionResponse(arena, &w, &pkg, mod, nm),
            };
            if (r) |_| actual = w.bytesWritten() else |e| switch (e) {
                error.Resolver => direct_err = pkg.message,
                else => return e,
            }
        } else |e| switch (e) {
            error.Resolver => direct_err = pkg.message,
            else => return e,
        }
        if (st_byte == 0) {
            if (direct_err) |m| c.failf("resolver error: {s}", .{m}) else c.bytes("response", expected, actual);
        } else {
            if (direct_err) |m| c.bytes("INTERNAL message", expected, m) else c.failf("expected INTERNAL '{s}', got a response", .{expected});
        }
        // through the service, for the version the store holds
        if (is_live) {
            const method = switch (kind) {
                1 => "GetPackage",
                2 => "GetDatatype",
                else => "GetFunction",
            };
            const rb = try arena.alloc(u8, 512 + mod.len + nm.len);
            var rw = proto.Writer.init(rb);
            try rw.string(1, &id_text);
            if (kind != 1) {
                try rw.string(2, mod);
                try rw.string(3, nm);
            }
            const reply = try loopback.unary(arena, st.handler, try std.fmt.allocPrint(arena, "/sui.rpc.v2.MovePackageService/{s}", .{method}), rw.bytesWritten());
            if (st_byte == 0) {
                if (reply.status != 0) c.failf("grpc-status {d}: {s}", .{ reply.status, reply.grpc_message }) else c.bytes("response over HTTP/2", expected, reply.message);
            } else {
                if (reply.status != 13) c.failf("grpc-status {d}, expected INTERNAL", .{reply.status}) else c.bytes("INTERNAL message over HTTP/2", expected, reply.grpc_message);
            }
            // get_package.rs load_package_at_version: a `version` selector equal to the stored
            // version answers from the package itself, without the package-version index
            if (kind == 1) {
                const ver = std.fmt.parseInt(u64, stem[65..], 10) catch return error.BadVector;
                try rw.uint(2, ver);
                const r2 = try loopback.unary(arena, st.handler, "/sui.rpc.v2.MovePackageService/GetPackage", rw.bytesWritten());
                if (st_byte == 0) {
                    if (r2.status != 0) c.failf("version selector: grpc-status {d}: {s}", .{ r2.status, r2.grpc_message }) else c.bytes("response over HTTP/2 (version selector)", expected, r2.message);
                } else {
                    if (r2.status != 13) c.failf("version selector: grpc-status {d}, expected INTERNAL", .{r2.status}) else c.bytes("INTERNAL message over HTTP/2 (version selector)", expected, r2.grpc_message);
                }
            }
        }
        _ = c.finish();
    }
}

/// GetPackage on an object that is not a package: INVALID_ARGUMENT "object is not a package".
fn pkgNotPackage(ctx: *harness.Ctx, handler: @import("h2/root.zig").Handler) !void {
    const names = try ctx.listFiles(pkg_dir, ".rec");
    defer ctx.freeNames(names);
    for (names) |n| {
        var ib: [160]u8 = undefined;
        const item = try std.fmt.bufPrint(&ib, "pkg/{s}/not-a-package", .{n[0 .. n.len - 4]});
        if (!ctx.selected(item)) continue;
        const arena = ctx.scratch();
        var idb: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&idb, n["notpkg-".len..][0..64]);
        var id_text: [66]u8 = undefined;
        var o: typestr.Out = .{ .buf = &id_text };
        try o.address(&idb);
        const rb = try arena.alloc(u8, 128);
        var rw = proto.Writer.init(rb);
        try rw.string(1, o.str());
        var c = ctx.check(item);
        for ([_][]const u8{ "GetPackage", "GetDatatype", "GetFunction" }) |method| {
            var w2 = proto.Writer.init(rb);
            try w2.string(1, o.str());
            if (!std.mem.eql(u8, method, "GetPackage")) {
                try w2.string(2, "m");
                try w2.string(3, "n");
            }
            const reply = try loopback.unary(arena, handler, try std.fmt.allocPrint(arena, "/sui.rpc.v2.MovePackageService/{s}", .{method}), w2.bytesWritten());
            // RpcError::new(InvalidArgument, "object is not a package"): code 3, Status{3, msg} details
            if (reply.status != 3) c.failf("{s}: grpc-status {d}, expected 3", .{ method, reply.status }) else {
                c.bytes("grpc-message", "object is not a package", reply.grpc_message);
                c.bytes("grpc-status-details-bin", "\x08\x03\x12\x17object is not a package", reply.details);
            }
        }
        _ = c.finish();
    }
}

/// With ZUI_SERVE_DUMP=<dir> set, writes both sides of a mismatch for offline diffing.
fn dumpPair(ctx: *harness.Ctx, item: []const u8, expected: []const u8, actual: []const u8) void {
    const dir = std.c.getenv("ZUI_SERVE_DUMP") orelse return;
    var nb: [256]u8 = undefined;
    for ([_]struct { []const u8, []const u8 }{ .{ "expected", expected }, .{ "actual", actual } }) |e| {
        const path = std.fmt.bufPrint(&nb, "{s}/{s}.{s}.bin", .{ std.mem.span(dir), std.mem.replaceOwned(u8, ctx.scratch(), item, "/", "_") catch return, e[0] }) catch return;
        std.Io.Dir.cwd().writeFile(ctx.io, .{ .sub_path = path, .data = e[1] }) catch {};
    }
}

/// Truth response with field 6 of the Checkpoint dropped, re-wrapped as field 1.
fn headOnly(arena: std.mem.Allocator, resp: []const u8, keep_objects: bool) ![]const u8 {
    var rd = proto.Reader.init(resp);
    const f = (try rd.next()) orelse return &.{};
    var body = std.ArrayList(u8).empty;
    var inner = proto.Reader.init(f.data);
    while (true) {
        const start = inner.pos;
        const g = (try inner.next()) orelse break;
        if (g.number <= 5 or (g.number == 7 and keep_objects)) try body.appendSlice(arena, f.data[start..inner.pos]);
    }
    var out = std.ArrayList(u8).empty;
    var hdr: [16]u8 = undefined;
    var hw = proto.Writer.init(&hdr);
    try hw.tag(1, proto.wire_len);
    try hw.varint(body.items.len);
    try out.appendSlice(arena, hw.bytesWritten());
    try out.appendSlice(arena, body.items);
    return out.items;
}

/// End to end: the corpus records are ingested into a real on-disk store (the storage lane's
/// ops files), and GetCheckpoint / GetTransaction / GetObject calls travel through a loopback
/// HTTP/2 connection and the service. Items are `e2e/ckpt/<seq>/m<mask>`, `e2e/tx/<seq>/<i>`
/// (digest + effects.bcs) and `e2e/obj/<seq>`.
fn runE2e(ctx: *harness.Ctx, masks_txt: []const u8, txmasks: []const u8, objmasks: []const u8) !void {
    const gpa = ctx.gpa;
    const names = try ctx.listFiles(rec_dir, ".rec.zst");
    defer ctx.freeNames(names);
    const dir = try sessionDir(gpa, ctx, "e2e-store");
    defer gpa.free(dir);
    std.Io.Dir.cwd().deleteTree(ctx.io, dir) catch {};
    defer std.Io.Dir.cwd().deleteTree(ctx.io, dir) catch {};
    var cfg: store.Config = .{ .dir = dir, .max_live_objects = 1 << 16, .max_object_versions = 1 << 18, .max_transactions = 1 << 16, .max_checkpoints = 1 << 12, .max_batch_bytes = 256 << 20, .max_batch_objects = 1 << 16, .max_segments = 2048, .segment_reserve = 16 << 20, .seed = 7 };
    var h = try store.openDir(gpa, ctx.io, &cfg, .{ .sync = .none });
    defer {
        h.store.deinit();
        h.io.deinit();
    }
    var ineligible: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer ineligible.deinit(gpa);
    var loaded_map: LoadedMap = .{ .gpa = gpa };
    defer loaded_map.deinit();
    var missing_tx: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer missing_tx.deinit(gpa);
    var archive_seqs: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer archive_seqs.deinit(gpa);
    var eidx = try types.index.CheckpointIndex.init(gpa);
    defer eidx.deinit(gpa);
    for (names) |name| {
        const seq = harness.leadingNumber(name) orelse continue;
        var nb: [96]u8 = undefined;
        const blob = try ctx.readFile(try std.fmt.bufPrint(&nb, "chk/{d}.chk", .{seq}), max_blob);
        const opsb = try ctx.readFile(try std.fmt.bufPrint(&nb, "vectors/store-replay/ops/{d}.ops", .{seq}), max_blob);
        const arena = ctx.scratch();
        var cp = try store.ops.parse(arena, opsb, blob);
        const b = h.store.begin(cp.seq, cp.epoch) catch |e| {
            std.debug.print("e2e ingest: begin seq {d} epoch {d}: {s}\n", .{ cp.seq, cp.epoch, @errorName(e) });
            return e;
        };
        // The node keeps every object version a transaction read (immutable inputs, read-only
        // roots, older versions): add the checkpoint's object set, oldest version first, ahead of
        // the checkpoint's own writes.
        try types.index.indexCheckpointData(blob, &eidx);
        var raws = std.ArrayList([]const u8).empty;
        if (try loadArchive(ctx, arena, seq, eidx.tx_count)) |a| {
            try raws.appendSlice(arena, a.objects);
            try archive_seqs.put(gpa, seq, {});
            if (a.cert) |c| {
                cp.summary_cert = c;
            }
            if (a.contents) |c| cp.contents = c;
            for (cp.txs, a.loaded, 0..) |*t, l, ti| {
                const sp = try service.splitEnvelope(arena, t.tx);
                if (a.sigs.len > 0) {
                    var env = std.ArrayList(u8).empty;
                    try env.appendSlice(arena, t.tx[0..4]);
                    try env.appendSlice(arena, sp.data);
                    var lb: [10]u8 = undefined;
                    var wl = proto.Writer.init(&lb);
                    try wl.varint(a.sigs[ti].len);
                    try env.appendSlice(arena, wl.bytesWritten());
                    for (a.sigs[ti]) |sg| {
                        var wl2 = proto.Writer.init(&lb);
                        try wl2.varint(sg.len);
                        try env.appendSlice(arena, wl2.bytesWritten());
                        try env.appendSlice(arena, sg);
                    }
                    t.tx = env.items;
                }
                try loaded_map.put(&types.digest.transactionDataDigest(sp.data), l);
            }
        } else for (eidx.objs[0..eidx.obj_total]) |o| try raws.append(arena, o.slice(blob));
        const Extra = struct { key: objset.Key, id: [32]u8, version: u64, raw: []const u8 };
        var extras = std.ArrayList(Extra).empty;
        // The lossy .chk form lacks some objects a transaction read (immutable inputs): the node
        // would fail such a request, so e2e only covers checkpoints whose transactions all have
        // their full object set in the corpus.
        {
            var have: std.AutoHashMapUnmanaged(objset.Key, void) = .empty;
            for (raws.items) |raw| try have.put(arena, try objset.headKey(raw), {});
            var complete = true;
            for (cp.txs, 0..) |t, ti| {
                const sp = try service.splitEnvelope(arena, t.tx);
                const td = try bcs.decode(types.TransactionData, arena, sp.data);
                const eff = try bcs.decode(types.TransactionEffects, arena, t.effects);
                for (try txobjects.keys(arena, td, eff, &.{})) |k| {
                    if (!have.contains(objset.key(&k.id, k.version))) {
                        complete = false;
                        try missing_tx.put(gpa, (seq << 24) | ti, {});
                    }
                }
            }
            if (!complete) {
                try ineligible.put(gpa, seq, {});
            }
        }
        var snap = h.store.snapshot();
        defer snap.release();
        for (raws.items) |raw| {
            const k = try objset.headKey(raw);
            const id = k[0..32].*;
            const version = std.mem.readInt(u64, k[32..40], .little);
            if (snap.objectAt(&id, version) != null) continue;
            var written = false;
            for (cp.txs) |t| for (t.puts) |p| {
                if (p.version == version and std.mem.eql(u8, p.id, &id)) written = true;
            };
            if (!written) try extras.append(arena, .{ .key = k, .id = id, .version = version, .raw = raw });
        }
        std.mem.sort(Extra, extras.items, {}, struct {
            fn lt(_: void, x: Extra, y: Extra) bool {
                const o = std.mem.order(u8, &x.id, &y.id);
                return if (o == .eq) x.version < y.version else o == .lt;
            }
        }.lt);
        for (extras.items, 0..) |x, i| {
            if (i > 0 and std.mem.eql(u8, &extras.items[i - 1].key, &x.key)) continue;
            try b.putObject(&x.id, x.version, &types.digest.objectDigest(x.raw), x.raw);
        }
        store.ops.apply(b, &cp) catch |e| {
            std.debug.print("e2e ingest: apply seq {d}: {s}\n", .{ cp.seq, @errorName(e) });
            return e;
        };
        h.store.commit(b) catch |e| {
            std.debug.print("e2e ingest: commit seq {d} epoch {d}: {s}\n", .{ cp.seq, cp.epoch, @errorName(e) });
            return e;
        };
    }
    var svc: service.Service = .{ .gpa = gpa, .store = h.store, .chain_id = @splat(0), .json = false, .display = false, .loaded = loaded_map.source() };
    defer svc.deinit();
    const handler = svc.handler();

    var st: E2e = .{ .handler = handler, .masks = masks_txt, .txmasks = txmasks, .objmasks = objmasks, .ineligible = &ineligible, .missing_tx = &missing_tx, .archive = &archive_seqs };
    try ctx.forEachName(names, &st, e2eOne);
    std.debug.print("e2e skips: lossy {d}, no_loaded {d}\n", .{ n_lossy.load(.monotonic), n_no_loaded.load(.monotonic) });
}

/// GetTransaction, GetObject, BatchGetTransactions and BatchGetObjects over loopback HTTP/2 against
/// the store, compared with the `grpc-v2-tx` records (a batch is the concatenation of its items).
fn e2eTxObj(st: *const E2e, ctx: *harness.Ctx, seq: u64, name: []const u8) !void {
    const rec = try readRec(ctx, tx_dir, name);
    const arena = ctx.scratch();
    const ld = try loadChk(ctx, arena, seq);
    const sorted = try arena.dupe([]const u8, ld.raw_objects);
    std.mem.sort([]const u8, sorted, {}, objLess);
    var uniq = std.ArrayList([]const u8).empty;
    for (sorted) |raw| {
        if (uniq.items.len > 0 and !objLess({}, uniq.items[uniq.items.len - 1], raw)) continue;
        try uniq.append(arena, raw);
    }
    // batch accumulators per mask: request bytes and expected reply bytes
    const nmasks = 16;
    var obj_req: [nmasks]std.ArrayList(u8) = @splat(.empty);
    var obj_exp: [nmasks]std.ArrayList(u8) = @splat(.empty);
    var tx_req: [nmasks]std.ArrayList(u8) = @splat(.empty);
    var tx_exp: [nmasks]std.ArrayList(u8) = @splat(.empty);
    var pos: usize = 0;
    while (pos < rec.len) {
        const kind = rec[pos];
        const mask_id = rec[pos + 1];
        const index = std.mem.readInt(u32, rec[pos + 2 ..][0..4], .little);
        const len = std.mem.readInt(u32, rec[pos + 6 ..][0..4], .little);
        const expected = rec[pos + 10 ..][0..len];
        pos += 10 + len;
        var ib: [64]u8 = undefined;
        const item = try std.fmt.bufPrint(&ib, "e2e/{s}/{d}/{d}/m{d}", .{ if (kind == 2) "tx" else "obj", seq, index, mask_id });
        if (!ctx.selected(item)) continue;
        const mask_str = maskLine(if (kind == 2) st.txmasks else st.objmasks, mask_id);
        var mbuf = std.ArrayList(u8).empty;
        {
            const mm = try arena.alloc(u8, mask_str.len * 2 + 16);
            var mw = proto.Writer.init(mm);
            var it = std.mem.splitScalar(u8, mask_str, ',');
            while (it.next()) |p| try mw.string(1, p);
            try mbuf.appendSlice(arena, mw.bytesWritten());
        }
        var req = std.ArrayList(u8).empty;
        if (kind == 3) {
            const hk = try objset.headKey(uniq.items[index]);
            var idbuf: [66]u8 = undefined;
            var o: typestr.Out = .{ .buf = &idbuf };
            try o.address(hk[0..32]);
            const version = std.mem.readInt(u64, hk[32..40], .little);
            const one = try arena.alloc(u8, 160);
            var w = proto.Writer.init(one);
            try w.string(1, o.str());
            try w.uint(2, version);
            // GetObjectRequest { object_id = 1, version = 2, read_mask = 3 }
            const wrapped = try arena.alloc(u8, w.len + mbuf.items.len + 16);
            var w2 = proto.Writer.init(wrapped);
            try w2.bytes(0 + 1, o.str());
            try w2.uint(2, version);
            try w2.bytes(3, mbuf.items);
            try req.appendSlice(arena, w2.bytesWritten());
            const reply = try loopback.unary(arena, st.handler, "/sui.rpc.v2.LedgerService/GetObject", req.items);
            var c = ctx.check(item);
            if (reply.status != 0) c.failf("grpc-status {d}: {s}", .{ reply.status, reply.grpc_message }) else c.bytes("GetObjectResponse over HTTP/2", expected, reply.message);
            _ = c.finish();
            // batch accumulation: requests (1) = GetObjectRequest without the mask
            const item_req = try arena.alloc(u8, 160);
            var w3 = proto.Writer.init(item_req);
            try w3.bytes(1, o.str());
            try w3.uint(2, version);
            const outer = try arena.alloc(u8, w3.len + 8);
            var w4 = proto.Writer.init(outer);
            try w4.bytes(1, w3.bytesWritten());
            try obj_req[mask_id].appendSlice(arena, w4.bytesWritten());
            const ex = try arena.alloc(u8, expected.len + 8);
            var w5 = proto.Writer.init(ex);
            try w5.bytes(1, expected);
            try obj_exp[mask_id].appendSlice(arena, w5.bytesWritten());
        } else if (kind == 2) {
            if (st.missing_tx.contains((seq << 24) | index)) {
                var tree = try mask.Tree.parse(arena, mask_str);
                if (service.needsObjectSet(tree.mask())) {
                    skipCount(ctx, item, skip_lossy);
                    continue;
                }
            }
            const t = ld.txs[index];
            const dg = types.digest.transactionDataDigest(t.transaction);
            var dbuf: [b58.max_len_32]u8 = undefined;
            const dtext = b58.encode32(&dbuf, &dg);
            const one = try arena.alloc(u8, 128 + mbuf.items.len);
            var w = proto.Writer.init(one);
            try w.string(1, dtext);
            try w.bytes(2, mbuf.items);
            const reply = try loopback.unary(arena, st.handler, "/sui.rpc.v2.LedgerService/GetTransaction", w.bytesWritten());
            var c = ctx.check(item);
            if (reply.status != 0) c.failf("grpc-status {d}: {s}", .{ reply.status, reply.grpc_message }) else c.bytes("GetTransactionResponse over HTTP/2", expected, reply.message);
            _ = c.finish();
            const rq = try arena.alloc(u8, 64);
            var w3 = proto.Writer.init(rq);
            try w3.string(1, dtext);
            try tx_req[mask_id].appendSlice(arena, w3.bytesWritten());
            const ex = try arena.alloc(u8, expected.len + 8);
            var w5 = proto.Writer.init(ex);
            try w5.bytes(1, expected);
            try tx_exp[mask_id].appendSlice(arena, w5.bytesWritten());
        }
    }
    for (0..nmasks) |mi| {
        if (obj_req[mi].items.len > 0) {
            var ib: [64]u8 = undefined;
            const item = try std.fmt.bufPrint(&ib, "e2e/batchobj/{d}/m{d}", .{ seq, mi });
            if (!ctx.selected(item)) continue;
            const mask_str = maskLine(st.objmasks, mi);
            const mm = try arena.alloc(u8, mask_str.len * 2 + 16);
            var mw = proto.Writer.init(mm);
            var it = std.mem.splitScalar(u8, mask_str, ',');
            while (it.next()) |p| try mw.string(1, p);
            const full = try arena.alloc(u8, obj_req[mi].items.len + mw.len + 16);
            var fw = proto.Writer.init(full);
            try fw.rawAppend(obj_req[mi].items);
            try fw.bytes(2, mw.bytesWritten());
            const reply = try loopback.unary(arena, st.handler, "/sui.rpc.v2.LedgerService/BatchGetObjects", fw.bytesWritten());
            var c = ctx.check(item);
            if (reply.status != 0) c.failf("grpc-status {d}: {s}", .{ reply.status, reply.grpc_message }) else c.bytes("BatchGetObjectsResponse over HTTP/2", obj_exp[mi].items, reply.message);
            _ = c.finish();
        }
        if (tx_req[mi].items.len > 0) {
            var ib: [64]u8 = undefined;
            const item = try std.fmt.bufPrint(&ib, "e2e/batchtx/{d}/m{d}", .{ seq, mi });
            if (!ctx.selected(item)) continue;
            const mask_str = maskLine(st.txmasks, mi);
            const mm = try arena.alloc(u8, mask_str.len * 2 + 16);
            var mw = proto.Writer.init(mm);
            var it = std.mem.splitScalar(u8, mask_str, ',');
            while (it.next()) |p| try mw.string(1, p);
            const full = try arena.alloc(u8, tx_req[mi].items.len + mw.len + 16);
            var fw = proto.Writer.init(full);
            try fw.rawAppend(tx_req[mi].items);
            try fw.bytes(2, mw.bytesWritten());
            const reply = try loopback.unary(arena, st.handler, "/sui.rpc.v2.LedgerService/BatchGetTransactions", fw.bytesWritten());
            var c = ctx.check(item);
            if (reply.status != 0) c.failf("grpc-status {d}: {s}", .{ reply.status, reply.grpc_message }) else c.bytes("BatchGetTransactionsResponse over HTTP/2", tx_exp[mi].items, reply.message);
            _ = c.finish();
        }
    }
}

var n_lossy = std.atomic.Value(u64).init(0);
var n_no_loaded = std.atomic.Value(u64).init(0);
fn skipCount(ctx: *harness.Ctx, item: []const u8, reason: []const u8) void {
    _ = (if (reason.ptr == skip_lossy.ptr) &n_lossy else &n_no_loaded).fetchAdd(1, .monotonic);
    ctx.skip(item, reason);
}
const skip_no_loaded = "store keeps no per-transaction unchanged_loaded_runtime_objects list (storage request in CONTRACTS 6.6)";
const skip_lossy = "checkpoint is only in the lossy .chk form: the corpus lacks an object a transaction read";

const E2e = struct { handler: @import("h2/root.zig").Handler, masks: []const u8, txmasks: []const u8, objmasks: []const u8, ineligible: *const std.AutoHashMapUnmanaged(u64, void), missing_tx: *const std.AutoHashMapUnmanaged(u64, void), archive: *const std.AutoHashMapUnmanaged(u64, void) };

fn e2eOne(st: *const E2e, ctx: *harness.Ctx, name: []const u8) !void {
    const seq = harness.leadingNumber(name) orelse return;
    try e2eTxObj(st, ctx, seq, name);
    const rec = try readRec(ctx, rec_dir, name);
    const arena = ctx.scratch();
    var pos: usize = 0;
    while (pos < rec.len) {
        const kind = rec[pos];
        const mask_id = rec[pos + 1];
        const len = std.mem.readInt(u32, rec[pos + 2 ..][0..4], .little);
        const expected = rec[pos + 6 ..][0..len];
        pos += 6 + len;
        if (kind != 1) continue;
        var ib: [64]u8 = undefined;
        const item = try std.fmt.bufPrint(&ib, "e2e/ckpt/{d}/m{d}", .{ seq, mask_id });
        if (!ctx.selected(item)) continue;
        var lines = std.mem.splitScalar(u8, st.masks, '\n');
        var mask_str: []const u8 = "";
        var i: usize = 0;
        while (lines.next()) |l| : (i += 1) if (i == mask_id) {
            mask_str = l;
            break;
        };
        var tree = try mask.Tree.parse(arena, mask_str);
        if (st.ineligible.contains(seq)) {
            const wants = tree.mask().subtree("objects") != null or (if (tree.mask().subtree("transactions")) |t| service.needsObjectSet(t) else false);
            if (wants) {
                skipCount(ctx, item, skip_lossy);
                continue;
            }
        }
        // GetCheckpointRequest { sequence_number = 1, read_mask = 3 { paths = 1 } }
        var req = try arena.alloc(u8, mask_str.len * 2 + 64);
        var w = proto.Writer.init(req);
        try w.uint(1, seq);
        const mm = try w.begin(3, mask_str.len + 8);
        var it = std.mem.splitScalar(u8, mask_str, ',');
        while (it.next()) |p| try w.string(1, p);
        try w.end(mm);
        req = req[0..w.len];
        const reply = try loopback.unary(arena, st.handler, "/sui.rpc.v2.LedgerService/GetCheckpoint", req);
        var c = ctx.check(item);
        if (reply.status == 12) {
            // field the renderer does not port yet: the service reported UNIMPLEMENTED
            _ = unsupported.fetchAdd(1, .monotonic);
            ctx.skip(item, "UNIMPLEMENTED: a field the renderer does not port yet");
            continue;
        } else if (reply.status != 0) {
            c.failf("grpc-status {d}: {s}", .{ reply.status, reply.grpc_message });
        } else {
            c.bytes("GetCheckpointResponse over HTTP/2", expected, reply.message);
            // The same call again comes from the pre-encoded response cache (cpcache.zig).
            const again = try loopback.unary(arena, st.handler, "/sui.rpc.v2.LedgerService/GetCheckpoint", req);
            if (again.status != 0) c.failf("cached call: grpc-status {d}: {s}", .{ again.status, again.grpc_message }) else c.bytes("GetCheckpointResponse from the response cache", expected, again.message);
        }
        _ = c.finish();
    }
}

// ---- verifysig ----

const verifysig = @import("verifysig.zig");
const verifysig_dir = "vectors/verifysig";
const h2 = @import("h2/root.zig");

/// Recorded chain objects (0x7, its AuthenticatorStateInner field, AddressAliases objects) by id.
const VsState = struct {
    map: std.AutoHashMapUnmanaged([32]u8, []const u8) = .empty,
    fn live(ctx: *anyopaque, id: *const [32]u8) ?[]const u8 {
        const st: *VsState = @ptrCast(@alignCast(ctx));
        return st.map.get(id.*);
    }
};

const VsHandler = struct {
    env: *const verifysig.Env,
    fn call(ctx: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const self: *VsHandler = @ptrCast(@alignCast(ctx));
        var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena_state.deinit();
        return verifysig.call(arena_state.allocator(), self.env, req, rs);
    }
};

/// `vectors/verifysig/cases.txt` (`tools/truth/verifysig/record.mjs` against sui-node 1.83.1):
/// name, request, grpc-status, response message, grpc-status-details-bin, grpc-message (hex).
/// Each request goes over loopback HTTP/2 to the handler with the recorded chain objects.
fn runVerifysig(ctx: *harness.Ctx) !void {
    const gpa = ctx.gpa;
    const txt = try ctx.corpus.readFileAlloc(ctx.io, verifysig_dir ++ "/cases.txt", gpa, .limited(1 << 28));
    defer gpa.free(txt);
    const st_txt = try ctx.corpus.readFileAlloc(ctx.io, verifysig_dir ++ "/state.txt", gpa, .limited(1 << 26));
    defer gpa.free(st_txt);
    var st: VsState = .{};
    defer {
        var it = st.map.valueIterator();
        while (it.next()) |v| gpa.free(v.*);
        st.map.deinit(gpa);
    }
    var sl = std.mem.splitScalar(u8, st_txt, '\n');
    while (sl.next()) |line| {
        if (line.len == 0) continue;
        var cols = std.mem.splitScalar(u8, line, '\t');
        const id_hex = cols.next() orelse return error.BadVector;
        const obj_hex = cols.next() orelse return error.BadVector;
        var id: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&id, id_hex);
        const obj = try gpa.alloc(u8, obj_hex.len / 2);
        _ = try std.fmt.hexToBytes(obj, obj_hex);
        try st.map.put(gpa, id, obj);
    }
    const env: verifysig.Env = .{ .chain_name = "mainnet", .ctx = &st, .liveObject = VsState.live };
    var vh: VsHandler = .{ .env = &env };
    const handler: h2.Handler = .{ .ctx = &vh, .call = VsHandler.call };
    // `cases-review.txt` (`tools/truth/verifysig/review.mjs`) is optional: the review round's cases.
    const review: []u8 = ctx.corpus.readFileAlloc(ctx.io, verifysig_dir ++ "/cases-review.txt", gpa, .limited(1 << 28)) catch |e| switch (e) {
        error.FileNotFound => &.{},
        else => return e,
    };
    defer gpa.free(review);
    for ([_][]const u8{ txt, review }) |file| {
    var lines = std.mem.splitScalar(u8, file, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (ctx.done()) break;
        ctx.nextItem();
        const arena = ctx.scratch();
        var cols = std.mem.splitScalar(u8, line, '\t');
        const name = cols.next() orelse return error.BadVector;
        const req_hex = cols.next() orelse return error.BadVector;
        const code_text = cols.next() orelse return error.BadVector;
        const body_hex = cols.next() orelse return error.BadVector;
        const det_hex = cols.next() orelse return error.BadVector;
        const msg_hex = cols.next() orelse return error.BadVector;
        const item = try std.fmt.allocPrint(arena, "verifysig/{s}", .{name});
        if (!ctx.selected(item)) continue;
        const req = try arena.alloc(u8, req_hex.len / 2);
        _ = try std.fmt.hexToBytes(req, req_hex);
        const body = try arena.alloc(u8, body_hex.len / 2);
        _ = try std.fmt.hexToBytes(body, body_hex);
        const det = try arena.alloc(u8, det_hex.len / 2);
        _ = try std.fmt.hexToBytes(det, det_hex);
        const msg = try arena.alloc(u8, msg_hex.len / 2);
        _ = try std.fmt.hexToBytes(msg, msg_hex);
        const code = try std.fmt.parseInt(u8, code_text, 10);
        const reply = try loopback.unary(arena, handler, verifysig.path, req);
        var c = ctx.check(item);
        if (reply.status != code) {
            c.failf("grpc-status {d} ({s}), expected {d} ({s})", .{ reply.status, reply.grpc_message, code, msg });
        } else {
            c.bytes("grpc-message", msg, reply.grpc_message);
            c.bytes("grpc-status-details-bin", det, reply.details);
            if (code == 0) c.bytes("VerifySignatureResponse", body, reply.message);
        }
        _ = c.finish();
    }
    }
}
