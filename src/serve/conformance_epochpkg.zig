//! Suite `epoch-pkg` (DROP-IN G6, G8): sui-node 1.83.1's recorded answers to GetEpoch,
//! GetPackage (every version selector), ListPackageVersions, GetDatatype, GetFunction, LookupName
//! and ReverseLookupName, replayed against deepwave over loopback HTTP/2 and compared byte for byte
//! (status, grpc-message, grpc-status-details-bin, response message).
//!
//! Two captures (`tools/truth/epoch-pkg/`), each with its own store and index:
//! - `vectors/epoch-pkg/capture/` (capture.mjs): every method;
//! - `vectors/epoch-pkg/atcp/` (capture-atcp.mjs): the package-version index: every lineage of the
//!   seed packages with each version's publishing checkpoint (`publish.jsonl`), and GetPackage
//!   `at_checkpoint` around each publish inside sui-node's window and at the window's edges, each
//!   bracketed by GetServiceInfo (sui-node's lowest available checkpoint and tip at that moment).
//!
//! deepwave's index is built only through the production feeds: `onCheckpoint` over the end-of-epoch
//! checkpoints (`chk/<seq>.chk`) and over every publish checkpoint inside the window
//! (`vectors/epoch-pkg/chk/<seq>.chk`, kept out of the plan-checked `chk/`), and
//! `onRestoredObject` (restore floors) for package versions published before sui-node's window. Rows
//! sui-node lists whose object no capture has (superseded system package versions, whose old
//! objects are not served) are the only ones seeded from its answers; the suite reports that count
//! and fails above `max_seeded`.
const std = @import("std");
const harness = @import("harness");
const store = @import("store");
const types = @import("types");
const service = @import("service.zig");
const loopback = @import("loopback.zig");
const rpcindex = @import("rpcindex.zig");
const proto = @import("proto.zig");
const sysstate = @import("sysstate.zig");
const bcs = @import("bcs");

/// Corpus-relative capture directory; `ZUI_EPOCHPKG_CAPTURE` overrides it (another capture).
const default_dir = "vectors/epoch-pkg/capture";

fn captureDir() []const u8 {
    const v = std.c.getenv("ZUI_EPOCHPKG_CAPTURE") orelse return default_dir;
    return std.mem.span(v);
}

const WindowInfo = struct { lowest: u64, tip: u64 };
const CaseInfo = struct { before: WindowInfo, after: WindowInfo };
const Case = struct { path: []const u8, tag: []const u8 = "", req: []const u8, status: i32, message: []const u8 = "", details: []const u8 = "", body: []const u8 = "", info: ?CaseInfo = null };
const Publish = struct { storage: []const u8, version: u64, original: []const u8, checkpoint: ?u64 = null };
const AtcpMeta = struct { start: Info, end: ?Info = null, publish_in_window: []const u64 = &.{} };

/// The captures are sui-node 1.83.1's answers (max protocol 141): deepwave renders GetEpoch protocol
/// configs as that release did, without the fields 1.84 added (`protocol.release_fields`).
const capture_release_max = 141;

/// Rows seeded from sui-node's own answers (objects no capture has) above this fail the suite.
const max_seeded = 64;
const Obj = struct { id: []const u8, version: []const u8, bcs: []const u8 };
const Info = struct { epoch: u64 = 0, tip: u64 = 0, lowest: u64 = 0, timestamp_ms: u64 = 0 };
const EpochRow = struct { epoch: u64, first: ?u64 = null, last: ?u64 = null };
const Meta = struct { start: Info, eoe: []const u64 = &.{}, names_summary: []const u8 = "", names_at: ?Info = null, epochs: []const EpochRow = &.{} };

fn unhex(arena: std.mem.Allocator, h: []const u8) ![]u8 {
    const s = if (std.mem.startsWith(u8, h, "0x")) h[2..] else h;
    const out = try arena.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

fn id32(h: []const u8) ![32]u8 {
    var s = if (std.mem.startsWith(u8, h, "0x")) h[2..] else h;
    var pad: [64]u8 = @splat('0');
    if (s.len > 64) return error.BadId;
    @memcpy(pad[64 - s.len ..], s);
    s = &pad;
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, s);
    return out;
}

const Obj3 = struct { id: [32]u8, version: u64, bytes: []const u8 };
const PubKey = struct { id: [32]u8, version: u64 };
const PubMap = std.AutoHashMapUnmanaged(PubKey, u64);

fn readOpt(ctx: *harness.Ctx, a: std.mem.Allocator, path: []const u8) ?[]u8 {
    return ctx.corpus.readFileAlloc(ctx.io, path, a, .limited(1 << 31)) catch null;
}

/// Objects of a capture, ascending versions (the newest of an id is its live version).
fn loadObjects(a: std.mem.Allocator, text: []const u8) ![]Obj3 {
    var objs: std.ArrayList(Obj3) = .empty;
    var it = harness.lines(text);
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const o = try std.json.parseFromSliceLeaky(Obj, a, line, .{ .ignore_unknown_fields = true });
        try objs.append(a, .{ .id = try id32(o.id), .version = try std.fmt.parseInt(u64, o.version, 10), .bytes = try unhex(a, o.bcs) });
    }
    std.mem.sort(Obj3, objs.items, {}, struct {
        fn lt(_: void, x: Obj3, y: Obj3) bool {
            return x.version < y.version;
        }
    }.lt);
    return objs.items;
}

/// Publishing checkpoint of each package version (capture-atcp's publish.jsonl): chain facts.
fn loadPublish(a: std.mem.Allocator, text: []const u8) !PubMap {
    var m: PubMap = .empty;
    var it = harness.lines(text);
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const p = try std.json.parseFromSliceLeaky(Publish, a, line, .{ .ignore_unknown_fields = true });
        const cp = p.checkpoint orelse continue;
        try m.put(a, .{ .id = try id32(p.storage), .version = p.version }, cp);
    }
    return m;
}

const Built = struct { fed: usize = 0, missing: usize = 0, floors: usize = 0, via_checkpoint: usize = 0 };

/// deepwave's index the way production builds it: restore floors for package versions published before
/// sui-node's window (`window_lo`), then `onCheckpoint` over every end-of-epoch and in-window
/// publish checkpoint, ascending. `members` gets each next committee an end-of-epoch checkpoint
/// carries (what the node persists per epoch, `trust.save`).
fn buildIndex(ctx: *harness.Ctx, a: std.mem.Allocator, index: *rpcindex.Index, objs: []const Obj3, pubs: *const PubMap, window_lo: u64, eoe: []const u64, members: ?*std.AutoHashMapUnmanaged(u64, []const sysstate.Member)) !Built {
    const gpa = ctx.gpa;
    var r: Built = .{};
    var seqs: std.ArrayList(u64) = .empty;
    try seqs.appendSlice(a, eoe);
    var pit = pubs.valueIterator();
    while (pit.next()) |cp| if (cp.* >= window_lo) try seqs.append(a, cp.*);
    std.mem.sort(u64, seqs.items, {}, std.sort.asc(u64));
    var blobs: std.AutoHashMapUnmanaged(u64, []const u8) = .empty;
    var prev: ?u64 = null;
    for (seqs.items) |seq| {
        if (prev != null and prev.? == seq) continue;
        prev = seq;
        // End-of-epoch checkpoints are corpus plan blobs (`chk/`); the in-window publish checkpoints
        // are not in plan/*.txt, so they live beside the captures (`vectors/epoch-pkg/chk/`) where
        // the corpus, hash and store-replay suites (which require every chk/ blob in the plan) do
        // not see them.
        const p = try std.fmt.allocPrint(a, "chk/{d}.chk", .{seq});
        const p2 = try std.fmt.allocPrint(a, "vectors/epoch-pkg/chk/{d}.chk", .{seq});
        const blob = ctx.corpus.readFileAlloc(ctx.io, p, a, .limited(1 << 30)) catch
            ctx.corpus.readFileAlloc(ctx.io, p2, a, .limited(1 << 30)) catch {
                ctx.fail(p2, "missing checkpoint blob (tools/corpus-fetch.sh epoch-pkg {d}, then move it from chk/ to vectors/epoch-pkg/chk/)", .{seq});
                r.missing += 1;
                continue;
            };
        try blobs.put(a, seq, blob);
    }
    for (objs) |o| {
        if (o.bytes.len == 0 or o.bytes[0] != 1) continue;
        if (pubs.get(.{ .id = o.id, .version = o.version })) |cp| if (cp >= window_lo and blobs.contains(cp)) {
            r.via_checkpoint += 1;
            continue; // indexed from its publish checkpoint below
        };
        try index.onRestoredObject(&o.id, o.version, o.bytes);
        r.floors += 1;
    }
    prev = null;
    for (seqs.items) |seq| {
        if (prev != null and prev.? == seq) continue;
        prev = seq;
        const blob = blobs.get(seq) orelse continue;
        try index.onCheckpoint(seq, blob);
        try index.commit(seq);
        r.fed += 1;
        if (members) |mm| {
            var sa = std.heap.ArenaAllocator.init(gpa);
            defer sa.deinit();
            const cd = try bcs.decode(types.CheckpointData, sa.allocator(), blob[1..]);
            const s = cd.checkpoint_summary.data;
            if (s.end_of_epoch_data) |eod| {
                const out = try a.alloc(sysstate.Member, eod.nextEpochCommittee.len);
                for (out, eod.nextEpochCommittee) |*m, c| m.* = .{ .key = try a.dupe(u8, &c[0].@"0"), .weight = c[1] };
                std.mem.sort(sysstate.Member, out, {}, struct {
                    fn lt(_: void, x: sysstate.Member, y: sysstate.Member) bool {
                        return std.mem.lessThan(u8, x.key, y.key);
                    }
                }.lt);
                try mm.put(a, s.epoch + 1, out);
            }
        }
    }
    return r;
}

/// Rows sui-node lists (`lpv:default` answers) whose object no capture has: the only rows taken
/// from its answers, and only for versions deepwave's index has no row for. Returns how many it added.
fn seedMissing(a: std.mem.Allocator, index: *rpcindex.Index, snap: *store.Snapshot, cases_text: []const u8, objs: []const Obj3) !usize {
    var have: std.AutoHashMapUnmanaged(PubKey, void) = .empty;
    for (objs) |o| try have.put(a, .{ .id = o.id, .version = o.version }, {});
    var added: usize = 0;
    var cit = harness.lines(cases_text);
    while (cit.next()) |line| {
        if (std.mem.indexOf(u8, line, "\"lpv:default\"") == null) continue;
        const c = try std.json.parseFromSliceLeaky(Case, a, line, .{ .ignore_unknown_fields = true });
        if (c.status != 0) continue;
        var rr = proto.Reader.init(try unhex(a, c.req));
        var pid_text: []const u8 = "";
        while (try rr.next()) |f| if (f.number == 1) {
            pid_text = try proto.Reader.stringOf(f);
        };
        const pid = id32(pid_text) catch continue;
        const live = snap.liveObject(&pid) orelse continue;
        const original = rpcindex.originalId(live.bytes) orelse continue;
        var br = proto.Reader.init(try unhex(a, c.body));
        while (try br.next()) |f| if (f.number == 1) {
            var vr = proto.Reader.init(try proto.Reader.bytesOf(f));
            var storage: [32]u8 = undefined;
            var version: u64 = 0;
            while (try vr.next()) |g| switch (g.number) {
                1 => storage = id32(try proto.Reader.stringOf(g)) catch continue,
                2 => version = try proto.Reader.varintOf(g),
                else => {},
            };
            if (have.contains(.{ .id = storage, .version = version })) continue;
            var present = false;
            for (index.lineage(&original)) |e| present = present or e.version == version;
            if (present) continue;
            try index.putPackage(&original, version, &storage, null);
            added += 1;
        };
    }
    return added;
}

const Tally = struct {
    ok: usize = 0,
    total: usize = 0,
    fn add(t: *Tally, pass: bool) void {
        t.total += 1;
        if (pass) t.ok += 1;
    }
};

/// One recorded case against deepwave; true when every part matched.
fn replay(ctx: *harness.Ctx, handler: anytype, c: Case, item: []const u8) !bool {
    const s = ctx.scratch();
    const req = try unhex(s, c.req);
    const reply = try loopback.unary(s, handler, c.path, req);
    var ck = ctx.check(item);
    ck.eql("status", @as(i32, c.status), @as(i32, reply.status));
    ck.text("grpc-message", c.message, reply.grpc_message);
    ck.bytes("details", try decodeB64(s, c.details), reply.details);
    ck.bytes("message", try unhex(s, c.body), reply.message);
    return ck.finish();
}

fn openStore(ctx: *harness.Ctx, tag: []const u8) !struct { h: @typeInfo(@TypeOf(store.openDir)).@"fn".return_type.?, dir: []u8 } {
    const gpa = ctx.gpa;
    const sdir = try std.fmt.allocPrint(gpa, "{s}/sessions/serve/{d}-{s}", .{ ctx.corpus_path, std.c.getpid(), tag });
    std.Io.Dir.cwd().deleteTree(ctx.io, sdir) catch {};
    var cfg: store.Config = .{ .dir = sdir, .max_live_objects = 1 << 16, .max_object_versions = 1 << 16, .max_transactions = 1 << 10, .max_checkpoints = 1 << 6, .max_batch_bytes = 1 << 30, .max_batch_objects = 1 << 16, .max_segments = 16, .segment_reserve = 1 << 28, .seed = 7 };
    return .{ .h = store.openDir(gpa, ctx.io, &cfg, .{ .sync = .none }), .dir = sdir };
}

pub fn run(ctx: *harness.Ctx) !void {
    var ar = std.heap.ArenaAllocator.init(ctx.gpa);
    defer ar.deinit();
    const a = ar.allocator();
    const atcp_dir = blk: {
        const v = std.c.getenv("ZUI_EPOCHPKG_ATCP") orelse break :blk "vectors/epoch-pkg/atcp";
        break :blk std.mem.span(v);
    };
    var pubs: PubMap = .empty;
    if (readOpt(ctx, a, try std.fmt.allocPrint(a, "{s}/publish.jsonl", .{atcp_dir}))) |t| pubs = try loadPublish(a, t);
    try runMain(ctx, a, &pubs);
    try runAtcp(ctx, a, atcp_dir, &pubs);
}

fn runMain(ctx: *harness.Ctx, a: std.mem.Allocator, pubs: *const PubMap) !void {
    const gpa = ctx.gpa;
    const meta_text = readOpt(ctx, a, try std.fmt.allocPrint(a, "{s}/meta.json", .{captureDir()})) orelse {
        ctx.skip("capture", "no capture (run tools/truth/epoch-pkg/capture.mjs)");
        return;
    };
    const meta = try std.json.parseFromSliceLeaky(Meta, a, meta_text, .{ .ignore_unknown_fields = true });
    const objs_text = try ctx.corpus.readFileAlloc(ctx.io, try std.fmt.allocPrint(a, "{s}/objects.jsonl", .{captureDir()}), a, .limited(1 << 31));
    const cases_text = try ctx.corpus.readFileAlloc(ctx.io, try std.fmt.allocPrint(a, "{s}/cases.jsonl", .{captureDir()}), a, .limited(1 << 31));

    // ---- store: every input object at the names' checkpoint
    const st = try openStore(ctx, "epochpkg");
    defer gpa.free(st.dir);
    defer std.Io.Dir.cwd().deleteTree(ctx.io, st.dir) catch {};
    var h = try st.h;
    defer {
        h.store.deinit();
        h.io.deinit();
    }
    var index = rpcindex.Index.initMemory(gpa);
    defer index.deinit();
    const names_at = meta.names_at orelse meta.start;
    const objs = try loadObjects(a, objs_text);
    {
        const b = try h.store.begin(names_at.tip, names_at.epoch);
        for (objs) |o| try b.putObject(&o.id, o.version, &types.digest.objectDigest(o.bytes), o.bytes);
        try b.checkpoint(try unhex(a, meta.names_summary), "contents");
        try h.store.commit(b);
    }
    var members: std.AutoHashMapUnmanaged(u64, []const sysstate.Member) = .empty;
    const built = try buildIndex(ctx, a, &index, objs, pubs, meta.start.lowest, meta.eoe, &members);
    ctx.detail("epoch-pkg: {d} checkpoints fed through onCheckpoint ({d} end-of-epoch), {d} package versions from their publish checkpoint, {d} restore floors\n", .{ built.fed, meta.eoe.len, built.via_checkpoint, built.floors });
    try checkBackfill(ctx, a, &index, meta.eoe);
    // sui-node's rpc index starts at its own restore: an oldest epoch without a first checkpoint was
    // restored mid-epoch (start record from the restored system state, no record of the epoch
    // before). Model the same bootstrap: drop the earlier epoch and the start checkpoint.
    for (meta.epochs) |row| {
        if (row.first != null or row.epoch == 0) continue;
        if (index.epoch(row.epoch)) |r| if (r.start) |s0| {
            var s2 = s0;
            s2.start_checkpoint = null;
            try index.putEpoch(row.epoch, s2, null);
            try index.dropEpoch(row.epoch - 1);
            ctx.detail("epoch-pkg: epoch {d} modelled as restored mid-epoch (as sui-node's index was)\n", .{row.epoch});
        };
    }
    index.publish(meta.start.tip);
    {
        var snap = h.store.snapshot();
        defer snap.release();
        const seeded = try seedMissing(a, &index, &snap, cases_text, objs);
        ctx.detail("epoch-pkg: {d} package-version rows taken from sui-node's answers (objects no capture has; limit {d})\n", .{ seeded, max_seeded });
        var ck = ctx.check("seeded rows");
        if (seeded > max_seeded) ck.failf("{d} rows seeded from sui-node's answers (limit {d})", .{ seeded, max_seeded });
        _ = ck.finish();
        try checkSeedFromStore(ctx, &snap);
    }

    var svc: service.Service = .{ .gpa = gpa, .store = h.store, .chain_id = @splat(0), .rpc = &index, .chain = .mainnet, .lowest_checkpoint = meta.start.lowest, .protocol_release_max = capture_release_max };
    defer svc.deinit();
    const handler = svc.handler();

    // committee from the persisted per-epoch committee (no state in the record): a second index
    // whose past records carry no state, with the committees the end-of-epoch checkpoints hand the
    // node (trust.save) as its committee source
    var bare = rpcindex.Index.initMemory(gpa);
    defer bare.deinit();
    var msrc: MembersSource = .{ .m = &members };
    bare.committees = .{ .ctx = &msrc, .get = MembersSource.get };
    {
        var it = index.epochs.iterator();
        while (it.next()) |kv| {
            var s0 = kv.value_ptr.*.start;
            if (s0) |*x| x.state = null;
            try bare.putEpoch(kv.key_ptr.*, s0, kv.value_ptr.*.end);
        }
    }
    var bare_svc: service.Service = .{ .gpa = gpa, .store = h.store, .chain_id = @splat(0), .rpc = &bare, .chain = .mainnet, .lowest_checkpoint = meta.start.lowest, .protocol_release_max = capture_release_max };
    defer bare_svc.deinit();
    const bare_handler = bare_svc.handler();

    var tallies: std.StringArrayHashMapUnmanaged(Tally) = .empty;
    var it = harness.lines(cases_text);
    var n: usize = 0;
    while (it.next()) |line| : (n += 1) {
        if (line.len == 0) continue;
        if (ctx.done()) break;
        ctx.nextItem();
        const s = ctx.scratch();
        const c = try std.json.parseFromSliceLeaky(Case, s, line, .{ .ignore_unknown_fields = true });
        const method = c.path[std.mem.lastIndexOfScalar(u8, c.path, '/').? + 1 ..];
        const item = try std.fmt.allocPrint(s, "{s} #{d} {s}", .{ method, n, c.tag });
        if (!ctx.selected(item)) continue;
        if (c.status < 0) {
            ctx.skip(item, "sui-node did not answer during the capture");
            continue;
        }
        // sui-node's lowest checkpoint moves during a capture. This capture recorded no window
        // per case: the reported value is taken only inside [lowest at the capture's start, tip
        // at its end] (lowest only grows); the atcp capture brackets each such case tightly.
        svc.lowest_checkpoint = bracketed(c.message, "lowest available checkpoint is ", meta.start.lowest, names_at.tip);
        const pass = try replay(ctx, handler, c, item);
        const gop = try tallies.getOrPut(a, try std.fmt.allocPrint(a, "{s}:{s}", .{ c.tag, if (c.status == 0) "OK" else "error" }));
        if (!gop.found_existing) gop.value_ptr.* = .{};
        gop.value_ptr.add(pass);
        // the same past-epoch committee answer through the committee source
        if (std.mem.startsWith(u8, c.tag, "epoch:") and std.mem.endsWith(u8, c.tag, ":tide") and !std.mem.startsWith(u8, c.tag, "epoch:cur")) {
            const item2 = try std.fmt.allocPrint(s, "{s} #{d} {s} (committee source)", .{ method, n, c.tag });
            _ = try replay(ctx, bare_handler, c, item2);
        }
    }
    try printTallies(ctx, a, "epoch-pkg matched/total", &tallies);
}

/// Node start's past-epoch fill (`Node.backfillEpochRecords`): an index fed only the end-of-epoch
/// checkpoints through `onEpochCheckpoint` (the oldest without its end, as the fill does) holds
/// the same epoch records as the follow path's `onCheckpoint`, state bytes included, and reports
/// nothing left to fetch afterwards.
fn checkBackfill(ctx: *harness.Ctx, a: std.mem.Allocator, index: *rpcindex.Index, eoe: []const u64) !void {
    if (eoe.len < 2) return;
    var back = rpcindex.Index.initMemory(ctx.gpa);
    defer back.deinit();
    const seqs = try a.dupe(u64, eoe);
    std.mem.sort(u64, seqs, {}, std.sort.asc(u64));
    var first_epoch: ?u64 = null;
    var fed: usize = 0;
    for (seqs, 0..) |seq, i| {
        // corpus plan blobs, or beside the captures (as buildIndex reads them)
        const blob = ctx.corpus.readFileAlloc(ctx.io, try std.fmt.allocPrint(a, "chk/{d}.chk", .{seq}), a, .limited(1 << 30)) catch
            ctx.corpus.readFileAlloc(ctx.io, try std.fmt.allocPrint(a, "vectors/epoch-pkg/chk/{d}.chk", .{seq}), a, .limited(1 << 30)) catch continue;
        const ep = (try bcs.decode(types.CheckpointData, a, blob[1..])).checkpoint_summary.data.epoch;
        if (i == 0) first_epoch = ep;
        var ck0 = ctx.check(try std.fmt.allocPrint(a, "backfill needs eoe {d}", .{seq}));
        if (!back.epochNeeds(ep, i > 0)) ck0.failf("epochNeeds({d}) false before the fill", .{ep});
        _ = ck0.finish();
        try back.onEpochCheckpoint(seq, blob, i > 0);
        var ck1 = ctx.check(try std.fmt.allocPrint(a, "backfill done eoe {d}", .{seq}));
        if (back.epochNeeds(ep, i > 0)) ck1.failf("epochNeeds({d}) still true after the fill", .{ep});
        _ = ck1.finish();
        fed += 1;
    }
    var compared: usize = 0;
    var it = back.epochs.iterator();
    while (it.next()) |kv| {
        const e = kv.key_ptr.*;
        const b = kv.value_ptr.*;
        var ck = ctx.check(try std.fmt.allocPrint(a, "backfill epoch {d}", .{e}));
        defer _ = ck.finish();
        if (first_epoch != null and e == first_epoch.?) {
            if (b.end != null) ck.failf("the oldest end-of-epoch checkpoint wrote an end record", .{});
            continue;
        }
        const f = index.epoch(e) orelse {
            ck.failf("epoch {d}: the follow path has no record", .{e});
            continue;
        };
        compared += 1;
        if (!std.meta.eql(f.end, b.end)) ck.failf("end differs: follow {?any} fill {?any}", .{ f.end, b.end });
        if ((f.start == null) != (b.start == null)) {
            ck.failf("start presence differs", .{});
            continue;
        }
        if (f.start) |fs| {
            const bs = b.start.?;
            if (fs.protocol_version != bs.protocol_version or fs.reference_gas_price != bs.reference_gas_price or fs.start_timestamp_ms != bs.start_timestamp_ms or !std.meta.eql(fs.start_checkpoint, bs.start_checkpoint)) ck.failf("start fields differ", .{});
            if ((fs.state == null) != (bs.state == null)) ck.failf("state presence differs", .{}) else if (fs.state) |fst| {
                if (fst.version != bs.state.?.version or !std.mem.eql(u8, fst.inner, bs.state.?.inner)) ck.failf("state bytes differ", .{});
            }
        }
    }
    // in-place system package rows of the fill (prior versions as floors, upgrades at their
    // checkpoint) are rows the follow path holds too: it saw the same checkpoints
    var pkg_rows: usize = 0;
    var lt = back.lineages.iterator();
    while (lt.next()) |kv| {
        const orig = kv.key_ptr.*;
        var ck = ctx.check(try std.fmt.allocPrint(a, "backfill package {x}", .{&orig}));
        defer _ = ck.finish();
        const follow = index.lineage(&orig);
        for (kv.value_ptr.*.versions) |v| {
            pkg_rows += 1;
            const f = for (follow) |fv| {
                if (fv.version == v.version) break fv;
            } else {
                ck.failf("version {d}: the follow path has no row", .{v.version});
                continue;
            };
            if (!std.mem.eql(u8, &f.storage_id, &v.storage_id)) ck.failf("version {d}: storage id differs", .{v.version});
            if (v.checkpoint != null and !std.meta.eql(f.checkpoint, v.checkpoint)) ck.failf("version {d}: checkpoint follow {?d} fill {?d}", .{ v.version, f.checkpoint, v.checkpoint });
        }
    }
    ctx.detail("epoch-pkg backfill: {d} end-of-epoch checkpoints through onEpochCheckpoint, {d} epoch records equal to the follow path's, {d} system package rows held by the follow path\n", .{ fed, compared, pkg_rows });
}

/// One line per pass (details are capped per suite).
fn printTallies(ctx: *harness.Ctx, a: std.mem.Allocator, title: []const u8, t: *const std.StringArrayHashMapUnmanaged(Tally)) !void {
    var buf: std.ArrayList(u8) = .empty;
    for (t.keys(), t.values()) |k, v| try buf.print(a, " {s}={d}/{d}", .{ k, v.ok, v.total });
    ctx.detail("{s}:{s}\n", .{ title, buf.items });
}

fn bracketed(message: []const u8, comptime prefix: []const u8, lo: u64, hi: u64) u64 {
    const at = std.mem.indexOf(u8, message, prefix) orelse return lo;
    const v = std.fmt.parseInt(u64, message[at + prefix.len ..], 10) catch return lo;
    return if (v >= lo and v <= hi) v else lo;
}

const MembersSource = struct {
    m: *std.AutoHashMapUnmanaged(u64, []const sysstate.Member),
    fn get(ctx: *anyopaque, _: std.mem.Allocator, e: u64) ?[]const sysstate.Member {
        const self: *MembersSource = @ptrCast(@alignCast(ctx));
        return self.m.get(e);
    }
};

/// A node started mid-epoch keeps the live system state in the epoch's start record (sui-node
/// `seed_current_epoch_start`), so GetEpoch for it still has `system_state` once it is past.
fn checkSeedFromStore(ctx: *harness.Ctx, snap: *store.Snapshot) !void {
    var x = rpcindex.Index.initMemory(ctx.gpa);
    defer x.deinit();
    try x.seedFromStore(snap);
    const live = rpcindex.liveState(snap) orelse return;
    const e = (try sysstate.summary(live)).epoch;
    var ck = ctx.check("seedFromStore keeps the start state");
    const r = x.epoch(e);
    ck.eql("record", true, r != null);
    if (r) |rec| {
        ck.eql("state", true, rec.start != null and rec.start.?.state != null);
        if (rec.start) |s0| if (s0.state) |stt| ck.bytes("state bytes", live.inner, stt.inner);
    }
    _ = ck.finish();
}

fn runAtcp(ctx: *harness.Ctx, a: std.mem.Allocator, dir: []const u8, pubs: *const PubMap) !void {
    const gpa = ctx.gpa;
    const meta_text = readOpt(ctx, a, try std.fmt.allocPrint(a, "{s}/meta.json", .{dir})) orelse {
        ctx.skip("atcp", "no atcp capture (run tools/truth/epoch-pkg/capture-atcp.mjs)");
        return;
    };
    const meta = try std.json.parseFromSliceLeaky(AtcpMeta, a, meta_text, .{ .ignore_unknown_fields = true });
    const objs = try loadObjects(a, try ctx.corpus.readFileAlloc(ctx.io, try std.fmt.allocPrint(a, "{s}/objects.jsonl", .{dir}), a, .limited(1 << 31)));
    const cases_text = try ctx.corpus.readFileAlloc(ctx.io, try std.fmt.allocPrint(a, "{s}/cases.jsonl", .{dir}), a, .limited(1 << 31));
    const st = try openStore(ctx, "epochpkg-atcp");
    defer gpa.free(st.dir);
    defer std.Io.Dir.cwd().deleteTree(ctx.io, st.dir) catch {};
    var h = try st.h;
    defer {
        h.store.deinit();
        h.io.deinit();
    }
    {
        const b = try h.store.begin(meta.start.tip, meta.start.epoch);
        for (objs) |o| try b.putObject(&o.id, o.version, &types.digest.objectDigest(o.bytes), o.bytes);
        try b.checkpoint("summary", "contents");
        try h.store.commit(b);
    }
    var index = rpcindex.Index.initMemory(gpa);
    defer index.deinit();
    var svc: service.Service = .{ .gpa = gpa, .store = h.store, .chain_id = @splat(0), .rpc = &index, .chain = .mainnet, .lowest_checkpoint = meta.start.lowest, .protocol_release_max = capture_release_max };
    defer svc.deinit();
    const handler = svc.handler();

    // before anything is fed: no watermark; sui-node get_package.rs:107 answers UNAVAILABLE
    // "rpc index is empty" (its index always has one, so the capture cannot show it)
    {
        var it0 = harness.lines(cases_text);
        while (it0.next()) |line| {
            if (std.mem.indexOf(u8, line, "\"pkg:at-tip\"") == null) continue;
            const c = try std.json.parseFromSliceLeaky(Case, a, line, .{ .ignore_unknown_fields = true });
            const s = ctx.scratch();
            const reply = try loopback.unary(s, handler, c.path, try unhex(s, c.req));
            var ck = ctx.check("GetPackage at_checkpoint, empty index");
            ck.eql("status", @as(i32, 14), @as(i32, reply.status)); // UNAVAILABLE
            ck.text("grpc-message", "rpc index is empty", reply.grpc_message);
            _ = ck.finish();
            break;
        }
    }
    const built = try buildIndex(ctx, a, &index, objs, pubs, meta.start.lowest, &.{}, null);
    {
        var snap = h.store.snapshot();
        defer snap.release();
        const seeded = try seedMissing(a, &index, &snap, cases_text, objs);
        ctx.detail("epoch-pkg atcp: {d} publish checkpoints fed through onCheckpoint ({d} in the window), {d} versions from them, {d} restore floors, {d} rows taken from sui-node's answers\n", .{ built.fed, meta.publish_in_window.len, built.via_checkpoint, built.floors, seeded });
        var ck = ctx.check("atcp seeded rows");
        if (seeded > max_seeded) ck.failf("{d} rows seeded from sui-node's answers (limit {d})", .{ seeded, max_seeded });
        _ = ck.finish();
    }
    var tallies: std.StringArrayHashMapUnmanaged(Tally) = .empty;
    var it = harness.lines(cases_text);
    var n: usize = 0;
    while (it.next()) |line| : (n += 1) {
        if (line.len == 0) continue;
        if (ctx.done()) break;
        ctx.nextItem();
        const s = ctx.scratch();
        const c = try std.json.parseFromSliceLeaky(Case, s, line, .{ .ignore_unknown_fields = true });
        const method = c.path[std.mem.lastIndexOfScalar(u8, c.path, '/').? + 1 ..];
        const item = try std.fmt.allocPrint(s, "atcp {s} #{d} {s}", .{ method, n, c.tag });
        if (!ctx.selected(item)) continue;
        if (c.status < 0) {
            ctx.skip(item, "sui-node did not answer during the capture");
            continue;
        }
        if (c.info) |info| {
            // sui-node's window at request time: GetServiceInfo just before and just after the
            // case bracket it (both move every few hundred ms). A number the answer reports is
            // taken only when it lies inside that independently observed bracket; otherwise the
            // bracket's start is used and the comparison fails.
            svc.lowest_checkpoint = bracketed(c.message, "lowest available checkpoint is ", info.before.lowest, info.after.lowest);
            index.indexed_hi.store(bracketed(c.message, "highest indexed checkpoint is ", info.before.tip, info.after.tip), .release);
        } else {
            svc.lowest_checkpoint = meta.start.lowest;
            index.indexed_hi.store(meta.start.tip, .release);
        }
        const pass = try replay(ctx, handler, c, item);
        const key = try std.fmt.allocPrint(a, "{s}:{s}", .{ c.tag, if (c.status == 0) "OK" else "error" });
        const gop = try tallies.getOrPut(a, key);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        gop.value_ptr.add(pass);
    }
    try printTallies(ctx, a, "epoch-pkg atcp matched/total", &tallies);
}

fn decodeB64(arena: std.mem.Allocator, text: []const u8) ![]const u8 {
    var t = text;
    while (t.len > 0 and t[t.len - 1] == '=') t = t[0 .. t.len - 1];
    const d = std.base64.standard_no_pad.Decoder;
    const out = try arena.alloc(u8, try d.calcSizeForSlice(t));
    try d.decode(out, t);
    return out;
}
