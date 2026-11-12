//! Formal snapshots (Mysten `sui-snapshot`, mainnet-v1.83.1): start a node from the live object set
//! at the end of an epoch instead of genesis plus all history.
//!
//! Layout of `epoch_<E>/` (sui-snapshot/src/lib.rs):
//!   MANIFEST        magic 0x00C0FFEE (u32 BE) ++ BCS(Manifest::V1 { snapshot_version: u8,
//!                   address_length: u64, file_metadata: Vec<FileMetadata { file_type: u8 enum,
//!                   bucket_num: u32, part_num: u32, file_compression: u8 enum, sha3_digest:
//!                   [u8; 32] }>, epoch: u64 }) ++ sha3_256(everything before)
//!   <b>_<p>.obj     (zstd) magic 0x00B7EC75 ++ { uvarint len, encoding u8 (1 = BCS),
//!                   BCS(LiveObject::{Normal(Object), Wrapped(ObjectKey)}) }*
//!   <b>_<p>.ref     (zstd) magic 0xDEADBEEF ++ { id 32, version u64 BE, digest 32 }*, one ref per
//!                   object of the partition's .obj, in the same order
//! Each file's sha3_256 (of the bytes as stored, compressed) is in the manifest.
//!
//! Trust. The manifest and files are untrusted (the free endpoint
//! https://formal-snapshot.mainnet.sui.io, or a local copy). What makes the restored live set
//! trustworthy is the state commitment: the ECMH of every ref digest must equal
//! `end_of_epoch_data.epoch_commitments[ECMHLiveObjectSetDigest]` of epoch E's last checkpoint,
//! whose certificate the trust walk verifies (and whose contents, effects and events are checked
//! in full). Every object's own digest must equal its ref, so the objects are as trusted as the
//! refs. sha3 checks only catch transfer damage early, like Mysten's reader.
//!
//! Crash safety. `node/snapshot.json` says `loading` while objects go into the store (commit groups
//! numbered 0, 1, 2, ... below the end-of-epoch checkpoint). The last group stores the
//! end-of-epoch checkpoint itself (summary, contents and transaction records) and only then,
//! with the live table durable, is the marker set to `done`. A node that finds `loading` wipes
//! the store and starts the restore again; afterwards it resumes from the stored end-of-epoch
//! checkpoint like any restart. `done` says the store is restored; it says nothing of the
//! derived indexes, which a node start reads from the indexes themselves
//! (restore_index.finishRestore).
const std = @import("std");
const Io = std.Io;
const bcs = @import("bcs");
const types = @import("types");
const hash = @import("hash");
const sig = @import("sig");
const store = @import("store");
const sync = @import("sync");
const exec = @import("exec");
const convert = @import("convert.zig");
const source_mod = @import("source.zig");
const Atomic = std.atomic.Value;

pub const manifest_magic: u32 = 0x00C0FFEE;
pub const object_magic: u32 = 0x00B7EC75;
pub const reference_magic: u32 = 0xDEADBEEF;
pub const ref_len = 32 + 8 + 32;
/// `ObjectDigest::OBJECT_DIGEST_WRAPPED` is 32 bytes of this value (sui-types digests.rs).
pub const digest_wrapped_byte: u8 = 88;
pub const mainnet_url = "https://formal-snapshot.mainnet.sui.io";

pub const FileType = enum(u8) { object = 0, reference = 1 };
pub const Compression = enum(u8) { none = 0, zstd = 1 };

pub const FileMeta = struct {
    kind: FileType,
    bucket: u32,
    part: u32,
    compression: Compression,
    sha3: [32]u8,

    pub fn name(f: FileMeta, buf: []u8) []const u8 {
        return std.fmt.bufPrint(buf, "{d}_{d}.{s}", .{ f.bucket, f.part, if (f.kind == .object) "obj" else "ref" }) catch unreachable;
    }
};

pub const Manifest = struct {
    snapshot_version: u8,
    address_length: u64,
    files: []const FileMeta,
    epoch: u64,

    /// Object/reference file pairs, one per (bucket, partition), sorted.
    pub fn partitions(m: *const Manifest, arena: std.mem.Allocator) ![]const Partition {
        var map: std.AutoArrayHashMapUnmanaged(u64, Partition) = .empty;
        for (m.files) |f| {
            const gop = try map.getOrPut(arena, (@as(u64, f.bucket) << 32) | f.part);
            if (!gop.found_existing) gop.value_ptr.* = .{ .bucket = f.bucket, .part = f.part, .obj = null, .ref = null };
            switch (f.kind) {
                .object => {
                    if (gop.value_ptr.obj != null) return error.BadManifest;
                    gop.value_ptr.obj = f;
                },
                .reference => {
                    if (gop.value_ptr.ref != null) return error.BadManifest;
                    gop.value_ptr.ref = f;
                },
            }
        }
        const out = try arena.dupe(Partition, map.values());
        for (out) |p| if (p.obj == null or p.ref == null) return error.BadManifest;
        std.mem.sort(Partition, out, {}, struct {
            fn lt(_: void, a: Partition, b: Partition) bool {
                return if (a.bucket != b.bucket) a.bucket < b.bucket else a.part < b.part;
            }
        }.lt);
        return out;
    }
};

pub const Partition = struct { bucket: u32, part: u32, obj: ?FileMeta, ref: ?FileMeta };

fn sha3(parts: []const []const u8) [32]u8 {
    var h = hash.Sha3_256.init();
    for (parts) |p| h.update(p);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// Parses and checks a MANIFEST file (magic, sha3 trailer, BCS with nothing left over).
pub fn parseManifest(arena: std.mem.Allocator, bytes: []const u8) !Manifest {
    if (bytes.len < 4 + 32) return error.BadManifest;
    if (std.mem.readInt(u32, bytes[0..4], .big) != manifest_magic) return error.BadManifest;
    const body_end = bytes.len - 32;
    if (!std.mem.eql(u8, &sha3(&.{bytes[0..body_end]}), bytes[body_end..])) return error.ManifestChecksum;
    var r = bcs.Reader.init(bytes[4..body_end]);
    if (try r.uleb32() != 0) return error.BadManifest; // Manifest::V1
    const version = try r.int(u8);
    const alen = try r.int(u64);
    const n = try r.length();
    if (n > r.remaining() / (1 + 8 + 1 + 32)) return error.BadManifest;
    const files = try arena.alloc(FileMeta, n);
    for (files) |*f| {
        f.kind = switch (try r.uleb32()) {
            0 => .object,
            1 => .reference,
            else => return error.BadManifest,
        };
        f.bucket = try r.int(u32);
        f.part = try r.int(u32);
        f.compression = switch (try r.uleb32()) {
            0 => .none,
            1 => .zstd,
            else => return error.BadManifest,
        };
        f.sha3 = (try r.bytes(32))[0..32].*;
    }
    const epoch = try r.int(u64);
    if (r.remaining() != 0) return error.BadManifest;
    if (version != 1 or alen != 32) return error.UnsupportedSnapshot;
    return .{ .snapshot_version = version, .address_length = alen, .files = files, .epoch = epoch };
}

fn putUleb(out: *std.ArrayList(u8), gpa: std.mem.Allocator, v: u64) !void {
    var x = v;
    while (true) {
        const b: u8 = @truncate(x & 0x7f);
        x >>= 7;
        if (x == 0) return out.append(gpa, b);
        try out.append(gpa, b | 0x80);
    }
}

/// Encodes a MANIFEST (tests and tools; Mysten's writer produces the same bytes).
pub fn writeManifest(gpa: std.mem.Allocator, m: *const Manifest, out: *std.ArrayList(u8)) !void {
    out.clearRetainingCapacity();
    var mb: [4]u8 = undefined;
    std.mem.writeInt(u32, &mb, manifest_magic, .big);
    try out.appendSlice(gpa, &mb);
    try out.append(gpa, 0);
    try out.append(gpa, m.snapshot_version);
    var b8: [8]u8 = undefined;
    std.mem.writeInt(u64, &b8, m.address_length, .little);
    try out.appendSlice(gpa, &b8);
    try putUleb(out, gpa, m.files.len);
    for (m.files) |f| {
        try out.append(gpa, @intFromEnum(f.kind));
        var b4: [4]u8 = undefined;
        std.mem.writeInt(u32, &b4, f.bucket, .little);
        try out.appendSlice(gpa, &b4);
        std.mem.writeInt(u32, &b4, f.part, .little);
        try out.appendSlice(gpa, &b4);
        try out.append(gpa, @intFromEnum(f.compression));
        try out.appendSlice(gpa, &f.sha3);
    }
    std.mem.writeInt(u64, &b8, m.epoch, .little);
    try out.appendSlice(gpa, &b8);
    const d = sha3(&.{out.items});
    try out.appendSlice(gpa, &d);
}

// ------------------------------------------------------------------ partitions

pub const Entry = union(enum) {
    /// A live object: its bytes (BCS Object), key and digest (equal to its ref).
    object: struct { bytes: []const u8, id: [32]u8, version: u64, digest: [32]u8 },
    /// LiveObject::Wrapped(ObjectKey).
    wrapped: struct { id: [32]u8, version: u64 },
};

/// One checked partition. `entries` point into `obj_plain`.
pub const Checked = struct {
    entries: std.ArrayList(Entry) = .empty,
    obj_plain: std.ArrayList(u8) = .empty,
    ref_plain: std.ArrayList(u8) = .empty,
    acc: sig.Ecmh = .{},
    bytes: u64 = 0,

    pub fn deinit(c: *Checked, gpa: std.mem.Allocator) void {
        c.entries.deinit(gpa);
        c.obj_plain.deinit(gpa);
        c.ref_plain.deinit(gpa);
    }
};

fn plain(gpa: std.mem.Allocator, raw: []const u8, comp: Compression, out: *std.ArrayList(u8)) !void {
    out.clearRetainingCapacity();
    switch (comp) {
        .none => try out.appendSlice(gpa, raw),
        .zstd => {
            const d = convert.unzstd(gpa, raw, 1 << 31) catch |e| switch (e) {
                error.OutOfMemory => return e,
                else => return error.BadSnapshotFile,
            };
            defer gpa.free(d);
            try out.appendSlice(gpa, d);
        },
    }
}

/// Checks one partition from its two files as stored: sha3 against the manifest, magic numbers,
/// one ref per object, each object's (id, version, digest) equal to its ref. Accumulates the ref
/// digests (Mysten's reader accumulates exactly these) into `out.acc`.
pub fn checkPartition(gpa: std.mem.Allocator, p: Partition, obj_raw: []const u8, ref_raw: []const u8, out: *Checked) !void {
    const om = p.obj.?;
    const rm = p.ref.?;
    if (!std.mem.eql(u8, &sha3(&.{obj_raw}), &om.sha3)) return error.ObjectFileChecksum;
    if (!std.mem.eql(u8, &sha3(&.{ref_raw}), &rm.sha3)) return error.ReferenceFileChecksum;
    try plain(gpa, obj_raw, om.compression, &out.obj_plain);
    try plain(gpa, ref_raw, rm.compression, &out.ref_plain);
    out.bytes += obj_raw.len + ref_raw.len;
    const ob = out.obj_plain.items;
    const rb = out.ref_plain.items;
    if (ob.len < 4 or std.mem.readInt(u32, ob[0..4], .big) != object_magic) return error.BadObjectFile;
    if (rb.len < 4 or std.mem.readInt(u32, rb[0..4], .big) != reference_magic) return error.BadReferenceFile;
    if ((rb.len - 4) % ref_len != 0) return error.BadReferenceFile;
    const n_refs = (rb.len - 4) / ref_len;
    out.entries.clearRetainingCapacity();
    try out.entries.ensureTotalCapacity(gpa, n_refs);
    var r = bcs.Reader.init(ob[4..]);
    var i: usize = 0;
    var digests: [64][]const u8 = undefined;
    var nd: usize = 0;
    while (r.remaining() > 0) : (i += 1) {
        if (i >= n_refs) return error.MoreObjectsThanRefs;
        const len = try r.length();
        if (len == 0) return error.BadObjectFile;
        if (try r.int(u8) != 1) return error.BadObjectFile; // BlobEncoding::Bcs
        const blob = try r.bytes(len);
        const ref = rb[4 + i * ref_len ..][0..ref_len];
        const rid = ref[0..32].*;
        const rver = std.mem.readInt(u64, ref[32..40], .big);
        const rdig = ref[40..72];
        if (blob.len < 1) return error.BadObjectFile;
        switch (blob[0]) {
            0 => {
                const bytes = blob[1..];
                const k = exec.objects.keyOf(bytes) catch return error.BadObject;
                const d = sync.verify.objectDigest(bytes);
                if (!std.mem.eql(u8, &k.id, &rid) or k.version != rver or !std.mem.eql(u8, &d, rdig)) return error.ObjectRefMismatch;
                out.entries.appendAssumeCapacity(.{ .object = .{ .bytes = bytes, .id = k.id, .version = k.version, .digest = d } });
            },
            1 => {
                if (blob.len != 1 + 32 + 8) return error.BadObject;
                const id = blob[1..33].*;
                const ver = std.mem.readInt(u64, blob[33..41], .little);
                // Rust `LiveObject::object_reference`: a wrapped entry's ref digest is
                // OBJECT_DIGEST_WRAPPED. Without this check the root (over ref digests only) would
                // not tell a wrapped entry from a live object with the same ref, so a tampered .obj
                // file could turn a live object into a tombstone.
                if (!std.mem.eql(u8, &id, &rid) or ver != rver or !std.mem.allEqual(u8, rdig, digest_wrapped_byte)) return error.ObjectRefMismatch;
                out.entries.appendAssumeCapacity(.{ .wrapped = .{ .id = id, .version = ver } });
            },
            else => return error.BadObject,
        }
        digests[nd] = rdig;
        nd += 1;
        if (nd == digests.len) {
            out.acc.insertAll(digests[0..nd]);
            nd = 0;
        }
    }
    out.acc.insertAll(digests[0..nd]);
    if (i != n_refs) return error.FewerObjectsThanRefs;
}

// ------------------------------------------------------------------ where files come from

pub const Origin = union(enum) {
    /// A local directory holding `epoch_<E>/...` (or the epoch's files directly, see `flat`).
    dir: struct { root: Io.Dir, flat: bool = false },
    /// An HTTPS base URL (Mysten's free endpoint by default): `<url>/epoch_<E>/<file>`.
    https: []const u8,
};

pub const Fetcher = struct {
    gpa: std.mem.Allocator,
    io: Io,
    origin: Origin,
    client: ?std.http.Client = null,
    bytes: Atomic(u64) = .init(0),

    pub fn deinit(f: *Fetcher) void {
        if (f.client) |*c| c.deinit();
    }

    pub fn get(f: *Fetcher, epoch: u64, name: []const u8, out: *std.ArrayList(u8)) !void {
        out.clearRetainingCapacity();
        switch (f.origin) {
            .dir => |d| {
                var pb: [128]u8 = undefined;
                const path = if (d.flat) name else std.fmt.bufPrint(&pb, "epoch_{d}/{s}", .{ epoch, name }) catch unreachable;
                const file = try d.root.openFile(f.io, path, .{});
                defer file.close(f.io);
                const size: usize = @intCast((try file.stat(f.io)).size);
                try out.resize(f.gpa, size);
                if (try file.readPositionalAll(f.io, out.items, 0) != size) return error.ShortRead;
            },
            .https => |base| {
                if (f.client == null) f.client = .{ .allocator = f.gpa, .io = f.io };
                var ub: [512]u8 = undefined;
                const url = try std.fmt.bufPrint(&ub, "{s}/epoch_{d}/{s}", .{ base, epoch, name });
                var attempt: u32 = 0;
                while (true) : (attempt += 1) {
                    var aw: std.Io.Writer.Allocating = .fromArrayList(f.gpa, out);
                    aw.writer.end = 0;
                    const res = f.client.?.fetch(.{ .location = .{ .url = url }, .method = .GET, .response_writer = &aw.writer, .headers = .{ .accept_encoding = .omit } });
                    out.* = aw.toArrayList();
                    if (res) |r| {
                        if (r.status == .ok) break;
                        if (r.status == .not_found) return error.SnapshotFileMissing;
                        std.log.warn("snapshot GET {s}: HTTP {d}", .{ url, @intFromEnum(r.status) });
                    } else |e| std.log.warn("snapshot GET {s}: {s}", .{ url, @errorName(e) });
                    if (attempt >= 8) return error.SnapshotFetchFailed;
                    f.io.sleep(.fromMilliseconds(@min(@as(u64, 250) << @intCast(attempt), 10_000)), .awake) catch {};
                }
            },
        }
        if (f.origin == .https) @import("http.zig").net_cap.charge(f.io, out.items.len); // --net-max-mbps, after the fact
        _ = f.bytes.fetchAdd(out.items.len, .monotonic);
    }
};

// ------------------------------------------------------------------ restore

/// The ECMH live object set commitment in a certified end-of-epoch summary.
pub fn commitmentOf(arena: std.mem.Allocator, summary_bytes: []const u8) ![32]u8 {
    const s = try bcs.decode(types.CheckpointSummary, arena, summary_bytes);
    const eoe = s.end_of_epoch_data orelse return error.NotEndOfEpoch;
    for (eoe.epochCommitments) |c| switch (c) {
        .ECMHLiveObjectSetDigest => |d| return d.digest.@"0",
        else => {},
    };
    return error.NoStateCommitment;
}

pub const Marker = enum { none, loading, done };

pub fn readMarker(io: Io, node_dir: Io.Dir) !struct { state: Marker, epoch: u64 } {
    var buf: [256]u8 = undefined;
    const text = node_dir.readFile(io, "snapshot.json", &buf) catch |e| switch (e) {
        error.FileNotFound => return .{ .state = .none, .epoch = 0 },
        else => return e,
    };
    const V = struct { epoch: u64, state: []const u8 };
    var fba = std.heap.FixedBufferAllocator.init(buf[text.len..]);
    const v = try std.json.parseFromSliceLeaky(V, fba.allocator(), text, .{});
    return .{ .state = std.meta.stringToEnum(Marker, v.state) orelse return error.BadMarker, .epoch = v.epoch };
}

pub fn writeMarker(io: Io, node_dir: Io.Dir, state: Marker, epoch: u64) !void {
    var buf: [128]u8 = undefined;
    const text = try std.fmt.bufPrint(&buf, "{{\"epoch\":{d},\"state\":\"{s}\"}}\n", .{ epoch, @tagName(state) });
    {
        const f = try node_dir.createFile(io, ".snapshot.json.tmp", .{ .truncate = true });
        defer f.close(io);
        try f.writePositionalAll(io, text, 0);
        try f.sync(io);
    }
    try node_dir.rename(".snapshot.json.tmp", node_dir, "snapshot.json", io);
    try @import("trust.zig").syncDir(io, node_dir);
}

pub const Stats = struct {
    partitions_done: Atomic(u64) = .init(0),
    objects: Atomic(u64) = .init(0),
    wrapped: Atomic(u64) = .init(0),
    bytes_fetched: Atomic(u64) = .init(0),
    groups: Atomic(u64) = .init(0),
    /// Partitions fetched again after a sha3 or decompression mismatch.
    refetched: Atomic(u64) = .init(0),
};

pub const RestoreOptions = struct {
    epoch: u64,
    origin: Origin,
    threads: u32 = 8,
    /// Verified end-of-epoch checkpoint blob of `epoch` (0x01 ++ CheckpointData): its ECMH
    /// commitment is the trust anchor and its records end the restore.
    eoe_blob: []const u8,
    /// Only for tests: accept this root instead of the blob's commitment.
    expect_root: ?[32]u8 = null,
    log_every_s: u64 = 10,
    /// Derived-index feed (CONTRACTS 6.8): called by the single writer for every live object of
    /// the snapshot, in store order, before the end-of-epoch checkpoint is stored. An error stops
    /// the restore (the marker stays `loading`, so the next start restores again).
    on_object: ?ObjectHook = null,
    /// Bulk-load the live table (store `bulkLiveBegin`/`bulkLiveFinish`, lane fast-start): the
    /// restore's private memory stays about 1 GB instead of the whole table (~35 GB at mainnet
    /// scale), and the table is written and named in `meta` before the end-of-epoch checkpoint.
    bulk_live: bool = false,
    /// Set by a signal: the restore stops within about a second (error.Stopped; the marker stays
    /// `loading`, so the next start restores again).
    stop: ?*const Atomic(bool) = null,
    /// Derived-index feed on the fetch threads (lane index-fast): called by fetch worker `worker`
    /// (0 .. threads-1) with every verified partition's entries, before the single writer takes
    /// them, in no particular order across partitions. Each partition is handed over exactly
    /// once (a refetched partition only after its check passed). An error fails the restore.
    on_partition: ?PartitionHook = null,
    /// Called once every partition is in and the root matched, before the live table is built
    /// (lane index-fast: the index merge starts here and runs beside the table build).
    after_objects: ?DoneHook = null,
    /// Store each partition's objects grouped by type (`sortForStore`): about 20% less disk for
    /// the restored live set once compressed (lane disk-fit). `ZUI_RESTORE_SORT=0` turns it off.
    sort_by_type: bool = true,
};

pub const PartitionHook = struct {
    ctx: *anyopaque,
    f: *const fn (ctx: *anyopaque, worker: usize, entries: []const Entry) anyerror!void,
};

pub const DoneHook = struct {
    ctx: *anyopaque,
    /// `at`: the restored end-of-epoch checkpoint (the live set's checkpoint).
    f: *const fn (ctx: *anyopaque, at: u64) anyerror!void,
};

/// Sort key of one partition entry (`sortForStore`): offsets into the object's own bytes.
pub const SortKey = struct {
    /// Index of the entry in the partition.
    i: u32,
    /// 0 Move object, 1 package, 2 wrapped (no bytes).
    class: u8,
    /// Move objects: the type is `bytes[1..ty_end]`, the owner `bytes[own_at..own_end]`.
    ty_end: u32 = 0,
    own_at: u32 = 0,
    own_end: u32 = 0,
};

/// Reorders a checked partition's entries for the store: Move objects grouped by type (the BCS
/// `MoveObjectType`), then by size, then by owner; packages after them; wrapped entries last.
///
/// Why: the store keeps the restored live set as compact records in commit order and compresses
/// them in 256 KiB chunks. In the snapshot's order (object id order, so types at random) a chunk
/// holds a thousand unrelated objects; grouped, records of one type sit together and their type
/// tags, layouts and shared owners compress away. On a mainnet epoch-1305 partition (571,770
/// objects) that took the chunk ratio from 1.516 to 1.873 at zstd -1 (python study,
/// measured). Nothing reads the store in commit order for meaning: every index
/// and lookup is by id (the live table) or rebuilt from it, the ECMH root is order-free and was
/// checked before this, and the end-of-epoch checkpoint still commits last.
pub fn sortForStore(gpa: std.mem.Allocator, entries: []Entry, keys: *std.ArrayList(SortKey), seen: *std.DynamicBitSetUnmanaged) !void {
    if (entries.len < 2) return;
    keys.clearRetainingCapacity();
    try keys.ensureTotalCapacity(gpa, entries.len);
    for (entries, 0..) |e, i| {
        var k: SortKey = .{ .i = @intCast(i), .class = 2 };
        switch (e) {
            .wrapped => {},
            .object => |o| {
                k.class = 1;
                if (exec.objects.ObjectView.parse(o.bytes)) |v| {
                    if (!v.is_package and v.version_at >= 2) {
                        k.class = 0;
                        k.ty_end = v.version_at - 1; // `has_public_transfer` sits between type and version
                        k.own_at = v.owner_at;
                        k.own_end = v.prev_tx_at;
                    }
                } else |_| {}
            },
        }
        keys.appendAssumeCapacity(k);
    }
    const Ctx = struct {
        es: []const Entry,
        fn bytesOf(c: @This(), k: SortKey) []const u8 {
            return switch (c.es[k.i]) {
                .object => |o| o.bytes,
                .wrapped => &.{},
            };
        }
        fn lt(c: @This(), a: SortKey, b: SortKey) bool {
            if (a.class != b.class) return a.class < b.class;
            if (a.class == 0) {
                const ab = c.bytesOf(a);
                const bb = c.bytesOf(b);
                switch (std.mem.order(u8, ab[1..a.ty_end], bb[1..b.ty_end])) {
                    .lt => return true,
                    .gt => return false,
                    .eq => {},
                }
                if (ab.len != bb.len) return ab.len < bb.len;
                switch (std.mem.order(u8, ab[a.own_at..a.own_end], bb[b.own_at..b.own_end])) {
                    .lt => return true,
                    .gt => return false,
                    .eq => {},
                }
            }
            return a.i < b.i;
        }
    };
    std.mem.sortUnstable(SortKey, keys.items, Ctx{ .es = entries }, Ctx.lt);
    // Apply the permutation in place: position j takes the entry at keys[j].i (cycle walk).
    try seen.resize(gpa, entries.len, false);
    seen.unsetAll();
    for (0..entries.len) |start| {
        if (seen.isSet(start)) continue;
        const tmp = entries[start];
        var j = start;
        while (true) {
            seen.set(j);
            const from = keys.items[j].i;
            if (from == start) {
                entries[j] = tmp;
                break;
            }
            entries[j] = entries[from];
            j = from;
        }
    }
}

pub const ObjectHook = struct {
    ctx: *anyopaque,
    f: *const fn (ctx: *anyopaque, id: *const [32]u8, version: u64, bytes: []const u8) anyerror!void,
};

const Slot = struct {
    state: Atomic(u8) = .init(0), // 0 free, 1 being filled, 2 ready
    checked: Checked = .{},
    part: Partition = undefined,
};

const Shared = struct {
    gpa: std.mem.Allocator,
    io: Io,
    opts: *const RestoreOptions,
    parts: []const Partition,
    next: Atomic(usize) = .init(0),
    slots: []Slot,
    failed: Atomic(bool) = .init(false),
    failure: ?anyerror = null,
    stats: *Stats,
    accs: []sig.Ecmh,
};

fn worker(sh: *Shared, wi: usize) void {
    var f: Fetcher = .{ .gpa = sh.gpa, .io = sh.io, .origin = sh.opts.origin };
    defer f.deinit();
    var obj_raw: std.ArrayList(u8) = .empty;
    defer obj_raw.deinit(sh.gpa);
    var ref_raw: std.ArrayList(u8) = .empty;
    defer ref_raw.deinit(sh.gpa);
    var sort_keys: std.ArrayList(SortKey) = .empty;
    defer sort_keys.deinit(sh.gpa);
    var sort_seen: std.DynamicBitSetUnmanaged = .{};
    defer sort_seen.deinit(sh.gpa);
    const slot = &sh.slots[wi];
    while (!sh.failed.load(.acquire)) {
        if (sh.opts.stop) |x| if (x.load(.acquire)) return;
        // Wait for the writer to consume this worker's previous partition.
        while (slot.state.load(.acquire) != 0) {
            if (sh.failed.load(.acquire)) return;
            sh.io.sleep(.fromMilliseconds(2), .awake) catch {};
        }
        const i = sh.next.fetchAdd(1, .monotonic);
        if (i >= sh.parts.len) return;
        const p = sh.parts[i];
        var nb: [64]u8 = undefined;
        // A file whose bytes do not match the MANIFEST's sha3 (or do not decompress) is fetched
        // again: a transfer can end short or damaged without an HTTP error (seen once in 1,448
        // partitions on 2026-11-07). The check itself never loosens; after `max_refetch` tries
        // the restore fails.
        const max_refetch = 4;
        var tries: u32 = 0;
        const r = while (true) : (tries += 1) {
            const one = blk: {
                f.get(sh.opts.epoch, p.ref.?.name(&nb), &ref_raw) catch |e| break :blk e;
                f.get(sh.opts.epoch, p.obj.?.name(&nb), &obj_raw) catch |e| break :blk e;
                slot.checked.acc = .{};
                checkPartition(sh.gpa, p, obj_raw.items, ref_raw.items, &slot.checked) catch |e| break :blk e;
                if (sh.opts.sort_by_type) sortForStore(sh.gpa, slot.checked.entries.items, &sort_keys, &sort_seen) catch |e| break :blk e;
                break :blk {};
            };
            one catch |e| switch (e) {
                error.ObjectFileChecksum, error.ReferenceFileChecksum, error.BadSnapshotFile => if (tries + 1 < max_refetch) {
                    _ = sh.stats.refetched.fetchAdd(1, .monotonic);
                    std.log.warn("snapshot partition {d}_{d}: {s} ({d} + {d} bytes); fetching it again", .{ p.bucket, p.part, @errorName(e), obj_raw.items.len, ref_raw.items.len });
                    continue;
                },
                else => {},
            };
            if (one) |_| {
                sh.accs[wi].add(&slot.checked.acc);
                slot.checked.acc = .{};
            } else |_| {}
            break one;
        };
        r catch |e| {
            std.log.err("snapshot partition {d}_{d}: {s}", .{ p.bucket, p.part, @errorName(e) });
            sh.failure = e;
            sh.failed.store(true, .release);
            return;
        };
        if (sh.opts.on_partition) |h| h.f(h.ctx, wi, slot.checked.entries.items) catch |e| {
            std.log.err("snapshot partition {d}_{d}: index feed: {s}", .{ p.bucket, p.part, @errorName(e) });
            sh.failure = e;
            sh.failed.store(true, .release);
            return;
        };
        _ = sh.stats.bytes_fetched.fetchAdd(obj_raw.items.len + ref_raw.items.len, .monotonic);
        slot.part = p;
        slot.state.store(2, .release);
    }
}

/// Loads epoch `opts.epoch`'s formal snapshot into an empty store and verifies its root against
/// the certified commitment. On success the store's last committed checkpoint is the epoch's
/// end-of-epoch checkpoint. The caller handles the marker file.
pub fn restore(gpa: std.mem.Allocator, io: Io, st: *store.Store, opts: RestoreOptions, stats: *Stats) !void {
    if (st.committed() != null) return error.StoreNotEmpty;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    try types.indexCheckpointData(opts.eoe_blob, &idx);
    const summary_bytes = idx.summary.slice(opts.eoe_blob);
    const s = try bcs.decode(types.CheckpointSummary, arena, summary_bytes);
    if (s.epoch != opts.epoch) return error.WrongEpoch;
    const want_root = opts.expect_root orelse try commitmentOf(arena, summary_bytes);

    var mf: Fetcher = .{ .gpa = gpa, .io = io, .origin = opts.origin };
    defer mf.deinit();
    var mbytes: std.ArrayList(u8) = .empty;
    defer mbytes.deinit(gpa);
    try mf.get(opts.epoch, "MANIFEST", &mbytes);
    const m = try parseManifest(arena, mbytes.items);
    if (m.epoch != opts.epoch) return error.WrongEpoch;
    const parts = try m.partitions(arena);
    std.log.info("snapshot: epoch {d}, {d} partitions, root must be {x}", .{ m.epoch, parts.len, &want_root });

    const nt: usize = @max(1, @min(opts.threads, parts.len));
    const slots = try gpa.alloc(Slot, nt);
    defer {
        for (slots) |*sl| sl.checked.deinit(gpa);
        gpa.free(slots);
    }
    @memset(slots, .{});
    const accs = try gpa.alloc(sig.Ecmh, nt);
    defer gpa.free(accs);
    @memset(accs, .{});
    var sh: Shared = .{ .gpa = gpa, .io = io, .opts = &opts, .parts = parts, .slots = slots, .stats = stats, .accs = accs };
    const threads = try gpa.alloc(std.Thread, nt);
    defer gpa.free(threads);
    for (threads, 0..) |*t, i| t.* = try std.Thread.spawn(.{ .stack_size = 16 << 20 }, worker, .{ &sh, i });
    defer for (threads) |t| t.join();
    errdefer sh.failed.store(true, .release);

    if (opts.bulk_live) try st.bulkLiveBegin();
    errdefer st.bulkLiveAbort();

    // Single writer: the store's commit groups 0, 1, 2, ... (below the end-of-epoch checkpoint).
    var group: u64 = 0;
    var b: ?*store.Batch = null;
    errdefer if (b) |x| st.abort(x);
    var done: usize = 0;
    var last_log = source_mod.nowNs();
    const t0 = last_log;
    while (done < parts.len) {
        if (sh.failed.load(.acquire)) return sh.failure orelse error.SnapshotFailed;
        if (opts.stop) |x| if (x.load(.acquire)) {
            sh.failed.store(true, .release);
            return error.Stopped;
        };
        var progressed = false;
        for (slots) |*sl| {
            if (sl.state.load(.acquire) != 2) continue;
            progressed = true;
            for (sl.checked.entries.items) |e| {
                while (true) {
                    if (b == null) {
                        if (group >= s.sequence_number) return error.TooManyGroups;
                        b = try st.begin(group, opts.epoch);
                    }
                    const r = switch (e) {
                        .object => |o| b.?.putBase(&o.id, o.version, &o.digest, o.bytes),
                        .wrapped => |w| b.?.removeObject(&w.id, w.version, .wrapped),
                    };
                    r catch |err| switch (err) {
                        error.BatchFull, error.SegmentFull => {
                            try st.commit(b.?);
                            b = null;
                            group += 1;
                            _ = stats.groups.fetchAdd(1, .monotonic);
                            continue;
                        },
                        else => return err,
                    };
                    break;
                }
                if (opts.on_object) |h| switch (e) {
                    .object => |o| try h.f(h.ctx, &o.id, o.version, o.bytes),
                    .wrapped => {},
                };
                switch (e) {
                    .object => _ = stats.objects.fetchAdd(1, .monotonic),
                    .wrapped => _ = stats.wrapped.fetchAdd(1, .monotonic),
                }
            }
            sl.state.store(0, .release);
            done += 1;
            _ = stats.partitions_done.fetchAdd(1, .monotonic);
        }
        const now = source_mod.nowNs();
        if (opts.log_every_s > 0 and now - last_log >= opts.log_every_s * std.time.ns_per_s) {
            last_log = now;
            const secs = @as(f64, @floatFromInt(now - t0)) / 1e9;
            std.log.info("snapshot: {d}/{d} partitions, {d} objects, {d} MiB fetched, {d:.0} objects/s", .{ done, parts.len, stats.objects.load(.monotonic), stats.bytes_fetched.load(.monotonic) >> 20, @as(f64, @floatFromInt(stats.objects.load(.monotonic))) / secs });
        }
        if (!progressed) io.sleep(.fromMilliseconds(1), .awake) catch {};
    }
    if (b) |x| {
        try st.commit(x);
        b = null;
        _ = stats.groups.fetchAdd(1, .monotonic);
    }
    // Every partition is consumed: the slots' decoded partitions (up to ~0.3 GB each) go before
    // the live table and the index merge allocate theirs. Workers only exit from here on.
    for (slots) |*sl| {
        sl.checked.deinit(gpa);
        sl.checked = .{};
    }

    // The root.
    var root: sig.Ecmh = .{};
    for (accs) |*a| root.add(a);
    const got = root.digest();
    if (!std.mem.eql(u8, &got, &want_root)) {
        std.log.err("snapshot: live object set root {x} differs from the certified commitment {x}", .{ &got, &want_root });
        return error.StateRootMismatch;
    }
    std.log.info("snapshot: root {x} matches the {s} ({d} objects, {d} wrapped, {d} s)", .{ &got, if (opts.expect_root != null) "expected test root" else "certified commitment", stats.objects.load(.monotonic), stats.wrapped.load(.monotonic), (source_mod.nowNs() - t0) / std.time.ns_per_s });

    if (opts.after_objects) |h| try h.f(h.ctx, s.sequence_number);

    if (opts.bulk_live) {
        const r = try st.bulkLiveFinish(opts.stop);
        std.log.info("snapshot: live table written in {d} s ({d} objects, {d} live, {d} MiB, {d} wrapped to the front)", .{ r.ms / 1000, r.objects, r.live, (r.pages * 4096) >> 20, r.wrapped });
    }

    // The end-of-epoch checkpoint closes the restore: the node resumes after it.
    const fb = try st.begin(s.sequence_number, opts.epoch);
    errdefer st.abort(fb);
    const blob = opts.eoe_blob;
    try fb.checkpoint(blob[idx.summary.o .. idx.sig.o + idx.sig.n], idx.contents.slice(blob));
    // The verified root, so the node can check the state hash at every later end of epoch.
    try @import("statehash.zig").Checker.storeRoot(fb, s.sequence_number, &root);
    var a2: std.heap.ArenaAllocator = .init(gpa);
    defer a2.deinit();
    const checked = switch (try sync.verify.check(a2.allocator(), blob, &idx)) {
        .ok => |c| c,
        .bad => return error.BadEndOfEpochCheckpoint,
    };
    try fb.checkpointDigest(&checked.digest); // checkpoint digest index (CONTRACTS 6.8)
    // sui-node's restore (sui-tool lib.rs: update_highest_pruned_checkpoint(last checkpoint);
    // sui-snapshot lib.rs: set_highest_pruned_checkpoint_without_wb) marks this checkpoint
    // pruned: lowest_available_checkpoint is S + 1 and GetCheckpoint(S) is NOT_FOUND. The
    // snapshot holds no input versions of S's transactions, so deepwave could not answer it anyway.
    try fb.highestPruned(s.sequence_number);
    for (checked.txs, 0..) |plan, i| {
        const t = idx.txAt(i);
        try fb.transaction(plan.tx_digest, &plan.effects_digest, t.transaction.slice(blob), t.effects.slice(blob), if (t.events) |ev| ev.slice(blob) else null);
    }
    try st.commit(fb);
}

/// The checkpoint store's lowest available checkpoint of a node store
/// (`store.Snapshot.lowestAvailable`): what state sync reports. The RPC surface reports
/// `lowestServed`. `restored_epoch` (the `done` marker's epoch) covers stores restored before the restore
/// recorded its highest pruned checkpoint: while the restored epoch is in the window, its only
/// checkpoint is the restored end-of-epoch one, which sui-node does not serve.
pub fn lowestAvailable(snap: *const store.Snapshot, restored_epoch: ?u64) ?u64 {
    const l = snap.lowestAvailable() orelse return null;
    if (snap.highestPruned() == null) if (restored_epoch) |e| if (snap.checkpoint(l)) |c| if (c.epoch == e) return l + 1;
    return l;
}

/// What the RPC surface reports and serves from: GetServiceInfo `lowest_available_checkpoint`
/// (and `_objects`), the `x-sui-lowest-available-*` headers, the floor of GetCheckpoint,
/// GetTransaction and the List* methods. sui-node (sui-rpc-api reader.rs
/// `get_lowest_available_checkpoint`) takes the higher of the checkpoint store's lowest available
/// checkpoint (`lowestAvailable`, 2 epochs by default) and the objects pruner's (1 epoch): below
/// the second a transaction's effects, balance changes and objects cannot be rendered, its input
/// and output versions are gone. With the defaults that is always the objects pruner's.
/// `lowestAvailable` stays the floor of state sync (GetCheckpointAvailability) and of the
/// checkpoint records themselves.
pub fn lowestServed(snap: *const store.Snapshot, restored_epoch: ?u64) ?u64 {
    return snap.objectsFrom(lowestAvailable(snap, restored_epoch) orelse return null);
}

// ------------------------------------------------------------------ writer (tests and tools)

/// Writes `epoch_<E>/` with one bucket and uncompressed partitions of at most `per_part` entries:
/// MANIFEST, `1_<p>.obj`, `1_<p>.ref`. Returns the ECMH root of the refs.
pub fn writeSnapshot(gpa: std.mem.Allocator, io: Io, root_dir: Io.Dir, epoch: u64, objects: []const []const u8, per_part: usize) ![32]u8 {
    var nb: [64]u8 = undefined;
    const dname = std.fmt.bufPrint(&nb, "epoch_{d}", .{epoch}) catch unreachable;
    try root_dir.createDirPath(io, dname);
    const d = try root_dir.openDir(io, dname, .{});
    defer d.close(io);
    var files: std.ArrayList(FileMeta) = .empty;
    defer files.deinit(gpa);
    var acc: sig.Ecmh = .{};
    var ob: std.ArrayList(u8) = .empty;
    defer ob.deinit(gpa);
    var rb: std.ArrayList(u8) = .empty;
    defer rb.deinit(gpa);
    var part: u32 = 1;
    var i: usize = 0;
    while (i < objects.len or (i == 0 and objects.len == 0)) : (part += 1) {
        ob.clearRetainingCapacity();
        rb.clearRetainingCapacity();
        var m4: [4]u8 = undefined;
        std.mem.writeInt(u32, &m4, object_magic, .big);
        try ob.appendSlice(gpa, &m4);
        std.mem.writeInt(u32, &m4, reference_magic, .big);
        try rb.appendSlice(gpa, &m4);
        const end = @min(objects.len, i + per_part);
        for (objects[i..end]) |o| {
            try putUleb(&ob, gpa, o.len + 1);
            try ob.append(gpa, 1);
            try ob.append(gpa, 0);
            try ob.appendSlice(gpa, o);
            const k = try exec.objects.keyOf(o);
            const dg = sync.verify.objectDigest(o);
            try rb.appendSlice(gpa, &k.id);
            var v8: [8]u8 = undefined;
            std.mem.writeInt(u64, &v8, k.version, .big);
            try rb.appendSlice(gpa, &v8);
            try rb.appendSlice(gpa, &dg);
            acc.insert(&dg);
        }
        i = end;
        inline for (.{ FileType.object, FileType.reference }) |kind| {
            const bytes = if (kind == .object) ob.items else rb.items;
            const fm: FileMeta = .{ .kind = kind, .bucket = 1, .part = part, .compression = .none, .sha3 = sha3(&.{bytes}) };
            var fnb: [64]u8 = undefined;
            try d.writeFile(io, .{ .sub_path = fm.name(&fnb), .data = bytes });
            try files.append(gpa, fm);
        }
        if (objects.len == 0) break;
    }
    const m: Manifest = .{ .snapshot_version = 1, .address_length = 32, .files = files.items, .epoch = epoch };
    var mb: std.ArrayList(u8) = .empty;
    defer mb.deinit(gpa);
    try writeManifest(gpa, &m, &mb);
    try d.writeFile(io, .{ .sub_path = "MANIFEST", .data = mb.items });
    return acc.digest();
}

test "snapshot: a wrapped entry must carry the wrapped ref digest" {
    const gpa = std.testing.allocator;
    var id: [32]u8 = @splat(0);
    id[31] = 0x42;
    var ob: std.ArrayList(u8) = .empty;
    defer ob.deinit(gpa);
    var m4: [4]u8 = undefined;
    std.mem.writeInt(u32, &m4, object_magic, .big);
    try ob.appendSlice(gpa, &m4);
    try putUleb(&ob, gpa, 1 + 32 + 8); // the LiveObject bytes (the encoding byte is not counted)
    try ob.append(gpa, 1); // BlobEncoding::Bcs
    try ob.append(gpa, 1); // LiveObject::Wrapped
    try ob.appendSlice(gpa, &id);
    var v8: [8]u8 = undefined;
    std.mem.writeInt(u64, &v8, 7, .little);
    try ob.appendSlice(gpa, &v8);
    for ([_]u8{ digest_wrapped_byte, 0x11 }) |fill| {
        var rb: std.ArrayList(u8) = .empty;
        defer rb.deinit(gpa);
        std.mem.writeInt(u32, &m4, reference_magic, .big);
        try rb.appendSlice(gpa, &m4);
        try rb.appendSlice(gpa, &id);
        std.mem.writeInt(u64, &v8, 7, .big);
        try rb.appendSlice(gpa, &v8);
        try rb.appendNTimes(gpa, fill, 32);
        const p: Partition = .{
            .bucket = 1,
            .part = 1,
            .obj = .{ .kind = .object, .bucket = 1, .part = 1, .compression = .none, .sha3 = sha3(&.{ob.items}) },
            .ref = .{ .kind = .reference, .bucket = 1, .part = 1, .compression = .none, .sha3 = sha3(&.{rb.items}) },
        };
        var c: Checked = .{};
        defer c.deinit(gpa);
        const r = checkPartition(gpa, p, ob.items, rb.items, &c);
        if (fill == digest_wrapped_byte) {
            try r;
            try std.testing.expectEqual(@as(usize, 1), c.entries.items.len);
            try std.testing.expect(c.entries.items[0] == .wrapped);
        } else try std.testing.expectError(error.ObjectRefMismatch, r);
    }
}
