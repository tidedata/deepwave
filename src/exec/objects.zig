//! Objects as exec sees them: raw `Object` BCS bytes, read in place. An object's key is
//! (id, version); its digest is Blake2b256("Object::" ++ bytes) (`Object::digest`).
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const harness = @import("harness");

const Allocator = std.mem.Allocator;
const Reader = bcs.Reader;

pub const Key = struct {
    id: [32]u8,
    version: u64,

    pub fn lessThan(_: void, a: Key, b: Key) bool {
        const o = std.mem.order(u8, &a.id, &b.id);
        if (o != .eq) return o == .lt;
        return a.version < b.version;
    }
};

/// Where the fields of an `Object` sit in its bytes. Move objects: `contents` starts with the
/// 32-byte UID. Packages: the id and version lead the package.
pub const ObjectView = struct {
    raw: []const u8,
    is_package: bool,
    id: [32]u8,
    version: u64,
    /// Byte offset of the u64 version inside `raw` (patched when an object is re-versioned).
    version_at: u32,
    /// Move objects: offset and length of `contents` (after the ULEB length).
    contents_at: u32,
    contents_len: u32,
    /// Offset of the owner (after `data`), and of `previous_transaction` and `storage_rebate`.
    owner_at: u32,
    prev_tx_at: u32,
    rebate_at: u32,

    pub fn parse(raw: []const u8) !ObjectView {
        var r = Reader.init(raw);
        var v: ObjectView = undefined;
        v.raw = raw;
        const tag = try r.uleb32();
        switch (tag) {
            0 => {
                v.is_package = false;
                try bcs.skip(types.MoveObjectType, &r);
                _ = try r.boolean();
                v.version_at = @intCast(r.at);
                v.version = try r.int(u64);
                const n = try r.length();
                v.contents_at = @intCast(r.at);
                v.contents_len = @intCast(n);
                const c = try r.bytes(n);
                if (n < 32) return error.InvalidValue;
                v.id = c[0..32].*;
            },
            1 => {
                v.is_package = true;
                const start = r.at;
                v.id = (try r.bytes(32))[0..32].*;
                v.version_at = @intCast(r.at);
                v.version = try r.int(u64);
                v.contents_at = 0;
                v.contents_len = 0;
                r.at = start;
                try bcs.skip(types.MovePackage, &r);
            },
            else => return error.InvalidEnumTag,
        }
        v.owner_at = @intCast(r.at);
        try bcs.skip(types.Owner, &r);
        v.prev_tx_at = @intCast(r.at);
        _ = try r.bytes(33);
        v.rebate_at = @intCast(r.at);
        _ = try r.int(u64);
        try r.finish();
        return v;
    }

    pub fn key(v: *const ObjectView) Key {
        return .{ .id = v.id, .version = v.version };
    }

    pub fn contents(v: *const ObjectView) []const u8 {
        return v.raw[v.contents_at..][0..v.contents_len];
    }

    pub fn ownerBytes(v: *const ObjectView) []const u8 {
        return v.raw[v.owner_at..v.prev_tx_at];
    }

    pub fn storageRebate(v: *const ObjectView) u64 {
        return std.mem.readInt(u64, v.raw[v.rebate_at..][0..8], .little);
    }

    pub fn digest(v: *const ObjectView) [32]u8 {
        return types.digest.objectDigest(v.raw);
    }
};

/// Key of an object from its bytes without validating the tail.
pub fn keyOf(raw: []const u8) !Key {
    const v = try ObjectView.parse(raw);
    return v.key();
}

/// (id, version) of BCS `Object` bytes for the store's compact records (CONTRACTS 6.8): reads
/// only up to the id (a Move object's `contents` start, or a package's first field), so it costs
/// a type-tag skip, not a full parse. Null when the bytes do not parse that far.
pub fn storeKey(raw: []const u8) ?@import("store").ObjKey {
    var r = Reader.init(raw);
    const tag = r.uleb32() catch return null;
    switch (tag) {
        0 => {
            bcs.skip(types.MoveObjectType, &r) catch return null;
            _ = r.boolean() catch return null;
            const version = r.int(u64) catch return null;
            const n = r.length() catch return null;
            if (n < 32) return null;
            const c = r.bytes(32) catch return null;
            return .{ .id = c[0..32].*, .version = version };
        },
        1 => {
            const id = r.bytes(32) catch return null;
            const version = r.int(u64) catch return null;
            return .{ .id = id[0..32].*, .version = version };
        },
        else => return null,
    }
}

/// The store codec every deepwave store holding restored (compact) objects is opened with.
pub const store_codec: @import("store").Codec = .{ .key = storeKey };

test "storeKey agrees with keyOf" {
    // Move object: GasCoin type (tag 1), has_public_transfer, version 7, contents id ++ balance.
    var buf: [128]u8 = undefined;
    var n: usize = 0;
    buf[n] = 0; n += 1; // Data::Move
    buf[n] = 1; n += 1; // MoveObjectType::GasCoin
    buf[n] = 1; n += 1; // has_public_transfer
    std.mem.writeInt(u64, buf[n..][0..8], 7, .little); n += 8;
    buf[n] = 40; n += 1; // contents length
    for (0..32) |i| buf[n + i] = @intCast(i + 1);
    n += 32;
    std.mem.writeInt(u64, buf[n..][0..8], 1000, .little); n += 8;
    buf[n] = 3; n += 1; // Owner::Immutable
    @memset(buf[n..][0..33], 0); buf[n] = 32; n += 33; // previous_transaction (len-prefixed digest)
    std.mem.writeInt(u64, buf[n..][0..8], 0, .little); n += 8;
    const raw = buf[0..n];
    const k = storeKey(raw).?;
    const want = try keyOf(raw);
    try std.testing.expectEqual(want.version, k.version);
    try std.testing.expectEqualSlices(u8, &want.id, &k.id);
    try std.testing.expect(storeKey(raw[0..5]) == null);
}

/// (id, version) -> object bytes, for one checkpoint's input and output objects.
pub const ObjectTable = struct {
    map: std.AutoHashMapUnmanaged(Key, []const u8) = .empty,

    pub fn addCheckpoint(t: *ObjectTable, arena: Allocator, blob: []const u8, idx: *const types.CheckpointIndex) !void {
        try t.map.ensureTotalCapacity(arena, idx.obj_total);
        for (idx.objs[0..idx.obj_total]) |range| {
            const raw = range.slice(blob);
            const k = try keyOf(raw);
            t.map.putAssumeCapacity(k, raw);
        }
    }

    pub fn get(t: *const ObjectTable, k: Key) ?[]const u8 {
        return t.map.get(k);
    }
};

pub const objects_path = "vectors/exec-replay/objects.bin.zst";

/// Objects that transactions read but their checkpoint does not carry (read-only shared inputs,
/// unchanged owned and immutable inputs), fetched by `zui-truth-exec objects` and checked
/// against their reference digests. (id, version) -> object bytes.
pub const ObjectDb = struct {
    map: std.AutoHashMapUnmanaged(Key, []const u8) = .empty,
    /// The coin deny list v2 objects by epoch (exec-move, `ptb/deny.zig`).
    deny: @import("ptb/deny.zig").Snapshot = .{},

    pub fn load(ctx: *harness.Ctx, arena: Allocator) !ObjectDb {
        var db: ObjectDb = .{};
        if (ctx.corpus.readFileAlloc(ctx.io, @import("ptb/deny.zig").Snapshot.path, arena, .limited(1 << 30))) |dz| {
            db.deny = try .parse(arena, try harness.decompressZstd(arena, dz, 1 << 32));
        } else |_| {}
        const z = ctx.corpus.readFileAlloc(ctx.io, objects_path, arena, .limited(1 << 32)) catch return db;
        const raw = try harness.decompressZstd(arena, z, 1 << 34);
        var at: usize = 0;
        while (at < raw.len) {
            if (raw.len - at < 4) return error.Truncated;
            const n = std.mem.readInt(u32, raw[at..][0..4], .little);
            at += 4;
            if (raw.len - at < n) return error.Truncated;
            const o = raw[at..][0..n];
            at += n;
            try db.map.put(arena, try keyOf(o), o);
        }
        return db;
    }

    pub fn get(db: *const ObjectDb, k: Key) ?[]const u8 {
        return db.map.get(k);
    }
};

/// The metadata part of `object_size_for_gas_metering`: owner 40, previous transaction 32,
/// storage rebate 8.
const gas_meta: u64 = 40 + 32 + 8;

/// `object_size_for_gas_metering` of a Move object from its parts, without the object's bytes:
/// `type_size` is the length of its serialized `MoveObjectType`.
pub fn moveSizeForGasMetering(type_size: u64, contents_len: u64) u64 {
    return gas_meta + contents_len + type_size + 1 + 8;
}

/// `Object::object_size_for_gas_metering`: 80 bytes of metadata (owner 40, previous transaction
/// 32, storage rebate 8) plus the data size. Move objects: contents + serialized type + 1 + 8.
/// Packages: `MovePackage::size` (module names and bytes, type origins, linkage entries).
pub fn sizeForGasMetering(arena: Allocator, v: *const ObjectView) !u64 {
    const meta = gas_meta;
    if (!v.is_package) {
        const type_size: u64 = v.version_at - 2; // raw[1 .. version_at - 1] is the type
        return moveSizeForGasMetering(type_size, v.contents_len);
    }
    var r = Reader.init(v.raw[1..]);
    const p = try bcs.decodeFrom(types.MovePackage, arena, &r);
    var size: u64 = 0;
    for (p.module_map.entries) |e| size += e.key.@"0".len + e.value.len;
    for (p.type_origin_table) |t| size += t.module_name.@"0".len + t.datatype_name.@"0".len + 32;
    size += p.linkage_table.entries.len * (32 + 32 + 8);
    size += 8; // SequenceNumber
    return meta + size;
}
