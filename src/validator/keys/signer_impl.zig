//! The signer's persistent state (docs/VALIDATOR-DESIGN.md 6.3, 8.2): the exclusive lock file,
//! the two-slot fsynced watermark file and the key material. `signer.zig` holds the rules and the
//! public surface; this file holds everything that touches the disk.
//!
//! Watermark file `<db>/validator/signer/watermarks`: two 128-byte slots written alternately, each
//! `[seq u64][block present u8][epoch u64][round u32][checkpoint present u8][epoch u64][seq u64]
//! [digest 32][pad][crc32 of the first 124 bytes]`. Recovery takes the valid slot with the higher
//! sequence number, so a torn write loses at most the write in flight, which had not signed yet.
//! A signature leaves the signer only after its watermark slot is fdatasync'd.
const std = @import("std");
const Io = std.Io;
const gate = @import("../gate.zig");
const signer = @import("../signer.zig");
const material = @import("material.zig");
const fsutil = @import("fsutil.zig");

pub const slot_len = 128;
const lock_name = "lock";
const wm_name = "watermarks";

pub const State = struct {
    gpa: std.mem.Allocator,
    io: Io,
    lock: fsutil.FileLock,
    file: Io.File,
    seq: u64,
    keys: material.KeySet,
    mutex: Io.Mutex = .init,

    pub fn open(gpa: std.mem.Allocator, io: Io, db_dir: []const u8, keys: material.KeySet, wm: *signer.Watermarks) signer.Error!*State {
        var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
        const dir = std.fmt.bufPrint(&dir_buf, "{s}/validator/signer", .{db_dir}) catch return error.Io;
        fsutil.makePath(io, dir) catch return error.Io;
        var p_buf: [std.fs.max_path_bytes]u8 = undefined;
        const lock_path = std.fmt.bufPrint(&p_buf, "{s}/{s}", .{ dir, lock_name }) catch return error.Io;
        var lock = fsutil.FileLock.acquire(lock_path) catch |e| return switch (e) {
            error.Locked => error.Locked,
            error.Io => error.Io,
        };
        errdefer lock.release();
        const wm_path = std.fmt.bufPrint(&p_buf, "{s}/{s}", .{ dir, wm_name }) catch return error.Io;
        const f = Io.Dir.cwd().createFile(io, wm_path, .{ .read = true, .truncate = false }) catch return error.Io;
        errdefer f.close(io);
        var raw: [2 * slot_len]u8 = @splat(0);
        const n = f.readPositionalAll(io, &raw, 0) catch return error.Io;
        _ = n;
        var best: ?struct { seq: u64, w: signer.Watermarks } = null;
        for (0..2) |i| {
            if (decodeSlot(raw[i * slot_len ..][0..slot_len])) |d| {
                if (best == null or d.seq > best.?.seq) best = .{ .seq = d.seq, .w = d.w };
            }
        }
        const self = gpa.create(State) catch return error.Io;
        self.* = .{ .gpa = gpa, .io = io, .lock = lock, .file = f, .seq = 0, .keys = keys };
        if (best) |b| {
            wm.* = b.w;
            self.seq = b.seq;
        }
        return self;
    }

    pub fn close(self: *State) void {
        self.file.close(self.io);
        self.lock.release();
        std.crypto.secureZero(u8, std.mem.asBytes(&self.keys));
        self.gpa.destroy(self);
    }

    /// Writes the slot for `wm` and fdatasyncs it. Must succeed before any signature is released.
    pub fn persist(self: *State, wm: *const signer.Watermarks) signer.Error!void {
        var slot: [slot_len]u8 = undefined;
        self.seq += 1;
        encodeSlot(&slot, self.seq, wm);
        self.file.writePositionalAll(self.io, &slot, (self.seq & 1) * slot_len) catch return error.Io;
        self.file.sync(self.io) catch return error.Io;
    }
};

pub fn encodeSlot(out: *[slot_len]u8, seq: u64, w: *const signer.Watermarks) void {
    @memset(out, 0);
    std.mem.writeInt(u64, out[0..8], seq, .little);
    if (w.block) |b| {
        out[8] = 1;
        std.mem.writeInt(u64, out[9..17], b.epoch, .little);
        std.mem.writeInt(u32, out[17..21], b.round, .little);
    }
    if (w.checkpoint) |c| {
        out[21] = 1;
        std.mem.writeInt(u64, out[22..30], c.epoch, .little);
        std.mem.writeInt(u64, out[30..38], c.seq, .little);
        out[38..70].* = c.digest;
    }
    std.mem.writeInt(u32, out[124..128], std.hash.Crc32.hash(out[0..124]), .little);
}

pub fn decodeSlot(b: *const [slot_len]u8) ?struct { seq: u64, w: signer.Watermarks } {
    if (std.hash.Crc32.hash(b[0..124]) != std.mem.readInt(u32, b[124..128], .little)) return null;
    const seq = std.mem.readInt(u64, b[0..8], .little);
    if (seq == 0) return null;
    var w: signer.Watermarks = .{};
    if (b[8] == 1) w.block = .{ .epoch = std.mem.readInt(u64, b[9..17], .little), .round = std.mem.readInt(u32, b[17..21], .little) };
    if (b[21] == 1) w.checkpoint = .{ .epoch = std.mem.readInt(u64, b[22..30], .little), .seq = std.mem.readInt(u64, b[30..38], .little), .digest = b[38..70].* };
    return .{ .seq = seq, .w = w };
}

test "slot round trip and torn slot rejected" {
    var w: signer.Watermarks = .{};
    w.recordBlock(3, 77);
    const d: [32]u8 = @splat(5);
    w.recordCheckpoint(3, 900, &d);
    var s: [slot_len]u8 = undefined;
    encodeSlot(&s, 42, &w);
    const got = decodeSlot(&s).?;
    try std.testing.expectEqual(@as(u64, 42), got.seq);
    try std.testing.expectEqual(@as(u32, 77), got.w.block.?.round);
    try std.testing.expectEqual(@as(u64, 900), got.w.checkpoint.?.seq);
    s[10] ^= 1;
    try std.testing.expect(decodeSlot(&s) == null);
}
