//! zstd compressor (RFC 8878): gRPC response messages (serve h2) and compressed store segment
//! chunks (chunk.zig).
//!
//! LZ77 with a hash-chain match finder (4-byte minimum match, greedy with one step of lazy
//! evaluation), sequences entropy-coded with the predefined FSE distributions, literals raw.
//! `compressWith(.{ .huffman = true })` Huffman-codes literals (4 streams, code lengths limited
//! to 11, weights FSE-coded with one fixed table) when smaller than raw. Off by default: on the
//! store's segments it gained 0.1-0.2% (the literals are mostly ids and digests) while
//! std.compress.zstd decoded those chunks ~10x slower (runner box 1, 2026-11-08). No dictionaries, no checksum. Each 128 KiB block is emitted compressed only when that is
//! smaller than the raw block. Frames up to 8 MiB are single-segment (window = content size,
//! content size in the header); larger ones declare an 8 MiB window, so every decoder with the
//! common 8 MiB limit (libzstd's default is 128 MiB, Zig std 8 MiB) accepts them.
//! Protobuf responses repeat addresses, type tags and field keys, which this captures; sui-node's
//! level 3 adds Huffman literals and adaptive FSE tables (a few percent more on top).
const std = @import("std");
const Allocator = std.mem.Allocator;

const block_max = 128 * 1024;
const single_segment_max = 8 << 20;
const window_log_large = 23;
const min_match = 4;
const max_offset = (1 << 22) - 1;
const hash_log = 16;
const chain_depth = 12;
const good_len = 64;

// ---------------------------------------------------------------- predefined FSE tables

const ll_norm = [_]i16{ 4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1 };
const ml_norm = [_]i16{ 1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1 };
const of_norm = [_]i16{ 1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1 };

const ll_base = [_]u32{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536 };
const ll_bits = [_]u5{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
const ml_base = [_]u32{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539 };
const ml_bits = [_]u5{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

/// FSE compression table (zstd's FSE_buildCTable): the state table and, per symbol, the
/// (deltaNbBits, deltaFindState) pair.
fn CTable(comptime norm: []const i16, comptime log: u5) type {
    return struct {
        const size = 1 << log;
        state: [size]u16,
        delta_nb_bits: [norm.len]i64,
        delta_find: [norm.len]i64,

        fn build() @This() {
            @setEvalBranchQuota(100_000);
            var t: @This() = undefined;
            var symbol_at: [size]u8 = undefined;
            var cumul: [norm.len + 1]u32 = undefined;
            var high: u32 = size - 1;
            cumul[0] = 0;
            for (norm, 0..) |n, s| {
                if (n == -1) {
                    cumul[s + 1] = cumul[s] + 1;
                    symbol_at[high] = @intCast(s);
                    high -%= 1;
                } else cumul[s + 1] = cumul[s] + @as(u32, @intCast(n));
            }
            const step = (size >> 1) + (size >> 3) + 3;
            const mask = size - 1;
            var pos: u32 = 0;
            for (norm, 0..) |n, s| {
                var i: i32 = 0;
                while (i < n) : (i += 1) {
                    symbol_at[pos] = @intCast(s);
                    pos = (pos + step) & mask;
                    while (pos > high) pos = (pos + step) & mask;
                }
            }
            std.debug.assert(pos == 0);
            var next = cumul;
            for (0..size) |u| {
                const s = symbol_at[u];
                t.state[next[s]] = @intCast(size + u);
                next[s] += 1;
            }
            var total: i64 = 0;
            for (norm, 0..) |n, s| switch (n) {
                0 => {
                    t.delta_nb_bits[s] = ((@as(i64, log) + 1) << 16) - size;
                    t.delta_find[s] = 0;
                },
                -1, 1 => {
                    t.delta_nb_bits[s] = (@as(i64, log) << 16) - size;
                    t.delta_find[s] = total - 1;
                    total += 1;
                },
                else => {
                    const c: u32 = @intCast(n);
                    const max_bits_out: i64 = @as(i64, log) - std.math.log2_int(u32, c - 1);
                    const min_state_plus: i64 = @as(i64, c) << @intCast(max_bits_out);
                    t.delta_nb_bits[s] = (max_bits_out << 16) - min_state_plus;
                    t.delta_find[s] = total - c;
                    total += c;
                },
            };
            return t;
        }

        fn init(t: *const @This(), sym: u8) u32 {
            const nb: i64 = (t.delta_nb_bits[sym] + (1 << 15)) >> 16;
            const v: i64 = (nb << 16) - t.delta_nb_bits[sym];
            return t.state[@intCast((v >> @intCast(nb)) + t.delta_find[sym])];
        }

        fn encode(t: *const @This(), bw: *BitWriter, state: *u32, sym: u8) void {
            const nb: u5 = @intCast((@as(i64, state.*) + t.delta_nb_bits[sym]) >> 16);
            bw.add(state.*, nb);
            state.* = t.state[@intCast((@as(i64, state.*) >> nb) + t.delta_find[sym])];
        }

        fn flush(_: *const @This(), bw: *BitWriter, state: u32) void {
            bw.add(state, log);
        }
    };
}

const LLTable = CTable(&ll_norm, 6);
const MLTable = CTable(&ml_norm, 6);
const OFTable = CTable(&of_norm, 5);
const ll_table: LLTable = LLTable.build();
const ml_table: MLTable = MLTable.build();
const of_table: OFTable = OFTable.build();

const BitWriter = struct {
    out: *std.ArrayList(u8),
    gpa: Allocator,
    acc: u64 = 0,
    n: u6 = 0,
    err: bool = false,

    fn add(w: *BitWriter, value: u64, bits: u5) void {
        if (bits == 0) return;
        const mask = (@as(u64, 1) << bits) - 1;
        w.acc |= (value & mask) << w.n;
        w.n += bits;
        while (w.n >= 8) {
            w.out.append(w.gpa, @truncate(w.acc)) catch {
                w.err = true;
            };
            w.acc >>= 8;
            w.n -= 8;
        }
    }

    fn close(w: *BitWriter) void {
        w.add(1, 1);
        if (w.n > 0) {
            w.out.append(w.gpa, @truncate(w.acc)) catch {
                w.err = true;
            };
            w.acc = 0;
            w.n = 0;
        }
    }
};

fn llCode(ll: u32) u8 {
    if (ll < 16) return @intCast(ll);
    if (ll < 64) {
        var c: u8 = 16;
        while (c + 1 < ll_base.len and ll_base[c + 1] <= ll) c += 1;
        return c;
    }
    return @intCast(@as(u32, std.math.log2_int(u32, ll)) + 19);
}

fn mlCode(ml: u32) u8 {
    if (ml < 35) return @intCast(ml - 3);
    if (ml < 131) {
        var c: u8 = 32;
        while (c + 1 < ml_base.len and ml_base[c + 1] <= ml) c += 1;
        return c;
    }
    return @intCast(@as(u32, std.math.log2_int(u32, ml - 3)) + 36);
}

const Seq = struct { lit_len: u32, match_len: u32, offset: u32 };

// ---------------------------------------------------------------- match finder

const Matcher = struct {
    src: []const u8,
    head: []u32,
    chain: []u32,

    fn hash(p: []const u8) u32 {
        const v = std.mem.readInt(u32, p[0..4], .little);
        return (v *% 2654435761) >> (32 - hash_log);
    }

    fn insert(m: *Matcher, pos: usize) void {
        if (pos + 4 > m.src.len) return;
        const h = hash(m.src[pos..]);
        m.chain[pos] = m.head[h];
        m.head[h] = @intCast(pos + 1);
    }

    /// Longest match for `pos` ending at or before `limit`.
    fn find(m: *const Matcher, pos: usize, limit: usize) struct { len: u32, off: u32 } {
        if (pos + min_match > limit) return .{ .len = 0, .off = 0 };
        const src = m.src;
        var best_len: usize = 0;
        var best_off: usize = 0;
        var cand = m.head[hash(src[pos..])];
        var depth: u32 = 0;
        const max_l = limit - pos;
        while (cand != 0 and depth < chain_depth) : (depth += 1) {
            const c: usize = cand - 1;
            if (c >= pos) break;
            const off = pos - c;
            if (off > max_offset) break;
            if (src[c + best_len] == src[pos + best_len] or best_len == 0) {
                var l: usize = 0;
                while (l + 8 <= max_l and std.mem.readInt(u64, src[c + l ..][0..8], .little) == std.mem.readInt(u64, src[pos + l ..][0..8], .little)) l += 8;
                while (l < max_l and src[c + l] == src[pos + l]) l += 1;
                if (l > best_len) {
                    best_len = l;
                    best_off = off;
                    if (l >= good_len or l == max_l) break;
                }
            }
            cand = m.chain[c];
        }
        if (best_len < min_match) return .{ .len = 0, .off = 0 };
        return .{ .len = @intCast(best_len), .off = @intCast(best_off) };
    }
};

// ---------------------------------------------------------------- frame

pub const Options = struct {
    huffman: bool = false,
};

/// A zstd frame holding `src` (caller frees).
pub fn compress(gpa: Allocator, src: []const u8) ![]u8 {
    return compressWith(gpa, src, .{});
}

pub fn compressWith(gpa: Allocator, src: []const u8, opts: Options) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.ensureTotalCapacity(gpa, 16 + src.len / 2);
    try frameHeader(&out, gpa, src.len);
    if (src.len == 0) {
        // one empty raw block
        try out.appendSlice(gpa, &.{ 1, 0, 0 });
        return out.toOwnedSlice(gpa);
    }
    const head = try gpa.alloc(u32, 1 << hash_log);
    defer gpa.free(head);
    @memset(head, 0);
    const chain = try gpa.alloc(u32, src.len);
    defer gpa.free(chain);
    var m: Matcher = .{ .src = src, .head = head, .chain = chain };

    var lits: std.ArrayList(u8) = .empty;
    defer lits.deinit(gpa);
    var seqs: std.ArrayList(Seq) = .empty;
    defer seqs.deinit(gpa);
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);

    var bs: usize = 0;
    while (bs < src.len) {
        const be = @min(src.len, bs + block_max);
        const last = be == src.len;
        lits.clearRetainingCapacity();
        seqs.clearRetainingCapacity();
        // parse the block
        var pos = bs;
        var anchor = bs;
        while (pos < be) {
            var mt = m.find(pos, be);
            if (mt.len == 0) {
                m.insert(pos);
                pos += 1;
                continue;
            }
            // one step of lazy evaluation: a longer match at the next byte wins
            m.insert(pos);
            if (pos + 1 < be) {
                const nx = m.find(pos + 1, be);
                if (nx.len > mt.len + 1) {
                    pos += 1;
                    mt = nx;
                    m.insert(pos);
                }
            }
            try lits.appendSlice(gpa, src[anchor..pos]);
            try seqs.append(gpa, .{ .lit_len = @intCast(pos - anchor), .match_len = mt.len, .offset = mt.off });
            const end = pos + mt.len;
            var q = pos + 1;
            while (q < end) : (q += 1) m.insert(q);
            pos = end;
            anchor = end;
        }
        try lits.appendSlice(gpa, src[anchor..be]);

        body.clearRetainingCapacity();
        const ok = encodeBlock(gpa, &body, lits.items, seqs.items, opts.huffman) catch false;
        const raw_len = be - bs;
        if (ok and body.items.len < raw_len) {
            try blockHeader(&out, gpa, last, 2, body.items.len);
            try out.appendSlice(gpa, body.items);
        } else {
            try blockHeader(&out, gpa, last, 0, raw_len);
            try out.appendSlice(gpa, src[bs..be]);
        }
        bs = be;
    }
    return out.toOwnedSlice(gpa);
}

fn frameHeader(out: *std.ArrayList(u8), gpa: Allocator, n: usize) !void {
    try out.appendSlice(gpa, &.{ 0x28, 0xb5, 0x2f, 0xfd });
    if (n <= single_segment_max) {
        const fcs_len: usize, const flag: u8 = if (n < 256) .{ 1, 0 } else if (n < 65536 + 256) .{ 2, 1 } else .{ 4, 2 };
        try out.append(gpa, (flag << 6) | (1 << 5));
        var b: [4]u8 = undefined;
        switch (fcs_len) {
            1 => try out.append(gpa, @intCast(n)),
            2 => {
                std.mem.writeInt(u16, b[0..2], @intCast(n - 256), .little);
                try out.appendSlice(gpa, b[0..2]);
            },
            else => {
                std.mem.writeInt(u32, &b, @intCast(n), .little);
                try out.appendSlice(gpa, &b);
            },
        }
    } else {
        // window descriptor (8 MiB) and an 8-byte content size
        try out.append(gpa, 3 << 6);
        try out.append(gpa, (window_log_large - 10) << 3);
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, n, .little);
        try out.appendSlice(gpa, &b);
    }
}

fn blockHeader(out: *std.ArrayList(u8), gpa: Allocator, last: bool, kind: u32, size: usize) !void {
    const h: u32 = @as(u32, @intFromBool(last)) | (kind << 1) | (@as(u32, @intCast(size)) << 3);
    try out.appendSlice(gpa, &.{ @truncate(h), @truncate(h >> 8), @truncate(h >> 16) });
}

/// Literals section (raw) and sequences section (predefined FSE modes). False when the block
/// does not fit the format (then it goes raw).
fn encodeBlock(gpa: Allocator, out: *std.ArrayList(u8), lits: []const u8, seqs: []const Seq, huffman: bool) !bool {
    const n = lits.len;
    const huffed = huffman and try huffLiterals(gpa, out, lits);
    if (huffed) {
        // Compressed_Literals_Block written
    } else if (n < 32) {
        try out.append(gpa, @intCast(n << 3));
    } else if (n < 4096) {
        try out.appendSlice(gpa, &.{ @intCast(((n & 0xf) << 4) | (1 << 2)), @intCast(n >> 4) });
    } else if (n < (1 << 20)) {
        try out.appendSlice(gpa, &.{ @intCast(((n & 0xf) << 4) | (3 << 2)), @intCast((n >> 4) & 0xff), @intCast(n >> 12) });
    } else return false;
    if (!huffed) try out.appendSlice(gpa, lits);
    // Number_of_Sequences
    const ns = seqs.len;
    if (ns < 128) {
        try out.append(gpa, @intCast(ns));
    } else if (ns < 0x7f00) {
        try out.appendSlice(gpa, &.{ @intCast((ns >> 8) + 128), @intCast(ns & 0xff) });
    } else {
        const v = ns - 0x7f00;
        try out.appendSlice(gpa, &.{ 255, @intCast(v & 0xff), @intCast(v >> 8) });
    }
    if (ns == 0) return true;
    try out.append(gpa, 0); // LL, OF, ML: Predefined_Mode
    var bw: BitWriter = .{ .out = out, .gpa = gpa };
    const lastq = seqs[ns - 1];
    const ll_c = llCode(lastq.lit_len);
    const ml_c = mlCode(lastq.match_len);
    const off_base: u32 = lastq.offset + 3;
    const of_c: u8 = std.math.log2_int(u32, off_base);
    var st_ml = ml_table.init(ml_c);
    var st_of = of_table.init(of_c);
    var st_ll = ll_table.init(ll_c);
    bw.add(lastq.lit_len - ll_base[ll_c], ll_bits[ll_c]);
    bw.add(lastq.match_len - ml_base[ml_c], ml_bits[ml_c]);
    bw.add(off_base, @intCast(of_c));
    var i = ns - 1;
    while (i > 0) {
        i -= 1;
        const q = seqs[i];
        const lc = llCode(q.lit_len);
        const mc = mlCode(q.match_len);
        const ob: u32 = q.offset + 3;
        const oc: u8 = std.math.log2_int(u32, ob);
        of_table.encode(&bw, &st_of, oc);
        ml_table.encode(&bw, &st_ml, mc);
        ll_table.encode(&bw, &st_ll, lc);
        bw.add(q.lit_len - ll_base[lc], ll_bits[lc]);
        bw.add(q.match_len - ml_base[mc], ml_bits[mc]);
        bw.add(ob, @intCast(oc));
    }
    ml_table.flush(&bw, st_ml);
    of_table.flush(&bw, st_of);
    ll_table.flush(&bw, st_ll);
    bw.close();
    if (bw.err) return error.OutOfMemory;
    return true;
}

// ---------------------------------------------------------------- Huffman literals

const huf_max_bits = 11;

/// Weight alphabet 0..11, accuracy log 6: one fixed distribution for every tree description
/// (any distribution is legal as long as every weight that occurs has a nonzero count).
const wt_norm = [12]i16{ 12, 6, 6, 6, 6, 6, 6, 5, 4, 3, 2, 2 };
const WTable = CTable(&wt_norm, 6);
const wt_table: WTable = WTable.build();

/// FSE_writeNCount of `wt_norm` (the table description in front of the weight bitstream).
fn wtHeader(gpa: Allocator, out: *std.ArrayList(u8)) !void {
    var bw: BitWriter = .{ .out = out, .gpa = gpa };
    const log = 6;
    const size: i32 = 1 << log;
    bw.add(log - 5, 4);
    var remaining: i32 = size + 1;
    var threshold: i32 = size;
    var nb: u5 = log + 1;
    for (wt_norm) |c0| {
        if (remaining <= 1) break;
        var count: i32 = c0;
        const max: i32 = (2 * threshold - 1) - remaining;
        remaining -= if (count < 0) -count else count;
        count += 1;
        if (count >= threshold) count += max;
        bw.add(@intCast(count), if (count < max) nb - 1 else nb);
        while (remaining < threshold) {
            nb -= 1;
            threshold >>= 1;
        }
    }
    std.debug.assert(remaining == 1);
    // flush to a byte boundary (no end marker: the header is read forward)
    if (bw.n > 0) {
        try out.append(gpa, @truncate(bw.acc));
        bw.acc = 0;
        bw.n = 0;
    }
    if (bw.err) return error.OutOfMemory;
}

/// Huffman code lengths (at most 11 bits, a complete prefix code) for the symbols with a nonzero
/// count. Returns the longest length, 0 when fewer than two symbols occur.
fn hufLengths(freq: *const [256]u32, lens: *[256]u8) u8 {
    @memset(lens, 0);
    var syms: [256]u8 = undefined;
    var n: usize = 0;
    for (freq, 0..) |f, i| if (f > 0) {
        syms[n] = @intCast(i);
        n += 1;
    };
    if (n < 2) return 0;
    const S = struct {
        fn lt(fr: *const [256]u32, a: u8, b: u8) bool {
            return fr[a] < fr[b] or (fr[a] == fr[b] and a < b);
        }
    };
    std.mem.sort(u8, syms[0..n], freq, S.lt);
    // Two-queue Huffman: leaves 0..n-1 (sorted), internal nodes n.. in creation order.
    var w: [512]u64 = undefined;
    var parent: [512]u16 = undefined;
    for (0..n) |i| w[i] = freq[syms[i]];
    var li: usize = 0;
    var ni: usize = n;
    var next: usize = n;
    while (next < 2 * n - 1) : (next += 1) {
        var pick: [2]usize = undefined;
        for (&pick) |*p| {
            if (li < n and (ni >= next or w[li] <= w[ni])) {
                p.* = li;
                li += 1;
            } else {
                p.* = ni;
                ni += 1;
            }
        }
        w[next] = w[pick[0]] + w[pick[1]];
        parent[pick[0]] = @intCast(next);
        parent[pick[1]] = @intCast(next);
    }
    var depth: [512]u8 = undefined;
    depth[2 * n - 2] = 0;
    var k: usize = 2 * n - 2;
    while (k > 0) {
        k -= 1;
        depth[k] = depth[parent[k]] + 1;
    }
    // Limit to 11 bits and repair the Kraft sum to exactly 2^11 (units of 2^-11).
    var kraft: i64 = 0;
    for (0..n) |i| {
        const d = @min(depth[i], huf_max_bits);
        lens[syms[i]] = d;
        kraft += @as(i64, 1) << @intCast(huf_max_bits - d);
    }
    const full: i64 = 1 << huf_max_bits;
    // Over-full: lengthen the rarest codes shorter than 11 (syms is in rising frequency).
    while (kraft > full) {
        var best: ?usize = null;
        for (0..n) |i| {
            const l = lens[syms[i]];
            if (l < huf_max_bits and (best == null or l > lens[syms[best.?]])) best = i;
        }
        const s0 = syms[best.?];
        kraft -= @as(i64, 1) << @intCast(huf_max_bits - lens[s0] - 1);
        lens[s0] += 1;
    }
    // Under-full: shorten the most frequent codes whose gain fits the deficit.
    while (kraft < full) {
        var i: usize = n;
        while (i > 0) {
            i -= 1;
            const s0 = syms[i];
            const gain = @as(i64, 1) << @intCast(huf_max_bits - lens[s0]);
            if (lens[s0] > 1 and kraft + gain <= full) {
                lens[s0] -= 1;
                kraft += gain;
                break;
            }
        } else unreachable;
    }
    var maxl: u8 = 0;
    for (lens) |l| maxl = @max(maxl, l);
    return maxl;
}

/// Writes a Compressed_Literals_Block (header, tree description, jump table, 4 streams) when it
/// is smaller than the raw one. False (nothing written) otherwise.
fn huffLiterals(gpa: Allocator, out: *std.ArrayList(u8), lits: []const u8) !bool {
    const n = lits.len;
    if (n < 256 or n > (1 << 18) - 1) return false;
    var freq: [256]u32 = @splat(0);
    for (lits) |b| freq[b] += 1;
    var lens: [256]u8 = undefined;
    const maxl = hufLengths(&freq, &lens);
    if (maxl == 0) return false;
    // Estimated stream bits: give up early when Huffman cannot win.
    var bits: u64 = 0;
    for (freq, lens) |f, l| bits += @as(u64, f) * l;
    if (bits / 8 + 64 >= n) return false;

    var last: usize = 0;
    for (lens, 0..) |l, i| if (l > 0) {
        last = i;
    };
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    // Tree description: weights of symbols 0..last-1 (last's is implied).
    var wts: [256]u8 = undefined;
    for (0..last) |i| wts[i] = if (lens[i] == 0) 0 else maxl + 1 - lens[i];
    const nw = last;
    if (nw <= 128) {
        try body.append(gpa, @intCast(127 + nw));
        var i: usize = 0;
        while (i < nw) : (i += 2) {
            const hi = wts[i];
            const lo: u8 = if (i + 1 < nw) wts[i + 1] else 0;
            try body.append(gpa, (hi << 4) | lo);
        }
    } else {
        try body.append(gpa, 0); // compressed size, patched below
        const at = body.items.len;
        try wtHeader(gpa, &body);
        // Two interleaved states (even, odd indices); bits are read in reverse of writing.
        var bw: BitWriter = .{ .out = &body, .gpa = gpa };
        const e_last = if ((nw - 1) % 2 == 0) nw - 1 else nw - 2;
        const o_last = if ((nw - 1) % 2 == 1) nw - 1 else nw - 2;
        var st_e = wt_table.init(wts[e_last]);
        var st_o = wt_table.init(wts[o_last]);
        var i: usize = nw - 2;
        while (i > 0) {
            i -= 1;
            if (i % 2 == 0) wt_table.encode(&bw, &st_e, wts[i]) else wt_table.encode(&bw, &st_o, wts[i]);
        }
        wt_table.flush(&bw, st_o);
        wt_table.flush(&bw, st_e);
        bw.close();
        if (bw.err) return error.OutOfMemory;
        const csz = body.items.len - at;
        if (csz >= 128) return false;
        body.items[at - 1] = @intCast(csz);
    }
    // Codes (zstd order: longest codes first, rising symbol within a length).
    var code: [256]u16 = @splat(0);
    {
        var c: u32 = 0;
        var l: u8 = maxl;
        while (l >= 1) : (l -= 1) {
            for (0..256) |sym| if (lens[sym] == l) {
                code[sym] = @intCast(c);
                c += 1;
            };
            c >>= 1;
        }
    }
    // Four streams, each written last literal first.
    const seg = (n + 3) / 4;
    const jt = body.items.len;
    try body.appendNTimes(gpa, 0, 6);
    var sizes: [4]usize = undefined;
    for (0..4) |k| {
        const from = @min(n, k * seg);
        const to = if (k == 3) n else @min(n, (k + 1) * seg);
        const before = body.items.len;
        var bw: BitWriter = .{ .out = &body, .gpa = gpa };
        var j = to;
        while (j > from) {
            j -= 1;
            const b = lits[j];
            bw.add(code[b], @intCast(lens[b]));
        }
        bw.close();
        if (bw.err) return error.OutOfMemory;
        sizes[k] = body.items.len - before;
    }
    for (0..3) |k| {
        if (sizes[k] > 0xffff) return false;
        std.mem.writeInt(u16, body.items[jt + 2 * k ..][0..2], @intCast(sizes[k]), .little);
    }
    const c = body.items.len;
    const hdr_len: usize = if (n < 1024 and c < 1024) 3 else if (n < 16384 and c < 16384) 4 else 5;
    if (c > (1 << 18) - 1 or c + hdr_len >= n + 3) return false;
    const r: u32 = @intCast(n);
    const cs: u32 = @intCast(c);
    switch (hdr_len) {
        3 => try out.appendSlice(gpa, &.{ @intCast(2 | (1 << 2) | ((r & 0xf) << 4)), @intCast(((r >> 4) & 0x3f) | ((cs & 3) << 6)), @intCast(cs >> 2) }),
        4 => try out.appendSlice(gpa, &.{ @intCast(2 | (2 << 2) | ((r & 0xf) << 4)), @intCast((r >> 4) & 0xff), @intCast(((r >> 12) & 3) | ((cs & 0x3f) << 2)), @intCast(cs >> 6) }),
        else => try out.appendSlice(gpa, &.{ @intCast(2 | (3 << 2) | ((r & 0xf) << 4)), @intCast((r >> 4) & 0xff), @intCast(((r >> 12) & 0x3f) | ((cs & 3) << 6)), @intCast((cs >> 2) & 0xff), @intCast(cs >> 10) }),
    }
    try out.appendSlice(gpa, body.items);
    return true;
}

// ---------------------------------------------------------------- tests

fn roundTrip(src: []const u8) !usize {
    return roundTripWith(src, .{});
}

fn roundTripWith(src: []const u8, opts: Options) !usize {
    const gpa = std.testing.allocator;
    const z = try compressWith(gpa, src, opts);
    defer gpa.free(z);
    var in: std.Io.Reader = .fixed(z);
    const dbuf = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(dbuf);
    var dz: std.compress.zstd.Decompress = .init(&in, dbuf, .{});
    const got = try dz.reader.allocRemaining(gpa, .unlimited);
    defer gpa.free(got);
    try std.testing.expectEqualSlices(u8, src, got);
    return z.len;
}

test "zstd: codes match the tables" {
    var v: u32 = 0;
    while (v < 131_072) : (v += 1) {
        const c = llCode(v);
        try std.testing.expect(ll_base[c] <= v and v - ll_base[c] < (@as(u32, 1) << ll_bits[c]));
    }
    v = 3;
    while (v < 131_000) : (v += 1) {
        const c = mlCode(v);
        try std.testing.expect(ml_base[c] <= v and v - ml_base[c] < (@as(u32, 1) << ml_bits[c]));
    }
}

test "zstd: round trips through std's decoder and compresses repetitive data" {
    const gpa = std.testing.allocator;
    _ = try roundTrip("");
    _ = try roundTrip("a");
    _ = try roundTrip("abcdabcdabcdabcdabcd");
    var prng = std.Random.DefaultPrng.init(7);
    const r = prng.random();
    for ([_]usize{ 5, 255, 256, 300, 4095, 4096, 65535, 65791, 65792, 131072, 131073, 300_000, 1_100_000 }) |n| {
        const buf = try gpa.alloc(u8, n);
        defer gpa.free(buf);
        // protobuf-like: random 32-byte ids repeated, field tags, small varints, some noise
        var ids: [16][32]u8 = undefined;
        for (&ids) |*id| r.bytes(id);
        var i: usize = 0;
        while (i < n) {
            const k = r.uintLessThan(u8, 4);
            switch (k) {
                0 => {
                    const id = &ids[r.uintLessThan(usize, ids.len)];
                    const l = @min(n - i, 34);
                    if (l >= 2) {
                        buf[i] = 0x0a;
                        buf[i + 1] = 32;
                        @memcpy(buf[i + 2 .. i + l], id[0 .. l - 2]);
                    } else @memset(buf[i .. i + l], 0x12);
                    i += l;
                },
                1 => {
                    const l = @min(n - i, r.uintLessThan(usize, 12) + 1);
                    r.bytes(buf[i .. i + l]);
                    i += l;
                },
                else => {
                    const s = "0x2::coin::Coin<0x2::sui::SUI>";
                    const l = @min(n - i, s.len);
                    @memcpy(buf[i .. i + l], s[0..l]);
                    i += l;
                },
            }
        }
        const zl = try roundTrip(buf);
        if (n >= 4096) try std.testing.expect(zl < n * 7 / 10);
        // incompressible input stays within a few bytes of the raw size
        r.bytes(buf);
        const zr = try roundTrip(buf);
        try std.testing.expect(zr <= n + 32 + 3 * (n / block_max + 1));
    }
    // long runs (overlapping matches, offsets of 1)
    const runs = try gpa.alloc(u8, 200_000);
    defer gpa.free(runs);
    @memset(runs, 'x');
    const zl = try roundTrip(runs);
    try std.testing.expect(zl < 2000);
}

test "zstd: frames over 8 MiB declare a window and decode" {
    const gpa = std.testing.allocator;
    const n = (8 << 20) + 1000;
    const buf = try gpa.alloc(u8, n);
    defer gpa.free(buf);
    for (buf, 0..) |*b, i| b.* = @truncate((i / 7) *% 31);
    _ = try roundTrip(buf);
}

test "zstd: Huffman literals (direct and FSE weights, skewed and flat) round trip" {
    var prng: std.Random.DefaultPrng = .init(7);
    const rnd = prng.random();
    const buf = try std.testing.allocator.alloc(u8, 300_000);
    defer std.testing.allocator.free(buf);
    // Skewed bytes over the whole alphabet (FSE-coded weights), no long matches.
    for (buf) |*b| {
        const r = rnd.float(f64);
        b.* = @intFromFloat(@min(255.0, -@log(1.0 - r) * 24.0));
    }
    const z1 = try roundTripWith(buf, .{ .huffman = true });
    try std.testing.expect(z1 < buf.len * 4 / 5);
    // Small alphabet (direct weights), lengths that need the 11-bit limit.
    for (buf, 0..) |*b, i| b.* = if (i % 3000 == 0) @intCast(rnd.int(u7)) else @intCast(rnd.uintLessThan(u8, 3) + 'a');
    _ = try roundTripWith(buf, .{ .huffman = true });
    // Uniform bytes: Huffman must not win, the block goes raw.
    rnd.bytes(buf);
    const z3 = try roundTripWith(buf, .{ .huffman = true });
    try std.testing.expect(z3 <= buf.len + 64);
    // Every size class of the literals header.
    for ([_]usize{ 256, 700, 1023, 1024, 5000, 16383, 16384, 100_000 }) |n| {
        for (buf[0..n]) |*b| b.* = @intCast(@min(255, rnd.uintLessThan(u16, 40) * rnd.uintLessThan(u16, 7)));
        _ = try roundTripWith(buf[0..n], .{ .huffman = true });
    }
}

test "zstd: Huffman code lengths are complete and limited" {
    var freq: [256]u32 = @splat(0);
    // Fibonacci counts force depths far past 11.
    var a: u32 = 1;
    var b: u32 = 1;
    for (0..30) |i| {
        freq[i] = a;
        const c = a +% b;
        a = b;
        b = c;
    }
    var lens: [256]u8 = undefined;
    const m = hufLengths(&freq, &lens);
    try std.testing.expect(m <= huf_max_bits);
    var k: u64 = 0;
    for (lens) |l| if (l > 0) {
        k += @as(u64, 1) << @intCast(huf_max_bits - l);
    };
    try std.testing.expectEqual(@as(u64, 1 << huf_max_bits), k);
}
