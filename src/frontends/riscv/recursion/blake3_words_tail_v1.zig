//! Exact ORIGINAL Frame.words chunk geometry. No replacement transcript recipe.
//! The reusable input commitment is a distinct typed public statement; its fixed
//! incoming state provides domain separation while preserving original framing.
const std = @import("std");
const core = @import("stwo_core");
const Frame = core.channel.blake3.framing.Frame;
const Compression = core.crypto.blake3_compression;
pub const VERSION: u32 = 1;
pub const TAG: u32 = 0x42355449; // B5TI; never the B5WM/v1 input-root type.
pub const HEADER_BYTES: usize = core.channel.blake3.framing.PROTOCOL_ID.len + 1 + 32 + 8;
pub const FIRST_INPUT_BYTES: usize = 1024 - HEADER_BYTES;
pub const DOMAIN_LABEL = "stwo-zig/block-v5/original-words-tail-input/v1\x00";
pub const DOMAIN_STATE: [32]u8 = blk: {
    @setEvalBranchQuota(20000);
    // One-block plain BLAKE3 hash; runtime std BLAKE3 independently checks it.
    // Avoid the std streaming implementation's comptime integer narrowing.
    if (DOMAIN_LABEL.len > 64) @compileError("tail domain requires a new chunk encoder");
    var bytes: [64]u8 = @splat(0);
    @memcpy(bytes[0..DOMAIN_LABEL.len], DOMAIN_LABEL);
    var block: [16]u32 = undefined;
    for (&block, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    const output = Compression.compress(Compression.IV, block, 0, DOMAIN_LABEL.len, 1 | 2 | 8) catch unreachable;
    break :blk digest(output[0..8].*);
};
comptime {
    if (HEADER_BYTES != 68 or FIRST_INPUT_BYTES != 956) @compileError("original words framing changed");
}
pub const Range = struct { first: usize, count: usize };
pub const Geometry = struct {
    words: usize,
    frame_bytes: usize,
    chunks: usize,
    /// Inner-to-outer right siblings of the exact chunk-zero path. These are
    /// disjoint, cover [1,chunks), and retain the original absolute counters.
    ranges: [@bitSizeOf(usize)]Range = undefined,
    range_count: usize = 0,
    pub fn init(words: usize) !Geometry {
        const payload = std.math.mul(usize, 4, words) catch return error.Blake3TailExtentOverflow;
        const frame_bytes = std.math.add(usize, HEADER_BYTES, payload) catch return error.Blake3TailExtentOverflow;
        const chunks = frame_bytes / 1024 + @intFromBool(frame_bytes % 1024 != 0);
        var result = Geometry{ .words = words, .frame_bytes = frame_bytes, .chunks = chunks };
        try result.path(chunks);
        return result;
    }
    fn path(self: *Geometry, count: usize) !void {
        if (count == 1) return;
        const left = @as(usize, 1) << @intCast(std.math.log2_int(usize, count - 1));
        try self.path(left);
        if (self.range_count == self.ranges.len) return error.Blake3TailExtentOverflow;
        self.ranges[self.range_count] = .{ .first = left, .count = count - left };
        self.range_count += 1;
    }
    pub fn frontier(self: *const Geometry) []const Range {
        return self.ranges[0..self.range_count];
    }
    pub fn require(self: *const Geometry, independent_words: usize) !void {
        const wanted = try init(independent_words);
        if (self.words != wanted.words or self.frame_bytes != wanted.frame_bytes or self.chunks != wanted.chunks or self.range_count != wanted.range_count) return error.UntrustedBlake3TailGeometry;
        for (self.frontier(), wanted.frontier()) |actual, expected| if (!std.meta.eql(actual, expected)) return error.UntrustedBlake3TailGeometry;
    }
};

/// Only the 68-byte original header is captured. The immutable payload is
/// borrowed; extracting a chunk never allocates or serializes the whole input.
pub const WordsView = struct {
    header: [HEADER_BYTES]u8,
    words: []const u32,
    length: usize,
    pub fn init(state: [32]u8, words: []const u32) !WordsView {
        const frame = Frame{ .words = .{ .state = state, .values = words } };
        var sink = Header{};
        frame.write(&sink);
        if (sink.total != try frame.encodedSize() or sink.total < HEADER_BYTES) return error.InvalidBlake3TailFrame;
        return .{ .header = sink.bytes, .words = words, .length = sink.total };
    }
    pub fn read(self: *const WordsView, offset: usize, destination: []u8) !void {
        if (offset > self.length or destination.len > self.length - offset) return error.InvalidBlake3TailExtent;
        for (destination, 0..) |*byte, i| {
            const position = offset + i;
            byte.* = if (position < HEADER_BYTES) self.header[position] else blk: {
                const raw = position - HEADER_BYTES;
                break :blk @truncate(self.words[raw / 4] >> @as(u5, @intCast(8 * (raw % 4))));
            };
        }
    }
};
const Header = struct {
    bytes: [HEADER_BYTES]u8 = undefined,
    total: usize = 0,
    pub fn update(self: *Header, value: []const u8) void {
        if (self.total < self.bytes.len) {
            const count = @min(value.len, self.bytes.len - self.total);
            @memcpy(self.bytes[self.total..][0..count], value[0..count]);
        }
        self.total += value.len;
    }
};
pub fn chunk(view: *const WordsView, index: usize, root: bool) ![8]u32 {
    const first = std.math.mul(usize, index, 1024) catch return error.InvalidBlake3TailExtent;
    if (first >= view.length) return error.InvalidBlake3TailExtent;
    const length = @min(1024, view.length - first);
    const blocks = length / 64 + @intFromBool(length % 64 != 0);
    var cv = Compression.IV;
    for (0..blocks) |i| {
        const len = @min(64, length - i * 64);
        var bytes: [64]u8 = @splat(0);
        try view.read(first + i * 64, bytes[0..len]);
        var block: [16]u32 = undefined;
        for (&block, 0..) |*word, j| word.* = std.mem.readInt(u32, bytes[4 * j ..][0..4], .little);
        const last = i + 1 == blocks;
        const flags: u32 = (if (i == 0) @as(u32, 1) else 0) | (if (last) @as(u32, 2) else 0) | (if (root and last) @as(u32, 8) else 0);
        const out = try Compression.compress(cv, block, @intCast(index), @intCast(len), flags);
        cv = out[0..8].*;
    }
    return cv;
}
pub fn subtree(view: *const WordsView, range: Range) anyerror![8]u32 {
    const geometry = try Geometry.init(view.words.len);
    if (range.count == 0 or range.first >= geometry.chunks or range.count > geometry.chunks - range.first) return error.InvalidBlake3TailExtent;
    if (range.count == 1) return chunk(view, range.first, false);
    const left_count = @as(usize, 1) << @intCast(std.math.log2_int(usize, range.count - 1));
    const left = try subtree(view, .{ .first = range.first, .count = left_count });
    const right = try subtree(view, .{ .first = range.first + left_count, .count = range.count - left_count });
    return parent(left, right, false);
}
pub fn parent(left: [8]u32, right: [8]u32, root: bool) ![8]u32 {
    const out = try Compression.compress(Compression.IV, left ++ right, 0, 64, 4 | (if (root) @as(u32, 8) else 0));
    return out[0..8].*;
}
pub fn digest(words: [8]u32) [32]u8 {
    var bytes: [32]u8 = undefined;
    for (words, 0..) |word, i| std.mem.writeInt(u32, bytes[4 * i ..][0..4], word, .little);
    return bytes;
}
/// Scalar oracle only. Neither these values nor this object authorize a proof.
pub const ScalarTail = struct {
    allocator: std.mem.Allocator,
    geometry: Geometry,
    cvs: [][8]u32,
    pub fn init(a: std.mem.Allocator, words: []const u32) !ScalarTail {
        const geometry = try Geometry.init(words.len);
        const view = try WordsView.init(DOMAIN_STATE, words);
        const cvs = try a.alloc([8]u32, geometry.range_count);
        errdefer a.free(cvs);
        for (cvs, geometry.frontier()) |*cv, range| cv.* = try subtree(&view, range);
        return .{ .allocator = a, .geometry = geometry, .cvs = cvs };
    }
    pub fn deinit(self: *ScalarTail) void {
        self.allocator.free(self.cvs);
        self.* = undefined;
    }
    pub fn fold(self: *const ScalarTail, state: [32]u8, words: []const u32) ![32]u8 {
        try self.geometry.require(words.len);
        if (self.cvs.len != self.geometry.range_count) return error.UntrustedBlake3TailGeometry;
        const view = try WordsView.init(state, words);
        var cv = try chunk(&view, 0, self.cvs.len == 0);
        for (self.cvs, 0..) |right, i| cv = try parent(cv, right, i + 1 == self.cvs.len);
        return digest(cv);
    }
};
