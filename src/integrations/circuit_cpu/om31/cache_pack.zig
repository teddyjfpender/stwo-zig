//! Lossless producer-cache encoding. Columns predict their previous u32;
//! fixed-width records predict each field separately. No proof/wire uses it.
const std = @import("std");
pub const Error = error{ CachePackShape, CachePackLength, CachePackOverflow, CachePackNoncanonical, CachePackDecoderUnavailable };
pub const Encoding = enum { raw, delta_varint, lz4_blocks };
pub const BLOCK_WORDS: usize = 16384;
pub fn compressClass(is_leaf: bool) bool {
    if (is_leaf) return true;
    const value = std.posix.getenv("STWO_RV64_PACK_FOLD_CACHE") orelse return false;
    return std.mem.eql(u8, value, "1");
}
pub const Block = struct { offset: usize, bytes: u32, raw: bool };
const Lz4 = struct {
    library: std.DynLib,
    compress: *const fn ([*]const u8, [*]u8, c_int, c_int) callconv(.c) c_int,
    decompress: *const fn ([*]const u8, [*]u8, c_int, c_int) callconv(.c) c_int,
};
var api_mutex: std.Thread.Mutex = .{};
var api_attempted = false;
var api: ?Lz4 = null;
fn native() ?*const Lz4 {
    // This is an optional host-cache accelerator. Portable builds keep the
    // independent varint codec; no verifier, proof or ABI depends on liblz4.
    if (!@import("builtin").link_libc or @import("builtin").os.tag != .linux) return null;
    api_mutex.lock();
    defer api_mutex.unlock();
    if (!api_attempted) {
        api_attempted = true;
        var library = std.DynLib.open("liblz4.so.1") catch return null;
        const compress = library.lookup(@FieldType(Lz4, "compress"), "LZ4_compress_default") orelse {
            library.close();
            return null;
        };
        const decompress = library.lookup(@FieldType(Lz4, "decompress"), "LZ4_decompress_safe") orelse {
            library.close();
            return null;
        };
        api = .{ .library = library, .compress = compress, .decompress = decompress };
    }
    return if (api) |*value| value else null;
}
pub const Packed = struct {
    data: []u8,
    words: usize,
    channels: u8,
    encoding: Encoding,
    blocks: []Block = &.{},
    pub fn heldBytes(self: Packed) usize {
        return self.data.len + self.blocks.len * @sizeOf(Block);
    }
    pub fn workItems(self: Packed) usize {
        return if (self.encoding == .lz4_blocks) self.blocks.len else 1;
    }
    /// Independent blocks write disjoint output records and use bounded stack
    /// scratch. A caller may partition these over its existing work pool.
    pub fn unpackRange(self: Packed, output: []u32, begin: usize, end: usize) Error!void {
        if (self.encoding != .lz4_blocks) {
            if (begin != 0 or end != 1) return error.CachePackShape;
            return self.unpack(output);
        }
        if (output.len != self.words or self.channels == 0 or self.words % self.channels != 0 or BLOCK_WORDS % self.channels != 0) return error.CachePackShape;
        if (self.blocks.len != (self.words + BLOCK_WORDS - 1) / BLOCK_WORDS or begin > end or end > self.blocks.len) return error.CachePackShape;
        const lz4 = native() orelse return error.CachePackDecoderUnavailable;
        var scratch: [BLOCK_WORDS * 4]u8 = undefined;
        for (self.blocks[begin..end], begin..) |block, index| {
            const first = index * BLOCK_WORDS;
            const count: usize = @min(BLOCK_WORDS, self.words - first);
            const bytes = count * 4;
            if (block.offset > self.data.len or block.bytes > self.data.len - block.offset) return error.CachePackLength;
            if (index == 0 and block.offset != 0) return error.CachePackLength;
            if (index > 0 and block.offset != self.blocks[index - 1].offset + self.blocks[index - 1].bytes) return error.CachePackLength;
            if (index + 1 == self.blocks.len and block.offset + block.bytes != self.data.len) return error.CachePackLength;
            const source = self.data[block.offset..][0..block.bytes];
            if (block.raw) {
                if (source.len != bytes) return error.CachePackLength;
                @memcpy(scratch[0..bytes], source);
            } else if (lz4.decompress(source.ptr, &scratch, @intCast(source.len), @intCast(bytes)) != @as(c_int, @intCast(bytes))) return error.CachePackLength;
            const rows = count / self.channels;
            for (0..self.channels) |channel| {
                const field = scratch[channel * rows * 4 ..][0 .. rows * 4];
                var previous: u32 = 0;
                for (0..rows) |row| {
                    const delta = @as(u32, field[row]) | (@as(u32, field[rows + row]) << 8) |
                        (@as(u32, field[2 * rows + row]) << 16) | (@as(u32, field[3 * rows + row]) << 24);
                    previous +%= delta;
                    output[first + row * self.channels + channel] = previous;
                }
            }
        }
    }
    pub fn deinit(self: *Packed, a: std.mem.Allocator) void {
        a.free(self.data);
        a.free(self.blocks);
        self.* = undefined;
    }
    pub fn unpack(self: Packed, output: []u32) Error!void {
        if (output.len != self.words or self.channels == 0 or self.words % self.channels != 0) return error.CachePackShape;
        if (self.encoding == .lz4_blocks) return self.unpackRange(output, 0, self.blocks.len);
        if (self.encoding == .raw) {
            if (self.data.len != output.len * 4) return error.CachePackLength;
            @memcpy(std.mem.sliceAsBytes(output), self.data);
            return;
        }
        var at: usize = 0;
        const rows = self.words / self.channels;
        for (0..self.channels) |column| {
            var previous: u32 = 0;
            for (0..rows) |row| {
                var word: u32 = 0;
                var bytes: usize = 0;
                while (true) {
                    if (at == self.data.len or bytes == 5) return error.CachePackLength;
                    const byte = self.data[at];
                    at += 1;
                    if (bytes == 4 and byte > 15) return error.CachePackOverflow;
                    word |= @as(u32, byte & 0x7f) << @as(u5, @intCast(7 * bytes));
                    bytes += 1;
                    if (byte < 128) {
                        if (bytes > 1 and byte == 0) return error.CachePackNoncanonical;
                        break;
                    }
                }
                const delta = (word >> 1) ^ (0 -% (word & 1));
                previous +%= delta;
                output[row * self.channels + column] = previous;
            }
        }
        if (at != self.data.len) return error.CachePackLength;
    }
};

pub fn pack(a: std.mem.Allocator, words: []const u32, channels: u8) !Packed {
    if (channels == 0 or words.len % channels != 0) return error.CachePackShape;
    if (words.len != 0 and BLOCK_WORDS % channels == 0) if (native()) |lz4| return packBlocks(a, words, channels, lz4);
    return packPortable(a, words, channels);
}
fn packBlocks(a: std.mem.Allocator, words: []const u32, channels: u8, lz4: *const Lz4) !Packed {
    const blocks = try a.alloc(Block, (words.len + BLOCK_WORDS - 1) / BLOCK_WORDS);
    errdefer a.free(blocks);
    var data: std.ArrayListUnmanaged(u8) = .empty;
    errdefer data.deinit(a);
    try data.ensureTotalCapacity(a, words.len);
    var filtered: [BLOCK_WORDS * 4]u8 = undefined;
    // LZ4_COMPRESSBOUND(65536), as specified by the upstream block API.
    var compressed: [BLOCK_WORDS * 4 + BLOCK_WORDS * 4 / 255 + 16]u8 = undefined;
    for (blocks, 0..) |*block, index| {
        const first = index * BLOCK_WORDS;
        const count: usize = @min(BLOCK_WORDS, words.len - first);
        const rows = count / channels;
        const bytes = count * 4;
        for (0..channels) |channel| {
            const field = filtered[channel * rows * 4 ..][0 .. rows * 4];
            var previous: u32 = 0;
            for (0..rows) |row| {
                const value = words[first + row * channels + channel];
                const delta = value -% previous;
                previous = value;
                field[row] = @truncate(delta);
                field[rows + row] = @truncate(delta >> 8);
                field[2 * rows + row] = @truncate(delta >> 16);
                field[3 * rows + row] = @truncate(delta >> 24);
            }
        }
        const size = lz4.compress(&filtered, &compressed, @intCast(bytes), @intCast(compressed.len));
        const raw = size <= 0 or size >= @as(c_int, @intCast(bytes));
        const source = if (raw) filtered[0..bytes] else compressed[0..@intCast(size)];
        block.* = .{ .offset = data.items.len, .bytes = @intCast(source.len), .raw = raw };
        try data.appendSlice(a, source);
    }
    return .{ .data = try data.toOwnedSlice(a), .blocks = blocks, .words = words.len, .channels = channels, .encoding = .lz4_blocks };
}
pub fn packPortable(a: std.mem.Allocator, words: []const u32, channels: u8) !Packed {
    if (channels == 0 or words.len % channels != 0) return error.CachePackShape;
    var data: std.ArrayListUnmanaged(u8) = .empty;
    errdefer data.deinit(a);
    try data.ensureTotalCapacity(a, words.len);
    const rows = words.len / channels;
    for (0..channels) |column| {
        var previous: u32 = 0;
        for (0..rows) |row| {
            const value = words[row * channels + column];
            const delta: i32 = @bitCast(value -% previous);
            previous = value;
            var word: u32 = (@as(u32, @bitCast(delta)) << 1) ^ @as(u32, @bitCast(delta >> 31));
            while (word >= 128) {
                try data.append(a, @as(u8, @truncate(word)) | 128);
                word >>= 7;
            }
            try data.append(a, @intCast(word));
        }
    }
    if (data.items.len >= words.len * 4) {
        data.deinit(a);
        data = .empty;
        return .{ .data = try a.dupe(u8, std.mem.sliceAsBytes(words)), .words = words.len, .channels = channels, .encoding = .raw };
    }
    return .{ .data = try data.toOwnedSlice(a), .words = words.len, .channels = channels, .encoding = .delta_varint };
}

test "cache encoding roundtrips wrapping words and strided task records" {
    const a = std.testing.allocator;
    var words: [8192]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = switch (i % 8) {
        0 => @intCast(i % 16),
        1 => @intCast(i * 5),
        2 => std.math.maxInt(u32) - @as(u32, @intCast(i)),
        3 => 0x80000000 + @as(u32, @intCast(i)),
        4 => 0,
        else => @truncate(i *% 0x9e3779b97f4a7c15),
    };
    for ([_]u8{ 1, 8 }) |channels| {
        var encoded = try pack(a, &words, channels);
        defer encoded.deinit(a);
        var result: [words.len]u32 = undefined;
        try encoded.unpack(&result);
        try std.testing.expectEqualSlices(u32, &words, &result);
        try std.testing.expect(encoded.data.len <= words.len * 4);
        if (channels == 8) try std.testing.expect(encoded.encoding != .raw);
    }
}
test "cache decoder refuses truncation overflow trailing and noncanonical words" {
    var out: [1]u32 = undefined;
    const Case = struct { bytes: []const u8, failure: anyerror };
    for ([_]Case{
        .{ .bytes = &.{128}, .failure = error.CachePackLength },
        .{ .bytes = &.{ 128, 128, 128, 128, 16 }, .failure = error.CachePackOverflow },
        .{ .bytes = &.{ 0, 0 }, .failure = error.CachePackLength },
        .{ .bytes = &.{ 128, 0 }, .failure = error.CachePackNoncanonical },
    }) |case| {
        const encoded = Packed{ .data = @constCast(case.bytes), .words = 1, .channels = 1, .encoding = .delta_varint };
        try std.testing.expectError(case.failure, encoded.unpack(&out));
    }
}

test "parallel block boundaries roundtrip independently and reject corrupt lengths" {
    const a = std.testing.allocator;
    if (native() == null) return error.SkipZigTest;
    const words = try a.alloc(u32, 3 * BLOCK_WORDS + 8);
    defer a.free(words);
    for (words, 0..) |*word, i| word.* = @truncate(i *% 0x9e3779b97f4a7c15);
    var encoded = try pack(a, words, 8);
    defer encoded.deinit(a);
    try std.testing.expectEqual(Encoding.lz4_blocks, encoded.encoding);
    const output = try a.alloc(u32, words.len);
    defer a.free(output);
    // Reversed independent block order, as a pool is permitted to execute.
    var index = encoded.blocks.len;
    while (index > 0) {
        index -= 1;
        try encoded.unpackRange(output, index, index + 1);
    }
    try std.testing.expectEqualSlices(u32, words, output);
    encoded.blocks[1].bytes += 1;
    try std.testing.expectError(error.CachePackLength, encoded.unpack(output));
}
