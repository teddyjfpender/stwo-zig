//! Immutable recursion data remains compressed on the GPU. A node expands
//! its class image and FIXED evaluations in its planned staging window.
//! FIXED interpolation materializes coefficients; no commitment is remixed.
const std = @import("std");
const api = @import("api.zig");
pub const magic: u32 = 0x3143504f; // OPC1
pub const field_index: u32 = 0x4f504331;
pub const block_words = 16384;
pub const Run = extern struct {
    program: [*]const u32,
    program_words: u64,
    output: [*]u32,
    output_words: u64,
    scratch: [*]u32,
    verdict: [*]u32,
    blocks: u32,
    data_bytes: u32,
    reject_code: u32,
    channels: u32,
};
comptime {
    if (@sizeOf(Run) != 64) @compileError("compressed class ABI");
}
pub const Launch = *const fn (*anyopaque, u32, *const Run) callconv(.c) c_int;
pub const Class = struct {
    words: []u32,
    key: [32]u8,
    class_words: usize,
    fixed_words: usize,
    channel_count: u32,
    pub fn deinit(self: *Class, a: std.mem.Allocator) void {
        a.free(self.words);
    }
    pub fn outputWords(self: *const Class) usize {
        return self.class_words + self.fixed_words;
    }
    pub fn blocks(self: *const Class) u32 {
        return self.words[4];
    }
    pub fn dataBytes(self: *const Class) u32 {
        return self.words[5];
    }
};
/// Pack builder runs at install only. `Packed` is the existing lossless
/// circuit cache codec, supplied through the host boundary.
pub fn build(a: std.mem.Allocator, compressed: anytype, class_words: usize, fixed_words: usize) !Class {
    const total = try std.math.add(usize, class_words, fixed_words);
    if (compressed.encoding != .lz4_blocks or compressed.channels == 0 or compressed.channels > 128 or !std.math.isPowerOfTwo(compressed.channels) or compressed.words != total or total == 0 or total > std.math.maxInt(u32) or total % compressed.channels != 0) return error.PackedClassShape;
    const n_blocks = try std.math.divCeil(usize, total, block_words);
    if (n_blocks != compressed.blocks.len or compressed.data.len > std.math.maxInt(u32)) return error.PackedClassShape;
    const data_at = std.mem.alignForward(usize, 16 + 4 * n_blocks, 4);
    const words = try a.alloc(u32, data_at + (try std.math.divCeil(usize, compressed.data.len, 4)));
    errdefer a.free(words);
    @memset(words, 0);
    @memcpy(words[0..16], &[_]u32{ magic, 2, @intCast(words.len), @intCast(total), @intCast(n_blocks), @intCast(compressed.data.len), @intCast(data_at), @intCast(class_words), @intCast(fixed_words), compressed.channels, 0, 0, 0, 0, 0, 0 });
    for (compressed.blocks, 0..) |block, i| {
        const at = 16 + 4 * i;
        const offset: u64 = block.offset;
        @memcpy(words[at..][0..4], &[_]u32{ @truncate(offset), @truncate(offset >> 32), block.bytes, @intFromBool(block.raw) });
    }
    @memcpy(std.mem.sliceAsBytes(words[data_at..])[0..compressed.data.len], compressed.data);
    var key: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(words), &key, .{});
    return .{ .words = words, .key = key, .class_words = class_words, .fixed_words = fixed_words, .channel_count = compressed.channels };
}
pub fn enqueue(sym: Launch, ctx: *anyopaque, class: *const Class, program: api.DeviceBuffer, output: api.DeviceBuffer, scratch: api.DeviceBuffer, verdict: api.DeviceBuffer, reject_code: u32) !void {
    if (program.words != class.words.len or output.words != class.outputWords() or scratch.words < 12 or verdict.words < 1) return error.PackedClassShape;
    const run = Run{ .program = program.ptr, .program_words = program.words, .output = output.ptr, .output_words = output.words, .scratch = scratch.ptr, .verdict = verdict.ptr, .blocks = class.blocks(), .data_bytes = class.dataBytes(), .reject_code = reject_code, .channels = class.channel_count };
    if (sym(ctx, 0, &run) != 0) return error.PackedClassEnqueueFailed;
}
