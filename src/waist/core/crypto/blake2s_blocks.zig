const std = @import("std");
const builtin = @import("builtin");
const terminal_parallel = @import("blake2s_terminal_parallel.zig");

pub const V4 = @Vector(4, u32);

pub fn loadFixed(block: *const [64]u8, out: *[16]u32) void {
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        out[i] = readFixed(block, i * 4);
    }
}

pub fn loadSlice(block: []const u8, out: *[16]u32) void {
    std.debug.assert(block.len == 64);
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        const start = i * 4;
        out[i] = (@as(u32, block[start + 0])) |
            (@as(u32, block[start + 1]) << 8) |
            (@as(u32, block[start + 2]) << 16) |
            (@as(u32, block[start + 3]) << 24);
    }
}

pub fn loadParallel4(data: *const [4][64]u8, out: *[16]V4) void {
    if (comptime builtin.cpu.arch.endian() == .little) {
        const words: [4][4]V4 = @bitCast(data.*);
        inline for (0..4) |group| {
            const transposed = transpose4x4(.{
                words[0][group],
                words[1][group],
                words[2][group],
                words[3][group],
            });
            inline for (0..4) |word| out[group * 4 + word] = transposed[word];
        }
    } else {
        for (0..16) |word_index| {
            const byte_index = word_index * 4;
            out[word_index] = .{
                readFixed(&data[0], byte_index),
                readFixed(&data[1], byte_index),
                readFixed(&data[2], byte_index),
                readFixed(&data[3], byte_index),
            };
        }
    }
}

pub fn parallelStatesToDigests(
    comptime Digest: type,
    states: *const [8]V4,
) [4]Digest {
    if (comptime builtin.cpu.arch.endian() == .little) {
        const low = transpose4x4(.{ states[0], states[1], states[2], states[3] });
        const high = transpose4x4(.{ states[4], states[5], states[6], states[7] });
        var words: [4][2]V4 = undefined;
        inline for (0..4) |lane| words[lane] = .{ low[lane], high[lane] };
        return @bitCast(words);
    } else {
        var out: [4]Digest = undefined;
        for (0..4) |lane| {
            var lane_state: [8]u32 = undefined;
            for (0..8) |word_index| lane_state[word_index] = states[word_index][lane];
            out[lane] = terminal_parallel.stateToDigest(Digest, lane_state);
        }
        return out;
    }
}

fn readFixed(data: *const [64]u8, at: usize) u32 {
    return (@as(u32, data[at + 0])) |
        (@as(u32, data[at + 1]) << 8) |
        (@as(u32, data[at + 2]) << 16) |
        (@as(u32, data[at + 3]) << 24);
}

fn transpose4x4(rows: [4]V4) [4]V4 {
    const ab_low = @shuffle(u32, rows[0], rows[1], @Vector(4, i32){ 0, -1, 1, -2 });
    const ab_high = @shuffle(u32, rows[0], rows[1], @Vector(4, i32){ 2, -3, 3, -4 });
    const cd_low = @shuffle(u32, rows[2], rows[3], @Vector(4, i32){ 0, -1, 1, -2 });
    const cd_high = @shuffle(u32, rows[2], rows[3], @Vector(4, i32){ 2, -3, 3, -4 });
    return .{
        @shuffle(u32, ab_low, cd_low, @Vector(4, i32){ 0, 1, -1, -2 }),
        @shuffle(u32, ab_low, cd_low, @Vector(4, i32){ 2, 3, -3, -4 }),
        @shuffle(u32, ab_high, cd_high, @Vector(4, i32){ 0, 1, -1, -2 }),
        @shuffle(u32, ab_high, cd_high, @Vector(4, i32){ 2, 3, -3, -4 }),
    };
}
