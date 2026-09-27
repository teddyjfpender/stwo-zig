//! Data-independent SHA compression DAG. Constants, aliases and multiplicities
//! are verifier-reconstructible; no witness chooses a dependency or use count.
const std = @import("std");
const sha = @import("sha256_compression.zig");
const program = @import("sha256_word_program.zig");
pub const source_count = 88; // 8 state, 16 big-endian message words, 64 K words.
pub const wire_count = 272;
pub const input_boundary_offset = 4096;
pub fn Operation(comptime kind: program.Kind) type {
    return struct { input: [program.inputCount(kind)]u32, output: [program.outputCount(kind)]u32 };
}
pub const Graph = struct {
    expansion: [48]Operation(.schedule),
    rounds: [64]Operation(.round),
    feed_forward: [8]Operation(.feed_forward),
    output: [8]u32,
    uses: [wire_count]u32,
};
pub fn build() Graph {
    var result: Graph = undefined;
    result.uses = @splat(0);
    var words: [64]u32 = undefined;
    for (words[0..16], 0..) |*wire, i| wire.* = @intCast(8 + i);
    for (&result.expansion, 16..) |*op, t| {
        words[t] = @intCast(88 + t - 16);
        op.* = .{ .input = .{ words[t - 2], words[t - 7], words[t - 15], words[t - 16] }, .output = .{words[t]} };
    }
    var state = [8]u32{ 0, 1, 2, 3, 4, 5, 6, 7 };
    for (&result.rounds, 0..) |*op, t| {
        const next_a: u32 = @intCast(136 + 2 * t);
        const next_e = next_a + 1;
        op.* = .{ .input = state ++ .{ words[t], @as(u32, @intCast(24 + t)) }, .output = .{ next_a, next_e } };
        const previous = state;
        state = .{ next_a, previous[0], previous[1], previous[2], next_e, previous[4], previous[5], previous[6] };
    }
    for (&result.feed_forward, 0..) |*op, i| {
        result.output[i] = @intCast(264 + i);
        op.* = .{ .input = .{ state[i], @intCast(i) }, .output = .{result.output[i]} };
    }
    for (result.expansion) |op| for (op.input) |wire| {
        result.uses[wire] += 1;
    };
    for (result.rounds) |op| for (op.input) |wire| {
        result.uses[wire] += 1;
    };
    for (result.feed_forward) |op| for (op.input) |wire| {
        result.uses[wire] += 1;
    };
    for (result.output) |wire| result.uses[wire] += 1; // caller output consumption
    return result;
}
pub fn sources(state: sha.State, block: [64]u8) [source_count]u32 {
    var result: [source_count]u32 = undefined;
    result[0..8].* = state;
    for (0..16) |i| result[8 + i] = std.mem.readInt(u32, block[i * 4 ..][0..4], .big);
    result[24..].* = sha.round_constants;
    return result;
}
