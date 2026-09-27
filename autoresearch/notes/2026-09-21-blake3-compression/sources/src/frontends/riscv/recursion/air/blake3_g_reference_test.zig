const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/mod.zig");
const air = @import("blake3_g_reference.zig");
const support = @import("test_support.zig");
const compression = core.crypto.blake3_compression;
const M31 = core.fields.m31.M31;
fn evaluate(definition: *const air.Definition, row: *const air.Row, valid: bool) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, row);
    defer std.testing.allocator.free(values);
    var satisfied = true;
    for (definition.arena.constraintsView()) |constraint| {
        satisfied = satisfied and values[lang.types.idIndex(constraint.root)].isZero();
    }
    try std.testing.expectEqual(valid, satisfied);
}
test "BLAKE3 typed G has degree two and agrees with native arithmetic" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    var degrees = try lang.degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(@as(u32, 2), degrees.maximumConstraintDegree());
    const identity = try lang.digest.computeIdentity(&definition.arena);
    try std.testing.expectEqualSlices(u8, &air.SEMANTIC_DIGEST, &identity.bytes);
    var prng = std.Random.DefaultPrng.init(0x424c414b4533);
    for (0..32) |case| {
        var input: [6]u32 = undefined;
        for (&input) |*word| word.* = switch (case) {
            0 => 0,
            1 => 0xffffffff,
            2 => 0x80000000,
            else => prng.random().int(u32),
        };
        const row = try air.witness(input);
        try evaluate(&definition, &row, true);
        const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
        defer std.testing.allocator.free(values);
        var ops = compression.Native{};
        const expected = try compression.g(compression.Native, &ops, input);
        for (definition.output, expected) |bits, want| {
            var actual: u32 = 0;
            for (bits, 0..) |bit, i| actual |= values[lang.types.idIndex(bit)].toU32() << @as(u5, @intCast(i));
            try std.testing.expectEqual(want, actual);
        }
    }
}
test "BLAKE3 typed G rejects every single-bit mutation and nonboolean witnesses" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const row = try air.witness(.{ 0xffffffff, 1, 0x80000000, 0x7fffffff, 0x12345678, 0xabcdef01 });
    for (0..air.COLUMN_COUNT) |i| {
        var changed = row;
        changed[i] = M31.fromCanonical(1 - row[i].toU32());
        try evaluate(&definition, &changed, false);
        changed[i] = M31.fromCanonical(2);
        try evaluate(&definition, &changed, false);
    }
}
test "BLAKE3 seven-round compression matches standard hash across chunks" {
    var data: [2048]u8 = undefined;
    for (&data, 0..) |*byte, i| byte.* = @intCast(i % 251);
    for (0..65) |len| try checkHash(data[0..len]);
    for ([_]usize{ 65, 127, 128, 1023, 1024, 1025, 2048 }) |len| try checkHash(data[0..len]);
    try std.testing.expectError(error.InvalidBlake3BlockLength, compression.compress(compression.IV, @splat(0), 0, 65, 0));
}
fn checkHash(data: []const u8) !void {
    const expected = core.vcs.blake3_hash.Blake3Hasher.hash(data);
    var result: [16]u32 = undefined;
    if (data.len <= 1024) {
        result = try chunk(data, 0, true);
    } else {
        const left = try chunk(data[0..1024], 0, false);
        const right = try chunk(data[1024..], 1, false);
        result = try compression.compress(compression.IV, left[0..8].* ++ right[0..8].*, 0, 64, 4 | 8);
    }
    var actual: [32]u8 = undefined;
    for (result[0..8], 0..) |word, i| std.mem.writeInt(u32, actual[4 * i ..][0..4], word, .little);
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}
fn chunk(data: []const u8, counter: u64, root: bool) ![16]u32 {
    var cv = compression.IV;
    var at: usize = 0;
    while (true) {
        const len = @min(64, data.len - at);
        var bytes: [64]u8 = @splat(0);
        @memcpy(bytes[0..len], data[at..][0..len]);
        var block: [16]u32 = undefined;
        for (&block, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
        const final = at + len == data.len;
        const flags: u32 = (if (at == 0) @as(u32, 1) else 0) | (if (final) @as(u32, 2) else 0) | (if (final and root) @as(u32, 8) else 0);
        const out = try compression.compress(cv, block, counter, @intCast(len), flags);
        if (final) return out;
        cv = out[0..8].*;
        at += len;
    }
}

test "BLAKE3 typed arithmetic covers all scheduled compression calls" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    var block: [16]u32 = undefined;
    for (&block, 0..) |*word, i| word.* = @as(u32, @intCast(i)) *% 0x12345678;
    const trace = try compression.trace(compression.IV, block, 0xabcdef0123456789, 63, 1 | 2 | 8);
    for (trace.calls, 0..) |call, i| {
        try std.testing.expectEqual(@as(u8, @intCast(i / 8)), call.round);
        try std.testing.expectEqual(@as(u8, @intCast(i % 8)), call.slot);
        const row = try air.witness(call.input);
        try evaluate(&definition, &row, true);
        const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
        defer std.testing.allocator.free(values);
        for (definition.output, call.output) |bits, want| {
            var actual: u32 = 0;
            for (bits, 0..) |bit, j| actual |= values[lang.types.idIndex(bit)].toU32() << @as(u5, @intCast(j));
            try std.testing.expectEqual(want, actual);
        }
    }
}
