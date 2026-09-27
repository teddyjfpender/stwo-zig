const std = @import("std");
const core = @import("stwo_core");
const runtime_mod = @import("runtime.zig");
const H = core.vcs_lifted.blake3_merkle.MerkleHasher;
const M31 = core.fields.m31.M31;

test "Metal BLAKE3 lifted leaves match CPU across compression and chunk boundaries" {
    const allocator = std.testing.allocator;
    try std.testing.expect(@import("hash_domain.zig").parameters(H) == null);
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();
    const lifting_log = 5;
    for ([_]usize{ 1, 8, 9, 10, 248, 249, 250, 505, 506, 761, 762, 1017, 1018, 2042 }) |width| {
        const offsets = try allocator.alloc(u32, width);
        defer allocator.free(offsets);
        const logs = try allocator.alloc(u32, width);
        defer allocator.free(logs);
        var cursor: u32 = 64;
        for (offsets, logs, 0..) |*offset, *log, i| {
            log.* = 1 + @as(u32, @intCast(i * 5 / width));
            offset.* = cursor;
            cursor += (@as(u32, 1) << @intCast(log.*)) + 3;
        }
        const destination = std.mem.alignForward(u32, cursor, 64) + 64;
        const arena_words = destination + 32 * 8 + 64;
        var arena = try runtime.allocateResidentBuffer(@as(usize, arena_words) * 4);
        defer arena.deinit();
        const actual = @as([*]u32, @ptrCast(@alignCast(arena.contents)))[0..arena_words];
        const expected = try allocator.alloc(u32, arena_words);
        defer allocator.free(expected);
        var plan = try runtime.prepareMerkleLeavesForFamily(offsets, logs, lifting_log, destination, .{0} ** 8, 0, .blake3);
        defer plan.deinit();
        try std.testing.expectError(error.CommitmentFailed, runtime.prepareMerkleLeavesForFamily(offsets, logs, lifting_log, destination, .{1} ** 8, 0, .blake3));
        try std.testing.expectError(error.CommitmentFailed, runtime.prepareMerkleLeavesForFamily(offsets, logs, lifting_log, destination, .{0} ** 8, 64, .blake3));
        for (0..2) |iteration| {
            @memset(actual, 0xa5a5a5a5);
            for (offsets, logs, 0..) |offset, log, column| {
                const count = @as(usize, 1) << @intCast(log);
                for (actual[offset..][0..count], 0..) |*word, row| {
                    word.* = ((@as(u32, @intCast(column * 37 + row + iteration)) *% 0x9e3779b9) % 0x7fffffff);
                }
            }
            @memcpy(expected, actual);
            for (0..32) |row| {
                var hasher = H.defaultWithInitialState();
                for (offsets, logs) |offset, log| {
                    const shift = lifting_log - log;
                    const source = if (shift == 0) row else ((row >> @intCast(shift + 1)) << 1) | (row & 1);
                    hasher.updateLeaf(&.{M31.fromCanonical(actual[offset + source])});
                }
                const digest = hasher.finalize();
                for (expected[destination + row * 8 ..][0..8], 0..) |*word, i|
                    word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
            }
            const gpu_ms = try runtime.merkleLeavesPrepared(arena, plan);
            try std.testing.expectEqualSlices(u32, expected, actual);
            std.debug.print("BLAKE3_METAL_LEAF columns={d} reuse={d} gpu_ms={d}\n", .{ width, iteration, gpu_ms });
        }
    }
}
