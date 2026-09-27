const std = @import("std");
const core = @import("stwo_core");
const runtime_mod = @import("runtime.zig");
const H = core.vcs_lifted.blake3_merkle.MerkleHasher;

test "Metal BLAKE3 resident parent chains preserve every layer and arena guards" {
    const allocator = std.testing.allocator;
    // Parent support must not silently admit unfinished leaf/FRI dispatch.
    try std.testing.expect(@import("hash_domain.zig").parameters(H) == null);
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();
    const Case = struct { depth: u32, levels: u32 };
    for ([_]Case{ .{ .depth = 1, .levels = 1 }, .{ .depth = 5, .levels = 5 }, .{ .depth = 11, .levels = 11 }, .{ .depth = 11, .levels = 1 } }) |case| {
        const depth = case.depth;
        const levels = case.levels;
        var offsets: [12]u32 = undefined;
        var counts: [11]u32 = undefined;
        var cursor: u32 = 64;
        var hashes: u32 = @as(u32, 1) << @intCast(depth);
        for (0..depth + 1) |level| {
            offsets[level] = cursor;
            cursor = std.mem.alignForward(u32, cursor + hashes * 8, 64) + 64;
            if (level < depth) counts[level] = hashes / 2;
            hashes /= 2;
        }
        var arena = try runtime.allocateResidentBuffer(@as(usize, cursor) * 4);
        defer arena.deinit();
        const actual = @as([*]u32, @ptrCast(@alignCast(arena.contents)))[0..cursor];
        const expected = try allocator.alloc(u32, cursor);
        defer allocator.free(expected);
        var plan = try runtime.prepareMerkleParentChainForFamily(offsets[0..levels], offsets[1..][0..levels], counts[0..levels], .{0} ** 8, 0, .blake3);
        defer plan.deinit();
        try std.testing.expectError(error.CommitmentFailed, runtime.prepareMerkleParentChainForFamily(offsets[0..levels], offsets[1..][0..levels], counts[0..levels], .{0} ** 8, 64, .blake3));
        try std.testing.expectError(error.CommitmentFailed, runtime.prepareMerkleParentChainForFamily(offsets[0..levels], offsets[1..][0..levels], counts[0..levels], .{1} ** 8, 0, .blake3));
        for (0..2) |iteration| {
            @memset(actual, 0xa5a5a5a5);
            const leaf_words = (@as(usize, 1) << @intCast(depth)) * 8;
            for (actual[offsets[0]..][0..leaf_words], 0..) |*word, i|
                word.* = (@as(u32, @intCast(i + iteration)) *% 0x9e3779b9) ^ 0xffffffff;
            @memcpy(expected, actual);
            for (0..levels) |level| for (0..counts[level]) |parent| {
                const source = offsets[level] + parent * 16;
                const destination = offsets[level + 1] + parent * 8;
                const digest = H.hashChildren(.{
                    .left = std.mem.toBytes(expected[source..][0..8].*),
                    .right = std.mem.toBytes(expected[source + 8 ..][0..8].*),
                });
                for (expected[destination..][0..8], 0..) |*word, i|
                    word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
            };
            const gpu_ms = try runtime.merkleParentChainPrepared(arena, plan);
            try std.testing.expectEqualSlices(u32, expected, actual);
            std.debug.print("BLAKE3_METAL_PARENT depth={d} levels={d} reuse={d} gpu_ms={d}\n", .{ depth, levels, iteration, gpu_ms });
        }
    }
}
