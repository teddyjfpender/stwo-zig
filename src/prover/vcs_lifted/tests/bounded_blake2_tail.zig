const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const tails = @import("stwo_prover_engine").vcs_lifted.bounded_blake2_tail;
const Column = struct { values: []const M31, log_size: u32 };

test "vcs_lifted BLAKE2s four-row prefix cache matches scalar mixed-height streams across shards" {
    const allocator = std.testing.allocator;
    const logs = [_]u32{ 2, 4, 7, 10 };
    const widths = [_]usize{ 17, 33, 8, 19 };
    var storage = std.ArrayList([]M31).empty;
    defer {
        for (storage.items) |values| allocator.free(values);
        storage.deinit(allocator);
    }
    var columns = std.ArrayList(Column).empty;
    defer columns.deinit(allocator);
    for (logs, widths) |log, width| for (0..width) |column| {
        const values = try allocator.alloc(M31, @as(usize, 1) << @intCast(log));
        try storage.append(allocator, values);
        for (values, 0..) |*value, row| value.* = M31.fromCanonical(@intCast((row * 97091 + column * 9011 + log) % core.fields.m31.Modulus));
        try columns.append(allocator, .{ .values = values, .log_size = log });
    };
    inline for (.{ core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher, core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher }) |H| {
        const base = [_]H{H.defaultWithInitialState()} ** 2;
        var expected: [1024]H.Hash = undefined;
        for (&expected, 0..) |*digest, position| {
            var hasher = H.defaultWithInitialStateWithMode(.scalar);
            for (columns.items) |column| {
                const shift: std.math.Log2Int(usize) = @intCast(10 - column.log_size + 1);
                const index = ((position >> shift) << 1) + (position & 1);
                hasher.updateLeaf(column.values[index..][0..1]);
            }
            digest.* = hasher.finalize();
        }
        for ([_]usize{ 1, 3, 7, 18 }) |shards| {
            var actual: [1024]H.Hash = undefined;
            for (0..shards) |shard| {
                const range = .{
                    .base_hashers = @as([]const H, &base),
                    .base_log_size = @as(u32, 1),
                    .tail_columns = @as([]const Column, columns.items),
                    .final_log_size = @as(u32, 10),
                    .leaves = @as([]H.Hash, &actual),
                    .start = actual.len * shard / shards,
                    .end = actual.len * (shard + 1) / shards,
                };
                try std.testing.expect(tails.finalize(H, &range) != null);
            }
            try std.testing.expectEqualSlices(H.Hash, &expected, &actual);
        }
    }
}

test "vcs_lifted BLAKE2s prefix cache declines two-row groups before output mutation" {
    const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
    const values = [_]M31{ M31.one(), M31.zero() };
    const columns = [_]Column{.{ .values = &values, .log_size = 1 }};
    const base = [_]H{H.defaultWithInitialState()} ** 2;
    var output = [_]H.Hash{[_]u8{0xab} ** 32} ** 4;
    const range = .{ .base_hashers = @as([]const H, &base), .base_log_size = @as(u32, 1), .tail_columns = @as([]const Column, &columns), .final_log_size = @as(u32, 2), .leaves = @as([]H.Hash, &output), .start = @as(usize, 0), .end = @as(usize, 4) };
    try std.testing.expect(tails.finalize(H, &range) == null);
    for (output) |digest| for (digest) |byte| try std.testing.expectEqual(@as(u8, 0xab), byte);
}
