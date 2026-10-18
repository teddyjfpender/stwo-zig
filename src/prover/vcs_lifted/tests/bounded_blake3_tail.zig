const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const tails = @import("stwo_prover_engine").vcs_lifted.bounded_blake3_tail;
const H = core.vcs_lifted.blake3_merkle.MerkleHasher;
const Column = struct { values: []const M31, log_size: u32 };

fn value(row: usize, column: usize, log: u32) M31 {
    return M31.fromCanonical(@intCast((row * 97091 + column * 9011 + log) % core.fields.m31.Modulus));
}

test "prover vcs_lifted BLAKE3 four-row prefix cache matches scalar mixed-height streams across shards and chunk edges" {
    const allocator = std.testing.allocator;
    const logs = [_]u32{ 3, 4, 7, 10 };
    // Leaf byte totals (28-byte prefix + 4 bytes per column including the
    // base prefix) land inside one chunk, exactly on 1024 and 2048, and in a
    // third chunk, so chunk ends, parent merges and root flags are all hit.
    const widths = [_][4]usize{ .{ 17, 33, 8, 19 }, .{ 40, 100, 60, 46 }, .{ 120, 200, 100, 82 }, .{ 150, 250, 100, 97 } };
    for (widths) |shape| {
        var storage = std.ArrayList([]M31).empty;
        defer {
            for (storage.items) |values| allocator.free(values);
            storage.deinit(allocator);
        }
        var columns = std.ArrayList(Column).empty;
        defer columns.deinit(allocator);
        for (logs, shape) |log, width| for (0..width) |column| {
            const values = try allocator.alloc(M31, @as(usize, 1) << @intCast(log));
            try storage.append(allocator, values);
            for (values, 0..) |*slot, row| slot.* = value(row, column, log);
            try columns.append(allocator, .{ .values = values, .log_size = log });
        };
        // Three native log-2 prefix columns give every base state a pending
        // partial block that differs between the four parity/row states.
        var base: [4]H = undefined;
        for (&base, 0..) |*hasher, index| {
            hasher.* = H.defaultWithInitialState();
            for (0..3) |column| hasher.updateLeaf(&.{value(index, column, 2)});
        }
        var expected: [1024]H.Hash = undefined;
        for (&expected, 0..) |*digest, position| {
            var hasher = base[((position >> (10 - 2 + 1)) << 1) + (position & 1)];
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
                    .base_log_size = @as(u32, 2),
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

test "prover vcs_lifted BLAKE3 prefix cache declines two-row groups before output mutation" {
    const values = [_]M31{ M31.one(), M31.zero() };
    const columns = [_]Column{.{ .values = &values, .log_size = 1 }};
    const base = [_]H{H.defaultWithInitialState()} ** 2;
    var output = [_]H.Hash{[_]u8{0xab} ** 32} ** 4;
    const range = .{ .base_hashers = @as([]const H, &base), .base_log_size = @as(u32, 1), .tail_columns = @as([]const Column, &columns), .final_log_size = @as(u32, 2), .leaves = @as([]H.Hash, &output), .start = @as(usize, 0), .end = @as(usize, 4) };
    try std.testing.expect(tails.finalize(H, &range) == null);
    for (output) |digest| for (digest) |byte| try std.testing.expectEqual(@as(u8, 0xab), byte);
}

test "prover vcs_lifted BLAKE3 prefix cache declines mismatched base geometry before output mutation" {
    const values = [_]M31{ M31.one(), M31.zero(), M31.one(), M31.zero() };
    const columns = [_]Column{.{ .values = &values, .log_size = 2 }};
    var base = [_]H{H.defaultWithInitialState()} ** 2;
    base[1].updateLeaf(&.{M31.one()});
    var output = [_]H.Hash{[_]u8{0xab} ** 32} ** 4;
    const range = .{ .base_hashers = @as([]const H, &base), .base_log_size = @as(u32, 1), .tail_columns = @as([]const Column, &columns), .final_log_size = @as(u32, 2), .leaves = @as([]H.Hash, &output), .start = @as(usize, 0), .end = @as(usize, 4) };
    try std.testing.expect(tails.finalize(H, &range) == null);
    for (output) |digest| for (digest) |byte| try std.testing.expectEqual(@as(u8, 0xab), byte);
}
