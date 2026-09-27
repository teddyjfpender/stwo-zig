//! Geometry/context fixtures and real key-body retention only, no PCS run.
const std = @import("std");
const Storage = @import("../recursion/air/blake3_parent_row_storage.zig");
const Key = @import("../recursion/blake3_parent_fixed_key_v1.zig");
const Protocol = @import("../recursion/blake3_execution_parent_protocol.zig");
const Partition = @import("../recursion/air/blake3_g_partition.zig");
fn empty() Storage.FixedTuple(false) {
    var fixed: Storage.FixedTuple(false) = undefined;
    inline for (0..Storage.Airs.len) |slot| fixed[slot] = &.{};
    return fixed;
}
test "parent fixed key: original exact row logs include zero one nonpower counts and joined G partitions" {
    var fixed = empty();
    inline for (Storage.Airs, 0..) |Air, slot| {
        var rows: [17]Storage.FixedRow(Air) = undefined;
        for ([_]usize{ 0, 1, 2, 3, 7, 8, 9, 16, 17 }) |count| {
            fixed[slot] = rows[0..count];
            const expected: u32 = if (count <= 1) 1 else std.math.log2_int_ceil(usize, count);
            try std.testing.expectEqual(expected, (try Key.rowLogs(fixed))[slot]);
        }
        fixed[slot] = &.{};
    }
    // Already joined/sharded children retain their exact actual cohort sizes,
    // as original partitionHashRows does when a secondary shard is nonempty.
    var g: [13]Storage.FixedRow(Storage.Airs[0]) = undefined;
    fixed[0] = g[0..3];
    inline for (Partition.SHARDS[1..], 1..) |slot, index| fixed[slot] = g[0 .. 1 + index];
    const logs = try Key.rowLogs(fixed);
    try std.testing.expectEqual(@as(u32, 2), logs[0]);
    inline for (Partition.SHARDS[1..], 1..) |slot, index| try std.testing.expectEqual(@as(u32, @intCast(std.math.log2_int_ceil(usize, 1 + index))), logs[slot]);
}
test "parent fixed key: original key domain ceiling rejects before reading impossible borrowed storage" {
    var fixed = empty();
    // The helper reads slice lengths only. An invalid oversized slice must be
    // rejected before projection, allocation or dereferencing this sentinel.
    const impossible = @as([*]Storage.FixedRow(Storage.Airs[0]), @ptrFromInt(@alignOf(Storage.FixedRow(Storage.Airs[0])) * 1024));
    fixed[0] = impossible[0 .. (@as(usize, 1) << 30) + 1];
    try std.testing.expectError(error.InvalidBlake3ParentGeometry, Key.rowLogs(fixed));
    fixed[0].len = @as(usize, 1) << 30;
    try std.testing.expectEqual(@as(u32, 30), (try Key.rowLogs(fixed))[0]);
}
test "parent fixed key: actual shared derivation rejects invalid context before allocator use" {
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const context = Protocol.Context{ .child_key_id = [_]u8{1} ** 32, .child_config = Protocol.CSP_CONFIG, .graph_ids = @splat([_]u8{2} ** 32), .transcript_plan_id = [_]u8{3} ** 32, .statement_identity = [_]u8{4} ** 32 };
    try std.testing.expectError(error.InvalidBlake3ParentSpan, Key.ForBackend(Cpu).derive(std.testing.failing_allocator, empty(), context, .csp_q70_pow26));
}
