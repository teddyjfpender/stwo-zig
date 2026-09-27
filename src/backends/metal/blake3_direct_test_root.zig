const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const runtime_mod = @import("runtime.zig");
const H = core.vcs_lifted.blake3_merkle.MerkleHasher;
const M31 = core.fields.m31.M31;
test "Metal BLAKE3 direct full trees match CPU with wide offset dispatch" {
    const allocator = std.testing.allocator;
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();
    try std.testing.expect(@import("hash_domain.zig").parameters(H) == null);
    try std.testing.expect(@import("hash_domain.zig").directParameters(H).?.family == .blake3);
    for ([_]usize{ 1, 9, 249, 250, 762 }) |width| for ([_]bool{ false, true }) |mixed| {
        const columns = try allocator.alloc([]const M31, width);
        defer allocator.free(columns);
        var initialized: usize = 0;
        defer for (columns[0..initialized]) |column| allocator.free(column);
        for (columns, 0..) |*column, i| {
            const rows: usize = if (mixed) @as(usize, 2) << @as(u6, @intCast(i % 3)) else 8;
            const values = try allocator.alloc(M31, rows);
            column.* = values;
            initialized += 1;
            for (values, 0..) |*value, row| value.* = M31.fromU64(i * 987654321 + row * 31337);
        }
        var cpu = try prover.vcs_lifted.prover.MerkleProverLifted(H).commit(allocator, columns);
        defer cpu.deinit(allocator);
        var gpu = try @import("merkle_tree.zig").MetalMerkleTree(H).commit(&runtime, allocator, columns);
        defer gpu.deinit(allocator);
        try std.testing.expectEqualSlices(u8, &cpu.root(), &gpu.root());
        std.debug.print("BLAKE3_DIRECT columns={d} mixed={}\n", .{ width, mixed });
    };
}
