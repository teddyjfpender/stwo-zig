const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const H = core.vcs_lifted.blake3_merkle.MerkleHasher;
const Column = engine.pcs.ColumnEvaluation;
fn checkStreaming(a: std.mem.Allocator) !void {
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const MC = core.vcs_lifted.blake3_merkle.MerkleChannel;
    const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, H, MC);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var baseline = try Scheme.init(a, config);
    defer baseline.deinit(a);
    var compact = try Scheme.init(a, config);
    defer compact.deinit(a);
    compact.setCompactPolynomialStorage(4);
    var original_channel = core.channel.blake3.Channel{};
    var compact_channel = original_channel;
    var small: [8]M = undefined;
    var large: [32]M = undefined;
    for (&small, 0..) |*x, i| x.* = M.fromU64(i * 7 + 13);
    for (&large, 0..) |*x, i| x.* = M.fromU64(i * i + 31);
    const columns = [_]Column{
        .{ .log_size = 5, .values = &large },
        .{ .log_size = 3, .values = &small },
        .{ .log_size = 5, .values = &large },
    };
    try baseline.commitBorrowedStreamingWithRecorder(a, &columns, 1, null, &original_channel);
    try compact.commitBorrowedStreamingWithRecorder(a, &columns, 1, null, &compact_channel);
    try std.testing.expectEqualSlices(u8, &original_channel.digestBytes(), &compact_channel.digestBytes());
    try std.testing.expectEqual(@as(usize, 0), compact.trees.items[0].columns[0].values.len);
    try std.testing.expect(compact.trees.items[0].columns[0].coefficient_values != null);
    const queries = [_]usize{ 0, 61, 7, 16, 7 };
    var expected = try baseline.trees.items[0].decommit(a, &queries);
    defer expected.deinit(a);
    var actual = try compact.trees.items[0].decommit(a, &queries);
    defer actual.deinit(a);
    try std.testing.expectEqualDeep(expected, actual);
}

test "coefficient storage CPU packed incremental commitments match materialized roots and openings" {
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = std.testing.allocator });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try checkStreaming(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkStreaming, .{});
}
