//! Execution-backed root admission checks; owned only by the focused test root.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const PublicData = frontend.air.public_data_v2.PublicDataV2;
const singleRootStatement = frontend.recursion.detached_segment_command_v1.singleRootStatement;

test "SegmentV2 single root admits a complete one-segment execution" {
    const allocator = std.testing.allocator;
    const model = @import("recursive_segment_v2_memory_workload.zig");
    const workload = @import("recursive_segment_v2_workload.zig");
    var segments = try model.materialize(1, allocator, 1, 13);
    defer segments[0].deinit();
    const results = [1]*const frontend.runner.SegmentResult{&segments[0].base};
    try workload.validateSegments(1, results, 1, 13);
    const statements = try workload.fixtureStatementsForSegments(1, allocator, results);
    const session = frontend.recursion.poseidon2_channel.hashBytes("single-root-test", 0x5632_504f);
    const admitted = try workload.admitSegments(1, results, session, statements);
    const source = admitted.sources[0];
    const words = try allocator.alloc(core.fields.m31.M31, try source.canonicalWordCount());
    defer allocator.free(words);
    _ = try source.encodeCanonical(words);
    const data = try PublicData.authenticate(words);
    const root = try singleRootStatement(&data);
    try std.testing.expectEqualDeep(admitted.folded, root.statement);
    try std.testing.expectEqual(@as(u32, 1), root.statement.job.segment_count);
    try std.testing.expect(segments[0].base.completion_reason != null);
}
