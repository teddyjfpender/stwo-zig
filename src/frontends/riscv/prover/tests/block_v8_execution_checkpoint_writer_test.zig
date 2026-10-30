const std = @import("std");
const Checkpoints = @import("../block_v8_execution_checkpoint_writer_v1.zig");
const Capture = @import("../block_v7_real_window_capture_v1.zig");

test "checkpoint writer preserves scheduled state and rejects gaps incomplete coverage and tampering" {
    const a = std.testing.allocator;
    var output = std.testing.tmpDir(.{});
    defer output.cleanup();
    var writer = try Checkpoints.Owned.init(a, output.dir, "{\"boundaries\":[0,2,5]}", 5);
    defer writer.deinit();
    var memory = try @import("../../runner/memory.zig").Memory.initFallible(a);
    defer memory.deinit();
    memory.writeU32(0x1000, 7);
    var cpu = @import("../../runner/cpu.zig").Cpu.init(4, 0);
    try writer.captureIfBoundary(0, cpu, &memory);
    try std.testing.expectEqual(@as(u64, 2), try writer.chunkCycles(0, 8));
    memory.writeU32(0x1000, 9);
    cpu.pc = 8;
    var expected = try Capture.snapshot(a, cpu, &memory, .{});
    defer expected.deinit(a);
    try writer.captureIfBoundary(2, cpu, &memory);
    try std.testing.expectEqual(@as(u64, 3), try writer.chunkCycles(2, 8));
    try std.testing.expectError(error.IncompleteExecutionCheckpointCoverage, writer.finish(2));
    try std.testing.expectError(error.SkippedExecutionCheckpoint, writer.captureIfBoundary(6, cpu, &memory));
    const encoded = try writer.directory.readFileAlloc(a, "state-2.b7win", 1 << 20);
    defer a.free(encoded);
    var received = try Capture.Snapshot.decode(a, encoded, expected.identity(), .{});
    defer received.deinit(a);
    try std.testing.expectEqualDeep(expected.cpu, received.cpu);
    try std.testing.expectEqualDeep(expected.words, received.words);
    encoded[encoded.len - 1] ^= 1;
    try std.testing.expectError(error.UntrustedRealWindowIncomingState, Capture.Snapshot.decode(a, encoded, expected.identity(), .{}));
    try writer.captureIfBoundary(5, cpu, &memory);
    try writer.finish(5);
}
test "checkpoint plan requires first instruction terminal coverage and strictly increasing cuts" {
    try std.testing.expectError(error.InvalidExecutionCheckpointCoverage, (Checkpoints.Plan{ .boundaries = &.{ 1, 5 } }).validate(5));
    try std.testing.expectError(error.InvalidExecutionCheckpointCoverage, (Checkpoints.Plan{ .boundaries = &.{ 0, 2, 2, 5 } }).validate(5));
    try std.testing.expectError(error.InvalidExecutionCheckpointCoverage, (Checkpoints.Plan{ .boundaries = &.{ 0, 4 } }).validate(5));
}
