const std = @import("std");
const stage = @import("block_v5_open_forest_stage_v1.zig");
const exact = @import("../recursion/block_v5_open_exact_forest_receiver_v1.zig");

fn pins() exact.OuterPins {
    return .{ .job_id = @splat(1), .source_image_digest = @splat(2), .sealed_digest = @splat(3),
        .segment_count = 5, .first_cycle = 1, .last_cycle = 5, .initial_pc = 4, .final_pc = 24 };
}
fn options() stage.Options {
    return .{ .profile = .diagnostic_q8_pow0, .lane_count = 2, .total_host_limit = 8 * 1024 * 1024,
        .max_execution_count = 5, .max_proof_bytes = 1024 * 1024, .pool_workers_per_lane = 1 };
}
test "open-v3 stream missing leaf finish joins waiting lanes and remains abortable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const stream = try stage.Stream.start(std.testing.allocator, tmp.dir, pins(), options());
    defer stream.abort();
    try std.testing.expectEqual(@as(usize, 0), stream.progress().submitted);
    try std.testing.expectError(error.IncompleteMixedForestLeaves, stream.finish());
    try std.testing.expect(stream.joined);
    try std.testing.expectEqual(@as(usize, 0), stream.progress().active);
}
test "open-v3 stream abort wakes lanes without retaining policy or setup" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const stream = try stage.Stream.start(std.testing.allocator, tmp.dir, pins(), options());
    stream.abort();
}
test "open-v3 stream metadata and cache limits reject before producing files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var limited = options();
    limited.total_host_limit = 1;
    try std.testing.expectError(error.OutOfMemory, stage.Stream.start(std.testing.allocator, tmp.dir, pins(), limited));
    limited = options();
    limited.setup_cache_entries_per_lane = 0;
    try std.testing.expectError(error.InvalidV5OpenForestOptions, stage.Stream.start(std.testing.allocator, tmp.dir, pins(), limited));
    limited = options();
    limited.max_execution_count = 4;
    try std.testing.expectError(error.V5ExactForestResourceLimit, stage.Stream.start(std.testing.allocator, tmp.dir, pins(), limited));
}
