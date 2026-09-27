const std = @import("std");
const engine = @import("stwo_prover_engine");
const leaf_stage = @import("block_v4_cpu_incremental_leaf_stage.zig");
const forest_stage = @import("block_v4_cpu_incremental_forest_stage.zig");
const outer_stage = @import("block_v4_cpu_incremental_outer_stage.zig");
const linked = @import("../recursion/blake3_exact_root_receiver_v3.zig");
const spans = @import("../recursion/span_statement_blake3.zig");

pub fn check(a: std.mem.Allocator, dir: std.fs.Dir, leaves: *const leaf_stage.Capture, job: spans.JobContext, pool: *engine.work_pool.WorkPool) !void {
    var timer = try std.time.Timer.start();
    var forest = try forest_stage.prove(a, dir, leaves, job, pool, .{
        .profile = .diagnostic_q8_pow0,
        .preparation_limit = 24 * 1024 * 1024 * 1024,
        .worker_options = .{ .worker_count = 4, .host_byte_limit = 24 * 1024 * 1024 * 1024, .retained_scratch_limit = 64 * 1024 * 1024 },
    });
    const elapsed_ns = timer.read();
    defer forest.deinit();
    try std.testing.expectEqual(@as(usize, 1), forest.parents.len);
    try std.testing.expectEqual(@as(usize, 1), forest.roots.len);
    const descriptors = try forest.rootDescriptors(a);
    defer a.free(descriptors);
    const digest = try linked.verifiedForestDigest(job, descriptors);
    try std.testing.expectEqualSlices(u8, &forest.digest, &digest);
    timer.reset();
    const outer = try outer_stage.prove(a, dir, leaves, &forest, job, .{
        .profile = .diagnostic_q8_pow0,
        .preparation_limit = 24 * 1024 * 1024 * 1024,
    });
    const outer_elapsed_ns = timer.read();
    try std.testing.expectEqualSlices(u8, &forest.digest, &outer.forest_digest);
    const outer_bytes = try outer.load();
    defer a.free(outer_bytes);
    try std.testing.expectEqual(outer.byte_len, outer_bytes.len);
    {
        var file = try dir.openFile(outer_stage.OUTER_FILE, .{ .mode = .read_write });
        defer file.close();
        try file.writeAll(&.{outer_bytes[0] ^ 1});
    }
    try std.testing.expectError(error.TamperedStagedOuter, outer.load());
    const bytes = try forest.loadParent(0);
    defer a.free(bytes);
    try std.testing.expectEqual(forest.parents[0].byte_len, bytes.len);
    {
        var file = try dir.openFile("block-v4-parent-0-1.proof", .{ .mode = .read_write });
        defer file.close();
        try file.writeAll(&.{bytes[0] ^ 1});
    }
    try std.testing.expectError(error.TamperedStagedDyadicParent, forest.loadParent(0));
    std.debug.print("BLOCK_V4_STREAMING_FOREST_STAGE verified=true parents={d} roots={d} parent_bytes={d} prove_ns={d} outer_bytes={d} outer_prove_ns={d} tamper_rejected=true\n", .{ forest.parents.len, forest.roots.len, bytes.len, elapsed_ns, outer.byte_len, outer_elapsed_ns });
}
