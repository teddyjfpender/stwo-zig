const std = @import("std");
const study = @import("../pcs_owned_profile_main.zig");

test "PCS owned arena preserves roots coefficients openings and provider originals across dispatch boundaries" {
    for ([_]usize{ 2, 64, 65, 127, 128 }) |total| {
        const report = try study.run(std.testing.allocator, .{ .native_log = 5, .main_columns = total - 1, .provider_logs = &.{5}, .workers = 3, .memory_limit_bytes = 64 << 20 });
        for (report.measurements) |measurement| {
            try std.testing.expect(measurement.provider_original_unchanged);
            try std.testing.expectEqual(measurement.variant == .policy_owned_arena, measurement.all_coefficients_adopt_source);
            try std.testing.expectEqual(@as(usize, total * 32 * 4), measurement.retained_coefficient_bytes);
        }
    }
}
fn allocationCase(a: std.mem.Allocator) !void {
    const result = try study.singleOwned(a, .{ .native_log = 5, .main_columns = 1, .provider_logs = &.{5}, .workers = 1, .memory_limit_bytes = 64 << 20 });
    try std.testing.expect(result.all_coefficients_adopt_source and result.provider_original_unchanged);
}
fn streamingAllocationCase(a: std.mem.Allocator) !void {
    const result = try study.singleOwned(a, .{ .native_log = 5, .main_columns = 127, .provider_logs = &.{5}, .workers = 1, .memory_limit_bytes = 64 << 20 });
    try std.testing.expect(result.all_coefficients_adopt_source and result.provider_original_unchanged);
}
test "PCS owned arena consumes source exactly once on every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, streamingAllocationCase, .{});
}

test "PCS recorder allocation failure preserves owned and streaming input custody" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, recordedCommit, .{true});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, recordedCommit, .{false});
}

fn recordedCommit(recorder_allocator: std.mem.Allocator, owned: bool) !void {
    const core = @import("stwo_core");
    const engine = @import("stwo_prover_engine");
    const B = @import("stwo_cpu_backend").CpuBackend;
    const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
    const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
    const M = core.fields.m31.M31;
    const a = std.testing.allocator;
    var recorder = engine.stage_profile.Recorder.initWithOptions(recorder_allocator, "pcs", "recorder-oom", .{ .capture_tasks = false });
    defer recorder.deinit();
    var scheme = try engine.pcs.CommitmentSchemeProver(B, H, MC).init(a, .{ .pow_bits = 26, .fri_config = try core.fri.FriConfig.init(0, 1, 70) });
    defer scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var channel = core.channel.blake2s.Blake2sChannel{};
    const columns = try a.alloc(engine.pcs.ColumnEvaluation, 2);
    for (columns) |*column| {
        const values = try a.alloc(M, 32);
        @memset(values, M.fromCanonical(7));
        column.* = .{ .log_size = 5, .values = values };
    }
    if (owned) {
        // The consuming API frees descriptors and values even on recorder OOM.
        try scheme.commitOwnedWithRecorder(a, columns, &recorder, &channel);
    } else {
        defer {
            for (columns) |column| a.free(column.values);
            a.free(columns);
        }
        try scheme.commitBorrowedStreamingWithRecorder(a, columns, 1, &recorder, &channel);
    }
}
