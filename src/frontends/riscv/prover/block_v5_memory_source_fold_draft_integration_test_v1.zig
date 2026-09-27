//! Canonical original collect wiring: pure limits/census/transport checks only.
const std = @import("std");
const CPU = @import("block_v5_cpu_source_pages_v1.zig");
const JobModule = @import("block_v5_memory_source_page_job_v1.zig");
const Collection = @import("block_v5_memory_source_fold_draft_collection_v1.zig");

test "source fold draft integration: actual Controller derives one exact independent capacity and aggregate file budget" {
    const options = CPU.Options{};
    const selected = try CPU.draftLimits(options);
    try std.testing.expectEqual(options.job.proof.protocol.page_row_log, selected.row_log);
    try std.testing.expectEqual(options.job.proof.protocol.max_fold_pages, selected.max_pages);
    try std.testing.expectEqual(@min(options.job.max_metadata_bytes, options.job.proof.protocol.max_roster_bytes), selected.max_metadata_bytes);
    try std.testing.expectEqual(@min(options.spool.max_file_bytes, options.job.max_operand_bytes), selected.max_total_bytes);
    try std.testing.expectEqual(@min(options.spool.max_operations, options.fold.max_operations), selected.max_operations);
    try std.testing.expect(std.meta.eql(options.job.proof.fold.stored, selected.stored));
    var changed = options;
    changed.spool.max_operations = 17;
    changed.spool.max_file_bytes = 1234;
    changed.job.max_operand_bytes = 1111;
    const smaller = try CPU.draftLimits(changed);
    try std.testing.expectEqual(@as(u64, 17), smaller.max_operations);
    try std.testing.expectEqual(@as(u64, 1111), smaller.max_total_bytes);
}
test "source fold draft integration: malformed transport geometry fails before allocator files and source access" {
    var cases: [4]CPU.Options = @splat(.{});
    cases[0].job.proof.protocol.page_row_log = 0;
    cases[1].job.proof.protocol.max_fold_pages = 0;
    cases[2].job.max_metadata_bytes = 1;
    cases[3].job.proof.fold.stored.max_operations = 0;
    for (cases) |options| {
        var deny = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        try std.testing.expectError(error.SourceFoldDraftResourceLimit, CPU.collect(deny.allocator(), undefined, undefined, undefined, undefined, undefined, undefined, undefined, options));
        try std.testing.expectEqual(@as(usize, 0), deny.alloc_index);
    }
    const Job = JobModule.ForBackend(@import("stwo_cpu_backend").CpuBackend).Job;
    var deny = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidSourcePageJobLimits, Job.collectWithDrafts(deny.allocator(), undefined, undefined, undefined, undefined, undefined, undefined, undefined, .{ .max_job_heap_bytes = 0 }));
    try std.testing.expectEqual(@as(usize, 0), deny.alloc_index);
}
test "source fold draft integration: rollback uses original raw and fold operand names including index extremes" {
    for ([_]u32{ 0, 1, 262143, std.math.maxInt(u32) }) |index| {
        var original: [128]u8 = undefined;
        var selected: [128]u8 = undefined;
        try std.testing.expectEqualStrings(try JobModule.name(&original, .raw, index, false), try Collection.rawPath(&selected, index));
        try std.testing.expectEqualStrings(try JobModule.name(&original, .fold, index, false), try @import("block_v5_memory_source_fold_draft_pages_v1.zig").path(&selected, index, true));
    }
}
