const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Job = @import("../block_v5_memory_source_page_job_v1.zig");
const Admissions = @import("../block_v6_source_recursive_admissions_v1.zig");
const Collection = @import("../block_v6_source_recursive_collection_v1.zig");
const Pages = @import("../block_v5_memory_source_unified_page_proof_v1.zig");

fn exercise(a: std.mem.Allocator, job: *const Job.ForBackend(Cpu).Job, context: *const Pages.Context, limits: Admissions.Limits) !void {
    const independent = try Admissions.Owner.createFromJob(a, job, context, limits);
    defer independent.deinit();
    var collected = try Collection.collect(a, job.dir, independent, .{});
    defer collected.deinit();
}
test "source recursive collection instantiates original raw fold capture and independent admission" {
    std.mem.doNotOptimizeAway(&exercise);
}
test "source recursive admission rejects incomplete or oversized roster before reading context" {
    var context: Pages.Context = undefined;
    context.raw = &.{};
    context.fold = &.{};
    try std.testing.expectError(error.SourceRecursiveAdmissionResourceLimit, Admissions.Owner.create(std.testing.allocator, &context, &.{}, .{}));
    var raw: [65]@import("../block_v5_memory_source_packed_sha_replay_v1.zig").Pin = undefined;
    context.raw = &raw;
    try std.testing.expectError(error.SourceRecursiveAdmissionResourceLimit, Admissions.Owner.create(std.testing.allocator, &context, &.{}, .{}));
}
