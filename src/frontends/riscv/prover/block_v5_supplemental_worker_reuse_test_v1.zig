//! Empty original worker owners and failure metadata only. No rows are admitted,
//! fixed commitments derived, proofs generated, or device operations submitted.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Providers = @import("block_v5_recursive_provider_definition_v1.zig");
const Executions = @import("block_v5_recursive_execution_leaf_files_v1.zig");
const Publication = @import("block_v5_cpu_recursive_publication_v1.zig");
const Options = @import("block_v5_native_recursive_setup_cache_v1.zig").Options;
const Modules = .{
    Providers.ForFamily(.range16),
    Providers.ForFamily(.ram_lanes),
    Providers.ForFamily(.program_table),
    Providers.ForFamily(.native_lookup),
    Executions.ForFamily(.caller_arithmetic),
    Executions.ForFamily(.caller_fused),
    Executions.ForFamily(.native_capacity_fused),
};
const OptionalTypes = blk: {
    var types: [Modules.len]type = undefined;
    for (Modules, 0..) |Module, i| types[i] = ?Module.Stage.ForBackend(Cpu).SetupCache;
    break :blk types;
};
const Owners = std.meta.Tuple(&OptionalTypes);

fn emptyOwners(a: std.mem.Allocator) !void {
    var owners: Owners = .{ null, null, null, null, null, null, null };
    defer inline for (0..Modules.len) |i| if (owners[i]) |*cache| cache.deinit();
    const options = Options{ .profile = .csp_q70_pow26, .aggregate_host_byte_limit = 1 << 20, .worker_options = .{ .worker_count = 1, .host_byte_limit = 1 << 20, .retained_scratch_limit = 0 } };
    inline for (Modules, 0..) |Module, i| {
        owners[i] = try Module.Stage.ForBackend(Cpu).SetupCache.init(a, options);
        try std.testing.expect(owners[i].?.entry == null);
        try std.testing.expectEqual(@as(usize, 0), owners[i].?.stats.hits);
        try std.testing.expectEqual(@as(usize, 0), owners[i].?.stats.misses);
        const lane = owners[i].?.request_lane.snapshot();
        try std.testing.expectEqual(@as(u64, 0), lane.starts);
        try std.testing.expectEqual(@as(u64, 0), lane.completed);
        try std.testing.expect(!lane.active and !lane.closed);
    }
}
test "supplemental worker reuse: seven original typed owners remain lazy and retain no proof state" {
    try emptyOwners(std.testing.allocator);
}
test "supplemental worker reuse: every partial seven-owner allocation failure unwinds" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, emptyOwners, .{});
}
test "supplemental worker reuse: uniform worker cap and scratch policy rejects before source admission" {
    const original = Publication.Options{};
    try original.validate();
    var rejected = original;
    rejected.max_worker_bytes = 0;
    try std.testing.expectError(error.InvalidCpuRecursivePublicationOptions, rejected.validate());
    rejected = original;
    rejected.worker_options.host_byte_limit = original.max_worker_bytes + 1;
    try std.testing.expectError(error.InvalidCpuRecursivePublicationOptions, rejected.validate());
    rejected = original;
    rejected.worker_options.retained_scratch_limit = original.worker_options.host_byte_limit + 1;
    try std.testing.expectError(error.InvalidCpuRecursivePublicationOptions, rejected.validate());
}
test "supplemental worker reuse: invalid standalone worker geometry rejects before metadata allocation" {
    var denied = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    inline for (Modules) |Module| {
        const Cache = Module.Stage.ForBackend(Cpu).SetupCache;
        const options = Options{ .profile = .csp_q70_pow26, .aggregate_host_byte_limit = 1 << 20, .worker_options = .{ .worker_count = 0, .host_byte_limit = 1 << 20, .retained_scratch_limit = 0 } };
        try std.testing.expectError(error.InvalidWorkerBudget, Cache.init(denied.allocator(), options));
    }
    try std.testing.expectEqual(@as(usize, 0), denied.alloc_index);
}
