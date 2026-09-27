//! Focused preflight guards and actual-body retention only; no proof runs.
const std = @import("std");
const Completion = @import("block_v5_cpu_recursive_completion_v1.zig");
const Driver = @import("block_v5_cpu_driver_common_v1.zig").ForCapacity(true);
fn options() Driver.Options {
    var result: Driver.Options = .{
        .profile = .csp_q70_pow26,
        .collection = undefined,
        .max_roster_entries = 1,
        .store = undefined,
        .forest = .{ .profile = .csp_q70_pow26, .lane_count = 1, .total_host_limit = 1024, .max_execution_count = 1, .max_proof_bytes = 1024 },
        .manifest = undefined,
        .metadata = undefined,
        .cache = .{ .profile = .csp_q70_pow26, .aggregate_host_byte_limit = 1024, .worker_options = .{ .worker_count = 1, .host_byte_limit = 1024, .retained_scratch_limit = 0 } },
        .workers = 1,
        .total_host_limit = 4096,
        .families = .{ .coordinators = 1, .capacity = 4, .reservation_limit = 2048, .family_reservation = 1024 },
    };
    result.collection.readonly = null;
    return result;
}
test "cpu recursive completion: required typed families source PAGE and exclusive topology reject before collection" {
    var selected = options();
    selected.recursive_completion = .{};
    try std.testing.expectError(error.RecursiveCompletionRequiresRecursiveFamilies, selected.validate());
    selected.recursive_families = .{};
    try std.testing.expectError(error.RecursiveCompletionRequiresSourcePages, selected.validate());
    selected.source_pages = .{};
    selected.scoped_job = .{};
    try std.testing.expectError(error.ConflictingCpuRecursiveCompletion, selected.validate());
    selected.scoped_job = null;
    selected.collection.ordinary.memory.register_custody_mode = 0;
    selected.collection.caller.register_custody_mode = 1;
    try std.testing.expectError(error.RecursiveCompletionRequiresRegisterWindows, selected.validate());
    selected.collection.ordinary.memory.register_custody_mode = 1;
    selected.collection.caller.register_custody_mode = 0;
    try std.testing.expectError(error.RecursiveCompletionRequiresRegisterWindows, selected.validate());
}
test "cpu recursive completion: aggregate and all four family resource policies fail before undefined sources" {
    var limits = Completion.Options{};
    limits.max_owned_bytes = 0;
    try std.testing.expectError(error.CpuRecursiveCompletionResourceLimit, Completion.publish(std.testing.allocator, undefined, undefined, limits));
    limits = .{};
    limits.requester.max_owned_bytes = 0;
    try std.testing.expectError(error.CpuRequesterJobResourceLimit, limits.validate());
    limits = .{};
    limits.page.max_live_bytes = 0;
    try std.testing.expectError(error.InvalidPageForestPolicyLimits, limits.validate());
    limits = .{};
    limits.memory.max_live_bytes = 0;
    try std.testing.expectError(error.InvalidRamForestOwnerLimits, limits.validate());
    limits = .{};
    limits.final.max_live_bytes = 0;
    try std.testing.expectError(error.FinalJobResourceLimit, limits.validate());
    inline for (.{ "page", "memory", "final" }) |field| {
        limits = .{};
        @field(limits, field).transcript_capacity /= 2;
        try std.testing.expectError(error.UntrustedCpuRecursiveCompletionGeometry, Completion.publish(std.testing.failing_allocator, undefined, undefined, limits));
    }
    try (Completion.Options{}).requireDependencies(true, true, false);
}
test "cpu recursive completion: capacity selection exposes stage timings and durable final pin with explicit pending authority" {
    const Legacy = @import("block_v5_cpu_driver_common_v1.zig").ForCapacity(false);
    try std.testing.expect(@FieldType(Legacy.Options, "recursive_completion") == void);
    try std.testing.expect(@FieldType(Driver.Options, "recursive_completion") == ?Completion.Options);
    try std.testing.expect(@FieldType(Driver.Result, "recursive_completion") == ?Completion.Report);
    try std.testing.expect(!Completion.Report.complete_block_authority);
    try std.testing.expect(!Completion.Report.reusable_setup);
    try std.testing.expect(@hasField(Completion.Report, "stage_ns"));
    try std.testing.expect(@hasField(Completion.Report, "final_manifest"));
}

test "cpu recursive completion: original lane limits reject mismatch before any guest or prove loop" {
    var lanes = @import("block_v5_ram_lanes_stage_v1.zig").Limits{};
    lanes.proof.max_row_log = 22;
    lanes.plan.max_instances = 123;
    const completion = (Completion.Options{}).withOriginalMemory(lanes);
    try completion.requireOriginalMemory(lanes);
    var rejected = completion;
    rejected.memory.catalogue.ram.proof.max_row_log += 1;
    try std.testing.expectError(error.UntrustedCpuRecursiveCompletionMemory, rejected.requireOriginalMemory(lanes));
    rejected = completion;
    rejected.memory.plan.lane.max_instances += 1;
    try std.testing.expectError(error.UntrustedCpuRecursiveCompletionMemory, rejected.requireOriginalMemory(lanes));
}

test "cpu recursive completion: installed product selection derives matching limits and preserves canonical security" {
    const Product = @import("block_v5_cpu_capacity_product_options_v1.zig");
    const original = Product.options(.csp_q70_pow26, 67, 4);
    const selected = try Product.optionsWithRecursiveCompletion(.csp_q70_pow26, 67, 4);
    try std.testing.expectEqualDeep(original.collection, selected.collection);
    try std.testing.expectEqualDeep(original.store, selected.store);
    try std.testing.expectEqualDeep(original.profile.config(), selected.profile.config());
    try std.testing.expectEqual(@as(usize, 70), selected.profile.config().fri_config.n_queries);
    try std.testing.expectEqual(@as(u32, 26), selected.profile.config().pow_bits);
    try std.testing.expect(selected.recursive_families != null and selected.source_pages != null and selected.recursive_completion != null and selected.scoped_job == null);
    try std.testing.expectError(error.RecursiveCompletionRequiresCapacityStack, @import("block_v5_cpu_product_options_common_v1.zig").ForCapacity(false).optionsWithRecursiveCompletion(.csp_q70_pow26, 67, 4));
}

test "cpu recursive completion: report totals reject either overflow within the completion rollback scope" {
    const maximum = Completion.ProofTotals{ .bytes = std.math.maxInt(u64), .files = std.math.maxInt(usize) };
    const before = Completion.ProofTotals{ .bytes = maximum.bytes - 17, .files = maximum.files - 3 };
    try std.testing.expectEqualDeep(maximum, try before.add(.{ .bytes = 17, .files = 3 }));
    try std.testing.expectError(error.Overflow, before.add(.{ .bytes = 18, .files = 0 }));
    try std.testing.expectError(error.Overflow, before.add(.{ .bytes = 0, .files = 4 }));
    try std.testing.expectEqualDeep(maximum, try maximum.add(.{}));
}
