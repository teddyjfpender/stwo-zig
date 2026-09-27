//! Policy/reporting/lifetime checks only. No received proof or fake Fresh is
//! constructed; actual producer and verifier bodies are retained separately.
const std = @import("std");
const Job = @import("block_v5_cpu_requester_job_v1.zig");
const Fold = @import("block_v5_cpu_scoped_job_fold_v1.zig");
const Coverage = @import("block_v5_recursive_coverage_plan_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;

test "cpu requester job: static recipe uses distinct files and preserves complete wrapper" {
    var old: [128]u8 = undefined;
    var complete: [128]u8 = undefined;
    var requester: [128]u8 = undefined;
    const expected = try Fold.path(&old, 7);
    try std.testing.expectEqualStrings(expected, try Fold.ForRecipe(.complete).path(&complete, 7));
    try std.testing.expectEqualStrings("block-v5-cpu-scoped-node-7.proof", expected);
    try std.testing.expectEqualStrings("block-v5-cpu-requester-node-7.proof", try Fold.ForRecipe(.requesters).path(&requester, 7));
    try std.testing.expect(!std.mem.eql(u8, expected, try Fold.ForRecipe(.requesters).path(&requester, 7)));
    try std.testing.expect(!Job.Owner.complete_block_authority and !Fold.Result.complete_block_authority);
}

test "cpu requester job: subtype availability reports actual capacity and caller adapters without granting source authority" {
    inline for (std.meta.fields(Coverage.Subtype)) |field| {
        const subtype: Coverage.Subtype = @enumFromInt(field.value);
        try std.testing.expectEqual(if (subtype == .native_fused_v2) Coverage.Adapter.missing_typed_adapter else Coverage.Adapter.existing_typed_adapter, Coverage.adapterForSubtype(subtype));
    }
    // A kind alone cannot distinguish legacy NativeV3 fusion from B5CT fusion.
    try std.testing.expectEqual(Coverage.Adapter.missing_typed_adapter, Coverage.adapter(.native_fused));
    try std.testing.expectEqual(Coverage.Adapter.existing_typed_adapter, Coverage.adapter(.caller_arithmetic));
    try std.testing.expectEqual(Coverage.Adapter.existing_typed_adapter, Coverage.adapter(.caller_fused));
    try std.testing.expectEqual(@as(usize, 10), Fold.Result.pending_source_authorities);
}

test "cpu requester job: invalid aggregate budget rejects before touching borrowed policies" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const a = std.testing.failing_allocator;
    const Caller = Job.ForBackend(@import("stwo_cpu_backend").CpuBackend);
    try std.testing.expectError(error.CpuRequesterJobResourceLimit, Caller.build(a, tmp.dir, undefined, undefined, &.{}, .diagnostic_q8_pow0, .{ .max_owned_bytes = 0 }, .{ .reconstruct = &.{} }));
}

fn emptyLifetime(a: std.mem.Allocator) !void {
    const budget = try Budget.createRetainingParent(a, 4096 + 2 * @sizeOf(Job.Owner));
    var owns_budget = true;
    errdefer if (owns_budget) budget.destroy();
    const owner = try budget.allocator().create(Job.Owner);
    owner.* = .{ .budget = budget };
    owns_budget = false;
    defer owner.deinit();
    try std.testing.expectError(error.CpuRequesterJobLifetime, owner.scoped());
    try std.testing.expectError(error.CpuRequesterJobLifetime, owner.rootFresh());
    try std.testing.expectError(error.CpuRequesterJobLifetime, owner.pins());
    try std.testing.expectError(error.CpuRequesterRootCaptureReleased, owner.source());
    owner.releaseRootCapture();
    Job.Owner.releaseRootCaptureCallback(owner);
    owner.releaseRootCapture();
    try std.testing.expectError(error.CpuRequesterRootCaptureReleased, owner.source());
}

test "cpu requester job: every empty owner allocation failure and repeated capture release preserves budget lifetime" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, emptyLifetime, .{});
}

test "cpu requester job: job allocation retains genuine aggregate allocator after coordinator release" {
    const parent = try Budget.create(std.testing.allocator, 16384 + 4 * @sizeOf(Job.Owner));
    var owns_parent = true;
    defer if (owns_parent) parent.destroy();
    const child = try Budget.createRetainingParent(parent.allocator(), 4096 + 2 * @sizeOf(Job.Owner));
    var owns_child = true;
    defer if (owns_child) child.destroy();
    parent.destroy();
    owns_parent = false;
    const owner = try child.allocator().create(Job.Owner);
    owner.* = .{ .budget = child };
    owns_child = false;
    defer owner.deinit();
    try std.testing.expectEqual(@as(usize, @sizeOf(Job.Owner)), child.snapshot().live_bytes);
    owner.releaseRootCapture();
    try std.testing.expectError(error.CpuRequesterRootCaptureReleased, owner.source());
}
