//! Why the V10 direct-leaf key cannot admit fixed rows 23 and 24 yet.
//!
//! The key authenticates aggregate core geometry, but not the ordered trace
//! column log sizes or the PCS sample-point layout. Both are verifier policy,
//! not facts that may be selected from a captured child proof. This module
//! deliberately has no fixed writer or proof activation until a successor key
//! seals those values and independently rebuilds the PCS graph.
const std = @import("std");
const v9 = @import("air/segment_leaf_wrapper_template_v9.zig");
const profile_mod = @import("air/segment_leaf_wrapper_template_v6.zig");
const schedule = @import("air/verifier_schedule.zig");
const trace = @import("air/trace_merkle_witness.zig");
const pcs = @import("air/pcs_deep_circuit.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const TEMPLATE_ADMISSION_AVAILABLE = false;

pub fn requireFixedRows23And24Authority(_: *const v9.TemplateManifestV9) error{OrderedTraceColumnAndPcsLayoutNotSealed}!void {
    return error.OrderedTraceColumnAndPcsLayoutNotSealed;
}

test "row23 has distinct fixed columns under the same V9 core geometry" {
    const allocator = std.testing.allocator;
    var plans = try @import("segment_profile.zig").initPlans(allocator, 16, 16);
    defer plans.vm.deinit();
    defer plans.recursion.deinit();
    const core = try profile_mod.testFrozenCoreProfileV6();
    const mapping = try core.reference();
    // Both layouts retain the real q193 tree column counts and maxima. The
    // schedule's table_count and queried-value count therefore stay equal.
    var first_logs = [_]u32{21} ** 38;
    first_logs[0] = 20;
    var swapped_logs = first_logs;
    std.mem.swap(u32, &swapped_logs[0], &swapped_logs[1]);
    const main_logs = [_]u32{21} ** 625;
    const interaction_logs = [_]u32{21} ** 200;
    const composition_logs = [_]u32{21} ** 8;
    const other_logs = [_][]const u32{ &main_logs, &interaction_logs, &composition_logs };
    const heights = core.vm.tree_heights[0..core.vm.tree_count];
    var first_trees: [4]trace.TreeProfile = undefined;
    var swapped_trees: [4]trace.TreeProfile = undefined;
    for (&first_trees, &swapped_trees, heights, 0..) |*first, *swapped, height, tree| {
        first.* = .{ .height = height, .column_log_sizes = if (tree == 0) &first_logs else other_logs[tree - 1] };
        swapped.* = .{ .height = height, .column_log_sizes = if (tree == 0) &swapped_logs else other_logs[tree - 1] };
    }
    const first_lane = trace.LaneProfile{
        .query_count = core.vm.query_count,
        .lifting_log_size = core.vm.lifting_log_size,
        .trees = &first_trees,
        .fri_fold_widths = core.vm.fri_fold_widths[0..core.vm.fri_count],
    };
    const swapped_lane = trace.LaneProfile{
        .query_count = core.vm.query_count,
        .lifting_log_size = core.vm.lifting_log_size,
        .trees = &swapped_trees,
        .fri_fold_widths = core.vm.fri_fold_widths[0..core.vm.fri_count],
    };
    const first_ref = try trace.Reference.seal(first_lane, &plans.vm, first_lane, &plans.recursion);
    const swapped_ref = try trace.Reference.seal(swapped_lane, &plans.vm, swapped_lane, &plans.recursion);
    try first_ref.validateQueryMapping(mapping);
    try swapped_ref.validateQueryMapping(mapping);
    var first = try trace.Preprocessed.init(allocator, first_ref);
    defer first.deinit();
    var swapped = try trace.Preprocessed.init(allocator, swapped_ref);
    defer swapped.deinit();
    try std.testing.expectEqual(first.log_size, swapped.log_size);
    try std.testing.expectEqual(first.rows.len, swapped.rows.len);
    try std.testing.expect(!std.meta.eql(first.authority_digest, swapped.authority_digest));
    try std.testing.expect(!TEMPLATE_ADMISSION_AVAILABLE);
    try std.testing.expect(!PRODUCTION_PROOF_ACTIVATION);
}

test "row24 PCS sample-point order is missing from V9 geometry" {
    const allocator = std.testing.allocator;
    const logs = [_]u32{5};
    const trees = [_]pcs.TreeProfile{.{ .column_log_sizes = &logs }};
    const current_first = [_]pcs.SamplePointLayout{.current_previous};
    const previous_first = [_]pcs.SamplePointLayout{.previous_current};
    const first_profile = pcs.Profile{
        .trees = &trees,
        .sample_layouts = &current_first,
        .lifting_log_size = 5,
        .log_blowup_factor = 1,
        .query_count = 1,
    };
    var second_profile = first_profile;
    second_profile.sample_layouts = &previous_first;
    try first_profile.validate();
    try second_profile.validate();
    try std.testing.expectEqual(try first_profile.sampleCount(), try second_profile.sampleCount());
    try std.testing.expect(!std.meta.eql(first_profile.identityDigest(), second_profile.identityDigest()));
    var first = try pcs.build(allocator, first_profile);
    defer first.deinit();
    var second = try pcs.build(allocator, second_profile);
    defer second.deinit();
    try std.testing.expect(!std.meta.eql(first.identity_digest, second.identity_digest));
}
