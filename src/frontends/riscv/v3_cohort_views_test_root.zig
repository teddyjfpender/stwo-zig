test {
    _ = @import("recursion/segment_leaf_wrapper_cohort_views_v3.zig");
}

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const views_mod = @import("recursion/segment_leaf_wrapper_cohort_views_v3.zig");
const direct = @import("recursion/air/segment_leaf_wrapper_roster_direct_v4.zig");
const v2 = @import("recursion/air/segment_outer_adapter_manifest_v2.zig");
const catalog = @import("recursion/air/segment_outer_typed_catalog_v2.zig");
const program_mod = @import("recursion/ethereum_leaf_link_program_v3.zig");
const fixture = @import("wrapper_roster_v3_test_root.zig");
const call_buffer = @import("recursion/segment_leaf_wrapper_cohort_calls_v3.zig");
const provider = @import("recursion/segment_leaf_wrapper_cohort_provider_v3.zig");

test "direct 47-row PlanV4 maps V2 main columns with only old row34 scratch" {
    const allocator = std.testing.allocator;
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    const base = try v2.assemble(&source_catalog, fixture.authorityIds());
    var program = try program_mod.ProgramV3.init(allocator);
    defer program.deinit();
    const plan = try direct.Plan.build(allocator, &base, &program, .{ .program_words = 100, .base_poseidon_calls = 1193 });
    const destination = try allocator.alloc([]M31, plan.total_main_columns);
    defer allocator.free(destination);
    for (plan.placements) |maybe_item| {
        const item = maybe_item.?;
        const rows = @as(usize, 1) << @intCast(item.geometry.log_size);
        for (destination[item.main_offset..][0..item.geometry.main_columns]) |*column| {
            column.* = try allocator.alloc(M31, rows);
            @memset(column.*, M31.zero());
        }
    }
    defer for (destination) |column| allocator.free(column);
    var views = try views_mod.Views.initForPlan(allocator, &base, &plan, destination, direct.MAIN_TREE_INDEX);
    defer views.deinit();
    try std.testing.expectEqual(@as(usize, base.total_main_columns), views.columns.len);
    const old_regular = base.placements[18].?.main_offset;
    const new_regular = plan.placements[18].?.main_offset;
    views.columns[old_regular][0] = M31.fromCanonical(19);
    try std.testing.expectEqual(@as(u32, 19), destination[new_regular][0].toU32());
    const old_provider = base.placements[34].?.main_offset;
    const new_provider = plan.placements[34].?.main_offset;
    views.columns[old_provider][0] = M31.fromCanonical(29);
    try std.testing.expectEqual(@as(u32, 29), views.old_provider_scratch[0].toU32());
    try std.testing.expect(destination[new_provider][0].isZero());
    try std.testing.expectEqual(
        @as(usize, base.placements[34].?.geometry.main_columns) << @intCast(base.placements[34].?.geometry.log_size),
        views.old_provider_scratch.len,
    );

    const calls = try allocator.alloc(call_buffer.Call, plan.poseidon_calls.total);
    defer allocator.free(calls);
    for (calls, 0..) |*call, i| call.* = .{ .input = @splat(@intCast(i + 1)), .io = true };
    const parts = [_][]const call_buffer.Call{
        calls[0..1193], calls[1193..1270], calls[1270..1277], calls[1277..1290],
    };
    var buffer = try call_buffer.Buffer.init(allocator, &parts);
    defer buffer.deinit();
    const writer = try provider.Writer.initForDirectPlan(allocator, &plan, &buffer, &parts);
    try std.testing.expectEqual(plan.placements[34].?.geometry.log_size, try writer.logSize());
    const wrong_parts = [_][]const call_buffer.Call{
        calls[0..1193], calls[1193..1269], calls[1269..1277], calls[1277..1290],
    };
    var wrong_buffer = try call_buffer.Buffer.init(allocator, &wrong_parts);
    defer wrong_buffer.deinit();
    try std.testing.expectError(
        error.DirectProviderCallLayoutMismatch,
        provider.Writer.initForDirectPlan(allocator, &plan, &wrong_buffer, &wrong_parts),
    );
}
