const std = @import("std");
const core = @import("stwo_core");
const Masks = @import("../block_v6_caller_joint_masks_v1.zig");
const Q = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
fn originalPoint(column: Masks.Column, current: Point, offset: isize) Point {
    const native_step = core.poly.circle.CanonicCoset.new(column.mask_log).step();
    const step = Point{ .x = Q.fromBase(native_step.x), .y = Q.fromBase(native_step.y) };
    return current.add(step.mulSigned(offset));
}
test "caller joint mask union exactly restores every ordered original layout pair" {
    const a = std.testing.allocator;
    for (std.meta.tags(Masks.Layout)) |left_tag| for (std.meta.tags(Masks.Layout)) |right_tag| {
        const left = Masks.Column{ .trace_log = 5, .mask_log = if (left_tag == .current_keccak_final) 5 else 7, .layout = left_tag };
        const right = Masks.Column{ .trace_log = 5, .mask_log = if (right_tag == .current_keccak_final) 5 else 7, .layout = right_tag };
        var plan = try Masks.Owned.init(a, &.{left}, &.{right}, 7, .{});
        defer plan.deinit();
        try plan.requireCanonical(&.{left}, &.{right}, 7, .{});
        const routes = plan.columnRoutes(0);
        try std.testing.expectEqual(left.layout.sampleCount(), routes.left.len);
        try std.testing.expectEqual(right.layout.sampleCount(), routes.right.len);
        for ([_]Q{ Q.fromU32Unchecked(7, 11, 13, 17), Q.fromU32Unchecked(19, 23, 29, 31) }) |seed| {
            const current = try core.circle.secureFieldPointFromRandomSeedChecked(seed);
            for ([_]Masks.Column{ left, right }, [_][]const u8{ routes.left, routes.right }) |source, source_routes| {
                for (source.layout.offsets(), source_routes) |offset, route| {
                    try std.testing.expect(plan.column(0)[route].point(current).eql(originalPoint(source, current, offset)));
                }
            }
            for (plan.column(0), 0..) |coordinate, i| for (plan.column(0)[0..i]) |previous| try std.testing.expect(!coordinate.point(current).eql(previous.point(current)));
        }
    };
}
test "caller joint mask union preserves distinct physical and common steps and rejects mutated routes" {
    const a = std.testing.allocator;
    const physical = Masks.Column{ .trace_log = 5, .mask_log = 5, .layout = .current_keccak_final };
    const common = Masks.Column{ .trace_log = 5, .mask_log = 7, .layout = .current_keccak_final_composition };
    var plan = try Masks.Owned.init(a, &.{physical}, &.{common}, 7, .{});
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 3), plan.column(0).len);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1 }, plan.columnRoutes(0).left);
    try std.testing.expectEqualSlices(u8, &.{ 0, 2 }, plan.columnRoutes(0).right);
    plan.routes[3] = 1;
    try std.testing.expectError(error.UntrustedCallerJointMasks, plan.requireCanonical(&.{physical}, &.{common}, 7, .{}));
    plan.routes[3] = 2;
    plan.coordinates[2].mask_log = 5;
    try std.testing.expectError(error.UntrustedCallerJointMasks, plan.requireCanonical(&.{physical}, &.{common}, 7, .{}));
    plan.coordinates[2].mask_log = 7;
    plan.right[0].layout = .current_keccak_final;
    try std.testing.expectError(error.UntrustedCallerJointMasks, plan.requireCanonical(&.{physical}, &.{common}, 7, .{}));
    var wrong = common;
    wrong.mask_log = 5;
    try std.testing.expectError(error.InvalidCallerJointMasks, Masks.Owned.init(a, &.{physical}, &.{wrong}, 7, .{}));
    wrong = common;
    wrong.trace_log = 6;
    try std.testing.expectError(error.UnsharedCallerJointColumn, Masks.Owned.init(a, &.{physical}, &.{wrong}, 7, .{}));
}
test "caller joint masks keep empty columns and reject limits before allocation" {
    const none = Masks.Column{ .trace_log = 13, .mask_log = 7, .layout = .none };
    var plan = try Masks.Owned.init(std.testing.allocator, &.{none}, &.{none}, 7, .{});
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 0), plan.column(0).len);
    try std.testing.expectEqual(@as(usize, 0), plan.columnRoutes(0).left.len);
    var forbidden_buffer: [0]u8 = .{};
    var forbidden = std.heap.FixedBufferAllocator.init(&forbidden_buffer);
    try std.testing.expectError(error.CallerJointMaskResourceLimit, Masks.Owned.init(forbidden.allocator(), &.{none}, &.{none}, 7, .{ .max_bytes = 0 }));
    var sampled = none;
    sampled.layout = .current;
    try std.testing.expectError(error.InvalidCallerJointMasks, Masks.Owned.init(forbidden.allocator(), &.{sampled}, &.{sampled}, 7, .{}));
    const wide = Masks.Column{ .trace_log = 5, .mask_log = 7, .layout = .keccak_state };
    try std.testing.expectError(error.CallerJointMaskResourceLimit, Masks.Owned.init(forbidden.allocator(), &.{wide}, &.{wide}, 7, .{ .max_union_samples = 1 }));
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocations, .{});
}
fn allocations(a: std.mem.Allocator) !void {
    const left = Masks.Column{ .trace_log = 5, .mask_log = 7, .layout = .keccak_state };
    const right = Masks.Column{ .trace_log = 5, .mask_log = 5, .layout = .current_keccak_final };
    var plan = try Masks.Owned.init(a, &.{left}, &.{right}, 7, .{});
    defer plan.deinit();
}

test "caller joint Keccak geometry census and vertical area budget" {
    const A = @import("../../air/guest_precompile/keccakf_authority.zig");
    const Trace = @import("../../air/guest_precompile/keccakf_trace.zig");
    const W = @import("../../air/guest_precompile/keccakf_witness.zig");
    const R = @import("../../air/guest_precompile/keccakf_relations.zig");
    const I = @import("../../air/guest_precompile/keccakf_interaction_plan.zig");
    const C = @import("../../air/guest_precompile/keccakf_component.zig");
    const width = Trace.Layout.preprocessed_columns + Trace.Layout.main_columns + I.interaction_column_count;
    const cells = width * (@as(usize, 1) << Trace.minimum_log_size);
    const sampled = Trace.Layout.preprocessed_columns + Trace.Layout.main_columns + 2 * R.io_arity +
        W.state_cell_count * (C.STATE_MASK_OFFSETS.len - 1) + 2 * I.interaction_column_count;
    try std.testing.expectEqual(@as(usize, 6399), width);
    try std.testing.expectEqual(@as(usize, 204768), cells);
    try std.testing.expectEqual(@as(usize, 18781), sampled);
    // Hypothetical schedules exclude boundaries/buses. These are upper bounds
    // on equal-area column budgets, never a qualified vertical AIR geometry.
    try std.testing.expectEqual(@as(usize, 2), A.geometry.operations_per_slot);
    try std.testing.expectEqual(@as(usize, 29), W.row_count);
    const lane_rows = std.math.ceilPowerOfTwoAssert(usize, A.round_count * (A.width_bits / A.lane_bits));
    const separate_lane_rows = std.math.ceilPowerOfTwoAssert(usize, A.geometry.operations_per_slot * A.round_count * (A.width_bits / A.lane_bits));
    const bit_rows = std.math.ceilPowerOfTwoAssert(usize, A.round_count * A.width_bits);
    try std.testing.expectEqual(@as(usize, 199), cells / lane_rows);
    try std.testing.expectEqual(@as(usize, 99), cells / separate_lane_rows);
    try std.testing.expectEqual(@as(usize, 3), cells / bit_rows);
}
