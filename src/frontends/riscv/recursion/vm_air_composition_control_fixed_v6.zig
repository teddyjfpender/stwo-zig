//! Shape-owned row-19 preprocessing for the direct leaf template.
//!
//! Both verifier plans must be selected before child proof admission. This
//! module rebuilds the exact core writer's nine columns; it never adopts a
//! captured preprocessed column or a child-supplied schedule digest.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const schedule = @import("air/verifier_schedule.zig");
const control = @import("air/control_slice_witness.zig");
const framework = @import("air/framework_interaction.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const ROW: u8 = 19;
pub const COLUMN_COUNT = control.COLUMN_COUNT;

pub const Fixed = struct {
    rows: control.CompositionPreprocessed,
    vm_plan_id: [8]u32,
    recursion_plan_id: [8]u32,

    pub fn init(
        allocator: std.mem.Allocator,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
    ) !Fixed {
        try vm.validate();
        try recursion.validate();
        const vm_sampled = try sampledCount(vm);
        if (vm_sampled != try sampledCount(recursion))
            return error.CompositionSampledCountMismatchV6;
        return .{
            .rows = try control.CompositionPreprocessed.init(
                allocator,
                vm,
                vm.spec.air_instruction_count,
                vm_sampled,
                recursion,
                recursion.spec.air_instruction_count,
                vm_sampled,
            ),
            .vm_plan_id = vm.authority_digest,
            .recursion_plan_id = recursion.authority_digest,
        };
    }

    pub fn deinit(self: *Fixed) void {
        self.rows.deinit();
        self.* = undefined;
    }

    /// Writes committed Tree0 order, including zero padding. The plan checks
    /// precede every destination write, so a changed plan or retained row
    /// cannot silently define a different fixed key.
    pub fn writePhysical(
        self: *const Fixed,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
        columns: [][]M31,
    ) !void {
        if (!std.meta.eql(self.vm_plan_id, vm.authority_digest) or
            !std.meta.eql(self.recursion_plan_id, recursion.authority_digest))
            return error.CompositionPlanMismatchV6;
        try self.rows.validateAgainst(vm, recursion);
        if (columns.len != COLUMN_COUNT or self.rows.log_size >= @bitSizeOf(usize))
            return error.CompositionColumnGeometryMismatchV6;
        const capacity = @as(usize, 1) << @intCast(self.rows.log_size);
        for (columns) |column| {
            if (column.len != capacity) return error.CompositionColumnGeometryMismatchV6;
            for (column) |value| if (!value.isZero())
                return error.CompositionDestinationNotFreshV6;
        }
        for (self.rows.rows, 0..) |row, logical| {
            const values = row.values();
            const physical = framework.committedRow(logical, self.rows.log_size);
            for (values, columns) |value, column| column[physical] = value;
        }
    }
};

fn sampledCount(plan: *const schedule.Plan) !u32 {
    var count: ?u32 = null;
    for (plan.steps) |step| switch (step) {
        .assert_composition => |assertion| {
            if (count != null) return error.DuplicateCompositionAssertionV6;
            count = assertion.sampled_value_count;
        },
        else => {},
    };
    return count orelse error.MissingCompositionAssertionV6;
}

test "V6 row19 physical columns match core for two same-shape plans and a larger shape" {
    const allocator = std.testing.allocator;
    const profile = @import("segment_profile.zig");
    var first_same_shape_digest: ?[8]u32 = null;
    for ([_]u32{ 16, 16, 32 }, 0..) |word_count, fixture_index| {
        var plans = try profile.initPlans(allocator, word_count, word_count);
        defer plans.vm.deinit();
        defer plans.recursion.deinit();
        var fixed = try Fixed.init(allocator, &plans.vm, &plans.recursion);
        defer fixed.deinit();
        if (fixture_index == 0) first_same_shape_digest = fixed.vm_plan_id;
        if (fixture_index == 1) try std.testing.expectEqualDeep(first_same_shape_digest.?, fixed.vm_plan_id);
        const capacity = @as(usize, 1) << @intCast(fixed.rows.log_size);
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const physical = try a.alloc([]M31, COLUMN_COUNT);
        var raw: [COLUMN_COUNT][]M31 = undefined;
        for (physical, &raw) |*destination, *source| {
            destination.* = try a.alloc(M31, capacity);
            @memset(destination.*, M31.zero());
            source.* = try a.alloc(M31, capacity);
        }
        try fixed.writePhysical(&plans.vm, &plans.recursion, physical);
        try fixed.rows.generateInto(&raw, &plans.vm, &plans.recursion);
        for (physical, raw) |destination, source| {
            for (source, 0..) |expected, logical| {
                const actual = destination[framework.committedRow(logical, fixed.rows.log_size)];
                try std.testing.expectEqual(expected.toU32(), actual.toU32());
            }
        }
        fixed.rows.rows[0].tag += 1;
        try std.testing.expectError(error.ScheduleAuthorityMismatch, fixed.writePhysical(&plans.vm, &plans.recursion, physical));
        fixed.rows.rows[0].tag -= 1;
        var other = try profile.initPlans(allocator, word_count + 1, word_count);
        defer other.vm.deinit();
        defer other.recursion.deinit();
        try std.testing.expectError(error.CompositionPlanMismatchV6, fixed.writePhysical(&other.vm, &plans.recursion, physical));
    }
}
