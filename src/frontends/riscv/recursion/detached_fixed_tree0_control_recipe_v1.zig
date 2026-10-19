//! Proof-free reconstruction of the SegmentV2 composition-control row.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const KeyV1 = @import("detached_segment_protocol_v1.zig").KeyV1;
const native_geometry = @import("detached_native_column_geometry_v1.zig");
const schedule = @import("air/verifier_schedule.zig");
const witness = @import("air/control_slice_witness.zig");

pub fn fillFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    columns: *[witness.COLUMN_COUNT][]M31,
) !void {
    try key.validate();
    if (key.profile != .recursive_q193_v1) return error.InvalidFixedControlProfile;
    const placement = key.manifest.placements[19] orelse return error.InvalidFixedControlGeometry;
    if (placement.geometry.preprocessed_columns != columns.len or
        placement.geometry.log_size >= @bitSizeOf(usize))
        return error.InvalidFixedControlGeometry;
    const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
    for (columns) |column| if (column.len != size)
        return error.InvalidFixedControlGeometry;

    var geometry = try native_geometry.init(
        allocator,
        key.native_descriptors,
        key.profile.nativePcsConfig().fri_config.log_blowup_factor,
    );
    defer geometry.deinit();
    const shape = try geometry.q193ScheduleShape(key.native_descriptors);
    var vm_plan = try schedule.Plan.initShape(
        allocator,
        try schedule.vmProgramSpec(0, 0),
        shape,
    );
    defer vm_plan.deinit();
    var recursion_plan = try schedule.Plan.initShape(
        allocator,
        schedule.RECURSION_PROGRAM_SPEC_V1,
        shape,
    );
    defer recursion_plan.deinit();
    var preprocessing = try witness.CompositionPreprocessed.init(
        allocator,
        &vm_plan,
        vm_plan.spec.air_instruction_count,
        shape.sampled_value_count,
        &recursion_plan,
        recursion_plan.spec.air_instruction_count,
        shape.sampled_value_count,
    );
    defer preprocessing.deinit();
    if (preprocessing.log_size != placement.geometry.log_size)
        return error.InvalidFixedControlGeometry;
    try preprocessing.generateInto(columns, &vm_plan, &recursion_plan);
}
