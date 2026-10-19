//! Proof-free reconstruction of the SegmentV2 composition-control row.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const KeyV1 = @import("detached_segment_protocol_v1.zig").KeyV1;
const native_geometry = @import("detached_native_column_geometry_v1.zig");
const schedule = @import("air/verifier_schedule.zig");
const witness = @import("air/control_slice_witness.zig");
const public_control = @import("air/vm_public_logup_control_witness_v2.zig");
const public_air = @import("air/vm_public_logup_control_v2.zig");
const framework = @import("air/framework_interaction.zig");
const transcript_control = @import("air/control_witness.zig");

const Plans = struct {
    vm: schedule.Plan,
    recursion: schedule.Plan,
    sampled_count: u32,

    fn init(allocator: std.mem.Allocator, key: *const KeyV1) !Plans {
        try key.validate();
        if (key.profile != .recursive_q193_v1) return error.InvalidFixedControlProfile;
        var geometry = try native_geometry.init(
            allocator,
            key.native_descriptors,
            key.profile.nativePcsConfig().fri_config.log_blowup_factor,
        );
        defer geometry.deinit();
        const shape = try geometry.q193ScheduleShape(key.native_descriptors);
        var vm_plan = try schedule.Plan.initShape(allocator, try schedule.vmProgramSpec(0, 0), shape);
        errdefer vm_plan.deinit();
        const recursion_plan = try schedule.Plan.initShape(allocator, schedule.RECURSION_PROGRAM_SPEC_V1, shape);
        return .{ .vm = vm_plan, .recursion = recursion_plan, .sampled_count = shape.sampled_value_count };
    }

    fn deinit(self: *Plans) void {
        self.recursion.deinit();
        self.vm.deinit();
        self.* = undefined;
    }
};

pub fn fillFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    columns: *[witness.COLUMN_COUNT][]M31,
) !void {
    var plans = try Plans.init(allocator, key);
    defer plans.deinit();
    const placement = key.manifest.placements[19] orelse return error.InvalidFixedControlGeometry;
    if (placement.geometry.preprocessed_columns != columns.len or
        placement.geometry.log_size >= @bitSizeOf(usize))
        return error.InvalidFixedControlGeometry;
    const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
    for (columns) |column| if (column.len != size)
        return error.InvalidFixedControlGeometry;

    var preprocessing = try witness.CompositionPreprocessed.init(
        allocator,
        &plans.vm,
        plans.vm.spec.air_instruction_count,
        plans.sampled_count,
        &plans.recursion,
        plans.recursion.spec.air_instruction_count,
        plans.sampled_count,
    );
    defer preprocessing.deinit();
    if (preprocessing.log_size != placement.geometry.log_size)
        return error.InvalidFixedControlGeometry;
    try preprocessing.generateInto(columns, &plans.vm, &plans.recursion);
}

/// Row 17's control value is a main-column witness. Its nine Tree0 columns
/// depend only on the fixed VM schedule and the admitted row geometry.
pub fn fillPublicControlFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    columns: *[public_air.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    var plans = try Plans.init(allocator, key);
    defer plans.deinit();
    const placement = key.manifest.placements[17] orelse return error.InvalidFixedControlGeometry;
    if (placement.geometry.preprocessed_columns != columns.len or
        placement.geometry.log_size != public_control.TRACE_LOG_SIZE)
        return error.InvalidFixedControlGeometry;
    for (columns) |column| {
        if (column.len != public_control.TRACE_ROW_COUNT)
            return error.InvalidFixedControlGeometry;
        @memset(column, M31.zero());
    }
    const relay = public_control.ControlRelayV2{ .value = M31.zero() };
    const prepared = try public_control.preflight(&plans.vm, &relay);
    for (prepared.rows, 0..) |row, logical_row| {
        const values = row.values();
        const committed = framework.committedRow(logical_row, placement.geometry.log_size);
        for (columns, 0..) |column, index| column[committed] = values[1 + index];
    }
}

/// Row 0 commits the VM verifier's step metadata, including its terminal
/// marker. Draw values and proof frames never enter these columns.
pub fn fillTranscriptControlFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    columns: *[transcript_control.COLUMN_COUNT][]M31,
) !void {
    var plans = try Plans.init(allocator, key);
    defer plans.deinit();
    const placement = key.manifest.placements[0] orelse return error.InvalidFixedControlGeometry;
    if (placement.geometry.preprocessed_columns != columns.len or
        placement.geometry.log_size >= @bitSizeOf(usize))
        return error.InvalidFixedControlGeometry;
    const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
    if (plans.vm.steps.len > size) return error.InvalidFixedControlGeometry;
    for (columns) |column| {
        if (column.len != size) return error.InvalidFixedControlGeometry;
        @memset(column, M31.zero());
    }
    for (plans.vm.steps, 0..) |step, sequence| {
        const encoded = step.encode();
        const row = transcript_control.Row{
            .segment_mask = 1,
            .binary_mask = 0,
            .verifier_id = transcript_control.SEGMENT_VERIFIER_ID,
            .sequence = @intCast(sequence),
            .tag = encoded.tag,
            .args = encoded.args,
            .terminal_mask = @intFromBool(step.terminal()),
        };
        const values = row.values();
        const committed = framework.committedRow(sequence, placement.geometry.log_size);
        for (columns, values) |column, value| column[committed] = value;
    }
}
