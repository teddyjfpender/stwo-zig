//! Proof-free reconstruction of the SegmentV2 VM composition input row.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const KeyV1 = @import("detached_segment_protocol_v1.zig").KeyV1;
const graph = @import("air/composition_circuit.zig");
const vm_graph = @import("vm_air_composition_key_graph_v2.zig");
const air = @import("air/vm_air_composition_input.zig");
const witness = @import("air/vm_air_composition_input_witness.zig");

pub fn fillFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    columns: *[witness.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    try key.validate();
    if (key.profile != .recursive_q193_v1) return error.InvalidFixedVmInputProfile;
    const placement = key.manifest.placements[18] orelse return error.InvalidFixedVmInputGeometry;
    if (placement.geometry.preprocessed_columns != columns.len or
        placement.geometry.log_size >= @bitSizeOf(usize))
        return error.InvalidFixedVmInputGeometry;
    const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
    for (columns) |column| if (column.len != size)
        return error.InvalidFixedVmInputGeometry;

    var vm = try vm_graph.buildFromDescriptors(
        allocator,
        key.native_descriptors,
        key.profile.nativePcsConfig(),
    );
    defer vm.deinit();
    const lane = vm.lane();
    const reference = try graph.Reference.authenticate(
        lane,
        &.{},
        &.{},
        graph.computeReferenceDigest(lane, &.{}, &.{}),
    );
    var preprocessing = try witness.Preprocessed.initFromReference(allocator, &reference);
    defer preprocessing.deinit();
    if (preprocessing.log_size != placement.geometry.log_size)
        return error.InvalidFixedVmInputGeometry;
    var definition = try air.build(allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    try executor.generatePreprocessedInto(&preprocessing, columns);
}
