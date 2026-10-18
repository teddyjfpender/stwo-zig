//! Proof-free reconstruction of detached q193 trace-Merkle Tree0 row 23.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const KeyV1 = @import("detached_segment_protocol_v1.zig").KeyV1;
const authority = @import("detached_segment_authority_boundary_v1.zig");
const geometry_mod = @import("detached_native_column_geometry_v1.zig");
const plans_mod = @import("detached_q193_key_schedule_v1.zig");
const segment = @import("segment_profile.zig");
const trace_air = @import("air/trace_merkle.zig");
const witness = @import("air/trace_merkle_witness.zig");

pub fn fillFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    columns: *[witness.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    try key.validate();
    if (key.profile != .recursive_q193_v1) return error.InvalidFixedTraceGeometry;
    const placement = key.manifest.placements[23] orelse return error.InvalidFixedTraceGeometry;
    if (placement.geometry.preprocessed_columns != columns.len)
        return error.InvalidFixedTraceGeometry;
    return fill(allocator, key.native_descriptors, placement.geometry.log_size, columns);
}

fn fill(
    allocator: std.mem.Allocator,
    descriptors: authority.DescriptorsV1,
    log_size: u32,
    columns: *[witness.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    var geometry = try geometry_mod.init(allocator, descriptors, segment.circuitProfile().log_blowup_factor);
    defer geometry.deinit();
    var plans = try plans_mod.Owned.init(allocator, descriptors);
    defer plans.deinit();
    var trees: [4]witness.TreeProfile = undefined;
    for (&trees, geometry.pcs_trees, plans.shape.tree_heights) |*tree, pcs_tree, height|
        tree.* = .{ .height = height, .column_log_sizes = pcs_tree.column_log_sizes };
    const lane = witness.LaneProfile{
        .query_count = segment.circuitProfile().query_count,
        .lifting_log_size = segment.circuitProfile().lifting_log_size,
        .trees = &trees,
        .fri_fold_widths = &segment.FOLD_WIDTHS,
    };
    const reference = try witness.Reference.seal(lane, &plans.vm, lane, &plans.recursive);
    var preprocessing = try witness.Preprocessed.init(allocator, reference);
    defer preprocessing.deinit();
    if (preprocessing.log_size != log_size or log_size >= @bitSizeOf(usize))
        return error.InvalidFixedTraceGeometry;
    const size = @as(usize, 1) << @intCast(log_size);
    for (columns) |column| if (column.len != size)
        return error.InvalidFixedTraceGeometry;
    var definition = try trace_air.build(allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    try executor.generatePreprocessedInto(&preprocessing, reference, columns);
}

test "q193 trace-Merkle fixed row 23 follows key-only query geometry" {
    const allocator = std.testing.allocator;
    const size: usize = 1 << 16;
    const count = witness.PREPROCESSED_COLUMN_COUNT;
    const words = try allocator.alloc(M31, size * count);
    defer allocator.free(words);
    var columns: [count][]M31 = undefined;
    var view: [count][]const M31 = undefined;
    for (&columns, &view, 0..) |*column, *source, index| {
        column.* = words[index * size ..][0..size];
        source.* = column.*;
    }
    try fill(allocator, @import("tests/q193_native_census_fixture.zig").DESCRIPTORS, 16, &columns);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    for (view) |column| {
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, column.len, .little);
        hash.update(&length);
        for (column) |word| {
            var field: [4]u8 = undefined;
            std.mem.writeInt(u32, &field, word.toU32(), .little);
            hash.update(&field);
        }
    }
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "a87e30ed1c0e0550a05a65154be54ef00cde1871db0fe8d3758f0a73d6618405");
    try std.testing.expectEqual(expected, hash.finalResult());
}
