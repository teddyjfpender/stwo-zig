//! Proof-free reconstruction of detached q193 query-routing Tree0 rows 20–22.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const KeyV1 = @import("detached_segment_protocol_v1.zig").KeyV1;
const authority = @import("detached_segment_authority_boundary_v1.zig");
const geometry_mod = @import("detached_native_column_geometry_v1.zig");
const segment = @import("segment_profile.zig");
const bits_air = @import("air/query_bits.zig");
const bits_witness = @import("air/query_bits_witness.zig");
const mapping_air = @import("air/query_mapping.zig");
const mapping_witness = @import("air/query_mapping_witness.zig");
const root_air = @import("air/merkle_root.zig");
const root_witness = @import("air/merkle_root_witness.zig");

const Owned = struct {
    geometry: geometry_mod.Geometry,
    shape: @import("air/verifier_schedule.zig").ScheduleShape,

    fn init(descriptors: authority.DescriptorsV1, allocator: std.mem.Allocator) !Owned {
        var geometry = try geometry_mod.init(allocator, descriptors, segment.circuitProfile().log_blowup_factor);
        errdefer geometry.deinit();
        return .{ .shape = try geometry.q193ScheduleShape(descriptors), .geometry = geometry };
    }

    fn deinit(self: *Owned) void {
        self.geometry.deinit();
        self.* = undefined;
    }

    fn references(self: *const Owned) !struct { mapping: mapping_witness.Reference, bits: bits_witness.Reference, root: root_witness.Reference } {
        const profile = segment.circuitProfile();
        const lane = mapping_witness.LaneProfile{
            .query_count = profile.query_count,
            .lifting_log_size = profile.lifting_log_size,
            .tree_heights = &self.shape.tree_heights,
            .fri_fold_widths = &segment.FOLD_WIDTHS,
        };
        const mapping = try mapping_witness.Reference.seal(lane, lane);
        const root_lane = root_witness.LaneProfile{
            .query_count = profile.query_count,
            .trace_tree_count = self.shape.tree_heights.len,
            .fri_layer_count = segment.FOLD_WIDTHS.len,
        };
        return .{
            .mapping = mapping,
            .bits = try mapping.queryBitsReference(),
            .root = try root_witness.Reference.seal(root_lane, root_lane),
        };
    }
};

fn checkColumns(comptime count: usize, expected_log_size: u32, log_size: u32, columns: *[count][]M31) !void {
    if (expected_log_size != log_size or log_size >= @bitSizeOf(usize))
        return error.InvalidFixedQueryGeometry;
    const size = @as(usize, 1) << @intCast(log_size);
    for (columns) |column| if (column.len != size)
        return error.InvalidFixedQueryGeometry;
}

pub fn fillBitsFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    columns: *[bits_witness.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    try key.validate();
    if (key.profile != .recursive_q193_v1) return error.InvalidFixedQueryGeometry;
    const placement = key.manifest.placements[20] orelse return error.InvalidFixedQueryGeometry;
    if (placement.geometry.preprocessed_columns != columns.len)
        return error.InvalidFixedQueryGeometry;
    return fillBits(allocator, key.native_descriptors, placement.geometry.log_size, columns);
}

pub fn fillMappingFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    columns: *[mapping_witness.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    try key.validate();
    if (key.profile != .recursive_q193_v1) return error.InvalidFixedQueryGeometry;
    const placement = key.manifest.placements[21] orelse return error.InvalidFixedQueryGeometry;
    if (placement.geometry.preprocessed_columns != columns.len)
        return error.InvalidFixedQueryGeometry;
    return fillMapping(allocator, key.native_descriptors, placement.geometry.log_size, columns);
}

pub fn fillRootFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    columns: *[root_witness.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    try key.validate();
    if (key.profile != .recursive_q193_v1) return error.InvalidFixedQueryGeometry;
    const placement = key.manifest.placements[22] orelse return error.InvalidFixedQueryGeometry;
    if (placement.geometry.preprocessed_columns != columns.len)
        return error.InvalidFixedQueryGeometry;
    return fillRoot(allocator, key.native_descriptors, placement.geometry.log_size, columns);
}

fn fillBits(allocator: std.mem.Allocator, descriptors: authority.DescriptorsV1, log_size: u32, columns: *[bits_witness.PREPROCESSED_COLUMN_COUNT][]M31) !void {
    var owner = try Owned.init(descriptors, allocator);
    defer owner.deinit();
    const refs = try owner.references();
    var preprocessing = try bits_witness.Preprocessed.init(allocator, refs.bits);
    defer preprocessing.deinit();
    try checkColumns(columns.len, preprocessing.log_size, log_size, columns);
    var definition = try bits_air.build(allocator);
    defer definition.deinit();
    const binding = try bits_witness.Binding.canonical(&definition);
    const executor = try bits_witness.Executor.init(&definition, &binding);
    try executor.generatePreprocessedInto(&preprocessing, refs.bits, columns);
}

fn fillMapping(allocator: std.mem.Allocator, descriptors: authority.DescriptorsV1, log_size: u32, columns: *[mapping_witness.PREPROCESSED_COLUMN_COUNT][]M31) !void {
    var owner = try Owned.init(descriptors, allocator);
    defer owner.deinit();
    const refs = try owner.references();
    var preprocessing = try mapping_witness.Preprocessed.init(allocator, refs.mapping);
    defer preprocessing.deinit();
    try checkColumns(columns.len, preprocessing.log_size, log_size, columns);
    var definition = try mapping_air.build(allocator);
    defer definition.deinit();
    const binding = try mapping_witness.Binding.canonical(&definition);
    const executor = try mapping_witness.Executor.init(&definition, &binding);
    try executor.generatePreprocessedInto(&preprocessing, refs.mapping, columns);
}

fn fillRoot(allocator: std.mem.Allocator, descriptors: authority.DescriptorsV1, log_size: u32, columns: *[root_witness.PREPROCESSED_COLUMN_COUNT][]M31) !void {
    var owner = try Owned.init(descriptors, allocator);
    defer owner.deinit();
    const refs = try owner.references();
    var preprocessing = try root_witness.Preprocessed.init(allocator, refs.root);
    defer preprocessing.deinit();
    try checkColumns(columns.len, preprocessing.log_size, log_size, columns);
    var definition = try root_air.build(allocator);
    defer definition.deinit();
    const binding = try root_witness.Binding.canonical(&definition);
    const executor = try root_witness.Executor.init(&definition, &binding);
    try executor.generatePreprocessedInto(&preprocessing, refs.root, columns);
}

fn expectCensus(
    comptime count: usize,
    allocator: std.mem.Allocator,
    descriptors: authority.DescriptorsV1,
    log_size: u32,
    expected_hex: []const u8,
    comptime fillFn: anytype,
) !void {
    const size = @as(usize, 1) << @intCast(log_size);
    const words = try allocator.alloc(M31, size * count);
    defer allocator.free(words);
    var columns: [count][]M31 = undefined;
    for (&columns, 0..) |*column, index| column.* = words[index * size ..][0..size];
    try fillFn(allocator, descriptors, log_size, &columns);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    for (columns) |column| {
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
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqual(expected, hash.finalResult());
}

test "q193 query bits, mapping, and root fixed rows follow native geometry" {
    const allocator = std.testing.allocator;
    const descriptors = @import("tests/q193_native_census_fixture.zig").DESCRIPTORS;
    try expectCensus(bits_witness.PREPROCESSED_COLUMN_COUNT, allocator, descriptors, 10, "a6aec2dfd05b26b9b56945d0c0c0d3036f877e0e56a181e8ff7204a19e07bcb1", fillBits);
    try expectCensus(mapping_witness.PREPROCESSED_COLUMN_COUNT, allocator, descriptors, 14, "a24a01d530535a6ede39ef1ef770d1301e8bcea40040613bd944e1d1e1cd70f3", fillMapping);
    try expectCensus(root_witness.PREPROCESSED_COLUMN_COUNT, allocator, descriptors, 5, "02894e264cf3bfa88cac858653c55bb04196f87aed2c63707d21846da06867c2", fillRoot);
}
