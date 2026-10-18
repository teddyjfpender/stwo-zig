//! Key-only reconstruction of detached q193 FRI leaf and node fixed rows.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const KeyV1 = @import("detached_segment_protocol_v1.zig").KeyV1;
const segment = @import("segment_profile.zig");
const leaf_air = @import("air/fri_merkle_leaf.zig");
const leaf_witness = @import("air/fri_merkle_leaf_witness.zig");
const node_air = @import("air/fri_merkle_node.zig");
const node_witness = @import("air/fri_merkle_node_witness.zig");
const anchor_air = @import("air/fri_merkle_anchor.zig");
const anchor_witness = @import("air/fri_merkle_anchor_witness.zig");
const authority = @import("detached_segment_authority_boundary_v1.zig");
const control_air = @import("air/fri_verifier_control.zig");
const control_witness = @import("air/fri_verifier_control_witness.zig");
const query_mapping_witness = @import("air/query_mapping_witness.zig");

const KeySchedule = @import("detached_q193_key_schedule_v1.zig").Owned;

const ReferenceOwner = struct {
    allocator: std.mem.Allocator,
    layers: []leaf_witness.LayerProfile,
    reference: leaf_witness.Reference,

    fn init(allocator: std.mem.Allocator) !ReferenceOwner {
        const profile = segment.circuitProfile();
        try profile.validate();
        const layers = try allocator.alloc(leaf_witness.LayerProfile, profile.fold_widths.len);
        errdefer allocator.free(layers);
        var folded_bits: u32 = 0;
        for (profile.fold_widths, layers) |width, *layer| {
            const fold_step = std.math.log2_int(u32, width);
            const leaf_log_size: u32 = if (fold_step > 1)
                @min(fold_step, std.math.log2_int(u32, leaf_witness.PACKED_LEAF_SIZE))
            else
                0;
            layer.* = .{
                .width = width,
                .tree_height = std.math.sub(u32, profile.lifting_log_size - folded_bits, leaf_log_size) catch
                    return error.InvalidFixedFriGeometry,
            };
            folded_bits = std.math.add(u32, folded_bits, fold_step) catch
                return error.InvalidFixedFriGeometry;
        }
        const lane = leaf_witness.LaneProfile{
            .query_count = profile.query_count,
            .lifting_log_size = profile.lifting_log_size,
            .layers = layers,
        };
        return .{
            .allocator = allocator,
            .layers = layers,
            .reference = try leaf_witness.Reference.seal(lane, lane),
        };
    }

    fn deinit(self: *ReferenceOwner) void {
        self.allocator.free(self.layers);
        self.* = undefined;
    }
};

pub fn fillLeafFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    columns: *[leaf_witness.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    try key.validate();
    if (key.profile != .recursive_q193_v1) return error.InvalidFixedFriGeometry;
    const placement = key.manifest.placements[25] orelse return error.InvalidFixedFriGeometry;
    if (placement.geometry.preprocessed_columns != columns.len)
        return error.InvalidFixedFriGeometry;
    return fillLeaf(allocator, placement.geometry.log_size, columns);
}

pub fn fillNodeFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    columns: *[node_witness.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    try key.validate();
    if (key.profile != .recursive_q193_v1) return error.InvalidFixedFriGeometry;
    const placement = key.manifest.placements[26] orelse return error.InvalidFixedFriGeometry;
    if (placement.geometry.preprocessed_columns != columns.len)
        return error.InvalidFixedFriGeometry;
    return fillNode(allocator, placement.geometry.log_size, columns);
}

pub fn fillAnchorFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    columns: *[anchor_witness.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    try key.validate();
    if (key.profile != .recursive_q193_v1) return error.InvalidFixedFriGeometry;
    const placement = key.manifest.placements[27] orelse return error.InvalidFixedFriGeometry;
    if (placement.geometry.preprocessed_columns != columns.len)
        return error.InvalidFixedFriGeometry;
    return fillAnchor(allocator, key.native_descriptors, placement.geometry.log_size, columns);
}

pub fn fillControlFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    columns: *[control_witness.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    try key.validate();
    if (key.profile != .recursive_q193_v1) return error.InvalidFixedFriGeometry;
    const placement = key.manifest.placements[28] orelse return error.InvalidFixedFriGeometry;
    if (placement.geometry.preprocessed_columns != columns.len)
        return error.InvalidFixedFriGeometry;
    return fillControl(allocator, key.native_descriptors, placement.geometry.log_size, columns);
}

fn fillLeaf(
    allocator: std.mem.Allocator,
    log_size: u32,
    columns: *[leaf_witness.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    var owner = try ReferenceOwner.init(allocator);
    defer owner.deinit();
    var preprocessing = try leaf_witness.Preprocessed.init(allocator, owner.reference);
    defer preprocessing.deinit();
    try checkColumns(log_size, preprocessing.log_size, columns);
    var definition = try leaf_air.build(allocator);
    defer definition.deinit();
    const binding = try leaf_witness.Binding.canonical(&definition);
    const executor = try leaf_witness.Executor.init(&definition, &binding);
    try executor.generatePreprocessedInto(&preprocessing, owner.reference, columns);
}

fn fillNode(
    allocator: std.mem.Allocator,
    log_size: u32,
    columns: *[node_witness.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    var owner = try ReferenceOwner.init(allocator);
    defer owner.deinit();
    var preprocessing = try node_witness.Preprocessed.init(allocator, owner.reference);
    defer preprocessing.deinit();
    try checkColumns(log_size, preprocessing.log_size, columns);
    var definition = try node_air.build(allocator);
    defer definition.deinit();
    const binding = try node_witness.Binding.canonical(&definition);
    const executor = try node_witness.Executor.init(&definition, &binding);
    try executor.generatePreprocessedInto(&preprocessing, owner.reference, columns);
}

fn fillAnchor(
    allocator: std.mem.Allocator,
    descriptors: authority.DescriptorsV1,
    log_size: u32,
    columns: *[anchor_witness.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    var plans = try KeySchedule.init(allocator, descriptors);
    defer plans.deinit();
    var owner = try ReferenceOwner.init(allocator);
    defer owner.deinit();
    var preprocessing = try anchor_witness.Preprocessed.init(allocator, owner.reference, &plans.vm, &plans.recursive);
    defer preprocessing.deinit();
    try checkColumns(log_size, preprocessing.log_size, columns);
    var definition = try anchor_air.build(allocator);
    defer definition.deinit();
    const binding = try anchor_witness.Binding.canonical(&definition);
    const executor = try anchor_witness.Executor.init(&definition, &binding);
    try executor.generatePreprocessedInto(&preprocessing, owner.reference, &plans.vm, &plans.recursive, columns);
}

fn fillControl(
    allocator: std.mem.Allocator,
    descriptors: authority.DescriptorsV1,
    log_size: u32,
    columns: *[control_witness.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    var plans = try KeySchedule.init(allocator, descriptors);
    defer plans.deinit();
    const mapping = query_mapping_witness.LaneProfile{
        .query_count = segment.circuitProfile().query_count,
        .lifting_log_size = segment.circuitProfile().lifting_log_size,
        .tree_heights = &plans.shape.tree_heights,
        .fri_fold_widths = &segment.FOLD_WIDTHS,
    };
    const reference = try control_witness.Reference.seal(
        .{ .plan = &plans.vm, .mapping = mapping },
        .{ .plan = &plans.recursive, .mapping = mapping },
    );
    var preprocessing = try control_witness.Preprocessed.init(allocator, reference);
    defer preprocessing.deinit();
    try checkColumns(log_size, preprocessing.log_size, columns);
    var definition = try control_air.build(allocator);
    defer definition.deinit();
    const binding = try control_witness.Binding.canonical(&definition);
    const executor = try control_witness.Executor.init(&definition, &binding);
    try executor.generatePreprocessedInto(&preprocessing, reference, columns);
}

fn checkColumns(log_size: u32, actual_log_size: u32, columns: anytype) !void {
    if (log_size != actual_log_size or log_size >= @bitSizeOf(usize))
        return error.InvalidFixedFriGeometry;
    const size = @as(usize, 1) << @intCast(log_size);
    for (columns) |column| if (column.len != size)
        return error.InvalidFixedFriGeometry;
}

fn censusDigest(columns: []const []const M31) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    for (columns) |column| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, column.len, .little);
        hash.update(&bytes);
        for (column) |word| {
            var field: [4]u8 = undefined;
            std.mem.writeInt(u32, &field, word.toU32(), .little);
            hash.update(&field);
        }
    }
    return hash.finalResult();
}

test "q193 FRI leaf and node fixed rows regenerate without proof input" {
    const allocator = std.testing.allocator;
    inline for (.{
        .{ .count = leaf_witness.PREPROCESSED_COLUMN_COUNT, .log_size = @as(u32, 16), .fill_fn = fillLeaf, .digest = "06f503f16ff5ce3bb169cdc4c3c4ae56287c6e379e7c2418e899393f1134106f" },
        .{ .count = node_witness.PREPROCESSED_COLUMN_COUNT, .log_size = @as(u32, 14), .fill_fn = fillNode, .digest = "1f00fde274c72a921f13e5d5a8986c3010c8e2bc15f9dcdcfe3766d8350631cd" },
    }) |case| {
        const size = @as(usize, 1) << @intCast(case.log_size);
        const words = try allocator.alloc(M31, size * case.count);
        defer allocator.free(words);
        var columns: [case.count][]M31 = undefined;
        var view: [case.count][]const M31 = undefined;
        for (&columns, &view, 0..) |*column, *source, index| {
            column.* = words[index * size ..][0..size];
            source.* = column.*;
        }
        try case.fill_fn(allocator, case.log_size, &columns);
        var expected: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, case.digest);
        try std.testing.expectEqual(expected, censusDigest(&view));
    }
}

test "q193 FRI anchor fixed row follows the key-derived verifier schedule" {
    const allocator = std.testing.allocator;
    const size: usize = 1 << 12;
    const count = anchor_witness.PREPROCESSED_COLUMN_COUNT;
    const words = try allocator.alloc(M31, size * count);
    defer allocator.free(words);
    var columns: [count][]M31 = undefined;
    var view: [count][]const M31 = undefined;
    for (&columns, &view, 0..) |*column, *source, index| {
        column.* = words[index * size ..][0..size];
        source.* = column.*;
    }
    try fillAnchor(allocator, @import("tests/q193_native_census_fixture.zig").DESCRIPTORS, 12, &columns);
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "1bc7af6872362f9181926c71ad6797eb93d985b8ebf968aa82b7593171c333a9");
    try std.testing.expectEqual(expected, censusDigest(&view));
}

test "q193 FRI control fixed row follows key-derived query mapping" {
    const allocator = std.testing.allocator;
    const size: usize = 1 << 12;
    const count = control_witness.PREPROCESSED_COLUMN_COUNT;
    const words = try allocator.alloc(M31, size * count);
    defer allocator.free(words);
    var columns: [count][]M31 = undefined;
    var view: [count][]const M31 = undefined;
    for (&columns, &view, 0..) |*column, *source, index| {
        column.* = words[index * size ..][0..size];
        source.* = column.*;
    }
    try fillControl(allocator, @import("tests/q193_native_census_fixture.zig").DESCRIPTORS, 12, &columns);
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "306100ea327d534c5dad7b624b95fd4f7082264f7c289e1f6a5a4c5f0398bcb1");
    try std.testing.expectEqual(expected, censusDigest(&view));
}
