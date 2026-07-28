//! Exact previous/current OODS policy and copy-free resident batches.

const std = @import("std");
const core = @import("stwo_core");
const field = @import("stwo_cuda_backend").abi.field;
const column = @import("stwo_cuda_backend").runtime.column;
const oods_batches = @import("../common/oods_batches.zig");
const resident_views = @import("../common/resident_views.zig");
const geometry_mod = @import("geometry.zig");
const layout = @import("layout.zig");
const topology = @import("topology.zig");

const CirclePointM31 = core.circle.CirclePointM31;
const CanonicCoset = core.poly.circle.CanonicCoset;

pub const Batch = oods_batches.Batch;
pub const max_batches = oods_batches.max_batches;

pub const Policy = struct {
    coefficient_log_sizes: [geometry_mod.source_columns]u32,
    offset_points: [geometry_mod.sampled_mask_points]field.CirclePointBaseField,
    fold_counts: [geometry_mod.sampled_mask_points]u32,
    output_indices: [geometry_mod.sampled_mask_points]u32,

    pub fn init(geometry: geometry_mod.Geometry) Policy {
        var result: Policy = undefined;
        @memset(
            &result.coefficient_log_sizes,
            geometry.statement.log_size,
        );
        @memset(
            &result.offset_points,
            rawPoint(CirclePointM31.identity()),
        );
        @memset(&result.fold_counts, 0);
        result.output_indices = topology.sample_output_indices;

        const step = CanonicCoset
            .new(geometry.statement.log_size + 1)
            .coset_value
            .step;
        const previous = CirclePointM31.identity().sub(step);
        for (result.offset_points[15..19]) |*offset| {
            offset.* = rawPoint(previous);
        }
        return result;
    }
};

pub fn buildBatches(
    prepared: anytype,
    ingress: anytype,
    views: anytype,
    storage: *[max_batches]Batch,
) ![]const Batch {
    return oods_batches.buildExplicit(
        prepared,
        ingress,
        views,
        &topology.sample_batches,
        storage,
    );
}

fn rawPoint(value: CirclePointM31) field.CirclePointBaseField {
    return .{ .x = value.x.toU32(), .y = value.y.toU32() };
}

test "exact OODS execution order preserves canonical source/sample pairs" {
    const geometry = try geometry_mod.admit(
        .{ .log_size = 16, .log_step = 3, .offset = 5 },
        core.pcs.PcsConfig.default(),
    );
    const policy = Policy.init(geometry);
    const execution_sources = [_]u32{
        0,  1,  2,  3,  4,  5,  6,
        7,  8,  9,  10, 11, 12, 13,
        14, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22,
    };
    for (
        execution_sources,
        policy.output_indices,
    ) |source, output| {
        try std.testing.expectEqual(
            source,
            topology.sample_source_indices[output],
        );
    }
    const identity = rawPoint(CirclePointM31.identity());
    try std.testing.expect(!std.meta.eql(policy.offset_points[15], identity));
    try std.testing.expect(std.meta.eql(policy.offset_points[19], identity));
}

test "exact OODS batches reuse cumulative coefficient columns without copy" {
    const geometry = try geometry_mod.admit(
        .{ .log_size = 4, .log_step = 2, .offset = 3 },
        core.pcs.PcsConfig.default(),
    );
    var logical = try layout.Layout.init(std.testing.allocator, geometry);
    defer logical.deinit(std.testing.allocator);
    const policy = Policy.init(geometry);

    const trees = [_]resident_views.TraceTree{
        testTree(.preprocessed, 0x10_0000, 7, 16),
        testTree(.main, 0x20_0000, 4, 16),
        testTree(.interaction, 0x30_0000, 4, 16),
        testTree(.composition, 0x40_0000, 8, 16),
    };
    const views = .{
        .trace = .{
            .trees = try resident_views.TraceTrees.init(&trees),
        },
        .oods = .{
            .parameter = device(field.SecureField, 0x50_0000, 1),
            .offset_points = device(
                field.CirclePointBaseField,
                0x51_0000,
                geometry_mod.sampled_mask_points,
            ),
            .fold_counts = device(
                u32,
                0x52_0000,
                geometry_mod.sampled_mask_points,
            ),
            .output_indices = device(
                u32,
                0x53_0000,
                geometry_mod.sampled_mask_points,
            ),
            .sample_points = device(
                field.SecureCirclePoint,
                0x54_0000,
                geometry_mod.sampled_mask_points,
            ),
            .evaluation_points = device(
                field.SecureCirclePoint,
                0x55_0000,
                geometry_mod.sampled_mask_points,
            ),
            .folding_factors = device(
                field.SecureField,
                0x56_0000,
                geometry_mod.sampled_mask_points * 4,
            ),
            .reduce_a = device(
                field.SecureField,
                0x57_0000,
                geometry_mod.sampled_mask_points,
            ),
            .reduce_b = device(
                field.SecureField,
                0x58_0000,
                geometry_mod.sampled_mask_points,
            ),
            .sampled_values = device(
                field.SecureField,
                0x59_0000,
                geometry_mod.sampled_mask_points,
            ),
        },
        .quotient = .{
            .challenge = device(field.SecureField, 0x5a_0000, 1),
        },
    };
    const ingress = .{
        .coefficient_log_sizes = policy.coefficient_log_sizes[0..],
        .oods_offset_points = policy.offset_points[0..],
        .oods_fold_counts = policy.fold_counts[0..],
        .oods_output_indices = policy.output_indices[0..],
    };
    const prepared = .{ .logical = logical };
    var storage: [max_batches]Batch = undefined;
    const batches = try buildBatches(
        &prepared,
        ingress,
        views,
        &storage,
    );
    try std.testing.expectEqual(@as(usize, 5), batches.len);
    try std.testing.expectEqual(
        batches[2].coefficients.storage.address,
        batches[3].coefficients.storage.address,
    );
    try std.testing.expectEqual(@as(usize, 11), batches[2].first_sample);
    try std.testing.expectEqual(@as(usize, 15), batches[3].first_sample);
}

fn testTree(
    role: layout.TraceRole,
    address: usize,
    columns: usize,
    rows: usize,
) resident_views.TraceTree {
    return .{
        .role = role,
        .coefficients = .{
            .storage = device(u32, address, columns * rows),
            .column_stride_words = rows,
        },
        .evaluations = .{
            .storage = device(
                u32,
                address + 0x2000,
                columns * rows * 2,
            ),
            .column_stride_words = rows * 2,
        },
        .column_log_sizes = device(
            u32,
            address + 0x4000,
            columns,
        ),
        .merkle_hashes = device(
            field.Blake2sHash,
            address + 0x5000,
            1,
        ),
        .merkle_layers = device(
            field.MerkleLayerDescriptor,
            address + 0x6000,
            1,
        ),
    };
}

fn device(
    comptime T: type,
    address: usize,
    len: usize,
) column.DeviceSlice(T) {
    return .{
        .address = address,
        .len = len,
        .owner = 7,
        .generation = 11,
    };
}
