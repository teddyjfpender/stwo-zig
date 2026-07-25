//! Exact Poseidon previous/current OODS policy.

const core = @import("stwo_core");
const field = @import("../../../backends/cuda/abi/field.zig");
const oods_batches = @import("../common/oods_batches.zig");
const geometry_mod = @import("geometry.zig");
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
        @memset(&result.coefficient_log_sizes, geometry.log_n_rows);
        @memset(
            &result.offset_points,
            rawPoint(CirclePointM31.identity()),
        );
        @memset(&result.fold_counts, 0);
        result.output_indices = topology.sample_output_indices;

        const step = CanonicCoset
            .new(geometry.composition_log_rows)
            .coset_value
            .step;
        const previous = CirclePointM31.identity().sub(step);
        for (0..4) |coordinate| {
            result.offset_points[1292 + coordinate * 2] =
                rawPoint(previous);
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

test "exact OODS policy binds four previous-coordinate samples" {
    const geometry = try geometry_mod.admit(
        .{ .log_n_instances = 13 },
        core.pcs.PcsConfig.default(),
    );
    const policy = Policy.init(geometry);
    const identity = rawPoint(CirclePointM31.identity());
    var previous_count: usize = 0;
    for (policy.offset_points, 0..) |point, index| {
        if (!@import("std").meta.eql(point, identity)) {
            previous_count += 1;
            try @import("std").testing.expect(
                index >= 1292 and index <= 1298 and index % 2 == 0,
            );
        }
    }
    try @import("std").testing.expectEqual(@as(usize, 4), previous_count);
}
