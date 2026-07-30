//! Exact mixed-height OODS batches for State Machine v2.

const oods_batches = @import("../common/oods_batches.zig");
const geometry_mod = @import("geometry.zig");
const topology = @import("topology.zig");

pub const Batch = oods_batches.Batch;
pub const max_batches = oods_batches.max_batches;

pub fn factorCount(geometry: geometry_mod.Geometry) !usize {
    return geometry_mod.oodsFactorCount(geometry);
}

pub fn scratchCount(geometry: geometry_mod.Geometry) !usize {
    return geometry_mod.oodsScratchCount(geometry);
}

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

test "State v2 compact OODS arenas account for both heights" {
    const std = @import("std");
    const geometry = try geometry_mod.admit(
        .{
            .log_n_rows = 16,
            .initial_state = .{
                @import("stwo_core").fields.m31.M31.fromU64(9),
                @import("stwo_core").fields.m31.M31.fromU64(3),
            },
        },
        @import("stwo_core").pcs.PcsConfig.default(),
    );
    try std.testing.expectEqual(
        @as(usize, 18 * 16 + 10 * 15),
        try factorCount(geometry),
    );
    try std.testing.expectEqual(
        @as(usize, 18 * 16 + 10 * 8),
        try scratchCount(geometry),
    );
}
