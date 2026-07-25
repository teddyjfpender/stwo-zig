//! Strict-AOT boundary for the exact mixed-height State Machine v2 trace.

const common = @import(
    "../../../backends/cuda/runtime/stages/common.zig",
);
const geometry_mod = @import("geometry.zig");

pub const Buffers = struct {
    main: common.WordMatrix,
    relation_sources: common.WordMatrix,
};

/// The legacy affine kernel emits one uniform component plus an indicator
/// column. State v2 requires two differently sized components and no
/// preprocessed column, so reusing that kernel would produce a plausible but
/// invalid proof. CUDA execution remains fail-closed until its exact AOT trace
/// kernel is built and pinned on a CUDA host.
pub fn generate(
    _: anytype,
    _: Buffers,
    _: geometry_mod.Geometry,
) !void {
    return error.StateMachineV2AotUnavailable;
}

test "State v2 trace generation does not reuse the legacy AOT recipe" {
    const std = @import("std");
    const empty = Buffers{
        .main = .{
            .storage = .{
                .address = 0,
                .len = 0,
                .owner = 0,
            },
            .column_stride_words = 0,
        },
        .relation_sources = .{
            .storage = .{
                .address = 0,
                .len = 0,
                .owner = 0,
            },
            .column_stride_words = 0,
        },
    };
    try std.testing.expectError(
        error.StateMachineV2AotUnavailable,
        generate({}, empty, undefined),
    );
}
