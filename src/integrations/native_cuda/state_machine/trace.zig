//! AIR-owned binding from state-machine semantics to a generic CUDA recipe.

const cpu_state_machine =
    @import("../../../examples/state_machine/input.zig");
const geometry_mod = @import("geometry.zig");
const circle_affine =
    @import("../../../backends/cuda/runtime/traces/circle_affine_state.zig");

pub const recipe = circle_affine.Recipe{
    .increment_coordinate = 0,
    .increment_value = 1,
    .indicator_first = 1,
    .indicator_default = 0,
};

pub fn prepare(
    session: anytype,
    destinations: circle_affine.Destinations,
    request: cpu_state_machine.Request,
) !circle_affine.PreparedLaunch {
    _ = try geometry_mod.admit(
        request,
        @import("stwo_core").pcs.PcsConfig.default(),
    );
    return circle_affine.prepare(
        session,
        destinations,
        .{ .log_n_rows = request.log_n_rows },
        .{
            .initial_state = .{
                request.initial_state[0].toU32(),
                request.initial_state[1].toU32(),
            },
        },
        recipe,
    );
}

pub fn generate(
    session: anytype,
    destinations: circle_affine.Destinations,
    request: cpu_state_machine.Request,
) !void {
    var launch = try prepare(session, destinations, request);
    try launch.launch(session);
}

test "state-machine binding contributes request values and AIR recipe" {
    const std = @import("std");
    const M31 = @import("stwo_core").fields.m31.M31;
    var session = TestSession{};
    try generate(
        &session,
        .{
            .preprocessed = testMatrix(0x1000, 32, 1),
            .main = testMatrix(0x4000, 32, 2),
        },
        .{
            .log_n_rows = 5,
            .initial_state = .{ M31.fromU64(17), M31.fromU64(23) },
        },
    );
    try std.testing.expectEqual(@as(u64, 1), session.launches);
}

const TestSession = struct {
    context: TestContext = .{},
    launches: u64 = 0,

    pub fn launchKernel(
        self: *TestSession,
        kernel: @import(
            "../../../backends/cuda/runtime/kernel.zig",
        ).Kernel,
        arguments: []const ?*anyopaque,
    ) @import("../../../backends/cuda/runtime/error.zig").Error!void {
        try kernel.validate();
        if (arguments.len != circle_affine.argument_count)
            return error.ArgumentCountMismatch;
        self.launches += 1;
    }
};

const TestContext = struct {
    active_stage: @import(
        "../../../backends/cuda/runtime/telemetry.zig",
    ).Stage = .trace_generation,

    pub fn requireStage(
        self: *TestContext,
        expected: @import(
            "../../../backends/cuda/runtime/telemetry.zig",
        ).Stage,
    ) @import("../../../backends/cuda/runtime/error.zig").Error!void {
        if (self.active_stage != expected) return error.StageOrderViolation;
    }

    pub fn deviceSlicePointer(
        _: *TestContext,
        comptime F: type,
        slice: anytype,
        minimum: usize,
    ) @import("../../../backends/cuda/runtime/error.zig").Error![*]F {
        if (minimum == 0 or slice.len < minimum or
            slice.owner != 7 or slice.generation != 11)
        {
            return error.InvalidDeviceAddress;
        }
        return @ptrFromInt(slice.address);
    }
};

fn testMatrix(
    address: usize,
    stride: usize,
    columns: usize,
) @import(
    "../../../backends/cuda/runtime/stages/common.zig",
).WordMatrix {
    return .{
        .storage = .{
            .address = address,
            .len = stride * columns,
            .owner = 7,
            .generation = 11,
        },
        .column_stride_words = stride,
    };
}
