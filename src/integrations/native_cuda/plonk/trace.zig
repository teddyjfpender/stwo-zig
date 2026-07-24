//! AIR-owned binding from Native Plonk semantics to a generic CUDA recipe.

const cpu_plonk = @import("../../../examples/plonk/input.zig");
const geometry_mod = @import("geometry.zig");
const indexed_recurrence =
    @import("../../../backends/cuda/runtime/traces/indexed_recurrence.zig");

pub const recipe = indexed_recurrence.Recipe{
    .index_base = 0,
    .index_step = 1,
    .preprocessed_constant = 1,
    .recurrence_seed0 = 1,
    .recurrence_seed1 = 1,
    .selector_default = 1,
    .selector_last = 0,
    .selector_penultimate = 1,
};

pub fn prepare(
    session: anytype,
    destinations: indexed_recurrence.Destinations,
    statement: cpu_plonk.Statement,
) !indexed_recurrence.PreparedLaunch {
    _ = try geometry_mod.admit(statement);
    return indexed_recurrence.prepare(
        session,
        destinations,
        .{ .log_n_rows = statement.log_n_rows },
        recipe,
    );
}

pub fn generate(
    session: anytype,
    destinations: indexed_recurrence.Destinations,
    statement: cpu_plonk.Statement,
) !void {
    var launch = try prepare(session, destinations, statement);
    try launch.launch(session);
}

test "Plonk binding contributes only statement geometry and AIR recipe" {
    const std = @import("std");
    var session = TestSession{};
    try generate(
        &session,
        .{
            .preprocessed = testMatrix(0x1000, 32),
            .main = testMatrix(0x4000, 32),
        },
        .{ .log_n_rows = 5 },
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
        if (arguments.len != indexed_recurrence.argument_count)
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

fn testMatrix(address: usize, stride: usize) @import(
    "../../../backends/cuda/runtime/stages/common.zig",
).WordMatrix {
    return .{
        .storage = .{
            .address = address,
            .len = stride * indexed_recurrence.column_count,
            .owner = 7,
            .generation = 11,
        },
        .column_stride_words = stride,
    };
}
