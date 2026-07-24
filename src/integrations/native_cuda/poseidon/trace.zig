//! AIR-owned binding from Native Poseidon semantics to a generic CUDA recipe.

const cpu_poseidon = @import("../../../examples/poseidon/input.zig");
const common = @import("../../../backends/cuda/runtime/stages/common.zig");
const runtime_error = @import("../../../backends/cuda/runtime/error.zig");
const m31_permutation =
    @import("../../../backends/cuda/runtime/traces/m31_permutation.zig");

pub const recipe = m31_permutation.Recipe{
    .initial_row_stride = cpu_poseidon.N_STATE,
    .initial_rep_stride = 1,
    .external_constant_base = 1234,
    .external_round_stride = 37,
    .internal_constant_base = 9876,
    .internal_round_stride = 17,
};

pub fn prepare(
    session: anytype,
    destination: common.WordMatrix,
    statement: cpu_poseidon.Statement,
) !m31_permutation.PreparedLaunch {
    const log_n_rows = try cpu_poseidon.logNRows(statement);
    return m31_permutation.prepare(
        session,
        destination,
        .{
            .log_n_rows = log_n_rows,
            .replication_count = cpu_poseidon.N_INSTANCES_PER_ROW,
            .half_full_rounds = cpu_poseidon.N_HALF_FULL_ROUNDS,
            .partial_rounds = cpu_poseidon.N_PARTIAL_ROUNDS,
        },
        recipe,
    );
}

pub fn generate(
    session: anytype,
    destination: common.WordMatrix,
    statement: cpu_poseidon.Statement,
) !void {
    var launch = try prepare(session, destination, statement);
    try launch.launch(session);
}

test "Poseidon binding contributes only statement geometry and AIR recipe" {
    const std = @import("std");
    var session = TestSession{};
    try generate(
        &session,
        .{
            .storage = .{
                .address = 0x1000,
                .len = 8 * cpu_poseidon.N_COLUMNS,
                .owner = 7,
                .generation = 11,
            },
            .column_stride_words = 8,
        },
        .{ .log_n_instances = 6 },
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
    ) runtime_error.Error!void {
        try kernel.validate();
        if (arguments.len != m31_permutation.argument_count)
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
    ) runtime_error.Error!void {
        if (self.active_stage != expected) return error.StageOrderViolation;
    }

    pub fn deviceSlicePointer(
        _: *TestContext,
        comptime F: type,
        slice: anytype,
        minimum: usize,
    ) runtime_error.Error![*]F {
        if (minimum == 0 or slice.len < minimum or
            slice.owner != 7 or slice.generation != 11)
        {
            return error.InvalidDeviceAddress;
        }
        return @ptrFromInt(slice.address);
    }
};
