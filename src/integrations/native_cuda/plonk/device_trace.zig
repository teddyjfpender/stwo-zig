//! Native Plonk binding to the generic indexed-recurrence trace primitive.

const common = @import("stwo_cuda_backend").runtime.stages.common;
const geometry_mod = @import("geometry.zig");
const trace = @import("trace.zig");

pub const Buffers = struct {
    preprocessed: common.WordMatrix,
    main: common.WordMatrix,
};

pub fn generate(
    session: anytype,
    buffers: Buffers,
    geometry: geometry_mod.Geometry,
) !void {
    try trace.generate(
        session,
        .{
            .preprocessed = buffers.preprocessed,
            .main = buffers.main,
        },
        geometry.statement,
    );
}

test "Plonk device trace binds the exact four-by-four destinations" {
    const std = @import("std");
    var session = TestSession{};
    const geometry = try geometry_mod.admit(
        .{ .log_n_rows = 5 },
        @import("stwo_core").pcs.PcsConfig.default(),
    );
    try generate(
        &session,
        .{
            .preprocessed = matrix(0x1000, 32),
            .main = matrix(0x4000, 32),
        },
        geometry,
    );
    try std.testing.expectEqual(@as(u64, 1), session.launches);
}

const indexed_recurrence = @import("stwo_cuda_backend").runtime.traces.indexed_recurrence;

const TestSession = struct {
    context: TestContext = .{},
    launches: u64 = 0,

    pub fn launchKernel(
        self: *TestSession,
        kernel: @import("stwo_cuda_backend").runtime.kernel.Kernel,
        arguments: []const ?*anyopaque,
    ) @import("stwo_cuda_backend").runtime.runtime_error.Error!void {
        try kernel.validate();
        if (arguments.len != indexed_recurrence.argument_count)
            return error.ArgumentCountMismatch;
        self.launches += 1;
    }
};

const TestContext = struct {
    active_stage: @import("stwo_cuda_backend").runtime.telemetry.Stage = .trace_generation,

    pub fn requireStage(
        self: *TestContext,
        expected: @import("stwo_cuda_backend").runtime.telemetry.Stage,
    ) @import("stwo_cuda_backend").runtime.runtime_error.Error!void {
        if (self.active_stage != expected) return error.StageOrderViolation;
    }

    pub fn deviceSlicePointer(
        _: *TestContext,
        comptime F: type,
        slice: anytype,
        minimum: usize,
    ) @import("stwo_cuda_backend").runtime.runtime_error.Error![*]F {
        if (minimum == 0 or slice.len < minimum or
            slice.owner != 7 or slice.generation != 11)
        {
            return error.InvalidDeviceAddress;
        }
        return @ptrFromInt(slice.address);
    }
};

fn matrix(address: usize, stride: usize) common.WordMatrix {
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
