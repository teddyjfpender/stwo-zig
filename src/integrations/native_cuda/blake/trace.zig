//! AIR-owned binding from Native Blake semantics to a generic CUDA recipe.

const geometry_mod = @import("geometry.zig");
const common = @import("../../../backends/cuda/runtime/stages/common.zig");
const runtime_error = @import("../../../backends/cuda/runtime/error.zig");
const seeded_xorshift =
    @import("../../../backends/cuda/runtime/traces/seeded_xorshift.zig");

pub const recipe = seeded_xorshift.Recipe{
    .seed_offset = 1,
    .left_shift = 13,
    .right_shift = 7,
    .final_left_shift = 17,
    .group_mix = 0x9e37_79b9_7f4a_7c15,
    .item_mix = 0x517c_c1b7_2722_0a95,
};

pub fn prepare(
    session: anytype,
    destination: common.WordMatrix,
    statement: @import("../../../examples/blake.zig").Statement,
) !seeded_xorshift.PreparedLaunch {
    _ = try geometry_mod.admit(statement);
    return seeded_xorshift.prepare(
        session,
        destination,
        .{
            .log_n_rows = statement.log_n_rows,
            .group_count = statement.n_rounds,
            .columns_per_group = geometry_mod.columns_per_round,
        },
        recipe,
    );
}

pub fn generate(
    session: anytype,
    destination: common.WordMatrix,
    statement: @import("../../../examples/blake.zig").Statement,
) !void {
    var launch = try prepare(session, destination, statement);
    try launch.launch(session);
}

test "Blake binding contributes only statement geometry and AIR recipe" {
    const std = @import("std");
    var session = TestSession{};
    const statement = @import("../../../examples/blake.zig").Statement{
        .log_n_rows = 3,
        .n_rounds = 2,
    };
    try generate(
        &session,
        .{
            .storage = .{
                .address = 0x1000,
                .len = 8 * 192,
                .owner = 7,
                .generation = 11,
            },
            .column_stride_words = 8,
        },
        statement,
    );
    try std.testing.expectEqual(@as(u64, 1), session.launches);
}

const TestSession = struct {
    context: TestContext = .{},
    launches: u64 = 0,

    pub fn launchKernel(
        self: *TestSession,
        kernel: @import("../../../backends/cuda/runtime/kernel.zig").Kernel,
        arguments: []const ?*anyopaque,
    ) runtime_error.Error!void {
        try kernel.validate();
        if (arguments.len != seeded_xorshift.argument_count)
            return error.ArgumentCountMismatch;
        self.launches += 1;
    }
};

const TestContext = struct {
    active_stage: @import("../../../backends/cuda/runtime/telemetry.zig").Stage =
        .trace_generation,

    pub fn requireStage(
        self: *TestContext,
        expected: @import("../../../backends/cuda/runtime/telemetry.zig").Stage,
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
