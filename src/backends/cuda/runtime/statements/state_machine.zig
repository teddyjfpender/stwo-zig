//! Strict-AOT resident State Machine statement transaction.

const kernel_module = @import("../kernel.zig");
const runtime_error = @import("../error.zig");
const common = @import("../stages/common.zig");
const layout = @import("../stages/resident_layout.zig");
const telemetry = @import("../telemetry.zig");

pub const argument_count: u32 = 11;
pub const cache_key: u64 = 0x2aff3bfd07da4568;
pub const kernel_name =
    "stwo_native_statement_state_machine_v1_6324a81f31d00d9e";

pub const Boundary = struct {
    expected_step: u32,
    expected_chain: u64,
    next_chain: u64,
};

pub const Buffers = struct {
    transcript_state: common.Words,
    statement_words: common.Words,
    input_snapshot: common.Words,
    output_snapshot: common.Words,
    boundary_snapshot: common.Words,
};

pub const PreparedLaunch = struct {
    kernel: kernel_module.Kernel,
    arguments: Arguments,

    pub fn launch(
        self: *PreparedLaunch,
        session: anytype,
    ) runtime_error.Error!void {
        var pointers = self.arguments.pointers();
        try session.launchKernel(self.kernel, &pointers);
    }
};

const Arguments = struct {
    state_words: [*]u32,
    expected_step: u32,
    expected_chain: u64,
    next_chain: u64,
    statement_words: [*]u32,
    statement_word_count: u64,
    input_snapshot: [*]u32,
    input_snapshot_words: u64,
    output_snapshot: [*]u32,
    output_snapshot_words: u64,
    boundary_snapshot: [*]u32,

    fn pointers(self: *Arguments) [argument_count]?*anyopaque {
        return .{
            @ptrCast(&self.state_words),
            @ptrCast(&self.expected_step),
            @ptrCast(&self.expected_chain),
            @ptrCast(&self.next_chain),
            @ptrCast(&self.statement_words),
            @ptrCast(&self.statement_word_count),
            @ptrCast(&self.input_snapshot),
            @ptrCast(&self.input_snapshot_words),
            @ptrCast(&self.output_snapshot),
            @ptrCast(&self.output_snapshot_words),
            @ptrCast(&self.boundary_snapshot),
        };
    }
};

pub fn prepare(
    session: anytype,
    buffers: Buffers,
    boundary: Boundary,
) runtime_error.Error!PreparedLaunch {
    try common.requireStage(session, .constraint_evaluation);
    if (buffers.transcript_state.len != 16 or
        buffers.statement_words.len != 14 or
        buffers.input_snapshot.len < 14 or
        buffers.output_snapshot.len < 8 or
        buffers.boundary_snapshot.len != 16)
    {
        return error.InvalidKernelDescriptor;
    }

    const state = try layout.resident(
        session,
        u32,
        buffers.transcript_state,
        16,
    );
    const statement = try layout.resident(
        session,
        u32,
        buffers.statement_words,
        14,
    );
    const input = try layout.resident(
        session,
        u32,
        buffers.input_snapshot,
        14,
    );
    const output = try layout.resident(
        session,
        u32,
        buffers.output_snapshot,
        8,
    );
    const snapshot = try layout.resident(
        session,
        u32,
        buffers.boundary_snapshot,
        16,
    );
    try requireDisjoint(&.{
        state.range,
        statement.range,
        input.range,
        output.range,
        snapshot.range,
    });

    return .{
        .kernel = descriptor(),
        .arguments = .{
            .state_words = state.pointer,
            .expected_step = boundary.expected_step,
            .expected_chain = boundary.expected_chain,
            .next_chain = boundary.next_chain,
            .statement_words = statement.pointer,
            .statement_word_count = 14,
            .input_snapshot = input.pointer,
            .input_snapshot_words = buffers.input_snapshot.len,
            .output_snapshot = output.pointer,
            .output_snapshot_words = buffers.output_snapshot.len,
            .boundary_snapshot = snapshot.pointer,
        },
    };
}

pub fn descriptor() kernel_module.Kernel {
    return .{
        .stage = .constraint_evaluation,
        .abi_schema = .native_state_machine_statement_v1,
        .cache_key = cache_key,
        .name = kernel_name,
        .grid = .{ 1, 1, 1 },
        .block = .{ 1, 1, 1 },
        .argument_count = argument_count,
    };
}

fn requireDisjoint(
    ranges: []const layout.DeviceRange,
) runtime_error.Error!void {
    for (ranges, 0..) |range, index| {
        for (ranges[0..index]) |previous| {
            if (layout.overlap(range, previous))
                return error.OverlappingDeviceRange;
        }
    }
}

test "state-machine statement descriptor is one strict AOT transaction" {
    const std = @import("std");
    const kernel = descriptor();
    try std.testing.expectEqual(@as(u32, 1), kernel.grid[0]);
    try std.testing.expectEqual(@as(u32, 1), kernel.block[0]);
    try std.testing.expectEqual(argument_count, kernel.argument_count);
}
