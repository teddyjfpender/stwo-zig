//! Typed binding for the Native wide-Fibonacci ordinary-constraint AOT kernel.

const std = @import("std");
const context_module = @import("../context.zig");
const kernel_module = @import("../kernel.zig");
const runtime_error = @import("../error.zig");

const Context = context_module.NativeContext;
const Buffer = Context.Buffer;

pub const max_sequence_len: u32 = 512;
pub const argument_count: u32 = 13;
pub const cache_key: u64 = 0xb0108a05e4de93ca;
pub const kernel_name = "stwo_jit_fused_4a5dad552ce2c7ae";

pub const Buffers = struct {
    trace_column_table: Buffer,
    interaction_offsets: Buffer,
    base_parameters: Buffer,
    extension_parameters: Buffer,
    random_coefficient_powers: Buffer,
    denominator_inverses: Buffer,
    coordinates: [4]Buffer,
};

pub const PreparedLaunch = struct {
    kernel: kernel_module.Kernel,
    arguments: Arguments,

    pub fn launch(self: *PreparedLaunch, session: anytype) runtime_error.Error!void {
        var pointers = self.arguments.pointers();
        try session.launchKernel(self.kernel, &pointers);
    }
};

const Arguments = struct {
    trace_columns: [*]u32,
    interaction_offsets: [*]u32,
    base_parameters: [*]u32,
    extension_parameters: [*]u32,
    random_coefficient_powers: [*]u32,
    denominator_inverses: [*]u32,
    coordinate_0: [*]u32,
    coordinate_1: [*]u32,
    coordinate_2: [*]u32,
    coordinate_3: [*]u32,
    row_count: u32,
    trace_log_size: u32,
    random_coefficient_base: u32,

    fn pointers(self: *Arguments) [argument_count]?*anyopaque {
        return .{
            @ptrCast(&self.trace_columns),
            @ptrCast(&self.interaction_offsets),
            @ptrCast(&self.base_parameters),
            @ptrCast(&self.extension_parameters),
            @ptrCast(&self.random_coefficient_powers),
            @ptrCast(&self.denominator_inverses),
            @ptrCast(&self.coordinate_0),
            @ptrCast(&self.coordinate_1),
            @ptrCast(&self.coordinate_2),
            @ptrCast(&self.coordinate_3),
            @ptrCast(&self.row_count),
            @ptrCast(&self.trace_log_size),
            @ptrCast(&self.random_coefficient_base),
        };
    }
};

pub fn prepare(
    context: *Context,
    buffers: Buffers,
    trace_log_size: u32,
    sequence_len: u32,
    random_coefficient_base: u32,
) runtime_error.Error!PreparedLaunch {
    const row_count = try evaluationRows(trace_log_size);
    if (sequence_len < 3 or sequence_len > max_sequence_len)
        return error.InvalidKernelDescriptor;

    const pointer_words = std.math.mul(
        usize,
        sequence_len,
        @sizeOf(usize) / @sizeOf(u32),
    ) catch return error.SizeOverflow;
    const coefficient_words = std.math.mul(
        usize,
        sequence_len - 2,
        4,
    ) catch return error.SizeOverflow;
    return .{
        .kernel = try descriptor(trace_log_size),
        .arguments = .{
            .trace_columns = try context.devicePointer(
                buffers.trace_column_table,
                pointer_words,
            ),
            .interaction_offsets = try context.devicePointer(
                buffers.interaction_offsets,
                3,
            ),
            .base_parameters = try context.devicePointer(buffers.base_parameters, 1),
            .extension_parameters = try context.devicePointer(
                buffers.extension_parameters,
                1,
            ),
            .random_coefficient_powers = try context.devicePointer(
                buffers.random_coefficient_powers,
                coefficient_words,
            ),
            .denominator_inverses = try context.devicePointer(
                buffers.denominator_inverses,
                2,
            ),
            .coordinate_0 = try context.devicePointer(buffers.coordinates[0], row_count),
            .coordinate_1 = try context.devicePointer(buffers.coordinates[1], row_count),
            .coordinate_2 = try context.devicePointer(buffers.coordinates[2], row_count),
            .coordinate_3 = try context.devicePointer(buffers.coordinates[3], row_count),
            .row_count = row_count,
            .trace_log_size = trace_log_size,
            .random_coefficient_base = random_coefficient_base,
        },
    };
}

pub fn descriptor(trace_log_size: u32) runtime_error.Error!kernel_module.Kernel {
    const rows = try evaluationRows(trace_log_size);
    return .{
        .stage = .constraint_evaluation,
        .abi_schema = .ordinary_constraint_v1,
        .cache_key = cache_key,
        .name = kernel_name,
        .grid = .{ 1 + (rows - 1) / 128, 1, 1 },
        .block = .{ 128, 1, 1 },
        .argument_count = argument_count,
    };
}

fn evaluationRows(trace_log_size: u32) runtime_error.Error!u32 {
    if (trace_log_size > 30) return error.SizeOverflow;
    const shift: u5 = @intCast(trace_log_size + 1);
    return @as(u32, 1) << shift;
}

test "wide-Fibonacci AOT descriptor covers each quotient-domain row once" {
    const descriptor_16 = try descriptor(15);
    try std.testing.expectEqual(@as(u32, 512), descriptor_16.grid[0]);
    try std.testing.expectEqual(@as(u32, 128), descriptor_16.block[0]);
    try std.testing.expectEqual(argument_count, descriptor_16.argument_count);
    try std.testing.expectEqual(cache_key, descriptor_16.cache_key);
    try std.testing.expectEqualStrings(kernel_name, descriptor_16.name);
}

test "wide-Fibonacci AOT descriptor rejects unrepresentable domains" {
    try std.testing.expectError(error.SizeOverflow, descriptor(31));
}
