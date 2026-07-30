//! Arena-native binding for the Native wide-Fibonacci trace-slab AOT kernel.

const std = @import("std");
const field = @import("../../abi/field.zig");
const kernel_module = @import("../kernel.zig");
const runtime_error = @import("../error.zig");
const common = @import("../stages/common.zig");
const layout = @import("../stages/resident_layout.zig");
const telemetry = @import("../telemetry.zig");

pub const max_sequence_len: u32 = 512;
pub const secure_extension_degree: u32 =
    @sizeOf(field.SecureField) / @sizeOf(u32);
pub const argument_count: u32 = 14;
pub const cache_key: u64 = 0x7a6ba68d80b91b07;
pub const kernel_name =
    "stwo_native_constraint_wide_fibonacci_slab_v1_6f60dbf6e15716eb";

pub const Buffers = struct {
    trace_evaluations: common.WordMatrix,
    random_coefficient_powers: common.SecureFields,
    denominator_inverses: common.Words,
    composition_coordinates: common.WordMatrix,
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
    trace_slab: [*]u32,
    trace_slab_words: u64,
    trace_column_stride_words: u64,
    sequence_len: u32,
    random_coefficient_powers: [*]u32,
    random_coefficient_words: u64,
    denominator_inverses: [*]u32,
    denominator_words: u64,
    coordinate_slab: [*]u32,
    coordinate_slab_words: u64,
    coordinate_stride_words: u64,
    row_count: u32,
    trace_log_size: u32,
    random_coefficient_base: u32,

    fn pointers(self: *Arguments) [argument_count]?*anyopaque {
        return .{
            @ptrCast(&self.trace_slab),
            @ptrCast(&self.trace_slab_words),
            @ptrCast(&self.trace_column_stride_words),
            @ptrCast(&self.sequence_len),
            @ptrCast(&self.random_coefficient_powers),
            @ptrCast(&self.random_coefficient_words),
            @ptrCast(&self.denominator_inverses),
            @ptrCast(&self.denominator_words),
            @ptrCast(&self.coordinate_slab),
            @ptrCast(&self.coordinate_slab_words),
            @ptrCast(&self.coordinate_stride_words),
            @ptrCast(&self.row_count),
            @ptrCast(&self.trace_log_size),
            @ptrCast(&self.random_coefficient_base),
        };
    }
};

pub fn prepare(
    session: anytype,
    buffers: Buffers,
    trace_log_size: u32,
    sequence_len: u32,
    random_coefficient_base: u32,
) runtime_error.Error!PreparedLaunch {
    try common.requireStage(session, .constraint_evaluation);
    const row_count = try evaluationRows(trace_log_size);
    if (sequence_len < 3 or sequence_len > max_sequence_len)
        return error.InvalidKernelDescriptor;
    const coefficient_count = try coefficientCount(
        sequence_len,
        random_coefficient_base,
    );
    if (buffers.random_coefficient_powers.len < coefficient_count or
        buffers.denominator_inverses.len < 2)
    {
        return error.SizeOverflow;
    }

    const trace = try layout.wordMatrix(
        session,
        buffers.trace_evaluations,
        row_count,
    );
    if (trace.column_count != sequence_len)
        return error.InvalidKernelDescriptor;
    const powers = try layout.resident(
        session,
        field.SecureField,
        buffers.random_coefficient_powers,
        coefficient_count,
    );
    const denominators = try layout.resident(
        session,
        u32,
        buffers.denominator_inverses,
        2,
    );
    const coordinates = try layout.wordMatrix(
        session,
        buffers.composition_coordinates,
        row_count,
    );
    if (coordinates.column_count != secure_extension_degree)
        return error.InvalidKernelDescriptor;
    try requirePairwiseDisjoint(&.{
        trace.range,
        powers.range,
        denominators.range,
        coordinates.range,
    });

    return .{
        .kernel = try descriptor(trace_log_size),
        .arguments = .{
            .trace_slab = trace.pointer,
            .trace_slab_words = try u64Count(
                buffers.trace_evaluations.storage.len,
            ),
            .trace_column_stride_words = try u64Count(trace.stride_words),
            .sequence_len = sequence_len,
            .random_coefficient_powers = @ptrCast(powers.pointer),
            .random_coefficient_words = try u64Count(
                std.math.mul(
                    usize,
                    buffers.random_coefficient_powers.len,
                    secure_extension_degree,
                ) catch return error.SizeOverflow,
            ),
            .denominator_inverses = denominators.pointer,
            .denominator_words = try u64Count(
                buffers.denominator_inverses.len,
            ),
            .coordinate_slab = coordinates.pointer,
            .coordinate_slab_words = try u64Count(
                buffers.composition_coordinates.storage.len,
            ),
            .coordinate_stride_words = try u64Count(
                coordinates.stride_words,
            ),
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
        .abi_schema = .native_constraint_slab_v1,
        .cache_key = cache_key,
        .name = kernel_name,
        .grid = .{ 1 + (rows - 1) / 128, 1, 1 },
        .block = .{ 128, 1, 1 },
        .argument_count = argument_count,
    };
}

fn coefficientCount(
    sequence_len: u32,
    random_coefficient_base: u32,
) runtime_error.Error!usize {
    return std.math.add(
        usize,
        random_coefficient_base,
        sequence_len - 2,
    ) catch return error.SizeOverflow;
}

fn requirePairwiseDisjoint(
    ranges: []const layout.DeviceRange,
) runtime_error.Error!void {
    for (ranges, 0..) |left, index| {
        for (ranges[index + 1 ..]) |right| {
            if (layout.overlap(left, right))
                return error.OverlappingDeviceRange;
        }
    }
}

fn evaluationRows(trace_log_size: u32) runtime_error.Error!u32 {
    if (trace_log_size > 30) return error.SizeOverflow;
    const shift: u5 = @intCast(trace_log_size + 1);
    return @as(u32, 1) << shift;
}

fn u64Count(value: usize) runtime_error.Error!u64 {
    return std.math.cast(u64, value) orelse error.SizeOverflow;
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

test "wide-Fibonacci slab binding validates arena ownership range and aliases" {
    var session = TestSession{};
    const buffers = testBuffers();
    _ = try prepare(&session, buffers, 2, 5, 1);

    var foreign = buffers;
    foreign.trace_evaluations.storage.owner += 1;
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        prepare(&session, foreign, 2, 5, 1),
    );

    var outside = buffers;
    outside.trace_evaluations.storage.address = 0x1fc0;
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        prepare(&session, outside, 2, 5, 1),
    );

    var alias = buffers;
    alias.composition_coordinates.storage.address =
        buffers.trace_evaluations.storage.address;
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        prepare(&session, alias, 2, 5, 1),
    );
}

test "wide-Fibonacci slab binding rejects invalid shape and capacity" {
    var session = TestSession{};
    const buffers = testBuffers();
    var short_powers = buffers;
    short_powers.random_coefficient_powers.len = 3;
    try std.testing.expectError(
        error.SizeOverflow,
        prepare(&session, short_powers, 2, 5, 1),
    );

    var short_trace = buffers;
    short_trace.trace_evaluations.storage.len = 32;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, short_trace, 2, 5, 1),
    );

    var short_stride = buffers;
    short_stride.trace_evaluations.column_stride_words = 7;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, short_stride, 2, 5, 1),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, buffers, 2, 2, 1),
    );
}

const TestSession = struct {
    context: TestContext = .{},
};

const TestContext = struct {
    active_stage: telemetry.Stage = .constraint_evaluation,

    pub fn requireStage(
        self: *TestContext,
        expected: telemetry.Stage,
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
            slice.owner != 7 or slice.generation != 11 or
            slice.address % @alignOf(F) != 0)
        {
            return error.InvalidDeviceAddress;
        }
        const bytes = std.math.mul(
            usize,
            minimum,
            @sizeOf(F),
        ) catch return error.SizeOverflow;
        const end = std.math.add(
            usize,
            slice.address,
            bytes,
        ) catch return error.SizeOverflow;
        if (slice.address < 0x1000 or end > 0x2000)
            return error.InvalidDeviceAddress;
        return @ptrFromInt(slice.address);
    }
};

fn testBuffers() Buffers {
    return .{
        .trace_evaluations = .{
            .storage = testWords(0x1000, 40),
            .column_stride_words = 8,
        },
        .random_coefficient_powers = .{
            .address = 0x1100,
            .len = 4,
            .owner = 7,
            .generation = 11,
        },
        .denominator_inverses = testWords(0x1200, 2),
        .composition_coordinates = .{
            .storage = testWords(0x1300, 32),
            .column_stride_words = 8,
        },
    };
}

fn testWords(address: usize, len: usize) common.Words {
    return .{
        .address = address,
        .len = len,
        .owner = 7,
        .generation = 11,
    };
}
