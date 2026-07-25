//! Arena-native binding for the exact Poseidon composition kernel.

const std = @import("std");
const field = @import("../../abi/field.zig");
const kernel_module = @import("../kernel.zig");
const runtime_error = @import("../error.zig");
const common = @import("../stages/common.zig");
const layout = @import("../stages/resident_layout.zig");
const telemetry = @import("../telemetry.zig");

pub const main_column_count: u32 = 1264;
pub const interaction_column_count: u32 = 32;
pub const source_column_count: u32 =
    main_column_count + interaction_column_count;
pub const constraint_count: u32 = 1144;
pub const argument_count: u32 = 17;
pub const cache_key: u64 = 0xfab354a9f2437fcb;
pub const kernel_name =
    "stwo_native_constraint_poseidon_slab_v1_2e0242737cfd5d1c";

pub const Buffers = struct {
    source_evaluations: common.WordMatrix,
    random_coefficient_powers: common.SecureFields,
    denominator_inverses: common.Words,
    lookup_elements: common.SecureFields,
    claimed_sum: common.SecureFields,
    composition_coordinates: common.WordMatrix,
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
    source_slab: [*]u32,
    source_slab_words: u64,
    source_stride_words: u64,
    random_powers: [*]u32,
    random_power_words: u64,
    denominator_inverses: [*]u32,
    denominator_words: u64,
    lookup_elements: [*]u32,
    lookup_words: u64,
    claimed_sum: [*]u32,
    claimed_sum_words: u64,
    coordinate_slab: [*]u32,
    coordinate_slab_words: u64,
    coordinate_stride_words: u64,
    row_count: u32,
    trace_log_size: u32,
    inverse_rows: u32,

    fn pointers(self: *Arguments) [argument_count]?*anyopaque {
        return .{
            @ptrCast(&self.source_slab),
            @ptrCast(&self.source_slab_words),
            @ptrCast(&self.source_stride_words),
            @ptrCast(&self.random_powers),
            @ptrCast(&self.random_power_words),
            @ptrCast(&self.denominator_inverses),
            @ptrCast(&self.denominator_words),
            @ptrCast(&self.lookup_elements),
            @ptrCast(&self.lookup_words),
            @ptrCast(&self.claimed_sum),
            @ptrCast(&self.claimed_sum_words),
            @ptrCast(&self.coordinate_slab),
            @ptrCast(&self.coordinate_slab_words),
            @ptrCast(&self.coordinate_stride_words),
            @ptrCast(&self.row_count),
            @ptrCast(&self.trace_log_size),
            @ptrCast(&self.inverse_rows),
        };
    }
};

pub fn prepare(
    session: anytype,
    buffers: Buffers,
    trace_log_size: u32,
) runtime_error.Error!PreparedLaunch {
    try common.requireStage(session, .constraint_evaluation);
    const row_count = try evaluationRows(trace_log_size);
    if (buffers.random_coefficient_powers.len != constraint_count or
        buffers.denominator_inverses.len != 4 or
        buffers.lookup_elements.len != 2 or
        buffers.claimed_sum.len != 1)
    {
        return error.InvalidKernelDescriptor;
    }
    const sources = try layout.wordMatrix(
        session,
        buffers.source_evaluations,
        row_count,
    );
    if (sources.column_count != source_column_count)
        return error.InvalidKernelDescriptor;
    const powers = try layout.resident(
        session,
        field.SecureField,
        buffers.random_coefficient_powers,
        constraint_count,
    );
    const denominators = try layout.resident(
        session,
        u32,
        buffers.denominator_inverses,
        4,
    );
    const lookup = try layout.resident(
        session,
        field.SecureField,
        buffers.lookup_elements,
        2,
    );
    const claimed = try layout.resident(
        session,
        field.SecureField,
        buffers.claimed_sum,
        1,
    );
    const coordinates = try layout.wordMatrix(
        session,
        buffers.composition_coordinates,
        row_count,
    );
    if (coordinates.column_count != 4)
        return error.InvalidKernelDescriptor;
    try requirePairwiseDisjoint(&.{
        sources.range,
        powers.range,
        denominators.range,
        lookup.range,
        claimed.range,
        coordinates.range,
    });

    return .{
        .kernel = try descriptor(trace_log_size),
        .arguments = .{
            .source_slab = sources.pointer,
            .source_slab_words = try u64Count(
                buffers.source_evaluations.storage.len,
            ),
            .source_stride_words = try u64Count(sources.stride_words),
            .random_powers = @ptrCast(powers.pointer),
            .random_power_words = try secureWordCount(
                buffers.random_coefficient_powers.len,
            ),
            .denominator_inverses = denominators.pointer,
            .denominator_words = buffers.denominator_inverses.len,
            .lookup_elements = @ptrCast(lookup.pointer),
            .lookup_words = try secureWordCount(
                buffers.lookup_elements.len,
            ),
            .claimed_sum = @ptrCast(claimed.pointer),
            .claimed_sum_words = try secureWordCount(
                buffers.claimed_sum.len,
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
            .inverse_rows = inverseRows(trace_log_size),
        },
    };
}

fn requirePairwiseDisjoint(ranges: []const layout.DeviceRange) !void {
    for (ranges, 0..) |left, index| {
        for (ranges[index + 1 ..]) |right| {
            if (layout.overlap(left, right))
                return error.OverlappingDeviceRange;
        }
    }
}

pub fn descriptor(
    trace_log_size: u32,
) runtime_error.Error!kernel_module.Kernel {
    const rows = try evaluationRows(trace_log_size);
    return .{
        .stage = .constraint_evaluation,
        .abi_schema = .native_poseidon_constraint_v1,
        .cache_key = cache_key,
        .name = kernel_name,
        .grid = .{ 1 + (rows - 1) / 64, 1, 1 },
        .block = .{ 64, 1, 1 },
        .argument_count = argument_count,
    };
}

fn evaluationRows(log_size: u32) runtime_error.Error!u32 {
    if (log_size >= 29) return error.SizeOverflow;
    return @as(u32, 1) << @intCast(log_size + 2);
}

fn inverseRows(log_size: u32) u32 {
    return if (log_size == 0)
        1
    else
        @as(u32, 1) << @intCast(31 - log_size);
}

fn secureWordCount(count: usize) runtime_error.Error!u64 {
    return u64Count(std.math.mul(
        usize,
        count,
        @sizeOf(field.SecureField) / @sizeOf(u32),
    ) catch return error.SizeOverflow);
}

fn u64Count(value: usize) runtime_error.Error!u64 {
    return std.math.cast(u64, value) orelse error.SizeOverflow;
}

test "exact Poseidon descriptor covers the fourfold domain once" {
    const kernel = try descriptor(15);
    try std.testing.expectEqual(@as(u32, 4096), kernel.grid[0]);
    try std.testing.expectEqual(@as(u32, 64), kernel.block[0]);
    try std.testing.expectEqual(argument_count, kernel.argument_count);
    try kernel.validate();
}

test "exact Poseidon binding admits only complete resident inputs" {
    var session = TestSession{};
    var launch = try prepare(&session, testBuffers(), 0);
    try launch.launch(&session);
    try std.testing.expectEqual(@as(u64, 1), session.launches);

    var short = testBuffers();
    short.random_coefficient_powers.len -= 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, short, 0),
    );

    var alias = testBuffers();
    alias.claimed_sum.address =
        alias.composition_coordinates.storage.address;
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        prepare(&session, alias, 0),
    );
}

const TestSession = struct {
    context: TestContext = .{},
    launches: u64 = 0,

    pub fn launchKernel(
        self: *TestSession,
        kernel: kernel_module.Kernel,
        pointers: *[argument_count]?*anyopaque,
    ) runtime_error.Error!void {
        try kernel.validate();
        if (kernel.stage != .constraint_evaluation or
            kernel.abi_schema != .native_poseidon_constraint_v1 or
            pointers.len != argument_count)
        {
            return error.InvalidKernelDescriptor;
        }
        self.launches += 1;
    }
};

const TestContext = struct {
    active_stage: telemetry.Stage = .constraint_evaluation,

    pub fn requireStage(
        self: *TestContext,
        expected: telemetry.Stage,
    ) runtime_error.Error!void {
        if (self.active_stage != expected)
            return error.StageOrderViolation;
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
        if (slice.address < 0x1000 or end > 0x20_000)
            return error.InvalidDeviceAddress;
        return @ptrFromInt(slice.address);
    }
};

fn testBuffers() Buffers {
    return .{
        .source_evaluations = .{
            .storage = testWords(0x1000, source_column_count * 4),
            .column_stride_words = 4,
        },
        .random_coefficient_powers = testSecure(0x7000, constraint_count),
        .denominator_inverses = testWords(0xc000, 4),
        .lookup_elements = testSecure(0xd000, 2),
        .claimed_sum = testSecure(0xe000, 1),
        .composition_coordinates = .{
            .storage = testWords(0xf000, 16),
            .column_stride_words = 4,
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

fn testSecure(address: usize, len: usize) common.SecureFields {
    return .{
        .address = address,
        .len = len,
        .owner = 7,
        .generation = 11,
    };
}
