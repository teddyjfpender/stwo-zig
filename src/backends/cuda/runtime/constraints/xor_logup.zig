//! Arena-native binding for the exact XOR truth-table LogUp composition.

const std = @import("std");
const field = @import("../../abi/field.zig");
const kernel_module = @import("../kernel.zig");
const runtime_error = @import("../error.zig");
const common = @import("../stages/common.zig");
const layout = @import("../stages/resident_layout.zig");
const telemetry = @import("../telemetry.zig");

pub const source_column_count: u32 = 15;
pub const constraint_count: u32 = 14;
pub const argument_count: u32 = 17;
pub const cache_key: u64 = 0x6361f95717acc1a8;
pub const kernel_name =
    "stwo_native_constraint_xor_logup_slab_v1_74e91bf393755b46";

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

    pub fn launch(self: *PreparedLaunch, session: anytype) runtime_error.Error!void {
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
        buffers.denominator_inverses.len != 2 or
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
        2,
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
            .random_power_words = try wordCount(
                buffers.random_coefficient_powers.len,
            ),
            .denominator_inverses = denominators.pointer,
            .denominator_words = try u64Count(
                buffers.denominator_inverses.len,
            ),
            .lookup_elements = @ptrCast(lookup.pointer),
            .lookup_words = try wordCount(buffers.lookup_elements.len),
            .claimed_sum = @ptrCast(claimed.pointer),
            .claimed_sum_words = try wordCount(buffers.claimed_sum.len),
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

pub fn descriptor(
    trace_log_size: u32,
) runtime_error.Error!kernel_module.Kernel {
    const rows = try evaluationRows(trace_log_size);
    return .{
        .stage = .constraint_evaluation,
        .abi_schema = .native_xor_logup_constraint_v1,
        .cache_key = cache_key,
        .name = kernel_name,
        .grid = .{ 1 + (rows - 1) / 128, 1, 1 },
        .block = .{ 128, 1, 1 },
        .argument_count = argument_count,
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

fn evaluationRows(log_size: u32) runtime_error.Error!u32 {
    if (log_size >= 30) return error.SizeOverflow;
    return @as(u32, 1) << @intCast(log_size + 1);
}

fn inverseRows(log_size: u32) u32 {
    return if (log_size == 0) 1 else @as(u32, 1) << @intCast(31 - log_size);
}

fn wordCount(secure_fields: usize) runtime_error.Error!u64 {
    return u64Count(std.math.mul(
        usize,
        secure_fields,
        @sizeOf(field.SecureField) / @sizeOf(u32),
    ) catch return error.SizeOverflow);
}

fn u64Count(value: usize) runtime_error.Error!u64 {
    return std.math.cast(u64, value) orelse error.SizeOverflow;
}

test "exact XOR descriptor covers every expanded-domain row once" {
    const kernel = try descriptor(15);
    try std.testing.expectEqual(@as(u32, 512), kernel.grid[0]);
    try std.testing.expectEqual(@as(u32, 128), kernel.block[0]);
    try std.testing.expectEqual(argument_count, kernel.argument_count);
    try kernel.validate();
}

test "exact XOR binding launches only a fully admitted descriptor" {
    var session = TestSession{};
    var launch = try prepare(&session, testBuffers(), 2);
    try launch.launch(&session);
    try std.testing.expectEqual(@as(u64, 1), session.launches);
}

test "exact XOR binding rejects malformed shapes and ownership" {
    var session = TestSession{};
    const buffers = testBuffers();

    var short_sources = buffers;
    short_sources.source_evaluations.storage.len -= 8;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, short_sources, 2),
    );

    var short_powers = buffers;
    short_powers.random_coefficient_powers.len = 2;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, short_powers, 2),
    );

    var short_denominators = buffers;
    short_denominators.denominator_inverses.len = 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, short_denominators, 2),
    );

    var short_lookup = buffers;
    short_lookup.lookup_elements.len = 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, short_lookup, 2),
    );

    var short_claim = buffers;
    short_claim.claimed_sum.len = 0;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, short_claim, 2),
    );

    var foreign = buffers;
    foreign.source_evaluations.storage.owner += 1;
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        prepare(&session, foreign, 2),
    );

    session.context.active_stage = .fri_commit;
    try std.testing.expectError(
        error.StageOrderViolation,
        prepare(&session, buffers, 2),
    );
    try std.testing.expectError(error.SizeOverflow, descriptor(30));
}

test "exact XOR binding rejects every read-write alias class" {
    var session = TestSession{};
    const buffers = testBuffers();

    inline for ([_][]const u8{
        "source",
        "powers",
        "denominators",
        "lookup",
        "claim",
    }) |alias_kind| {
        var alias = buffers;
        const address = buffers.composition_coordinates.storage.address;
        if (std.mem.eql(u8, alias_kind, "source")) {
            alias.source_evaluations.storage.address = address;
        } else if (std.mem.eql(u8, alias_kind, "powers")) {
            alias.random_coefficient_powers.address = address;
        } else if (std.mem.eql(u8, alias_kind, "denominators")) {
            alias.denominator_inverses.address = address;
        } else if (std.mem.eql(u8, alias_kind, "lookup")) {
            alias.lookup_elements.address = address;
        } else {
            alias.claimed_sum.address = address;
        }
        try std.testing.expectError(
            error.OverlappingDeviceRange,
            prepare(&session, alias, 2),
        );
    }
}

test "exact XOR binding rejects aliases among immutable inputs" {
    var session = TestSession{};
    const buffers = testBuffers();
    var alias = buffers;
    alias.lookup_elements.address =
        buffers.random_coefficient_powers.address;
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        prepare(&session, alias, 2),
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
            kernel.abi_schema != .native_xor_logup_constraint_v1 or
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
        if (slice.address < 0x1000 or end > 0x2000)
            return error.InvalidDeviceAddress;
        return @ptrFromInt(slice.address);
    }
};

fn testBuffers() Buffers {
    return .{
        .source_evaluations = .{
            .storage = testWords(0x1000, 120),
            .column_stride_words = 8,
        },
        .random_coefficient_powers = testSecure(0x1300, 14),
        .denominator_inverses = testWords(0x1400, 2),
        .lookup_elements = testSecure(0x1500, 2),
        .claimed_sum = testSecure(0x1600, 1),
        .composition_coordinates = .{
            .storage = testWords(0x1700, 32),
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

fn testSecure(address: usize, len: usize) common.SecureFields {
    return .{
        .address = address,
        .len = len,
        .owner = 7,
        .generation = 11,
    };
}
