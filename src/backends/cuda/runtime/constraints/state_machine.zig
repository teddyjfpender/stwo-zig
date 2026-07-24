//! Structural AOT binding for the State Machine claimed-sum composition.

const std = @import("std");
const field = @import("../../abi/field.zig");
const kernel_module = @import("../kernel.zig");
const runtime_error = @import("../error.zig");
const common = @import("../stages/common.zig");
const layout = @import("../stages/resident_layout.zig");
const telemetry = @import("../telemetry.zig");

pub const secure_extension_degree: u32 =
    @sizeOf(field.SecureField) / @sizeOf(u32);
pub const argument_count: u32 = 15;
pub const cache_key: u64 = 0xbe136f524ac0d95c;
pub const kernel_name =
    "stwo_native_constraint_state_machine_slab_v1_199a83f08c52455b";

pub const Geometry = struct {
    component_index: u32,
    component_count: u32,
    evaluation_log_size: u32,
    trace_log_size: u32,
    preprocessed_column_count: u32,
    main_column_count: u32,
};

pub const Buffers = struct {
    statement_parameters: common.Words,
    challenge_parameters: common.Words,
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
    component_index: u32,
    component_count: u32,
    evaluation_log_size: u32,
    trace_log_size: u32,
    preprocessed_column_count: u32,
    main_column_count: u32,
    statement_words: ?[*]const u32,
    statement_word_count: u64,
    challenge_words: ?[*]const u32,
    challenge_word_count: u64,
    abi_placeholder: field.SecureField,
    coordinate_slab: [*]u32,
    coordinate_slab_words: u64,
    coordinate_stride_words: u64,
    row_count: u32,

    fn pointers(self: *Arguments) [argument_count]?*anyopaque {
        return .{
            @ptrCast(&self.component_index),
            @ptrCast(&self.component_count),
            @ptrCast(&self.evaluation_log_size),
            @ptrCast(&self.trace_log_size),
            @ptrCast(&self.preprocessed_column_count),
            @ptrCast(&self.main_column_count),
            @ptrCast(&self.statement_words),
            @ptrCast(&self.statement_word_count),
            @ptrCast(&self.challenge_words),
            @ptrCast(&self.challenge_word_count),
            @ptrCast(&self.abi_placeholder),
            @ptrCast(&self.coordinate_slab),
            @ptrCast(&self.coordinate_slab_words),
            @ptrCast(&self.coordinate_stride_words),
            @ptrCast(&self.row_count),
        };
    }
};

const OptionalWords = struct {
    pointer: ?[*]const u32,
    range: ?layout.DeviceRange,
};

pub fn prepare(
    session: anytype,
    buffers: Buffers,
    geometry: Geometry,
    abi_placeholder: field.SecureField,
) runtime_error.Error!PreparedLaunch {
    try common.requireStage(session, .constraint_evaluation);
    try validateGeometry(geometry);
    try validatePlaceholder(abi_placeholder);
    const row_count = try evaluationRows(geometry.evaluation_log_size);

    const statement = try optionalWords(session, buffers.statement_parameters);
    const challenges = try optionalWords(session, buffers.challenge_parameters);
    const coordinates = try layout.wordMatrix(
        session,
        buffers.composition_coordinates,
        row_count,
    );
    if (coordinates.column_count != secure_extension_degree)
        return error.InvalidKernelDescriptor;
    try requireDisjoint(
        coordinates.range,
        statement.range,
        challenges.range,
    );

    return .{
        .kernel = try descriptor(geometry.evaluation_log_size),
        .arguments = .{
            .component_index = geometry.component_index,
            .component_count = geometry.component_count,
            .evaluation_log_size = geometry.evaluation_log_size,
            .trace_log_size = geometry.trace_log_size,
            .preprocessed_column_count = geometry.preprocessed_column_count,
            .main_column_count = geometry.main_column_count,
            .statement_words = statement.pointer,
            .statement_word_count = try u64Count(buffers.statement_parameters.len),
            .challenge_words = challenges.pointer,
            .challenge_word_count = try u64Count(buffers.challenge_parameters.len),
            .abi_placeholder = abi_placeholder,
            .coordinate_slab = coordinates.pointer,
            .coordinate_slab_words = try u64Count(
                buffers.composition_coordinates.storage.len,
            ),
            .coordinate_stride_words = try u64Count(coordinates.stride_words),
            .row_count = row_count,
        },
    };
}

pub fn descriptor(evaluation_log_size: u32) runtime_error.Error!kernel_module.Kernel {
    const rows = try evaluationRows(evaluation_log_size);
    return .{
        .stage = .constraint_evaluation,
        .abi_schema = .native_state_machine_constraint_v1,
        .cache_key = cache_key,
        .name = kernel_name,
        .grid = .{ 1 + (rows - 1) / 128, 1, 1 },
        .block = .{ 128, 1, 1 },
        .argument_count = argument_count,
    };
}

fn validateGeometry(geometry: Geometry) runtime_error.Error!void {
    if (geometry.component_count == 0 or
        geometry.component_index >= geometry.component_count or
        geometry.trace_log_size > geometry.evaluation_log_size)
    {
        return error.InvalidKernelDescriptor;
    }
    const total_columns = std.math.add(
        u32,
        geometry.preprocessed_column_count,
        geometry.main_column_count,
    ) catch return error.SizeOverflow;
    if (total_columns == 0) return error.InvalidKernelDescriptor;
}

fn validatePlaceholder(value: field.SecureField) runtime_error.Error!void {
    const prime: u32 = 2_147_483_647;
    if (value.a >= prime or value.b >= prime or
        value.c >= prime or value.d >= prime)
    {
        return error.InvalidKernelDescriptor;
    }
}

fn optionalWords(
    session: anytype,
    words: common.Words,
) runtime_error.Error!OptionalWords {
    if (words.len == 0) {
        if (words.address != 0) return error.InvalidDeviceAddress;
        return .{ .pointer = null, .range = null };
    }
    const resident = try layout.resident(session, u32, words, words.len);
    return .{ .pointer = resident.pointer, .range = resident.range };
}

fn requireDisjoint(
    output: layout.DeviceRange,
    statement: ?layout.DeviceRange,
    challenges: ?layout.DeviceRange,
) runtime_error.Error!void {
    if (statement) |range| {
        if (layout.overlap(output, range)) return error.OverlappingDeviceRange;
        if (challenges) |other| {
            if (layout.overlap(range, other))
                return error.OverlappingDeviceRange;
        }
    }
    if (challenges) |range| {
        if (layout.overlap(output, range)) return error.OverlappingDeviceRange;
    }
}

fn evaluationRows(log_size: u32) runtime_error.Error!u32 {
    if (log_size > 30) return error.SizeOverflow;
    const shift: u5 = @intCast(log_size);
    return @as(u32, 1) << shift;
}

fn u64Count(value: usize) runtime_error.Error!u64 {
    return std.math.cast(u64, value) orelse error.SizeOverflow;
}

test "State Machine descriptor is structural and covers each row once" {
    const kernel = try descriptor(16);
    try std.testing.expectEqual(@as(u32, 512), kernel.grid[0]);
    try std.testing.expectEqual(@as(u32, 128), kernel.block[0]);
    try std.testing.expectEqual(argument_count, kernel.argument_count);
    try std.testing.expectEqual(cache_key, kernel.cache_key);
    try std.testing.expectEqualStrings(kernel_name, kernel.name);
}

test "State Machine binding admits zero and nonzero preprocessed widths" {
    var session = TestSession{};
    const buffers = testBuffers();
    var zero_preprocessed = try prepare(
        &session,
        buffers,
        .{
            .component_index = 0,
            .component_count = 1,
            .evaluation_log_size = 3,
            .trace_log_size = 2,
            .preprocessed_column_count = 0,
            .main_column_count = 37,
        },
        .{ .a = 1, .b = 2, .c = 3, .d = 4 },
    );
    try zero_preprocessed.launch(&session);

    var nonzero = try prepare(
        &session,
        buffers,
        .{
            .component_index = 2,
            .component_count = 4,
            .evaluation_log_size = 3,
            .trace_log_size = 3,
            .preprocessed_column_count = 5,
            .main_column_count = 37,
        },
        .{ .a = 11, .b = 13, .c = 17, .d = 19 },
    );
    try nonzero.launch(&session);
    try std.testing.expectEqual(@as(u64, 2), session.launches);
}

test "State Machine binding rejects invalid geometry ranges and aliases" {
    var session = TestSession{};
    const buffers = testBuffers();
    const valid = Geometry{
        .component_index = 0,
        .component_count = 1,
        .evaluation_log_size = 3,
        .trace_log_size = 2,
        .preprocessed_column_count = 0,
        .main_column_count = 3,
    };
    var bad = valid;
    bad.component_index = 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, buffers, bad, .{ .a = 1, .b = 2, .c = 3, .d = 4 }),
    );
    bad = valid;
    bad.trace_log_size = 4;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, buffers, bad, .{ .a = 1, .b = 2, .c = 3, .d = 4 }),
    );

    var foreign = buffers;
    foreign.statement_parameters.owner += 1;
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        prepare(&session, foreign, valid, .{ .a = 1, .b = 2, .c = 3, .d = 4 }),
    );
    var alias = buffers;
    alias.challenge_parameters.address = buffers.statement_parameters.address;
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        prepare(&session, alias, valid, .{ .a = 1, .b = 2, .c = 3, .d = 4 }),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(
            &session,
            buffers,
            valid,
            .{ .a = 2_147_483_647, .b = 2, .c = 3, .d = 4 },
        ),
    );
}

const TestSession = struct {
    context: TestContext = .{},
    launches: u64 = 0,

    pub fn launchKernel(
        self: *TestSession,
        kernel: kernel_module.Kernel,
        arguments: []const ?*anyopaque,
    ) runtime_error.Error!void {
        try kernel.validate();
        if (arguments.len != argument_count)
            return error.ArgumentCountMismatch;
        self.launches += 1;
    }
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
        .statement_parameters = testWords(0x1000, 4),
        .challenge_parameters = testWords(0x1100, 3),
        .composition_coordinates = .{
            .storage = testWords(0x1200, 32),
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
