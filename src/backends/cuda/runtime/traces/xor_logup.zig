//! Strict-AOT binding for the exact Native XOR truth-table witness.

const std = @import("std");
const kernel_module = @import("../kernel.zig");
const runtime_error = @import("../error.zig");
const common = @import("../stages/common.zig");
const layout = @import("../stages/resident_layout.zig");
const telemetry = @import("../telemetry.zig");

pub const argument_count: u32 = 13;
pub const cache_key: u64 = 0x9c64de1ac2adb7de;
pub const kernel_name =
    "stwo_native_trace_xor_logup_slabs_v1_77dc01e39a2d5eb5";
pub const preprocessed_columns: u32 = 7;
pub const main_columns: u32 = 4;
pub const relation_source_columns: u32 = 7;

pub const Statement = struct {
    log_size: u32,
    log_step: u32,
    offset: u64,
};

pub const Destinations = struct {
    preprocessed: common.WordMatrix,
    main: common.WordMatrix,
    relation_sources: common.WordMatrix,
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
    preprocessed_slab: [*]u32,
    preprocessed_slab_words: u64,
    preprocessed_stride_words: u64,
    main_slab: [*]u32,
    main_slab_words: u64,
    main_stride_words: u64,
    relation_source_slab: [*]u32,
    relation_source_slab_words: u64,
    relation_source_stride_words: u64,
    row_count: u32,
    log_size: u32,
    log_step: u32,
    offset: u64,

    fn pointers(self: *Arguments) [argument_count]?*anyopaque {
        return .{
            @ptrCast(&self.preprocessed_slab),
            @ptrCast(&self.preprocessed_slab_words),
            @ptrCast(&self.preprocessed_stride_words),
            @ptrCast(&self.main_slab),
            @ptrCast(&self.main_slab_words),
            @ptrCast(&self.main_stride_words),
            @ptrCast(&self.relation_source_slab),
            @ptrCast(&self.relation_source_slab_words),
            @ptrCast(&self.relation_source_stride_words),
            @ptrCast(&self.row_count),
            @ptrCast(&self.log_size),
            @ptrCast(&self.log_step),
            @ptrCast(&self.offset),
        };
    }
};

pub fn prepare(
    session: anytype,
    destinations: Destinations,
    statement: Statement,
) runtime_error.Error!PreparedLaunch {
    try common.requireStage(session, .trace_generation);
    const rows = try rowCount(statement.log_size);
    if (statement.log_step > statement.log_size)
        return error.InvalidKernelDescriptor;
    const preprocessed = try exactMatrix(
        session,
        destinations.preprocessed,
        rows,
        preprocessed_columns,
    );
    const main = try exactMatrix(
        session,
        destinations.main,
        rows,
        main_columns,
    );
    const relation_sources = try exactMatrix(
        session,
        destinations.relation_sources,
        rows,
        relation_source_columns,
    );
    try layout.requireDisjoint(
        &.{ preprocessed.range, main.range, relation_sources.range },
        &.{},
    );
    return .{
        .kernel = try descriptor(statement.log_size),
        .arguments = .{
            .preprocessed_slab = preprocessed.pointer,
            .preprocessed_slab_words = try u64Count(
                destinations.preprocessed.storage.len,
            ),
            .preprocessed_stride_words = try u64Count(
                preprocessed.stride_words,
            ),
            .main_slab = main.pointer,
            .main_slab_words = try u64Count(destinations.main.storage.len),
            .main_stride_words = try u64Count(main.stride_words),
            .relation_source_slab = relation_sources.pointer,
            .relation_source_slab_words = try u64Count(
                destinations.relation_sources.storage.len,
            ),
            .relation_source_stride_words = try u64Count(
                relation_sources.stride_words,
            ),
            .row_count = rows,
            .log_size = statement.log_size,
            .log_step = statement.log_step,
            .offset = statement.offset,
        },
    };
}

pub fn generate(
    session: anytype,
    destinations: Destinations,
    statement: Statement,
) runtime_error.Error!void {
    var launch = try prepare(session, destinations, statement);
    try launch.launch(session);
}

pub fn descriptor(log_size: u32) runtime_error.Error!kernel_module.Kernel {
    const rows = try rowCount(log_size);
    return .{
        .stage = .trace_generation,
        .abi_schema = .native_xor_logup_trace_v1,
        .cache_key = cache_key,
        .name = kernel_name,
        .grid = .{ 1 + (rows - 1) / 128, 1, 1 },
        .block = .{ 128, 1, 1 },
        .argument_count = argument_count,
    };
}

fn exactMatrix(
    session: anytype,
    matrix: common.WordMatrix,
    rows: u32,
    columns: u32,
) runtime_error.Error!layout.WordMatrix {
    const resident = try layout.wordMatrix(session, matrix, rows);
    if (resident.column_count != columns)
        return error.InvalidKernelDescriptor;
    const exact_words = std.math.mul(
        usize,
        resident.stride_words,
        @as(usize, @intCast(columns)),
    ) catch return error.SizeOverflow;
    if (matrix.storage.len != exact_words)
        return error.InvalidKernelDescriptor;
    return resident;
}

fn rowCount(log_size: u32) runtime_error.Error!u32 {
    if (log_size < 2 or log_size >= 30)
        return error.InvalidKernelDescriptor;
    return @as(u32, 1) << @intCast(log_size);
}

fn u64Count(value: usize) runtime_error.Error!u64 {
    return std.math.cast(u64, value) orelse error.SizeOverflow;
}

test "exact XOR trace admits guard and non-target geometries" {
    var session = TestSession{};
    try generate(
        &session,
        testDestinations(1 << 14),
        .{ .log_size = 14, .log_step = 3, .offset = 5 },
    );
    try generate(
        &session,
        testDestinations(1 << 5),
        .{ .log_size = 5, .log_step = 2, .offset = 3 },
    );
    try std.testing.expectEqual(@as(u64, 2), session.launches);
}

test "exact XOR trace rejects shape aliases and invalid statements" {
    var session = TestSession{};
    const statement = Statement{ .log_size = 5, .log_step = 2, .offset = 3 };
    const destinations = testDestinations(1 << 5);
    var short = destinations;
    short.main.storage.len -= 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, short, statement),
    );
    var alias = destinations;
    alias.main.storage.address = alias.preprocessed.storage.address;
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        prepare(&session, alias, statement),
    );
    alias = destinations;
    alias.relation_sources.storage.address =
        alias.preprocessed.storage.address;
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        prepare(&session, alias, statement),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(
            &session,
            destinations,
            .{ .log_size = 5, .log_step = 6, .offset = 0 },
        ),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        descriptor(1),
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
        if (kernel.abi_schema != .native_xor_logup_trace_v1 or
            arguments.len != argument_count)
        {
            return error.InvalidKernelDescriptor;
        }
        self.launches += 1;
    }
};

const TestContext = struct {
    active_stage: telemetry.Stage = .trace_generation,

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
        return @ptrFromInt(slice.address);
    }
};

fn testDestinations(stride: usize) Destinations {
    return .{
        .preprocessed = testMatrix(
            0x1000,
            stride,
            @intCast(preprocessed_columns),
        ),
        .main = testMatrix(0x80_0000, stride, @intCast(main_columns)),
        .relation_sources = testMatrix(
            0x100_0000,
            stride,
            @intCast(relation_source_columns),
        ),
    };
}

fn testMatrix(
    address: usize,
    stride: usize,
    columns: usize,
) common.WordMatrix {
    return .{
        .storage = .{
            .address = address,
            .len = stride * columns,
            .owner = 7,
            .generation = 11,
        },
        .column_stride_words = stride,
    };
}
