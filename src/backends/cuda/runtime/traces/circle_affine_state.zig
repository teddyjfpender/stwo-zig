//! Strict-AOT binding for a circle-bit-reversed affine M31 state trace.

const std = @import("std");
const kernel_module = @import("../kernel.zig");
const runtime_error = @import("../error.zig");
const common = @import("../stages/common.zig");
const layout = @import("../stages/resident_layout.zig");
const telemetry = @import("../telemetry.zig");

pub const argument_count: u32 = 14;
pub const cache_key: u64 = 0x17c0a4c208b9f08a;
pub const kernel_name =
    "stwo_native_trace_circle_affine_state_slabs_v1_09db5e660658cf5e";

pub const preprocessed_columns: u32 = 1;
pub const main_columns: u32 = 2;

pub const Geometry = struct {
    log_n_rows: u32,
};

pub const Parameters = struct {
    initial_state: [2]u32,
};

pub const Recipe = struct {
    increment_coordinate: u32,
    increment_value: u64,
    indicator_first: u64,
    indicator_default: u64,
};

pub const Destinations = struct {
    preprocessed: common.WordMatrix,
    main: common.WordMatrix,
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
    preprocessed_slab: [*]u32,
    preprocessed_slab_words: u64,
    preprocessed_stride_words: u64,
    main_slab: [*]u32,
    main_slab_words: u64,
    main_stride_words: u64,
    row_count: u32,
    log_n_rows: u32,
    initial_state0: u64,
    initial_state1: u64,
    increment_coordinate: u32,
    increment_value: u64,
    indicator_first: u64,
    indicator_default: u64,

    fn pointers(self: *Arguments) [argument_count]?*anyopaque {
        return .{
            @ptrCast(&self.preprocessed_slab),
            @ptrCast(&self.preprocessed_slab_words),
            @ptrCast(&self.preprocessed_stride_words),
            @ptrCast(&self.main_slab),
            @ptrCast(&self.main_slab_words),
            @ptrCast(&self.main_stride_words),
            @ptrCast(&self.row_count),
            @ptrCast(&self.log_n_rows),
            @ptrCast(&self.initial_state0),
            @ptrCast(&self.initial_state1),
            @ptrCast(&self.increment_coordinate),
            @ptrCast(&self.increment_value),
            @ptrCast(&self.indicator_first),
            @ptrCast(&self.indicator_default),
        };
    }
};

pub fn prepare(
    session: anytype,
    destinations: Destinations,
    geometry: Geometry,
    parameters: Parameters,
    recipe: Recipe,
) runtime_error.Error!PreparedLaunch {
    try common.requireStage(session, .trace_generation);
    const rows = try rowCount(geometry.log_n_rows);
    if (recipe.increment_coordinate >= 2)
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
    try layout.requireDisjoint(
        &.{ preprocessed.range, main.range },
        &.{},
    );

    return .{
        .kernel = try descriptor(geometry.log_n_rows),
        .arguments = .{
            .preprocessed_slab = preprocessed.pointer,
            .preprocessed_slab_words = try u64Count(destinations.preprocessed.storage.len),
            .preprocessed_stride_words = try u64Count(preprocessed.stride_words),
            .main_slab = main.pointer,
            .main_slab_words = try u64Count(destinations.main.storage.len),
            .main_stride_words = try u64Count(main.stride_words),
            .row_count = rows,
            .log_n_rows = geometry.log_n_rows,
            .initial_state0 = parameters.initial_state[0],
            .initial_state1 = parameters.initial_state[1],
            .increment_coordinate = recipe.increment_coordinate,
            .increment_value = recipe.increment_value,
            .indicator_first = recipe.indicator_first,
            .indicator_default = recipe.indicator_default,
        },
    };
}

pub fn descriptor(log_n_rows: u32) runtime_error.Error!kernel_module.Kernel {
    const rows = try rowCount(log_n_rows);
    return .{
        .stage = .trace_generation,
        .abi_schema = .native_circle_affine_state_trace_v1,
        .cache_key = cache_key,
        .name = kernel_name,
        .grid = .{ 1 + (rows - 1) / 256, 1, 1 },
        .block = .{ 256, 1, 1 },
        .argument_count = argument_count,
    };
}

fn exactMatrix(
    session: anytype,
    matrix: common.WordMatrix,
    rows: u32,
    expected_columns: u32,
) runtime_error.Error!layout.WordMatrix {
    const resident = try layout.wordMatrix(session, matrix, rows);
    if (resident.column_count != expected_columns)
        return error.InvalidKernelDescriptor;
    const exact_words = std.math.mul(
        usize,
        resident.stride_words,
        expected_columns,
    ) catch return error.SizeOverflow;
    if (matrix.storage.len != exact_words)
        return error.InvalidKernelDescriptor;
    return resident;
}

fn rowCount(log_n_rows: u32) runtime_error.Error!u32 {
    if (log_n_rows == 0 or log_n_rows > 30)
        return error.InvalidKernelDescriptor;
    const shift: u5 = @intCast(log_n_rows);
    return @as(u32, 1) << shift;
}

fn u64Count(value: usize) runtime_error.Error!u64 {
    return std.math.cast(u64, value) orelse error.SizeOverflow;
}

test "circle affine state admits guard and non-target geometries" {
    var session = TestSession{};
    var guard = try prepare(
        &session,
        testDestinations(1 << 14),
        .{ .log_n_rows = 14 },
        .{ .initial_state = .{ 17, 23 } },
        testRecipe(),
    );
    try guard.launch(&session);
    var non_target = try prepare(
        &session,
        testDestinations(1 << 5),
        .{ .log_n_rows = 5 },
        .{ .initial_state = .{ 29, 31 } },
        testRecipe(),
    );
    try non_target.launch(&session);
    try std.testing.expectEqual(@as(u64, 2), session.launches);
}

test "circle affine state rejects shapes aliases and recipe drift" {
    var session = TestSession{};
    const geometry = Geometry{ .log_n_rows = 5 };
    const destinations = testDestinations(1 << 5);
    const parameters = Parameters{ .initial_state = .{ 17, 23 } };
    var short = destinations;
    short.main.storage.len -= 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, short, geometry, parameters, testRecipe()),
    );
    var alias = destinations;
    alias.main.storage.address = alias.preprocessed.storage.address;
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        prepare(&session, alias, geometry, parameters, testRecipe()),
    );
    var invalid = testRecipe();
    invalid.increment_coordinate = 2;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, destinations, geometry, parameters, invalid),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        descriptor(0),
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
        if (slice.address < 0x1000 or end > 0x20_0000)
            return error.InvalidDeviceAddress;
        return @ptrFromInt(slice.address);
    }
};

fn testDestinations(stride: usize) Destinations {
    return .{
        .preprocessed = testMatrix(0x1000, stride, preprocessed_columns),
        .main = testMatrix(0x40_000, stride, main_columns),
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

fn testRecipe() Recipe {
    return .{
        .increment_coordinate = 0,
        .increment_value = 1,
        .indicator_first = 1,
        .indicator_default = 0,
    };
}
