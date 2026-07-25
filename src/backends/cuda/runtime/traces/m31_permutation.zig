//! Strict-AOT binding for a structural 16-lane M31 permutation trace.

const std = @import("std");
const kernel_module = @import("../kernel.zig");
const runtime_error = @import("../error.zig");
const common = @import("../stages/common.zig");
const layout = @import("../stages/resident_layout.zig");
const telemetry = @import("../telemetry.zig");

pub const argument_count: u32 = 15;
pub const cache_key: u64 = 0xd5701a3db042081d;
pub const kernel_name =
    "stwo_native_trace_m31_permutation_slab_v2_92bacae40f1ca782";

pub const state_width: u32 = 16;

pub const Geometry = struct {
    log_n_rows: u32,
    replication_count: u32,
    half_full_rounds: u32,
    partial_rounds: u32,
};

pub const Recipe = struct {
    initial_row_stride: u64,
    initial_rep_stride: u64,
    external_constant_base: u64,
    external_round_stride: u64,
    external_lane_stride: u64,
    internal_constant_base: u64,
    internal_round_stride: u64,
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
    column_stride_words: u64,
    row_count: u32,
    log_n_rows: u32,
    replication_count: u32,
    half_full_rounds: u32,
    partial_rounds: u32,
    initial_row_stride: u64,
    initial_rep_stride: u64,
    external_constant_base: u64,
    external_round_stride: u64,
    external_lane_stride: u64,
    internal_constant_base: u64,
    internal_round_stride: u64,

    fn pointers(self: *Arguments) [argument_count]?*anyopaque {
        return .{
            @ptrCast(&self.trace_slab),
            @ptrCast(&self.trace_slab_words),
            @ptrCast(&self.column_stride_words),
            @ptrCast(&self.row_count),
            @ptrCast(&self.log_n_rows),
            @ptrCast(&self.replication_count),
            @ptrCast(&self.half_full_rounds),
            @ptrCast(&self.partial_rounds),
            @ptrCast(&self.initial_row_stride),
            @ptrCast(&self.initial_rep_stride),
            @ptrCast(&self.external_constant_base),
            @ptrCast(&self.external_round_stride),
            @ptrCast(&self.external_lane_stride),
            @ptrCast(&self.internal_constant_base),
            @ptrCast(&self.internal_round_stride),
        };
    }
};

pub fn prepare(
    session: anytype,
    destination: common.WordMatrix,
    geometry: Geometry,
    recipe: Recipe,
) runtime_error.Error!PreparedLaunch {
    try common.requireStage(session, .trace_generation);
    const row_count = try rowCount(geometry.log_n_rows);
    const column_count = try columnCount(geometry);
    try validateRecipe(geometry, recipe, row_count);

    const matrix = try layout.wordMatrix(session, destination, row_count);
    if (matrix.column_count != column_count)
        return error.InvalidKernelDescriptor;
    const exact_words = std.math.mul(
        usize,
        matrix.stride_words,
        column_count,
    ) catch return error.SizeOverflow;
    if (destination.storage.len != exact_words)
        return error.InvalidKernelDescriptor;

    return .{
        .kernel = try descriptor(geometry.log_n_rows),
        .arguments = .{
            .trace_slab = matrix.pointer,
            .trace_slab_words = try u64Count(destination.storage.len),
            .column_stride_words = try u64Count(matrix.stride_words),
            .row_count = row_count,
            .log_n_rows = geometry.log_n_rows,
            .replication_count = geometry.replication_count,
            .half_full_rounds = geometry.half_full_rounds,
            .partial_rounds = geometry.partial_rounds,
            .initial_row_stride = recipe.initial_row_stride,
            .initial_rep_stride = recipe.initial_rep_stride,
            .external_constant_base = recipe.external_constant_base,
            .external_round_stride = recipe.external_round_stride,
            .external_lane_stride = recipe.external_lane_stride,
            .internal_constant_base = recipe.internal_constant_base,
            .internal_round_stride = recipe.internal_round_stride,
        },
    };
}

pub fn descriptor(log_n_rows: u32) runtime_error.Error!kernel_module.Kernel {
    const rows = try rowCount(log_n_rows);
    return .{
        .stage = .trace_generation,
        .abi_schema = .native_m31_permutation_trace_v2,
        .cache_key = cache_key,
        .name = kernel_name,
        .grid = .{ 1 + (rows - 1) / 256, 1, 1 },
        .block = .{ 256, 1, 1 },
        .argument_count = argument_count,
    };
}

pub fn columnCount(geometry: Geometry) runtime_error.Error!u32 {
    if (geometry.replication_count == 0 or
        geometry.replication_count > 256 or
        geometry.half_full_rounds == 0 or
        geometry.half_full_rounds > 64 or
        geometry.partial_rounds == 0 or
        geometry.partial_rounds > 256)
    {
        return error.InvalidKernelDescriptor;
    }
    const full_round_columns = std.math.mul(
        u32,
        state_width,
        std.math.add(
            u32,
            1,
            std.math.mul(
                u32,
                2,
                geometry.half_full_rounds,
            ) catch return error.SizeOverflow,
        ) catch return error.SizeOverflow,
    ) catch return error.SizeOverflow;
    const columns_per_rep = std.math.add(
        u32,
        full_round_columns,
        geometry.partial_rounds,
    ) catch return error.SizeOverflow;
    return std.math.mul(
        u32,
        geometry.replication_count,
        columns_per_rep,
    ) catch return error.SizeOverflow;
}

fn rowCount(log_n_rows: u32) runtime_error.Error!u32 {
    if (log_n_rows > 30) return error.InvalidKernelDescriptor;
    const shift: u5 = @intCast(log_n_rows);
    return @as(u32, 1) << shift;
}

fn validateRecipe(
    geometry: Geometry,
    recipe: Recipe,
    rows: u32,
) runtime_error.Error!void {
    if (recipe.initial_row_stride == 0 or recipe.initial_rep_stride == 0)
        return error.InvalidKernelDescriptor;

    var maximum_initial = std.math.mul(
        u64,
        rows - 1,
        recipe.initial_row_stride,
    ) catch return error.SizeOverflow;
    maximum_initial = std.math.add(
        u64,
        maximum_initial,
        std.math.mul(
            u64,
            geometry.replication_count - 1,
            recipe.initial_rep_stride,
        ) catch return error.SizeOverflow,
    ) catch return error.SizeOverflow;
    _ = std.math.add(
        u64,
        maximum_initial,
        state_width - 1,
    ) catch return error.SizeOverflow;

    const full_round_count = std.math.mul(
        u32,
        2,
        geometry.half_full_rounds,
    ) catch return error.SizeOverflow;
    const maximum_external_round = std.math.mul(
        u64,
        full_round_count - 1,
        recipe.external_round_stride,
    ) catch return error.SizeOverflow;
    const maximum_external_round_and_lane = std.math.add(
        u64,
        maximum_external_round,
        std.math.mul(
            u64,
            state_width - 1,
            recipe.external_lane_stride,
        ) catch return error.SizeOverflow,
    ) catch return error.SizeOverflow;
    _ = std.math.add(
        u64,
        recipe.external_constant_base,
        maximum_external_round_and_lane,
    ) catch return error.SizeOverflow;

    const maximum_internal_round = std.math.mul(
        u64,
        geometry.partial_rounds - 1,
        recipe.internal_round_stride,
    ) catch return error.SizeOverflow;
    _ = std.math.add(
        u64,
        recipe.internal_constant_base,
        maximum_internal_round,
    ) catch return error.SizeOverflow;
}

fn u64Count(value: usize) runtime_error.Error!u64 {
    return std.math.cast(u64, value) orelse error.SizeOverflow;
}

test "M31 permutation binding admits target and non-target geometry" {
    var session = TestSession{};
    const recipe = testRecipe();
    var target = try prepare(
        &session,
        testMatrix(0x1000, 128, 1264),
        .{
            .log_n_rows = 7,
            .replication_count = 8,
            .half_full_rounds = 4,
            .partial_rounds = 14,
        },
        recipe,
    );
    try target.launch(&session);
    var non_target = try prepare(
        &session,
        testMatrix(0x1000, 8, 158),
        .{
            .log_n_rows = 3,
            .replication_count = 1,
            .half_full_rounds = 4,
            .partial_rounds = 14,
        },
        recipe,
    );
    try non_target.launch(&session);
    try std.testing.expectEqual(@as(u64, 2), session.launches);
}

test "M31 permutation binding rejects shape range and recipe drift" {
    var session = TestSession{};
    const geometry = Geometry{
        .log_n_rows = 3,
        .replication_count = 1,
        .half_full_rounds = 4,
        .partial_rounds = 14,
    };
    const matrix = testMatrix(0x1000, 8, 158);
    var short = matrix;
    short.storage.len -= 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, short, geometry, testRecipe()),
    );
    var foreign = matrix;
    foreign.storage.owner += 1;
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        prepare(&session, foreign, geometry, testRecipe()),
    );
    var invalid = testRecipe();
    invalid.initial_rep_stride = 0;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, matrix, geometry, invalid),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        descriptor(31),
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
        if (slice.address < 0x1000 or end > 0x10_0000_0000)
            return error.InvalidDeviceAddress;
        return @ptrFromInt(slice.address);
    }
};

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
        .initial_row_stride = 16,
        .initial_rep_stride = 1,
        .external_constant_base = 1234,
        .external_round_stride = 37,
        .external_lane_stride = 1,
        .internal_constant_base = 9876,
        .internal_round_stride = 17,
    };
}
