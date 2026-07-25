//! Strict-AOT binding for a structural seeded-xorshift M31 trace recipe.

const std = @import("std");
const kernel_module = @import("../kernel.zig");
const runtime_error = @import("../error.zig");
const common = @import("../stages/common.zig");
const layout = @import("../stages/resident_layout.zig");
const telemetry = @import("../telemetry.zig");

pub const argument_count: u32 = 13;
pub const cache_key: u64 = 0x1888a1a02b4e35b5;
pub const kernel_name =
    "stwo_native_trace_seeded_xorshift_slab_v1_21cc1d6d9728809e";

pub const Geometry = struct {
    log_n_rows: u32,
    group_count: u32,
    columns_per_group: u32,
};

pub const Recipe = struct {
    seed_offset: u64,
    left_shift: u32,
    right_shift: u32,
    final_left_shift: u32,
    group_mix: u64,
    item_mix: u64,
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
    group_count: u32,
    columns_per_group: u32,
    seed_offset: u64,
    left_shift: u32,
    right_shift: u32,
    final_left_shift: u32,
    group_mix: u64,
    item_mix: u64,

    fn pointers(self: *Arguments) [argument_count]?*anyopaque {
        return .{
            @ptrCast(&self.trace_slab),
            @ptrCast(&self.trace_slab_words),
            @ptrCast(&self.column_stride_words),
            @ptrCast(&self.row_count),
            @ptrCast(&self.log_n_rows),
            @ptrCast(&self.group_count),
            @ptrCast(&self.columns_per_group),
            @ptrCast(&self.seed_offset),
            @ptrCast(&self.left_shift),
            @ptrCast(&self.right_shift),
            @ptrCast(&self.final_left_shift),
            @ptrCast(&self.group_mix),
            @ptrCast(&self.item_mix),
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
    try validateRecipe(recipe, row_count);

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
            .group_count = geometry.group_count,
            .columns_per_group = geometry.columns_per_group,
            .seed_offset = recipe.seed_offset,
            .left_shift = recipe.left_shift,
            .right_shift = recipe.right_shift,
            .final_left_shift = recipe.final_left_shift,
            .group_mix = recipe.group_mix,
            .item_mix = recipe.item_mix,
        },
    };
}

pub fn descriptor(log_n_rows: u32) runtime_error.Error!kernel_module.Kernel {
    const rows = try rowCount(log_n_rows);
    return .{
        .stage = .trace_generation,
        .abi_schema = .native_seeded_xorshift_trace_v1,
        .cache_key = cache_key,
        .name = kernel_name,
        .grid = .{ 1 + (rows - 1) / 256, 1, 1 },
        .block = .{ 256, 1, 1 },
        .argument_count = argument_count,
    };
}

fn rowCount(log_n_rows: u32) runtime_error.Error!u32 {
    if (log_n_rows == 0 or log_n_rows > 30) return error.InvalidKernelDescriptor;
    const shift: u5 = @intCast(log_n_rows);
    return @as(u32, 1) << shift;
}

fn columnCount(geometry: Geometry) runtime_error.Error!u32 {
    if (geometry.group_count == 0 or geometry.columns_per_group == 0)
        return error.InvalidKernelDescriptor;
    return std.math.mul(
        u32,
        geometry.group_count,
        geometry.columns_per_group,
    ) catch return error.SizeOverflow;
}

fn validateRecipe(recipe: Recipe, rows: u32) runtime_error.Error!void {
    if (recipe.left_shift == 0 or recipe.left_shift >= 64 or
        recipe.right_shift == 0 or recipe.right_shift >= 64 or
        recipe.final_left_shift == 0 or recipe.final_left_shift >= 64)
    {
        return error.InvalidKernelDescriptor;
    }
    _ = std.math.add(
        u64,
        recipe.seed_offset,
        rows - 1,
    ) catch return error.SizeOverflow;
}

fn u64Count(value: usize) runtime_error.Error!u64 {
    return std.math.cast(u64, value) orelse error.SizeOverflow;
}

test "seeded-xorshift binding admits target and non-target geometry" {
    var session = TestSession{};
    var target = try prepare(
        &session,
        testMatrix(0x1000, 8, 960),
        .{ .log_n_rows = 3, .group_count = 10, .columns_per_group = 96 },
        testRecipe(),
    );
    try target.launch(&session);
    var non_target = try prepare(
        &session,
        testMatrix(0x1000, 8, 111),
        .{ .log_n_rows = 3, .group_count = 3, .columns_per_group = 37 },
        testRecipe(),
    );
    try non_target.launch(&session);
    try std.testing.expectEqual(@as(u64, 2), session.launches);
}

test "seeded-xorshift binding rejects range shape and recipe drift" {
    var session = TestSession{};
    const geometry = Geometry{
        .log_n_rows = 3,
        .group_count = 2,
        .columns_per_group = 5,
    };
    const matrix = testMatrix(0x1000, 8, 10);
    var foreign = matrix;
    foreign.storage.owner += 1;
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        prepare(&session, foreign, geometry, testRecipe()),
    );
    var short = matrix;
    short.storage.len -= 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, short, geometry, testRecipe()),
    );
    var bad_recipe = testRecipe();
    bad_recipe.right_shift = 64;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, matrix, geometry, bad_recipe),
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
        if (slice.address < 0x1000 or end > 0x200000)
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
        .seed_offset = 1,
        .left_shift = 13,
        .right_shift = 7,
        .final_left_shift = 17,
        .group_mix = 0x9e37_79b9_7f4a_7c15,
        .item_mix = 0x517c_c1b7_2722_0a95,
    };
}
