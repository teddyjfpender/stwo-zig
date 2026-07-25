//! Strict-AOT binding for the exact mixed-height Native Blake witness.

const std = @import("std");
const kernel_module = @import("../kernel.zig");
const runtime_error = @import("../error.zig");
const common = @import("../stages/common.zig");
const resident_layout = @import("../stages/resident_layout.zig");
const telemetry = @import("../telemetry.zig");

pub const argument_count: u32 = 6;
pub const cache_key: u64 = 0xb475750894301a14;
pub const kernel_name =
    "stwo_native_trace_blake_exact_mixed_v2_b8a99643ffc4a29b";
pub const program_identity = [32]u8{
    0x29, 0x4a, 0x62, 0x64, 0xa1, 0x1c, 0x1e, 0xfb,
    0x77, 0xae, 0x3f, 0x31, 0x06, 0xa1, 0xb4, 0x29,
    0x3b, 0xdc, 0xa2, 0xaf, 0x75, 0x3e, 0x15, 0x73,
    0xf4, 0x54, 0x88, 0x95, 0xa5, 0x41, 0x31, 0x6c,
};

pub const preprocessed_group_count: usize = 5;
pub const main_group_count: usize = 8;
pub const exact_round_count: u32 = 10;
pub const minimum_log_rows: u32 = 4;
pub const maximum_log_rows: u32 = 13;

pub const Statement = struct {
    log_n_rows: u32,
    n_rounds: u32,
};

pub const Destinations = struct {
    preprocessed: common.Words,
    main: common.Words,
};

pub const Group = struct {
    first_column: u32,
    column_count: u32,
    log_rows: u32,
    offset_words: usize,
    words: usize,

    pub fn rowCount(self: Group) usize {
        return @as(usize, 1) << @intCast(self.log_rows);
    }
};

pub const Layout = struct {
    preprocessed: [preprocessed_group_count]Group,
    main: [main_group_count]Group,
    preprocessed_words: usize,
    main_words: usize,

    pub fn init(statement: Statement) runtime_error.Error!Layout {
        try validateStatement(statement);
        const table_logs = [5]u32{ 16, 14, 12, 10, 8 };
        const preprocessed_widths = [5]u32{ 3, 3, 3, 3, 3 };
        const main_logs = [8]u32{
            statement.log_n_rows,
            statement.log_n_rows + 3,
            statement.log_n_rows + 1,
            16,
            14,
            12,
            10,
            8,
        };
        const main_widths = [8]u32{
            384, 384, 384, 256, 16, 16, 16, 1,
        };
        var result: Layout = undefined;
        result.preprocessed_words = try fillGroups(
            &result.preprocessed,
            preprocessed_widths,
            table_logs,
            0,
            0,
        );
        result.main_words = try fillGroups(
            &result.main,
            main_widths,
            main_logs,
            0,
            0,
        );
        return result;
    }
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
    preprocessed_words: u64,
    main_slab: [*]u32,
    main_words: u64,
    log_n_rows: u32,
    n_rounds: u32,

    fn pointers(self: *Arguments) [argument_count]?*anyopaque {
        return .{
            @ptrCast(&self.preprocessed_slab),
            @ptrCast(&self.preprocessed_words),
            @ptrCast(&self.main_slab),
            @ptrCast(&self.main_words),
            @ptrCast(&self.log_n_rows),
            @ptrCast(&self.n_rounds),
        };
    }
};

pub fn prepare(
    session: anytype,
    destinations: Destinations,
    statement: Statement,
) runtime_error.Error!PreparedLaunch {
    try common.requireStage(session, .trace_generation);
    const shape = try Layout.init(statement);
    const preprocessed = try exactWords(
        session,
        destinations.preprocessed,
        shape.preprocessed_words,
    );
    const main = try exactWords(
        session,
        destinations.main,
        shape.main_words,
    );
    try resident_layout.requireDisjoint(
        &.{ preprocessed.range, main.range },
        &.{},
    );
    return .{
        .kernel = try descriptor(statement.log_n_rows),
        .arguments = .{
            .preprocessed_slab = preprocessed.pointer,
            .preprocessed_words = try u64Count(shape.preprocessed_words),
            .main_slab = main.pointer,
            .main_words = try u64Count(shape.main_words),
            .log_n_rows = statement.log_n_rows,
            .n_rounds = statement.n_rounds,
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

pub fn descriptor(
    log_n_rows: u32,
) runtime_error.Error!kernel_module.Kernel {
    try validateStatement(.{
        .log_n_rows = log_n_rows,
        .n_rounds = exact_round_count,
    });
    const work_rows = @max(
        @as(u32, 1) << @intCast(log_n_rows + 3),
        @as(u32, 1) << 16,
    );
    return .{
        .stage = .trace_generation,
        .abi_schema = .native_blake_exact_trace_v2,
        .cache_key = cache_key,
        .name = kernel_name,
        .grid = .{ 1 + (work_rows - 1) / 128, 1, 1 },
        .block = .{ 128, 1, 1 },
        .argument_count = argument_count,
    };
}

fn fillGroups(
    output: []Group,
    widths: anytype,
    logs: anytype,
    first_column: u32,
    first_word: usize,
) runtime_error.Error!usize {
    if (output.len != widths.len or output.len != logs.len)
        return error.InvalidKernelDescriptor;
    var column = first_column;
    var offset = first_word;
    for (output, widths, logs) |*group, width, log_rows| {
        const rows = @as(usize, 1) << @intCast(log_rows);
        const words = std.math.mul(
            usize,
            @intCast(width),
            rows,
        ) catch return error.SizeOverflow;
        group.* = .{
            .first_column = column,
            .column_count = width,
            .log_rows = log_rows,
            .offset_words = offset,
            .words = words,
        };
        column = std.math.add(
            u32,
            column,
            width,
        ) catch return error.SizeOverflow;
        offset = std.math.add(
            usize,
            offset,
            words,
        ) catch return error.SizeOverflow;
    }
    return offset;
}

fn validateStatement(statement: Statement) runtime_error.Error!void {
    if (statement.log_n_rows < minimum_log_rows or
        statement.log_n_rows > maximum_log_rows or
        statement.n_rounds != exact_round_count)
    {
        return error.InvalidKernelDescriptor;
    }
}

fn exactWords(
    session: anytype,
    words: common.Words,
    expected: usize,
) runtime_error.Error!resident_layout.Resident(u32) {
    if (words.len != expected) return error.InvalidKernelDescriptor;
    return resident_layout.resident(session, u32, words, expected);
}

fn u64Count(value: usize) runtime_error.Error!u64 {
    return std.math.cast(u64, value) orelse error.SizeOverflow;
}

test "exact Blake layout seals all mixed-height component groups" {
    const shape = try Layout.init(.{
        .log_n_rows = 5,
        .n_rounds = exact_round_count,
    });
    try std.testing.expectEqual(@as(u32, 5), shape.main[0].log_rows);
    try std.testing.expectEqual(@as(u32, 8), shape.main[1].log_rows);
    try std.testing.expectEqual(@as(u32, 6), shape.main[2].log_rows);
    try std.testing.expectEqual(@as(u32, 16), shape.main[3].log_rows);
    try std.testing.expectEqual(@as(u32, 1457), blk: {
        const last = shape.main[main_group_count - 1];
        break :blk last.first_column + last.column_count;
    });
}

test "exact Blake binding rejects aliases and incomplete slabs" {
    var session = TestSession{};
    const statement = Statement{
        .log_n_rows = 4,
        .n_rounds = exact_round_count,
    };
    const shape = try Layout.init(statement);
    const destinations = testDestinations(shape);
    var launch = try prepare(&session, destinations, statement);
    try launch.launch(&session);
    try std.testing.expectEqual(@as(u64, 1), session.launches);

    var short = destinations;
    short.main.len -= 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, short, statement),
    );
    var alias = destinations;
    alias.main.address = alias.preprocessed.address;
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        prepare(&session, alias, statement),
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
        if (kernel.abi_schema != .native_blake_exact_trace_v2 or
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
        return @ptrFromInt(slice.address);
    }
};

fn testDestinations(shape: Layout) Destinations {
    return .{
        .preprocessed = testWords(0x1000, shape.preprocessed_words),
        .main = testWords(0x1000_0000, shape.main_words),
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
