//! Strict-AOT binding for exact mixed-height Blake paired LogUp fractions.

const std = @import("std");
const field = @import("../../abi/field.zig");
const kernel_module = @import("../kernel.zig");
const runtime_error = @import("../error.zig");
const common = @import("../stages/common.zig");
const layout = @import("../stages/resident_layout.zig");
const telemetry = @import("../telemetry.zig");

pub const component_count: usize = 8;
pub const relation_element_count: usize = 14;
pub const argument_count: u32 = 12;
pub const cache_key: u64 = 0x3a3849f2a4f47320;
pub const kernel_name = "stwo_native_interaction_blake_exact_pairs_v1";
pub const program_identity = [32]u8{
    0xcb, 0x84, 0x34, 0x10, 0x1b, 0x21, 0xf5, 0x47,
    0x2e, 0x86, 0x76, 0xc6, 0x28, 0xa4, 0x02, 0x71,
    0x73, 0x62, 0x5b, 0x27, 0x6c, 0x56, 0x86, 0xee,
    0xc1, 0x02, 0xe3, 0x5e, 0x82, 0xe7, 0x1e, 0x61,
};

pub const main_columns = [component_count]usize{
    384, 384, 384, 256, 16, 16, 16, 1,
};
pub const secure_columns = [component_count]usize{
    6, 65, 65, 128, 8, 8, 8, 1,
};

pub const Component = struct {
    log_rows: u32,
    main: common.WordMatrix,
    preprocessed: ?common.WordMatrix,
    interaction: common.WordMatrix,
    denominators: common.SecureFields,
};

pub const Buffers = struct {
    relation_elements: common.SecureFields,
    components: [component_count]Component,
};

pub const PreparedLaunch = struct {
    components: [component_count]PreparedComponent,

    pub fn launch(
        self: *PreparedLaunch,
        session: anytype,
    ) runtime_error.Error!void {
        for (&self.components) |*component| {
            var pointers = component.arguments.pointers();
            try session.launchKernel(component.kernel, &pointers);
        }
    }
};

const PreparedComponent = struct {
    kernel: kernel_module.Kernel,
    arguments: Arguments,
};

const Arguments = struct {
    main_source: [*]u32,
    main_words: u64,
    preprocessed_source: ?[*]u32,
    preprocessed_words: u64,
    relations: [*]u32,
    relation_words: u64,
    output: [*]u32,
    output_words: u64,
    denominator_words: [*]u32,
    denominator_word_count: u64,
    component_index: u32,
    log_n_rows: u32,

    fn pointers(self: *Arguments) [argument_count]?*anyopaque {
        return .{
            @ptrCast(&self.main_source),
            @ptrCast(&self.main_words),
            @ptrCast(&self.preprocessed_source),
            @ptrCast(&self.preprocessed_words),
            @ptrCast(&self.relations),
            @ptrCast(&self.relation_words),
            @ptrCast(&self.output),
            @ptrCast(&self.output_words),
            @ptrCast(&self.denominator_words),
            @ptrCast(&self.denominator_word_count),
            @ptrCast(&self.component_index),
            @ptrCast(&self.log_n_rows),
        };
    }
};

pub fn prepare(
    session: anytype,
    buffers: Buffers,
    log_n_rows: u32,
) runtime_error.Error!PreparedLaunch {
    try common.requireStage(session, .constraint_evaluation);
    try validateStatement(log_n_rows);
    const relation = try exactSecure(
        session,
        buffers.relation_elements,
        relation_element_count,
    );
    var result: PreparedLaunch = undefined;
    var writes: [component_count * 2]layout.DeviceRange = undefined;
    var reads: [component_count * 2]layout.DeviceRange = undefined;
    var read_count: usize = 0;

    for (
        buffers.components,
        &result.components,
        0..,
    ) |component, *prepared_component, index| {
        const rows = try rowsAtLog(component.log_rows);
        if (component.log_rows != componentLog(log_n_rows, index))
            return error.InvalidKernelDescriptor;
        const main = try exactMatrix(
            session,
            component.main,
            main_columns[index],
            rows,
        );
        const interaction = try exactMatrix(
            session,
            component.interaction,
            4 * secure_columns[index],
            rows,
        );
        const denominators = try exactSecure(
            session,
            component.denominators,
            secure_columns[index] * rows,
        );
        const preprocessed = if (index >= 3)
            try exactMatrix(
                session,
                component.preprocessed orelse
                    return error.InvalidKernelDescriptor,
                3,
                rows,
            )
        else blk: {
            if (component.preprocessed != null)
                return error.InvalidKernelDescriptor;
            break :blk null;
        };
        reads[read_count] = main.range;
        read_count += 1;
        if (preprocessed) |source| {
            reads[read_count] = source.range;
            read_count += 1;
        }
        writes[2 * index] = interaction.range;
        writes[2 * index + 1] = denominators.range;
        prepared_component.* = .{
            .kernel = try descriptor(component.log_rows),
            .arguments = .{
                .main_source = main.pointer,
                .main_words = try u64Count(main_columns[index] * rows),
                .preprocessed_source = if (preprocessed) |value|
                    value.pointer
                else
                    null,
                .preprocessed_words = if (preprocessed != null)
                    try u64Count(3 * rows)
                else
                    0,
                .relations = @ptrCast(relation.pointer),
                .relation_words = relation_element_count * 4,
                .output = interaction.pointer,
                .output_words = try u64Count(
                    4 * secure_columns[index] * rows,
                ),
                .denominator_words = @ptrCast(denominators.pointer),
                .denominator_word_count = try u64Count(
                    4 * secure_columns[index] * rows,
                ),
                .component_index = @intCast(index),
                .log_n_rows = log_n_rows,
            },
        };
    }
    reads[read_count] = relation.range;
    read_count += 1;
    try layout.requireDisjoint(&writes, reads[0..read_count]);
    try layout.requireDisjoint(&writes, &.{});
    return result;
}

pub fn generate(
    session: anytype,
    buffers: Buffers,
    log_n_rows: u32,
) runtime_error.Error!void {
    var launch = try prepare(session, buffers, log_n_rows);
    try launch.launch(session);
}

pub fn descriptor(log_rows: u32) runtime_error.Error!kernel_module.Kernel {
    const rows = try rowsAtLog(log_rows);
    return .{
        .stage = .constraint_evaluation,
        .abi_schema = .native_blake_exact_interaction_v1,
        .cache_key = cache_key,
        .name = kernel_name,
        .grid = .{ @intCast((rows + 127) / 128), 1, 1 },
        .block = .{ 128, 1, 1 },
        .argument_count = argument_count,
    };
}

fn exactMatrix(
    session: anytype,
    matrix: common.WordMatrix,
    columns: usize,
    rows: usize,
) runtime_error.Error!layout.WordMatrix {
    if (matrix.column_stride_words != rows or
        matrix.storage.len != columns * rows)
    {
        return error.InvalidKernelDescriptor;
    }
    return layout.wordMatrix(session, matrix, rows);
}

fn exactSecure(
    session: anytype,
    values: common.SecureFields,
    count: usize,
) runtime_error.Error!layout.Resident(field.SecureField) {
    if (values.len != count) return error.InvalidKernelDescriptor;
    return layout.resident(session, field.SecureField, values, count);
}

fn validateStatement(log_n_rows: u32) runtime_error.Error!void {
    if (log_n_rows < 4 or log_n_rows > 13)
        return error.InvalidKernelDescriptor;
}

fn componentLog(log_n_rows: u32, index: usize) u32 {
    return switch (index) {
        0 => log_n_rows,
        1 => log_n_rows + 3,
        2 => log_n_rows + 1,
        3 => 16,
        4 => 14,
        5 => 12,
        6 => 10,
        7 => 8,
        else => unreachable,
    };
}

fn rowsAtLog(log_rows: u32) runtime_error.Error!usize {
    if (log_rows >= @bitSizeOf(usize))
        return error.SizeOverflow;
    return @as(usize, 1) << @intCast(log_rows);
}

fn u64Count(value: usize) runtime_error.Error!u64 {
    return std.math.cast(u64, value) orelse error.SizeOverflow;
}

test "exact interaction binding launches all mixed-height components" {
    var session = TestSession{};
    var components: [component_count]Component = undefined;
    var address: usize = 0x1_0000_0000;
    for (&components, 0..) |*component, index| {
        const log_rows = componentLog(4, index);
        const rows = try rowsAtLog(log_rows);
        const main_words = main_columns[index] * rows;
        const interaction_words = 4 * secure_columns[index] * rows;
        component.* = .{
            .log_rows = log_rows,
            .main = .{
                .storage = words(address, main_words),
                .column_stride_words = rows,
            },
            .preprocessed = if (index >= 3) .{
                .storage = words(address + main_words * 4, 3 * rows),
                .column_stride_words = rows,
            } else null,
            .interaction = .{
                .storage = words(
                    address + (main_words + 3 * rows) * 4,
                    interaction_words,
                ),
                .column_stride_words = rows,
            },
            .denominators = .{
                .address = address +
                    (main_words + 3 * rows + interaction_words) * 4,
                .len = secure_columns[index] * rows,
                .owner = 7,
                .generation = 11,
            },
        };
        address += (main_words + 3 * rows + 2 * interaction_words) * 4 +
            0x1000;
    }
    try generate(&session, .{
        .relation_elements = .{
            .address = address,
            .len = relation_element_count,
            .owner = 7,
            .generation = 11,
        },
        .components = components,
    }, 4);
    try std.testing.expectEqual(@as(u64, component_count), session.launches);
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
        if (kernel.abi_schema != .native_blake_exact_interaction_v1 or
            arguments.len != argument_count)
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
        return @ptrFromInt(slice.address);
    }
};

fn words(address: usize, len: usize) common.Words {
    return .{
        .address = address,
        .len = len,
        .owner = 7,
        .generation = 11,
    };
}
