//! Arena-native binding for the exact mixed-height Blake AIR.

const std = @import("std");
const field = @import("../../abi/field.zig");
const kernel_module = @import("../kernel.zig");
const runtime_error = @import("../error.zig");
const common = @import("../stages/common.zig");
const layout = @import("../stages/resident_layout.zig");

pub const component_count: usize = 8;
pub const relation_element_count: usize = 14;
pub const claimed_sum_count: usize = component_count;
pub const constraint_count: usize = 417;
pub const argument_count: u32 = 20;
pub const cache_key: u64 = 0x3b9fbc925d6d3336;
pub const kernel_name =
    "stwo_native_constraint_blake_component_v1_64a336ee32f09d7e";

pub const ComponentKind = enum(u32) {
    scheduler,
    round,
    xor,
};

pub const ComponentDescriptor = struct {
    kind: ComponentKind,
    source_columns: u32,
    constraint_columns: u32,
    power_start: u32,
    trace_log_size: u32,
    evaluation_log_size: u32,
    relation_index: u32,
    claimed_sum_index: u32,
    xor_table_index: u32,
};

pub const ComponentBuffers = struct {
    source_evaluations: common.WordMatrix,
    denominator_inverses: common.Words,
};

pub const Buffers = struct {
    components: [component_count]ComponentBuffers,
    random_coefficient_powers: common.SecureFields,
    relation_elements: common.SecureFields,
    claimed_sums: common.SecureFields,
    composition_coordinates: common.WordMatrix,
};

pub const PreparedLaunch = struct {
    components: [component_count]PreparedComponent,

    pub fn launch(
        self: *PreparedLaunch,
        session: anytype,
    ) runtime_error.Error!void {
        for (&self.components) |*prepared_component| {
            var pointers = prepared_component.arguments.pointers();
            try session.launchKernel(prepared_component.kernel, &pointers);
        }
    }
};

const PreparedComponent = struct {
    kernel: kernel_module.Kernel,
    arguments: Arguments,
};

const Arguments = struct {
    source_slab: [*]u32,
    source_slab_words: u64,
    source_stride_words: u64,
    random_powers: [*]u32,
    random_power_words: u64,
    denominator_inverses: [*]u32,
    denominator_words: u64,
    relation_elements: [*]u32,
    relation_words: u64,
    claimed_sums: [*]u32,
    claimed_sum_words: u64,
    coordinate_slab: [*]u32,
    coordinate_slab_words: u64,
    coordinate_stride_words: u64,
    local_row_count: u32,
    trace_log_size: u32,
    evaluation_log_size: u32,
    maximum_evaluation_log_size: u32,
    component_index: u32,
    initialize_output: u32,

    fn pointers(self: *Arguments) [argument_count]?*anyopaque {
        return .{
            @ptrCast(&self.source_slab),
            @ptrCast(&self.source_slab_words),
            @ptrCast(&self.source_stride_words),
            @ptrCast(&self.random_powers),
            @ptrCast(&self.random_power_words),
            @ptrCast(&self.denominator_inverses),
            @ptrCast(&self.denominator_words),
            @ptrCast(&self.relation_elements),
            @ptrCast(&self.relation_words),
            @ptrCast(&self.claimed_sums),
            @ptrCast(&self.claimed_sum_words),
            @ptrCast(&self.coordinate_slab),
            @ptrCast(&self.coordinate_slab_words),
            @ptrCast(&self.coordinate_stride_words),
            @ptrCast(&self.local_row_count),
            @ptrCast(&self.trace_log_size),
            @ptrCast(&self.evaluation_log_size),
            @ptrCast(&self.maximum_evaluation_log_size),
            @ptrCast(&self.component_index),
            @ptrCast(&self.initialize_output),
        };
    }
};

pub fn prepare(
    session: anytype,
    buffers: Buffers,
    log_size: u32,
) runtime_error.Error!PreparedLaunch {
    try common.requireStage(session, .constraint_evaluation);
    const descriptors = try componentDescriptors(log_size);
    const maximum_log_size = try maximumEvaluationLogSize(log_size);
    const maximum_rows = try rowsAtLog(maximum_log_size);

    if (buffers.random_coefficient_powers.len != constraint_count or
        buffers.relation_elements.len != relation_element_count or
        buffers.claimed_sums.len != claimed_sum_count or
        buffers.composition_coordinates.column_stride_words != maximum_rows)
    {
        return error.InvalidKernelDescriptor;
    }

    const powers = try layout.resident(
        session,
        field.SecureField,
        buffers.random_coefficient_powers,
        constraint_count,
    );
    const relations = try layout.resident(
        session,
        field.SecureField,
        buffers.relation_elements,
        relation_element_count,
    );
    const claims = try layout.resident(
        session,
        field.SecureField,
        buffers.claimed_sums,
        claimed_sum_count,
    );
    const coordinates = try layout.wordMatrix(
        session,
        buffers.composition_coordinates,
        maximum_rows,
    );
    if (coordinates.column_count != 4)
        return error.InvalidKernelDescriptor;

    var result: PreparedLaunch = undefined;
    var read_ranges: [3 + 2 * component_count]layout.DeviceRange = undefined;
    read_ranges[0] = powers.range;
    read_ranges[1] = relations.range;
    read_ranges[2] = claims.range;
    for (descriptors, 0..) |descriptor, component_index| {
        const component_buffers = buffers.components[component_index];
        const local_rows = try rowsAtLog(descriptor.evaluation_log_size);
        if (component_buffers.source_evaluations.column_stride_words !=
            local_rows or
            component_buffers.denominator_inverses.len != 2)
        {
            return error.InvalidKernelDescriptor;
        }
        const sources = try layout.wordMatrix(
            session,
            component_buffers.source_evaluations,
            local_rows,
        );
        if (sources.column_count != descriptor.source_columns)
            return error.InvalidKernelDescriptor;
        const denominators = try layout.resident(
            session,
            u32,
            component_buffers.denominator_inverses,
            2,
        );
        read_ranges[3 + 2 * component_index] = sources.range;
        read_ranges[4 + 2 * component_index] = denominators.range;

        result.components[component_index] = .{
            .kernel = try descriptorForRows(local_rows),
            .arguments = .{
                .source_slab = sources.pointer,
                .source_slab_words = try u64Count(
                    component_buffers.source_evaluations.storage.len,
                ),
                .source_stride_words = try u64Count(sources.stride_words),
                .random_powers = @ptrCast(powers.pointer),
                .random_power_words = try secureWordCount(constraint_count),
                .denominator_inverses = denominators.pointer,
                .denominator_words = 2,
                .relation_elements = @ptrCast(relations.pointer),
                .relation_words = try secureWordCount(
                    relation_element_count,
                ),
                .claimed_sums = @ptrCast(claims.pointer),
                .claimed_sum_words = try secureWordCount(claimed_sum_count),
                .coordinate_slab = coordinates.pointer,
                .coordinate_slab_words = try u64Count(
                    buffers.composition_coordinates.storage.len,
                ),
                .coordinate_stride_words = try u64Count(
                    coordinates.stride_words,
                ),
                .local_row_count = local_rows,
                .trace_log_size = descriptor.trace_log_size,
                .evaluation_log_size = descriptor.evaluation_log_size,
                .maximum_evaluation_log_size = maximum_log_size,
                .component_index = @intCast(component_index),
                .initialize_output = @intFromBool(component_index == 0),
            },
        };
    }
    try layout.requireDisjoint(
        &.{coordinates.range},
        &read_ranges,
    );
    return result;
}

pub fn componentDescriptors(
    log_size: u32,
) runtime_error.Error![component_count]ComponentDescriptor {
    if (log_size < 4 or log_size > 24)
        return error.InvalidKernelDescriptor;
    return .{
        component(.scheduler, 408, 6, 411, log_size, log_size + 1, 0, 0, 0),
        component(.round, 644, 129, 282, log_size + 3, log_size + 4, 1, 6, 0),
        component(.round, 644, 129, 153, log_size + 1, log_size + 2, 1, 7, 0),
        component(.xor, 771, 128, 25, 16, 17, 2, 1, 0),
        component(.xor, 51, 8, 17, 14, 15, 3, 2, 1),
        component(.xor, 51, 8, 9, 12, 13, 4, 3, 2),
        component(.xor, 51, 8, 1, 10, 11, 5, 4, 3),
        component(.xor, 8, 1, 0, 8, 9, 6, 5, 4),
    };
}

pub fn maximumEvaluationLogSize(
    log_size: u32,
) runtime_error.Error!u32 {
    if (log_size < 4 or log_size > 24)
        return error.InvalidKernelDescriptor;
    return @max(log_size + 4, 17);
}

fn component(
    kind: ComponentKind,
    source_columns: u32,
    constraint_columns: u32,
    power_start: u32,
    trace_log_size: u32,
    evaluation_log_size: u32,
    relation_index: u32,
    claimed_sum_index: u32,
    xor_table_index: u32,
) ComponentDescriptor {
    return .{
        .kind = kind,
        .source_columns = source_columns,
        .constraint_columns = constraint_columns,
        .power_start = power_start,
        .trace_log_size = trace_log_size,
        .evaluation_log_size = evaluation_log_size,
        .relation_index = relation_index,
        .claimed_sum_index = claimed_sum_index,
        .xor_table_index = xor_table_index,
    };
}

fn descriptorForRows(
    rows: u32,
) runtime_error.Error!kernel_module.Kernel {
    return .{
        .stage = .constraint_evaluation,
        .abi_schema = .native_blake_constraint_v1,
        .cache_key = cache_key,
        .name = kernel_name,
        .grid = .{ 1 + (rows - 1) / 64, 1, 1 },
        .block = .{ 64, 1, 1 },
        .argument_count = argument_count,
    };
}

fn rowsAtLog(log_size: u32) runtime_error.Error!u32 {
    if (log_size >= 31) return error.SizeOverflow;
    return @as(u32, 1) << @intCast(log_size);
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

test "exact Blake descriptors preserve mixed-height AIR and power order" {
    const descriptors = try componentDescriptors(13);
    try std.testing.expectEqual(@as(u32, 17), descriptors[1].evaluation_log_size);
    try std.testing.expectEqual(@as(u32, 17), descriptors[3].evaluation_log_size);
    try std.testing.expectEqual(@as(u32, 9), descriptors[7].evaluation_log_size);
    var constraints: u32 = 0;
    for (descriptors) |descriptor| {
        constraints += descriptor.constraint_columns;
    }
    try std.testing.expectEqual(@as(u32, constraint_count), constraints);
    try std.testing.expectEqual(@as(u32, 411), descriptors[0].power_start);
    try std.testing.expectEqual(@as(u32, 0), descriptors[7].power_start);
    try std.testing.expectEqual(
        [component_count]u32{ 0, 6, 7, 1, 2, 3, 4, 5 },
        blk: {
            var indices: [component_count]u32 = undefined;
            for (descriptors, &indices) |descriptor, *index| {
                index.* = descriptor.claimed_sum_index;
            }
            break :blk indices;
        },
    );
}

test "exact Blake descriptor rejects geometry outside resident u32 domains" {
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        componentDescriptors(3),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        componentDescriptors(25),
    );
}

test "exact Blake binding accepts only complete component-local slabs" {
    var session = TestSession{};
    var buffers = testBuffers(4);
    var launch = try prepare(&session, buffers, 4);
    try launch.launch(&session);
    try std.testing.expectEqual(
        @as(u64, component_count),
        session.launches,
    );

    buffers.components[3].source_evaluations.column_stride_words -= 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        prepare(&session, buffers, 4),
    );
}

test "exact Blake binding rejects output aliasing a component source" {
    var session = TestSession{};
    var buffers = testBuffers(4);
    buffers.composition_coordinates.storage.address =
        buffers.components[0].source_evaluations.storage.address;
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        prepare(&session, buffers, 4),
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
            kernel.abi_schema != .native_blake_constraint_v1 or
            pointers.len != argument_count)
        {
            return error.InvalidKernelDescriptor;
        }
        self.launches += 1;
    }
};

const TestContext = struct {
    pub fn requireStage(
        _: *TestContext,
        expected: @import("../telemetry.zig").Stage,
    ) runtime_error.Error!void {
        if (expected != .constraint_evaluation)
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

fn testBuffers(log_size: u32) Buffers {
    const descriptors = componentDescriptors(log_size) catch unreachable;
    const maximum_log = maximumEvaluationLogSize(log_size) catch unreachable;
    const maximum_rows = rowsAtLog(maximum_log) catch unreachable;
    var next_address: usize = 0x10_000;
    var components: [component_count]ComponentBuffers = undefined;
    for (descriptors, 0..) |descriptor, index| {
        const rows = rowsAtLog(descriptor.evaluation_log_size) catch
            unreachable;
        const source_words = @as(usize, descriptor.source_columns) * rows;
        components[index] = .{
            .source_evaluations = .{
                .storage = testWords(next_address, source_words),
                .column_stride_words = rows,
            },
            .denominator_inverses = testWords(
                next_address + source_words * @sizeOf(u32),
                2,
            ),
        };
        next_address += source_words * @sizeOf(u32) + 0x1000;
    }
    const powers_address = next_address;
    const relations_address = powers_address +
        constraint_count * @sizeOf(field.SecureField) + 0x1000;
    const claims_address = relations_address +
        relation_element_count * @sizeOf(field.SecureField) + 0x1000;
    const coordinates_address = claims_address +
        claimed_sum_count * @sizeOf(field.SecureField) + 0x1000;
    return .{
        .components = components,
        .random_coefficient_powers = testSecure(
            powers_address,
            constraint_count,
        ),
        .relation_elements = testSecure(
            relations_address,
            relation_element_count,
        ),
        .claimed_sums = testSecure(
            claims_address,
            claimed_sum_count,
        ),
        .composition_coordinates = .{
            .storage = testWords(
                coordinates_address,
                4 * maximum_rows,
            ),
            .column_stride_words = maximum_rows,
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
