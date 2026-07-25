//! Executable contract tests for the resident relation-graph wrapper.

const std = @import("std");
const field = @import("../../abi/field.zig");
const relation = @import("relation.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

const owner: usize = 7;
const generation: u64 = 11;

const TestApi = struct {
    var calls: u32 = 0;
    var expected_stream: *anyopaque = undefined;

    fn accept(stream: *anyopaque) c_int {
        if (stream != expected_stream) return 1;
        calls += 1;
        return 0;
    }

    pub fn stwo_relation_expand_challenges_on(
        _: [*]const field.SecureField,
        _: [*]field.SecureField,
        alpha_count: u32,
        _: *field.SecureField,
        stream: *anyopaque,
    ) c_int {
        if (alpha_count != 2) return 1;
        return accept(stream);
    }

    pub fn stwo_relation_pairs_global_on(
        _: [*]const u32,
        _: [*]const u32,
        _: [*]const u32,
        _: [*]const u32,
        _: [*]const relation.Geometry,
        instances: u32,
        pair_blocks: u32,
        _: [*]const field.SecureField,
        alpha_count: u32,
        _: *const field.SecureField,
        stream: *anyopaque,
    ) c_int {
        if (instances != 1 or pair_blocks != 2 or alpha_count != 2) return 1;
        return accept(stream);
    }

    pub fn stwo_relation_fraction_chain_global_on(
        _: [*]const u32,
        _: [*]const u32,
        _: [*]const relation.Geometry,
        instances: u32,
        inverse_blocks: u32,
        chain_blocks: u32,
        stream: *anyopaque,
    ) c_int {
        if (instances != 1 or inverse_blocks != 1 or chain_blocks != 1)
            return 1;
        return accept(stream);
    }

    pub fn stwo_relation_tail_global_on(
        _: [*]const u32,
        _: [*]const u32,
        _: [*]const relation.Geometry,
        instances: u32,
        row_blocks: u32,
        _: [*]u32,
        reduction_capacity: u32,
        _: [*]u32,
        scan_capacity: u32,
        stream: *anyopaque,
    ) c_int {
        if (instances != 1 or row_blocks != 1 or
            reduction_capacity != 1 or scan_capacity != 4)
        {
            return 1;
        }
        return accept(stream);
    }
};

const TestContext = struct {
    active_stage: telemetry.Stage = .constraint_evaluation,
    stream: *anyopaque = @ptrFromInt(0x3000),

    pub fn requireStage(
        self: *TestContext,
        expected: telemetry.Stage,
    ) runtime_error.Error!void {
        if (self.active_stage != expected) return error.StageOrderViolation;
    }

    pub fn deviceSlicePointer(
        _: *TestContext,
        comptime F: type,
        device_slice: anytype,
        minimum: usize,
    ) runtime_error.Error![*]F {
        if (minimum == 0 or device_slice.len < minimum or
            device_slice.owner != owner or
            device_slice.generation != generation or
            device_slice.address % @alignOf(F) != 0)
        {
            return error.InvalidDeviceAddress;
        }
        return @ptrFromInt(device_slice.address);
    }
};

const TestSession = struct {
    context: TestContext = .{},
    launches: u64 = 0,

    pub fn recordOrdinaryKernel(
        self: *TestSession,
        stage: telemetry.Stage,
        status: c_int,
    ) runtime_error.Error!void {
        try self.recordOrdinaryKernels(stage, status, 1);
    }

    pub fn recordOrdinaryKernels(
        self: *TestSession,
        stage: telemetry.Stage,
        status: c_int,
        count: u64,
    ) runtime_error.Error!void {
        try self.context.requireStage(stage);
        try runtime_error.check(status);
        self.launches += count;
    }
};

fn slice(comptime F: type, address: usize, len: usize) @import(
    "../column.zig",
).DeviceSlice(F) {
    return .{
        .address = address,
        .len = len,
        .owner = owner,
        .generation = generation,
    };
}

const geometry = [_]relation.Geometry{.{
    .pair_first = 0,
    .pair_blocks = 2,
    .inverse_first = 0,
    .inverse_blocks = 1,
    .row_first = 0,
    .row_blocks = 1,
    .rows = 16,
    .columns = 2,
    .real_rows = 16,
    .source_offset_rows = 0,
    .inverse_rows = 1 << 27,
}};

const topology = relation.Topology{
    .geometry = &geometry,
    .max_alpha_powers = 2,
    .total_pair_blocks = 2,
    .total_inverse_blocks = 1,
    .total_chain_blocks = 1,
    .total_row_blocks = 1,
};

fn buffers() relation.DeviceBuffers {
    return .{
        .drawn_z_alpha = slice(field.SecureField, 0x10_0000, 2),
        .alpha_powers = slice(field.SecureField, 0x10_0100, 2),
        .z = slice(field.SecureField, 0x10_0200, 1),
        .source_tables = slice(u32, 0x10_0300, 2),
        .descriptors = slice(u32, 0x10_0400, 2),
        .output_tables = slice(u32, 0x10_0500, 2),
        .denominator_slabs = slice(u32, 0x10_0600, 2),
        .geometry = slice(relation.Geometry, 0x10_0700, 1),
        .claimed_sums = slice(u32, 0x10_0800, 2),
        .reduction_partials = slice(u32, 0x10_0900, 4),
        .scan_block_sums = slice(u32, 0x10_0a00, 4),
    };
}

const direct = relation.UseDescriptor.init(
    .projected_columns_no_id,
    0,
    2,
    0,
    .one,
    0,
    false,
);
const descriptors = [_]relation.ColumnDescriptor{
    relation.ColumnDescriptor.pair(direct, direct),
    relation.ColumnDescriptor.single(direct),
};
const source_columns = [_]@import("../column.zig").DeviceSlice(u32){
    slice(u32, 0x20_0000, 16),
    slice(u32, 0x20_1000, 16),
};
const output_coordinates = [_]@import("../column.zig").DeviceSlice(u32){
    slice(u32, 0x30_0000, 16),
    slice(u32, 0x30_1000, 16),
    slice(u32, 0x30_2000, 16),
    slice(u32, 0x30_3000, 16),
    slice(u32, 0x30_4000, 16),
    slice(u32, 0x30_5000, 16),
    slice(u32, 0x30_6000, 16),
    slice(u32, 0x30_7000, 16),
};

fn instance() relation.InstanceBinding {
    return .{
        .source_pointer_table = slice(u32, 0x40_0000, 4),
        .source_columns = &source_columns,
        .descriptor_storage = slice(u32, 0x40_1000, 32),
        .descriptors = &descriptors,
        .output_pointer_table = slice(u32, 0x40_2000, 16),
        .output_coordinates = &output_coordinates,
        .denominator_slab = slice(field.SecureField, 0x40_3000, 32),
        .claimed_sum = slice(field.SecureField, 0x40_5000, 1),
    };
}

test "resident relation graph binds one stream and records exact launches" {
    TestApi.calls = 0;
    var session = TestSession{};
    TestApi.expected_stream = session.context.stream;
    const instances = [_]relation.InstanceBinding{instance()};
    const prepared = try relation.prepare(std.testing.allocator, .{
        .topology = topology,
        .buffers = buffers(),
        .instances = &instances,
    });
    defer relation.deinit(std.testing.allocator, prepared);

    try relation.OpsFor(TestApi).execute(&session, prepared);

    try std.testing.expectEqual(@as(u32, 4), TestApi.calls);
    try std.testing.expectEqual(@as(u64, relation.launch_count), session.launches);
}

test "relation transcript binding seals challenges and canonical claims" {
    const instances = [_]relation.InstanceBinding{instance()};
    const prepared = try relation.prepare(std.testing.allocator, .{
        .topology = topology,
        .buffers = buffers(),
        .instances = &instances,
    });
    defer relation.deinit(std.testing.allocator, prepared);

    try relation.validateTranscriptChallenge(
        prepared,
        buffers().drawn_z_alpha,
    );
    try std.testing.expectEqual(
        slice(u32, 0x40_5000, 4),
        try relation.transcriptClaims(prepared),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        relation.validateTranscriptChallenge(
            prepared,
            slice(field.SecureField, 0x10_1000, 2),
        ),
    );
}

test "resident relation graph rejects alias and stage drift before launch" {
    TestApi.calls = 0;
    var session = TestSession{};
    TestApi.expected_stream = session.context.stream;
    var aliased = instance();
    var aliased_outputs = output_coordinates;
    aliased_outputs[0] = source_columns[0];
    aliased.output_coordinates = &aliased_outputs;
    const aliased_instances = [_]relation.InstanceBinding{aliased};
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        relation.prepare(std.testing.allocator, .{
            .topology = topology,
            .buffers = buffers(),
            .instances = &aliased_instances,
        }),
    );
    try std.testing.expectEqual(@as(u32, 0), TestApi.calls);

    const instances = [_]relation.InstanceBinding{instance()};
    const prepared = try relation.prepare(std.testing.allocator, .{
        .topology = topology,
        .buffers = buffers(),
        .instances = &instances,
    });
    defer relation.deinit(std.testing.allocator, prepared);
    session.context.active_stage = .trace_generation;
    try std.testing.expectError(
        error.StageOrderViolation,
        relation.OpsFor(TestApi).execute(&session, prepared),
    );
    try std.testing.expectEqual(@as(u32, 0), TestApi.calls);
}

test "resident relation graph ranges the complete flattened lookup source" {
    var flattened = instance();
    const extents = [_]u32{ 32, 16 };
    flattened.source_word_extents = &extents;

    var undersized_sources = source_columns;
    undersized_sources[0].len = 31;
    flattened.source_columns = &undersized_sources;
    const undersized = [_]relation.InstanceBinding{flattened};
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        relation.prepare(std.testing.allocator, .{
            .topology = topology,
            .buffers = buffers(),
            .instances = &undersized,
        }),
    );

    var overlapping_sources = source_columns;
    overlapping_sources[0].len = 32;
    flattened.source_columns = &overlapping_sources;
    var overlapping_outputs = output_coordinates;
    overlapping_outputs[0] = slice(u32, 0x20_0040, 16);
    flattened.output_coordinates = &overlapping_outputs;
    const overlapping = [_]relation.InstanceBinding{flattened};
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        relation.prepare(std.testing.allocator, .{
            .topology = topology,
            .buffers = buffers(),
            .instances = &overlapping,
        }),
    );
}

test "prepared plan rejects unaligned pointer tables and stale pointees" {
    var unaligned_buffers = buffers();
    unaligned_buffers.source_tables.address += @sizeOf(u32);
    const instances = [_]relation.InstanceBinding{instance()};
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        relation.prepare(std.testing.allocator, .{
            .topology = topology,
            .buffers = unaligned_buffers,
            .instances = &instances,
        }),
    );

    var stale = instance();
    var stale_sources = source_columns;
    stale_sources[0].generation += 1;
    stale.source_columns = &stale_sources;
    const stale_instances = [_]relation.InstanceBinding{stale};
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        relation.prepare(std.testing.allocator, .{
            .topology = topology,
            .buffers = buffers(),
            .instances = &stale_instances,
        }),
    );
}

test "relation topology rejects CUDA signed extent overflow" {
    const rows: u32 = 1 << 30;
    const columns: u32 = 2;
    const row_blocks = rows / 256;
    const too_large_geometry = [_]relation.Geometry{.{
        .pair_first = 0,
        .pair_blocks = row_blocks * columns,
        .inverse_first = 0,
        .inverse_blocks = (rows / 1024) * columns,
        .row_first = 0,
        .row_blocks = row_blocks,
        .rows = rows,
        .columns = columns,
        .real_rows = rows,
        .source_offset_rows = 0,
        .inverse_rows = 2,
    }};
    const too_large = relation.Topology{
        .geometry = &too_large_geometry,
        .max_alpha_powers = 2,
        .total_pair_blocks = too_large_geometry[0].pair_blocks,
        .total_inverse_blocks = too_large_geometry[0].inverse_blocks,
        .total_chain_blocks = row_blocks,
        .total_row_blocks = row_blocks,
    };
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        too_large.validate(),
    );
}

test "relation topology rejects cumulative offsets and row inverse drift" {
    var changed = geometry;
    changed[0].pair_first = 1;
    var changed_topology = topology;
    changed_topology.geometry = &changed;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        changed_topology.validate(),
    );

    changed = geometry;
    changed[0].inverse_rows = 1;
    changed_topology.geometry = &changed;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        changed_topology.validate(),
    );
}

test "relation topology matches ragged inverse transitions" {
    const row_counts = [_]u32{ 1, 2, 512, 1024, 2048 };
    for (row_counts) |rows| {
        const row_blocks = blockCount(rows, 256);
        const pair_blocks = row_blocks * 2;
        const inverse_blocks = blockCount(rows * 2, 1024);
        const row_geometry = [_]relation.Geometry{.{
            .pair_first = 0,
            .pair_blocks = pair_blocks,
            .inverse_first = 0,
            .inverse_blocks = inverse_blocks,
            .row_first = 0,
            .row_blocks = row_blocks,
            .rows = rows,
            .columns = 2,
            .real_rows = rows,
            .source_offset_rows = 0,
            .inverse_rows = inverseRowCount(rows),
        }};
        const row_topology = relation.Topology{
            .geometry = &row_geometry,
            .max_alpha_powers = 2,
            .total_pair_blocks = pair_blocks,
            .total_inverse_blocks = inverse_blocks,
            .total_chain_blocks = row_blocks,
            .total_row_blocks = row_blocks,
        };
        try row_topology.validate();
    }
}

fn blockCount(values: u32, block_size: u32) u32 {
    return values / block_size + @intFromBool(values % block_size != 0);
}

fn inverseRowCount(rows: u32) u32 {
    const log_rows = std.math.log2_int(u32, rows);
    return if (log_rows == 0) 1 else @as(u32, 1) << @intCast(31 - log_rows);
}
