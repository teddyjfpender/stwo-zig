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

fn buffers() relation.Buffers {
    return .{
        .drawn_z_alpha = slice(field.SecureField, 0x1000, 2),
        .alpha_powers = slice(field.SecureField, 0x1100, 2),
        .z = slice(field.SecureField, 0x1200, 1),
        .source_tables = slice(u32, 0x1300, 2),
        .descriptors = slice(u32, 0x1400, 2),
        .output_tables = slice(u32, 0x1500, 2),
        .denominator_slabs = slice(u32, 0x1600, 2),
        .geometry = slice(relation.Geometry, 0x1700, 1),
        .claimed_sums = slice(u32, 0x1800, 2),
        .reduction_partials = slice(u32, 0x1900, 4),
        .scan_block_sums = slice(u32, 0x1a00, 4),
    };
}

test "resident relation graph binds one stream and records exact launches" {
    TestApi.calls = 0;
    var session = TestSession{};
    TestApi.expected_stream = session.context.stream;

    try relation.OpsFor(TestApi).execute(&session, topology, buffers());

    try std.testing.expectEqual(@as(u32, 4), TestApi.calls);
    try std.testing.expectEqual(@as(u64, relation.launch_count), session.launches);
}

test "resident relation graph rejects alias and stage drift before launch" {
    TestApi.calls = 0;
    var session = TestSession{};
    TestApi.expected_stream = session.context.stream;
    var aliased = buffers();
    aliased.output_tables.address = aliased.source_tables.address;
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        relation.OpsFor(TestApi).execute(&session, topology, aliased),
    );
    try std.testing.expectEqual(@as(u32, 0), TestApi.calls);

    session.context.active_stage = .trace_generation;
    try std.testing.expectError(
        error.StageOrderViolation,
        relation.OpsFor(TestApi).execute(&session, topology, buffers()),
    );
    try std.testing.expectEqual(@as(u32, 0), TestApi.calls);
}
