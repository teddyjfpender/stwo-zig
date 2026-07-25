const std = @import("std");
const memory = @import("memory.zig");
const telemetry = @import("../../telemetry.zig");

test "memory split binds exact big and small resident columns" {
    var session = TestSession{};
    var big_outputs: [memory.big_limb_count]Words = undefined;
    fillColumns(&big_outputs, 0x20_0000, 16);
    try memory.OpsFor(TestApi).split(
        &session,
        .{ .kind = .big, .value_count = 2, .row_count = 16 },
        .{
            .values = words(0x10_0000, 16),
            .outputs = &big_outputs,
        },
    );
    var small_outputs: [memory.small_limb_count]Words = undefined;
    fillColumns(&small_outputs, 0x40_0000, 16);
    try memory.OpsFor(TestApi).split(
        &session,
        .{ .kind = .small, .value_count = 3, .row_count = 16 },
        .{
            .values = words(0x30_0000, 12),
            .outputs = &small_outputs,
        },
    );
    try std.testing.expectEqual(@as(u64, 2), session.launches);
    try std.testing.expectEqual(@as(u32, 2), TestApi.big_value_count);
    try std.testing.expectEqual(@as(u32, 3), TestApi.small_value_count);
}

test "memory split zero-value padding requires an absent source" {
    var outputs: [memory.small_limb_count]Words = undefined;
    fillColumns(&outputs, 0x20_0000, 16);
    var session = TestSession{};
    try memory.OpsFor(TestApi).split(
        &session,
        .{ .kind = .small, .value_count = 0, .row_count = 16 },
        .{ .values = words(0, 0), .outputs = &outputs },
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        memory.OpsFor(TestApi).split(
            &session,
            .{ .kind = .small, .value_count = 0, .row_count = 16 },
            .{ .values = words(0x1000, 1), .outputs = &outputs },
        ),
    );
}

test "memory address base rejects extent and alias drift" {
    var outputs: [memory.address_column_count]Words = undefined;
    fillColumns(&outputs, 0x30_0000, 16);
    const geometry = memory.AddressGeometry{
        .address_id_words = 113,
        .row_count = 16,
    };
    const exact = memory.AddressBuffers{
        .address_ids = words(0x10_0000, 113),
        .multiplicities = words(0x20_0000, 256),
        .outputs = &outputs,
    };
    var session = TestSession{};
    try memory.OpsFor(TestApi).addressBase(&session, geometry, exact);

    var wrong = exact;
    wrong.multiplicities.len -= 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        memory.OpsFor(TestApi).addressBase(&session, geometry, wrong),
    );
    outputs[0].address = exact.address_ids.address;
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        memory.OpsFor(TestApi).addressBase(&session, geometry, exact),
    );
}

test "memory value base binds canonical 28-limb graph" {
    var sources: [memory.big_limb_count]Words = undefined;
    fillColumns(&sources, 0x10_0000, 16);
    var outputs: [memory.big_limb_count + 1]Words = undefined;
    fillColumns(&outputs, 0x40_0000, 16);
    var session = TestSession{};
    try memory.OpsFor(TestApi).valueBase(
        &session,
        .{
            .limb_count = memory.big_limb_count,
            .source_words = 16,
            .row_count = 16,
        },
        .{
            .sources = &sources,
            .multiplicities = words(0x30_0000, 16),
            .outputs = &outputs,
        },
    );
    try std.testing.expectEqual(
        @as(u32, memory.big_limb_count),
        TestApi.value_limb_count,
    );
}

test "memory range-check feed requires exact table and count extents" {
    var limbs: [memory.big_limb_count]Words = undefined;
    fillColumns(&limbs, 0x10_0000, 16);
    const geometry = memory.RangeCheckGeometry{
        .pair_count = memory.big_limb_count / 2,
        .row_count = 16,
    };
    const exact = memory.RangeCheckBuffers{
        .limbs = &limbs,
        .input_to_row = words(0x30_0000, memory.range_check_table_rows),
        .counts = words(
            0x50_0000,
            memory.range_check_pair_columns * memory.range_check_table_rows,
        ),
    };
    var session = TestSession{};
    try memory.OpsFor(TestApi).rangeCheck9_9(&session, geometry, exact);
    var wrong = exact;
    wrong.input_to_row.len -= 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        memory.OpsFor(TestApi).rangeCheck9_9(&session, geometry, wrong),
    );
}

const TestApi = struct {
    var big_value_count: u32 = 0;
    var small_value_count: u32 = 0;
    var value_limb_count: u32 = 0;

    pub fn stwo_cairo_memory_split_big_on(
        _: ?[*]const u32,
        value_count: u32,
        _: u32,
        _: [*]const [*]u32,
        _: *anyopaque,
    ) c_int {
        big_value_count = value_count;
        return 0;
    }

    pub fn stwo_cairo_memory_split_small_on(
        _: ?[*]const u32,
        value_count: u32,
        _: u32,
        _: [*]const [*]u32,
        _: *anyopaque,
    ) c_int {
        small_value_count = value_count;
        return 0;
    }

    pub fn stwo_cairo_memory_address_base_on(
        _: [*]const u32,
        _: u32,
        _: [*]const u32,
        _: u32,
        _: u32,
        _: [*]const [*]u32,
        _: *anyopaque,
    ) c_int {
        return 0;
    }

    pub fn stwo_cairo_memory_value_base_on(
        _: [*]const [*]const u32,
        limb_count: u32,
        _: u32,
        _: [*]const u32,
        _: u32,
        _: u32,
        _: [*]const [*]u32,
        _: *anyopaque,
    ) c_int {
        value_limb_count = limb_count;
        return 0;
    }

    pub fn stwo_cairo_memory_range_check_9_9_on(
        _: [*]const [*]const u32,
        _: u32,
        _: u32,
        _: [*]const u32,
        _: u32,
        _: [*]u32,
        _: u32,
        _: *anyopaque,
    ) c_int {
        return 0;
    }
};

const TestSession = struct {
    context: TestContext = .{},
    launches: u64 = 0,

    pub fn recordOrdinaryKernel(
        self: *TestSession,
        stage: telemetry.Stage,
        status: c_int,
    ) !void {
        if (stage != .trace_generation or status != 0)
            return error.InvalidState;
        self.launches += 1;
    }
};

const TestContext = struct {
    stream: *anyopaque = @ptrFromInt(1),

    pub fn requireStage(_: *TestContext, stage: telemetry.Stage) !void {
        if (stage != .trace_generation) return error.StageOrderViolation;
    }

    pub fn deviceSlicePointer(
        _: *TestContext,
        comptime T: type,
        slice: anytype,
        minimum: usize,
    ) ![*]T {
        if (slice.len < minimum or slice.address == 0 or
            slice.address % @alignOf(T) != 0)
        {
            return error.InvalidDeviceAddress;
        }
        return @ptrFromInt(slice.address);
    }
};

const Words = @import("../../column.zig").DeviceSlice(u32);

fn words(address: usize, len: usize) Words {
    return .{
        .address = address,
        .len = len,
        .owner = 7,
        .generation = 11,
    };
}

fn fillColumns(columns: []Words, base: usize, len: usize) void {
    for (columns, 0..) |*column, index| {
        column.* = words(base + index * 0x1000, len);
    }
}
