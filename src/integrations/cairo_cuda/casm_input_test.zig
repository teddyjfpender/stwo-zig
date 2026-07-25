const std = @import("std");
const runtime_error = @import("../../backends/cuda/runtime/error.zig");
const telemetry = @import("../../backends/cuda/runtime/telemetry.zig");
const casm = @import("casm_input.zig");

const owner: usize = 29;

const FakeApi = struct {
    var calls: usize = 0;
    var expected_stream: *anyopaque = undefined;

    pub fn stwo_witness_casm_input_scatter_on(
        rows: [*]const u32,
        real_rows: u32,
        consumer_rows: u32,
        pc: [*]u32,
        ap: [*]u32,
        fp: [*]u32,
        enabler: [*]u32,
        iota: ?[*]u32,
        stream: *anyopaque,
    ) c_int {
        std.debug.assert(stream == expected_stream);
        for (0..consumer_rows) |row| {
            const source_row: usize = if (row < real_rows) row else 0;
            pc[row] = rows[source_row * 3];
            ap[row] = rows[source_row * 3 + 1];
            fp[row] = rows[source_row * 3 + 2];
            enabler[row] = @intFromBool(row < real_rows);
            if (iota) |values| values[row] = @intCast(row);
        }
        calls += 1;
        return 0;
    }
};

const FakeContext = struct {
    stream_storage: u8 = 0,
    stream: *anyopaque = undefined,
    active_stage: telemetry.Stage = .trace_generation,

    fn init() FakeContext {
        var result = FakeContext{};
        result.stream = &result.stream_storage;
        return result;
    }

    pub fn requireStage(
        self: *FakeContext,
        expected: telemetry.Stage,
    ) runtime_error.Error!void {
        if (self.active_stage != expected) return error.StageOrderViolation;
    }

    pub fn deviceSlicePointer(
        _: *FakeContext,
        comptime F: type,
        slice: anytype,
        minimum: usize,
    ) runtime_error.Error![*]F {
        if (minimum == 0 or slice.len < minimum or slice.owner != owner or
            slice.address == 0 or slice.address % @alignOf(F) != 0)
        {
            return error.InvalidDeviceAddress;
        }
        return @ptrFromInt(slice.address);
    }
};

const FakeSession = struct {
    context: FakeContext = FakeContext.init(),
    launches: usize = 0,

    pub fn recordOrdinaryKernel(
        self: *FakeSession,
        stage: telemetry.Stage,
        status: c_int,
    ) runtime_error.Error!void {
        if (status != 0) return error.CudaFailure;
        try self.context.requireStage(stage);
        self.launches += 1;
    }
};

fn words(values: []u32) @import("../../backends/cuda/runtime/stages/common.zig").Words {
    return .{
        .address = @intFromPtr(values.ptr),
        .len = values.len,
        .owner = owner,
    };
}

fn none() @import("../../backends/cuda/runtime/stages/common.zig").Words {
    return .{ .address = 0, .len = 0, .owner = owner };
}

test "CASM scatter transposes canonical states and pads from row zero" {
    var rows = [_]u32{
        101, 102, 103,
        201, 202, 203,
        301, 302, 303,
    };
    var pc = [_]u32{999} ** 16;
    var ap = [_]u32{999} ** 16;
    var fp = [_]u32{999} ** 16;
    var enabler = [_]u32{999} ** 16;
    var iota = [_]u32{999} ** 16;
    var session = FakeSession{};
    FakeApi.calls = 0;
    FakeApi.expected_stream = session.context.stream;

    try casm.OpsFor(FakeApi).scatter(
        &session,
        .{ .real_rows = 3, .consumer_rows = 16, .include_iota = true },
        words(&rows),
        .{
            .pc = words(&pc),
            .ap = words(&ap),
            .fp = words(&fp),
            .enabler = words(&enabler),
            .iota = words(&iota),
        },
    );

    try std.testing.expectEqualSlices(u32, &.{ 101, 201, 301 }, pc[0..3]);
    try std.testing.expectEqualSlices(u32, &.{ 102, 202, 302 }, ap[0..3]);
    try std.testing.expectEqualSlices(u32, &.{ 103, 203, 303 }, fp[0..3]);
    try std.testing.expectEqualSlices(u32, &.{ 1, 1, 1 }, enabler[0..3]);
    for (3..16) |row| {
        try std.testing.expectEqual(@as(u32, 101), pc[row]);
        try std.testing.expectEqual(@as(u32, 102), ap[row]);
        try std.testing.expectEqual(@as(u32, 103), fp[row]);
        try std.testing.expectEqual(@as(u32, 0), enabler[row]);
        try std.testing.expectEqual(@as(u32, @intCast(row)), iota[row]);
    }
    try std.testing.expectEqual(@as(usize, 1), FakeApi.calls);
    try std.testing.expectEqual(@as(usize, 1), session.launches);
}

test "CASM scatter admits absent iota and rejects contract drift" {
    var rows = [_]u32{1} ** 9;
    var outputs = [_][16]u32{
        [_]u32{0} ** 16,
        [_]u32{0} ** 16,
        [_]u32{0} ** 16,
        [_]u32{0} ** 16,
    };
    var session = FakeSession{};
    FakeApi.expected_stream = session.context.stream;
    const columns = casm.Columns{
        .pc = words(&outputs[0]),
        .ap = words(&outputs[1]),
        .fp = words(&outputs[2]),
        .enabler = words(&outputs[3]),
        .iota = none(),
    };
    try casm.OpsFor(FakeApi).scatter(
        &session,
        .{ .real_rows = 3, .consumer_rows = 16, .include_iota = false },
        words(&rows),
        columns,
    );

    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        casm.OpsFor(FakeApi).scatter(
            &session,
            .{ .real_rows = 17, .consumer_rows = 64, .include_iota = false },
            words(&rows),
            columns,
        ),
    );
    var short_rows = words(&rows);
    short_rows.len -= 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        casm.OpsFor(FakeApi).scatter(
            &session,
            .{ .real_rows = 3, .consumer_rows = 16, .include_iota = false },
            short_rows,
            columns,
        ),
    );
    var overlapping = columns;
    overlapping.ap = overlapping.pc;
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        casm.OpsFor(FakeApi).scatter(
            &session,
            .{ .real_rows = 3, .consumer_rows = 16, .include_iota = false },
            words(&rows),
            overlapping,
        ),
    );
    session.context.active_stage = .trace_commit;
    try std.testing.expectError(
        error.StageOrderViolation,
        casm.OpsFor(FakeApi).scatter(
            &session,
            .{ .real_rows = 3, .consumer_rows = 16, .include_iota = false },
            words(&rows),
            columns,
        ),
    );
}

test "CASM geometry retains the pinned Rust extreme boundary" {
    try (casm.Geometry{
        .real_rows = @as(u32, 1) << 31,
        .consumer_rows = @as(u32, 1) << 31,
        .include_iota = false,
    }).validate();
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        (casm.Geometry{
            .real_rows = (@as(u32, 1) << 31) + 1,
            .consumer_rows = @as(u32, 1) << 31,
            .include_iota = false,
        }).validate(),
    );
}
