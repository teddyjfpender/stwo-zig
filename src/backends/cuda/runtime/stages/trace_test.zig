const std = @import("std");
const common = @import("common.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");
const trace = @import("trace.zig");

const TestApi = struct {
    var calls: usize = 0;
    var observed_offset: u64 = 0;

    pub fn stwo_native_xor_trace_on(
        _: [*]u32,
        preprocessed_stride_words: usize,
        preprocessed_capacity_words: usize,
        _: [*]u32,
        main_stride_words: usize,
        main_capacity_words: usize,
        row_count: u32,
        log_n_rows: u32,
        log_step: u32,
        offset: u64,
        stream: *anyopaque,
    ) c_int {
        std.debug.assert(preprocessed_stride_words == 16);
        std.debug.assert(preprocessed_capacity_words == 32);
        std.debug.assert(main_stride_words == 24);
        std.debug.assert(main_capacity_words == 24);
        std.debug.assert(row_count == 8);
        std.debug.assert(log_n_rows == 3);
        std.debug.assert(log_step == 2);
        std.debug.assert(stream == @as(*anyopaque, @ptrFromInt(0x80)));
        calls += 1;
        observed_offset = offset;
        return 0;
    }

    pub fn stwo_native_wide_fibonacci_trace_on(
        _: [*]u32,
        _: usize,
        _: usize,
        _: u32,
        _: u32,
        _: *anyopaque,
    ) c_int {
        return 0;
    }
};

const TestSession = struct {
    context: TestContext = .{},
    recorded: usize = 0,

    pub fn recordOrdinaryKernel(
        self: *TestSession,
        stage: telemetry.Stage,
        status: c_int,
    ) runtime_error.Error!void {
        if (stage != .trace_generation or status != 0)
            return error.CudaFailure;
        self.recorded += 1;
    }
};

const TestContext = struct {
    active_stage: telemetry.Stage = .trace_generation,
    stream: *anyopaque = @ptrFromInt(0x80),

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
        return @ptrFromInt(slice.address);
    }
};

fn matrix(address: usize, stride: usize, columns: usize) common.WordMatrix {
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

test "XOR trace binding admits independent padded trees" {
    TestApi.calls = 0;
    var session = TestSession{};
    try trace.OpsFor(TestApi).xor(
        &session,
        matrix(0x1000, 16, 2),
        matrix(0x2000, 24, 1),
        8,
        3,
        2,
        0x1_0000_0005,
    );
    try std.testing.expectEqual(@as(usize, 1), TestApi.calls);
    try std.testing.expectEqual(@as(u64, 0x1_0000_0005), TestApi.observed_offset);
    try std.testing.expectEqual(@as(usize, 1), session.recorded);
}

test "XOR trace binding rejects geometry and slab drift" {
    var session = TestSession{};
    const preprocessed = matrix(0x1000, 16, 2);
    const main_trace = matrix(0x2000, 24, 1);
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        trace.OpsFor(TestApi).xor(
            &session,
            preprocessed,
            main_trace,
            8,
            3,
            4,
            0,
        ),
    );
    var short = preprocessed;
    short.storage.len -= 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        trace.OpsFor(TestApi).xor(
            &session,
            short,
            main_trace,
            8,
            3,
            2,
            0,
        ),
    );
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        trace.OpsFor(TestApi).xor(
            &session,
            preprocessed,
            matrix(0x1010, 24, 1),
            8,
            3,
            2,
            0,
        ),
    );
}
