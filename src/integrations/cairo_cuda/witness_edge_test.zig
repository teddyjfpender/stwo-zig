const std = @import("std");
const common = @import("../../backends/cuda/runtime/stages/common.zig");
const runtime_error = @import("../../backends/cuda/runtime/error.zig");
const telemetry = @import("../../backends/cuda/runtime/telemetry.zig");
const witness = @import("casm_input.zig");

const owner: usize = 31;

const FakeApi = struct {
    var calls: usize = 0;
    var expected_stream: *anyopaque = undefined;

    pub fn stwo_witness_edge_gather_contiguous_on(
        producer: [*]const u32,
        producer_capacity_words: usize,
        producer_rows: u32,
        word_base: u32,
        words_per_instance: u32,
        instance_count: u32,
        consumer_rows: u32,
        outputs: [*]u32,
        output_stride_words: usize,
        output_capacity_words: usize,
        include_enabler: u32,
        include_iota: u32,
        stream: *anyopaque,
    ) c_int {
        std.debug.assert(stream == expected_stream);
        const real_rows: usize =
            @as(usize, producer_rows) * @as(usize, instance_count);
        const source_words =
            (@as(usize, word_base) +
                @as(usize, words_per_instance) *
                    @as(usize, instance_count)) *
            @as(usize, producer_rows);
        std.debug.assert(producer_capacity_words >= source_words);
        const output_columns: usize = @as(usize, words_per_instance) +
            @as(usize, include_enabler) + @as(usize, include_iota);
        std.debug.assert(
            output_capacity_words == output_stride_words * output_columns,
        );
        for (0..output_columns) |column| {
            for (0..consumer_rows) |row| {
                const source_row = if (row < real_rows) row else row & 15;
                outputs[column * output_stride_words + row] =
                    if (column < @as(usize, words_per_instance)) value: {
                        const instance =
                            source_row / @as(usize, producer_rows);
                        const producer_row =
                            source_row % @as(usize, producer_rows);
                        const source_word = @as(usize, word_base) +
                            instance * @as(usize, words_per_instance) + column;
                        break :value producer[
                            source_word * @as(usize, producer_rows) +
                                producer_row
                        ];
                    } else if (include_enabler != 0 and
                    column == @as(usize, words_per_instance))
                        @intFromBool(row < real_rows)
                    else
                        @intCast(row);
            }
        }
        calls += 1;
        return 0;
    }
};

const FakeContext = struct {
    stream: *anyopaque = &fake_stream_storage,
    active_stage: telemetry.Stage = .trace_generation,

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
    context: FakeContext = .{},
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

var fake_stream_storage: u8 = 0;

fn words(values: []u32) common.Words {
    return .{
        .address = @intFromPtr(values.ptr),
        .len = values.len,
        .owner = owner,
    };
}

fn matrix(values: []u32, stride_words: usize) common.WordMatrix {
    return .{
        .storage = words(values),
        .column_stride_words = stride_words,
    };
}

test "single-edge gather preserves packed order and first-pack padding" {
    var producer: [112]u32 = undefined;
    for (&producer, 0..) |*value, index| {
        const word = index / 16;
        const row = index % 16;
        value.* = @intCast(word * 100 + row);
    }
    var outputs = [_]u32{999} ** 280;
    var session = FakeSession{};
    FakeApi.calls = 0;
    FakeApi.expected_stream = session.context.stream;
    try witness.OpsFor(FakeApi).gatherEdge(
        &session,
        .{
            .producer_rows = 16,
            .word_base = 1,
            .words_per_instance = 2,
            .instance_count = 3,
            .consumer_rows = 64,
            .include_enabler = true,
            .include_iota = true,
        },
        words(&producer),
        matrix(&outputs, 70),
    );

    for (0..64) |row| {
        const source_row = if (row < 48) row else row & 15;
        const instance = source_row / 16;
        const lane = source_row % 16;
        try std.testing.expectEqual(
            @as(u32, @intCast((1 + instance * 2) * 100 + lane)),
            outputs[row],
        );
        try std.testing.expectEqual(
            @as(u32, @intCast((2 + instance * 2) * 100 + lane)),
            outputs[70 + row],
        );
        try std.testing.expectEqual(
            @as(u32, @intFromBool(row < 48)),
            outputs[140 + row],
        );
        try std.testing.expectEqual(
            @as(u32, @intCast(row)),
            outputs[210 + row],
        );
    }
    for (64..70) |padding| {
        inline for (0..4) |column| {
            try std.testing.expectEqual(
                @as(u32, 999),
                outputs[column * 70 + padding],
            );
        }
    }
    try std.testing.expectEqual(@as(usize, 1), FakeApi.calls);
    try std.testing.expectEqual(@as(usize, 1), session.launches);
}

test "single-edge gather rejects geometry, extent, and alias drift" {
    var producer = [_]u32{1} ** 112;
    var outputs = [_]u32{0} ** 256;
    var session = FakeSession{};
    FakeApi.expected_stream = session.context.stream;
    const valid = witness.EdgeGeometry{
        .producer_rows = 16,
        .word_base = 1,
        .words_per_instance = 2,
        .instance_count = 3,
        .consumer_rows = 64,
        .include_enabler = true,
        .include_iota = true,
    };
    var invalid = valid;
    invalid.consumer_rows = 128;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        witness.OpsFor(FakeApi).gatherEdge(
            &session,
            invalid,
            words(&producer),
            matrix(&outputs, 64),
        ),
    );
    var short = words(&producer);
    short.len -= 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        witness.OpsFor(FakeApi).gatherEdge(
            &session,
            valid,
            short,
            matrix(&outputs, 64),
        ),
    );
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        witness.OpsFor(FakeApi).gatherEdge(
            &session,
            .{
                .producer_rows = 16,
                .word_base = 0,
                .words_per_instance = 1,
                .instance_count = 1,
                .consumer_rows = 16,
                .include_enabler = false,
                .include_iota = false,
            },
            words(outputs[0..16]),
            matrix(outputs[0..16], 16),
        ),
    );
}
