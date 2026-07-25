const std = @import("std");
const column = @import("../../backends/cuda/runtime/column.zig");
const common = @import("../../backends/cuda/runtime/stages/common.zig");
const runtime_error = @import("../../backends/cuda/runtime/error.zig");
const telemetry = @import("../../backends/cuda/runtime/telemetry.zig");
const witness = @import("casm_input.zig");

const owner: usize = 37;

const FakeApi = struct {
    var calls: usize = 0;
    var expected_stream: *anyopaque = undefined;

    pub fn stwo_witness_multi_edge_gather_contiguous_on(
        producer: [*]const u32,
        producer_word_count: usize,
        descriptors: [*]const witness.MultiEdgeDescriptor,
        edge_count: u32,
        input_width: u32,
        total_real_rows: u32,
        consumer_rows: u32,
        outputs: [*]u32,
        output_stride_words: usize,
        output_capacity_words: usize,
        include_enabler: u32,
        include_iota: u32,
        stream: *anyopaque,
    ) c_int {
        std.debug.assert(stream == expected_stream);
        const output_columns: usize = @as(usize, input_width) +
            @as(usize, include_enabler) + @as(usize, include_iota);
        std.debug.assert(
            output_capacity_words == output_stride_words * output_columns,
        );
        for (0..consumer_rows) |row| {
            const source_global_row: u32 =
                if (row < total_real_rows) @intCast(row) else @intCast(row & 15);
            var edge_index: usize = 0;
            for (descriptors[0..edge_count], 0..) |edge, index| {
                if (edge.destination_row_offset <= source_global_row)
                    edge_index = index;
            }
            const edge = descriptors[edge_index];
            const local_row = source_global_row -
                edge.destination_row_offset;
            const instance = local_row / edge.producer_rows;
            const producer_row = local_row % edge.producer_rows;
            for (0..input_width) |word| {
                const source_word = @as(u64, edge.word_base) +
                    @as(u64, instance) * input_width + word;
                const source_index = edge.source_offset_words +
                    source_word * edge.producer_rows + producer_row;
                std.debug.assert(source_index < producer_word_count);
                outputs[word * output_stride_words + row] =
                    producer[source_index];
            }
            var tail: usize = input_width;
            if (include_enabler != 0) {
                outputs[tail * output_stride_words + row] =
                    @intFromBool(row < total_real_rows);
                tail += 1;
            }
            if (include_iota != 0)
                outputs[tail * output_stride_words + row] = @intCast(row);
        }
        calls += 1;
        return 0;
    }
};

const FakeContext = struct {
    stream: *anyopaque = &fake_stream_storage,
    active_stage: telemetry.Stage = .ingress,

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

    pub fn uploadSlice(
        self: *FakeContext,
        comptime F: type,
        destination: anytype,
        source: []const F,
    ) runtime_error.Error!void {
        try self.requireStage(.ingress);
        const target = try self.deviceSlicePointer(
            F,
            destination,
            source.len,
        );
        @memcpy(target[0..source.len], source);
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

fn view(
    comptime F: type,
    values: []F,
) column.DeviceSlice(F) {
    return .{
        .address = @intFromPtr(values.ptr),
        .len = values.len,
        .owner = owner,
    };
}

fn words(values: []u32) common.Words {
    return view(u32, values);
}

fn matrix(values: []u32, stride_words: usize) common.WordMatrix {
    return .{
        .storage = words(values),
        .column_stride_words = stride_words,
    };
}

test "multi-edge gather preserves canonical edge order and packed padding" {
    var producer: [160]u32 = undefined;
    for (&producer, 0..) |*value, index| value.* = @intCast(10_000 + index);
    const host_edges = [_]witness.MultiEdgeDescriptor{
        .{
            .source_offset_words = 0,
            .producer_rows = 16,
            .word_base = 1,
            .words_per_instance = 2,
            .instance_count = 1,
            .destination_row_offset = 0,
        },
        .{
            .source_offset_words = 64,
            .producer_rows = 32,
            .word_base = 0,
            .words_per_instance = 2,
            .instance_count = 1,
            .destination_row_offset = 16,
        },
    };
    var device_edges: [2]witness.MultiEdgeDescriptor = undefined;
    var outputs = [_]u32{999} ** 280;
    var session = FakeSession{};
    const topology = try witness.prepareMultiEdgeTopology(
        &session,
        &host_edges,
        view(witness.MultiEdgeDescriptor, &device_edges),
        producer.len,
        true,
        true,
    );
    try std.testing.expectEqual(@as(u32, 48), topology.total_real_rows);
    try std.testing.expectEqual(@as(u32, 64), topology.consumer_rows);
    try std.testing.expectEqualSlices(
        witness.MultiEdgeDescriptor,
        &host_edges,
        &device_edges,
    );

    session.context.active_stage = .trace_generation;
    FakeApi.calls = 0;
    FakeApi.expected_stream = session.context.stream;
    try witness.OpsFor(FakeApi).gatherEdges(
        &session,
        topology,
        words(&producer),
        matrix(&outputs, 70),
    );
    for (0..64) |row| {
        const source_global = if (row < 48) row else row & 15;
        const expected_first = if (source_global < 16)
            10_000 + 16 + source_global
        else
            10_000 + 64 + source_global - 16;
        const expected_second = if (source_global < 16)
            10_000 + 32 + source_global
        else
            10_000 + 96 + source_global - 16;
        try std.testing.expectEqual(
            @as(u32, @intCast(expected_first)),
            outputs[row],
        );
        try std.testing.expectEqual(
            @as(u32, @intCast(expected_second)),
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
    try std.testing.expectEqual(@as(usize, 1), FakeApi.calls);
    try std.testing.expectEqual(@as(usize, 1), session.launches);
}

test "multi-edge topology rejects order, width, source, and reserved drift" {
    const valid = [_]witness.MultiEdgeDescriptor{
        .{
            .source_offset_words = 0,
            .producer_rows = 16,
            .word_base = 0,
            .words_per_instance = 2,
            .instance_count = 1,
            .destination_row_offset = 0,
        },
        .{
            .source_offset_words = 32,
            .producer_rows = 16,
            .word_base = 0,
            .words_per_instance = 2,
            .instance_count = 1,
            .destination_row_offset = 16,
        },
    };
    var device_edges: [2]witness.MultiEdgeDescriptor = undefined;
    var session = FakeSession{};
    var changed = valid;
    changed[1].destination_row_offset = 17;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        witness.prepareMultiEdgeTopology(
            &session,
            &changed,
            view(witness.MultiEdgeDescriptor, &device_edges),
            64,
            false,
            false,
        ),
    );
    changed = valid;
    changed[1].words_per_instance = 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        witness.prepareMultiEdgeTopology(
            &session,
            &changed,
            view(witness.MultiEdgeDescriptor, &device_edges),
            64,
            false,
            false,
        ),
    );
    changed = valid;
    changed[1].source_offset_words = 33;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        witness.prepareMultiEdgeTopology(
            &session,
            &changed,
            view(witness.MultiEdgeDescriptor, &device_edges),
            64,
            false,
            false,
        ),
    );
    changed = valid;
    changed[0].reserved = 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        witness.prepareMultiEdgeTopology(
            &session,
            &changed,
            view(witness.MultiEdgeDescriptor, &device_edges),
            64,
            false,
            false,
        ),
    );
}

test "multi-edge executor rejects output alias and stage drift" {
    const edges = [_]witness.MultiEdgeDescriptor{
        .{
            .source_offset_words = 0,
            .producer_rows = 16,
            .word_base = 0,
            .words_per_instance = 2,
            .instance_count = 2,
            .destination_row_offset = 0,
        },
    };
    var device_edges: [1]witness.MultiEdgeDescriptor = undefined;
    var producer = [_]u32{0} ** 64;
    var session = FakeSession{};
    const topology = try witness.prepareMultiEdgeTopology(
        &session,
        &edges,
        view(witness.MultiEdgeDescriptor, &device_edges),
        producer.len,
        false,
        false,
    );
    session.context.active_stage = .trace_generation;
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        witness.OpsFor(FakeApi).gatherEdges(
            &session,
            topology,
            words(&producer),
            matrix(&producer, 32),
        ),
    );
    session.context.active_stage = .trace_commit;
    try std.testing.expectError(
        error.StageOrderViolation,
        witness.OpsFor(FakeApi).gatherEdges(
            &session,
            topology,
            words(&producer),
            matrix(&producer, 32),
        ),
    );
}
