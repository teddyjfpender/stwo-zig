//! Checked resident interpolation and split for a secure composition column.

const std = @import("std");
const abi = @import("../../abi/stages/composition_split.zig");
const common = @import("common.zig");
const layout = @import("resident_layout.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);
pub const coordinate_count: usize = 4;
pub const coefficient_column_count: usize = 8;
pub const depth_two_coefficient_column_count: usize = 16;

const stage = telemetry.Stage.constraint_evaluation;

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn interpolateAndSplit(
            session: anytype,
            coordinates: common.WordMatrix,
            coefficients: common.WordMatrix,
            log_n: u32,
            inverse_twiddles: common.Words,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const shape = try compositionShape(log_n);
            const inputs = try exactMatrix(
                session,
                coordinates,
                coordinate_count,
                shape.values,
            );
            const outputs = try exactMatrix(
                session,
                coefficients,
                coefficient_column_count,
                shape.domain,
            );
            if (inverse_twiddles.len < shape.domain)
                return error.InvalidKernelDescriptor;
            const twiddles = try layout.resident(
                session,
                u32,
                inverse_twiddles,
                inverse_twiddles.len,
            );
            try layout.requireDisjoint(
                &.{outputs.range},
                &.{ inputs.range, twiddles.range },
            );
            if (layout.overlap(inputs.range, twiddles.range))
                return error.OverlappingDeviceRange;

            var launches: u32 = 0;
            const status =
                Api.stwo_ntt_b2n_composition_split_compact_on(
                    inputs.pointer,
                    coordinates.storage.len,
                    inputs.stride_words,
                    outputs.pointer,
                    coefficients.storage.len,
                    outputs.stride_words,
                    log_n,
                    twiddles.pointer,
                    try common.count(inverse_twiddles.len),
                    try common.count(shape.domain),
                    session.context.stream,
                    &launches,
                );
            try common.recordMany(session, stage, status, launches);
        }

        /// Interpolates four secure coordinates and emits the canonical
        /// depth-two coefficient partition directly as 16 degree-<N columns.
        pub fn interpolateAndSplitDepthTwo(
            session: anytype,
            coordinates: common.WordMatrix,
            coefficients: common.WordMatrix,
            log_n: u32,
            inverse_twiddles: common.Words,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            if (log_n < 4)
                return error.InvalidKernelDescriptor;
            const shape = try compositionShape(log_n);
            const inputs = try exactMatrix(
                session,
                coordinates,
                coordinate_count,
                shape.values,
            );
            const outputs = try exactMatrix(
                session,
                coefficients,
                depth_two_coefficient_column_count,
                shape.domain / 2,
            );
            if (inverse_twiddles.len < shape.domain)
                return error.InvalidKernelDescriptor;
            const twiddles = try layout.resident(
                session,
                u32,
                inverse_twiddles,
                inverse_twiddles.len,
            );
            try layout.requireDisjoint(
                &.{outputs.range},
                &.{ inputs.range, twiddles.range },
            );
            if (layout.overlap(inputs.range, twiddles.range))
                return error.OverlappingDeviceRange;

            var launches: u32 = 0;
            const status =
                Api.stwo_ntt_b2n_composition_split_depth_two_on(
                    inputs.pointer,
                    coordinates.storage.len,
                    inputs.stride_words,
                    outputs.pointer,
                    coefficients.storage.len,
                    outputs.stride_words,
                    log_n,
                    twiddles.pointer,
                    try common.count(inverse_twiddles.len),
                    try common.count(shape.domain),
                    session.context.stream,
                    &launches,
                );
            try common.recordMany(session, stage, status, launches);
        }
    };
}

const CompositionShape = struct {
    domain: usize,
    values: usize,
};

fn compositionShape(log_n: u32) runtime_error.Error!CompositionShape {
    if (log_n < 3 or log_n > 30)
        return error.InvalidKernelDescriptor;
    const values = @as(usize, 1) << @intCast(log_n);
    return .{ .domain = values / 2, .values = values };
}

fn exactMatrix(
    session: anytype,
    descriptor: common.WordMatrix,
    expected_columns: usize,
    expected_stride: usize,
) runtime_error.Error!layout.WordMatrix {
    const expected_words = std.math.mul(
        usize,
        expected_columns,
        expected_stride,
    ) catch return error.SizeOverflow;
    if (descriptor.column_stride_words != expected_stride or
        descriptor.storage.len != expected_words)
    {
        return error.InvalidKernelDescriptor;
    }
    const matrix = try layout.wordMatrix(
        session,
        descriptor,
        expected_stride,
    );
    if (matrix.column_count != expected_columns)
        return error.InvalidKernelDescriptor;
    return matrix;
}

test "composition split maps four log4 evaluations to eight log3 coefficients" {
    const TestApi = struct {
        var launches: u32 = 0;
        var stream: usize = 0;

        fn stwo_ntt_b2n_composition_split_compact_on(
            _: [*]u32,
            input_capacity: usize,
            input_stride: usize,
            _: [*]u32,
            output_capacity: usize,
            output_stride: usize,
            log_n: u32,
            _: [*]const u32,
            twiddle_words: u32,
            domain: u32,
            proof_stream: *anyopaque,
            launches_out: *u32,
        ) c_int {
            const values = @as(usize, 1) << @intCast(log_n);
            if (input_capacity != coordinate_count * values or
                input_stride != values or
                output_capacity != coefficient_column_count * (values / 2) or
                output_stride != values / 2 or
                twiddle_words < domain)
            {
                return 1;
            }
            launches += 1;
            stream = @intFromPtr(proof_stream);
            launches_out.* = 2;
            return 0;
        }
    };
    const Ops = OpsFor(TestApi);
    var session = TestSession{};
    const inputs = testMatrix(0x1000, coordinate_count, 16);
    const outputs = testMatrix(0x1200, coefficient_column_count, 8);
    const twiddles = testWords(0x1500, 8);

    try Ops.interpolateAndSplit(
        &session,
        inputs,
        outputs,
        4,
        twiddles,
    );
    try std.testing.expectEqual(@as(u32, 1), TestApi.launches);
    try std.testing.expectEqual(
        @intFromPtr(session.context.stream),
        TestApi.stream,
    );
    try std.testing.expectEqual(@as(u64, 2), session.launches);

    var short_input = inputs;
    short_input.storage.len -= 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        Ops.interpolateAndSplit(
            &session,
            short_input,
            outputs,
            4,
            twiddles,
        ),
    );
    var padded_output = outputs;
    padded_output.column_stride_words += 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        Ops.interpolateAndSplit(
            &session,
            inputs,
            padded_output,
            4,
            twiddles,
        ),
    );
    var aliased_output = outputs;
    aliased_output.storage.address = inputs.storage.address;
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        Ops.interpolateAndSplit(
            &session,
            inputs,
            aliased_output,
            4,
            twiddles,
        ),
    );
    const aliased_twiddles = testWords(inputs.storage.address, 8);
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        Ops.interpolateAndSplit(
            &session,
            inputs,
            outputs,
            4,
            aliased_twiddles,
        ),
    );
    session.context.active_stage = .oods;
    try std.testing.expectError(
        error.StageOrderViolation,
        Ops.interpolateAndSplit(
            &session,
            inputs,
            outputs,
            4,
            twiddles,
        ),
    );
}

test "depth-two composition split emits sixteen canonical columns directly" {
    const TestApi = struct {
        var calls: u32 = 0;

        fn stwo_ntt_b2n_composition_split_depth_two_on(
            _: [*]u32,
            input_capacity: usize,
            input_stride: usize,
            _: [*]u32,
            output_capacity: usize,
            output_stride: usize,
            log_n: u32,
            _: [*]const u32,
            twiddle_words: u32,
            domain: u32,
            _: *anyopaque,
            launches_out: *u32,
        ) c_int {
            const values = @as(usize, 1) << @intCast(log_n);
            if (input_capacity != coordinate_count * values or
                input_stride != values or
                output_capacity !=
                    depth_two_coefficient_column_count * (values / 4) or
                output_stride != values / 4 or
                twiddle_words < domain)
            {
                return 1;
            }
            calls += 1;
            launches_out.* = 3;
            return 0;
        }
    };
    const Ops = OpsFor(TestApi);
    var session = TestSession{};
    const inputs = testMatrix(0x1000, coordinate_count, 16);
    const outputs = testMatrix(
        0x1200,
        depth_two_coefficient_column_count,
        4,
    );
    const twiddles = testWords(0x1500, 8);

    try Ops.interpolateAndSplitDepthTwo(
        &session,
        inputs,
        outputs,
        4,
        twiddles,
    );
    try std.testing.expectEqual(@as(u32, 1), TestApi.calls);
    try std.testing.expectEqual(@as(u64, 3), session.launches);

    var wrong_stride = outputs;
    wrong_stride.column_stride_words = 8;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        Ops.interpolateAndSplitDepthTwo(
            &session,
            inputs,
            wrong_stride,
            4,
            twiddles,
        ),
    );
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        Ops.interpolateAndSplitDepthTwo(
            &session,
            testMatrix(0x1000, coordinate_count, 8),
            testMatrix(
                0x1200,
                depth_two_coefficient_column_count,
                2,
            ),
            3,
            testWords(0x1500, 4),
        ),
    );
}

const TestSession = struct {
    context: TestContext = .{},
    launches: u64 = 0,

    pub fn recordOrdinaryKernels(
        self: *TestSession,
        expected: telemetry.Stage,
        status: c_int,
        count: u64,
    ) runtime_error.Error!void {
        if (expected != self.context.active_stage)
            return error.StageOrderViolation;
        try runtime_error.check(status);
        self.launches += count;
    }
};

const TestContext = struct {
    active_stage: telemetry.Stage = stage,
    stream: *anyopaque = @ptrFromInt(0x3000),

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
        const bytes = std.math.mul(
            usize,
            minimum,
            @sizeOf(F),
        ) catch return error.SizeOverflow;
        const end = std.math.add(
            usize,
            slice.address,
            bytes,
        ) catch return error.SizeOverflow;
        if (slice.address < 0x1000 or end > 0x2000)
            return error.InvalidDeviceAddress;
        return @ptrFromInt(slice.address);
    }
};

fn testWords(address: usize, len: usize) common.Words {
    return .{
        .address = address,
        .len = len,
        .owner = 7,
        .generation = 11,
    };
}

fn testMatrix(
    address: usize,
    columns: usize,
    stride: usize,
) common.WordMatrix {
    return .{
        .storage = testWords(address, columns * stride),
        .column_stride_words = stride,
    };
}
