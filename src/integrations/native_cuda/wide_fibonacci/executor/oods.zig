//! Resident OODS evaluation and its exact Fiat-Shamir boundaries.
//!
//! Main coefficients retain a `2N` column stride while only their first `N`
//! coefficients are live. Composition coefficients are dense `N` columns.
//! Keeping these as two dispatch batches avoids both a repack and a host
//! pointer table.

const std = @import("std");
const field = @import("../../../../backends/cuda/abi/field.zig");
const column = @import("../../../../backends/cuda/runtime/column.zig");
const telemetry = @import("../../../../backends/cuda/runtime/telemetry.zig");
const common = @import("../../../../backends/cuda/runtime/stages/common.zig");
const oods_stage = @import("../../../../backends/cuda/runtime/stages/oods.zig");
const transcript_stage = @import("../../../../backends/cuda/runtime/stages/transcript.zig");
const canonical_ingress = @import("../canonical_ingress.zig");
const plan_mod = @import("../plan.zig");
const proof_assembly = @import("proof_assembly.zig");
const request = @import("../request.zig");
const types = @import("../resident_bindings/types.zig");
const transcript_schedule = @import("../transcript_schedule.zig");

const NativeTranscript = transcript_stage.Native;
const NativeOods = oods_stage.Native;

/// A rejection failure after 64 complete Blake2s draws has probability below
/// 2^-64. This bound matches the imported CUDA transcript authority while
/// retaining the core channel's rejection-sampling semantics.
pub const max_rejection_rounds: u32 = 64;

const draw_oods_step: u32 = 6;
const mix_samples_step: u32 = 7;
const draw_quotient_step: u32 = 8;

const Dispatch = struct {
    schedule: transcript_schedule.Schedule,
    log_n_rows: u32,
    trace_rows: u32,
    main_columns: usize,
    transcript: types.Transcript,
    oods: types.Oods,
    quotient_challenge: common.SecureFields,
    main_coefficients: common.WordMatrix,
    composition_coefficients: common.WordMatrix,
};

/// Enqueues the complete OODS stage on the proof transaction's stream.
///
/// This function allocates no memory, performs no host read, and does not
/// synchronize. CUDA launch/runtime failures remain attached to the resident
/// transaction and are surfaced by its normal fail-closed completion path.
pub fn execute(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    ingress: *const canonical_ingress.Pack,
    views: *const types.Views,
) !void {
    try validate(prepared, ingress, views);
    const geometry = prepared.logical.geometry;
    try executeWithOps(
        NativeTranscript,
        NativeOods,
        transaction.proofSession(),
        .{
            .schedule = prepared.transcript,
            .log_n_rows = geometry.statement.log_n_rows,
            .trace_rows = try u32Count(geometry.trace_rows),
            .main_columns = geometry.main_columns,
            .transcript = views.transcript,
            .oods = views.oods,
            .quotient_challenge = views.quotient.challenge,
            .main_coefficients = views.trace.main_coefficients,
            .composition_coefficients = views.trace.composition_coefficients,
        },
    );
    try proof_assembly.captureSampledValues(transaction.proofSession(), views);
}

/// Naming alias for stage executors that expose `run`.
pub const run = execute;

fn executeWithOps(
    comptime TranscriptOps: type,
    comptime OodsOps: type,
    session: anytype,
    dispatch: Dispatch,
) !void {
    const output_snapshot = try firstSecureSnapshot(
        dispatch.transcript.output_snapshot,
    );
    try TranscriptOps.drawSecure(
        session,
        .oods,
        dispatch.transcript.state,
        try boundary(
            dispatch.schedule,
            draw_oods_step,
            dispatch.transcript.boundary_snapshot,
        ),
        1,
        max_rejection_rounds,
        dispatch.oods.parameter,
        output_snapshot,
    );

    try OodsOps.derivePoints(
        session,
        dispatch.oods.parameter,
        dispatch.oods.offset_points,
        dispatch.oods.sampleMap(),
        dispatch.log_n_rows,
        dispatch.oods.sample_points,
        dispatch.oods.evaluation_points,
        dispatch.oods.folding_factors,
    );

    try evaluateBatch(
        OodsOps,
        session,
        dispatch.main_coefficients,
        dispatch.trace_rows,
        dispatch.log_n_rows,
        0,
        dispatch.main_columns,
        dispatch.oods,
    );
    try evaluateBatch(
        OodsOps,
        session,
        dispatch.composition_coefficients,
        dispatch.trace_rows,
        dispatch.log_n_rows,
        dispatch.main_columns,
        request.composition_column_count,
        dispatch.oods,
    );

    const sampled_words = try dispatch.oods.sampled_values.cast(u32);
    try TranscriptOps.mixWords(
        session,
        .oods,
        dispatch.transcript.state,
        try boundary(
            dispatch.schedule,
            mix_samples_step,
            dispatch.transcript.boundary_snapshot,
        ),
        sampled_words,
        true,
        try dispatch.transcript.input_snapshot.sub(0, sampled_words.len),
    );
    try TranscriptOps.drawSecure(
        session,
        .oods,
        dispatch.transcript.state,
        try boundary(
            dispatch.schedule,
            draw_quotient_step,
            dispatch.transcript.boundary_snapshot,
        ),
        1,
        max_rejection_rounds,
        dispatch.quotient_challenge,
        output_snapshot,
    );
}

fn evaluateBatch(
    comptime OodsOps: type,
    session: anytype,
    coefficients: common.WordMatrix,
    coefficient_rows: u32,
    coefficient_log_size: u32,
    first_sample: usize,
    sample_count: usize,
    oods: types.Oods,
) !void {
    const blocks_per_sample = try ceilDiv(
        @as(usize, coefficient_rows),
        512,
    );
    const factor_first = try mul(first_sample, coefficient_log_size);
    const factor_count = try mul(sample_count, coefficient_log_size);
    const factors = try oods.folding_factors.sub(factor_first, factor_count);
    const scratch_first = try mul(first_sample, blocks_per_sample);
    const scratch_count = try mul(sample_count, blocks_per_sample);
    const scratch_a = try oods.reduce_a.sub(scratch_first, scratch_count);
    const scratch_b = try oods.reduce_b.sub(scratch_first, scratch_count);

    try OodsOps.evaluateFirst(
        session,
        coefficients,
        coefficient_rows,
        factors,
        scratch_a,
    );

    var reduced = scratch_a;
    var alternate = scratch_b;
    var reduced_stride = try u32Count(blocks_per_sample);
    while (reduced_stride > 1) {
        const output_stride = try ceilDivU32(reduced_stride, 512);
        const output_count = try mul(sample_count, output_stride);
        const output = try alternate.sub(0, output_count);
        try OodsOps.reduce(
            session,
            reduced,
            reduced_stride,
            reduced_stride,
            std.math.log2_int(u32, reduced_stride) - 1,
            coefficient_log_size,
            factors,
            output,
        );
        alternate = reduced;
        reduced = output;
        reduced_stride = output_stride;
    }

    try OodsOps.storeResults(
        session,
        reduced,
        reduced_stride,
        .{
            .device = try oods.output_indices.sub(first_sample, sample_count),
            .output_capacity = oods.sampled_values.len,
        },
        oods.sampled_values,
    );
}

fn validate(
    prepared: *const plan_mod.PreparedPlan,
    ingress: *const canonical_ingress.Pack,
    views: *const types.Views,
) !void {
    const geometry = prepared.logical.geometry;
    const sample_count = try add(
        geometry.main_columns,
        request.composition_column_count,
    );
    if (sample_count != geometry.sampled_value_count or
        geometry.trace_rows == 0 or
        std.math.cast(u32, geometry.trace_rows) == null or
        ingress.circle.domain_log_size != geometry.queryLogSize() or
        ingress.coefficient_log_sizes.len != sample_count or
        ingress.oods_offset_points.len != sample_count or
        ingress.oods_fold_counts.len != sample_count or
        ingress.oods_output_indices.len != sample_count or
        views.oods.parameter.len != 1 or
        views.oods.offset_points.len != sample_count or
        views.oods.fold_counts.len != sample_count or
        views.oods.output_indices.len != sample_count or
        views.oods.sample_points.len != sample_count or
        views.oods.evaluation_points.len != sample_count or
        views.oods.sampled_values.len != sample_count or
        views.quotient.challenge.len != 1 or
        views.trace.coefficient_log_sizes.len != sample_count)
    {
        return error.InvalidKernelDescriptor;
    }

    const expected_factors = try mul(
        sample_count,
        geometry.statement.log_n_rows,
    );
    const blocks = try ceilDiv(geometry.trace_rows, 512);
    const expected_scratch = try mul(sample_count, blocks);
    if (views.oods.folding_factors.len != expected_factors or
        views.oods.reduce_a.len != expected_scratch or
        views.oods.reduce_b.len != expected_scratch)
    {
        return error.InvalidKernelDescriptor;
    }

    try validateMatrix(
        views.trace.main_coefficients,
        geometry.main_columns,
        geometry.commitment_rows,
    );
    try validateMatrix(
        views.trace.composition_coefficients,
        request.composition_column_count,
        geometry.trace_rows,
    );
    for (
        ingress.coefficient_log_sizes,
        ingress.oods_offset_points,
        ingress.oods_fold_counts,
        ingress.oods_output_indices,
        0..,
    ) |log_size, offset, fold_count, output_index, index| {
        if (log_size != geometry.statement.log_n_rows or
            offset.x != 1 or
            offset.y != 0 or
            fold_count > 31 or
            output_index != try u32Count(index))
        {
            return error.InvalidKernelDescriptor;
        }
    }

    if (!std.meta.eql(
        try prepared.transcript.operation(draw_oods_step),
        transcript_schedule.Operation.draw_oods_point,
    ) or !std.meta.eql(
        try prepared.transcript.operation(mix_samples_step),
        transcript_schedule.Operation.mix_sampled_values,
    ) or !std.meta.eql(
        try prepared.transcript.operation(draw_quotient_step),
        transcript_schedule.Operation.draw_quotient_alpha,
    )) {
        return error.InvalidKernelDescriptor;
    }
}

fn validateMatrix(
    matrix: common.WordMatrix,
    columns: usize,
    stride: usize,
) !void {
    if (matrix.column_stride_words != stride or
        matrix.storage.len != try mul(columns, stride))
    {
        return error.InvalidKernelDescriptor;
    }
}

fn boundary(
    schedule: transcript_schedule.Schedule,
    step: u32,
    snapshot: common.Words,
) !transcript_stage.Boundary {
    const sealed = try schedule.boundary(step);
    return .{
        .expected_step = sealed.expected_step,
        .expected_chain = sealed.expected_chain,
        .next_chain = sealed.next_chain,
        .snapshot = snapshot,
    };
}

fn firstSecureSnapshot(words: common.Words) !common.SecureFields {
    const secure = try words.cast(field.SecureField);
    return secure.sub(0, 1);
}

fn u32Count(value: usize) !u32 {
    return std.math.cast(u32, value) orelse error.SizeOverflow;
}

fn add(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch error.SizeOverflow;
}

fn mul(left: anytype, right: anytype) !usize {
    const left_usize = std.math.cast(usize, left) orelse
        return error.SizeOverflow;
    const right_usize = std.math.cast(usize, right) orelse
        return error.SizeOverflow;
    return std.math.mul(usize, left_usize, right_usize) catch
        error.SizeOverflow;
}

fn ceilDiv(value: usize, divisor: usize) !usize {
    return std.math.divCeil(usize, value, divisor) catch error.SizeOverflow;
}

fn ceilDivU32(value: u32, divisor: u32) !u32 {
    return std.math.divCeil(u32, value, divisor) catch error.SizeOverflow;
}

fn deviceSlice(
    comptime T: type,
    address: usize,
    len: usize,
) column.DeviceSlice(T) {
    return .{
        .address = address,
        .len = len,
        .owner = 7,
        .generation = 11,
    };
}

test "OODS contract launches heterogeneous batches in canonical transcript order" {
    const Call = enum {
        draw,
        derive,
        evaluate,
        reduce,
        store,
        mix,
    };
    const Recorder = struct {
        var calls: [10]Call = undefined;
        var count: usize = 0;

        fn record(call: Call) void {
            calls[count] = call;
            count += 1;
        }
    };
    const FakeTranscript = struct {
        pub fn drawSecure(
            _: anytype,
            stage: telemetry.Stage,
            _: common.Words,
            _: transcript_stage.Boundary,
            felt_count: u32,
            rejection_rounds: u32,
            _: common.SecureFields,
            _: common.SecureFields,
        ) !void {
            try std.testing.expectEqual(telemetry.Stage.oods, stage);
            try std.testing.expectEqual(@as(u32, 1), felt_count);
            try std.testing.expectEqual(max_rejection_rounds, rejection_rounds);
            Recorder.record(.draw);
        }

        pub fn mixWords(
            _: anytype,
            stage: telemetry.Stage,
            _: common.Words,
            _: transcript_stage.Boundary,
            source: common.Words,
            validate_m31: bool,
            snapshot: common.Words,
        ) !void {
            try std.testing.expectEqual(telemetry.Stage.oods, stage);
            try std.testing.expectEqual(@as(usize, 44), source.len);
            try std.testing.expectEqual(source.len, snapshot.len);
            try std.testing.expect(validate_m31);
            Recorder.record(.mix);
        }
    };
    const FakeOods = struct {
        var evaluations: usize = 0;

        pub fn derivePoints(
            _: anytype,
            _: common.SecureFields,
            _: common.CirclePoints,
            samples: oods_stage.SampleMap,
            coefficient_log_size: u32,
            _: common.SecureCirclePoints,
            _: common.SecureCirclePoints,
            factors: common.SecureFields,
        ) !void {
            try std.testing.expectEqual(@as(usize, 11), samples.indices.device.len);
            try std.testing.expectEqual(@as(u32, 10), coefficient_log_size);
            try std.testing.expectEqual(@as(usize, 110), factors.len);
            Recorder.record(.derive);
        }

        pub fn evaluateFirst(
            _: anytype,
            coefficients: common.WordMatrix,
            coefficient_size: u32,
            factors: common.SecureFields,
            scratch: common.SecureFields,
        ) !void {
            const expected_columns: usize = if (evaluations == 0) 3 else 8;
            const expected_stride: usize = if (evaluations == 0) 2048 else 1024;
            try std.testing.expectEqual(@as(u32, 1024), coefficient_size);
            try std.testing.expectEqual(expected_stride, coefficients.column_stride_words);
            try std.testing.expectEqual(
                expected_columns * expected_stride,
                coefficients.storage.len,
            );
            try std.testing.expectEqual(expected_columns * 10, factors.len);
            try std.testing.expectEqual(expected_columns * 2, scratch.len);
            evaluations += 1;
            Recorder.record(.evaluate);
        }

        pub fn reduce(
            _: anytype,
            _: common.SecureFields,
            input_size: u32,
            input_stride: u32,
            factor_index: u32,
            coefficient_log_size: u32,
            _: common.SecureFields,
            _: common.SecureFields,
        ) !void {
            try std.testing.expectEqual(@as(u32, 2), input_size);
            try std.testing.expectEqual(input_size, input_stride);
            try std.testing.expectEqual(@as(u32, 0), factor_index);
            try std.testing.expectEqual(@as(u32, 10), coefficient_log_size);
            Recorder.record(.reduce);
        }

        pub fn storeResults(
            _: anytype,
            _: common.SecureFields,
            reduced_stride: u32,
            indices: oods_stage.IndexMap,
            sampled_values: common.SecureFields,
        ) !void {
            try std.testing.expectEqual(@as(u32, 1), reduced_stride);
            try std.testing.expectEqual(@as(usize, 11), indices.output_capacity);
            try std.testing.expect(
                indices.device.len == 3 or indices.device.len == 8,
            );
            try std.testing.expectEqual(@as(usize, 11), sampled_values.len);
            Recorder.record(.store);
        }
    };
    const words = struct {
        fn at(address: usize, len: usize) common.Words {
            return deviceSlice(u32, address, len);
        }
        fn matrix(
            address: usize,
            columns: usize,
            stride: usize,
        ) common.WordMatrix {
            return .{
                .storage = at(address, columns * stride),
                .column_stride_words = stride,
            };
        }
    };

    const geometry = try request.admit(.{
        .statement = .{ .log_n_rows = 10, .sequence_len = 3 },
        .protocol = .{
            .pow_bits = 10,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
            .fold_step = 1,
            .lifting_log_size = null,
        },
    });
    Recorder.count = 0;
    FakeOods.evaluations = 0;
    var fake_session: u8 = 0;
    try executeWithOps(
        FakeTranscript,
        FakeOods,
        &fake_session,
        .{
            .schedule = try transcript_schedule.Schedule.init(geometry),
            .log_n_rows = 10,
            .trace_rows = 1024,
            .main_columns = 3,
            .transcript = .{
                .state = words.at(0x1000, 16),
                .input_snapshot = words.at(0x2000, 44),
                .output_snapshot = words.at(0x3000, 8),
                .boundary_snapshot = words.at(0x4000, 16),
                .static_inputs = words.at(0x4800, 1),
            },
            .oods = .{
                .parameter = deviceSlice(field.SecureField, 0x5000, 1),
                .offset_points = deviceSlice(
                    field.CirclePointBaseField,
                    0x6000,
                    11,
                ),
                .fold_counts = words.at(0x7000, 11),
                .output_indices = words.at(0x8000, 11),
                .sample_points = deviceSlice(
                    field.SecureCirclePoint,
                    0x9000,
                    11,
                ),
                .evaluation_points = deviceSlice(
                    field.SecureCirclePoint,
                    0xa000,
                    11,
                ),
                .folding_factors = deviceSlice(
                    field.SecureField,
                    0xb000,
                    110,
                ),
                .reduce_a = deviceSlice(field.SecureField, 0xc000, 22),
                .reduce_b = deviceSlice(field.SecureField, 0xd000, 22),
                .sampled_values = deviceSlice(
                    field.SecureField,
                    0xe000,
                    11,
                ),
            },
            .quotient_challenge = deviceSlice(
                field.SecureField,
                0xf000,
                1,
            ),
            .main_coefficients = words.matrix(0x10000, 3, 2048),
            .composition_coefficients = words.matrix(0x20000, 8, 1024),
        },
    );
    try std.testing.expectEqualSlices(
        Call,
        &.{
            .draw,
            .derive,
            .evaluate,
            .reduce,
            .store,
            .evaluate,
            .reduce,
            .store,
            .mix,
            .draw,
        },
        Recorder.calls[0..Recorder.count],
    );
}

test "coefficient batches preserve the exact factor reduction schedule" {
    const Case = struct {
        log_size: u32,
        first_blocks: u32,
        first_factor: ?u32,
        second_blocks: ?u32,
        second_factor: ?u32,
    };
    const cases = [_]Case{
        .{ .log_size = 3, .first_blocks = 1, .first_factor = null, .second_blocks = null, .second_factor = null },
        .{ .log_size = 9, .first_blocks = 1, .first_factor = null, .second_blocks = null, .second_factor = null },
        .{ .log_size = 10, .first_blocks = 2, .first_factor = 0, .second_blocks = null, .second_factor = null },
        .{ .log_size = 18, .first_blocks = 512, .first_factor = 8, .second_blocks = null, .second_factor = null },
        .{ .log_size = 22, .first_blocks = 8192, .first_factor = 12, .second_blocks = 16, .second_factor = 3 },
    };
    for (cases) |case| {
        const rows = @as(usize, 1) << @intCast(case.log_size);
        var size = try u32Count(try ceilDiv(rows, 512));
        try std.testing.expectEqual(case.first_blocks, size);
        if (case.first_factor) |factor| {
            try std.testing.expectEqual(
                factor,
                std.math.log2_int(u32, size) - 1,
            );
            size = try ceilDivU32(size, 512);
        }
        if (case.second_blocks) |second| {
            try std.testing.expectEqual(second, size);
            try std.testing.expectEqual(
                case.second_factor.?,
                std.math.log2_int(u32, size) - 1,
            );
            size = try ceilDivU32(size, 512);
        }
        try std.testing.expectEqual(@as(u32, 1), size);
    }
}
