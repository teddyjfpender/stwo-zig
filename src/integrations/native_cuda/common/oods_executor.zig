//! AIR-neutral resident OODS evaluation and transcript boundaries.

const std = @import("std");
const field = @import("../../../backends/cuda/abi/field.zig");
const column = @import("../../../backends/cuda/runtime/column.zig");
const telemetry = @import("../../../backends/cuda/runtime/telemetry.zig");
const common = @import("../../../backends/cuda/runtime/stages/common.zig");
const oods_stage = @import(
    "../../../backends/cuda/runtime/stages/oods.zig",
);
const transcript_stage = @import(
    "../../../backends/cuda/runtime/stages/transcript.zig",
);
const proof_assembly = @import("proof_assembly.zig");
const resident_views = @import("resident_views.zig");
const transcript_schedule = @import("transcript_schedule.zig");

const NativeTranscript = transcript_stage.Native;
const NativeOods = oods_stage.Native;

pub const max_rejection_rounds: u32 = 64;
const draw_oods_step: u32 = 6;
const mix_samples_step: u32 = 7;
const draw_quotient_step: u32 = 8;

pub const Batch = struct {
    coefficients: common.WordMatrix,
    coefficient_rows: u32,
    coefficient_log_size: u32,
    first_sample: usize,
    sample_count: usize,
};

pub fn run(
    transaction: anytype,
    prepared: anytype,
    ingress: anytype,
    views: anytype,
) !void {
    var storage: [resident_views.max_trace_trees]Batch = undefined;
    const batches = try buildBatches(prepared, ingress, views, &storage);
    try executeWithOps(
        NativeTranscript,
        NativeOods,
        transaction.proofSession(),
        prepared.transcript,
        views.transcript,
        views.oods,
        views.quotient.challenge,
        batches,
    );
    try proof_assembly.captureSampledValues(
        transaction.proofSession(),
        views,
    );
}

pub fn executeWithOps(
    comptime TranscriptOps: type,
    comptime OodsOps: type,
    session: anytype,
    schedule: anytype,
    transcript: resident_views.Transcript,
    oods: resident_views.Oods,
    quotient_challenge: common.SecureFields,
    batches: []const Batch,
) !void {
    if (batches.len == 0) return error.InvalidKernelDescriptor;
    const log_size = batches[0].coefficient_log_size;
    const output_snapshot = try firstSecureSnapshot(
        transcript.output_snapshot,
    );
    try requireOperation(
        schedule,
        draw_oods_step,
        .draw_oods_point,
    );
    try TranscriptOps.drawSecure(
        session,
        .oods,
        transcript.state,
        try boundary(
            schedule,
            draw_oods_step,
            transcript.boundary_snapshot,
        ),
        1,
        max_rejection_rounds,
        oods.parameter,
        output_snapshot,
    );

    try OodsOps.derivePoints(
        session,
        oods.parameter,
        oods.offset_points,
        oods.sampleMap(),
        log_size,
        oods.sample_points,
        oods.evaluation_points,
        oods.folding_factors,
    );
    for (batches) |batch| {
        try evaluateBatch(OodsOps, session, batch, oods);
    }

    const sampled_words = try oods.sampled_values.cast(u32);
    try requireOperation(
        schedule,
        mix_samples_step,
        .mix_sampled_values,
    );
    try TranscriptOps.mixWords(
        session,
        .oods,
        transcript.state,
        try boundary(
            schedule,
            mix_samples_step,
            transcript.boundary_snapshot,
        ),
        sampled_words,
        true,
        try transcript.input_snapshot.sub(0, sampled_words.len),
    );
    try requireOperation(
        schedule,
        draw_quotient_step,
        .draw_quotient_alpha,
    );
    try TranscriptOps.drawSecure(
        session,
        .oods,
        transcript.state,
        try boundary(
            schedule,
            draw_quotient_step,
            transcript.boundary_snapshot,
        ),
        1,
        max_rejection_rounds,
        quotient_challenge,
        output_snapshot,
    );
}

fn buildBatches(
    prepared: anytype,
    ingress: anytype,
    views: anytype,
    storage: *[resident_views.max_trace_trees]Batch,
) ![]const Batch {
    const logical = prepared.logical;
    const sample_count = logical.quotient.sample_count;
    if (sample_count != logical.quotient.source_column_count or
        ingress.circle.domain_log_size !=
            logical.geometry.queryLogSize() or
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
        views.quotient.challenge.len != 1)
    {
        return error.InvalidKernelDescriptor;
    }

    var batch_count: usize = 0;
    var first_sample: usize = 0;
    var common_log_size: ?u32 = null;
    var common_rows: ?usize = null;
    for (logical.trace_trees) |tree| {
        if (!tree.sampled) continue;
        if (batch_count == storage.len)
            return error.InvalidKernelDescriptor;
        const resident = try views.trace.trees.require(tree.role);
        const coefficient_rows = try pow2(tree.column_log_size);
        if (resident.column_log_sizes.len != tree.column_count or
            resident.coefficients.column_stride_words <
                coefficient_rows or
            resident.coefficients.storage.len != try mul(
                tree.column_count,
                resident.coefficients.column_stride_words,
            ))
        {
            return error.InvalidKernelDescriptor;
        }
        if (common_log_size) |expected| {
            if (tree.column_log_size != expected)
                return error.InvalidKernelDescriptor;
        } else {
            common_log_size = tree.column_log_size;
            common_rows = coefficient_rows;
        }
        const end_sample = try add(first_sample, tree.column_count);
        for (first_sample..end_sample) |index| {
            const offset = ingress.oods_offset_points[index];
            if (ingress.coefficient_log_sizes[index] !=
                tree.column_log_size or
                offset.x != 1 or
                offset.y != 0 or
                ingress.oods_fold_counts[index] > 31 or
                ingress.oods_output_indices[index] != try u32Count(index))
            {
                return error.InvalidKernelDescriptor;
            }
        }
        storage[batch_count] = .{
            .coefficients = resident.coefficients,
            .coefficient_rows = try u32Count(coefficient_rows),
            .coefficient_log_size = tree.column_log_size,
            .first_sample = first_sample,
            .sample_count = tree.column_count,
        };
        batch_count += 1;
        first_sample = end_sample;
    }
    if (batch_count == 0 or first_sample != sample_count)
        return error.InvalidKernelDescriptor;

    const log_size = common_log_size orelse
        return error.InvalidKernelDescriptor;
    const rows = common_rows orelse
        return error.InvalidKernelDescriptor;
    if (views.oods.folding_factors.len !=
        try mul(sample_count, log_size))
    {
        return error.InvalidKernelDescriptor;
    }
    const blocks = try ceilDiv(
        rows,
        oods_stage.first_coefficients_per_block,
    );
    const expected_scratch = try mul(sample_count, blocks);
    if (views.oods.reduce_a.len != expected_scratch or
        views.oods.reduce_b.len != expected_scratch)
    {
        return error.InvalidKernelDescriptor;
    }
    return storage[0..batch_count];
}

fn evaluateBatch(
    comptime OodsOps: type,
    session: anytype,
    batch: Batch,
    oods: resident_views.Oods,
) !void {
    const blocks_per_sample = try ceilDiv(
        @as(usize, batch.coefficient_rows),
        oods_stage.first_coefficients_per_block,
    );
    const factor_first = try mul(
        batch.first_sample,
        batch.coefficient_log_size,
    );
    const factor_count = try mul(
        batch.sample_count,
        batch.coefficient_log_size,
    );
    const factors = try oods.folding_factors.sub(
        factor_first,
        factor_count,
    );
    const scratch_first = try mul(
        batch.first_sample,
        blocks_per_sample,
    );
    const scratch_count = try mul(
        batch.sample_count,
        blocks_per_sample,
    );
    const scratch_a = try oods.reduce_a.sub(
        scratch_first,
        scratch_count,
    );
    const scratch_b = try oods.reduce_b.sub(
        scratch_first,
        scratch_count,
    );

    try OodsOps.evaluateFirst(
        session,
        batch.coefficients,
        batch.coefficient_rows,
        factors,
        scratch_a,
    );

    var reduced = scratch_a;
    var alternate = scratch_b;
    var reduced_stride = try u32Count(blocks_per_sample);
    while (reduced_stride > 1) {
        const output_stride = try ceilDivU32(
            reduced_stride,
            oods_stage.reduce_coefficients_per_block,
        );
        const output_count = try mul(
            batch.sample_count,
            output_stride,
        );
        const output = try alternate.sub(0, output_count);
        try OodsOps.reduce(
            session,
            reduced,
            reduced_stride,
            reduced_stride,
            std.math.log2_int(u32, reduced_stride) - 1,
            batch.coefficient_log_size,
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
            .device = try oods.output_indices.sub(
                batch.first_sample,
                batch.sample_count,
            ),
            .output_capacity = oods.sampled_values.len,
        },
        oods.sampled_values,
    );
}

fn requireOperation(
    schedule: anytype,
    step: u32,
    expected: transcript_schedule.Operation,
) !void {
    if (!std.meta.eql(try schedule.operation(step), expected))
        return error.InvalidKernelDescriptor;
}

fn boundary(
    schedule: anytype,
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

fn pow2(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) return error.SizeOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

fn u32Count(value: usize) !u32 {
    return std.math.cast(u32, value) orelse error.SizeOverflow;
}

fn add(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch error.SizeOverflow;
}

fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.SizeOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return error.SizeOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.SizeOverflow;
}

fn ceilDiv(value: usize, divisor: usize) !usize {
    return std.math.divCeil(usize, value, divisor) catch
        error.SizeOverflow;
}

fn ceilDivU32(value: u32, divisor: u32) !u32 {
    return std.math.divCeil(u32, value, divisor) catch
        error.SizeOverflow;
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

test "generic OODS evaluates every role batch in one sample space" {
    const Recorder = struct {
        var evaluations: usize = 0;
        var stores: usize = 0;
    };
    const FakeTranscript = struct {
        pub fn drawSecure(
            _: anytype,
            stage: telemetry.Stage,
            _: common.Words,
            _: transcript_stage.Boundary,
            _: u32,
            _: u32,
            _: common.SecureFields,
            _: common.SecureFields,
        ) !void {
            try std.testing.expectEqual(.oods, stage);
        }
        pub fn mixWords(
            _: anytype,
            stage: telemetry.Stage,
            _: common.Words,
            _: transcript_stage.Boundary,
            _: common.Words,
            _: bool,
            _: common.Words,
        ) !void {
            try std.testing.expectEqual(.oods, stage);
        }
    };
    const FakeOods = struct {
        pub fn derivePoints(
            _: anytype,
            _: common.SecureFields,
            _: common.CirclePoints,
            _: oods_stage.SampleMap,
            _: u32,
            _: common.SecureCirclePoints,
            _: common.SecureCirclePoints,
            _: common.SecureFields,
        ) !void {}
        pub fn evaluateFirst(
            _: anytype,
            _: common.WordMatrix,
            _: u32,
            _: common.SecureFields,
            _: common.SecureFields,
        ) !void {
            Recorder.evaluations += 1;
        }
        pub fn reduce(
            _: anytype,
            _: common.SecureFields,
            _: u32,
            _: u32,
            _: u32,
            _: u32,
            _: common.SecureFields,
            _: common.SecureFields,
        ) !void {}
        pub fn storeResults(
            _: anytype,
            _: common.SecureFields,
            _: u32,
            _: oods_stage.IndexMap,
            _: common.SecureFields,
        ) !void {
            Recorder.stores += 1;
        }
    };
    const words = struct {
        fn at(address: usize, len: usize) common.Words {
            return deviceSlice(u32, address, len);
        }
    };
    const schedule = try transcript_schedule.Schedule.init(0x1234, 3);
    const oods = resident_views.Oods{
        .parameter = deviceSlice(field.SecureField, 0x1000, 1),
        .offset_points = deviceSlice(
            field.CirclePointBaseField,
            0x2000,
            11,
        ),
        .fold_counts = words.at(0x3000, 11),
        .output_indices = words.at(0x4000, 11),
        .sample_points = deviceSlice(
            field.SecureCirclePoint,
            0x5000,
            11,
        ),
        .evaluation_points = deviceSlice(
            field.SecureCirclePoint,
            0x6000,
            11,
        ),
        .folding_factors = deviceSlice(
            field.SecureField,
            0x7000,
            110,
        ),
        .reduce_a = deviceSlice(field.SecureField, 0x8000, 22),
        .reduce_b = deviceSlice(field.SecureField, 0x9000, 22),
        .sampled_values = deviceSlice(
            field.SecureField,
            0xa000,
            11,
        ),
    };
    const transcript = resident_views.Transcript{
        .state = words.at(0xb000, 16),
        .input_snapshot = words.at(0xc000, 44),
        .output_snapshot = words.at(0xd000, 8),
        .boundary_snapshot = words.at(0xe000, 16),
        .static_inputs = words.at(0xf000, 1),
    };
    const batches = [_]Batch{
        .{
            .coefficients = .{
                .storage = words.at(0x10000, 2 * 2048),
                .column_stride_words = 2048,
            },
            .coefficient_rows = 1024,
            .coefficient_log_size = 10,
            .first_sample = 0,
            .sample_count = 2,
        },
        .{
            .coefficients = .{
                .storage = words.at(0x20000, 1024),
                .column_stride_words = 1024,
            },
            .coefficient_rows = 1024,
            .coefficient_log_size = 10,
            .first_sample = 2,
            .sample_count = 1,
        },
        .{
            .coefficients = .{
                .storage = words.at(0x30000, 8 * 1024),
                .column_stride_words = 1024,
            },
            .coefficient_rows = 1024,
            .coefficient_log_size = 10,
            .first_sample = 3,
            .sample_count = 8,
        },
    };
    Recorder.evaluations = 0;
    Recorder.stores = 0;
    var session: u8 = 0;
    try executeWithOps(
        FakeTranscript,
        FakeOods,
        &session,
        schedule,
        transcript,
        oods,
        deviceSlice(field.SecureField, 0x40000, 1),
        &batches,
    );
    try std.testing.expectEqual(@as(usize, 3), Recorder.evaluations);
    try std.testing.expectEqual(@as(usize, 3), Recorder.stores);
}

test "generic OODS preserves the coefficient factor schedule" {
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
        .{ .log_size = 10, .first_blocks = 1, .first_factor = null, .second_blocks = null, .second_factor = null },
        .{ .log_size = 18, .first_blocks = 64, .first_factor = 5, .second_blocks = null, .second_factor = null },
        .{ .log_size = 22, .first_blocks = 1024, .first_factor = 9, .second_blocks = 2, .second_factor = 0 },
    };
    for (cases) |case| {
        const rows = try pow2(case.log_size);
        var size = try u32Count(try ceilDiv(
            rows,
            oods_stage.first_coefficients_per_block,
        ));
        try std.testing.expectEqual(case.first_blocks, size);
        if (case.first_factor) |factor| {
            try std.testing.expectEqual(
                factor,
                std.math.log2_int(u32, size) - 1,
            );
            size = try ceilDivU32(
                size,
                oods_stage.reduce_coefficients_per_block,
            );
        }
        if (case.second_blocks) |second| {
            try std.testing.expectEqual(second, size);
            try std.testing.expectEqual(
                case.second_factor.?,
                std.math.log2_int(u32, size) - 1,
            );
            size = try ceilDivU32(
                size,
                oods_stage.reduce_coefficients_per_block,
            );
        }
        try std.testing.expectEqual(@as(u32, 1), size);
    }
}
