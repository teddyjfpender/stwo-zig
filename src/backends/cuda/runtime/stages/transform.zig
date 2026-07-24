//! Checked resident circle-transform dispatch over contiguous arena slabs.

const std = @import("std");
const abi = @import("../../abi/stages/transform.zig");
const common = @import("common.zig");
const layout = @import("resident_layout.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);

/// One contiguous allocation with a fixed per-column stride. The column count
/// is derived from the extent, so no pointer table or duplicate count can
/// disagree with the checked descriptor.
pub const WordMatrix = common.WordMatrix;

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn inverseToRetained(
            session: anytype,
            stage: telemetry.Stage,
            inputs: WordMatrix,
            retained_outputs: WordMatrix,
            log_n: u32,
            inverse_twiddles: common.Words,
        ) runtime_error.Error!void {
            try requireTransformStage(stage);
            try common.requireStage(session, stage);
            const shape = try transformShape(log_n);
            const input = try layout.wordMatrix(
                session,
                inputs,
                shape.values,
            );
            const output = try layout.wordMatrix(
                session,
                retained_outputs,
                shape.retained_values,
            );
            if (input.column_count != output.column_count)
                return error.InvalidKernelDescriptor;
            if (layout.overlap(input.range, output.range) and
                (input.range.start != output.range.start or
                    input.stride_words != output.stride_words))
            {
                return error.OverlappingDeviceRange;
            }
            const twiddles = try layout.resident(
                session,
                u32,
                inverse_twiddles,
                shape.domain,
            );
            if (layout.overlap(output.range, twiddles.range))
                return error.OverlappingDeviceRange;

            const status = Api.stwo_ntt_b2n_columns_to_retained_on(
                input.pointer,
                input.stride_words,
                output.pointer,
                output.stride_words,
                log_n,
                input.column_count,
                twiddles.pointer,
                try common.count(inverse_twiddles.len),
                try common.count(shape.domain),
                session.context.stream,
            );
            try common.recordMany(
                session,
                stage,
                status,
                try transformLaunches(input.column_count, log_n),
            );
        }

        pub fn forwardInPlace(
            session: anytype,
            stage: telemetry.Stage,
            columns: WordMatrix,
            log_n: u32,
            twiddles: common.Words,
        ) runtime_error.Error!void {
            try requireTransformStage(stage);
            try common.requireStage(session, stage);
            const shape = try transformShape(log_n);
            const values = try layout.wordMatrix(session, columns, shape.values);
            const twiddle_values = try layout.resident(
                session,
                u32,
                twiddles,
                shape.domain,
            );
            if (layout.overlap(values.range, twiddle_values.range))
                return error.OverlappingDeviceRange;

            const status = Api.stwo_ntt_n2b_columns_on(
                values.pointer,
                values.stride_words,
                log_n,
                values.column_count,
                twiddle_values.pointer,
                try common.count(twiddles.len),
                try common.count(shape.domain),
                session.context.stream,
            );
            try common.recordMany(
                session,
                stage,
                status,
                try transformLaunches(values.column_count, log_n),
            );
        }

        pub fn extend(
            session: anytype,
            stage: telemetry.Stage,
            coefficients: WordMatrix,
            coefficient_sizes: common.Words,
            evaluations: WordMatrix,
            log_n: u32,
            twiddles: common.Words,
            before_final_circle: bool,
        ) runtime_error.Error!void {
            try requireTransformStage(stage);
            try common.requireStage(session, stage);
            const shape = try transformShape(log_n);
            const coefficient_values = try layout.wordMatrix(
                session,
                coefficients,
                shape.domain,
            );
            const evaluation_values = try layout.wordMatrix(
                session,
                evaluations,
                shape.values,
            );
            if (coefficient_values.column_count != evaluation_values.column_count)
                return error.InvalidKernelDescriptor;
            const count: usize = evaluation_values.column_count;
            const sizes = try layout.resident(
                session,
                u32,
                coefficient_sizes,
                count,
            );
            const twiddle_values = try layout.resident(
                session,
                u32,
                twiddles,
                shape.domain,
            );
            for ([_]layout.DeviceRange{
                coefficient_values.range,
                sizes.range,
                twiddle_values.range,
            }) |read_range| {
                if (layout.overlap(evaluation_values.range, read_range))
                    return error.OverlappingDeviceRange;
            }

            const status = if (before_final_circle)
                Api.stwo_lde_n2b_columns_before_circle_on(
                    coefficient_values.pointer,
                    coefficient_values.stride_words,
                    sizes.pointer,
                    evaluation_values.pointer,
                    evaluation_values.stride_words,
                    log_n,
                    evaluation_values.column_count,
                    twiddle_values.pointer,
                    try common.count(twiddles.len),
                    try common.count(shape.domain),
                    session.context.stream,
                )
            else
                Api.stwo_lde_n2b_columns_on(
                    coefficient_values.pointer,
                    coefficient_values.stride_words,
                    sizes.pointer,
                    evaluation_values.pointer,
                    evaluation_values.stride_words,
                    log_n,
                    evaluation_values.column_count,
                    twiddle_values.pointer,
                    try common.count(twiddles.len),
                    try common.count(shape.domain),
                    session.context.stream,
                );
            const stages_per_chunk: u32 = if (before_final_circle)
                log_n
            else
                log_n + 1;
            try common.recordMany(
                session,
                stage,
                status,
                try transformLaunches(
                    evaluation_values.column_count,
                    stages_per_chunk,
                ),
            );
        }
    };
}

const TransformShape = struct {
    domain: usize,
    values: usize,
    retained_values: usize,
};

fn transformShape(log_n: u32) runtime_error.Error!TransformShape {
    if (log_n < 3 or log_n > 30) return error.InvalidKernelDescriptor;
    const values = @as(usize, 1) << @intCast(log_n);
    return .{
        .domain = values / 2,
        .values = values,
        .retained_values = std.math.mul(usize, values, 2) catch
            return error.SizeOverflow,
    };
}

fn transformLaunches(
    column_count: u32,
    stages_per_chunk: u32,
) runtime_error.Error!u64 {
    const chunks = std.math.divCeil(
        u64,
        column_count,
        65_535,
    ) catch return error.SizeOverflow;
    return std.math.mul(u64, chunks, stages_per_chunk) catch
        return error.SizeOverflow;
}

fn requireTransformStage(stage: telemetry.Stage) runtime_error.Error!void {
    switch (stage) {
        .trace_commit, .oods, .quotient, .fri_commit => {},
        else => return error.StageOrderViolation,
    }
}
