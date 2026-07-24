//! Checked resident Native trace construction.

const std = @import("std");
const abi = @import("../../abi/stages/trace.zig");
const common = @import("common.zig");
const layout = @import("resident_layout.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn xor(
            session: anytype,
            preprocessed: common.WordMatrix,
            main_trace: common.WordMatrix,
            row_count: u32,
            log_n_rows: u32,
            log_step: u32,
            offset: u64,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.trace_generation;
            try common.requireStage(session, stage);
            if (log_n_rows == 0 or log_n_rows >= 31 or
                row_count != @as(u32, 1) << @intCast(log_n_rows) or
                log_step > log_n_rows)
            {
                return error.InvalidKernelDescriptor;
            }
            try exactMatrix(preprocessed, row_count, 2);
            try exactMatrix(main_trace, row_count, 1);
            const preprocessed_view = try layout.wordMatrix(
                session,
                preprocessed,
                row_count,
            );
            const main_view = try layout.wordMatrix(
                session,
                main_trace,
                row_count,
            );
            if (preprocessed_view.column_count != 2 or
                main_view.column_count != 1)
            {
                return error.InvalidKernelDescriptor;
            }
            try layout.requireDisjoint(
                &.{ preprocessed_view.range, main_view.range },
                &.{},
            );
            const status = Api.stwo_native_xor_trace_on(
                preprocessed_view.pointer,
                preprocessed.column_stride_words,
                preprocessed.storage.len,
                main_view.pointer,
                main_trace.column_stride_words,
                main_trace.storage.len,
                row_count,
                log_n_rows,
                log_step,
                offset,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn wideFibonacci(
            session: anytype,
            trace: common.WordMatrix,
            row_count: u32,
            log_n_rows: u32,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.trace_generation;
            try common.requireStage(session, stage);
            if (log_n_rows == 0 or log_n_rows >= 31 or
                row_count != @as(u32, 1) << @intCast(log_n_rows) or
                trace.column_stride_words < row_count or
                trace.column_stride_words == 0 or trace.storage.len == 0 or
                trace.storage.len % trace.column_stride_words != 0)
            {
                return error.InvalidKernelDescriptor;
            }
            const sequence_len =
                trace.storage.len / trace.column_stride_words;
            if (sequence_len < 2 or sequence_len > 512)
                return error.InvalidKernelDescriptor;
            const exact_capacity = std.math.mul(
                usize,
                trace.column_stride_words,
                sequence_len,
            ) catch return error.SizeOverflow;
            if (exact_capacity != trace.storage.len)
                return error.InvalidKernelDescriptor;
            const status = Api.stwo_native_wide_fibonacci_trace_on(
                try common.words(session, trace.storage, trace.storage.len),
                trace.column_stride_words,
                trace.storage.len,
                row_count,
                log_n_rows,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}

fn exactMatrix(
    matrix: common.WordMatrix,
    row_count: u32,
    expected_columns: usize,
) runtime_error.Error!void {
    if (matrix.column_stride_words < row_count or
        matrix.column_stride_words == 0 or matrix.storage.len == 0)
    {
        return error.InvalidKernelDescriptor;
    }
    const exact_capacity = std.math.mul(
        usize,
        matrix.column_stride_words,
        expected_columns,
    ) catch return error.SizeOverflow;
    if (matrix.storage.len != exact_capacity)
        return error.InvalidKernelDescriptor;
}
