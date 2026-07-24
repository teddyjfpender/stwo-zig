//! Checked resident Native trace construction.

const std = @import("std");
const abi = @import("../../abi/stages/trace.zig");
const common = @import("common.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn wideFibonacci(
            session: anytype,
            trace: common.Words,
            row_count: u32,
            sequence_len: u32,
            log_n_rows: u32,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.trace_generation;
            try common.requireStage(session, stage);
            if (log_n_rows == 0 or log_n_rows >= 31 or
                sequence_len < 2 or sequence_len > 512 or
                row_count != @as(u32, 1) << @intCast(log_n_rows))
            {
                return error.InvalidKernelDescriptor;
            }
            const expected_words = std.math.mul(
                usize,
                row_count,
                sequence_len,
            ) catch return error.SizeOverflow;
            if (trace.len != expected_words) return error.SizeOverflow;
            const status = Api.stwo_native_wide_fibonacci_trace_on(
                try common.words(session, trace, expected_words),
                trace.len,
                row_count,
                sequence_len,
                log_n_rows,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}
