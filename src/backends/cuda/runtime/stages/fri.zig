//! Checked resident FRI folding, terminal interpolation, and PoW dispatch.

const abi = @import("../../abi/stages/fri.zig");
const common = @import("common.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn fold(
            session: anytype,
            circle: bool,
            domain: common.Words,
            twiddle_offset: u32,
            size: u32,
            evaluation_values: common.WordMatrix,
            alpha: common.SecureFields,
            alpha_squarings: u32,
            folded_values: common.WordMatrix,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.fri_commit;
            try common.requireStage(session, stage);
            try common.requireNonZero(&.{size});
            if (size > (@as(u32, 1) << 30) or
                size & (size - 1) != 0 or alpha_squarings > 30)
                return error.InvalidKernelDescriptor;
            const output_size = size / 2;
            const source = try matrix(
                session,
                evaluation_values,
                size,
            );
            const destination = try matrix(
                session,
                folded_values,
                output_size,
            );
            const domain_words = domain.len;
            const alpha_pointer = @as(
                *const @import("../../abi/field.zig").SecureField,
                @ptrCast(try common.secure(session, alpha, 1)),
            );
            const status = if (circle)
                Api.stwo_fold_circle_into_line_on(
                    try common.words(session, domain, 1),
                    domain_words,
                    twiddle_offset,
                    size,
                    source.pointer,
                    source.words,
                    source.stride,
                    alpha_pointer,
                    alpha_squarings,
                    destination.pointer,
                    destination.words,
                    destination.stride,
                    session.context.stream,
                )
            else
                Api.stwo_fold_line_on(
                    try common.words(session, domain, 1),
                    domain_words,
                    twiddle_offset,
                    size,
                    source.pointer,
                    source.words,
                    source.stride,
                    alpha_pointer,
                    alpha_squarings,
                    destination.pointer,
                    destination.words,
                    destination.stride,
                    session.context.stream,
                );
            try common.record(session, stage, status);
        }

        pub fn foldThree(
            session: anytype,
            domain: common.Words,
            twiddle_offsets: [3]u32,
            size: u32,
            first_fold_is_circle: bool,
            evaluation_values: common.WordMatrix,
            alpha: common.SecureFields,
            folded_values: common.WordMatrix,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.fri_commit;
            try common.requireStage(session, stage);
            try common.requireNonZero(&.{size});
            if (size < 8 or size > (@as(u32, 1) << 30) or
                size & (size - 1) != 0)
                return error.InvalidKernelDescriptor;
            const source = try matrix(session, evaluation_values, size);
            const destination = try matrix(session, folded_values, size / 8);
            const status = Api.stwo_fri_fold_fused3_on(
                try common.words(session, domain, 1),
                domain.len,
                twiddle_offsets[0],
                twiddle_offsets[1],
                twiddle_offsets[2],
                size,
                @intFromBool(first_fold_is_circle),
                source.pointer,
                source.words,
                source.stride,
                @ptrCast(try common.secure(session, alpha, 1)),
                destination.pointer,
                destination.words,
                destination.stride,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn lastLayer(
            session: anytype,
            evaluation: common.Words,
            evaluation_stride: u32,
            log_size: u32,
            inverse_twiddles: common.Words,
            log_degree_bound: u32,
            coefficients: common.Words,
            degree_error: common.Words,
            transcript_coefficients: common.Words,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.fri_commit;
            try common.requireStage(session, stage);
            if (log_size == 0 or log_size > 30 or
                log_degree_bound > log_size)
                return error.InvalidKernelDescriptor;
            const size = @as(usize, 1) << @intCast(log_size);
            const degree_bound = @as(usize, 1) << @intCast(log_degree_bound);
            if (evaluation_stride < size or inverse_twiddles.len < size)
                return error.SizeOverflow;
            const evaluation_words = @import("std").math.mul(
                usize,
                evaluation_stride,
                4,
            ) catch return error.SizeOverflow;
            const coefficient_words = @import("std").math.mul(
                usize,
                size,
                4,
            ) catch return error.SizeOverflow;
            const transcript_words = @import("std").math.mul(
                usize,
                degree_bound,
                4,
            ) catch return error.SizeOverflow;
            if (evaluation.len < evaluation_words or
                coefficients.len != coefficient_words or
                degree_error.len != 1 or
                transcript_coefficients.len != transcript_words)
                return error.SizeOverflow;
            const status = Api.stwo_fri_last_layer_on(
                try common.words(session, evaluation, evaluation_words),
                evaluation_words,
                evaluation_stride,
                log_size,
                try common.words(session, inverse_twiddles, 1),
                try common.count(inverse_twiddles.len),
                log_degree_bound,
                try common.words(session, coefficients, coefficient_words),
                coefficient_words,
                try common.words(session, degree_error, 1),
                1,
                try common.words(session, transcript_coefficients, transcript_words),
                transcript_words,
                session.context.stream,
            );
            const launch_count =
                @as(u64, log_size) + 4 +
                @as(u64, @intFromBool(degree_bound < size));
            try common.recordMany(session, stage, status, launch_count);
        }

        pub fn grindPow(
            session: anytype,
            transcript_state: common.Words,
            pow_bits: u32,
            search_end: u64,
            prefix_digest: common.Words,
            best_nonce: common.Nonce,
            completed_blocks: common.Words,
            transcript_nonce: common.Words,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.pow;
            try common.requireStage(session, stage);
            if (pow_bits > 32 or search_end == 0 or
                search_end > (@as(u64, 0x7fff_ffff) << 20))
                return error.InvalidKernelDescriptor;
            const status = Api.stwo_blake2s_pow_persistent_on(
                try common.words(session, transcript_state, 16),
                pow_bits,
                search_end,
                try common.words(session, prefix_digest, 8),
                try common.nonce(session, best_nonce),
                try common.words(session, completed_blocks, 1),
                try common.words(session, transcript_nonce, 2),
                session.context.stream,
            );
            try common.recordMany(session, stage, status, 3);
        }
    };
}

const MatrixPointer = struct {
    pointer: [*]u32,
    words: usize,
    stride: u32,
};

fn matrix(
    session: anytype,
    value: common.WordMatrix,
    minimum_stride: usize,
) runtime_error.Error!MatrixPointer {
    if (value.column_stride_words < minimum_stride)
        return error.SizeOverflow;
    const words = @import("std").math.mul(
        usize,
        value.column_stride_words,
        4,
    ) catch return error.SizeOverflow;
    return .{
        .pointer = try common.words(session, value.storage, words),
        .words = words,
        .stride = try common.count(value.column_stride_words),
    };
}
