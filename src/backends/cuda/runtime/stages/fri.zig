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
            evaluation_values: common.PointerTable,
            alpha: common.SecureFields,
            alpha_squarings: u32,
            folded_values: common.PointerTable,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.fri_commit;
            try common.requireStage(session, stage);
            try common.requireNonZero(&.{size});
            const source = try common.mutableWordTable(session, evaluation_values, 4);
            const destination = try common.mutableWordTable(session, folded_values, 4);
            const alpha_pointer = @as(
                *const @import("../../abi/field.zig").SecureField,
                @ptrCast(try common.secure(session, alpha, 1)),
            );
            const status = if (circle)
                Api.stwo_fold_circle_into_line_on(
                    try common.words(session, domain, size),
                    twiddle_offset,
                    size,
                    source,
                    alpha_pointer,
                    alpha_squarings,
                    destination,
                    session.context.stream,
                )
            else
                Api.stwo_fold_line_on(
                    try common.words(session, domain, size),
                    twiddle_offset,
                    size,
                    source,
                    alpha_pointer,
                    alpha_squarings,
                    destination,
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
            evaluation_values: common.PointerTable,
            alpha: common.SecureFields,
            folded_values: common.PointerTable,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.fri_commit;
            try common.requireStage(session, stage);
            try common.requireNonZero(&.{size});
            const status = Api.stwo_fri_fold_fused3_on(
                try common.words(session, domain, size),
                twiddle_offsets[0],
                twiddle_offsets[1],
                twiddle_offsets[2],
                size,
                @intFromBool(first_fold_is_circle),
                try common.mutableWordTable(session, evaluation_values, 4),
                @ptrCast(try common.secure(session, alpha, 1)),
                try common.mutableWordTable(session, folded_values, 4),
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
            try common.requireNonZero(&.{evaluation_stride});
            const status = Api.stwo_fri_last_layer_on(
                try common.words(session, evaluation, 1),
                evaluation_stride,
                log_size,
                try common.words(session, inverse_twiddles, 1),
                try common.count(inverse_twiddles.len),
                log_degree_bound,
                try common.words(session, coefficients, 1),
                try common.words(session, degree_error, 1),
                try common.words(session, transcript_coefficients, 1),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn grindPow(
            session: anytype,
            transcript_state: common.Words,
            pow_bits: u32,
            prefix_digest: common.Words,
            best_nonce: common.Nonce,
            completed_blocks: common.Words,
            transcript_nonce: common.Words,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.pow;
            try common.requireStage(session, stage);
            const status = Api.stwo_blake2s_pow_persistent_on(
                try common.words(session, transcript_state, 16),
                pow_bits,
                try common.words(session, prefix_digest, 8),
                try common.nonce(session, best_nonce),
                try common.words(session, completed_blocks, 1),
                try common.words(session, transcript_nonce, 2),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}
