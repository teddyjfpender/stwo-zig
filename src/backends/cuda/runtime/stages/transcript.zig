//! Checked resident Blake2s Fiat-Shamir dispatch.

const abi = @import("../../abi/stages/transcript.zig");
const common = @import("common.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);

pub const Boundary = struct {
    expected_step: u32,
    expected_chain: u64,
    next_chain: u64,
    snapshot: common.Words,
};

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn initialize(
            session: anytype,
            stage: telemetry.Stage,
            state: common.Words,
            seed: common.Words,
            seed_snapshot: common.Words,
            initial_chain: u64,
        ) runtime_error.Error!void {
            try requireTranscriptStage(session, stage);
            const status = Api.stwo_blake2s_transcript_init_on(
                try common.words(session, state, 16),
                try common.words(session, seed, 8),
                try common.words(session, seed_snapshot, 8),
                initial_chain,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn mixWords(
            session: anytype,
            stage: telemetry.Stage,
            state: common.Words,
            boundary: Boundary,
            source: common.Words,
            validate_m31: bool,
            input_snapshot: common.Words,
        ) runtime_error.Error!void {
            try requireTranscriptStage(session, stage);
            const status = Api.stwo_blake2s_transcript_mix_words_on(
                try common.words(session, state, 16),
                boundary.expected_step,
                boundary.expected_chain,
                boundary.next_chain,
                try common.words(session, source, 1),
                try common.count(source.len),
                @intFromBool(validate_m31),
                try common.words(session, input_snapshot, source.len),
                try common.words(session, boundary.snapshot, 16),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn absorbPow(
            session: anytype,
            state: common.Words,
            boundary: Boundary,
            nonce_words: common.Words,
            pow_bits: u32,
            input_snapshot: common.Words,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.pow;
            try requireTranscriptStage(session, stage);
            const status = Api.stwo_blake2s_transcript_absorb_pow_on(
                try common.words(session, state, 16),
                boundary.expected_step,
                boundary.expected_chain,
                boundary.next_chain,
                try common.words(session, nonce_words, 2),
                pow_bits,
                try common.words(session, input_snapshot, 2),
                try common.words(session, boundary.snapshot, 16),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn drawWords(
            session: anytype,
            stage: telemetry.Stage,
            state: common.Words,
            boundary: Boundary,
            output: common.Words,
            output_snapshot: common.Words,
        ) runtime_error.Error!void {
            try requireTranscriptStage(session, stage);
            if (output.len != 8 or output_snapshot.len != 8)
                return error.SizeOverflow;
            const status = Api.stwo_blake2s_transcript_draw_u32s_on(
                try common.words(session, state, 16),
                boundary.expected_step,
                boundary.expected_chain,
                boundary.next_chain,
                try common.words(session, output, 8),
                try common.words(session, output_snapshot, 8),
                try common.words(session, boundary.snapshot, 16),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn drawSecure(
            session: anytype,
            stage: telemetry.Stage,
            state: common.Words,
            boundary: Boundary,
            felt_count: u32,
            max_rejection_rounds: u32,
            output: common.SecureFields,
            output_snapshot: common.SecureFields,
        ) runtime_error.Error!void {
            try requireTranscriptStage(session, stage);
            try common.requireNonZero(&.{ felt_count, max_rejection_rounds });
            if (output.len != felt_count or output_snapshot.len != felt_count)
                return error.SizeOverflow;
            const status = Api.stwo_blake2s_transcript_draw_secure_on(
                try common.words(session, state, 16),
                boundary.expected_step,
                boundary.expected_chain,
                boundary.next_chain,
                felt_count,
                max_rejection_rounds,
                try common.secure(session, output, felt_count),
                try common.secure(session, output_snapshot, felt_count),
                try common.words(session, boundary.snapshot, 16),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn drawQueries(
            session: anytype,
            state: common.Words,
            boundary: Boundary,
            log_domain_size: u32,
            output: common.Words,
            output_snapshot: common.Words,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.decommit;
            try requireTranscriptStage(session, stage);
            if (output.len == 0 or output_snapshot.len < output.len)
                return error.SizeOverflow;
            const query_count = try common.count(output.len);
            const status = Api.stwo_blake2s_transcript_draw_queries_on(
                try common.words(session, state, 16),
                boundary.expected_step,
                boundary.expected_chain,
                boundary.next_chain,
                log_domain_size,
                query_count,
                try common.words(session, output, output.len),
                try common.words(session, output_snapshot, output.len),
                try common.words(session, boundary.snapshot, 16),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}

fn requireTranscriptStage(
    session: anytype,
    stage: telemetry.Stage,
) runtime_error.Error!void {
    switch (stage) {
        .ingress, .trace_generation, .proof_assembly => return error.StageOrderViolation,
        else => try common.requireStage(session, stage),
    }
}
