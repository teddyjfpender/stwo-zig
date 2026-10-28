//! Exact raw-channel comparison between a freshly verified native SegmentV2
//! proof and the transcript execution supplied to its recursive leaf.
//! Neither recording is an admission receipt on its own: callers must verify
//! the proof and admit the recursive plan before invoking this comparison.
const std = @import("std");
const recorded = @import("recording_poseidon_channel_v4.zig");
const scheduled = @import("transcript_program_v2.zig");

pub fn compare(
    native: *const recorded.ExecutionV4,
    recursive: *const scheduled.Execution,
    program: *const scheduled.Program,
) !void {
    try native.validate();
    try recursive.replayNative(program);
    if (native.operations.len != program.instructions.len or
        native.hash_frames.len != recursive.hash_frames.len or
        native.poseidon_calls.len != recursive.poseidon_calls.len or
        native.pow_checks.len != recursive.pow_checks.len or
        !std.meta.eql(native.final_digest, recursive.final_digest) or
        native.final_draw_count != recursive.final_draw_count)
        return error.NativeRecursiveTranscriptMismatch;

    for (native.operations, recursive.operations, program.instructions, 0..) |left, right, instruction, index| {
        if (right.instruction_index != index)
            return error.NativeRecursiveTranscriptMismatch;
        if (@intFromEnum(left.effect) != @intFromEnum(instruction.effect()) + 1 or
            left.first_hash_id != right.first_hash_id or
            left.hash_count != right.hash_count or
            left.first_call_id != right.first_call_id or
            left.call_count != right.call_count or
            (left.pow_check_index != null) != (instruction.effect() == .pow))
            return error.NativeRecursiveTranscriptMismatch;
    }
    for (native.hash_frames, recursive.hash_frames) |left, right| {
        if (left.hash_id != right.hash_id or
            left.first_call_id != right.first_call_id or
            left.call_count != right.call_count or
            left.purpose != right.purpose or
            left.words.len != right.words.len or
            !std.meta.eql(left.output, right.output))
            return error.NativeRecursiveTranscriptMismatch;
        for (left.words, right.words) |actual, expected|
            if (!actual.eql(expected)) return error.NativeRecursiveTranscriptMismatch;
    }
    for (native.poseidon_calls, recursive.poseidon_calls) |left, right|
        if (!std.meta.eql(left, right)) return error.NativeRecursiveTranscriptMismatch;
    for (native.pow_checks, recursive.pow_checks) |left, right|
        if (!std.meta.eql(left, right)) return error.NativeRecursiveTranscriptMismatch;
}

/// Producer and detached verifier must issue exactly the same ordinary-channel
/// operations for identical proof bytes and independently supplied admission.
pub fn compareRecordings(
    producer: *const recorded.ExecutionV4,
    verifier: *const recorded.ExecutionV4,
) !void {
    try producer.validate();
    try verifier.validate();
    if (producer.operations.len != verifier.operations.len or
        producer.hash_frames.len != verifier.hash_frames.len or
        producer.poseidon_calls.len != verifier.poseidon_calls.len or
        producer.pow_checks.len != verifier.pow_checks.len or
        !std.meta.eql(producer.final_digest, verifier.final_digest) or
        producer.final_draw_count != verifier.final_draw_count)
        return error.ProducerVerifierTranscriptMismatch;
    for (producer.operations, verifier.operations) |left, right|
        if (!std.meta.eql(left, right)) return error.ProducerVerifierTranscriptMismatch;
    for (producer.hash_frames, verifier.hash_frames) |left, right| {
        if (left.hash_id != right.hash_id or
            left.first_call_id != right.first_call_id or
            left.call_count != right.call_count or
            left.purpose != right.purpose or
            left.words.len != right.words.len or
            !std.meta.eql(left.output, right.output))
            return error.ProducerVerifierTranscriptMismatch;
        for (left.words, right.words) |actual, expected|
            if (!actual.eql(expected)) return error.ProducerVerifierTranscriptMismatch;
    }
    for (producer.poseidon_calls, verifier.poseidon_calls) |left, right|
        if (!std.meta.eql(left, right)) return error.ProducerVerifierTranscriptMismatch;
    for (producer.pow_checks, verifier.pow_checks) |left, right|
        if (!std.meta.eql(left, right)) return error.ProducerVerifierTranscriptMismatch;
}
