//! PCS transcript rows following the detached SD prefix. Operation order comes
//! from the shared secure program; sponge rows use the common frame writers.
//! These rows create lookup obligations, not a recursive verifier receipt.
const recursion = struct {
    const recording_poseidon_channel_v4 = @import("recording_poseidon_channel_v4.zig");
    const segment_transcript_outer_source_v2 = @import("segment_transcript_outer_source_v2.zig");
};
const air = struct {
    const control = @import("air/control.zig");
    const control_witness = @import("air/control_witness.zig");
    const field_statement_word_v3 = @import("air/field_statement_word_v3.zig");
    const pow_check = @import("air/pow_check.zig");
    const pow_check_witness = @import("air/pow_check_witness.zig");
    const pow_frame = @import("air/pow_frame.zig");
    const pow_frame_witness = @import("air/pow_frame_witness.zig");
    const relation_interaction = @import("air/relation_interaction.zig");
    const transcript_air = @import("air/transcript_air.zig");
    const transcript_air_witness = @import("air/transcript_air_witness.zig");
    const transcript_binding = @import("air/transcript_binding.zig");
    const transcript_payload = @import("air/transcript_payload.zig");
    const transcript_state = @import("air/transcript_state.zig");
    const transcript_word = @import("air/transcript_word.zig");
    const verifier_randomness = @import("air/verifier_randomness.zig");
    const verifier_randomness_witness = @import("air/verifier_randomness_witness.zig");
};
const std = @import("std");

const core = @import("stwo_core");
const recording = recursion.recording_poseidon_channel_v4;
const rows = recursion.segment_transcript_outer_source_v2;
const prefix_mod = @import("detached_prefix_preparation_v1.zig");
const frame_rows = @import("transcript_frame_rows_v1.zig");
const shared_rows = @import("transcript_payload_kind_v1.zig");
const M31 = core.fields.m31.M31;
const NonceRow = frame_rows.NonceRow;
const STEP_TAG_BASE: u32 = 0x5354_0000;

pub const View = struct {
    control: []const air.control_witness.Row,
    sponge: []const rows.TranscriptAirRowV2,
    binding: []const rows.TranscriptBindingRowV2,
    state: []const rows.TranscriptStateRowV2,
    word: []const rows.TranscriptWordRowV2,
    payload: []const prefix_mod.PayloadRow,
    pow_check: []const air.pow_check_witness.RelationRow,
    pow_frame: []const air.pow_frame_witness.RelationRow,
    randomness: []const rows.VerifierRandomnessRowV2,
    nonce: []const NonceRow,
    provider: []const rows.ProviderCall,
};

pub const OwnedV1 = opaque {
    const Storage = struct { arena: std.heap.ArenaAllocator, rows: View };

    pub fn init(allocator: std.mem.Allocator, child: anytype, prefix: *const prefix_mod.OwnedV1, lane: u32) !*OwnedV1 {
        if (lane != 1 and lane != 2) return error.InvalidDetachedPcsLane;
        const start = prefix.view();
        const execution = child.recordingView();
        if (start.control.len == 0 or start.control[0].verifier_id != lane or
            start.next_operation >= execution.operations.len or
            start.next_hash >= execution.trace.hash_frames.len or
            start.next_call >= execution.trace.poseidon_calls.len)
            return error.DetachedPcsPrefixMismatch;
        // A prefix from another proof must not be combined with this suffix.
        if (!std.meta.eql(start.state[start.state.len - 1].main.outputs, execution.trace.hash_frames[start.next_hash - 1].output[0..recording.RATE].*))
            return error.DetachedPcsPrefixMismatch;
        const storage_value = try allocator.create(Storage);
        errdefer allocator.destroy(storage_value);
        storage_value.arena = std.heap.ArenaAllocator.init(allocator);
        errdefer storage_value.arena.deinit();
        const owned = storage_value.arena.allocator();
        const operations = try prefix_mod.initPcsOperations(owned, child);
        const captured = execution.operations[start.next_operation..];
        if (operations.len != captured.len) return error.DetachedPcsScheduleMismatch;
        const frame_count = execution.trace.hash_frames.len - start.next_hash;
        const call_count = execution.trace.poseidon_calls.len - start.next_call;
        var payload_count: usize = 0;
        var draw_count: usize = 0;
        var pow_count: usize = 0;
        for (operations) |op| {
            if (shared_rows.payloadKind(op.source) != null) payload_count += op.payload_words;
            draw_count += @intFromBool(op.effect == .draw);
            pow_count += @intFromBool(op.effect == .pow);
        }
        const control = try owned.alloc(air.control_witness.Row, operations.len);
        const sponge = try owned.alloc(rows.TranscriptAirRowV2, call_count);
        const binding = try owned.alloc(rows.TranscriptBindingRowV2, call_count);
        const state = try owned.alloc(rows.TranscriptStateRowV2, frame_count);
        const word = try owned.alloc(rows.TranscriptWordRowV2, (call_count - frame_count) * recording.RATE);
        const payload = try owned.alloc(prefix_mod.PayloadRow, payload_count);
        const pow_check = try owned.alloc(air.pow_check_witness.RelationRow, pow_count);
        const pow_frame = try owned.alloc(air.pow_frame_witness.RelationRow, pow_count);
        const randomness = try owned.alloc(rows.VerifierRandomnessRowV2, draw_count);
        const nonce = try owned.alloc(NonceRow, 2 * pow_count);
        const provider = try owned.alloc(rows.ProviderCall, call_count);
        var mix_ordinal: u32 = 0;
        for (execution.trace.hash_frames[0..start.next_hash]) |frame| mix_ordinal += @intFromBool(frame.purpose == .mix);
        var hash_at: usize = start.next_hash;
        var call_at: usize = start.next_call;
        var word_at: usize = 0;
        var payload_at: usize = 0;
        var random_at: usize = 0;
        var pow_at: usize = 0;
        for (operations, captured, 0..) |instruction, operation, index| {
            const is_pow = instruction.effect == .pow;
            const hash_count: usize = if (is_pow) 2 else 1;
            if (operation.effect != instruction.effect or operation.first_hash_id != hash_at or
                operation.first_call_id != call_at or operation.hash_count != hash_count)
                return error.DetachedPcsScheduleMismatch;
            const step = frame_rows.Step{
                .verifier_id = lane,
                .sequence = @intCast(start.next_operation + index),
                .tag = if (is_pow) air.pow_frame.controlTag(.pcs) else STEP_TAG_BASE + @intFromEnum(instruction.context),
                .args = .{ if (is_pow) instruction.pow_bits else @intFromEnum(instruction.effect), instruction.payload_words, @intFromEnum(instruction.draw), instruction.item },
            };
            control[index] = .{ .segment_mask = 0, .binary_mask = 1, .verifier_id = lane, .sequence = step.sequence, .tag = step.tag, .args = step.args, .terminal_mask = 0 };
            for (0..hash_count) |part| {
                const frame = execution.trace.hash_frames[hash_at];
                const pow_draw = is_pow and part == 1;
                const is_draw = instruction.effect == .draw or pow_draw;
                const expected_words = recording.RATE + @as(usize, if (is_draw) 2 else instruction.payload_words);
                if (frame.hash_id != hash_at or frame.first_call_id != call_at or
                    frame.words.len != expected_words or frame.call_count != expected_words / recording.RATE + 1 or
                    frame.purpose != @as(recording.HashPurpose, if (is_draw) .draw else .mix))
                    return error.DetachedPcsScheduleMismatch;
                state[hash_at - start.next_hash] = frame_rows.state(step, execution.trace.hash_frames, hash_at, mix_ordinal, pow_draw);
                mix_ordinal += @intFromBool(frame.purpose == .mix);
                for (recording.RATE..frame.call_count * recording.RATE) |at| {
                    word[word_at] = frame_rows.word(step, frame, @intCast(at));
                    word_at += 1;
                }
                if (instruction.source == .nonce and part == 0) {
                    nonce[2 * pow_at ..][0..2].* = try frame_rows.nonceRows(step, frame.words[recording.RATE..]);
                }
                if (shared_rows.payloadKind(instruction.source)) |kind| {
                    const width: u32 = if (kind == .commitment or kind == .fri_commitment) 8 else 4;
                    for (frame.words[recording.RATE..], 0..) |value, at| {
                        const position: u32 = @intCast(at);
                        payload[payload_at] = .{ .preprocessing = .{
                            .row_mask = 1,
                            .segment_mask = 0,
                            .binary_mask = 1,
                            .verifier_id = lane,
                            .sequence = step.sequence,
                            .tag = step.tag,
                            .args = step.args,
                            .payload_index = position,
                            .source_kind = kind,
                            .item_index = instruction.item + position / width,
                            .limb_index = position % width,
                            .constant_mask = 0,
                            .input_use_count = if (kind == .sampled_value) 2 else 1,
                            .constant_value = 0,
                            .source_hash_id = frame.hash_id,
                            .source_word_index = @intCast(recording.RATE + at),
                        }, .value = value };
                        payload_at += 1;
                    }
                }
                if (pow_draw) {
                    const check_index = operation.pow_check_index orelse return error.DetachedPcsScheduleMismatch;
                    const check = execution.trace.pow_checks[check_index];
                    if (check.bits != instruction.pow_bits) return error.DetachedPcsNonceMismatch;
                    pow_check[pow_at] = try air.pow_check_witness.mainRow(.{ .verifier_id = lane, .kind = .pcs, .check = check });
                    pow_frame[pow_at] = try air.pow_frame_witness.mainRow(.{ .verifier_id = lane, .sequence = step.sequence, .kind = .pcs, .hash_id = frame.hash_id, .check = check, .words = frame.output[0..recording.RATE].* });
                    pow_at += 1;
                } else if (instruction.effect == .draw) {
                    const kind: air.verifier_randomness_witness.Kind = switch (instruction.draw) {
                        .composition => .composition_randomness,
                        .oods => .oods_point,
                        .deep => .deep_randomness,
                        .fri_alpha => .fri_alpha,
                        .queries => .raw_query,
                        else => return error.DetachedPcsScheduleMismatch,
                    };
                    var multiplicities: [8]u32 = undefined;
                    for (&multiplicities, 0..) |*value, at| value.* = kind.semanticUseCount() * @intFromBool(at < instruction.draw_word_count);
                    randomness[random_at] = .{ .preprocessing = .{
                        .row_mask = 1,
                        .segment_mask = 0,
                        .binary_mask = 1,
                        .verifier_id = lane,
                        .sequence = step.sequence,
                        .tag = step.tag,
                        .args = step.args,
                        .kind = kind,
                        .item_base = instruction.item,
                        .query_items = @intFromBool(instruction.draw == .queries),
                        .multiplicities = multiplicities,
                        .draw_index = @intCast(random_at),
                    }, .main = .{ .enabler = 1, .outputs = frame.output[0..recording.RATE].* } };
                    random_at += 1;
                }
                for (frame.first_call_id..frame.first_call_id + frame.call_count) |absolute| {
                    const call = execution.trace.poseidon_calls[absolute];
                    const local = absolute - start.next_call;
                    const previous = if (call.id.step == 0) [_]M31{M31.zero()} ** recording.WIDTH else execution.trace.poseidon_calls[absolute - 1].output;
                    sponge[local] = air.transcript_air_witness.rowFromCall(lane, frame, call, previous);
                    binding[local] = frame_rows.binding(step, @intCast(absolute), frame, call, sponge[local], part == 0, pow_draw);
                    provider[local] = frame_rows.providerCall(call);
                }
                call_at += frame.call_count;
                hash_at += 1;
            }
        }
        if (word_at != word.len or payload_at != payload.len or random_at != randomness.len or pow_at != pow_count or
            hash_at != execution.trace.hash_frames.len or call_at != execution.trace.poseidon_calls.len)
            return error.DetachedPcsScheduleMismatch;
        storage_value.rows = .{ .control = control, .sponge = sponge, .binding = binding, .state = state, .word = word, .payload = payload, .pow_check = pow_check, .pow_frame = pow_frame, .randomness = randomness, .nonce = nonce, .provider = provider };
        return @ptrCast(storage_value);
    }

    pub fn view(self: *const OwnedV1) View {
        const value: *const Storage = @ptrCast(@alignCast(self));
        return value.rows;
    }

    pub fn deinit(self: *OwnedV1) void {
        const value: *Storage = @ptrCast(@alignCast(self));
        const allocator = value.arena.child_allocator;
        value.arena.deinit();
        allocator.destroy(value);
    }
};

pub fn testFromVerifiedChild(allocator: std.mem.Allocator, child: anytype) !void {
    const prefix = try prefix_mod.OwnedV1.init(allocator, child, 1);
    defer prefix.deinit();
    const owner = try OwnedV1.init(allocator, child, prefix, 1);
    defer owner.deinit();
    const view = owner.view();
    var ledger = air.relation_interaction.TupleLedger.init(allocator);
    defer ledger.deinit();
    const checks = @import("transcript_row_checks_v1.zig");
    try checks.checkRows(0, air.control, view.control, &ledger);
    try checks.checkRows(1, air.transcript_air, view.sponge, &ledger);
    try checks.checkRows(2, air.transcript_binding, view.binding, &ledger);
    try checks.checkRows(3, air.transcript_state, view.state, &ledger);
    try checks.checkRows(4, air.transcript_word, view.word, &ledger);
    try checks.checkRows(5, air.transcript_payload, view.payload, &ledger);
    try checks.checkRows(6, air.pow_check, view.pow_check, &ledger);
    try checks.checkRows(7, air.pow_frame, view.pow_frame, &ledger);
    try checks.checkRows(9, air.verifier_randomness, view.randomness, &ledger);
    try checks.checkRows(12, air.field_statement_word_v3, view.nonce, &ledger);
    try std.testing.expectEqual(child.recordingView().trace.poseidon_calls.len, prefix.view().provider.len + view.provider.len);
    var sampled_words: usize = 0;
    for (view.payload) |payload| if (payload.preprocessing.source_kind == .sampled_value) {
        try std.testing.expectEqual(@as(u32, 2), payload.preprocessing.input_use_count);
        sampled_words += 1;
    };
    try std.testing.expectEqual(4 * child.captureView().sampled_values.len, sampled_words);
    std.debug.print("SEGMENT_V2_DETACHED_PCS_ROWS operations={d} provider_calls={d} sampled_words={d} randomness_rows={d} pow_rows={d} parent_proof_verified=false\n", .{
        view.control.len, view.provider.len, sampled_words, view.randomness.len, view.pow_check.len,
    });
}
