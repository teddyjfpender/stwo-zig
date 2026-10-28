//! Key-only transcript frame topology for detached parent rows 2–5 and 8–10.
//! Zero-valued synthetic calls enter only the shared preprocessing builders;
//! no synthetic main column is admitted as a proof witness.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const child_mod = @import("detached_child_views_v1.zig");
const prefix = @import("detached_prefix_preparation_v1.zig");
const suffix = @import("detached_pcs_rows_v1.zig");
const frame_rows = @import("transcript_frame_rows_v1.zig");
const recording = @import("recording_poseidon_channel_v4.zig");
const rows = @import("segment_transcript_outer_source_v2.zig");
const transcript_air = @import("air/transcript_air_witness.zig");
const channel = @import("poseidon2_channel.zig");
const shared_payload = @import("transcript_payload_kind_v1.zig");
const randomness_witness = @import("air/verifier_randomness_witness.zig");

const FrameSpec = struct {
    frame: recording.HashFrame,
    step: frame_rows.Step,
    pow_draw: bool,
    operation_first: bool,
};

pub const OwnedV1 = struct {
    arena: std.heap.ArenaAllocator,
    binding: []rows.TranscriptBindingRowV2,
    state: []rows.TranscriptStateRowV2,
    word: []rows.TranscriptWordRowV2,
    payload: []prefix.PayloadRow,
    prefix_payload_count: usize,
    challenges: []rows.RelationChallengeRowV2,
    randomness: []rows.VerifierRandomnessRowV2,
    nonce: []frame_rows.NonceRow,

    pub fn deinit(self: *OwnedV1) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn init(comptime family: child_mod.Family, allocator: std.mem.Allocator, key: anytype, lane: u32) !OwnedV1 {
        if (lane != 1 and lane != 2) return error.InvalidDetachedPrefixLane;
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const a = arena.allocator();
        const prefix_ops = try prefix.operationsFromKey(family, a, key);
        const prefix_control = try prefix.controlRowsFromOperations(a, prefix_ops, lane);
        const prefix_shape = try prefix.PrefixShape.fromOperations(prefix_ops);
        const pcs_ops = try prefix.initPcsOperationsFromKey(a, key);
        const pcs_control = try suffix.controlRowsFromOperations(a, pcs_ops, lane, prefix_shape.operation_count);
        var specs: std.ArrayList(FrameSpec) = .empty;
        var payload: std.ArrayList(prefix.PayloadRow) = .empty;
        var challenges: std.ArrayList(rows.RelationChallengeRowV2) = .empty;
        var randomness: std.ArrayList(rows.VerifierRandomnessRowV2) = .empty;
        var nonce: std.ArrayList(frame_rows.NonceRow) = .empty;
        var calls: u32 = 0;
        var draw_ordinal: u32 = 0;
        for (prefix_ops, prefix_control) |operation, control| {
            const first_frame = std.math.cast(u32, specs.items.len) orelse return error.ArithmeticOverflow;
            try appendOperation(a, &specs, &calls, &draw_ordinal, operation.effect, operation.payload_words, control);
            if (operation.effect != .pow and operation.effect != .draw)
                try appendPrefixPayload(family, a, &payload, operation, control, first_frame);
            if (operation.effect == .draw)
                try appendChallenge(family, a, &challenges, control);
            if (operation.effect == .pow)
                try appendNonce(a, &nonce, control);
        }
        const prefix_payload_count = payload.items.len;
        for (pcs_ops, pcs_control) |operation, control| {
            const first_frame = std.math.cast(u32, specs.items.len) orelse return error.ArithmeticOverflow;
            try appendOperation(a, &specs, &calls, &draw_ordinal, operation.effect, operation.payload_words, control);
            try appendPcsPayload(a, &payload, operation, control, first_frame);
            if (operation.effect == .draw)
                try appendRandomness(a, &randomness, operation, control);
            if (operation.effect == .pow)
                try appendNonce(a, &nonce, control);
        }

        const frames = try a.alloc(recording.HashFrame, specs.items.len);
        for (frames, specs.items) |*frame, spec| frame.* = spec.frame;
        const binding = try a.alloc(rows.TranscriptBindingRowV2, calls);
        const state = try a.alloc(rows.TranscriptStateRowV2, frames.len);
        const word_count = try std.math.mul(usize, @as(usize, calls) - frames.len, recording.RATE);
        const word = try a.alloc(rows.TranscriptWordRowV2, word_count);
        var binding_at: usize = 0;
        var word_at: usize = 0;
        var mix_ordinal: u32 = 0;
        const zero_state: [recording.WIDTH]M31 = @splat(M31.zero());
        for (specs.items, frames, state) |spec, frame, *state_row| {
            state_row.* = frame_rows.state(spec.step, frames, @intCast(frame.hash_id), mix_ordinal, spec.pow_draw);
            mix_ordinal += @intFromBool(frame.purpose == .mix);
            for (0..frame.call_count) |local| {
                const call = recording.PoseidonCall{
                    .id = .{ .call_id = frame.first_call_id + @as(u32, @intCast(local)), .hash_id = frame.hash_id, .step = @intCast(local) },
                    .input = zero_state,
                    .output = zero_state,
                };
                const air_row = transcript_air.rowFromCall(lane, frame, call, zero_state);
                binding[binding_at] = frame_rows.binding(spec.step, call.id.call_id, frame, call, air_row, spec.operation_first, spec.pow_draw);
                binding_at += 1;
            }
            for (recording.RATE..@as(usize, frame.call_count) * recording.RATE) |index| {
                word[word_at] = frame_rows.word(spec.step, frame, @intCast(index));
                word_at += 1;
            }
        }
        std.debug.assert(binding_at == binding.len and word_at == word.len);
        return .{
            .arena = arena,
            .binding = binding,
            .state = state,
            .word = word,
            .payload = try payload.toOwnedSlice(a),
            .prefix_payload_count = prefix_payload_count,
            .challenges = try challenges.toOwnedSlice(a),
            .randomness = try randomness.toOwnedSlice(a),
            .nonce = try nonce.toOwnedSlice(a),
        };
    }
};

fn appendChallenge(comptime family: child_mod.Family, allocator: std.mem.Allocator, destination: *std.ArrayList(rows.RelationChallengeRowV2), control: @import("air/control_witness.zig").Row) !void {
    const challenge = std.math.cast(u32, destination.items.len) orelse return error.ArithmeticOverflow;
    try destination.append(allocator, .{ .preprocessing = .{
        .row_mask = 1,
        .segment_mask = 0,
        .binary_mask = 1,
        .public_logup_mask = @intFromBool(prefix.boundaryChallengeFor(family, challenge)),
        .verifier_id = control.verifier_id,
        .sequence = control.sequence,
        .tag = control.tag,
        .args = control.args,
        .challenge = challenge,
    }, .main = .{ .enabler = 1, .outputs = @splat(M31.zero()) } });
}

fn appendRandomness(allocator: std.mem.Allocator, destination: *std.ArrayList(rows.VerifierRandomnessRowV2), operation: @import("pcs_transcript_program_v1.zig").Operation, control: @import("air/control_witness.zig").Row) !void {
    const kind: randomness_witness.Kind = switch (operation.draw) {
        .composition => .composition_randomness,
        .oods => .oods_point,
        .deep => .deep_randomness,
        .fri_alpha => .fri_alpha,
        .queries => .raw_query,
        else => return error.DetachedPcsScheduleMismatch,
    };
    var multiplicities: [8]u32 = undefined;
    for (&multiplicities, 0..) |*value, at|
        value.* = kind.semanticUseCount() * @intFromBool(at < operation.draw_word_count);
    try destination.append(allocator, .{ .preprocessing = .{
        .row_mask = 1,
        .segment_mask = 0,
        .binary_mask = 1,
        .verifier_id = control.verifier_id,
        .sequence = control.sequence,
        .tag = control.tag,
        .args = control.args,
        .kind = kind,
        .item_base = operation.item,
        .query_items = @intFromBool(operation.draw == .queries),
        .multiplicities = multiplicities,
        .draw_index = std.math.cast(u32, destination.items.len) orelse return error.ArithmeticOverflow,
    }, .main = .{ .enabler = 1, .outputs = @splat(M31.zero()) } });
}

fn appendNonce(allocator: std.mem.Allocator, destination: *std.ArrayList(frame_rows.NonceRow), control: @import("air/control_witness.zig").Row) !void {
    const step = frame_rows.Step{ .verifier_id = control.verifier_id, .sequence = control.sequence, .tag = control.tag, .args = control.args };
    const zero_limbs: [4]M31 = @splat(M31.zero());
    const pair = try frame_rows.nonceRows(step, &zero_limbs);
    try destination.appendSlice(allocator, &pair);
}

fn appendPrefixPayload(comptime family: child_mod.Family, allocator: std.mem.Allocator, destination: *std.ArrayList(prefix.PayloadRow), operation: prefix.Operation, control: @import("air/control_witness.zig").Row, hash_id: u32) !void {
    if (operation.source.fixed() and operation.payload_words > operation.constant_words.len)
        return error.DetachedPrefixScheduleMismatch;
    for (0..operation.payload_words) |index| {
        const position: u32 = @intCast(index);
        const coordinate = prefix.inputCoordinateFor(family, operation.source, position) orelse
            return error.DetachedPrefixScheduleMismatch;
        const fixed = operation.source.fixed();
        const constant = if (fixed) operation.constant_words[index] else 0;
        try destination.append(allocator, .{ .preprocessing = .{
            .row_mask = 1,
            .segment_mask = 0,
            .binary_mask = 1,
            .verifier_id = control.verifier_id,
            .sequence = control.sequence,
            .tag = control.tag,
            .args = control.args,
            .payload_index = position,
            .source_kind = coordinate.kind,
            .item_index = coordinate.item,
            .limb_index = coordinate.limb,
            .constant_mask = @intFromBool(fixed),
            .input_use_count = coordinate.uses,
            .constant_value = constant,
            .source_hash_id = hash_id,
            .source_word_index = std.math.add(u32, @intCast(recording.RATE), position) catch return error.ArithmeticOverflow,
        }, .value = M31.fromCanonical(constant) });
    }
}

fn appendPcsPayload(allocator: std.mem.Allocator, destination: *std.ArrayList(prefix.PayloadRow), operation: @import("pcs_transcript_program_v1.zig").Operation, control: @import("air/control_witness.zig").Row, hash_id: u32) !void {
    const kind = shared_payload.payloadKind(operation.source) orelse return;
    const width: u32 = if (kind == .commitment or kind == .fri_commitment) 8 else 4;
    for (0..operation.payload_words) |index| {
        const position: u32 = @intCast(index);
        try destination.append(allocator, .{ .preprocessing = .{
            .row_mask = 1,
            .segment_mask = 0,
            .binary_mask = 1,
            .verifier_id = control.verifier_id,
            .sequence = control.sequence,
            .tag = control.tag,
            .args = control.args,
            .payload_index = position,
            .source_kind = kind,
            .item_index = try std.math.add(u32, operation.item, position / width),
            .limb_index = position % width,
            .constant_mask = 0,
            .input_use_count = if (kind == .sampled_value) 2 else 1,
            .constant_value = 0,
            .source_hash_id = hash_id,
            .source_word_index = std.math.add(u32, @intCast(recording.RATE), position) catch return error.ArithmeticOverflow,
        }, .value = M31.zero() });
    }
}

fn appendOperation(allocator: std.mem.Allocator, specs: *std.ArrayList(FrameSpec), call_at: *u32, draw_ordinal: *u32, effect: recording.Effect, payload_words: u32, control: @import("air/control_witness.zig").Row) !void {
    const is_pow = effect == .pow;
    const parts: usize = if (is_pow) 2 else 1;
    for (0..parts) |part| {
        const draw = effect == .draw or (is_pow and part == 1);
        const words_count = try std.math.add(usize, recording.RATE, if (draw) 2 else payload_words);
        const words = try allocator.alloc(M31, words_count);
        @memset(words, M31.zero());
        if (draw) {
            if (draw_ordinal.* >= @import("stwo_core").fields.m31.Modulus) return error.ArithmeticOverflow;
            words[recording.RATE] = M31.fromCanonical(draw_ordinal.*);
            words[recording.RATE + 1] = M31.fromCanonical(channel.DRAW_TAG);
            // The PoW check draws on a copied channel. It proves the nonce
            // without advancing the real transcript's draw counter.
            if (!(is_pow and part == 1))
                draw_ordinal.* = try std.math.add(u32, draw_ordinal.*, 1);
        } else {
            draw_ordinal.* = 0;
        }
        const count = std.math.cast(u32, words_count / recording.RATE + 1) orelse return error.ArithmeticOverflow;
        const hash_id = std.math.cast(u32, specs.items.len) orelse return error.ArithmeticOverflow;
        try specs.append(allocator, .{
            .frame = .{
                .hash_id = hash_id,
                .first_call_id = call_at.*,
                .call_count = count,
                .purpose = if (draw) .draw else .mix,
                .words = words,
                .output = @splat(M31.zero()),
            },
            .step = .{ .verifier_id = control.verifier_id, .sequence = control.sequence, .tag = control.tag, .args = control.args },
            .pow_draw = is_pow and part == 1,
            .operation_first = part == 0,
        });
        call_at.* = try std.math.add(u32, call_at.*, count);
    }
}

pub fn testAgainstVerifiedChild(allocator: std.mem.Allocator, child: anytype) !void {
    const family = @typeInfo(@TypeOf(child)).pointer.child.FAMILY;
    var fixed = try OwnedV1.init(family, allocator, child.key(), 1);
    defer fixed.deinit();
    const head = try prefix.OwnedV1.init(allocator, child, 1);
    defer head.deinit();
    const tail = try suffix.OwnedV1.init(allocator, child, head, 1);
    defer tail.deinit();
    inline for (.{ "binding", "state", "word", "payload" }) |field| {
        const first = @field(head.view(), field);
        const second = @field(tail.view(), field);
        const reconstructed = @field(fixed, field);
        try std.testing.expectEqual(first.len + second.len, reconstructed.len);
        for (first, reconstructed[0..first.len], 0..) |actual, expected, index| {
            if (!std.meta.eql(actual.preprocessing, expected.preprocessing))
                std.debug.print("KEY_FIXED_TRANSCRIPT_MISMATCH field={s} lane=prefix index={d} actual={any} rebuilt={any}\n", .{ field, index, actual.preprocessing, expected.preprocessing });
            try std.testing.expectEqualDeep(actual.preprocessing, expected.preprocessing);
        }
        for (second, reconstructed[first.len..], 0..) |actual, expected, index| {
            if (!std.meta.eql(actual.preprocessing, expected.preprocessing))
                std.debug.print("KEY_FIXED_TRANSCRIPT_MISMATCH field={s} lane=pcs index={d} actual={any} rebuilt={any}\n", .{ field, index, actual.preprocessing, expected.preprocessing });
            try std.testing.expectEqualDeep(actual.preprocessing, expected.preprocessing);
        }
    }
    try std.testing.expectEqualDeep(head.view().challenges.len, fixed.challenges.len);
    for (head.view().challenges, fixed.challenges) |actual, expected|
        try std.testing.expectEqualDeep(actual.preprocessing, expected.preprocessing);
    try std.testing.expectEqualDeep(tail.view().randomness.len, fixed.randomness.len);
    for (tail.view().randomness, fixed.randomness) |actual, expected|
        try std.testing.expectEqualDeep(actual.preprocessing, expected.preprocessing);
    const nonce_main = @import("air/field_statement_word_v3.zig").PHYSICAL_MAIN_COLUMN_COUNT;
    const actual_nonce_len = head.view().nonce.len + tail.view().nonce.len;
    try std.testing.expectEqual(actual_nonce_len, fixed.nonce.len);
    for (head.view().nonce, fixed.nonce[0..head.view().nonce.len]) |actual, expected|
        try std.testing.expectEqualSlices(M31, actual[nonce_main..], expected[nonce_main..]);
    for (tail.view().nonce, fixed.nonce[head.view().nonce.len..]) |actual, expected|
        try std.testing.expectEqualSlices(M31, actual[nonce_main..], expected[nonce_main..]);
}
