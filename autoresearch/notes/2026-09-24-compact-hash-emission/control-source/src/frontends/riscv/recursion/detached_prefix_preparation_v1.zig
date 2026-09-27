//! SD child prefix rows for an explicitly admitted detached-parent profile.
//! The shared verifier transcript emits the schedule; recorded payload values
//! never select constants. Dynamic exports remain obligations of the parent's
//! expected-boundary/composition AIRs until their exact lookup closure passes.
const recursion = struct {
    const pcs_transcript_program_v1 = @import("pcs_transcript_program_v1.zig");
    const poseidon2_channel = @import("poseidon2_channel.zig");
    const recording_poseidon_channel_v4 = @import("recording_poseidon_channel_v4.zig");
    const recursion_air_composition_circuit_v3 = @import("recursion_air_composition_circuit_v3.zig");
    const segment_leaf_authority_v2 = @import("segment_leaf_authority_v2.zig");
    const segment_transcript_outer_source_v2 = @import("segment_transcript_outer_source_v2.zig");
};
const air = struct {
    const control_witness = @import("air/control_witness.zig");
    const field_statement_word_v3 = @import("air/field_statement_word_v3.zig");
    const pow_check = @import("air/pow_check.zig");
    const pow_check_witness = @import("air/pow_check_witness.zig");
    const pow_frame = @import("air/pow_frame.zig");
    const pow_frame_witness = @import("air/pow_frame_witness.zig");
    const relation_challenge_witness = @import("air/relation_challenge_witness.zig");
    const transcript_air_witness = @import("air/transcript_air_witness.zig");
    const transcript_payload = @import("air/transcript_payload.zig");
    const transcript_payload_relation = @import("air/transcript_payload_relation.zig");
    const transcript_payload_witness = @import("air/transcript_payload_witness.zig");
    const universal_challenges = @import("air/universal_challenges.zig");
};
const std = @import("std");
const relation = @import("../air/lang/relation.zig");

const core = @import("stwo_core");
const recording = recursion.recording_poseidon_channel_v4;
const transcript = @import("detached_segment_protocol_v1.zig");
const child_mod = @import("detached_child_views_v1.zig");
const frame_rows = @import("transcript_frame_rows_v1.zig");
const rows = recursion.segment_transcript_outer_source_v2;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Digest = recursion.poseidon2_channel.Digest;
const Kind = air.transcript_payload.VerifierInputKind;
const universal = air.universal_challenges;
const v3 = recursion.recursion_air_composition_circuit_v3;
pub const VERSION: u16 = 1;
pub const RAW_WIRE_BASE: u32 = 0x10000;
pub const WIRE_ID_BASE: u32 = 0x20000;
pub const BOUNDARY_CLAIM_INDEX: u32 = v3.COMPOSITION_CLAIM_INPUT_COUNT;
pub const BOUNDARY_CHALLENGE_SCOPE = air.relation_challenge_witness.VM_PUBLIC_LOGUP_CHALLENGE_SCOPE;
const STEP_TAG_BASE: u32 = 0x5344_0000;

pub const PayloadSource = enum(u8) {
    tree0,
    tree1,
    admission_header,
    key_identity,
    public_frame,
    wire_id,
    wire,
    relations,
    claims_header,
    claims,
    boundary_header,
    boundary,
    partials,
    tree2,
    span_u32,
    interaction_pow,
    pub fn fixed(self: PayloadSource) bool {
        return switch (self) {
            .tree0, .admission_header, .key_identity, .public_frame, .claims_header, .boundary_header => true,
            else => false,
        };
    }
};
pub const Operation = struct {
    source: PayloadSource,
    effect: recording.Effect,
    item: u32 = 0,
    payload_words: u32 = 0,
    pow_bits: u32 = 0,
    constant_words: [16]u32 = @splat(0),
};
pub const InputCoordinate = struct { kind: Kind, item: u32, limb: u32, uses: u32 };

/// One authority for transcript payload fan-out. The boundary graph consumes
/// wire/digest exports once and emits its canonical Span projection separately.
pub fn inputCoordinate(source: PayloadSource, word: u32) ?InputCoordinate {
    return inputCoordinateFor(.segment, source, word);
}
pub fn inputCoordinateFor(comptime family: child_mod.Family, source: PayloadSource, word: u32) ?InputCoordinate {
    return switch (source) {
        .tree0, .tree1, .tree2 => .{ .kind = .commitment, .item = switch (source) {
            .tree0 => 0,
            .tree1 => 1,
            else => 2,
        }, .limb = word, .uses = 1 },
        .wire => .{ .kind = .statement, .item = RAW_WIRE_BASE + word, .limb = 0, .uses = 1 },
        .span_u32 => .{ .kind = .statement, .item = RAW_WIRE_BASE + word / 2, .limb = word % 2, .uses = 1 },
        .wire_id => .{ .kind = .statement, .item = WIRE_ID_BASE + word / 2, .limb = word % 2, .uses = 1 },
        .claims => .{ .kind = .claimed_sum, .item = word / 4, .limb = word % 4, .uses = if (family == .segment and word / 4 == 36) 2 else 1 },
        .boundary => .{ .kind = .claimed_sum, .item = BOUNDARY_CLAIM_INDEX, .limb = word, .uses = 2 },
        .partials => .{ .kind = .claimed_sum, .item = @intCast(v3.POSEIDON_AUX_START + word / 4), .limb = word % 4, .uses = 1 },
        .relations, .interaction_pow => null,
        else => .{ .kind = .protocol, .item = 0, .limb = word, .uses = 0 },
    };
}
pub fn boundaryChallenge(challenge: usize) bool {
    return boundaryChallengeFor(.segment, challenge);
}
pub fn boundaryChallengeFor(comptime family: child_mod.Family, challenge: usize) bool {
    if (family == .parent) return challenge == @intFromEnum(relation.Domain.recursion_statement_word);
    return challenge == @intFromEnum(recursion.segment_leaf_authority_v2.STATEMENT_RELATION_DOMAIN) or challenge == @intFromEnum(relation.Domain.recursion_wire);
}

/// The admitted child owns verified geometry. Reuse the secure recursive
/// program's PCS emitter so the detached suffix cannot grow a parallel order.
pub fn initPcsOperations(allocator: std.mem.Allocator, child: anytype) ![]recursion.pcs_transcript_program_v1.Operation {
    const captured = child.captureView();
    return recursion.pcs_transcript_program_v1.initPcsOperations(allocator, .{
        .sampled_value_count = captured.sampled_values.len,
        .fri_layer_count = captured.fri_layer_count,
        .last_layer_coefficient_count = captured.last_layer_coefficients.len,
        .query_count = child.key().pcs_config.fri_config.n_queries,
        .pow_bits = child.key().pcs_config.pow_bits,
    });
}

pub const PayloadRow = struct { preprocessing: air.transcript_payload_witness.Row, value: M31 };
pub const View = struct {
    operations: []const Operation,
    control: []const air.control_witness.Row,
    sponge: []const rows.TranscriptAirRowV2,
    binding: []const rows.TranscriptBindingRowV2,
    state: []const rows.TranscriptStateRowV2,
    word: []const rows.TranscriptWordRowV2,
    payload: []const PayloadRow,
    challenges: []const rows.RelationChallengeRowV2,
    pow_check: []const air.pow_check_witness.RelationRow,
    pow_frame: []const air.pow_frame_witness.RelationRow,
    nonce: []const frame_rows.NonceRow,
    provider: []const rows.ProviderCall,
    next_operation: u32,
    next_hash: u32,
    next_call: u32,
};

pub const OwnedV1 = opaque {
    const Storage = struct {
        allocator: std.mem.Allocator,
        operations: []Operation,
        control: []air.control_witness.Row,
        sponge: []rows.TranscriptAirRowV2,
        binding: []rows.TranscriptBindingRowV2,
        state: []rows.TranscriptStateRowV2,
        word: []rows.TranscriptWordRowV2,
        payload: []PayloadRow,
        challenges: []rows.RelationChallengeRowV2,
        pow_check: []air.pow_check_witness.RelationRow,
        pow_frame: []air.pow_frame_witness.RelationRow,
        nonce: []frame_rows.NonceRow,
        provider: []rows.ProviderCall,
        fn deinit(self: *Storage) void {
            self.allocator.free(self.operations);
            self.allocator.free(self.control);
            self.allocator.free(self.sponge);
            self.allocator.free(self.binding);
            self.allocator.free(self.state);
            self.allocator.free(self.word);
            self.allocator.free(self.payload);
            self.allocator.free(self.challenges);
            self.allocator.free(self.pow_check);
            self.allocator.free(self.pow_frame);
            self.allocator.free(self.nonce);
            self.allocator.free(self.provider);
        }
    };

    pub fn init(allocator: std.mem.Allocator, child: anytype, lane: u32) !*OwnedV1 {
        if (lane != 1 and lane != 2) return error.InvalidDetachedPrefixLane;
        const family = @typeInfo(@TypeOf(child)).pointer.child.FAMILY;
        const Protocol = if (family == .segment) transcript else @import("detached_parent_protocol_v1.zig");
        if (child.expectedWords().len >= WIRE_ID_BASE - RAW_WIRE_BASE) return error.DetachedPrefixWireGeometryOutOfRange;
        var plan = PlanChannel{ .allocator = allocator, .relations = child.relations() };
        defer plan.operations.deinit(allocator);
        const captured = child.captureView();
        try plan.root(.tree0, child.key().preprocessed_root);
        try plan.root(.tree1, captured.commitments[1]);
        try Protocol.mixAdmission(&plan, child.key(), child.expected());
        try Protocol.mixInteractionPow(&plan, child.key(), child.claims().interaction_pow);
        const relations = try universal.UniversalRelations.draw(allocator, &plan);
        try Protocol.mixClaimsAndBoundary(&plan, child.key(), child.expected(), child.claims(), &relations);
        try plan.root(.tree2, captured.commitments[2]);
        if (plan.failure) |err| return err;
        const execution = child.recordingView();
        if (plan.operations.items.len > execution.operations.len) return error.DetachedPrefixScheduleMismatch;
        const operation_count = plan.operations.items.len;
        const last = execution.operations[operation_count - 1];
        const frame_count = @as(usize, last.first_hash_id) + last.hash_count;
        const call_count = @as(usize, last.first_call_id) + last.call_count;
        var payload_count: usize = 0;
        var pow_count: usize = 0;
        for (plan.operations.items) |operation| {
            if (operation.effect == .pow) pow_count += 1 else payload_count += operation.payload_words;
        }
        const operation_values = try plan.operations.toOwnedSlice(allocator);
        errdefer allocator.free(operation_values);
        const control = try allocator.alloc(air.control_witness.Row, operation_count);
        errdefer allocator.free(control);
        const sponge = try allocator.alloc(rows.TranscriptAirRowV2, call_count);
        errdefer allocator.free(sponge);
        const binding = try allocator.alloc(rows.TranscriptBindingRowV2, call_count);
        errdefer allocator.free(binding);
        const state = try allocator.alloc(rows.TranscriptStateRowV2, frame_count);
        errdefer allocator.free(state);
        const word = try allocator.alloc(rows.TranscriptWordRowV2, (call_count - frame_count) * recording.RATE);
        errdefer allocator.free(word);
        const payload = try allocator.alloc(PayloadRow, payload_count);
        errdefer allocator.free(payload);
        const challenges = try allocator.alloc(rows.RelationChallengeRowV2, universal.RELATION_COUNT);
        errdefer allocator.free(challenges);
        const provider = try allocator.alloc(rows.ProviderCall, call_count);
        errdefer allocator.free(provider);
        const pow_check = try allocator.alloc(air.pow_check_witness.RelationRow, pow_count);
        errdefer allocator.free(pow_check);
        const pow_frame = try allocator.alloc(air.pow_frame_witness.RelationRow, pow_count);
        errdefer allocator.free(pow_frame);
        const nonce = try allocator.alloc(frame_rows.NonceRow, 2 * pow_count);
        errdefer allocator.free(nonce);
        var mix_ordinal: u32 = 0;
        var draw_count: u32 = 0;
        var word_at: usize = 0;
        var payload_at: usize = 0;
        var challenge_at: usize = 0;
        var call_at: usize = 0;
        var hash_at: usize = 0;
        var pow_at: usize = 0;
        for (operation_values, execution.operations[0..operation_count], 0..) |instruction, operation, index| {
            const is_pow = instruction.effect == .pow;
            const hash_count: usize = if (is_pow) 2 else 1;
            if (operation.effect != instruction.effect or operation.hash_count != hash_count or
                operation.first_hash_id != hash_at or operation.first_call_id != call_at or
                (operation.pow_check_index != null) != is_pow)
                return error.DetachedPrefixScheduleMismatch;
            const step = frame_rows.Step{
                .verifier_id = lane,
                .sequence = @intCast(index),
                .tag = if (is_pow) air.pow_frame.controlTag(.interaction) else STEP_TAG_BASE + @intFromEnum(instruction.source),
                .args = if (is_pow) .{ instruction.pow_bits, 4, 0, 0 } else .{ @intFromEnum(instruction.effect), instruction.payload_words, instruction.item, VERSION },
            };
            control[index] = .{ .segment_mask = 0, .binary_mask = 1, .verifier_id = lane, .sequence = step.sequence, .tag = step.tag, .args = step.args, .terminal_mask = 0 };
            for (0..hash_count) |part| {
                const frame = execution.trace.hash_frames[hash_at];
                const pow_draw = is_pow and part == 1;
                const draw = instruction.effect == .draw;
                const expected_words = recording.RATE + @as(usize, if (draw or pow_draw) 2 else instruction.payload_words);
                if (frame.hash_id != hash_at or frame.first_call_id != call_at or frame.words.len != expected_words or
                    frame.call_count != expected_words / recording.RATE + 1 or
                    frame.purpose != @as(recording.HashPurpose, if (draw or pow_draw) .draw else .mix))
                    return error.DetachedPrefixScheduleMismatch;
                state[hash_at] = frame_rows.state(step, execution.trace.hash_frames, hash_at, mix_ordinal, pow_draw);
                mix_ordinal += @intFromBool(frame.purpose == .mix);
                if (pow_draw) {
                    if (frame.words[recording.RATE].toU32() != 0 or frame.words[recording.RATE + 1].toU32() != recursion.poseidon2_channel.DRAW_TAG)
                        return error.DetachedPrefixScheduleMismatch;
                    const check = execution.trace.pow_checks[operation.pow_check_index.?];
                    if (check.bits != instruction.pow_bits) return error.DetachedPrefixPowMismatch;
                    pow_check[pow_at] = try air.pow_check_witness.mainRow(.{ .verifier_id = lane, .kind = .interaction, .check = check });
                    pow_frame[pow_at] = try air.pow_frame_witness.mainRow(.{ .verifier_id = lane, .sequence = step.sequence, .kind = .interaction, .hash_id = frame.hash_id, .check = check, .words = frame.output[0..recording.RATE].* });
                    pow_at += 1;
                } else if (draw) {
                    if (frame.words[recording.RATE].toU32() != draw_count or frame.words[recording.RATE + 1].toU32() != recursion.poseidon2_channel.DRAW_TAG or instruction.item != challenge_at)
                        return error.DetachedPrefixScheduleMismatch;
                    draw_count += 1;
                    challenges[challenge_at] = .{ .preprocessing = .{ .row_mask = 1, .segment_mask = 0, .binary_mask = 1, .public_logup_mask = @intFromBool(boundaryChallengeFor(family, challenge_at)), .verifier_id = lane, .sequence = step.sequence, .tag = step.tag, .args = step.args, .challenge = @intCast(challenge_at) }, .main = .{ .enabler = 1, .outputs = frame.output[0..recording.RATE].* } };
                    challenge_at += 1;
                } else {
                    draw_count = 0;
                    if (is_pow) {
                        nonce[2 * pow_at ..][0..2].* = try frame_rows.nonceRows(step, frame.words[recording.RATE..]);
                    } else for (frame.words[recording.RATE..], 0..) |value, offset| {
                        const at: u32 = @intCast(offset);
                        const coordinate = inputCoordinateFor(family, instruction.source, at) orelse return error.DetachedPrefixScheduleMismatch;
                        if (instruction.source.fixed() and value.toU32() != instruction.constant_words[offset]) return error.DetachedPrefixFixedWordMismatch;
                        payload[payload_at] = .{ .preprocessing = .{ .row_mask = 1, .segment_mask = 0, .binary_mask = 1, .verifier_id = lane, .sequence = step.sequence, .tag = step.tag, .args = step.args, .payload_index = at, .source_kind = coordinate.kind, .item_index = coordinate.item, .limb_index = coordinate.limb, .constant_mask = @intFromBool(instruction.source.fixed()), .input_use_count = coordinate.uses, .constant_value = if (instruction.source.fixed()) instruction.constant_words[offset] else 0, .source_hash_id = @intCast(hash_at), .source_word_index = @intCast(recording.RATE + at) }, .value = value };
                        payload_at += 1;
                    }
                }
                for (frame.first_call_id..frame.first_call_id + frame.call_count) |call_index| {
                    const call = execution.trace.poseidon_calls[call_index];
                    const previous = if (call.id.step == 0) [_]M31{M31.zero()} ** recording.WIDTH else execution.trace.poseidon_calls[call_index - 1].output;
                    sponge[call_index] = air.transcript_air_witness.rowFromCall(lane, frame, call, previous);
                    binding[call_index] = frame_rows.binding(step, @intCast(call_index), frame, call, sponge[call_index], part == 0, pow_draw);
                    provider[call_index] = frame_rows.providerCall(call);
                }
                for (recording.RATE..frame.call_count * recording.RATE) |index_in_frame| {
                    word[word_at] = frame_rows.word(step, frame, @intCast(index_in_frame));
                    word_at += 1;
                }
                call_at += frame.call_count;
                hash_at += 1;
            }
        }
        if (pow_at != pow_count or hash_at != frame_count or challenge_at != challenges.len or word_at != word.len or payload_at != payload.len or call_at != call_count) return error.DetachedPrefixScheduleMismatch;
        const value = try allocator.create(Storage);
        value.* = .{ .allocator = allocator, .operations = operation_values, .control = control, .sponge = sponge, .binding = binding, .state = state, .word = word, .payload = payload, .challenges = challenges, .pow_check = pow_check, .pow_frame = pow_frame, .nonce = nonce, .provider = provider };
        return @ptrCast(value);
    }
    fn storage(self: *const OwnedV1) *const Storage {
        return @ptrCast(@alignCast(self));
    }
    pub fn view(self: *const OwnedV1) View {
        const value = self.storage();
        return .{ .operations = value.operations, .control = value.control, .sponge = value.sponge, .binding = value.binding, .state = value.state, .word = value.word, .payload = value.payload, .challenges = value.challenges, .pow_check = value.pow_check, .pow_frame = value.pow_frame, .nonce = value.nonce, .provider = value.provider, .next_operation = @intCast(value.operations.len), .next_hash = @intCast(value.state.len), .next_call = @intCast(value.sponge.len) };
    }
    /// This SD-only mapping consumes internally admitted immutable rows. The
    /// legacy witness mapper intentionally keeps its old statement namespace
    /// and multiplicities; it is not widened for this new parent profile.
    pub fn payloadLogical(self: *const OwnedV1, index: usize) [air.transcript_payload.LOGICAL_INPUT_COUNT]M31 {
        const row = self.storage().payload[index];
        return .{ M31.one(), row.value } ++ row.preprocessing.values() ++ .{ M31.zero(), M31.one() };
    }
    pub fn deinit(self: *OwnedV1) void {
        const value: *Storage = @ptrCast(@alignCast(self));
        const allocator = value.allocator;
        value.deinit();
        allocator.destroy(value);
    }
};

/// Receives semantic labels from the shared SD emitter. Only fixed labels may
/// retain emitted values; all other operation metadata consists of dimensions.
const PlanChannel = struct {
    allocator: std.mem.Allocator,
    relations: *const universal.UniversalRelations,
    operations: std.ArrayList(Operation) = .empty,
    source: transcript.PayloadSourceV1 = .admission_header,
    failure: ?anyerror = null,
    pending_pow_bits: ?u32 = null,
    pub fn beginDetachedPayload(self: *PlanChannel, source: transcript.PayloadSourceV1) void {
        self.source = source;
    }
    fn append(self: *PlanChannel, operation: Operation) void {
        if (self.failure != null) return;
        self.operations.append(self.allocator, operation) catch |err| {
            self.failure = err;
        };
    }
    fn root(self: *PlanChannel, source: PayloadSource, root_value: Digest) !void {
        var operation = Operation{ .source = source, .effect = .mix, .payload_words = 8 };
        if (source.fixed()) @memcpy(operation.constant_words[0..8], &root_value);
        self.append(operation);
        if (self.failure) |err| return err;
    }
    pub fn verifyPowNonce(self: *PlanChannel, bits: u32, _: u64) bool {
        if (self.pending_pow_bits != null) {
            self.failure = error.DetachedPrefixScheduleMismatch;
            return false;
        }
        self.pending_pow_bits = bits;
        return true;
    }
    pub fn mixU64(self: *PlanChannel, _: u64) void {
        const bits = self.pending_pow_bits orelse {
            self.failure = error.DetachedPrefixScheduleMismatch;
            return;
        };
        self.pending_pow_bits = null;
        self.append(.{ .source = .interaction_pow, .effect = .pow, .payload_words = 4, .pow_bits = bits });
    }
    pub fn mixU32s(self: *PlanChannel, values: []const u32) void {
        const source: PayloadSource = switch (self.source) {
            .admission_header => .admission_header,
            .key_identity => .key_identity,
            .expected => if (values.len == 4) .public_frame else if (values.len == 8) .wire_id else {
                self.failure = error.DetachedPrefixScheduleMismatch;
                return;
            },
            .expected_u32 => .span_u32,
            .claims_header => .claims_header,
            .boundary_header => .boundary_header,
            else => {
                self.failure = error.DetachedPrefixScheduleMismatch;
                return;
            },
        };
        var operation = Operation{ .source = source, .effect = .mix, .payload_words = std.math.cast(u32, values.len * 2) orelse {
            self.failure = error.ArithmeticOverflow;
            return;
        } };
        if (source.fixed()) {
            if (operation.payload_words > operation.constant_words.len) {
                self.failure = error.DetachedPrefixScheduleMismatch;
                return;
            }
            for (values, 0..) |value, index| {
                operation.constant_words[2 * index] = value & 0xffff;
                operation.constant_words[2 * index + 1] = value >> 16;
            }
        }
        self.append(operation);
    }
    pub fn mixCanonicalM31Words(self: *PlanChannel, values: []const M31) void {
        if (self.source != .expected) {
            self.failure = error.DetachedPrefixScheduleMismatch;
            return;
        }
        self.append(.{ .source = .wire, .effect = .mix, .payload_words = std.math.cast(u32, values.len) orelse {
            self.failure = error.ArithmeticOverflow;
            return;
        } });
    }
    pub fn mixFelts(self: *PlanChannel, values: []const QM31) void {
        const source: PayloadSource = switch (self.source) {
            .claims => .claims,
            .boundary => .boundary,
            .partials => .partials,
            else => {
                self.failure = error.DetachedPrefixScheduleMismatch;
                return;
            },
        };
        self.append(.{ .source = source, .effect = .mix, .payload_words = std.math.cast(u32, values.len * 4) orelse {
            self.failure = error.ArithmeticOverflow;
            return;
        } });
    }
    pub fn drawSecureFelts(self: *PlanChannel, allocator: std.mem.Allocator, count: usize) ![]QM31 {
        if (count != universal.DRAW_COUNT) return error.DetachedPrefixScheduleMismatch;
        const result = try allocator.alloc(QM31, count);
        errdefer allocator.free(result);
        for (self.relations.elements, 0..) |element, index| {
            result[2 * index] = element.z;
            result[2 * index + 1] = element.alpha;
            self.append(.{ .source = .relations, .effect = .draw, .item = @intCast(index) });
        }
        if (self.failure) |err| return err;
        return result;
    }
};

pub fn testFromVerifiedChild(allocator: std.mem.Allocator, child: anytype) !void {
    const owner = try OwnedV1.init(allocator, child, 1);
    defer owner.deinit();
    const view = owner.view();
    if (child.key().profile.interactionPowBits() > 0) {
        const check = @import("detached_pcs_preparation_v1.zig").checkLogicalRows;
        try std.testing.expectEqual(@as(usize, 1), view.pow_check.len);
        try std.testing.expectEqual(@as(usize, 1), view.pow_frame.len);
        try std.testing.expectEqual(@as(usize, 2), view.nonce.len);
        try check(allocator, air.pow_check, view.pow_check);
        try check(allocator, air.pow_frame, view.pow_frame);
        try check(allocator, air.field_statement_word_v3, view.nonce);
        // Keep the word and its bit decomposition consistent while violating
        // the admitted low-bit work threshold. The AIR itself must reject.
        var invalid = view.pow_check[0];
        try std.testing.expect(invalid[6].isZero());
        invalid[5] = invalid[5].add(M31.one());
        invalid[6] = M31.one();
        try std.testing.expectError(error.DetachedPcsConstraintMismatch, check(allocator, air.pow_check, &.{invalid}));
    }
    var definition = try air.transcript_payload.build(allocator);
    defer definition.deinit();
    const plan = try air.transcript_payload_relation.authenticate(&definition);
    var fixed: usize = 0;
    var dynamic: usize = 0;
    var uses: usize = 0;
    var wire_words: usize = 0;
    var wire_id_words: usize = 0;
    var claim_words: usize = 0;
    var boundary_words: usize = 0;
    var partial_words: usize = 0;
    for (view.payload, 0..) |payload, index| {
        const row = payload.preprocessing;
        const operation = view.operations[row.sequence];
        const coordinate = inputCoordinate(operation.source, row.payload_index).?;
        try std.testing.expectEqual(coordinate.uses, row.input_use_count);
        try std.testing.expectEqual(@intFromBool(operation.source.fixed()), row.constant_mask);
        if (operation.source.fixed()) {
            fixed += 1;
            try std.testing.expectEqual(operation.constant_words[row.payload_index], payload.value.toU32());
        } else {
            dynamic += 1;
            try std.testing.expectEqual(@as(u32, 0), row.constant_value);
            try std.testing.expect(std.mem.allEqual(u32, &operation.constant_words, 0));
        }
        const entries = try plan.entries(&definition.arena, air.transcript_payload.SEMANTIC_DIGEST, definition.events.ordered(), owner.payloadLogical(index));
        try std.testing.expect(entries[0].numerator.eql(QM31.one()));
        try std.testing.expect(entries[1].numerator.eql(QM31.fromBase(M31.fromCanonical(coordinate.uses))));
        try std.testing.expectEqualSlices(QM31, &.{ QM31.fromU32Unchecked(1, 0, 0, 0), QM31.fromU32Unchecked(@intFromEnum(coordinate.kind), 0, 0, 0), QM31.fromU32Unchecked(coordinate.item, 0, 0, 0), QM31.fromU32Unchecked(coordinate.limb, 0, 0, 0), QM31.fromBase(payload.value) }, entries[1].values[0..5]);
        uses += coordinate.uses;
        switch (operation.source) {
            .wire => wire_words += 1,
            .wire_id => wire_id_words += 1,
            .claims => claim_words += 1,
            .boundary => boundary_words += 1,
            .partials => partial_words += 1,
            else => {},
        }
    }
    try std.testing.expectEqual(child.expected().words().len, wire_words);
    try std.testing.expectEqual(@as(usize, 16), wire_id_words);
    try std.testing.expectEqual(@as(usize, 39 * 4), claim_words);
    try std.testing.expectEqual(@as(usize, 4), boundary_words);
    try std.testing.expectEqual(@as(usize, 8), partial_words);
    var public_challenges: usize = 0;
    for (view.challenges, 0..) |challenge, index| {
        try std.testing.expectEqual(@intFromBool(boundaryChallenge(index)), challenge.preprocessing.public_logup_mask);
        public_challenges += challenge.preprocessing.public_logup_mask;
    }
    try std.testing.expectEqual(@as(usize, 2), public_challenges);
    try std.testing.expectEqual(view.sponge.len, view.provider.len);
    const recording_view = child.recordingView();
    try std.testing.expectEqual(@as(u32, @intCast(view.operations.len)), view.next_operation);
    try std.testing.expectEqual(recording_view.operations[view.next_operation].first_hash_id, view.next_hash);
    try std.testing.expectEqual(recording_view.operations[view.next_operation].first_call_id, view.next_call);
    const suffix = try initPcsOperations(allocator, child);
    defer allocator.free(suffix);
    const suffix_capture = recording_view.operations[view.next_operation..];
    try std.testing.expectEqual(suffix_capture.len, suffix.len);
    var hash_at: usize = view.next_hash;
    var call_at: usize = view.next_call;
    for (suffix, suffix_capture) |expected, actual| {
        try std.testing.expectEqual(expected.effect, actual.effect);
        try std.testing.expectEqual(hash_at, actual.first_hash_id);
        try std.testing.expectEqual(call_at, actual.first_call_id);
        const is_pow = expected.effect == .pow;
        const hash_count: usize = if (is_pow) 2 else 1;
        try std.testing.expectEqual(hash_count, actual.hash_count);
        for (0..hash_count) |part| {
            const draw = expected.effect == .draw or (is_pow and part == 1);
            const word_count = recording.RATE + @as(usize, if (draw) 2 else expected.payload_words);
            const frame = recording_view.trace.hash_frames[hash_at];
            try std.testing.expectEqual(word_count, frame.words.len);
            try std.testing.expectEqual(word_count / recording.RATE + 1, frame.call_count);
            try std.testing.expectEqual(@as(recording.HashPurpose, if (draw) .draw else .mix), frame.purpose);
            try std.testing.expect(std.mem.allEqual(u32, &expected.constant_words, 0));
            call_at += frame.call_count;
            hash_at += 1;
        }
    }
    try std.testing.expectEqual(recording_view.trace.hash_frames.len, hash_at);
    try std.testing.expectEqual(recording_view.trace.poseidon_calls.len, call_at);
    std.debug.print("SEGMENT_V2_DETACHED_PREFIX operations={d} calls={d} payload_fixed={d} payload_dynamic={d} input_uses={d} boundary_challenges={d} parent_proof_verified=false\n", .{ view.operations.len, view.provider.len, fixed, dynamic, uses, public_challenges });
    std.debug.print("SEGMENT_V2_DETACHED_PCS_SCHEDULE operations={d} shared_secure_emitter=true\n", .{suffix.len});
}
