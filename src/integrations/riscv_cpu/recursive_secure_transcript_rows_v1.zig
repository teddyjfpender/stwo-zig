//! Program-derived transcript and statement rows (common-fold rows 0--9, 12).
//! These rows expose payload and semantic challenge lookup obligations. They are not
//! a complete child verifier: the semantic producers/consumers must join them.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const frontend = @import("stwo_riscv_frontend");
const recursion = frontend.recursion;
const air = recursion.air;
const recording = recursion.recording_poseidon_channel_v4;
const source = recursion.segment_transcript_outer_source_v2;
const program_mod = @import("recursive_secure_transcript_program_v1.zig");
pub const catalog = @import("recursive_common_fold_catalog_v3.zig");
const public = @import("recursive_field_node_public_v2.zig");
const public_hash = @import("recursive_common_fold_public_hash_v3.zig");
const StatementRow = [air.field_statement_word_v3.LOGICAL_INPUT_COUNT]M31;
const frame_rows = @import("recursive_transcript_frame_rows_v1.zig");

// Separate from the suffix verifier's existing step tags 1--28.
const STEP_TAG_BASE: u32 = 0x5354_0000;

const PayloadRow = struct {
    preprocessing: air.transcript_payload_witness.Row,
    value: M31,
};

/// Dimension-independent borrow of a cold owner's transcript witness. The
/// parent supplies its lane; row construction validates the retained contents.
pub const View = struct {
    program: *const program_mod.Program,
    execution: *const recording.ExecutionV4,

    pub fn prepareTranscriptRows(self: View, allocator: std.mem.Allocator, verifier_id: u32) !Rows {
        return Rows.init(allocator, verifier_id, self.program, self.execution);
    }
};

pub const Rows = struct {
    allocator: std.mem.Allocator,
    program_identity: [32]u8,
    physical_claim_count: u32,
    control: []air.control_witness.Row,
    sponge: []source.TranscriptAirRowV2,
    binding: []source.TranscriptBindingRowV2,
    state: []source.TranscriptStateRowV2,
    word: []source.TranscriptWordRowV2,
    payload: []PayloadRow,
    provider: []source.ProviderCall,
    pow_check: []air.pow_check_witness.RelationRow,
    pow_frame: []air.pow_frame_witness.RelationRow,
    challenges: []source.RelationChallengeRowV2,
    randomness: []source.VerifierRandomnessRowV2,
    statement: []StatementRow,

    pub fn init(allocator: std.mem.Allocator, verifier_id: u32, program: *const program_mod.Program, execution: *const recording.ExecutionV4) !Rows {
        if (verifier_id != 1 and verifier_id != 2) return error.InvalidRecursiveTranscriptLane;
        try program.validateRecording(execution);
        const physical_claim_count = try physicalClaimCount(program);
        const control = try allocator.alloc(air.control_witness.Row, program.operations.len);
        errdefer allocator.free(control);
        const sponge = try allocator.alloc(source.TranscriptAirRowV2, execution.poseidon_calls.len);
        errdefer allocator.free(sponge);
        const binding = try allocator.alloc(source.TranscriptBindingRowV2, sponge.len);
        errdefer allocator.free(binding);
        const state = try allocator.alloc(source.TranscriptStateRowV2, execution.hash_frames.len);
        errdefer allocator.free(state);
        const word_count = try std.math.mul(usize, sponge.len - state.len, recording.RATE);
        const word = try allocator.alloc(source.TranscriptWordRowV2, word_count);
        errdefer allocator.free(word);
        var payload_count: usize = 0;
        for (program.operations) |instruction| if (payloadKind(instruction.source) != null) {
            payload_count = try std.math.add(usize, payload_count, instruction.payload_words);
        };
        const payload = try allocator.alloc(PayloadRow, payload_count);
        errdefer allocator.free(payload);
        const provider = try allocator.alloc(source.ProviderCall, sponge.len);
        errdefer allocator.free(provider);
        const pow_check = try allocator.alloc(air.pow_check_witness.RelationRow, execution.pow_checks.len);
        errdefer allocator.free(pow_check);
        const pow_frame = try allocator.alloc(air.pow_frame_witness.RelationRow, execution.pow_checks.len);
        errdefer allocator.free(pow_frame);
        var challenge_count: usize = 0;
        var randomness_count: usize = 0;
        for (program.operations) |op| {
            if (op.draw == .relation) challenge_count += 1 else if (op.effect == .draw) randomness_count += 1;
        }
        const challenges = try allocator.alloc(source.RelationChallengeRowV2, challenge_count);
        errdefer allocator.free(challenges);
        const randomness = try allocator.alloc(source.VerifierRandomnessRowV2, randomness_count);
        errdefer allocator.free(randomness);
        const statement = try allocator.alloc(StatementRow, public.AIR_WORD_COUNT + 2 * execution.pow_checks.len);
        var nonce_at: usize = public.AIR_WORD_COUNT;
        errdefer allocator.free(statement);
        var statement_found = false;
        var challenge_at: usize = 0;
        var randomness_at: usize = 0;
        var mix_ordinal: u32 = 0;
        var word_at: usize = 0;
        var payload_at: usize = 0;
        for (program.operations, execution.operations, 0..) |instruction, operation, index| {
            const step = frame_rows.Step{
                .verifier_id = verifier_id,
                .sequence = @intCast(index),
                .tag = switch (instruction.context) {
                    .interaction_pow => air.pow_frame.controlTag(.interaction),
                    .pcs_pow => air.pow_frame.controlTag(.pcs),
                    else => STEP_TAG_BASE + @intFromEnum(instruction.context),
                },
                .args = .{ if (instruction.effect == .pow) instruction.pow_bits else @intFromEnum(instruction.effect), instruction.payload_words, @intFromEnum(instruction.draw), instruction.item },
            };
            control[index] = .{
                .segment_mask = 0,
                .binary_mask = 1,
                .verifier_id = verifier_id,
                .sequence = step.sequence,
                .tag = step.tag,
                .args = step.args,
                .terminal_mask = 0,
            };
            for (0..operation.hash_count) |part| {
                const frame_index = operation.first_hash_id + part;
                const frame = execution.hash_frames[frame_index];
                const pow_draw = instruction.effect == .pow and part == 1;
                if (instruction.source == .statement) {
                    const limbs = frame.words[recording.RATE..];
                    if (statement_found or operation.hash_count != 1 or limbs.len != 2 * public.AIR_WORD_COUNT)
                        return error.RecursiveTranscriptRowsMismatch;
                    statement_found = true;
                    const scope = if (verifier_id == 1) recursion.binary_fri_outer_source.LEFT_COMPOSITION_STATEMENT_SCOPE else recursion.binary_fri_outer_source.RIGHT_COMPOSITION_STATEMENT_SCOPE;
                    for (statement[0..public.AIR_WORD_COUNT], 0..) |*row, word_index| {
                        const low = limbs[2 * word_index].toU32();
                        const high = limbs[2 * word_index + 1].toU32();
                        if (low > 65535 or high > 32767) return error.NonCanonicalFieldStatementWord;
                        const body = word_index >= public.HEADER_WORD_COUNT and word_index < public.HEADER_WORD_COUNT + public.STATEMENT_WORD_COUNT;
                        const extra = !body;
                        const existing = body or word_index >= public_hash.CHILD_HASH_START;
                        const pp = [_]u32{ 1, verifier_id, step.sequence, step.tag } ++ step.args ++ [_]u32{ @intCast(2 * word_index), scope, public_hash.nodeWordIndex(word_index), @intFromBool(existing or extra), 1 + @as(u32, @intFromBool(existing and extra)) };
                        row[0..air.field_statement_word_v3.PHYSICAL_MAIN_COLUMN_COUNT].* = try air.field_statement_word_v3.mainRow(low + 65536 * high);
                        for (row[air.field_statement_word_v3.PHYSICAL_MAIN_COLUMN_COUNT..], pp) |*value, raw| value.* = M31.fromCanonical(raw);
                    }
                }
                if (instruction.source == .nonce and part == 0) {
                    const limbs = frame.words[recording.RATE..];
                    if (limbs.len != 4) return error.RecursiveTranscriptRowsMismatch;
                    for (0..2) |index_in_nonce| {
                        const low = limbs[2 * index_in_nonce].toU32();
                        const high = limbs[2 * index_in_nonce + 1].toU32();
                        if (low > 65535 or high > 65535) return error.RecursiveTranscriptRowsMismatch;
                        const row = &statement[nonce_at];
                        const pp = [_]u32{ 1, verifier_id, step.sequence, step.tag } ++ step.args ++ [_]u32{ @intCast(2 * index_in_nonce), 0, 0, 0, 0 };
                        row[0..air.field_statement_word_v3.PHYSICAL_MAIN_COLUMN_COUNT].* = try air.field_statement_word_v3.nonceRow(low + 65536 * high);
                        for (row[air.field_statement_word_v3.PHYSICAL_MAIN_COLUMN_COUNT..], pp) |*value, raw| value.* = M31.fromCanonical(raw);
                        nonce_at += 1;
                    }
                }
                if (payloadKind(instruction.source)) |kind| {
                    const width: u32 = if (kind == .commitment or kind == .fri_commitment) 8 else 4;
                    for (frame.words[recording.RATE..], 0..) |value, payload_index| {
                        const word_index: u32 = @intCast(payload_index);
                        payload[payload_at] = .{
                            .preprocessing = .{
                                .row_mask = 1,
                                .segment_mask = 0,
                                .binary_mask = 1,
                                .verifier_id = verifier_id,
                                .sequence = step.sequence,
                                .tag = step.tag,
                                .args = step.args,
                                .payload_index = word_index,
                                .source_kind = kind,
                                .item_index = instruction.item + word_index / width,
                                .limb_index = word_index % width,
                                .constant_mask = @intFromBool(instruction.source.isConstantPayload()),
                                .input_use_count = if (kind == .protocol) 0 else if (kind == .sampled_value) 2 else 1,
                                .constant_value = if (instruction.source.isConstantPayload()) instruction.constant_words[word_index] else 0,
                                .source_hash_id = frame.hash_id,
                                .source_word_index = @intCast(recording.RATE + word_index),
                            },
                            .value = value,
                        };
                        payload_at += 1;
                    }
                }

                state[frame_index] = frame_rows.state(step, execution.hash_frames, frame_index, mix_ordinal, pow_draw);
                mix_ordinal += @intFromBool(frame.purpose == .mix);
                if (pow_draw) {
                    const check_index = operation.pow_check_index.?;
                    const check = execution.pow_checks[check_index];
                    const kind: air.pow_check.PowKind = if (instruction.context == .interaction_pow) .interaction else .pcs;
                    pow_check[check_index] = try air.pow_check_witness.mainRow(.{
                        .verifier_id = verifier_id,
                        .kind = kind,
                        .check = check,
                    });
                    pow_frame[check_index] = try air.pow_frame_witness.mainRow(.{
                        .verifier_id = verifier_id,
                        .sequence = step.sequence,
                        .kind = kind,
                        .hash_id = frame.hash_id,
                        .check = check,
                        .words = frame.output[0..8].*,
                    });
                } else if (instruction.effect == .draw) {
                    if (instruction.draw == .relation) {
                        challenges[challenge_at] = .{
                            .preprocessing = .{
                                .row_mask = 1,
                                .segment_mask = 0,
                                .binary_mask = 1,
                                .public_logup_mask = 0,
                                .verifier_id = verifier_id,
                                .sequence = step.sequence,
                                .tag = step.tag,
                                .args = step.args,
                                .challenge = instruction.item,
                            },
                            .main = .{ .enabler = 1, .outputs = frame.output[0..8].* },
                        };
                        challenge_at += 1;
                    } else {
                        const kind: air.verifier_randomness_witness.Kind = switch (instruction.draw) {
                            .composition => .composition_randomness,
                            .oods => .oods_point,
                            .deep => .deep_randomness,
                            .fri_alpha => .fri_alpha,
                            .queries => .raw_query,
                            else => unreachable,
                        };
                        var multiplicities: [8]u32 = undefined;
                        for (&multiplicities, 0..) |*value, word_index|
                            value.* = kind.semanticUseCount() * @intFromBool(word_index < instruction.draw_word_count);
                        randomness[randomness_at] = .{
                            .preprocessing = .{
                                .row_mask = 1,
                                .segment_mask = 0,
                                .binary_mask = 1,
                                .verifier_id = verifier_id,
                                .sequence = step.sequence,
                                .tag = step.tag,
                                .args = step.args,
                                .kind = kind,
                                .item_base = instruction.item,
                                .query_items = @intFromBool(instruction.draw == .queries),
                                .multiplicities = multiplicities,
                                .draw_index = @intCast(randomness_at),
                            },
                            .main = .{ .enabler = 1, .outputs = frame.output[0..8].* },
                        };
                        randomness_at += 1;
                    }
                }
                for (frame.first_call_id..frame.first_call_id + frame.call_count) |call_index| {
                    const call = execution.poseidon_calls[call_index];
                    sponge[call_index] = try frame_rows.callRow(execution, call_index, frame, verifier_id);
                    binding[call_index] = frame_rows.binding(step, @intCast(call_index), frame, call, sponge[call_index], part == 0, pow_draw);
                    provider[call_index] = frame_rows.providerCall(call);
                }
                for (recording.RATE..frame.call_count * recording.RATE) |word_index| {
                    word[word_at] = frame_rows.word(step, frame, @intCast(word_index));
                    word_at += 1;
                }
            }
        }
        std.debug.assert(word_at == word.len and payload_at == payload.len and challenge_at == challenges.len and randomness_at == randomness.len);
        if (!statement_found or nonce_at != statement.len) return error.RecursiveTranscriptRowsMismatch;
        return .{ .allocator = allocator, .program_identity = program.identity, .physical_claim_count = physical_claim_count, .control = control, .sponge = sponge, .binding = binding, .state = state, .word = word, .payload = payload, .provider = provider, .pow_check = pow_check, .pow_frame = pow_frame, .challenges = challenges, .randomness = randomness, .statement = statement };
    }

    pub fn deinit(self: *Rows) void {
        self.allocator.free(self.control);
        self.allocator.free(self.sponge);
        self.allocator.free(self.binding);
        self.allocator.free(self.state);
        self.allocator.free(self.word);
        self.allocator.free(self.payload);
        self.allocator.free(self.provider);
        self.allocator.free(self.pow_check);
        self.allocator.free(self.pow_frame);
        self.allocator.free(self.challenges);
        self.allocator.free(self.randomness);
        self.allocator.free(self.statement);
        self.* = undefined;
    }
};

/// Row 5 binds fixed metadata and proof material; row 12 binds canonical
/// statement words. Both field profiles bind provider partials and key IDs.
pub const ACTIVE_ROWS = [_]usize{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 10, 11, 13, 14, 15, 16, 17 };
const ROW_FIELDS = .{ "control", "sponge", "binding", "state", "word", "payload", "pow_check", "pow_frame", "challenges", "randomness", "statement" };

pub fn payloadKind(kind: program_mod.Source) ?air.transcript_payload.VerifierInputKind {
    if (kind == .canonical_preprocessed_root or kind == .common_preprocessed_root) return .commitment;
    if (kind.isConstantPayload()) return .protocol;
    return switch (kind) {
        .commitment => .commitment,
        .claim_value, .provider_partial, .canonical_wire_boundary => .claimed_sum,
        .sampled_values => .sampled_value,
        .fri_commitment => .fri_commitment,
        .last_layer => .last_layer_coefficient,
        else => null,
    };
}

pub fn bindsVerifierInput(kind: u32, item: u32) bool {
    const Kind = air.transcript_payload.VerifierInputKind;
    return switch (kind) {
        // Physical claims are present in both supported transcript profiles.
        // The per-lane method additionally admits provider subclaims.
        @intFromEnum(Kind.claimed_sum) => item < air.universal_roster.COMPONENT_COUNT,
        @intFromEnum(Kind.commitment), @intFromEnum(Kind.sampled_value), @intFromEnum(Kind.fri_commitment), @intFromEnum(Kind.last_layer_coefficient) => true,
        else => false,
    };
}

/// Tags consumed by the existing composition, opening and FRI AIRs. The
/// transcript's control tags are separate; its two PoW tags are 6 and 20.
pub fn bindsControlTag(tag: u32) bool {
    return switch (tag) {
        13, 14, 22, 23, 24, 25, 26 => true,
        else => false,
    };
}

pub fn logicalRow(comptime index: usize, row: anytype) ![catalog.LOGICAL_ROWS[index].Air.LOGICAL_INPUT_COUNT]M31 {
    return switch (index) {
        0 => air.control_witness.logicalRow(row, .binary_node),
        1 => air.transcript_air_witness.logicalRow(row),
        2 => air.transcript_binding_witness.logicalInputs(row.main, row.preprocessing, .binary_node),
        3 => air.transcript_state_witness.logicalInputs(row.main, row.preprocessing, .binary_node),
        4 => air.transcript_word_witness.logicalRow(row.preprocessing, row.value, .binary_node),
        5 => air.transcript_payload_witness.logicalRowForRecordedFrame(row.preprocessing, row.value, .binary_node),
        6, 7, 12 => row,
        8 => air.relation_challenge_witness.logicalInputs(row.main, row.preprocessing, .binary_node),
        9 => air.verifier_randomness_witness.logicalInputs(row.main, row.preprocessing, .binary_node),
        else => @compileError("inactive transcript component"),
    };
}

const LogicalRows = blk: {
    var types: [ACTIVE_ROWS.len]type = undefined;
    for (ACTIVE_ROWS, &types) |index, *T| T.* = []const [catalog.LOGICAL_ROWS[index].Air.LOGICAL_INPUT_COUNT]M31;
    break :blk std.meta.Tuple(&types);
};

/// Owned physical-writer input for both child lanes. Raw recording rows are
/// released after each lane, so the parent retains only the logical AIR rows
/// and complete transcript permutation requests. This is witness custody,
/// not a claim that the parent already commits or closes these components.
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    logical: LogicalRows,
    provider: []source.ProviderCall,
    programs: [2][32]u8,
    program_kinds: [2]program_mod.Kind,
    program_claim_counts: [2]u32,
    bound_payload_steps: [2][]bool,
    identity: [32]u8,

    pub fn init(allocator: std.mem.Allocator, children: [2]View) !Prepared {
        var result: Prepared = .{ .allocator = allocator, .logical = undefined, .provider = &.{}, .programs = undefined, .program_kinds = undefined, .program_claim_counts = undefined, .bound_payload_steps = .{ &.{}, &.{} }, .identity = undefined };
        inline for (0..ACTIVE_ROWS.len) |slot| result.logical[slot] = &.{};
        errdefer result.deinit();
        for (children, 0..) |child, lane| {
            var rows = try child.prepareTranscriptRows(allocator, @intCast(lane + 1));
            defer rows.deinit();
            result.programs[lane] = rows.program_identity;
            result.program_kinds[lane] = child.program.kind;
            result.program_claim_counts[lane] = rows.physical_claim_count;
            result.bound_payload_steps[lane] = try allocator.alloc(bool, child.program.operations.len);
            for (child.program.operations, result.bound_payload_steps[lane]) |operation, *bound| bound.* = payloadKind(operation.source) != null or operation.source == .statement or operation.source == .nonce;
            inline for (ACTIVE_ROWS[0..ROW_FIELDS.len], ROW_FIELDS, 0..) |index, field, slot| {
                const input = @field(rows, field);
                const previous = result.logical[slot].len;
                const count = try std.math.add(usize, previous, input.len);
                const values = try allocator.realloc(@constCast(result.logical[slot]), count);
                result.logical[slot] = values;
                for (input, values[previous..]) |row, *value| value.* = try logicalRow(index, row);
            }
            const previous = result.provider.len;
            result.provider = try allocator.realloc(result.provider, try std.math.add(usize, previous, rows.provider.len));
            @memcpy(result.provider[previous..], rows.provider);
        }
        result.identity = result.contentIdentity();
        return result;
    }

    /// Install the owned statement circuit inputs; row 12 now serves both
    /// composition and continuation consumers for each child body word.
    pub fn appendStatement(self: *Prepared, statement: *const @import("recursive_common_fold_statement_v3.zig").Prepared) !void {
        try self.validate();
        try statement.validate();
        if (self.logical[11].len != 0 or self.logical[12].len != 0) return error.RecursiveTranscriptRowsMismatch;
        const semantics = try self.allocator.dupe(@TypeOf(statement.semantics_rows[0]), statement.semantics_rows);
        self.logical[12] = semantics;
        for (@constCast(self.logical[10])) |*row| if (!row[21].isZero() and row[20].toU32() < public.STATEMENT_WORD_COUNT) {
            row[22] = M31.fromCanonical(2);
        };
        self.identity = self.contentIdentity();
    }

    pub fn isFixedZeroInput(kind: program_mod.Kind, item: u32) bool {
        return isFixedZeroInputForClaimCount(kind, air.universal_roster.COMPONENT_COUNT, item);
    }

    pub fn isFixedZeroInputForClaimCount(kind: program_mod.Kind, physical_count: u32, item: u32) bool {
        if (!supportedPhysicalClaimCount(kind, physical_count)) return false;
        const composition = recursion.recursion_air_composition_circuit_v3;
        return (item >= physical_count and item < composition.POSEIDON_AUX_START) or
            (kind == .common_fold and item == composition.COMPOSITION_CLAIM_INPUT_COUNT);
    }

    /// Install graph anchors and protocol zero inputs, never an observed residual.
    pub fn appendFixedWires(self: *Prepared, plan: *const air.verifier_arithmetic_lowering.Plan, reference: air.verifier_arithmetic_lowering.Reference) !void {
        try self.validate();
        try plan.validateAgainst(reference);
        if (self.logical[11].len != 0) return error.RecursiveTranscriptRowsMismatch;
        var count: usize = 0;
        for (plan.public_terms) |term| if (term.active_in == .binary) {
            count += 1;
        };
        for (self.program_kinds, self.program_claim_counts) |kind, physical_count| for (0..recursion.recursion_air_composition_circuit_v3.COMPOSITION_CLAIM_INPUT_COUNT + 1) |item| {
            if (isFixedZeroInputForClaimCount(kind, physical_count, @intCast(item))) count += 4;
        };
        const rows = try self.allocator.alloc(air.fixed_wire_v3.Row, count);
        errdefer self.allocator.free(rows);
        var at: usize = 0;
        for (plan.public_terms) |term| {
            if (term.active_in != .binary) continue;
            rows[at] = try air.fixed_wire_v3.logicalRow(term);
            at += 1;
        }
        for (self.program_kinds, self.program_claim_counts, 1..) |kind, physical_count, verifier_id| for (0..recursion.recursion_air_composition_circuit_v3.COMPOSITION_CLAIM_INPUT_COUNT + 1) |item| {
            if (!isFixedZeroInputForClaimCount(kind, physical_count, @intCast(item))) continue;
            for (0..4) |word| {
                rows[at] = try air.fixed_wire_v3.zeroVerifierInputRow(@intCast(verifier_id), @intCast(item), @intCast(word));
                at += 1;
            }
        };
        std.debug.assert(at == rows.len);
        self.logical[11] = rows;
        self.identity = self.contentIdentity();
    }

    pub fn validateFixedWires(self: *const Prepared, plan: *const air.verifier_arithmetic_lowering.Plan, reference: air.verifier_arithmetic_lowering.Reference) !void {
        try self.validate();
        try plan.validateAgainst(reference);
        var at: usize = 0;
        for (plan.public_terms) |term| {
            if (term.active_in != .binary) continue;
            if (at >= self.logical[11].len or !std.meta.eql(self.logical[11][at], try air.fixed_wire_v3.logicalRow(term)))
                return error.RecursiveTranscriptRowsMismatch;
            at += 1;
        }
        for (self.program_kinds, self.program_claim_counts, 1..) |kind, physical_count, verifier_id| for (0..recursion.recursion_air_composition_circuit_v3.COMPOSITION_CLAIM_INPUT_COUNT + 1) |item| {
            if (!isFixedZeroInputForClaimCount(kind, physical_count, @intCast(item))) continue;
            for (0..4) |word| {
                const expected = try air.fixed_wire_v3.zeroVerifierInputRow(@intCast(verifier_id), @intCast(item), @intCast(word));
                if (at >= self.logical[11].len or !std.meta.eql(self.logical[11][at], expected)) return error.RecursiveTranscriptRowsMismatch;
                at += 1;
            }
        };
        if (at != self.logical[11].len) return error.RecursiveTranscriptRowsMismatch;
    }

    pub fn appendPublicHashes(self: *Prepared, prepared: *const public_hash.Prepared) !void {
        try self.validate();
        inline for (13..18) |slot| if (self.logical[slot].len != 0) return error.RecursiveTranscriptRowsMismatch;
        var staged: @TypeOf(prepared.hashes) = .{ &.{}, &.{}, &.{}, &.{} };
        errdefer for (staged) |rows| self.allocator.free(rows);
        for (prepared.hashes, &staged) |rows, *copy| copy.* = try self.allocator.dupe(public_hash.HashRow, rows);
        const words = try self.allocator.dupe(public_hash.WordRow, prepared.words);
        inline for (0..4) |phase| self.logical[13 + phase] = staged[phase];
        self.logical[17] = words;
        self.identity = self.contentIdentity();
    }

    /// Extend row 0 from the authenticated verifier program, never from an
    /// observed consumer ledger. Prepare all rows before changing this owner.
    pub fn appendVerifierControl(self: *Prepared, plan: *const air.verifier_schedule.Plan) !void {
        try self.validate();
        try plan.validate();
        if (plan.schema != .recursion) return error.RecursiveTranscriptRowsMismatch;
        var count: usize = 0;
        for (plan.steps) |step| if (bindsControlTag(step.encode().tag)) {
            count = try std.math.add(usize, count, 2);
        };
        const previous = self.logical[0];
        const values = try self.allocator.alloc(@TypeOf(previous[0]), try std.math.add(usize, previous.len, count));
        errdefer self.allocator.free(values);
        @memcpy(values[0..previous.len], previous);
        var at = previous.len;
        for (1..3) |lane| for (plan.steps, 0..) |step, sequence| {
            if (!bindsControlTag(step.encode().tag)) continue;
            const row = air.control_witness.rowForVerifierStep(step, @intCast(sequence), @intCast(lane), 0, 1);
            values[at] = try logicalRow(0, row);
            at += 1;
        };
        std.debug.assert(at == values.len);
        self.allocator.free(previous);
        self.logical[0] = values;
        self.identity = self.contentIdentity();
    }

    pub fn deinit(self: *Prepared) void {
        inline for (0..ACTIVE_ROWS.len) |slot| self.allocator.free(self.logical[slot]);
        self.allocator.free(self.provider);
        for (self.bound_payload_steps) |steps| self.allocator.free(steps);
        self.* = undefined;
    }

    pub fn bindsPayloadStep(self: *const Prepared, verifier_id: u32, sequence: u32) !bool {
        if (verifier_id < 1 or verifier_id > 2 or sequence >= self.bound_payload_steps[verifier_id - 1].len) return error.RecursiveTranscriptRowsMismatch;
        return self.bound_payload_steps[verifier_id - 1][sequence];
    }

    pub fn bindsVerifierInputForLane(self: *const Prepared, verifier_id: u32, kind: u32, item: u32) !bool {
        if (verifier_id < 1 or verifier_id > 2) return error.RecursiveTranscriptRowsMismatch;
        return bindsVerifierInputForClaimCount(self.program_kinds[verifier_id - 1], self.program_claim_counts[verifier_id - 1], kind, item);
    }

    /// Same single-lane protocol predicate used by pair routing and detached
    /// replay. Canonical-empty and Ethereum field transcripts both publish a
    /// dynamic wire boundary; common-fold supplies its admitted zero instead.
    pub fn bindsVerifierInputForKind(program_kind: program_mod.Kind, kind: u32, item: u32) bool {
        return bindsVerifierInputForClaimCount(program_kind, air.universal_roster.COMPONENT_COUNT, kind, item);
    }

    pub fn bindsVerifierInputForClaimCount(program_kind: program_mod.Kind, physical_count: u32, kind: u32, item: u32) bool {
        if (!supportedPhysicalClaimCount(program_kind, physical_count)) return false;
        if (kind != @intFromEnum(air.transcript_payload.VerifierInputKind.claimed_sum)) return bindsVerifierInput(kind, item);
        if (item < physical_count or isFixedZeroInputForClaimCount(program_kind, physical_count, item)) return true;
        const composition = recursion.recursion_air_composition_circuit_v3;
        if (item >= composition.POSEIDON_AUX_START and item < composition.POSEIDON_AUX_START + 2) return true;
        return switch (program_kind) {
            .canonical_empty, .ethereum_incremental_field_v1 => item == composition.COMPOSITION_CLAIM_INPUT_COUNT,
            .common_fold => false,
        };
    }

    pub fn validate(self: *const Prepared) !void {
        for (self.program_kinds, self.program_claim_counts) |kind, count|
            if (!supportedPhysicalClaimCount(kind, count)) return error.RecursiveTranscriptRowsMismatch;
        if (!std.mem.eql(u8, &self.identity, &self.contentIdentity())) return error.RecursiveTranscriptRowsMismatch;
    }

    pub fn installLogSizes(self: *const Prepared, logs: *[36]u32) !void {
        inline for (ACTIVE_ROWS, 0..) |index, slot| {
            logs[index] = try air.transcript_air_witness.traceLogSize(self.logical[slot].len);
        }
    }

    /// Reuse the Ethereum wrapper's writer and whole-tree alias/geometry
    /// preflight. All destinations are checked before the first row is written.
    pub fn preflight(self: *const Prepared, manifest: *const air.universal_adapter_manifest.Manifest, tree: usize, destination: []const []M31) !void {
        const support = @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4_support.zig");
        if (tree > 2) return error.InvalidTreeIndex;
        try self.validate();
        var protected: [ACTIVE_ROWS.len + 4]support.AddressRange = undefined;
        inline for (0..ACTIVE_ROWS.len) |slot| protected[slot] = try support.sliceRange(self.logical[slot]);
        protected[ACTIVE_ROWS.len] = try support.sliceRange(self.provider);
        protected[ACTIVE_ROWS.len + 1] = try support.sliceRange(std.mem.asBytes(self));
        for (self.bound_payload_steps, 0..) |steps, index| protected[ACTIVE_ROWS.len + 2 + index] = try support.sliceRange(steps);
        try support.preflightTree(manifest, tree, destination, &protected);
        // Do not let a smaller valid manifest truncate an active component.
        inline for (ACTIVE_ROWS, 0..) |index, slot| {
            const placement = try manifest.placement(@enumFromInt(index));
            if (self.logical[slot].len > try support.traceSize(placement.geometry.log_size)) return error.DestinationLogSizeMismatch;
        }
    }

    pub fn writePhysicalInto(self: *const Prepared, manifest: *const air.universal_adapter_manifest.Manifest, tree: usize, destination: []const []M31) !void {
        const support = @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4_support.zig");
        if (tree != 0 and tree != 1) return error.InvalidTreeIndex;
        try self.preflight(manifest, tree, destination);
        inline for (ACTIVE_ROWS, 0..) |index, slot| support.writePhysical(catalog.LOGICAL_ROWS[index].Air, self.logical[slot], try manifest.placement(@enumFromInt(index)), tree, destination);
    }

    fn contentIdentity(self: *const Prepared) [32]u8 {
        const support = @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4_support.zig");
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/recursive-child-transcript-rows/v1\x00");
        for (self.programs) |program| hash.update(&program);
        for (self.program_kinds) |kind| hash.update(&.{@intFromEnum(kind)});
        // Preserve ordinary custody bytes; the appended selection must still be
        // sealed so changing a physical claim into a fixed zero cannot pass.
        if (!std.meta.eql(self.program_claim_counts, [_]u32{ 36, 36 })) {
            hash.update("initial-physical-claim-counts/v1\x00");
            for (self.program_claim_counts) |count| {
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &bytes, count, .little);
                hash.update(&bytes);
            }
        }
        for (self.bound_payload_steps) |steps| hash.update(std.mem.sliceAsBytes(steps));
        inline for (0..ACTIVE_ROWS.len) |slot| support.hashRows(&hash, self.logical[slot]);
        hash.update(&@import("recursive_common_fold_poseidon_schedule_v2.zig").callBufferIdentity(self.provider));
        return hash.finalResult();
    }
};

fn supportedPhysicalClaimCount(kind: program_mod.Kind, count: u32) bool {
    return count == air.universal_roster.COMPONENT_COUNT or
        (kind == .ethereum_incremental_field_v1 and count == air.ethereum_initial_input_manifest_v1.COMPONENT_COUNT);
}

/// Called only after recording admission. The fixed header and exact ordered
/// claim operations supply this count, never candidate claims or a caller flag.
fn physicalClaimCount(program: *const program_mod.Program) !u32 {
    var expected: ?u32 = null;
    var count: u32 = 0;
    for (program.operations) |operation| switch (operation.source) {
        .claim_count => {
            if (expected != null or operation.effect != .mix or operation.context != .claims or
                operation.payload_words != 2 or operation.constant_words[1] != 0 or
                !supportedPhysicalClaimCount(program.kind, operation.constant_words[0])) return error.RecursiveTranscriptRowsMismatch;
            expected = operation.constant_words[0];
        },
        .claim_value => {
            if (expected == null or operation.effect != .mix or operation.context != .claims or
                operation.payload_words != 4 or operation.item != count) return error.RecursiveTranscriptRowsMismatch;
            count = try std.math.add(u32, count, 1);
        },
        else => {},
    };
    if (count != (expected orelse return error.RecursiveTranscriptRowsMismatch)) return error.RecursiveTranscriptRowsMismatch;
    return count;
}

test "Ethereum initial transcript zero slots follow admitted physical claims" {
    const allocator = std.testing.allocator;
    var operations: [39]program_mod.Operation = undefined;
    operations[0] = .{ .context = .claims, .effect = .mix, .source = .claim_count, .payload_words = 2, .constant_words = .{38} ++ .{0} ** 15 };
    for (operations[1..], 0..) |*operation, index| operation.* = .{ .context = .claims, .effect = .mix, .source = .claim_value, .payload_words = 4, .item = @intCast(index) };
    var program = program_mod.Program{ .allocator = allocator, .kind = .ethereum_incremental_field_v1, .manifest_seal = @splat(0), .operations = &operations, .identity = @splat(0) };
    try std.testing.expectEqual(@as(u32, 38), try physicalClaimCount(&program));
    operations[38].item = 36;
    try std.testing.expectError(error.RecursiveTranscriptRowsMismatch, physicalClaimCount(&program));
    operations[38].item = 37;
    operations[0].constant_words[0] = 36;
    try std.testing.expectError(error.RecursiveTranscriptRowsMismatch, physicalClaimCount(&program));
    program.operations = operations[0..37];
    try std.testing.expectEqual(@as(u32, 36), try physicalClaimCount(&program));
    operations[0].constant_words[0] = 38;
    program.operations = &operations;
    program.kind = .common_fold;
    try std.testing.expectError(error.RecursiveTranscriptRowsMismatch, physicalClaimCount(&program));

    const graph_mod = air.composition_circuit;
    const nodes = [_]graph_mod.Node{ .{ .op = .input }, .{ .op = .{ .sub = .{ .lhs = 0, .rhs = 0 } } } };
    const outputs = [_]u32{1};
    const graph = graph_mod.CircuitGraph{ .nodes = &nodes, .outputs = &outputs, .identity_digest = graph_mod.computeGraphDigest(&nodes, &outputs) };
    const lowering = air.verifier_arithmetic_lowering;
    const lanes = [_]lowering.Lane{
        .{ .circuit_id = 10, .active_in = .segment, .circuit_identity = graph.identity_digest, .graph = graph },
        .{ .circuit_id = 11, .active_in = .binary, .circuit_identity = graph.identity_digest, .graph = graph },
    };
    const reference = try lowering.Reference.seal(&lanes);
    var plan = try lowering.Plan.init(allocator, reference);
    defer plan.deinit();
    // A mixed selection tests per-lane custody without claiming heterogeneous
    // child-wire/fold admission; that boundary remains a separate milestone.
    var prepared = Prepared{ .allocator = allocator, .logical = undefined, .provider = &.{}, .programs = .{ @splat(1), @splat(2) }, .program_kinds = .{ .ethereum_incremental_field_v1, .ethereum_incremental_field_v1 }, .program_claim_counts = .{ 38, 36 }, .bound_payload_steps = .{ &.{}, &.{} }, .identity = undefined };
    inline for (0..ACTIVE_ROWS.len) |slot| prepared.logical[slot] = &.{};
    prepared.identity = prepared.contentIdentity();
    defer prepared.deinit();
    try prepared.appendFixedWires(&plan, reference);
    try prepared.validateFixedWires(&plan, reference);
    var anchors: usize = 0;
    for (plan.public_terms) |term| if (term.active_in == .binary) {
        anchors += 1;
    };
    try std.testing.expectEqual(anchors + 16, prepared.logical[11].len);
    for (prepared.logical[11][anchors..][0..4], 0..) |row, word| try std.testing.expectEqualDeep(try air.fixed_wire_v3.zeroVerifierInputRow(1, 38, @intCast(word)), row);
    for (prepared.logical[11][anchors + 4 ..], 0..) |row, limb| try std.testing.expectEqualDeep(try air.fixed_wire_v3.zeroVerifierInputRow(2, @intCast(36 + limb / 4), @intCast(limb % 4)), row);
    const claim_kind = @intFromEnum(air.transcript_payload.VerifierInputKind.claimed_sum);
    for ([_]u32{ 36, 37 }) |item| {
        try std.testing.expect(!Prepared.isFixedZeroInputForClaimCount(.ethereum_incremental_field_v1, 38, item));
        try std.testing.expect(Prepared.isFixedZeroInput(.ethereum_incremental_field_v1, item));
        try std.testing.expect(try prepared.bindsVerifierInputForLane(1, claim_kind, item));
    }
    for ([_]u32{ 39, 40, 41 }) |item| try std.testing.expect(!Prepared.isFixedZeroInputForClaimCount(.ethereum_incremental_field_v1, 38, item));
    prepared.program_claim_counts[0] = 36;
    try std.testing.expectError(error.RecursiveTranscriptRowsMismatch, prepared.validate());
    prepared.program_claim_counts[0] = 38;
    const rows = @constCast(prepared.logical[11]);
    const original = rows[anchors];
    rows[anchors] = try air.fixed_wire_v3.zeroVerifierInputRow(1, 36, 0);
    prepared.identity = prepared.contentIdentity();
    try std.testing.expectError(error.RecursiveTranscriptRowsMismatch, prepared.validateFixedWires(&plan, reference));
    rows[anchors] = original;
    const complete_rows = prepared.logical[11];
    prepared.logical[11] = complete_rows[0 .. complete_rows.len - 1];
    prepared.identity = prepared.contentIdentity();
    try std.testing.expectError(error.RecursiveTranscriptRowsMismatch, prepared.validateFixedWires(&plan, reference));
    prepared.logical[11] = complete_rows;
    prepared.identity = prepared.contentIdentity();
    try prepared.validateFixedWires(&plan, reference);
}
