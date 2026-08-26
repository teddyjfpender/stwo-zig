//! Internal transcript payload witness authority shard; use transcript_payload_witness.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const digest = @import("../../air/lang/digest.zig");
pub const direct = @import("../../air/lang/direct_witness_executor.zig");
pub const types = @import("../../air/lang/types.zig");
pub const protocol = @import("../protocol.zig");
pub const component = @import("transcript_payload.zig");
pub const proof_kind_mod = @import("proof_kind.zig");
pub const schedule = @import("verifier_schedule.zig");
pub const trace_mod = @import("pow_frame_witness.zig");

pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = component.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = proof_kind_mod.ProofKind;
pub const TranscriptTrace = trace_mod.TranscriptTrace;
pub const VerifierInputKind = component.VerifierInputKind;
pub const MIN_LOG_SIZE = component.MIN_LOG_SIZE;
pub const MAX_LOG_SIZE = component.MAX_LOG_SIZE;
pub const SEGMENT_VERIFIER_ID: u32 = 0;
pub const LEFT_RECURSION_VERIFIER_ID: u32 = 1;
pub const RIGHT_RECURSION_VERIFIER_ID: u32 = 2;
pub const PAYLOAD_WORD_OFFSET: u32 = 2 * component.DIGEST_WORD_COUNT;

/// Re-exported for existing row-5 callers. The verifier schedule owns these
/// protocol words so the native transcript program cannot drift from the AIR.
pub const PCS_PARAMETER_WORDS = schedule.PCS_PARAMETER_WORDS;

pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-transcript-payload-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "e7f06c9a648cbe2bce7f357548033762335f02645fbd0684ec900df2e27f8af5";
pub const BINDING_DIGEST = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion transcript-payload witness-binding digest",
);
pub const PREPROCESSING_FORMAT_VERSION: u16 = 1;
pub const PREPROCESSING_DOMAIN =
    "stwo-zig/typed-air/recursion-transcript-payload-preprocessing/v1\x00";
pub const PREPARED_BATCH_FORMAT_VERSION: u16 = 1;
pub const PREPARED_BATCH_DOMAIN =
    "stwo-zig/typed-air/recursion-transcript-payload-batch/v1\x00";

pub const MainSource = enum(u8) {
    enabler = 0,
    value = 1,
};

pub const PreprocessedSource = enum(u8) {
    row_mask = 0,
    segment_mask = 1,
    binary_mask = 2,
    verifier_id = 3,
    sequence = 4,
    tag = 5,
    arg_0 = 6,
    arg_1 = 7,
    arg_2 = 8,
    arg_3 = 9,
    payload_index = 10,
    source_kind = 11,
    item_index = 12,
    limb_index = 13,
    constant_mask = 14,
    input_use_count = 15,
    constant_value = 16,
};

pub fn Slot(comptime SourceType: type) type {
    return struct {
        column: u8,
        value: types.ValueId,
        source: SourceType,
    };
}

pub const Binding = struct {
    format_version: u16,
    semantic_format_version: u16,
    semantic_digest: digest.Digest,
    source_authority_digest: digest.Digest,
    main: [MAIN_COLUMN_COUNT]Slot(MainSource),
    preprocessed: [PREPROCESSED_COLUMN_COUNT]Slot(PreprocessedSource),
    parameters: [component.PARAMETER_COUNT]types.ValueId,

    pub fn canonical(
        definition: *const component.Definition,
    ) ConstructionError!Binding {
        try definition.validate();
        var main: [MAIN_COLUMN_COUNT]Slot(MainSource) = undefined;
        for (&main, definition.main.physical(), std.enums.values(MainSource), 0..) |
            *slot,
            value,
            source_value,
            column,
        | slot.* = .{
            .column = @intCast(column),
            .value = value,
            .source = source_value,
        };
        var preprocessed: [PREPROCESSED_COLUMN_COUNT]Slot(PreprocessedSource) =
            undefined;
        for (
            &preprocessed,
            definition.preprocessed.physical(),
            std.enums.values(PreprocessedSource),
            0..,
        ) |*slot, value, source_value, column| slot.* = .{
            .column = @intCast(column),
            .value = value,
            .source = source_value,
        };
        return .{
            .format_version = BINDING_FORMAT_VERSION,
            .semantic_format_version = digest.typed_effect_format_version,
            .semantic_digest = component.SEMANTIC_DIGEST,
            .source_authority_digest = component.SOURCE_AUTHORITY_DIGEST,
            .main = main,
            .preprocessed = preprocessed,
            .parameters = definition.parameters.physical(),
        };
    }

    pub fn identityDigest(self: *const Binding) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(BINDING_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.semantic_format_version);
        hash.update(&self.semantic_digest);
        hash.update(&self.source_authority_digest);
        hashInt(&hash, u16, self.main.len);
        for (self.main) |slot| hashSlot(&hash, slot);
        hashInt(&hash, u16, self.preprocessed.len);
        for (self.preprocessed) |slot| hashSlot(&hash, slot);
        hashInt(&hash, u16, self.parameters.len);
        for (self.parameters) |value| hashInt(&hash, u32, @intFromEnum(value));
        return hash.finalResult();
    }
};

pub const ConstructionError = component.ValidationError || error{
    InvalidWitnessBinding,
};
pub const Error = direct.Error || schedule.Error || trace_mod.Error ||
    protocol.Error || std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    InvalidFieldElement,
    InvalidTranscriptLayout,
    InvalidTranscriptSource,
    InvalidWitnessBinding,
    LogSizeOutOfRange,
    SchemaMismatch,
};

pub const Row = struct {
    row_mask: u32,
    segment_mask: u32,
    binary_mask: u32,
    verifier_id: u32,
    sequence: u32,
    tag: u32,
    args: [4]u32,
    payload_index: u32,
    source_kind: VerifierInputKind,
    item_index: u32,
    limb_index: u32,
    constant_mask: u32,
    input_use_count: u32,
    constant_value: u32,
    source_hash_id: u32,
    source_word_index: u32,

    pub fn values(self: Row) [PREPROCESSED_COLUMN_COUNT]M31 {
        return .{
            M31.fromCanonical(self.row_mask),
            M31.fromCanonical(self.segment_mask),
            M31.fromCanonical(self.binary_mask),
            M31.fromCanonical(self.verifier_id),
            M31.fromCanonical(self.sequence),
            M31.fromCanonical(self.tag),
            M31.fromCanonical(self.args[0]),
            M31.fromCanonical(self.args[1]),
            M31.fromCanonical(self.args[2]),
            M31.fromCanonical(self.args[3]),
            M31.fromCanonical(self.payload_index),
            M31.fromCanonical(@intFromEnum(self.source_kind)),
            M31.fromCanonical(self.item_index),
            M31.fromCanonical(self.limb_index),
            M31.fromCanonical(self.constant_mask),
            M31.fromCanonical(self.input_use_count),
            M31.fromCanonical(self.constant_value),
        };
    }
};

pub fn validateLanePlans(
    vm: *const schedule.Plan,
    recursion: *const schedule.Plan,
) Error!void {
    try vm.validate();
    try recursion.validate();
    if (vm.schema != .vm or recursion.schema != .recursion)
        return error.SchemaMismatch;
}

pub const Effect = enum { mix, draw, pow };

pub fn transcriptEffect(step: schedule.VerifierStep) ?Effect {
    return switch (step) {
        .bind_protocol,
        .bind_statement,
        .bind_pcs_parameters,
        .absorb_trace_commitment,
        .absorb_public_claim,
        .absorb_claimed_sums,
        .absorb_sampled_values,
        .absorb_fri_commitment,
        .absorb_last_layer_coefficients,
        => .mix,
        .draw_relation_challenge,
        .draw_composition_randomness,
        .draw_oods_point,
        .draw_deep_randomness,
        .draw_fri_alpha,
        .draw_query_block,
        => .draw,
        .verify_and_absorb_interaction_pow,
        .verify_and_absorb_pcs_pow,
        => .pow,
        else => null,
    };
}

pub fn payloadWordCount(
    schema: schedule.Schema,
    step: schedule.VerifierStep,
) Error!usize {
    return switch (step) {
        .bind_protocol => component.PROTOCOL_BINDING_WORD_COUNT,
        .bind_statement => component.STATEMENT_WORD_COUNT,
        .bind_pcs_parameters => component.PCS_PARAMETER_WORD_COUNT,
        .absorb_trace_commitment, .absorb_fri_commitment => component.DIGEST_WORD_COUNT,
        .absorb_public_claim => if (schema == .vm)
            component.DIGEST_WORD_COUNT
        else
            0,
        .verify_and_absorb_interaction_pow, .verify_and_absorb_pcs_pow => component.QM31_WORD_COUNT,
        .absorb_claimed_sums => |item| try timesFour(item.count),
        .absorb_sampled_values => |item| try timesFour(item.count),
        .absorb_last_layer_coefficients => |item| try timesFour(item.count),
        .draw_relation_challenge,
        .draw_composition_randomness,
        .draw_oods_point,
        .draw_deep_randomness,
        .draw_fri_alpha,
        .draw_query_block,
        => 0,
        else => return error.InvalidTranscriptLayout,
    };
}

pub fn laneRowCount(plan: *const schedule.Plan) Error!usize {
    var result: usize = 0;
    for (plan.steps) |step| {
        if (transcriptEffect(step) == null) continue;
        result = std.math.add(
            usize,
            result,
            try payloadWordCount(plan.schema, step),
        ) catch return error.ArithmeticOverflow;
    }
    return result;
}

pub const Sink = struct {
    mode: enum { write, compare },
    rows: []Row,
    at: usize = 0,

    pub fn write(rows: []Row) Sink {
        return .{ .mode = .write, .rows = rows };
    }

    pub fn compare(rows: []const Row) Sink {
        return .{ .mode = .compare, .rows = @constCast(rows) };
    }

    fn put(self: *Sink, row: Row) Error!void {
        if (self.at >= self.rows.len) return error.AuthorityMismatch;
        switch (self.mode) {
            .write => self.rows[self.at] = row,
            .compare => if (!std.meta.eql(self.rows[self.at], row))
                return error.AuthorityMismatch,
        }
        self.at += 1;
    }
};

pub fn emitLane(
    sink: *Sink,
    plan: *const schedule.Plan,
    protocol_id: *const [component.DIGEST_WORD_COUNT]u32,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Error!void {
    var hash_id: u32 = 0;
    for (plan.steps, 0..) |step, sequence| {
        const effect = transcriptEffect(step) orelse continue;
        const payload_count = try payloadWordCount(plan.schema, step);
        const encoded = step.encode();
        for (0..payload_count) |payload_index| {
            const payload_u32: u32 = @intCast(payload_index);
            const source = try payloadSource(
                plan,
                protocol_id,
                step,
                payload_u32,
            );
            try sink.put(.{
                .row_mask = 1,
                .segment_mask = segment_mask,
                .binary_mask = binary_mask,
                .verifier_id = verifier_id,
                .sequence = @intCast(sequence),
                .tag = encoded.tag,
                .args = encoded.args,
                .payload_index = payload_u32,
                .source_kind = source.kind,
                .item_index = source.item_index,
                .limb_index = source.limb_index,
                .constant_mask = @intFromBool(source.constant != null),
                .input_use_count = inputUseCount(source.kind),
                .constant_value = source.constant orelse 0,
                .source_hash_id = hash_id,
                .source_word_index = PAYLOAD_WORD_OFFSET + payload_u32,
            });
        }
        hash_id = std.math.add(u32, hash_id, 1) catch
            return error.ArithmeticOverflow;
        if (effect != .mix) {
            hash_id = std.math.add(u32, hash_id, 1) catch
                return error.ArithmeticOverflow;
        }
    }
}

pub const PayloadSource = struct {
    kind: VerifierInputKind,
    item_index: u32,
    limb_index: u32,
    constant: ?u32,
};

pub fn payloadSource(
    plan: *const schedule.Plan,
    protocol_id: *const [component.DIGEST_WORD_COUNT]u32,
    step: schedule.VerifierStep,
    payload_index: u32,
) Error!PayloadSource {
    return switch (step) {
        .bind_protocol => if (payload_index < component.DIGEST_WORD_COUNT)
            constantIndexedSource(
                .protocol,
                0,
                payload_index,
                try indexedWord(protocol_id, payload_index),
            )
        else blk: {
            const shape_index = payload_index - @as(u32, component.DIGEST_WORD_COUNT);
            break :blk constantIndexedSource(
                .protocol,
                1,
                shape_index,
                try indexedWord(&plan.shape_id, shape_index),
            );
        },
        .bind_statement => dynamicSource(.statement, 0, payload_index),
        .bind_pcs_parameters => constantSource(
            .pcs_parameters,
            payload_index,
            try indexedWord(&PCS_PARAMETER_WORDS, payload_index),
        ),
        .absorb_trace_commitment => |item| blk: {
            try requireWidth(payload_index, component.DIGEST_WORD_COUNT);
            break :blk dynamicSource(.commitment, item.tree, payload_index);
        },
        .verify_and_absorb_interaction_pow => blk: {
            try requireWidth(payload_index, component.QM31_WORD_COUNT);
            break :blk dynamicSource(.interaction_pow_nonce, 0, payload_index);
        },
        .absorb_claimed_sums => |item| try indexedQm31Source(
            .claimed_sum,
            payload_index,
            item.count,
        ),
        .absorb_sampled_values => |item| try indexedQm31Source(
            .sampled_value,
            payload_index,
            item.count,
        ),
        .absorb_fri_commitment => |item| blk: {
            try requireWidth(payload_index, component.DIGEST_WORD_COUNT);
            break :blk dynamicSource(.fri_commitment, item.layer, payload_index);
        },
        .absorb_last_layer_coefficients => |item| try indexedQm31Source(
            .last_layer_coefficient,
            payload_index,
            item.count,
        ),
        .verify_and_absorb_pcs_pow => blk: {
            try requireWidth(payload_index, component.QM31_WORD_COUNT);
            break :blk dynamicSource(.pcs_pow_nonce, 0, payload_index);
        },
        .absorb_public_claim => blk: {
            if (plan.schema != .vm) return error.InvalidTranscriptLayout;
            try requireWidth(payload_index, component.DIGEST_WORD_COUNT);
            break :blk dynamicSource(.vm_public_claim_digest, 0, payload_index);
        },
        else => return error.InvalidTranscriptLayout,
    };
}

pub fn dynamicSource(
    kind: VerifierInputKind,
    item_index: u32,
    limb_index: u32,
) PayloadSource {
    return .{
        .kind = kind,
        .item_index = item_index,
        .limb_index = limb_index,
        .constant = null,
    };
}

pub fn constantSource(
    kind: VerifierInputKind,
    limb_index: u32,
    value: u32,
) PayloadSource {
    return .{
        .kind = kind,
        .item_index = 0,
        .limb_index = limb_index,
        .constant = value,
    };
}

pub fn constantIndexedSource(
    kind: VerifierInputKind,
    item_index: u32,
    limb_index: u32,
    value: u32,
) PayloadSource {
    return .{
        .kind = kind,
        .item_index = item_index,
        .limb_index = limb_index,
        .constant = value,
    };
}

pub fn indexedQm31Source(
    kind: VerifierInputKind,
    payload_index: u32,
    item_count: u32,
) Error!PayloadSource {
    const payload_count = std.math.mul(
        u32,
        item_count,
        @as(u32, component.QM31_WORD_COUNT),
    ) catch return error.ArithmeticOverflow;
    try requireWidth(payload_index, payload_count);
    return dynamicSource(
        kind,
        payload_index / @as(u32, component.QM31_WORD_COUNT),
        payload_index % @as(u32, component.QM31_WORD_COUNT),
    );
}

pub fn indexedWord(words: []const u32, index: u32) Error!u32 {
    if (index >= words.len) return error.InvalidTranscriptLayout;
    return words[index];
}

pub fn requireWidth(index: u32, width: u32) Error!void {
    if (index >= width) return error.InvalidTranscriptLayout;
}

pub fn inputUseCount(kind: VerifierInputKind) u32 {
    return switch (kind) {
        .sampled_value => 2,
        .statement,
        .commitment,
        .claimed_sum,
        .fri_commitment,
        .last_layer_coefficient,
        .vm_public_claim_digest,
        => 1,
        .protocol,
        .pcs_parameters,
        .interaction_pow_nonce,
        .pcs_pow_nonce,
        .vm_air_claimed_sum,
        => 0,
    };
}

pub fn requiresInputRelation(kind: VerifierInputKind) bool {
    return inputUseCount(kind) != 0;
}

pub fn rowActive(row: Row, kind: ProofKind) bool {
    return switch (kind) {
        .segment_leaf => row.segment_mask == 1,
        .binary_node => row.binary_mask == 1,
        .empty_leaf => false,
    };
}

pub fn validateRow(row: Row) direct.Error!void {
    if (row.row_mask != 1 or row.segment_mask > 1 or row.binary_mask > 1 or
        row.segment_mask + row.binary_mask != 1 or
        row.verifier_id >= m31.Modulus or row.sequence >= m31.Modulus or
        row.tag >= m31.Modulus or row.payload_index >= m31.Modulus or
        row.item_index >= m31.Modulus or row.limb_index >= m31.Modulus or
        row.constant_mask > 1 or row.input_use_count > 2 or
        row.constant_value >= m31.Modulus or
        row.source_hash_id >= m31.Modulus or
        row.source_word_index != PAYLOAD_WORD_OFFSET + row.payload_index or
        row.source_word_index >= m31.Modulus or
        row.input_use_count != inputUseCount(row.source_kind))
    {
        return error.InvalidTraceRow;
    }
    for (row.args) |arg| if (arg >= m31.Modulus)
        return error.InvalidTraceRow;
    switch (row.verifier_id) {
        SEGMENT_VERIFIER_ID => if (row.segment_mask != 1 or row.binary_mask != 0)
            return error.InvalidTraceRow,
        LEFT_RECURSION_VERIFIER_ID, RIGHT_RECURSION_VERIFIER_ID => if (row.segment_mask != 0 or row.binary_mask != 1)
            return error.InvalidTraceRow,
        else => return error.InvalidTraceRow,
    }
    switch (row.source_kind) {
        .protocol => if (row.constant_mask != 1 or row.item_index > 1 or
            row.limb_index >= component.DIGEST_WORD_COUNT)
        {
            return error.InvalidTraceRow;
        },
        .statement => if (row.constant_mask != 0 or row.constant_value != 0 or
            row.item_index != 0 or row.limb_index >= component.STATEMENT_WORD_COUNT)
        {
            return error.InvalidTraceRow;
        },
        .pcs_parameters => if (row.constant_mask != 1 or row.item_index != 0 or
            row.limb_index >= component.PCS_PARAMETER_WORD_COUNT)
        {
            return error.InvalidTraceRow;
        },
        .commitment, .fri_commitment => if (row.constant_mask != 0 or
            row.constant_value != 0 or row.limb_index >= component.DIGEST_WORD_COUNT)
        {
            return error.InvalidTraceRow;
        },
        .claimed_sum, .sampled_value, .last_layer_coefficient => if (row.constant_mask != 0 or
            row.constant_value != 0 or row.limb_index >= component.QM31_WORD_COUNT)
        {
            return error.InvalidTraceRow;
        },
        .interaction_pow_nonce, .pcs_pow_nonce => if (row.constant_mask != 0 or
            row.constant_value != 0 or row.item_index != 0 or
            row.limb_index >= component.QM31_WORD_COUNT)
        {
            return error.InvalidTraceRow;
        },
        .vm_public_claim_digest => if (row.constant_mask != 0 or
            row.constant_value != 0 or row.item_index != 0 or
            row.limb_index >= component.DIGEST_WORD_COUNT or
            row.verifier_id != SEGMENT_VERIFIER_ID)
        {
            return error.InvalidTraceRow;
        },
        .vm_air_claimed_sum => return error.InvalidTraceRow,
    }
}

pub fn validateMainValue(value: M31) direct.Error!void {
    if (value.v >= m31.Modulus) return error.InvalidTraceRow;
}

pub fn timesFour(value: u32) Error!usize {
    return std.math.mul(usize, value, component.QM31_WORD_COUNT) catch
        error.ArithmeticOverflow;
}

pub fn hashSlot(hash: anytype, slot: anytype) void {
    hashInt(hash, u8, slot.column);
    hashInt(hash, u32, @intFromEnum(slot.value));
    hashInt(hash, u8, @intFromEnum(slot.source));
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

pub fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
