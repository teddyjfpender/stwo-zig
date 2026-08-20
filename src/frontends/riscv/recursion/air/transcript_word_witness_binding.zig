//! Internal transcript word witness authority shard; use transcript_word_witness.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const digest = @import("../../air/lang/digest.zig");
pub const direct = @import("../../air/lang/direct_witness_executor.zig");
pub const types = @import("../../air/lang/types.zig");
pub const component = @import("transcript_word.zig");
pub const proof_kind_mod = @import("proof_kind.zig");
pub const schedule = @import("verifier_schedule.zig");
pub const trace_mod = @import("pow_frame_witness.zig");

pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = component.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = proof_kind_mod.ProofKind;
pub const TranscriptTrace = trace_mod.TranscriptTrace;
pub const MIN_LOG_SIZE = component.MIN_LOG_SIZE;
pub const MAX_LOG_SIZE = component.MAX_LOG_SIZE;
pub const SEGMENT_VERIFIER_ID: u32 = 0;
pub const LEFT_RECURSION_VERIFIER_ID: u32 = 1;
pub const RIGHT_RECURSION_VERIFIER_ID: u32 = 2;

pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-transcript-word-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "7aac0c47922bf9b9270284d408586487889914e3709de4426f6f1bd54c0914f8";
pub const BINDING_DIGEST = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion transcript-word witness-binding digest",
);
pub const PREPROCESSING_FORMAT_VERSION: u16 = 1;
pub const PREPROCESSING_DOMAIN =
    "stwo-zig/typed-air/recursion-transcript-word-preprocessing/v1\x00";
pub const PREPARED_BATCH_FORMAT_VERSION: u16 = 1;
pub const PREPARED_BATCH_DOMAIN =
    "stwo-zig/typed-air/recursion-transcript-word-batch/v1\x00";

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
    hash_id = 10,
    word_index = 11,
    is_payload = 12,
    payload_index = 13,
    constant_value = 14,
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
    std.mem.Allocator.Error || error{
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
    hash_id: u32,
    word_index: u32,
    is_payload: u32,
    payload_index: u32,
    constant_value: u32,

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
            M31.fromCanonical(self.hash_id),
            M31.fromCanonical(self.word_index),
            M31.fromCanonical(self.is_payload),
            M31.fromCanonical(self.payload_index),
            M31.fromCanonical(self.constant_value),
        };
    }
};

pub const BinarySource = struct {
    left: *const TranscriptTrace,
    right: *const TranscriptTrace,
};

pub const Source = union(ProofKind) {
    segment_leaf: *const TranscriptTrace,
    binary_node: BinarySource,
    empty_leaf: void,
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
        .bind_protocol => 2 * component.DIGEST_WORD_COUNT,
        .bind_statement => component.STATEMENT_WORD_COUNT,
        .bind_pcs_parameters => component.PCS_PARAMETER_WORD_COUNT,
        .absorb_trace_commitment, .absorb_fri_commitment => component.DIGEST_WORD_COUNT,
        .absorb_public_claim => if (schema == .vm)
            component.DIGEST_WORD_COUNT
        else
            0,
        .verify_and_absorb_interaction_pow, .verify_and_absorb_pcs_pow => component.POW_NONCE_WORD_COUNT,
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
        const effect = transcriptEffect(step) orelse continue;
        const payload_count = try payloadWordCount(plan.schema, step);
        const raw_mix = std.math.add(
            usize,
            2 * component.RATE,
            payload_count,
        ) catch return error.ArithmeticOverflow;
        const padded_mix = try paddedWordCount(raw_mix);
        result = std.math.add(
            usize,
            result,
            padded_mix - component.DIGEST_WORD_COUNT,
        ) catch return error.ArithmeticOverflow;
        if (effect != .mix) {
            // A draw frame is 8 digest words, two constants, one delimiter,
            // and five zero-padding words: exactly eight row-4 words.
            result = std.math.add(usize, result, component.RATE) catch
                return error.ArithmeticOverflow;
        }
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
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Error!void {
    var hash_id: u32 = 0;
    for (plan.steps, 0..) |step, sequence| {
        const effect = transcriptEffect(step) orelse continue;
        const payload_count = try payloadWordCount(plan.schema, step);
        try emitMixFrame(
            sink,
            verifier_id,
            segment_mask,
            binary_mask,
            @intCast(sequence),
            step,
            hash_id,
            payload_count,
        );
        hash_id = std.math.add(u32, hash_id, 1) catch
            return error.ArithmeticOverflow;
        if (effect != .mix) {
            try emitDrawFrame(
                sink,
                verifier_id,
                segment_mask,
                binary_mask,
                @intCast(sequence),
                step,
                hash_id,
            );
            hash_id = std.math.add(u32, hash_id, 1) catch
                return error.ArithmeticOverflow;
        }
    }
}

pub fn emitMixFrame(
    sink: *Sink,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
    sequence: u32,
    step: schedule.VerifierStep,
    hash_id: u32,
    payload_count: usize,
) Error!void {
    const encoded = step.encode();
    const header: [component.TRANSCRIPT_HEADER_WORD_COUNT]u32 = .{
        component.TRANSCRIPT_OPERATION_TAG,
        sequence,
        encoded.tag,
        @as(u32, encoded.arity),
    } ++ encoded.args;
    const raw_count = std.math.add(
        usize,
        2 * component.RATE,
        payload_count,
    ) catch return error.ArithmeticOverflow;
    const padded_count = try paddedWordCount(raw_count);
    for (component.DIGEST_WORD_COUNT..padded_count) |word_index| {
        const is_header = word_index < 2 * component.RATE;
        const payload_end = std.math.add(
            usize,
            2 * component.RATE,
            payload_count,
        ) catch return error.ArithmeticOverflow;
        const is_payload = word_index >= 2 * component.RATE and
            word_index < payload_end;
        const constant_value: u32 = if (is_header)
            header[word_index - component.RATE]
        else if (word_index == payload_end)
            1
        else
            0;
        try sink.put(.{
            .row_mask = 1,
            .segment_mask = segment_mask,
            .binary_mask = binary_mask,
            .verifier_id = verifier_id,
            .sequence = sequence,
            .tag = encoded.tag,
            .args = encoded.args,
            .hash_id = hash_id,
            .word_index = @intCast(word_index),
            .is_payload = @intFromBool(is_payload),
            .payload_index = if (is_payload)
                @intCast(word_index - 2 * component.RATE)
            else
                0,
            .constant_value = constant_value,
        });
    }
}

pub fn emitDrawFrame(
    sink: *Sink,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
    sequence: u32,
    step: schedule.VerifierStep,
    hash_id: u32,
) Error!void {
    const encoded = step.encode();
    for (component.DIGEST_WORD_COUNT..2 * component.RATE) |word_index| {
        const constant_value: u32 = switch (word_index) {
            component.DIGEST_WORD_COUNT => component.DRAW_COUNTER,
            component.DIGEST_WORD_COUNT + 1 => component.DRAW_TAG,
            component.DIGEST_WORD_COUNT + 2 => 1,
            else => 0,
        };
        try sink.put(.{
            .row_mask = 1,
            .segment_mask = segment_mask,
            .binary_mask = binary_mask,
            .verifier_id = verifier_id,
            .sequence = sequence,
            .tag = encoded.tag,
            .args = encoded.args,
            .hash_id = hash_id,
            .word_index = @intCast(word_index),
            .is_payload = 0,
            .payload_index = 0,
            .constant_value = constant_value,
        });
    }
}

pub fn validateRow(row: Row) direct.Error!void {
    if (row.row_mask != 1 or row.segment_mask > 1 or row.binary_mask > 1 or
        row.segment_mask + row.binary_mask != 1 or row.is_payload > 1 or
        row.word_index < component.DIGEST_WORD_COUNT or
        row.verifier_id >= m31.Modulus or row.sequence >= m31.Modulus or
        row.tag >= m31.Modulus or row.hash_id >= m31.Modulus or
        row.word_index >= m31.Modulus or row.payload_index >= m31.Modulus or
        row.constant_value >= m31.Modulus or
        (row.is_payload == 1 and row.constant_value != 0) or
        (row.is_payload == 0 and row.payload_index != 0))
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
}

pub fn writePreprocessedRow(
    columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
    logical_row: usize,
    row: Row,
) void {
    const values = row.values();
    inline for (0..PREPROCESSED_COLUMN_COUNT) |column|
        columns[column][logical_row] = values[column];
}

pub const Receipts = struct {
    lane_count: u8,
    schedules: [2][8]u32,
    transcripts: [2]digest.Digest,
};

pub fn preprocessingDigest(
    log_size: u32,
    vm_rows: usize,
    recursion_rows: usize,
    vm_schedule: [8]u32,
    recursion_schedule: [8]u32,
    rows: []const Row,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PREPROCESSING_DOMAIN);
    hashInt(&hash, u16, PREPROCESSING_FORMAT_VERSION);
    hash.update(&component.SOURCE_AUTHORITY_DIGEST);
    hashInt(&hash, u32, log_size);
    hashInt(&hash, u64, vm_rows);
    hashInt(&hash, u64, recursion_rows);
    for (vm_schedule) |word| hashInt(&hash, u32, word);
    for (recursion_schedule) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u64, rows.len);
    for (rows) |row| hashRow(&hash, row);
    return hash.finalResult();
}

pub fn batchDigest(
    kind: ProofKind,
    preprocessing_digest: digest.Digest,
    receipts: Receipts,
    values: []const M31,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PREPARED_BATCH_DOMAIN);
    hashInt(&hash, u16, PREPARED_BATCH_FORMAT_VERSION);
    hash.update(&component.SOURCE_AUTHORITY_DIGEST);
    hashInt(&hash, u8, @intFromEnum(kind));
    hash.update(&preprocessing_digest);
    hashInt(&hash, u8, receipts.lane_count);
    for (receipts.schedules) |receipt| for (receipt) |word|
        hashInt(&hash, u32, word);
    for (receipts.transcripts) |receipt| hash.update(&receipt);
    hashInt(&hash, u64, values.len);
    for (values) |value| hashInt(&hash, u32, value.v);
    return hash.finalResult();
}

pub fn hashRow(hash: anytype, row: Row) void {
    hashInt(hash, u32, row.row_mask);
    hashInt(hash, u32, row.segment_mask);
    hashInt(hash, u32, row.binary_mask);
    hashInt(hash, u32, row.verifier_id);
    hashInt(hash, u32, row.sequence);
    hashInt(hash, u32, row.tag);
    for (row.args) |arg| hashInt(hash, u32, arg);
    hashInt(hash, u32, row.hash_id);
    hashInt(hash, u32, row.word_index);
    hashInt(hash, u32, row.is_payload);
    hashInt(hash, u32, row.payload_index);
    hashInt(hash, u32, row.constant_value);
}

pub fn paddedWordCount(raw_count: usize) Error!usize {
    const with_marker = std.math.add(usize, raw_count, 1) catch
        return error.ArithmeticOverflow;
    const chunks = std.math.divCeil(usize, with_marker, component.RATE) catch
        return error.ArithmeticOverflow;
    return std.math.mul(usize, chunks, component.RATE) catch
        return error.ArithmeticOverflow;
}

pub fn timesFour(value: u32) Error!usize {
    return std.math.mul(usize, value, 4) catch error.ArithmeticOverflow;
}

pub fn logSizeFor(row_count: usize) Error!u32 {
    const log_size: u32 = @max(
        MIN_LOG_SIZE,
        @as(u32, @intCast(std.math.log2_int_ceil(usize, @max(row_count, 1)))),
    );
    if (log_size > MAX_LOG_SIZE) return error.LogSizeOutOfRange;
    return log_size;
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
