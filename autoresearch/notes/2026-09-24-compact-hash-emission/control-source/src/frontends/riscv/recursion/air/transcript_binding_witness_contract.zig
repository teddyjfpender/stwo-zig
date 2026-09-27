//! Internal transcript binding witness authority shard; use transcript_binding_witness.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const digest = @import("../../air/lang/digest.zig");
pub const direct = @import("../../air/lang/direct_witness_executor.zig");
pub const types = @import("../../air/lang/types.zig");
pub const component = @import("transcript_binding.zig");
pub const proof_kind_mod = @import("proof_kind.zig");
pub const schedule = @import("verifier_schedule.zig");
pub const transcript = @import("pow_frame_witness.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const SEGMENT_VERIFIER_ID: u32 = 0;
pub const LEFT_RECURSION_VERIFIER_ID: u32 = 1;
pub const RIGHT_RECURSION_VERIFIER_ID: u32 = 2;
pub const RATE = component.RATE;
pub const WIDTH = transcript.WIDTH;
pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = component.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = proof_kind_mod.ProofKind;
pub const TranscriptTrace = transcript.TranscriptTrace;
pub const PoseidonCall = transcript.PoseidonCall;
pub const HashFrame = transcript.HashFrame;
pub const HashPurpose = transcript.HashPurpose;

pub const DIGEST_WORD_COUNT: usize = 8;
pub const PROTOCOL_BINDING_WORD_COUNT: usize = 2 * DIGEST_WORD_COUNT;
pub const OPERATION_HEADER_WORD_COUNT: usize = 8;
pub const DRAW_WORD_COUNT: usize = RATE + 2;
pub const POW_NONCE_WORD_COUNT: usize = 4;
pub const STATEMENT_WORD_COUNT: usize = 412;
pub const PCS_PARAMETER_WORD_COUNT: usize = 16;
pub const TRANSCRIPT_OPERATION_TAG: u32 = 0x5452;
pub const DRAW_TAG: u32 = transcript.DRAW_TAG;

pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-transcript-binding-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "4ec5fc3eb545ae97bcadf5ee7cbcea4be99d05b24df6642e4c94ac03fd2f1367";
pub const BINDING_DIGEST = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion transcript-binding witness digest",
);
pub const PREPROCESSING_FORMAT_VERSION: u16 = 1;
pub const PREPROCESSING_DOMAIN =
    "stwo-zig/typed-air/recursion-transcript-binding-preprocessing/v1\x00";
pub const WITNESS_FORMAT_VERSION: u16 = 1;
pub const WITNESS_DOMAIN =
    "stwo-zig/typed-air/recursion-transcript-binding-main/v1\x00";

pub const Error = direct.Error || schedule.Error || component.ValidationError ||
    std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    BindingMismatch,
    CallCountMismatch,
    CallIndexOutOfRange,
    FrameCountMismatch,
    InvalidFieldElement,
    InvalidPreprocessedRow,
    InvalidTranscriptLayout,
    InvalidTranscriptTrace,
    InvalidWitnessRow,
    LogSizeOutOfRange,
    PowCheckCountMismatch,
    PowCheckMismatch,
    SchemaMismatch,
    UnknownVerifierId,
};

pub const Binding = struct {
    format_version: u16,
    semantic_format_version: u16,
    semantic_digest: digest.Digest,
    source_authority_digest: digest.Digest,
    main: [MAIN_COLUMN_COUNT]types.ValueId,
    preprocessed: [PREPROCESSED_COLUMN_COUNT]types.ValueId,
    parameters: [component.PARAMETER_COUNT]types.ValueId,

    pub fn canonical(definition: *const component.Definition) !Binding {
        try definition.validate();
        return .{
            .format_version = BINDING_FORMAT_VERSION,
            .semantic_format_version = digest.typed_effect_format_version,
            .semantic_digest = component.SEMANTIC_DIGEST,
            .source_authority_digest = component.SOURCE_AUTHORITY_DIGEST,
            .main = definition.main.physical(),
            .preprocessed = definition.preprocessed.physical(),
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
        for (self.main) |value| hashInt(&hash, u32, @intFromEnum(value));
        for (self.preprocessed) |value| hashInt(&hash, u32, @intFromEnum(value));
        for (self.parameters) |value| hashInt(&hash, u32, @intFromEnum(value));
        return hash.finalResult();
    }
};

pub const PreprocessedRow = struct {
    row_mask: u32,
    segment_mask: u32,
    binary_mask: u32,
    verifier_id: u32,
    sequence: u32,
    tag: u32,
    args: [4]u32,
    call_id: u32,
    hash_id: u32,
    hash_step: u32,
    is_first: u32,
    is_last: u32,
    is_draw: u32,
    is_operation_first: u32,
    pow_final_mask: u32,

    pub fn values(self: PreprocessedRow) [PREPROCESSED_COLUMN_COUNT]M31 {
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
            M31.fromCanonical(self.call_id),
            M31.fromCanonical(self.hash_id),
            M31.fromCanonical(self.hash_step),
            M31.fromCanonical(self.is_first),
            M31.fromCanonical(self.is_last),
            M31.fromCanonical(self.is_draw),
            M31.fromCanonical(self.is_operation_first),
            M31.fromCanonical(self.pow_final_mask),
        };
    }
};

pub fn validatePlans(vm: *const schedule.Plan, recursion: *const schedule.Plan) Error!void {
    try vm.validate();
    try recursion.validate();
    if (vm.schema != .vm or recursion.schema != .recursion)
        return error.SchemaMismatch;
}

pub const TranscriptEffect = enum { mix, draw, pow };

pub fn transcriptEffect(step: schedule.VerifierStep) ?TranscriptEffect {
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

pub fn payloadWordCount(plan: *const schedule.Plan, step: schedule.VerifierStep) Error!usize {
    return switch (step) {
        .bind_protocol => PROTOCOL_BINDING_WORD_COUNT,
        .bind_statement => STATEMENT_WORD_COUNT,
        .bind_pcs_parameters => PCS_PARAMETER_WORD_COUNT,
        .absorb_trace_commitment, .absorb_fri_commitment => DIGEST_WORD_COUNT,
        .absorb_public_claim => if (plan.schema == .vm) DIGEST_WORD_COUNT else 0,
        .verify_and_absorb_interaction_pow, .verify_and_absorb_pcs_pow => POW_NONCE_WORD_COUNT,
        .absorb_claimed_sums => |item| try qm31WordCount(item.count),
        .absorb_sampled_values => |item| try qm31WordCount(item.count),
        .absorb_last_layer_coefficients => |item| try qm31WordCount(item.count),
        .draw_relation_challenge,
        .draw_composition_randomness,
        .draw_oods_point,
        .draw_deep_randomness,
        .draw_fri_alpha,
        .draw_query_block,
        => 0,
        else => error.InvalidTranscriptLayout,
    };
}

pub fn qm31WordCount(count: u32) Error!usize {
    return std.math.mul(usize, count, 4) catch error.ArithmeticOverflow;
}

pub fn frameCallCount(stream_words: usize) Error!usize {
    const with_marker = std.math.add(usize, stream_words, 1) catch
        return error.ArithmeticOverflow;
    return std.math.divCeil(usize, with_marker, RATE) catch
        return error.ArithmeticOverflow;
}

pub fn operationCallCount(plan: *const schedule.Plan, step: schedule.VerifierStep) Error!usize {
    const effect = transcriptEffect(step) orelse return error.InvalidTranscriptLayout;
    const mix_words = std.math.add(
        usize,
        DIGEST_WORD_COUNT + OPERATION_HEADER_WORD_COUNT,
        try payloadWordCount(plan, step),
    ) catch return error.ArithmeticOverflow;
    var result = try frameCallCount(mix_words);
    if (effect != .mix) result = std.math.add(
        usize,
        result,
        try frameCallCount(DRAW_WORD_COUNT),
    ) catch return error.ArithmeticOverflow;
    return result;
}

pub fn callCount(plan: *const schedule.Plan) Error!usize {
    var result: usize = 0;
    for (plan.steps) |step| {
        if (transcriptEffect(step) == null) continue;
        result = std.math.add(usize, result, try operationCallCount(plan, step)) catch
            return error.ArithmeticOverflow;
    }
    return result;
}

pub fn appendPlanRows(
    destination: []PreprocessedRow,
    cursor: *usize,
    plan: *const schedule.Plan,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Error!void {
    var call_id: usize = 0;
    var hash_id: usize = 0;
    for (plan.steps, 0..) |step, sequence| {
        const effect = transcriptEffect(step) orelse continue;
        const operation_calls = try operationCallCount(plan, step);
        const encoded = step.encode();
        const mix_words = std.math.add(
            usize,
            DIGEST_WORD_COUNT + OPERATION_HEADER_WORD_COUNT,
            try payloadWordCount(plan, step),
        ) catch return error.ArithmeticOverflow;
        const mix_calls = try frameCallCount(mix_words);
        try appendFrameRows(
            destination,
            cursor,
            verifier_id,
            segment_mask,
            binary_mask,
            @intCast(sequence),
            encoded,
            call_id,
            hash_id,
            mix_calls,
            false,
            true,
            false,
        );
        call_id = std.math.add(usize, call_id, mix_calls) catch
            return error.ArithmeticOverflow;
        hash_id = std.math.add(usize, hash_id, 1) catch
            return error.ArithmeticOverflow;
        if (effect != .mix) {
            const draw_calls = try frameCallCount(DRAW_WORD_COUNT);
            try appendFrameRows(
                destination,
                cursor,
                verifier_id,
                segment_mask,
                binary_mask,
                @intCast(sequence),
                encoded,
                call_id,
                hash_id,
                draw_calls,
                true,
                false,
                effect == .pow,
            );
            call_id = std.math.add(usize, call_id, draw_calls) catch
                return error.ArithmeticOverflow;
            hash_id = std.math.add(usize, hash_id, 1) catch
                return error.ArithmeticOverflow;
        }
        if (operation_calls == 0) return error.InvalidTranscriptLayout;
    }
    if (call_id > std.math.maxInt(u32) or hash_id > std.math.maxInt(u32))
        return error.CallIndexOutOfRange;
}

pub fn appendFrameRows(
    destination: []PreprocessedRow,
    cursor: *usize,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
    sequence: u32,
    encoded: schedule.EncodedStep,
    first_call: usize,
    hash_id: usize,
    call_count: usize,
    is_draw: bool,
    is_operation_first_frame: bool,
    pow_final: bool,
) Error!void {
    for (0..call_count) |hash_step| {
        const call_index = std.math.add(usize, first_call, hash_step) catch
            return error.ArithmeticOverflow;
        if (cursor.* >= destination.len or call_index >= m31.Modulus or
            hash_id >= m31.Modulus or hash_step >= m31.Modulus)
        {
            return error.CallIndexOutOfRange;
        }
        destination[cursor.*] = .{
            .row_mask = 1,
            .segment_mask = segment_mask,
            .binary_mask = binary_mask,
            .verifier_id = verifier_id,
            .sequence = sequence,
            .tag = encoded.tag,
            .args = encoded.args,
            .call_id = @intCast(call_index),
            .hash_id = @intCast(hash_id),
            .hash_step = @intCast(hash_step),
            .is_first = @intFromBool(hash_step == 0),
            .is_last = @intFromBool(hash_step + 1 == call_count),
            .is_draw = @intFromBool(is_draw),
            .is_operation_first = @intFromBool(is_operation_first_frame and hash_step == 0),
            .pow_final_mask = @intFromBool(pow_final and hash_step + 1 == call_count),
        };
        cursor.* += 1;
    }
}

pub fn comparePlanRows(
    actual: []const PreprocessedRow,
    cursor: *usize,
    plan: *const schedule.Plan,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Error!void {
    const count = try callCount(plan);
    const end = std.math.add(usize, cursor.*, count) catch
        return error.ArithmeticOverflow;
    if (end > actual.len) return error.AuthorityMismatch;
    // Compare without allocation by regenerating one fixed row at a time.
    var call_id: usize = 0;
    var hash_id: usize = 0;
    for (plan.steps, 0..) |step, sequence| {
        const effect = transcriptEffect(step) orelse continue;
        const encoded = step.encode();
        const mix_words = DIGEST_WORD_COUNT + OPERATION_HEADER_WORD_COUNT +
            try payloadWordCount(plan, step);
        const mix_calls = try frameCallCount(mix_words);
        try compareFrameRows(
            actual,
            cursor,
            verifier_id,
            segment_mask,
            binary_mask,
            @intCast(sequence),
            encoded,
            call_id,
            hash_id,
            mix_calls,
            false,
            true,
            false,
        );
        call_id = std.math.add(usize, call_id, mix_calls) catch
            return error.ArithmeticOverflow;
        hash_id = std.math.add(usize, hash_id, 1) catch
            return error.ArithmeticOverflow;
        if (effect != .mix) {
            const draw_calls = try frameCallCount(DRAW_WORD_COUNT);
            try compareFrameRows(
                actual,
                cursor,
                verifier_id,
                segment_mask,
                binary_mask,
                @intCast(sequence),
                encoded,
                call_id,
                hash_id,
                draw_calls,
                true,
                false,
                effect == .pow,
            );
            call_id = std.math.add(usize, call_id, draw_calls) catch
                return error.ArithmeticOverflow;
            hash_id = std.math.add(usize, hash_id, 1) catch
                return error.ArithmeticOverflow;
        }
    }
}

pub fn compareFrameRows(
    actual: []const PreprocessedRow,
    cursor: *usize,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
    sequence: u32,
    encoded: schedule.EncodedStep,
    first_call: usize,
    hash_id: usize,
    call_count: usize,
    is_draw: bool,
    operation_first: bool,
    pow_final: bool,
) Error!void {
    for (0..call_count) |hash_step| {
        const call_index = std.math.add(usize, first_call, hash_step) catch
            return error.ArithmeticOverflow;
        const expected = PreprocessedRow{
            .row_mask = 1,
            .segment_mask = segment_mask,
            .binary_mask = binary_mask,
            .verifier_id = verifier_id,
            .sequence = sequence,
            .tag = encoded.tag,
            .args = encoded.args,
            .call_id = @intCast(call_index),
            .hash_id = @intCast(hash_id),
            .hash_step = @intCast(hash_step),
            .is_first = @intFromBool(hash_step == 0),
            .is_last = @intFromBool(hash_step + 1 == call_count),
            .is_draw = @intFromBool(is_draw),
            .is_operation_first = @intFromBool(operation_first and hash_step == 0),
            .pow_final_mask = @intFromBool(pow_final and hash_step + 1 == call_count),
        };
        if (cursor.* >= actual.len or !std.meta.eql(actual[cursor.*], expected))
            return error.AuthorityMismatch;
        cursor.* += 1;
    }
}

pub fn validatePreprocessedRow(row: PreprocessedRow) Error!void {
    if (row.row_mask != 1 or row.segment_mask > 1 or row.binary_mask > 1 or
        row.segment_mask + row.binary_mask != 1 or row.verifier_id >= 3 or
        row.sequence >= m31.Modulus or row.tag >= m31.Modulus or
        row.call_id >= m31.Modulus or row.hash_id >= m31.Modulus or
        row.hash_step >= m31.Modulus or row.is_first > 1 or row.is_last > 1 or
        row.is_draw > 1 or row.is_operation_first > 1 or row.pow_final_mask > 1 or
        (row.is_first == 1) != (row.hash_step == 0) or
        (row.pow_final_mask == 1 and (row.is_draw != 1 or row.is_last != 1)) or
        (row.verifier_id == SEGMENT_VERIFIER_ID) != (row.segment_mask == 1))
    {
        return error.InvalidPreprocessedRow;
    }
    for (row.args) |arg| if (arg >= m31.Modulus)
        return error.InvalidFieldElement;
}

pub fn traceLogSize(row_count: usize) Error!u32 {
    const padded = std.math.ceilPowerOfTwo(usize, @max(row_count, 1)) catch
        return error.ArithmeticOverflow;
    const log_size: u32 = @max(MIN_LOG_SIZE, std.math.log2_int(usize, padded));
    if (log_size > MAX_LOG_SIZE) return error.LogSizeOutOfRange;
    return log_size;
}

pub fn preprocessingDigest(
    log_size: u32,
    vm_count: usize,
    recursion_count: usize,
    vm_schedule: [8]u32,
    recursion_schedule: [8]u32,
    rows: []const PreprocessedRow,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PREPROCESSING_DOMAIN);
    hashInt(&hash, u16, PREPROCESSING_FORMAT_VERSION);
    hash.update(&component.SOURCE_AUTHORITY_DIGEST);
    hashInt(&hash, u32, log_size);
    hashInt(&hash, u64, vm_count);
    hashInt(&hash, u64, recursion_count);
    for (vm_schedule) |word| hashInt(&hash, u32, word);
    for (recursion_schedule) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u64, rows.len);
    for (rows) |row| hashPreprocessedRow(&hash, row);
    return hash.finalResult();
}

pub fn hashPreprocessedRow(hash: anytype, row: PreprocessedRow) void {
    hashInt(hash, u32, row.row_mask);
    hashInt(hash, u32, row.segment_mask);
    hashInt(hash, u32, row.binary_mask);
    hashInt(hash, u32, row.verifier_id);
    hashInt(hash, u32, row.sequence);
    hashInt(hash, u32, row.tag);
    for (row.args) |word| hashInt(hash, u32, word);
    hashInt(hash, u32, row.call_id);
    hashInt(hash, u32, row.hash_id);
    hashInt(hash, u32, row.hash_step);
    hashInt(hash, u32, row.is_first);
    hashInt(hash, u32, row.is_last);
    hashInt(hash, u32, row.is_draw);
    hashInt(hash, u32, row.is_operation_first);
    hashInt(hash, u32, row.pow_final_mask);
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
