//! Internal transcript air witness authority shard; use transcript_air_witness.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const digest = @import("../../air/lang/digest.zig");
pub const direct = @import("../../air/lang/direct_witness_executor.zig");
pub const poseidon2 = @import("../../air/memory_commitment/poseidon2.zig");
pub const poseidon_executor = @import("../../air/lang/typed_poseidon2_witness.zig");
pub const types = @import("../../air/lang/types.zig");
pub const component = @import("transcript_air.zig");
pub const binding_witness = @import("transcript_binding_witness.zig");
pub const proof_kind_mod = @import("proof_kind.zig");
pub const schedule = @import("verifier_schedule.zig");
pub const trace_mod = @import("pow_frame_witness.zig");

pub const RATE = component.RATE;
pub const WIDTH = component.WIDTH;
pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const SEGMENT_VERIFIER_ID: u32 = binding_witness.SEGMENT_VERIFIER_ID;
pub const LEFT_RECURSION_VERIFIER_ID: u32 =
    binding_witness.LEFT_RECURSION_VERIFIER_ID;
pub const RIGHT_RECURSION_VERIFIER_ID: u32 =
    binding_witness.RIGHT_RECURSION_VERIFIER_ID;
pub const ProofKind = proof_kind_mod.ProofKind;
pub const TranscriptTrace = trace_mod.TranscriptTrace;
pub const PoseidonCall = trace_mod.PoseidonCall;
pub const HashFrame = trace_mod.HashFrame;
pub const HashPurpose = trace_mod.HashPurpose;
pub const DRAW_TAG: u32 = trace_mod.DRAW_TAG;
pub const Lane = binding_witness.Lane;
pub const BinaryLanes = binding_witness.BinaryLanes;
pub const Source = binding_witness.Source;
pub const ProviderCall = poseidon_executor.Call;

pub const DIGEST_WORD_COUNT: usize = 8;
pub const PROTOCOL_BINDING_WORD_COUNT: usize = 2 * DIGEST_WORD_COUNT;
pub const OPERATION_HEADER_WORD_COUNT: usize = 8;
pub const DRAW_WORD_COUNT: usize = RATE + 2;
pub const POW_NONCE_WORD_COUNT: usize = 4;
pub const STATEMENT_WORD_COUNT: usize = 412;
pub const PCS_PARAMETER_WORD_COUNT: usize = 16;
pub const TRANSCRIPT_OPERATION_TAG: u32 = 0x5452;

pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-transcript-air-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "7303f29001bf144e146e08606189861399a6af24741f377a2403bb4e463fe78d";
pub const BINDING_DIGEST = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion transcript-air witness binding",
);
pub const PREPARED_BATCH_FORMAT_VERSION: u16 = 1;
pub const PREPARED_BATCH_DOMAIN =
    "stwo-zig/typed-air/recursion-transcript-air-batch/v1\x00";

pub const Slot = struct {
    column: u8,
    value: types.ValueId,
    source: u8,
};

pub const Binding = struct {
    format_version: u16,
    semantic_format_version: u16,
    semantic_digest: digest.Digest,
    source_authority_digest: digest.Digest,
    main: [MAIN_COLUMN_COUNT]Slot,

    pub fn canonical(definition: *const component.Definition) ConstructionError!Binding {
        try definition.validate();
        var main: [MAIN_COLUMN_COUNT]Slot = undefined;
        for (&main, definition.main.physical(), 0..) |*slot, value, column| {
            slot.* = .{
                .column = @intCast(column),
                .value = value,
                .source = @intCast(column),
            };
        }
        return .{
            .format_version = BINDING_FORMAT_VERSION,
            .semantic_format_version = digest.typed_effect_format_version,
            .semantic_digest = component.SEMANTIC_DIGEST,
            .source_authority_digest = component.SOURCE_AUTHORITY_DIGEST,
            .main = main,
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
        for (self.main) |slot| {
            hashInt(&hash, u8, slot.column);
            hashInt(&hash, u32, @intFromEnum(slot.value));
            hashInt(&hash, u8, slot.source);
        }
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
    CallCountMismatch,
    FrameCountMismatch,
    InvalidFieldElement,
    InvalidProviderCallGeometry,
    InvalidTranscriptLayout,
    InvalidTranscriptSource,
    InvalidWitnessBinding,
    InvalidWitnessRow,
    LogSizeOutOfRange,
    PowCheckCountMismatch,
    PowCheckMismatch,
    RecordedPoseidonOutputMismatch,
    SchemaMismatch,
};

pub const Row = struct {
    enabler: u32,
    verifier_id: u32,
    call_id: u32,
    hash_id: u32,
    step: u32,
    is_first: u32,
    is_last: u32,
    is_draw: u32,
    previous: [WIDTH]M31,
    chunk: [RATE]M31,
    output: [WIDTH]M31,

    pub fn values(self: Row) [MAIN_COLUMN_COUNT]M31 {
        return .{
            M31.fromCanonical(self.enabler),
            M31.fromCanonical(self.verifier_id),
            M31.fromCanonical(self.call_id),
            M31.fromCanonical(self.hash_id),
            M31.fromCanonical(self.step),
            M31.fromCanonical(self.is_first),
            M31.fromCanonical(self.is_last),
            M31.fromCanonical(self.is_draw),
        } ++ self.previous ++ self.chunk ++ self.output;
    }

    pub fn providerInput(self: Row) [WIDTH]u32 {
        var input: [WIDTH]u32 = undefined;
        for (&input, self.previous) |*target, value| target.* = value.v;
        for (self.previous[0..RATE], self.chunk, 0..) |previous, chunk, index|
            input[index] = previous.add(chunk).v;
        return input;
    }
};

pub fn providerCallAssumeValid(row: Row) ProviderCall {
    return .{
        .input = row.providerInput(),
        .wide = false,
        .io = true,
        .narrow_output = null,
    };
}

pub fn validateSource(source_value: Source) Error!void {
    switch (source_value) {
        .segment_leaf => |lane| try validateLane(lane, .vm),
        .binary_node => |lanes| {
            try validateLane(lanes.left, .recursion);
            try validateLane(lanes.right, .recursion);
        },
        .empty_leaf => {},
    }
}

pub fn validateLane(lane: Lane, expected_schema: schedule.Schema) Error!void {
    try lane.plan.validate();
    if (lane.plan.schema != expected_schema) return error.SchemaMismatch;
    lane.trace.validate() catch return error.InvalidTranscriptSource;
    if (lane.trace.poseidon_calls.len != try callCount(lane.plan))
        return error.CallCountMismatch;

    var frame_at: usize = 0;
    var call_at: usize = 0;
    var pow_at: usize = 0;
    for (lane.plan.steps, 0..) |step, sequence| {
        const effect = transcriptEffect(step) orelse continue;
        const encoded = step.encode();
        const payload_words = try payloadWordCount(lane.plan, step);
        _ = try validateFrame(
            lane.trace,
            &frame_at,
            &call_at,
            .mix,
            DIGEST_WORD_COUNT + OPERATION_HEADER_WORD_COUNT + payload_words,
            @intCast(sequence),
            encoded,
            true,
        );
        if (effect != .mix) {
            const final_call = try validateFrame(
                lane.trace,
                &frame_at,
                &call_at,
                .draw,
                DRAW_WORD_COUNT,
                @intCast(sequence),
                encoded,
                false,
            );
            if (effect == .pow) {
                if (pow_at >= lane.trace.pow_checks.len)
                    return error.PowCheckCountMismatch;
                const check = lane.trace.pow_checks[pow_at];
                const bits = powBits(step) orelse
                    return error.InvalidTranscriptLayout;
                if (check.call_id != final_call or check.bits != bits or
                    !check.word.eql(lane.trace.poseidon_calls[final_call].output[0]))
                {
                    return error.PowCheckMismatch;
                }
                pow_at += 1;
            }
        }
    }
    if (frame_at != lane.trace.hash_frames.len)
        return error.FrameCountMismatch;
    if (call_at != lane.trace.poseidon_calls.len)
        return error.CallCountMismatch;
    if (pow_at != lane.trace.pow_checks.len)
        return error.PowCheckCountMismatch;

    // This mirrors Stark-V's materialization check while keeping the AIR
    // authority in the shared provider. It is a cold source-integrity gate.
    for (lane.trace.poseidon_calls) |call| {
        var expected = call.input;
        poseidon2.permute(&expected);
        if (!fieldArrayEql(WIDTH, expected, call.output))
            return error.RecordedPoseidonOutputMismatch;
    }
}

pub fn validateFrame(
    trace: *const TranscriptTrace,
    frame_at: *usize,
    call_at: *usize,
    purpose: HashPurpose,
    stream_words: usize,
    sequence: u32,
    encoded: schedule.EncodedStep,
    is_mix: bool,
) Error!u32 {
    if (frame_at.* >= trace.hash_frames.len) return error.FrameCountMismatch;
    const frame = trace.hash_frames[frame_at.*];
    const expected_calls = try frameCallCount(stream_words);
    if (frame.hash_id != frame_at.* or frame.first_call_id != call_at.* or
        frame.call_count != expected_calls or frame.purpose != purpose or
        frame.words.len != stream_words)
    {
        return error.InvalidTranscriptLayout;
    }
    if (is_mix) {
        const header = [_]u32{
            TRANSCRIPT_OPERATION_TAG,
            sequence,
            encoded.tag,
            encoded.arity,
            encoded.args[0],
            encoded.args[1],
            encoded.args[2],
            encoded.args[3],
        };
        for (header, 0..) |expected, index| {
            if (frame.words[DIGEST_WORD_COUNT + index].v != expected)
                return error.InvalidTranscriptLayout;
        }
    } else if (frame.words[RATE].v != 0 or
        frame.words[RATE + 1].v != DRAW_TAG)
    {
        return error.InvalidTranscriptLayout;
    }
    for (0..expected_calls) |step| {
        const call_index = std.math.add(usize, call_at.*, step) catch
            return error.ArithmeticOverflow;
        if (call_index >= trace.poseidon_calls.len)
            return error.CallCountMismatch;
        const call = trace.poseidon_calls[call_index];
        if (call.id.call_id != call_index or
            call.id.hash_id != frame_at.* or call.id.step != step)
        {
            return error.InvalidTranscriptLayout;
        }
    }
    const call_end = std.math.add(usize, call_at.*, expected_calls) catch
        return error.ArithmeticOverflow;
    const final_call: u32 = @intCast(call_end - 1);
    call_at.* = call_end;
    frame_at.* = std.math.add(usize, frame_at.*, 1) catch
        return error.ArithmeticOverflow;
    return final_call;
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

pub fn powBits(step: schedule.VerifierStep) ?u32 {
    return switch (step) {
        .verify_and_absorb_interaction_pow => |item| item.bits,
        .verify_and_absorb_pcs_pow => |item| item.bits,
        else => null,
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
    const effect = transcriptEffect(step) orelse
        return error.InvalidTranscriptLayout;
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
        result = std.math.add(
            usize,
            result,
            try operationCallCount(plan, step),
        ) catch return error.ArithmeticOverflow;
    }
    return result;
}

pub fn fillLane(
    destination: []Row,
    at: *usize,
    verifier_id: u32,
    trace: *const TranscriptTrace,
) void {
    for (trace.hash_frames) |frame| {
        var previous = [_]M31{M31.zero()} ** WIDTH;
        for (0..frame.call_count) |step| {
            const call = trace.poseidon_calls[frame.first_call_id + step];
            destination[at.*] = rowFromCall(
                verifier_id,
                frame,
                call,
                previous,
            );
            previous = call.output;
            at.* += 1;
        }
    }
}

pub fn compareLane(
    expected: []const Row,
    at: *usize,
    verifier_id: u32,
    trace: *const TranscriptTrace,
) Error!void {
    for (trace.hash_frames) |frame| {
        var previous = [_]M31{M31.zero()} ** WIDTH;
        for (0..frame.call_count) |step| {
            if (at.* >= expected.len) return error.AuthorityMismatch;
            const call = trace.poseidon_calls[frame.first_call_id + step];
            const actual = rowFromCall(verifier_id, frame, call, previous);
            if (!std.meta.eql(expected[at.*], actual))
                return error.AuthorityMismatch;
            previous = call.output;
            at.* += 1;
        }
    }
}

pub fn rowFromCall(
    verifier_id: u32,
    frame: HashFrame,
    call: PoseidonCall,
    previous: [WIDTH]M31,
) Row {
    var chunk: [RATE]M31 = undefined;
    for (&chunk, call.input[0..RATE], previous[0..RATE]) |*target, input, prior|
        target.* = input.sub(prior);
    return .{
        .enabler = 1,
        .verifier_id = verifier_id,
        .call_id = call.id.call_id,
        .hash_id = call.id.hash_id,
        .step = call.id.step,
        .is_first = @intFromBool(call.id.step == 0),
        .is_last = @intFromBool(frame.finalCallId().? == call.id.call_id),
        .is_draw = @intFromBool(frame.purpose == .draw),
        .previous = previous,
        .chunk = chunk,
        .output = call.output,
    };
}

pub const Receipts = struct {
    lane_count: u8,
    lane_rows: [2]usize,
    schedules: [2][8]u32,
    transcripts: [2]digest.Digest,
};

pub fn sourceReceipts(source_value: Source) Receipts {
    var result = Receipts{
        .lane_count = 0,
        .lane_rows = .{ 0, 0 },
        .schedules = .{.{0} ** 8} ** 2,
        .transcripts = .{.{0} ** 32} ** 2,
    };
    switch (source_value) {
        .segment_leaf => |lane| {
            result.lane_count = 1;
            result.lane_rows[0] = lane.trace.poseidon_calls.len;
            result.schedules[0] = lane.plan.authority_digest;
            result.transcripts[0] = lane.trace.receiptDigest();
        },
        .binary_node => |lanes| {
            result.lane_count = 2;
            result.lane_rows[0] = lanes.left.trace.poseidon_calls.len;
            result.lane_rows[1] = lanes.right.trace.poseidon_calls.len;
            result.schedules[0] = lanes.left.plan.authority_digest;
            result.schedules[1] = lanes.right.plan.authority_digest;
            result.transcripts[0] = lanes.left.trace.receiptDigest();
            result.transcripts[1] = lanes.right.trace.receiptDigest();
        },
        .empty_leaf => {},
    }
    return result;
}

pub fn validateRow(row: Row) Error!void {
    if (row.enabler != 1 or row.verifier_id > RIGHT_RECURSION_VERIFIER_ID or
        row.call_id >= m31.Modulus or row.hash_id >= m31.Modulus or
        row.step >= m31.Modulus or row.is_first > 1 or row.is_last > 1 or
        row.is_draw > 1 or (row.is_first == 1) != (row.step == 0))
    {
        return error.InvalidWitnessRow;
    }
    for (row.previous) |word| if (word.v >= m31.Modulus)
        return error.InvalidFieldElement;
    for (row.chunk) |word| if (word.v >= m31.Modulus)
        return error.InvalidFieldElement;
    for (row.output) |word| if (word.v >= m31.Modulus)
        return error.InvalidFieldElement;
    if (row.is_first == 1) for (row.previous) |word| {
        if (!word.isZero()) return error.InvalidWitnessRow;
    };
}

pub fn validateRowDirect(row: Row) direct.Error!void {
    validateRow(row) catch return error.InvalidTraceRow;
}

pub fn writeRow(
    columns: *[MAIN_COLUMN_COUNT][]M31,
    logical_row: usize,
    row: Row,
) void {
    const values = row.values();
    inline for (0..MAIN_COLUMN_COUNT) |column|
        columns[column][logical_row] = values[column];
}

pub fn fieldArrayEql(
    comptime count: usize,
    lhs: [count]M31,
    rhs: [count]M31,
) bool {
    for (lhs, rhs) |left, right| if (!left.eql(right)) return false;
    return true;
}

pub fn protectHeader(columns: anytype, object: anytype) direct.Error!void {
    const header = try objectRange(object);
    const descriptors = try objectRange(columns);
    if (header.overlaps(descriptors)) return error.AliasedInput;
    for (columns.*) |column| {
        const destination = (try sliceRange(M31, column)) orelse continue;
        if (destination.overlaps(header)) return error.AliasedInput;
    }
}

pub const AddressRange = struct {
    start: usize,
    end: usize,

    pub fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

pub fn objectRange(pointer: anytype) direct.Error!AddressRange {
    const info = @typeInfo(@TypeOf(pointer));
    if (info != .pointer or info.pointer.size != .one)
        @compileError("protected header must be a single-item pointer");
    const start = @intFromPtr(pointer);
    const end = std.math.add(usize, start, @sizeOf(info.pointer.child)) catch
        return error.AddressOverflow;
    return .{ .start = start, .end = end };
}

pub fn sliceRange(comptime T: type, values: []const T) direct.Error!?AddressRange {
    if (values.len == 0) return null;
    const bytes = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    const end = std.math.add(usize, start, bytes) catch
        return error.AddressOverflow;
    return .{ .start = start, .end = end };
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
