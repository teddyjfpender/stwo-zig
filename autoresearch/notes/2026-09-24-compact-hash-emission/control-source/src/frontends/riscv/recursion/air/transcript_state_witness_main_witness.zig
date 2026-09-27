//! Internal transcript state witness authority shard; use transcript_state_witness.zig publicly.

const dependency_0 = @import("transcript_state_witness_contract.zig");

const BINDING_DIGEST = dependency_0.BINDING_DIGEST;
const Binding = dependency_0.Binding;
const DIGEST_WORD_COUNT = dependency_0.DIGEST_WORD_COUNT;
const DRAW_TAG = dependency_0.DRAW_TAG;
const DRAW_WORD_COUNT = dependency_0.DRAW_WORD_COUNT;
const Error = dependency_0.Error;
const HashPurpose = dependency_0.HashPurpose;
const LEFT_RECURSION_VERIFIER_ID = dependency_0.LEFT_RECURSION_VERIFIER_ID;
const Lane = dependency_0.Lane;
const M31 = dependency_0.M31;
const MAIN_COLUMN_COUNT = dependency_0.MAIN_COLUMN_COUNT;
const MainRow = dependency_0.MainRow;
const OPERATION_HEADER_WORD_COUNT = dependency_0.OPERATION_HEADER_WORD_COUNT;
const PCS_PARAMETER_WORD_COUNT = dependency_0.PCS_PARAMETER_WORD_COUNT;
const POW_NONCE_WORD_COUNT = dependency_0.POW_NONCE_WORD_COUNT;
const PREPROCESSED_COLUMN_COUNT = dependency_0.PREPROCESSED_COLUMN_COUNT;
const PROTOCOL_BINDING_WORD_COUNT = dependency_0.PROTOCOL_BINDING_WORD_COUNT;
const Preprocessed = dependency_0.Preprocessed;
const PreprocessedRow = dependency_0.PreprocessedRow;
const ProofKind = dependency_0.ProofKind;
const RATE = dependency_0.RATE;
const RIGHT_RECURSION_VERIFIER_ID = dependency_0.RIGHT_RECURSION_VERIFIER_ID;
const SEGMENT_VERIFIER_ID = dependency_0.SEGMENT_VERIFIER_ID;
const STATEMENT_WORD_COUNT = dependency_0.STATEMENT_WORD_COUNT;
const Source = dependency_0.Source;
const TRANSCRIPT_OPERATION_TAG = dependency_0.TRANSCRIPT_OPERATION_TAG;
const TranscriptTrace = dependency_0.TranscriptTrace;
const WITNESS_DOMAIN = dependency_0.WITNESS_DOMAIN;
const WITNESS_FORMAT_VERSION = dependency_0.WITNESS_FORMAT_VERSION;
const component = dependency_0.component;
const digest = dependency_0.digest;
const direct = dependency_0.direct;
const hashInt = dependency_0.hashInt;
const m31 = dependency_0.m31;
const schedule = dependency_0.schedule;
const std = dependency_0.std;
const validatePreprocessedRow = dependency_0.validatePreprocessedRow;

pub const MainWitness = struct {
    allocator: std.mem.Allocator,
    rows: []MainRow,
    proof_kind: ProofKind,
    preprocessing_digest: digest.Digest,
    lane_count: u8,
    schedule_receipts: [2][8]u32,
    transcript_receipts: [2]digest.Digest,
    authority_digest: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        preprocessing: *const Preprocessed,
        source_value: Source,
    ) Error!MainWitness {
        try preprocessing.validate();
        try validateSource(source_value);
        try sourceMatchesPreprocessing(preprocessing, source_value);
        const rows = try allocator.alloc(MainRow, preprocessing.rows.len);
        errdefer allocator.free(rows);
        for (rows, preprocessing.rows) |*target, metadata| {
            target.* = try rowForSource(source_value, metadata);
            try validateMainRowFor(metadata, std.meta.activeTag(source_value), target.*);
        }
        const receipts = sourceReceipts(source_value);
        const authority_digest = witnessDigest(
            std.meta.activeTag(source_value),
            preprocessing.authority_digest,
            receipts.lane_count,
            receipts.schedules,
            receipts.transcripts,
            rows,
        );
        return .{
            .allocator = allocator,
            .rows = rows,
            .proof_kind = std.meta.activeTag(source_value),
            .preprocessing_digest = preprocessing.authority_digest,
            .lane_count = receipts.lane_count,
            .schedule_receipts = receipts.schedules,
            .transcript_receipts = receipts.transcripts,
            .authority_digest = authority_digest,
        };
    }

    pub fn deinit(self: *MainWitness) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const MainWitness,
        preprocessing: *const Preprocessed,
    ) Error!void {
        try preprocessing.validate();
        const expected_lanes: u8 = switch (self.proof_kind) {
            .segment_leaf => 1,
            .binary_node => 2,
            .empty_leaf => 0,
        };
        if (!std.mem.eql(u8, &self.preprocessing_digest, &preprocessing.authority_digest) or
            self.rows.len != preprocessing.rows.len or self.lane_count != expected_lanes)
        {
            return error.AuthorityMismatch;
        }
        for (self.rows, preprocessing.rows) |row, metadata|
            try validateMainRowFor(metadata, self.proof_kind, row);
        const actual = witnessDigest(
            self.proof_kind,
            self.preprocessing_digest,
            self.lane_count,
            self.schedule_receipts,
            self.transcript_receipts,
            self.rows,
        );
        if (!std.mem.eql(u8, &actual, &self.authority_digest))
            return error.AuthorityMismatch;
    }

    pub fn validateAgainstSource(
        self: *const MainWitness,
        preprocessing: *const Preprocessed,
        source_value: Source,
    ) Error!void {
        try self.validateAgainst(preprocessing);
        if (std.meta.activeTag(source_value) != self.proof_kind)
            return error.AuthorityMismatch;
        try validateSource(source_value);
        try sourceMatchesPreprocessing(preprocessing, source_value);
        const receipts = sourceReceipts(source_value);
        if (receipts.lane_count != self.lane_count or
            !std.meta.eql(receipts.schedules, self.schedule_receipts) or
            !std.meta.eql(receipts.transcripts, self.transcript_receipts))
        {
            return error.AuthorityMismatch;
        }
        for (self.rows, preprocessing.rows) |row, metadata| {
            const expected = try rowForSource(source_value, metadata);
            if (!std.meta.eql(row, expected)) return error.AuthorityMismatch;
        }
    }
};

pub const Executor = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const component.Definition,
        supplied: *const Binding,
    ) Error!Executor {
        const expected = try Binding.canonical(definition);
        if (!std.meta.eql(expected, supplied.*)) return error.BindingMismatch;
        const actual = supplied.identityDigest();
        if (!std.mem.eql(u8, &actual, &BINDING_DIGEST))
            return error.BindingMismatch;
        return .{ .binding = supplied.*, .binding_digest = actual };
    }

    pub fn validate(self: *const Executor) Error!void {
        const actual = self.binding.identityDigest();
        if (!std.mem.eql(u8, &actual, &self.binding_digest) or
            !std.mem.eql(u8, &actual, &BINDING_DIGEST) or
            !std.mem.eql(u8, &self.binding.source_authority_digest, &component.SOURCE_AUTHORITY_DIGEST))
        {
            return error.BindingMismatch;
        }
    }

    pub fn generatePreprocessedInto(
        self: *const Executor,
        preprocessing: *const Preprocessed,
        columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
    ) Error!void {
        try self.validate();
        try preprocessing.validate();
        try protectHeader(columns, preprocessing);
        return direct.generateMainInto(
            M31,
            PreprocessedRow,
            PREPROCESSED_COLUMN_COUNT,
            columns,
            preprocessing.rows,
            preprocessing.log_size,
            M31.zero(),
            self,
            validatePreprocessedRowDirect,
            writePreprocessedRow,
        );
    }

    pub fn generateMainInto(
        self: *const Executor,
        witness: *const MainWitness,
        preprocessing: *const Preprocessed,
        columns: *[MAIN_COLUMN_COUNT][]M31,
    ) Error!void {
        try self.validate();
        try witness.validateAgainst(preprocessing);
        try protectHeader(columns, witness);
        try protectHeader(columns, preprocessing);
        return direct.generateMainInto(
            M31,
            MainRow,
            MAIN_COLUMN_COUNT,
            columns,
            witness.rows,
            preprocessing.log_size,
            M31.zero(),
            self,
            validateMainRowDirect,
            writeMainRow,
        );
    }
};

pub fn logicalInputs(
    main: MainRow,
    preprocessing: PreprocessedRow,
    proof_kind: ProofKind,
) [component.LOGICAL_INPUT_COUNT]M31 {
    const selectors = proof_kind.selectors();
    return main.values() ++ preprocessing.values() ++ .{
        selectors[0],
        selectors[1],
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
    lane.trace.validate() catch return error.InvalidTranscriptTrace;
    var frame_at: usize = 0;
    var call_at: usize = 0;
    var pow_at: usize = 0;
    var digest_state = [_]M31{M31.zero()} ** RATE;
    for (lane.plan.steps, 0..) |step, sequence| {
        const effect = transcriptEffect(step) orelse continue;
        const encoded = step.encode();
        const payload_words = try payloadWordCount(lane.plan, step);
        try validateStatePrefix(lane.trace, frame_at, digest_state);
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
        digest_state = lane.trace.hash_frames[frame_at - 1].output[0..RATE].*;
        if (effect != .mix) {
            try validateStatePrefix(lane.trace, frame_at, digest_state);
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
                const bits = switch (step) {
                    .verify_and_absorb_interaction_pow => |item| item.bits,
                    .verify_and_absorb_pcs_pow => |item| item.bits,
                    else => return error.InvalidTranscriptLayout,
                };
                if (check.call_id != final_call or check.bits != bits or
                    !check.word.eql(lane.trace.poseidon_calls[final_call].output[0]))
                {
                    return error.PowCheckMismatch;
                }
                pow_at += 1;
            }
        }
    }
    if (frame_at != lane.trace.hash_frames.len) return error.FrameCountMismatch;
    if (call_at != lane.trace.poseidon_calls.len) return error.CallCountMismatch;
    if (pow_at != lane.trace.pow_checks.len) return error.PowCheckCountMismatch;
}

pub fn validateStatePrefix(
    trace_value: *const TranscriptTrace,
    frame_index: usize,
    expected: [RATE]M31,
) Error!void {
    if (frame_index >= trace_value.hash_frames.len)
        return error.FrameCountMismatch;
    const frame = trace_value.hash_frames[frame_index];
    if (frame.words.len < RATE) return error.InvalidTranscriptTrace;
    for (frame.words[0..RATE], expected) |actual, word| {
        if (!actual.eql(word)) return error.InvalidTranscriptTrace;
    }
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

pub fn validateFrame(
    trace_value: *const TranscriptTrace,
    frame_at: *usize,
    call_at: *usize,
    purpose: HashPurpose,
    stream_words: usize,
    sequence: u32,
    encoded: schedule.EncodedStep,
    is_mix: bool,
) Error!u32 {
    if (frame_at.* >= trace_value.hash_frames.len)
        return error.FrameCountMismatch;
    const frame = trace_value.hash_frames[frame_at.*];
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
        if (call_index >= trace_value.poseidon_calls.len)
            return error.CallCountMismatch;
        const call = trace_value.poseidon_calls[call_index];
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

pub fn sourceMatchesPreprocessing(
    preprocessing: *const Preprocessed,
    source_value: Source,
) Error!void {
    switch (source_value) {
        .segment_leaf => |lane| {
            if (!std.meta.eql(lane.plan.authority_digest, preprocessing.vm_schedule_digest) or
                lane.trace.poseidon_calls.len != preprocessing.vm_call_count or
                lane.trace.hash_frames.len != preprocessing.vm_frame_count)
            {
                return error.AuthorityMismatch;
            }
        },
        .binary_node => |lanes| {
            if (!std.meta.eql(lanes.left.plan.authority_digest, preprocessing.recursion_schedule_digest) or
                !std.meta.eql(lanes.right.plan.authority_digest, preprocessing.recursion_schedule_digest) or
                lanes.left.trace.poseidon_calls.len != preprocessing.recursion_call_count or
                lanes.right.trace.poseidon_calls.len != preprocessing.recursion_call_count or
                lanes.left.trace.hash_frames.len != preprocessing.recursion_frame_count or
                lanes.right.trace.hash_frames.len != preprocessing.recursion_frame_count)
            {
                return error.AuthorityMismatch;
            }
        },
        .empty_leaf => {},
    }
}

pub fn rowForSource(source_value: Source, metadata: PreprocessedRow) Error!MainRow {
    const trace_value: ?*const TranscriptTrace = switch (source_value) {
        .segment_leaf => |lane| if (metadata.verifier_id == SEGMENT_VERIFIER_ID)
            lane.trace
        else
            null,
        .binary_node => |lanes| switch (metadata.verifier_id) {
            LEFT_RECURSION_VERIFIER_ID => lanes.left.trace,
            RIGHT_RECURSION_VERIFIER_ID => lanes.right.trace,
            SEGMENT_VERIFIER_ID => null,
            else => return error.UnknownVerifierId,
        },
        .empty_leaf => null,
    };
    const active_trace = trace_value orelse return .{
        .enabler = 1,
        .inputs = [_]M31{M31.zero()} ** RATE,
        .outputs = [_]M31{M31.zero()} ** RATE,
    };
    const frame_index: usize = metadata.hash_id;
    if (frame_index >= active_trace.hash_frames.len)
        return error.FrameIndexOutOfRange;
    const frame = active_trace.hash_frames[frame_index];
    if (frame.words.len < RATE) return error.InvalidTranscriptTrace;
    return .{
        .enabler = 1,
        .inputs = frame.words[0..RATE].*,
        .outputs = frame.output[0..RATE].*,
    };
}

pub const Receipts = struct {
    lane_count: u8,
    schedules: [2][8]u32,
    transcripts: [2]digest.Digest,
};

pub fn sourceReceipts(source_value: Source) Receipts {
    var result = Receipts{
        .lane_count = 0,
        .schedules = .{.{0} ** 8} ** 2,
        .transcripts = .{.{0} ** 32} ** 2,
    };
    switch (source_value) {
        .segment_leaf => |lane| {
            result.lane_count = 1;
            result.schedules[0] = lane.plan.authority_digest;
            result.transcripts[0] = lane.trace.receiptDigest();
        },
        .binary_node => |lanes| {
            result.lane_count = 2;
            result.schedules[0] = lanes.left.plan.authority_digest;
            result.schedules[1] = lanes.right.plan.authority_digest;
            result.transcripts[0] = lanes.left.trace.receiptDigest();
            result.transcripts[1] = lanes.right.trace.receiptDigest();
        },
        .empty_leaf => {},
    }
    return result;
}

pub fn validatePreprocessedRowDirect(row: PreprocessedRow) direct.Error!void {
    validatePreprocessedRow(row) catch return error.InvalidTraceRow;
}

pub fn validateMainRowFor(
    metadata: PreprocessedRow,
    proof_kind: ProofKind,
    row: MainRow,
) Error!void {
    if (row.enabler != 1) return error.InvalidWitnessRow;
    const active = switch (proof_kind) {
        .segment_leaf => metadata.verifier_id == SEGMENT_VERIFIER_ID,
        .binary_node => metadata.verifier_id != SEGMENT_VERIFIER_ID,
        .empty_leaf => false,
    };
    for (row.inputs) |word| {
        if (word.v >= m31.Modulus or (!active and !word.isZero()) or
            (active and metadata.initial_mask == 1 and !word.isZero()))
        {
            return error.InvalidWitnessRow;
        }
    }
    for (row.outputs) |word| {
        if (word.v >= m31.Modulus or (!active and !word.isZero()))
            return error.InvalidWitnessRow;
    }
}

pub fn validateMainRowDirect(row: MainRow) direct.Error!void {
    if (row.enabler != 1) return error.InvalidTraceRow;
    for (row.inputs) |word| if (word.v >= m31.Modulus)
        return error.InvalidTraceRow;
    for (row.outputs) |word| if (word.v >= m31.Modulus)
        return error.InvalidTraceRow;
}

pub fn witnessDigest(
    proof_kind: ProofKind,
    preprocessing_digest: digest.Digest,
    lane_count: u8,
    schedule_receipts: [2][8]u32,
    transcript_receipts: [2]digest.Digest,
    rows: []const MainRow,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(WITNESS_DOMAIN);
    hashInt(&hash, u16, WITNESS_FORMAT_VERSION);
    hash.update(&component.SOURCE_AUTHORITY_DIGEST);
    hashInt(&hash, u8, @intFromEnum(proof_kind));
    hash.update(&preprocessing_digest);
    hashInt(&hash, u8, lane_count);
    for (schedule_receipts) |receipt| for (receipt) |word|
        hashInt(&hash, u32, word);
    for (transcript_receipts) |receipt| hash.update(&receipt);
    hashInt(&hash, u64, rows.len);
    for (rows) |row| {
        hashInt(&hash, u32, row.enabler);
        for (row.inputs) |word| hashInt(&hash, u32, word.v);
        for (row.outputs) |word| hashInt(&hash, u32, word.v);
    }
    return hash.finalResult();
}

pub fn writePreprocessedRow(
    columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
    row_index: usize,
    row: PreprocessedRow,
) void {
    for (columns, row.values()) |column, value| column[row_index] = value;
}

pub fn writeMainRow(
    columns: *[MAIN_COLUMN_COUNT][]M31,
    row_index: usize,
    row: MainRow,
) void {
    for (columns, row.values()) |column, value| column[row_index] = value;
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

    fn overlaps(self: AddressRange, other: AddressRange) bool {
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
