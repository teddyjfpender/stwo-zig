//! Internal transcript binding witness authority shard; use transcript_binding_witness.zig publicly.

const dependency_0 = @import("transcript_binding_witness_contract.zig");

const DIGEST_WORD_COUNT = dependency_0.DIGEST_WORD_COUNT;
const DRAW_TAG = dependency_0.DRAW_TAG;
const DRAW_WORD_COUNT = dependency_0.DRAW_WORD_COUNT;
const Error = dependency_0.Error;
const HashPurpose = dependency_0.HashPurpose;
const LEFT_RECURSION_VERIFIER_ID = dependency_0.LEFT_RECURSION_VERIFIER_ID;
const M31 = dependency_0.M31;
const MAIN_COLUMN_COUNT = dependency_0.MAIN_COLUMN_COUNT;
const OPERATION_HEADER_WORD_COUNT = dependency_0.OPERATION_HEADER_WORD_COUNT;
const PREPROCESSED_COLUMN_COUNT = dependency_0.PREPROCESSED_COLUMN_COUNT;
const PreprocessedRow = dependency_0.PreprocessedRow;
const ProofKind = dependency_0.ProofKind;
const RATE = dependency_0.RATE;
const RIGHT_RECURSION_VERIFIER_ID = dependency_0.RIGHT_RECURSION_VERIFIER_ID;
const SEGMENT_VERIFIER_ID = dependency_0.SEGMENT_VERIFIER_ID;
const TRANSCRIPT_OPERATION_TAG = dependency_0.TRANSCRIPT_OPERATION_TAG;
const TranscriptTrace = dependency_0.TranscriptTrace;
const WIDTH = dependency_0.WIDTH;
const WITNESS_DOMAIN = dependency_0.WITNESS_DOMAIN;
const WITNESS_FORMAT_VERSION = dependency_0.WITNESS_FORMAT_VERSION;
const appendPlanRows = dependency_0.appendPlanRows;
const callCount = dependency_0.callCount;
const comparePlanRows = dependency_0.comparePlanRows;
const component = dependency_0.component;
const digest = dependency_0.digest;
const direct = dependency_0.direct;
const frameCallCount = dependency_0.frameCallCount;
const hashInt = dependency_0.hashInt;
const m31 = dependency_0.m31;
const payloadWordCount = dependency_0.payloadWordCount;
const preprocessingDigest = dependency_0.preprocessingDigest;
const schedule = dependency_0.schedule;
const std = dependency_0.std;
const traceLogSize = dependency_0.traceLogSize;
const transcriptEffect = dependency_0.transcriptEffect;
const validatePlans = dependency_0.validatePlans;
const validatePreprocessedRow = dependency_0.validatePreprocessedRow;

pub const Preprocessed = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    rows: []PreprocessedRow,
    vm_call_count: usize,
    recursion_call_count: usize,
    vm_schedule_digest: [8]u32,
    recursion_schedule_digest: [8]u32,
    authority_digest: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
    ) Error!Preprocessed {
        try component.SourceAuthority.pinned().validate();
        try validatePlans(vm, recursion);
        const vm_count = try callCount(vm);
        const recursion_count = try callCount(recursion);
        const row_count = std.math.add(
            usize,
            vm_count,
            std.math.mul(usize, recursion_count, 2) catch
                return error.ArithmeticOverflow,
        ) catch return error.ArithmeticOverflow;
        const log_size = try traceLogSize(row_count);
        const rows = try allocator.alloc(PreprocessedRow, row_count);
        errdefer allocator.free(rows);
        var cursor: usize = 0;
        try appendPlanRows(rows, &cursor, vm, SEGMENT_VERIFIER_ID, 1, 0);
        try appendPlanRows(rows, &cursor, recursion, LEFT_RECURSION_VERIFIER_ID, 0, 1);
        try appendPlanRows(rows, &cursor, recursion, RIGHT_RECURSION_VERIFIER_ID, 0, 1);
        if (cursor != rows.len) return error.InvalidTranscriptLayout;
        for (rows) |row| try validatePreprocessedRow(row);
        const authority_digest = preprocessingDigest(
            log_size,
            vm_count,
            recursion_count,
            vm.authority_digest,
            recursion.authority_digest,
            rows,
        );
        return .{
            .allocator = allocator,
            .log_size = log_size,
            .rows = rows,
            .vm_call_count = vm_count,
            .recursion_call_count = recursion_count,
            .vm_schedule_digest = vm.authority_digest,
            .recursion_schedule_digest = recursion.authority_digest,
            .authority_digest = authority_digest,
        };
    }

    pub fn deinit(self: *Preprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    /// Allocation-free validation suitable for the prepared writer boundary.
    pub fn validate(self: *const Preprocessed) Error!void {
        const recursion_rows = std.math.mul(
            usize,
            self.recursion_call_count,
            2,
        ) catch return error.ArithmeticOverflow;
        const expected_rows = std.math.add(
            usize,
            self.vm_call_count,
            recursion_rows,
        ) catch return error.ArithmeticOverflow;
        if (self.log_size != try traceLogSize(self.rows.len) or
            self.rows.len != expected_rows)
        {
            return error.AuthorityMismatch;
        }
        for (self.rows) |row| try validatePreprocessedRow(row);
        const actual = preprocessingDigest(
            self.log_size,
            self.vm_call_count,
            self.recursion_call_count,
            self.vm_schedule_digest,
            self.recursion_schedule_digest,
            self.rows,
        );
        if (!std.mem.eql(u8, &actual, &self.authority_digest))
            return error.AuthorityMismatch;
    }

    /// Cold verifier-key admission check against the originating schedules.
    pub fn validateAgainst(
        self: *const Preprocessed,
        vm: *const schedule.Plan,
        recursion: *const schedule.Plan,
    ) Error!void {
        try self.validate();
        try validatePlans(vm, recursion);
        if (!std.meta.eql(self.vm_schedule_digest, vm.authority_digest) or
            !std.meta.eql(self.recursion_schedule_digest, recursion.authority_digest) or
            self.vm_call_count != try callCount(vm) or
            self.recursion_call_count != try callCount(recursion))
        {
            return error.AuthorityMismatch;
        }
        var cursor: usize = 0;
        try comparePlanRows(self.rows, &cursor, vm, SEGMENT_VERIFIER_ID, 1, 0);
        try comparePlanRows(self.rows, &cursor, recursion, LEFT_RECURSION_VERIFIER_ID, 0, 1);
        try comparePlanRows(self.rows, &cursor, recursion, RIGHT_RECURSION_VERIFIER_ID, 0, 1);
        if (cursor != self.rows.len) return error.AuthorityMismatch;
    }
};

pub const Lane = struct {
    plan: *const schedule.Plan,
    trace: *const TranscriptTrace,
};

pub const BinaryLanes = struct {
    left: Lane,
    right: Lane,
};

pub const Source = union(ProofKind) {
    segment_leaf: Lane,
    binary_node: BinaryLanes,
    empty_leaf: void,
};

pub const MainRow = struct {
    enabler: u32,
    chunks: [RATE]M31,
    outputs: [RATE]M31,

    pub fn values(self: MainRow) [MAIN_COLUMN_COUNT]M31 {
        return .{M31.fromCanonical(self.enabler)} ++ self.chunks ++ self.outputs;
    }
};

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

    /// Allocation-free validation of a cold-authenticated snapshot.
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
    const expected_calls = try callCount(lane.plan);
    if (lane.trace.poseidon_calls.len != expected_calls)
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
    } else if (frame.words[RATE].v != 0 or frame.words[RATE + 1].v != DRAW_TAG) {
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

pub fn sourceMatchesPreprocessing(
    preprocessing: *const Preprocessed,
    source_value: Source,
) Error!void {
    switch (source_value) {
        .segment_leaf => |lane| {
            if (!std.meta.eql(lane.plan.authority_digest, preprocessing.vm_schedule_digest) or
                lane.trace.poseidon_calls.len != preprocessing.vm_call_count)
            {
                return error.AuthorityMismatch;
            }
        },
        .binary_node => |lanes| {
            if (!std.meta.eql(lanes.left.plan.authority_digest, preprocessing.recursion_schedule_digest) or
                !std.meta.eql(lanes.right.plan.authority_digest, preprocessing.recursion_schedule_digest) or
                lanes.left.trace.poseidon_calls.len != preprocessing.recursion_call_count or
                lanes.right.trace.poseidon_calls.len != preprocessing.recursion_call_count)
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
        .chunks = [_]M31{M31.zero()} ** RATE,
        .outputs = [_]M31{M31.zero()} ** RATE,
    };
    const call_index: usize = metadata.call_id;
    if (call_index >= active_trace.poseidon_calls.len)
        return error.CallIndexOutOfRange;
    const call = active_trace.poseidon_calls[call_index];
    var previous = [_]M31{M31.zero()} ** WIDTH;
    if (metadata.hash_step != 0) {
        if (call_index == 0) return error.InvalidTranscriptTrace;
        previous = active_trace.poseidon_calls[call_index - 1].output;
    }
    var chunks: [RATE]M31 = undefined;
    for (&chunks, call.input[0..RATE], previous[0..RATE]) |*target, input, prior|
        target.* = input.sub(prior);
    return .{
        .enabler = 1,
        .chunks = chunks,
        .outputs = if (metadata.is_last == 1)
            call.output[0..RATE].*
        else
            [_]M31{M31.zero()} ** RATE,
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
    for (row.chunks) |word| {
        if (word.v >= m31.Modulus or (!active and !word.isZero()))
            return error.InvalidWitnessRow;
    }
    for (row.outputs) |word| {
        if (word.v >= m31.Modulus or
            ((!active or metadata.is_last == 0) and !word.isZero()))
        {
            return error.InvalidWitnessRow;
        }
    }
}

pub fn validateMainRowDirect(row: MainRow) direct.Error!void {
    if (row.enabler != 1) return error.InvalidTraceRow;
    for (row.chunks) |word| if (word.v >= m31.Modulus)
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
        for (row.chunks) |word| hashInt(&hash, u32, word.v);
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
