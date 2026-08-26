//! Internal transcript payload witness authority shard; use transcript_payload_witness.zig publicly.

const dependency_0 = @import("transcript_payload_witness_binding.zig");

const Error = dependency_0.Error;
const LEFT_RECURSION_VERIFIER_ID = dependency_0.LEFT_RECURSION_VERIFIER_ID;
const M31 = dependency_0.M31;
const MAIN_COLUMN_COUNT = dependency_0.MAIN_COLUMN_COUNT;
const MAX_LOG_SIZE = dependency_0.MAX_LOG_SIZE;
const MIN_LOG_SIZE = dependency_0.MIN_LOG_SIZE;
const PAYLOAD_WORD_OFFSET = dependency_0.PAYLOAD_WORD_OFFSET;
const PREPARED_BATCH_DOMAIN = dependency_0.PREPARED_BATCH_DOMAIN;
const PREPARED_BATCH_FORMAT_VERSION = dependency_0.PREPARED_BATCH_FORMAT_VERSION;
const PREPROCESSED_COLUMN_COUNT = dependency_0.PREPROCESSED_COLUMN_COUNT;
const PREPROCESSING_DOMAIN = dependency_0.PREPROCESSING_DOMAIN;
const PREPROCESSING_FORMAT_VERSION = dependency_0.PREPROCESSING_FORMAT_VERSION;
const ProofKind = dependency_0.ProofKind;
const RIGHT_RECURSION_VERIFIER_ID = dependency_0.RIGHT_RECURSION_VERIFIER_ID;
const Row = dependency_0.Row;
const SEGMENT_VERIFIER_ID = dependency_0.SEGMENT_VERIFIER_ID;
const TranscriptTrace = dependency_0.TranscriptTrace;
const component = dependency_0.component;
const digest = dependency_0.digest;
const direct = dependency_0.direct;
const hashInt = dependency_0.hashInt;
const payloadWordCount = dependency_0.payloadWordCount;
const rowActive = dependency_0.rowActive;
const schedule = dependency_0.schedule;
const std = dependency_0.std;
const trace_mod = dependency_0.trace_mod;
const transcriptEffect = dependency_0.transcriptEffect;

pub const BinarySource = struct {
    left: *const TranscriptTrace,
    right: *const TranscriptTrace,
};

pub const Source = union(ProofKind) {
    segment_leaf: *const TranscriptTrace,
    binary_node: BinarySource,
    empty_leaf: void,
};

pub fn validateSource(
    vm: *const schedule.Plan,
    recursion: *const schedule.Plan,
    source: Source,
) Error!void {
    switch (source) {
        .segment_leaf => |trace| try validateTraceAgainstPlan(vm, trace),
        .binary_node => |traces| {
            try validateTraceAgainstPlan(recursion, traces.left);
            try validateTraceAgainstPlan(recursion, traces.right);
        },
        .empty_leaf => {},
    }
}

pub fn validateTraceAgainstPlan(
    plan: *const schedule.Plan,
    trace: *const TranscriptTrace,
) Error!void {
    try plan.validate();
    try trace.validate();
    var frame_at: usize = 0;
    var call_at: usize = 0;
    var pow_at: usize = 0;
    for (plan.steps, 0..) |step, sequence| {
        const effect = transcriptEffect(step) orelse continue;
        const payload_count = try payloadWordCount(plan.schema, step);
        const mix_frame = try validateExpectedFrame(
            trace,
            &frame_at,
            &call_at,
            .mix,
            sequence,
            step,
            payload_count,
        );
        if (effect != .mix) {
            const draw_frame = try validateExpectedFrame(
                trace,
                &frame_at,
                &call_at,
                .draw,
                sequence,
                step,
                0,
            );
            if (effect == .pow) {
                if (pow_at >= trace.pow_checks.len)
                    return error.InvalidTranscriptSource;
                const check = trace.pow_checks[pow_at];
                const bits = powBits(step) orelse
                    return error.InvalidTranscriptSource;
                if (draw_frame.finalCallId() != check.call_id or
                    check.bits != bits or
                    !draw_frame.output[0].eql(check.word))
                {
                    return error.InvalidTranscriptSource;
                }
                for (0..component.QM31_WORD_COUNT) |limb| {
                    const expected: u32 = @truncate(
                        (check.nonce >> @intCast(16 * limb)) & 0xffff,
                    );
                    if (mix_frame.words[PAYLOAD_WORD_OFFSET + limb].v != expected)
                        return error.InvalidTranscriptSource;
                }
                pow_at += 1;
            }
        }
    }
    if (frame_at != trace.hash_frames.len or
        call_at != trace.poseidon_calls.len or
        pow_at != trace.pow_checks.len)
    {
        return error.InvalidTranscriptSource;
    }
}

pub fn validateExpectedFrame(
    trace: *const TranscriptTrace,
    frame_at: *usize,
    call_at: *usize,
    purpose: trace_mod.HashPurpose,
    sequence: usize,
    step: schedule.VerifierStep,
    payload_count: usize,
) Error!*const trace_mod.HashFrame {
    if (frame_at.* >= trace.hash_frames.len)
        return error.InvalidTranscriptSource;
    const frame = &trace.hash_frames[frame_at.*];
    const raw_count: usize = if (purpose == .mix)
        PAYLOAD_WORD_OFFSET + payload_count
    else
        component.DIGEST_WORD_COUNT + 2;
    const padded_count = try paddedWordCount(raw_count);
    const call_count = padded_count / component.DIGEST_WORD_COUNT;
    if (frame.hash_id != @as(u32, @intCast(frame_at.*)) or
        frame.first_call_id != @as(u32, @intCast(call_at.*)) or
        frame.call_count != @as(u32, @intCast(call_count)) or
        frame.purpose != purpose or frame.words.len != raw_count)
    {
        return error.InvalidTranscriptSource;
    }
    if (purpose == .mix) {
        const encoded = step.encode();
        const header: [component.DIGEST_WORD_COUNT]u32 = .{
            0x5452,
            @as(u32, @intCast(sequence)),
            encoded.tag,
            @as(u32, encoded.arity),
        } ++ encoded.args;
        for (header, 0..) |expected, index| {
            if (frame.words[component.DIGEST_WORD_COUNT + index].v != expected)
                return error.InvalidTranscriptSource;
        }
    } else if (frame.words[component.DIGEST_WORD_COUNT].v != 0 or
        frame.words[component.DIGEST_WORD_COUNT + 1].v != 0x4452_4157)
    {
        return error.InvalidTranscriptSource;
    }
    frame_at.* += 1;
    call_at.* = std.math.add(usize, call_at.*, call_count) catch
        return error.ArithmeticOverflow;
    return frame;
}

pub fn powBits(step: schedule.VerifierStep) ?u32 {
    return switch (step) {
        .verify_and_absorb_interaction_pow => |item| item.bits,
        .verify_and_absorb_pcs_pow => |item| item.bits,
        else => null,
    };
}

pub fn fillValues(destination: []M31, rows: []const Row, source: Source) void {
    std.debug.assert(destination.len == rows.len);
    for (destination, rows) |*value, row| value.* = valueFor(row, source);
}

pub fn valueFor(row: Row, source: Source) M31 {
    if (!rowActive(row, std.meta.activeTag(source))) return M31.zero();
    const trace: ?*const TranscriptTrace = switch (source) {
        .segment_leaf => |segment| if (row.verifier_id == SEGMENT_VERIFIER_ID)
            segment
        else
            null,
        .binary_node => |binary| switch (row.verifier_id) {
            LEFT_RECURSION_VERIFIER_ID => binary.left,
            RIGHT_RECURSION_VERIFIER_ID => binary.right,
            else => null,
        },
        .empty_leaf => null,
    };
    const selected = trace orelse return M31.zero();
    return selected.hash_frames[row.source_hash_id].words[row.source_word_index];
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

pub fn writeMainValue(
    columns: *[MAIN_COLUMN_COUNT][]M31,
    logical_row: usize,
    value: M31,
) void {
    columns[0][logical_row] = M31.one();
    columns[1][logical_row] = value;
}

pub const Receipts = struct {
    lane_count: u8,
    schedules: [2][8]u32,
    transcripts: [2]digest.Digest,
};

pub fn sourceReceipts(source: Source) Receipts {
    var result = Receipts{
        .lane_count = 0,
        .schedules = .{.{0} ** 8} ** 2,
        .transcripts = .{.{0} ** 32} ** 2,
    };
    switch (source) {
        .segment_leaf => |trace| {
            result.lane_count = 1;
            result.transcripts[0] = trace.receiptDigest();
        },
        .binary_node => |traces| {
            result.lane_count = 2;
            result.transcripts[0] = traces.left.receiptDigest();
            result.transcripts[1] = traces.right.receiptDigest();
        },
        .empty_leaf => {},
    }
    return result;
}

pub fn preprocessingDigest(
    log_size: u32,
    vm_rows: usize,
    recursion_rows: usize,
    protocol_id: [component.DIGEST_WORD_COUNT]u32,
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
    for (protocol_id) |word| hashInt(&hash, u32, word);
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
    hashInt(hash, u32, row.payload_index);
    hashInt(hash, u32, @intFromEnum(row.source_kind));
    hashInt(hash, u32, row.item_index);
    hashInt(hash, u32, row.limb_index);
    hashInt(hash, u32, row.constant_mask);
    hashInt(hash, u32, row.input_use_count);
    hashInt(hash, u32, row.constant_value);
    hashInt(hash, u32, row.source_hash_id);
    hashInt(hash, u32, row.source_word_index);
}

pub fn paddedWordCount(raw_count: usize) Error!usize {
    const with_marker = std.math.add(usize, raw_count, 1) catch
        return error.ArithmeticOverflow;
    const chunks = std.math.divCeil(
        usize,
        with_marker,
        component.DIGEST_WORD_COUNT,
    ) catch return error.ArithmeticOverflow;
    return std.math.mul(
        usize,
        chunks,
        component.DIGEST_WORD_COUNT,
    ) catch return error.ArithmeticOverflow;
}

pub fn logSizeFor(row_count: usize) Error!u32 {
    const log_size: u32 = @max(
        MIN_LOG_SIZE,
        @as(u32, @intCast(std.math.log2_int_ceil(usize, @max(row_count, 1)))),
    );
    if (log_size > MAX_LOG_SIZE) return error.LogSizeOutOfRange;
    return log_size;
}

pub const AddressRange = struct {
    start: usize,
    end: usize,

    pub inline fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

pub fn sliceRange(comptime T: type, values: []const T) direct.Error!AddressRange {
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    return .{
        .start = start,
        .end = std.math.add(usize, start, byte_len) catch
            return error.AddressOverflow,
    };
}

pub fn objectRange(pointer: anytype) direct.Error!AddressRange {
    const info = @typeInfo(@TypeOf(pointer));
    if (info != .pointer or info.pointer.size != .one)
        @compileError("protected storage must be a single-item pointer");
    const start = @intFromPtr(pointer);
    return .{
        .start = start,
        .end = std.math.add(usize, start, @sizeOf(info.pointer.child)) catch
            return error.AddressOverflow,
    };
}
