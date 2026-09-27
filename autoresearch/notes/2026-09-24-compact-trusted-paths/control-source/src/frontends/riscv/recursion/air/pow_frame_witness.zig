//! Schedule-derived, source-sealed witness path for universal PoW row 7.
//!
//! Raw frame tuples are never accepted as authority.  The cold path validates
//! each verifier plan and complete recording-transcript trace, matches the two
//! PoW instructions to checks in program order, locates their final Draw
//! frames, and snapshots only the resulting 15-column rows.  Segment and
//! binary lanes are fixed to verifier ids 0 and 1/2 respectively.  The hot
//! writer is allocation-free and failure-atomic.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const digest = @import("../../air/lang/digest.zig");
const direct = @import("../../air/lang/direct_witness_executor.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("pow_frame.zig");
const check_witness = @import("pow_check_witness.zig");
const proof_kind_mod = @import("proof_kind.zig");
const schedule = @import("verifier_schedule.zig");

pub const RATE: usize = 8;
pub const WIDTH: usize = 16;
pub const DRAW_TAG: u32 = 0x4452_4157;
pub const MAIN_COLUMN_COUNT: usize = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const RelationRow = [component.LOGICAL_INPUT_COUNT]M31;
pub const ProofKind = proof_kind_mod.ProofKind;
pub const PowKind = component.PowKind;

pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-pow-frame-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "cab81542c5e6976ddcab89fe47342b3d0782a8c9d9915c71c3cb5685701df869";
pub const BINDING_DIGEST = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion PoW-frame witness-binding digest",
);
pub const PREPARED_BATCH_FORMAT_VERSION: u16 = 1;
pub const PREPARED_BATCH_DOMAIN =
    "stwo-zig/typed-air/recursion-pow-frame-batch/v1\x00";
pub const TRANSCRIPT_RECEIPT_FORMAT_VERSION: u16 = 1;
pub const TRANSCRIPT_RECEIPT_DOMAIN =
    "stwo-zig/typed-air/recursion-pow-transcript-receipt/v1\x00";

pub const HashPurpose = enum(u32) {
    mix = 1,
    draw = 2,
};

pub const PermutationId = struct {
    call_id: u32,
    hash_id: u32,
    step: u32,
};

pub const PoseidonCall = struct {
    id: PermutationId,
    input: [WIDTH]M31,
    output: [WIDTH]M31,
};

pub const HashFrame = struct {
    hash_id: u32,
    first_call_id: u32,
    call_count: u32,
    purpose: HashPurpose,
    words: []const M31,
    output: [WIDTH]M31,

    pub fn finalCallId(self: HashFrame) ?u32 {
        const offset = std.math.sub(u32, self.call_count, 1) catch return null;
        return std.math.add(u32, self.first_call_id, offset) catch null;
    }
};

pub const TranscriptTrace = struct {
    poseidon_calls: []const PoseidonCall,
    hash_frames: []const HashFrame,
    pow_checks: []const check_witness.Check,

    /// Allocation-free equivalent of Stark-V's `sponge_rows` validation.
    /// Permutation correctness remains owned by the shared Poseidon2 AIR; this
    /// boundary deliberately does not duplicate that expensive computation.
    pub fn validate(self: *const TranscriptTrace) Error!void {
        var call_at: usize = 0;
        for (self.hash_frames, 0..) |frame, frame_index| {
            if (frame.hash_id != frame_index or
                frame.first_call_id != call_at or
                frame.hash_id >= m31.Modulus or
                frame.first_call_id >= m31.Modulus)
            {
                return error.InvalidTranscriptTrace;
            }
            for (frame.words) |word| if (word.v >= m31.Modulus)
                return error.InvalidTranscriptTrace;
            const word_count_with_marker = std.math.add(
                usize,
                frame.words.len,
                1,
            ) catch return error.ArithmeticOverflow;
            const expected_calls = std.math.divCeil(
                usize,
                word_count_with_marker,
                RATE,
            ) catch return error.ArithmeticOverflow;
            if (expected_calls > std.math.maxInt(u32) or
                frame.call_count != expected_calls or expected_calls == 0)
            {
                return error.InvalidTranscriptTrace;
            }
            if (frame.purpose == .draw and
                (frame.words.len != RATE + 2 or
                    frame.words[RATE + 1].v != DRAW_TAG))
            {
                return error.InvalidTranscriptTrace;
            }

            var previous: [WIDTH]M31 = .{M31.zero()} ** WIDTH;
            for (0..expected_calls) |step| {
                if (call_at >= self.poseidon_calls.len)
                    return error.InvalidTranscriptTrace;
                const call = self.poseidon_calls[call_at];
                if (call.id.call_id != call_at or
                    call.id.hash_id != frame.hash_id or
                    call.id.step != step or
                    call.id.call_id >= m31.Modulus or
                    call.id.step >= m31.Modulus)
                {
                    return error.InvalidTranscriptTrace;
                }
                for (call.input) |word| if (word.v >= m31.Modulus)
                    return error.InvalidTranscriptTrace;
                for (call.output) |word| if (word.v >= m31.Modulus)
                    return error.InvalidTranscriptTrace;
                for (RATE..WIDTH) |lane| if (!call.input[lane].eql(previous[lane]))
                    return error.InvalidTranscriptTrace;
                for (0..RATE) |lane| {
                    const stream_index = step * RATE + lane;
                    const expected_chunk = if (stream_index < frame.words.len)
                        frame.words[stream_index]
                    else if (stream_index == frame.words.len)
                        M31.one()
                    else
                        M31.zero();
                    if (!call.input[lane].sub(previous[lane]).eql(expected_chunk))
                        return error.InvalidTranscriptTrace;
                }
                previous = call.output;
                call_at += 1;
            }
            if (!fieldArrayEql(WIDTH, previous, frame.output))
                return error.InvalidTranscriptTrace;
        }
        if (call_at != self.poseidon_calls.len)
            return error.InvalidTranscriptTrace;

        for (self.pow_checks) |check| {
            try validateCheck(check);
            if (check.call_id >= self.poseidon_calls.len or
                !self.poseidon_calls[check.call_id].output[0].eql(check.word))
            {
                return error.InvalidTranscriptTrace;
            }
            const frame = self.findDrawFrame(check.call_id) orelse
                return error.DrawFrameMissing;
            if (!frame.output[0].eql(check.word))
                return error.InvalidTranscriptTrace;
        }
    }

    pub fn findDrawFrame(
        self: *const TranscriptTrace,
        call_id: u32,
    ) ?*const HashFrame {
        for (self.hash_frames) |*frame| {
            if (frame.purpose == .draw and frame.finalCallId() == call_id)
                return frame;
        }
        return null;
    }

    pub fn receiptDigest(self: *const TranscriptTrace) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(TRANSCRIPT_RECEIPT_DOMAIN);
        hashInt(&hash, u16, TRANSCRIPT_RECEIPT_FORMAT_VERSION);
        hashInt(&hash, u64, self.poseidon_calls.len);
        for (self.poseidon_calls) |call| {
            hashInt(&hash, u32, call.id.call_id);
            hashInt(&hash, u32, call.id.hash_id);
            hashInt(&hash, u32, call.id.step);
            for (call.input) |word| hashInt(&hash, u32, word.v);
            for (call.output) |word| hashInt(&hash, u32, word.v);
        }
        hashInt(&hash, u64, self.hash_frames.len);
        for (self.hash_frames) |frame| {
            hashInt(&hash, u32, frame.hash_id);
            hashInt(&hash, u32, frame.first_call_id);
            hashInt(&hash, u32, frame.call_count);
            hashInt(&hash, u32, @intFromEnum(frame.purpose));
            hashInt(&hash, u64, frame.words.len);
            for (frame.words) |word| hashInt(&hash, u32, word.v);
            for (frame.output) |word| hashInt(&hash, u32, word.v);
        }
        hashInt(&hash, u64, self.pow_checks.len);
        for (self.pow_checks) |check| {
            hashInt(&hash, u32, check.call_id);
            hashInt(&hash, u64, check.nonce);
            hashInt(&hash, u32, check.bits);
            hashInt(&hash, u32, check.word.v);
        }
        return hash.finalResult();
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

pub const Invocation = struct {
    verifier_id: u32,
    sequence: u32,
    kind: PowKind,
    hash_id: u32,
    check: check_witness.Check,
    words: [component.WORD_COUNT]M31,
};

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

    pub fn canonical(
        definition: *const component.Definition,
    ) ConstructionError!Binding {
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
pub const Error = direct.Error || schedule.Error || std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    BitsMismatch,
    BitsOutOfRange,
    DrawFrameMissing,
    InvalidFieldElement,
    InvalidTranscriptTrace,
    InvalidWitnessBinding,
    PowCheckCountMismatch,
    SchemaMismatch,
};

pub const Executor = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const component.Definition,
        supplied: *const Binding,
    ) ConstructionError!Executor {
        const expected = try Binding.canonical(definition);
        if (!std.meta.eql(expected, supplied.*))
            return error.InvalidWitnessBinding;
        const binding_digest = supplied.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &BINDING_DIGEST))
            return error.InvalidWitnessBinding;
        return .{ .binding = supplied.*, .binding_digest = binding_digest };
    }

    pub fn validate(self: *const Executor) Error!void {
        const actual = self.binding.identityDigest();
        if (!std.mem.eql(u8, &actual, &self.binding_digest) or
            !std.mem.eql(u8, &actual, &BINDING_DIGEST) or
            !std.mem.eql(
                u8,
                &self.binding.source_authority_digest,
                &component.SOURCE_AUTHORITY_DIGEST,
            ))
        {
            return error.InvalidWitnessBinding;
        }
    }

    pub fn generateMainInto(
        self: *const Executor,
        batch: *const PreparedBatch,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        log_size: u32,
    ) Error!void {
        try self.validate();
        try batch.validate();
        try protectBatchHeader(columns, batch);
        return direct.generateMainInto(
            M31,
            Invocation,
            MAIN_COLUMN_COUNT,
            columns,
            batch.invocations,
            log_size,
            M31.zero(),
            self,
            validateInvocation,
            writeMainRow,
        );
    }
};

pub const PreparedBatch = struct {
    allocator: std.mem.Allocator,
    proof_kind: ProofKind,
    invocations: []Invocation,
    lane_count: u8,
    schedule_receipts: [2][8]u32,
    transcript_receipts: [2]digest.Digest,
    authority_digest: digest.Digest,

    /// The only allocation charged to this constructor is the compact row
    /// snapshot. Plans and transcript traces are borrowed and already owned.
    pub fn init(allocator: std.mem.Allocator, source: Source) Error!PreparedBatch {
        try component.SourceAuthority.pinned().validate();
        try validateSource(source);
        const row_count = countSourceRows(source);
        const invocations = try allocator.alloc(Invocation, row_count);
        errdefer allocator.free(invocations);
        var at: usize = 0;
        fillSourceRows(invocations, &at, source) catch unreachable;
        std.debug.assert(at == row_count);
        const receipts = sourceReceipts(source);
        return .{
            .allocator = allocator,
            .proof_kind = std.meta.activeTag(source),
            .invocations = invocations,
            .lane_count = receipts.lane_count,
            .schedule_receipts = receipts.schedules,
            .transcript_receipts = receipts.transcripts,
            .authority_digest = batchDigest(
                source,
                receipts.lane_count,
                receipts.schedules,
                receipts.transcripts,
                invocations,
            ),
        };
    }

    pub fn deinit(self: *PreparedBatch) void {
        self.allocator.free(self.invocations);
        self.* = undefined;
    }

    pub fn validate(self: *const PreparedBatch) Error!void {
        try component.SourceAuthority.pinned().validate();
        const expected_lanes: u8 = switch (self.proof_kind) {
            .segment_leaf => 1,
            .binary_node => 2,
            .empty_leaf => 0,
        };
        if (self.lane_count != expected_lanes)
            return error.AuthorityMismatch;
        try validatePreparedLaneShape(self.proof_kind, self.invocations);
        for (self.invocations) |invocation| try validateFrameInvocation(invocation);
        const actual = batchDigest(
            self.proof_kind,
            self.lane_count,
            self.schedule_receipts,
            self.transcript_receipts,
            self.invocations,
        );
        if (!std.mem.eql(u8, &actual, &self.authority_digest))
            return error.AuthorityMismatch;
    }

    pub fn validateAgainstSource(
        self: *const PreparedBatch,
        source: Source,
    ) Error!void {
        try self.validate();
        if (std.meta.activeTag(source) != self.proof_kind)
            return error.AuthorityMismatch;
        try validateSource(source);
        const receipts = sourceReceipts(source);
        if (receipts.lane_count != self.lane_count or
            !std.meta.eql(receipts.schedules, self.schedule_receipts) or
            !std.meta.eql(receipts.transcripts, self.transcript_receipts) or
            countSourceRows(source) != self.invocations.len)
        {
            return error.AuthorityMismatch;
        }
        var at: usize = 0;
        try compareSourceRows(self.invocations, &at, source);
        if (at != self.invocations.len) return error.AuthorityMismatch;
    }

    pub fn row(self: *const PreparedBatch, index: usize) Error!RelationRow {
        try self.validate();
        if (index >= self.invocations.len) return error.InvalidTraceRow;
        return mainRow(self.invocations[index]);
    }

    pub inline fn preparedRow(self: *const PreparedBatch, index: usize) RelationRow {
        std.debug.assert(index < self.invocations.len);
        return mainRowUnchecked(self.invocations[index]);
    }
};

pub fn mainRow(invocation: Invocation) direct.Error!RelationRow {
    try validateInvocation(invocation);
    return mainRowUnchecked(invocation);
}

pub inline fn mainRowUnchecked(invocation: Invocation) RelationRow {
    return .{
        M31.one(),
        M31.fromCanonical(invocation.verifier_id),
        M31.fromCanonical(invocation.sequence),
        M31.fromCanonical(@intFromEnum(invocation.kind)),
        M31.fromCanonical(invocation.hash_id),
        M31.fromCanonical(invocation.check.call_id),
        M31.fromCanonical(invocation.check.bits),
    } ++ invocation.words;
}

pub inline fn writeMainRow(
    columns: *[MAIN_COLUMN_COUNT][]M31,
    row_index: usize,
    invocation: Invocation,
) void {
    const row = mainRowUnchecked(invocation);
    inline for (0..MAIN_COLUMN_COUNT) |column|
        columns[column][row_index] = row[column];
}

fn validateSource(source: Source) Error!void {
    switch (source) {
        .segment_leaf => |lane| try validateLane(lane, .vm),
        .binary_node => |lanes| {
            try validateLane(lanes.left, .recursion);
            try validateLane(lanes.right, .recursion);
        },
        .empty_leaf => {},
    }
}

fn validateLane(lane: Lane, expected_schema: schedule.Schema) Error!void {
    try lane.plan.validate();
    if (lane.plan.schema != expected_schema) return error.SchemaMismatch;
    try lane.trace.validate();
    var check_at: usize = 0;
    for (lane.plan.steps) |step| {
        const scheduled = powStep(step) orelse continue;
        if (check_at >= lane.trace.pow_checks.len)
            return error.PowCheckCountMismatch;
        const check = lane.trace.pow_checks[check_at];
        if (check.bits != scheduled.bits) return error.BitsMismatch;
        if (lane.trace.findDrawFrame(check.call_id) == null)
            return error.DrawFrameMissing;
        check_at += 1;
    }
    if (check_at != lane.trace.pow_checks.len)
        return error.PowCheckCountMismatch;
}

fn countSourceRows(source: Source) usize {
    return switch (source) {
        .segment_leaf => |lane| countLaneRows(lane),
        .binary_node => |lanes| countLaneRows(lanes.left) +
            countLaneRows(lanes.right),
        .empty_leaf => 0,
    };
}

fn countLaneRows(lane: Lane) usize {
    var result: usize = 0;
    for (lane.plan.steps) |step| result += @intFromBool(powStep(step) != null);
    return result;
}

fn fillSourceRows(
    destination: []Invocation,
    at: *usize,
    source: Source,
) Error!void {
    switch (source) {
        .segment_leaf => |lane| try fillLaneRows(destination, at, lane, 0),
        .binary_node => |lanes| {
            try fillLaneRows(destination, at, lanes.left, 1);
            try fillLaneRows(destination, at, lanes.right, 2);
        },
        .empty_leaf => {},
    }
}

fn fillLaneRows(
    destination: []Invocation,
    at: *usize,
    lane: Lane,
    verifier_id: u32,
) Error!void {
    var check_at: usize = 0;
    for (lane.plan.steps, 0..) |step, sequence| {
        const scheduled = powStep(step) orelse continue;
        const check = lane.trace.pow_checks[check_at];
        const frame = lane.trace.findDrawFrame(check.call_id) orelse
            return error.DrawFrameMissing;
        destination[at.*] = .{
            .verifier_id = verifier_id,
            .sequence = @intCast(sequence),
            .kind = scheduled.kind,
            .hash_id = frame.hash_id,
            .check = check,
            .words = frame.output[0..component.WORD_COUNT].*,
        };
        at.* += 1;
        check_at += 1;
    }
}

fn compareSourceRows(
    actual: []const Invocation,
    at: *usize,
    source: Source,
) Error!void {
    switch (source) {
        .segment_leaf => |lane| try compareLaneRows(actual, at, lane, 0),
        .binary_node => |lanes| {
            try compareLaneRows(actual, at, lanes.left, 1);
            try compareLaneRows(actual, at, lanes.right, 2);
        },
        .empty_leaf => {},
    }
}

fn compareLaneRows(
    actual: []const Invocation,
    at: *usize,
    lane: Lane,
    verifier_id: u32,
) Error!void {
    var check_at: usize = 0;
    for (lane.plan.steps, 0..) |step, sequence| {
        const scheduled = powStep(step) orelse continue;
        const check = lane.trace.pow_checks[check_at];
        const frame = lane.trace.findDrawFrame(check.call_id) orelse
            return error.DrawFrameMissing;
        const expected = Invocation{
            .verifier_id = verifier_id,
            .sequence = @intCast(sequence),
            .kind = scheduled.kind,
            .hash_id = frame.hash_id,
            .check = check,
            .words = frame.output[0..component.WORD_COUNT].*,
        };
        if (at.* >= actual.len or !std.meta.eql(actual[at.*], expected))
            return error.AuthorityMismatch;
        at.* += 1;
        check_at += 1;
    }
}

const ScheduledPow = struct { kind: PowKind, bits: u32 };

fn powStep(step: schedule.VerifierStep) ?ScheduledPow {
    return switch (step) {
        .verify_and_absorb_interaction_pow => |item| .{
            .kind = .interaction,
            .bits = item.bits,
        },
        .verify_and_absorb_pcs_pow => |item| .{
            .kind = .pcs,
            .bits = item.bits,
        },
        else => null,
    };
}

const Receipts = struct {
    lane_count: u8,
    schedules: [2][8]u32,
    transcripts: [2]digest.Digest,
};

fn sourceReceipts(source: Source) Receipts {
    var result = Receipts{
        .lane_count = 0,
        .schedules = .{.{0} ** 8} ** 2,
        .transcripts = .{.{0} ** 32} ** 2,
    };
    switch (source) {
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

fn batchDigest(
    proof_kind: ProofKind,
    lane_count: u8,
    schedule_receipts: [2][8]u32,
    transcript_receipts: [2]digest.Digest,
    invocations: []const Invocation,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PREPARED_BATCH_DOMAIN);
    hashInt(&hash, u16, PREPARED_BATCH_FORMAT_VERSION);
    hash.update(&component.SOURCE_AUTHORITY_DIGEST);
    hashInt(&hash, u8, @intFromEnum(proof_kind));
    hashInt(&hash, u8, lane_count);
    for (schedule_receipts) |receipt| for (receipt) |word|
        hashInt(&hash, u32, word);
    for (transcript_receipts) |receipt| hash.update(&receipt);
    hashInt(&hash, u64, invocations.len);
    for (invocations) |invocation| {
        hashInt(&hash, u32, invocation.verifier_id);
        hashInt(&hash, u32, invocation.sequence);
        hashInt(&hash, u32, @intFromEnum(invocation.kind));
        hashInt(&hash, u32, invocation.hash_id);
        hashInt(&hash, u32, invocation.check.call_id);
        hashInt(&hash, u64, invocation.check.nonce);
        hashInt(&hash, u32, invocation.check.bits);
        hashInt(&hash, u32, invocation.check.word.v);
        for (invocation.words) |word| hashInt(&hash, u32, word.v);
    }
    return hash.finalResult();
}

fn validateCheck(check: check_witness.Check) Error!void {
    if (check.call_id >= m31.Modulus or check.word.v >= m31.Modulus)
        return error.InvalidFieldElement;
    if (check.bits > 31) return error.BitsOutOfRange;
}

fn validateFrameInvocation(invocation: Invocation) Error!void {
    if (invocation.verifier_id >= m31.Modulus or
        invocation.sequence >= m31.Modulus or
        invocation.hash_id >= m31.Modulus)
    {
        return error.InvalidFieldElement;
    }
    try validateCheck(invocation.check);
    for (invocation.words) |word| if (word.v >= m31.Modulus)
        return error.InvalidFieldElement;
    if (!invocation.words[0].eql(invocation.check.word))
        return error.InvalidTranscriptTrace;
}

fn validatePreparedLaneShape(
    proof_kind: ProofKind,
    invocations: []const Invocation,
) Error!void {
    const expected_rows: usize = switch (proof_kind) {
        .segment_leaf => 2,
        .binary_node => 4,
        .empty_leaf => 0,
    };
    if (invocations.len != expected_rows) return error.AuthorityMismatch;
    for (invocations, 0..) |invocation, index| {
        const expected_verifier: u32 = switch (proof_kind) {
            .segment_leaf => 0,
            .binary_node => if (index < 2) 1 else 2,
            .empty_leaf => unreachable,
        };
        const expected_kind: PowKind = if (index % 2 == 0)
            .interaction
        else
            .pcs;
        if (invocation.verifier_id != expected_verifier or
            invocation.kind != expected_kind)
        {
            return error.AuthorityMismatch;
        }
    }
}

fn validateInvocation(invocation: Invocation) direct.Error!void {
    validateFrameInvocation(invocation) catch return error.InvalidTraceRow;
}

fn protectBatchHeader(
    columns: *const [MAIN_COLUMN_COUNT][]M31,
    batch: *const PreparedBatch,
) direct.Error!void {
    const descriptors = try objectRange(columns);
    const batch_header = try objectRange(batch);
    if (descriptors.overlaps(batch_header)) return error.AliasedInput;
    for (columns) |column| {
        const destination = (try sliceRange(M31, column)) orelse continue;
        if (destination.overlaps(batch_header)) return error.AliasedDestination;
    }
}

const AddressRange = struct {
    start: usize,
    end: usize,

    inline fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

fn sliceRange(comptime T: type, values: []const T) direct.Error!?AddressRange {
    if (values.len == 0) return null;
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    return .{
        .start = start,
        .end = std.math.add(usize, start, byte_len) catch
            return error.AddressOverflow,
    };
}

fn objectRange(pointer: anytype) direct.Error!AddressRange {
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

fn fieldArrayEql(
    comptime count: usize,
    lhs: [count]M31,
    rhs: [count]M31,
) bool {
    for (lhs, rhs) |left, right| if (!left.eql(right)) return false;
    return true;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}

comptime {
    if (WIDTH != 16 or RATE != 8 or MAIN_COLUMN_COUNT != 15 or
        component.controlTag(.interaction) != 6 or
        component.controlTag(.pcs) != 20)
    {
        @compileError("PoW-frame witness geometry drifted");
    }
}
