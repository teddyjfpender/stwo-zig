//! Internal segment transcript outer source v2 authority shard; use segment_transcript_outer_source_v2.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const m31 = stwo_core.fields.m31;
pub const M31 = m31.M31;
pub const PcsConfig = stwo_core.pcs.PcsConfig;

pub const public_data_v2 = @import("../air/public_data_v2.zig");
pub const statement_v1 = @import("../air/statement.zig");
pub const relation = @import("../air/lang/relation.zig");
pub const provider = @import("../air/lang/typed_poseidon2_witness.zig");
pub const transcript = @import("transcript_program_v2.zig");
pub const channel = @import("poseidon2_channel.zig");
pub const schedule = @import("air/verifier_schedule.zig");
pub const roster = @import("air/universal_roster.zig");
pub const universal = @import("air/universal_challenges.zig");
pub const control_witness = @import("air/control_witness.zig");
pub const transcript_air_witness = @import("air/transcript_air_witness.zig");
pub const binding_witness = @import("air/transcript_binding_witness.zig");
pub const state_witness = @import("air/transcript_state_witness.zig");
pub const word_witness = @import("air/transcript_word_witness.zig");
pub const payload_air = @import("air/transcript_payload.zig");
pub const pow_check_air = @import("air/pow_check.zig");
pub const relation_witness = @import("air/relation_challenge_witness.zig");
pub const randomness_witness = @import("air/verifier_randomness_witness.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const MANIFEST_VERSION: u16 = 2;
pub const FIRST_ROW: usize = @intFromEnum(roster.Component.control);
pub const ROW_COUNT: usize = 10;
pub const LAST_ROW: usize = FIRST_ROW + ROW_COUNT - 1;
pub const VERIFIER_ID: u32 = 0;
pub const MIN_LOG_SIZE: u8 = 4;
pub const MAX_LOG_SIZE: u8 = 30;
pub const SOURCE_ID_DOMAIN: u32 = 0x5453_5632; // "TSV2"
pub const MANIFEST_ID_DOMAIN: u32 = 0x544d_5632; // "TMV2"
pub const RANGE_ID_DOMAIN: u32 = 0x5452_4732; // "TRG2"
pub const AUTHORITY_INPUT_KIND: u32 = 0x5456_3241; // "TV2A"

pub const HOT_HEAP_ALLOCATIONS: usize = 0;
pub const TRACE_WRITES_FAIL_BEFORE_FIRST_WRITE = true;
pub const RELATION_WRITES_FAIL_BEFORE_FIRST_WRITE = true;
pub const FROZEN_V1_ROW_COMPATIBLE = false;
pub const REQUIRES_VERSIONED_OUTER_MANIFEST = true;
pub const PRODUCTION_ACTIVATION = false;

pub const Digest = transcript.Digest;
pub const ProviderCall = provider.Call;
pub const ControlRowV2 = control_witness.Row;
pub const TranscriptAirRowV2 = transcript_air_witness.Row;

pub const Error = transcript.Error || error{
    AliasedDestination,
    ArithmeticOverflow,
    AuthorityMismatch,
    DestinationLengthMismatch,
    InvalidManifest,
    InvalidQuerySchedule,
    InvalidRelationEvent,
    InvalidTraceShape,
    NonCanonicalProgramWord,
    PoseidonRangeMismatch,
    SourceMismatch,
    UnsupportedVersion,
};

/// Exact dynamic geometry for V2 rows 0--9.  Counts are logical rows; each
/// `log_size` is the smallest admitted power-of-two trace with the universal
/// minimum of sixteen rows.
pub const ManifestV2 = struct {
    format_version: u16 = MANIFEST_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    frozen_v1_compatible: bool = FROZEN_V1_ROW_COMPATIBLE,
    first_roster_row: u8 = FIRST_ROW,
    row_count: u8 = ROW_COUNT,
    logical_rows: [ROW_COUNT]u32,
    log_sizes: [ROW_COUNT]u8,
    relation_event_count: u32,
    poseidon_request_count: u32,
    program_id: Digest,
    wire_id: Digest,
    statement_authority_id: Digest,
    identity: Digest,

    pub fn validate(self: *const ManifestV2) Error!void {
        if (self.format_version != MANIFEST_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.frozen_v1_compatible or self.first_roster_row != FIRST_ROW or
            self.row_count != ROW_COUNT)
        {
            return error.UnsupportedVersion;
        }
        for (self.logical_rows, self.log_sizes) |count, log_size| {
            if (log_size < MIN_LOG_SIZE or log_size > MAX_LOG_SIZE or
                (@as(u64, 1) << @intCast(log_size)) < count or
                (log_size > MIN_LOG_SIZE and
                    (@as(u64, 1) << @intCast(log_size - 1)) >= count))
            {
                return error.InvalidManifest;
            }
        }
        if (self.poseidon_request_count != self.logical_rows[rowIndex(.transcript_air)] or
            self.logical_rows[rowIndex(.transcript_air)] !=
                self.logical_rows[rowIndex(.transcript_binding)] or
            !std.meta.eql(self.identity, manifestId(self)))
        {
            return error.InvalidManifest;
        }
    }
};

pub const CountsV2 = struct {
    control: usize,
    transcript_air: usize,
    transcript_binding: usize,
    transcript_state: usize,
    transcript_word: usize,
    transcript_payload: usize,
    pow_check: usize,
    pow_frame: usize,
    relation_challenge: usize,
    verifier_randomness: usize,
    relation_events: usize,
    poseidon_requests: usize,

    pub fn asRows(self: CountsV2) [ROW_COUNT]usize {
        return .{
            self.control,
            self.transcript_air,
            self.transcript_binding,
            self.transcript_state,
            self.transcript_word,
            self.transcript_payload,
            self.pow_check,
            self.pow_frame,
            self.relation_challenge,
            self.verifier_randomness,
        };
    }
};

/// The three native identities that the V2 integration must make
/// proof-visible.  `canonicalWords` is deliberately allocation-free.
pub const AuthorityBindingV2 = struct {
    program_id: Digest,
    wire_id: Digest,
    statement_authority_id: Digest,

    pub fn canonicalWords(self: AuthorityBindingV2) [3 * channel.RATE]M31 {
        var result: [3 * channel.RATE]M31 = undefined;
        writeDigestFields(result[0..channel.RATE], self.program_id);
        writeDigestFields(result[channel.RATE .. 2 * channel.RATE], self.wire_id);
        writeDigestFields(
            result[2 * channel.RATE .. 3 * channel.RATE],
            self.statement_authority_id,
        );
        return result;
    }
};

pub fn deriveCounts(
    program: *const transcript.Program,
    execution: *const transcript.Execution,
    plan: *const schedule.Plan,
) Error!CountsV2 {
    var word_count: usize = 0;
    var payload_count: usize = 0;
    for (execution.hash_frames) |frame| {
        const padded = std.math.mul(
            usize,
            frame.call_count,
            channel.RATE,
        ) catch return error.ArithmeticOverflow;
        if (padded < channel.RATE or frame.words.len < channel.RATE)
            return error.InvalidTraceShape;
        word_count = try checkedAdd(word_count, padded - channel.RATE);
        if (frame.purpose == .mix)
            payload_count = try checkedAdd(payload_count, frame.words.len - channel.RATE);
    }
    var relation_count: usize = 0;
    var randomness_count: usize = 0;
    for (program.instructions) |instruction| switch (instruction.kind) {
        .relation_draw => relation_count += 1,
        .composition_draw,
        .oods_draw,
        .deep_draw,
        .fri_alpha_draw,
        .query_draw,
        => randomness_count += 1,
        else => {},
    };

    const control_count = plan.steps.len;
    var event_count: usize = 0;
    event_count = try checkedAdd(event_count, try checkedMul(control_count, 2));
    event_count = try checkedAdd(
        event_count,
        try checkedMul(execution.poseidon_calls.len, 6 + 14),
    );
    event_count = try checkedAdd(
        event_count,
        try checkedMul(execution.hash_frames.len, 12),
    );
    event_count = try checkedAdd(event_count, try checkedMul(word_count, 2));
    event_count = try checkedAdd(event_count, try checkedMul(payload_count, 2));
    event_count = try checkedAdd(
        event_count,
        try checkedMul(execution.pow_checks.len, 1 + 2),
    );
    event_count = try checkedAdd(event_count, try checkedMul(relation_count, 17));
    event_count = try checkedAdd(event_count, try checkedMul(randomness_count, 9));

    return .{
        .control = control_count,
        .transcript_air = execution.poseidon_calls.len,
        .transcript_binding = execution.poseidon_calls.len,
        .transcript_state = execution.hash_frames.len,
        .transcript_word = word_count,
        .transcript_payload = payload_count,
        .pow_check = execution.pow_checks.len,
        .pow_frame = execution.pow_checks.len,
        .relation_challenge = relation_count,
        .verifier_randomness = randomness_count,
        .relation_events = event_count,
        .poseidon_requests = execution.poseidon_calls.len,
    };
}

pub fn manifestFor(program: *const transcript.Program, counts: CountsV2) Error!ManifestV2 {
    const rows = counts.asRows();
    var logical_rows: [ROW_COUNT]u32 = undefined;
    var log_sizes: [ROW_COUNT]u8 = undefined;
    for (rows, 0..) |count, index| {
        logical_rows[index] = std.math.cast(u32, count) orelse
            return error.ArithmeticOverflow;
        log_sizes[index] = try traceLogSize(count);
    }
    var result = ManifestV2{
        .logical_rows = logical_rows,
        .log_sizes = log_sizes,
        .relation_event_count = std.math.cast(u32, counts.relation_events) orelse
            return error.ArithmeticOverflow,
        .poseidon_request_count = std.math.cast(u32, counts.poseidon_requests) orelse
            return error.ArithmeticOverflow,
        .program_id = program.identity,
        .wire_id = program.wire_id,
        .statement_authority_id = program.statement_authority_id,
        .identity = undefined,
    };
    result.identity = manifestId(&result);
    try result.validate();
    return result;
}

pub fn countsFromManifest(manifest: ManifestV2) CountsV2 {
    return .{
        .control = manifest.logical_rows[rowIndex(.control)],
        .transcript_air = manifest.logical_rows[rowIndex(.transcript_air)],
        .transcript_binding = manifest.logical_rows[rowIndex(.transcript_binding)],
        .transcript_state = manifest.logical_rows[rowIndex(.transcript_state)],
        .transcript_word = manifest.logical_rows[rowIndex(.transcript_word)],
        .transcript_payload = manifest.logical_rows[rowIndex(.transcript_payload)],
        .pow_check = manifest.logical_rows[rowIndex(.pow_check)],
        .pow_frame = manifest.logical_rows[rowIndex(.pow_frame)],
        .relation_challenge = manifest.logical_rows[rowIndex(.relation_challenge)],
        .verifier_randomness = manifest.logical_rows[rowIndex(.verifier_randomness)],
        .relation_events = manifest.relation_event_count,
        .poseidon_requests = manifest.poseidon_request_count,
    };
}

pub fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

pub fn validateProgramWords(
    program: *const transcript.Program,
    plan: *const schedule.Plan,
) Error!void {
    if (program.instructions.len == 0 or program.instructions.len >= m31.Modulus or
        plan.steps.len == 0 or plan.steps.len >= m31.Modulus)
    {
        return error.NonCanonicalProgramWord;
    }
    for (plan.steps, 0..) |step, sequence| {
        const encoded = step.encode();
        if (sequence >= m31.Modulus or encoded.tag >= m31.Modulus)
            return error.NonCanonicalProgramWord;
        for (encoded.args) |arg| if (arg >= m31.Modulus)
            return error.NonCanonicalProgramWord;
    }
    for (program.instructions, 0..) |instruction, index| {
        if (index >= m31.Modulus or instruction.verifier_sequence >= plan.steps.len or
            instruction.sub_index >= m31.Modulus or typedTag(instruction.kind) >= m31.Modulus)
        {
            return error.NonCanonicalProgramWord;
        }
        for (instruction.args) |arg| if (arg >= m31.Modulus)
            return error.NonCanonicalProgramWord;
        if (instruction.kind == .query_draw and
            (instruction.args[2] == 0 or instruction.args[2] > channel.RATE))
        {
            return error.InvalidTraceShape;
        }
    }
}

pub fn validateRawQuerySchedule(
    program: *const transcript.Program,
    execution: *const transcript.Execution,
) Error!usize {
    var expected_block: u32 = 0;
    var expected_item: usize = 0;
    for (program.instructions, execution.operations) |instruction, operation| {
        if (instruction.kind != .query_draw) continue;
        const width: usize = @intCast(instruction.args[2]);
        const expected_item_u32 = std.math.cast(u32, expected_item) orelse
            return error.ArithmeticOverflow;
        if (instruction.args[0] != expected_block or
            instruction.args[1] != expected_item_u32 or width == 0 or
            width > channel.RATE or operation.draw == null)
        {
            return error.InvalidQuerySchedule;
        }
        expected_item = try checkedAdd(expected_item, width);
        expected_block = std.math.add(u32, expected_block, 1) catch
            return error.ArithmeticOverflow;
    }
    if (expected_item == 0) return error.InvalidQuerySchedule;
    return expected_item;
}

pub fn typedTag(kind: transcript.Kind) u32 {
    return switch (kind) {
        .interaction_pow => 6,
        .relation_draw => 7,
        .composition_draw => 9,
        .oods_draw => 10,
        .deep_draw => 16,
        .fri_alpha_draw => 18,
        .pcs_pow => 20,
        .query_draw => 21,
        else => @as(u32, 0x200) + @intFromEnum(kind),
    };
}

pub fn traceLogSize(row_count: usize) Error!u8 {
    const padded = std.math.ceilPowerOfTwo(usize, @max(row_count, 1)) catch
        return error.ArithmeticOverflow;
    const result: u8 = @max(MIN_LOG_SIZE, std.math.log2_int(usize, padded));
    if (result > MAX_LOG_SIZE) return error.InvalidTraceShape;
    return result;
}

pub fn rowIndex(component: roster.Component) usize {
    const raw = @intFromEnum(component);
    std.debug.assert(raw >= FIRST_ROW and raw <= LAST_ROW);
    return raw - FIRST_ROW;
}

pub fn felt(value: u32) M31 {
    std.debug.assert(value < m31.Modulus);
    return M31.fromCanonical(value);
}

pub fn writeDigestFields(destination: []M31, value: Digest) void {
    std.debug.assert(destination.len == channel.RATE);
    for (destination, value) |*target, word| target.* = felt(word);
}

pub fn checkedAdd(left: usize, right: usize) Error!usize {
    return std.math.add(usize, left, right) catch error.ArithmeticOverflow;
}

pub fn checkedMul(left: usize, right: usize) Error!usize {
    return std.math.mul(usize, left, right) catch error.ArithmeticOverflow;
}

pub fn manifestId(manifest: *const ManifestV2) Digest {
    var hash = IdentityHasher.init(MANIFEST_ID_DOMAIN);
    hash.scalar(manifest.format_version);
    hash.scalar(manifest.schema_version);
    hash.scalar(@intFromBool(manifest.frozen_v1_compatible));
    hash.scalar(manifest.first_roster_row);
    hash.scalar(manifest.row_count);
    for (manifest.logical_rows) |value| hash.u32Value(value);
    for (manifest.log_sizes) |value| hash.scalar(value);
    hash.u32Value(manifest.relation_event_count);
    hash.u32Value(manifest.poseidon_request_count);
    hash.digest(manifest.program_id);
    hash.digest(manifest.wire_id);
    hash.digest(manifest.statement_authority_id);
    return hash.finalize();
}

pub const IdentityHasher = struct {
    inner: channel.CanonicalWordHasher,

    pub fn init(domain: u32) IdentityHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    pub fn scalar(self: *IdentityHasher, value: anytype) void {
        const raw: u32 = @intCast(value);
        std.debug.assert(raw < m31.Modulus);
        const words = [_]M31{M31.fromCanonical(raw)};
        self.inner.update(&words);
    }

    pub fn u32Value(self: *IdentityHasher, value: u32) void {
        self.scalar(value & 0xffff);
        self.scalar(value >> 16);
    }

    pub fn digest(self: *IdentityHasher, value: Digest) void {
        for (value) |word| self.scalar(word);
    }

    pub fn bytes(self: *IdentityHasher, value: []const u8) void {
        self.u32Value(@intCast(value.len));
        for (value) |byte| self.scalar(byte);
    }

    pub fn finalize(self: *IdentityHasher) Digest {
        return self.inner.finalize();
    }
};
