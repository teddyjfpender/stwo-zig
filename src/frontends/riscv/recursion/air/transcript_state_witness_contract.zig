//! Internal transcript state witness authority shard; use transcript_state_witness.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const digest = @import("../../air/lang/digest.zig");
pub const direct = @import("../../air/lang/direct_witness_executor.zig");
pub const types = @import("../../air/lang/types.zig");
pub const binding_witness = @import("transcript_binding_witness.zig");
pub const component = @import("transcript_state.zig");
pub const proof_kind_mod = @import("proof_kind.zig");
pub const schedule = @import("verifier_schedule.zig");
pub const transcript = @import("pow_frame_witness.zig");

pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const SEGMENT_VERIFIER_ID: u32 = binding_witness.SEGMENT_VERIFIER_ID;
pub const LEFT_RECURSION_VERIFIER_ID: u32 =
    binding_witness.LEFT_RECURSION_VERIFIER_ID;
pub const RIGHT_RECURSION_VERIFIER_ID: u32 =
    binding_witness.RIGHT_RECURSION_VERIFIER_ID;
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
    "stwo-zig/typed-air/recursion-transcript-state-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "ec928fa62ba519b92ac08c9b8f8326d4a3ad06bad7a6210944a626e6531ad33e";
pub const BINDING_DIGEST = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion transcript-state witness digest",
);
pub const PREPROCESSING_FORMAT_VERSION: u16 = 1;
pub const PREPROCESSING_DOMAIN =
    "stwo-zig/typed-air/recursion-transcript-state-preprocessing/v1\x00";
pub const WITNESS_FORMAT_VERSION: u16 = 1;
pub const WITNESS_DOMAIN =
    "stwo-zig/typed-air/recursion-transcript-state-main/v1\x00";

pub const Error = direct.Error || schedule.Error || component.ValidationError ||
    binding_witness.Error || std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    BindingMismatch,
    CallCountMismatch,
    FrameCountMismatch,
    FrameIndexOutOfRange,
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
    hash_id: u32,
    input_state_key: u32,
    output_state_key: u32,
    initial_mask: u32,
    state_consume_mask: u32,
    state_produce_multiplicity: u32,
    draw_output_mask: u32,

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
            M31.fromCanonical(self.hash_id),
            M31.fromCanonical(self.input_state_key),
            M31.fromCanonical(self.output_state_key),
            M31.fromCanonical(self.initial_mask),
            M31.fromCanonical(self.state_consume_mask),
            M31.fromCanonical(self.state_produce_multiplicity),
            M31.fromCanonical(self.draw_output_mask),
        };
    }
};

pub const Preprocessed = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    rows: []PreprocessedRow,
    vm_frame_count: usize,
    recursion_frame_count: usize,
    vm_call_count: usize,
    recursion_call_count: usize,
    vm_schedule_digest: [8]u32,
    recursion_schedule_digest: [8]u32,
    call_preprocessing_digest: digest.Digest,
    authority_digest: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        calls: *const binding_witness.Preprocessed,
    ) Error!Preprocessed {
        try component.SourceAuthority.pinned().validate();
        try calls.validate();
        const lanes = try callLanes(calls);
        const vm_frames = try frameCount(lanes.vm);
        const recursion_frames = try frameCount(lanes.left);
        if (try frameCount(lanes.right) != recursion_frames)
            return error.InvalidTranscriptLayout;
        const row_count = std.math.add(
            usize,
            vm_frames,
            std.math.mul(usize, recursion_frames, 2) catch
                return error.ArithmeticOverflow,
        ) catch return error.ArithmeticOverflow;
        const log_size = try traceLogSize(row_count);
        const rows = try allocator.alloc(PreprocessedRow, row_count);
        errdefer allocator.free(rows);
        var cursor: usize = 0;
        try appendCallRows(rows, &cursor, lanes.vm, SEGMENT_VERIFIER_ID, 1, 0);
        try appendCallRows(rows, &cursor, lanes.left, LEFT_RECURSION_VERIFIER_ID, 0, 1);
        try appendCallRows(rows, &cursor, lanes.right, RIGHT_RECURSION_VERIFIER_ID, 0, 1);
        if (cursor != rows.len) return error.InvalidTranscriptLayout;
        for (rows) |row| try validatePreprocessedRow(row);
        const authority_digest = preprocessingDigest(
            log_size,
            vm_frames,
            recursion_frames,
            calls.vm_call_count,
            calls.recursion_call_count,
            calls.vm_schedule_digest,
            calls.recursion_schedule_digest,
            calls.authority_digest,
            rows,
        );
        return .{
            .allocator = allocator,
            .log_size = log_size,
            .rows = rows,
            .vm_frame_count = vm_frames,
            .recursion_frame_count = recursion_frames,
            .vm_call_count = calls.vm_call_count,
            .recursion_call_count = calls.recursion_call_count,
            .vm_schedule_digest = calls.vm_schedule_digest,
            .recursion_schedule_digest = calls.recursion_schedule_digest,
            .call_preprocessing_digest = calls.authority_digest,
            .authority_digest = authority_digest,
        };
    }

    pub fn deinit(self: *Preprocessed) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    /// Allocation-free validation suitable for the prepared writer boundary.
    pub fn validate(self: *const Preprocessed) Error!void {
        const expected_rows = std.math.add(
            usize,
            self.vm_frame_count,
            std.math.mul(usize, self.recursion_frame_count, 2) catch
                return error.ArithmeticOverflow,
        ) catch return error.ArithmeticOverflow;
        if (self.rows.len != expected_rows or
            self.log_size != try traceLogSize(self.rows.len))
        {
            return error.AuthorityMismatch;
        }
        for (self.rows) |row| try validatePreprocessedRow(row);
        const actual = preprocessingDigest(
            self.log_size,
            self.vm_frame_count,
            self.recursion_frame_count,
            self.vm_call_count,
            self.recursion_call_count,
            self.vm_schedule_digest,
            self.recursion_schedule_digest,
            self.call_preprocessing_digest,
            self.rows,
        );
        if (!std.mem.eql(u8, &actual, &self.authority_digest))
            return error.AuthorityMismatch;
    }

    /// Cold verifier-key admission check against row 2's originating call map.
    pub fn validateAgainst(
        self: *const Preprocessed,
        calls: *const binding_witness.Preprocessed,
    ) Error!void {
        try self.validate();
        try calls.validate();
        if (!std.mem.eql(u8, &self.call_preprocessing_digest, &calls.authority_digest) or
            self.vm_call_count != calls.vm_call_count or
            self.recursion_call_count != calls.recursion_call_count or
            !std.meta.eql(self.vm_schedule_digest, calls.vm_schedule_digest) or
            !std.meta.eql(self.recursion_schedule_digest, calls.recursion_schedule_digest))
        {
            return error.AuthorityMismatch;
        }
        const lanes = try callLanes(calls);
        if (self.vm_frame_count != try frameCount(lanes.vm) or
            self.recursion_frame_count != try frameCount(lanes.left) or
            self.recursion_frame_count != try frameCount(lanes.right))
        {
            return error.AuthorityMismatch;
        }
        var cursor: usize = 0;
        try compareCallRows(self.rows, &cursor, lanes.vm, SEGMENT_VERIFIER_ID, 1, 0);
        try compareCallRows(self.rows, &cursor, lanes.left, LEFT_RECURSION_VERIFIER_ID, 0, 1);
        try compareCallRows(self.rows, &cursor, lanes.right, RIGHT_RECURSION_VERIFIER_ID, 0, 1);
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
    inputs: [RATE]M31,
    outputs: [RATE]M31,

    pub fn values(self: MainRow) [MAIN_COLUMN_COUNT]M31 {
        return .{M31.fromCanonical(self.enabler)} ++ self.inputs ++ self.outputs;
    }
};

pub const CallLanes = struct {
    vm: []const binding_witness.PreprocessedRow,
    left: []const binding_witness.PreprocessedRow,
    right: []const binding_witness.PreprocessedRow,
};

pub fn callLanes(calls: *const binding_witness.Preprocessed) Error!CallLanes {
    const left_start = calls.vm_call_count;
    const right_start = std.math.add(
        usize,
        left_start,
        calls.recursion_call_count,
    ) catch return error.ArithmeticOverflow;
    const end = std.math.add(
        usize,
        right_start,
        calls.recursion_call_count,
    ) catch return error.ArithmeticOverflow;
    if (end != calls.rows.len) return error.InvalidTranscriptLayout;
    return .{
        .vm = calls.rows[0..left_start],
        .left = calls.rows[left_start..right_start],
        .right = calls.rows[right_start..end],
    };
}

pub fn frameCount(rows: []const binding_witness.PreprocessedRow) Error!usize {
    var count: usize = 0;
    var row_at: usize = 0;
    while (row_at < rows.len) {
        const first = rows[row_at];
        if (first.is_first != 1) return error.InvalidTranscriptLayout;
        count = std.math.add(usize, count, 1) catch
            return error.ArithmeticOverflow;
        var end = row_at;
        while (end < rows.len and rows[end].is_last == 0) : (end += 1) {}
        if (end >= rows.len) return error.InvalidTranscriptLayout;
        row_at = end + 1;
    }
    return count;
}

pub fn operationCount(rows: []const binding_witness.PreprocessedRow) Error!usize {
    var count: usize = 0;
    var row_at: usize = 0;
    while (row_at < rows.len) {
        const first = rows[row_at];
        if (first.is_first != 1) return error.InvalidTranscriptLayout;
        count = std.math.add(
            usize,
            count,
            @intFromBool(first.is_operation_first == 1),
        ) catch return error.ArithmeticOverflow;
        var end = row_at;
        while (end < rows.len and rows[end].is_last == 0) : (end += 1) {}
        if (end >= rows.len) return error.InvalidTranscriptLayout;
        row_at = end + 1;
    }
    if (count == 0) return error.InvalidTranscriptLayout;
    return count;
}

pub fn appendCallRows(
    destination: []PreprocessedRow,
    cursor: *usize,
    calls: []const binding_witness.PreprocessedRow,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Error!void {
    const operation_count = try operationCount(calls);
    var next_ordinal: usize = 0;
    var row_at: usize = 0;
    while (row_at < calls.len) {
        const first = calls[row_at];
        if (first.is_first != 1) return error.InvalidTranscriptLayout;
        var frame_end = row_at;
        while (frame_end < calls.len and calls[frame_end].is_last == 0) : (frame_end += 1) {}
        if (frame_end >= calls.len) return error.InvalidTranscriptLayout;
        const is_mix = first.is_operation_first == 1;
        const ordinal = if (is_mix) next_ordinal else std.math.sub(
            usize,
            next_ordinal,
            1,
        ) catch return error.InvalidTranscriptLayout;
        if (is_mix) next_ordinal = std.math.add(usize, next_ordinal, 1) catch
            return error.ArithmeticOverflow;
        const next_frame = frame_end + 1;
        const has_draw = is_mix and next_frame < calls.len and
            calls[next_frame].is_first == 1 and calls[next_frame].is_draw == 1 and
            calls[next_frame].sequence == first.sequence;
        const has_next = ordinal + 1 < operation_count;
        const pow_frame = calls[frame_end].pow_final_mask == 1;
        if ((first.is_draw == 1) == is_mix or (pow_frame and is_mix))
            return error.InvalidTranscriptLayout;
        if (cursor.* >= destination.len or ordinal >= m31.Modulus or
            ordinal + 1 >= m31.Modulus)
        {
            return error.FrameIndexOutOfRange;
        }
        destination[cursor.*] = stateRow(
            first,
            verifier_id,
            segment_mask,
            binary_mask,
            @intCast(ordinal),
            is_mix,
            has_draw,
            has_next,
            pow_frame,
        );
        cursor.* += 1;
        row_at = next_frame;
    }
    if (next_ordinal != operation_count) return error.InvalidTranscriptLayout;
}

pub fn compareCallRows(
    actual: []const PreprocessedRow,
    cursor: *usize,
    calls: []const binding_witness.PreprocessedRow,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
) Error!void {
    const operation_count = try operationCount(calls);
    var next_ordinal: usize = 0;
    var row_at: usize = 0;
    while (row_at < calls.len) {
        const first = calls[row_at];
        if (first.is_first != 1) return error.AuthorityMismatch;
        var frame_end = row_at;
        while (frame_end < calls.len and calls[frame_end].is_last == 0) : (frame_end += 1) {}
        if (frame_end >= calls.len) return error.AuthorityMismatch;
        const is_mix = first.is_operation_first == 1;
        const ordinal = if (is_mix) next_ordinal else std.math.sub(
            usize,
            next_ordinal,
            1,
        ) catch return error.AuthorityMismatch;
        if (is_mix) next_ordinal = std.math.add(usize, next_ordinal, 1) catch
            return error.ArithmeticOverflow;
        const next_frame = frame_end + 1;
        const has_draw = is_mix and next_frame < calls.len and
            calls[next_frame].is_first == 1 and calls[next_frame].is_draw == 1 and
            calls[next_frame].sequence == first.sequence;
        const expected = stateRow(
            first,
            verifier_id,
            segment_mask,
            binary_mask,
            @intCast(ordinal),
            is_mix,
            has_draw,
            ordinal + 1 < operation_count,
            calls[frame_end].pow_final_mask == 1,
        );
        if (cursor.* >= actual.len or !std.meta.eql(actual[cursor.*], expected))
            return error.AuthorityMismatch;
        cursor.* += 1;
        row_at = next_frame;
    }
    if (next_ordinal != operation_count) return error.AuthorityMismatch;
}

pub fn stateRow(
    first: binding_witness.PreprocessedRow,
    verifier_id: u32,
    segment_mask: u32,
    binary_mask: u32,
    ordinal: u32,
    is_mix: bool,
    has_draw: bool,
    has_next: bool,
    pow_frame: bool,
) PreprocessedRow {
    const next_key = ordinal + 1;
    return .{
        .row_mask = 1,
        .segment_mask = segment_mask,
        .binary_mask = binary_mask,
        .verifier_id = verifier_id,
        .sequence = first.sequence,
        .tag = first.tag,
        .args = first.args,
        .hash_id = first.hash_id,
        .input_state_key = if (is_mix) ordinal else next_key,
        .output_state_key = next_key,
        .initial_mask = @intFromBool(is_mix and ordinal == 0),
        .state_consume_mask = @intFromBool(!is_mix or ordinal > 0),
        .state_produce_multiplicity = if (is_mix)
            @as(u32, @intFromBool(has_draw)) + @intFromBool(has_next)
        else
            0,
        .draw_output_mask = @intFromBool(!is_mix and !pow_frame),
    };
}

pub fn validatePreprocessedRow(row: PreprocessedRow) Error!void {
    if (row.row_mask != 1 or row.segment_mask > 1 or row.binary_mask > 1 or
        row.segment_mask + row.binary_mask != 1 or row.verifier_id >= 3 or
        row.sequence >= m31.Modulus or row.tag >= m31.Modulus or
        row.hash_id >= m31.Modulus or row.input_state_key >= m31.Modulus or
        row.output_state_key >= m31.Modulus or row.initial_mask > 1 or
        row.state_consume_mask > 1 or row.state_produce_multiplicity > 2 or
        row.draw_output_mask > 1 or row.output_state_key == 0 or
        (row.verifier_id == SEGMENT_VERIFIER_ID) != (row.segment_mask == 1))
    {
        return error.InvalidPreprocessedRow;
    }
    for (row.args) |arg| if (arg >= m31.Modulus)
        return error.InvalidFieldElement;
    const mix = row.input_state_key + 1 == row.output_state_key;
    const draw = row.input_state_key == row.output_state_key;
    if ((!mix and !draw) or
        (row.initial_mask == 1 and (!mix or row.input_state_key != 0)) or
        (row.state_consume_mask == 1) != (draw or row.input_state_key > 0) or
        (!mix and row.state_produce_multiplicity != 0) or
        (row.draw_output_mask == 1 and !draw))
    {
        return error.InvalidPreprocessedRow;
    }
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
    vm_frames: usize,
    recursion_frames: usize,
    vm_calls: usize,
    recursion_calls: usize,
    vm_schedule: [8]u32,
    recursion_schedule: [8]u32,
    call_digest: digest.Digest,
    rows: []const PreprocessedRow,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PREPROCESSING_DOMAIN);
    hashInt(&hash, u16, PREPROCESSING_FORMAT_VERSION);
    hash.update(&component.SOURCE_AUTHORITY_DIGEST);
    hashInt(&hash, u32, log_size);
    hashInt(&hash, u64, vm_frames);
    hashInt(&hash, u64, recursion_frames);
    hashInt(&hash, u64, vm_calls);
    hashInt(&hash, u64, recursion_calls);
    for (vm_schedule) |word| hashInt(&hash, u32, word);
    for (recursion_schedule) |word| hashInt(&hash, u32, word);
    hash.update(&call_digest);
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
    hashInt(hash, u32, row.hash_id);
    hashInt(hash, u32, row.input_state_key);
    hashInt(hash, u32, row.output_state_key);
    hashInt(hash, u32, row.initial_mask);
    hashInt(hash, u32, row.state_consume_mask);
    hashInt(hash, u32, row.state_produce_multiplicity);
    hashInt(hash, u32, row.draw_output_mask);
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
