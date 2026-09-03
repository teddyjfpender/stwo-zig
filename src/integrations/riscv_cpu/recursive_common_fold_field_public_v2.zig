//! Field-native public authority and Poseidon schedule for the common fold.
//!
//! Both children are already verifier-owned common-wrapper admissions.  This
//! module derives the parent `NodePublicV2` and the exact native Poseidon calls
//! which authenticate its statement, ordered child source, subtree, and full
//! output.  It does not verify either child proof and cannot mint a parent
//! admission on its own.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_mod = @import("recursive_node_artifact_v1.zig");
const field_public = @import("recursive_field_node_public_v2.zig");

const m31 = stwo_core.fields.m31;
const M31 = m31.M31;
const channel = frontend.recursion.poseidon2_channel;
const poseidon = frontend.air.memory_commitment.poseidon2;
const poseidon_air = frontend.air.memory_commitment.poseidon2_air;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const CHILD_COUNT: usize = 2;
pub const HEADER_WORD_COUNT: usize = field_public.HEADER_WORD_COUNT;
pub const STATEMENT_WORD_COUNT: usize = field_public.STATEMENT_WORD_COUNT;
pub const SOURCE_PREIMAGE_WORD_COUNT: usize = 4 * channel.RATE;
pub const SUBTREE_PREIMAGE_WORD_COUNT: usize =
    HEADER_WORD_COUNT + 2 * channel.RATE;
pub const OUTPUT_PREIMAGE_WORD_COUNT: usize =
    HEADER_WORD_COUNT + STATEMENT_WORD_COUNT + 3 * channel.RATE;

pub const STATEMENT_CALL_COUNT: usize =
    channel.canonicalWordPermutationCount(STATEMENT_WORD_COUNT);
pub const SOURCE_CALL_COUNT: usize =
    channel.canonicalWordPermutationCount(SOURCE_PREIMAGE_WORD_COUNT);
pub const SUBTREE_CALL_COUNT: usize =
    channel.canonicalWordPermutationCount(SUBTREE_PREIMAGE_WORD_COUNT);
pub const OUTPUT_CALL_COUNT: usize =
    channel.canonicalWordPermutationCount(OUTPUT_PREIMAGE_WORD_COUNT);
pub const POSEIDON_CALL_COUNT: usize = STATEMENT_CALL_COUNT +
    SOURCE_CALL_COUNT + SUBTREE_CALL_COUNT + OUTPUT_CALL_COUNT;
pub const MINIMUM_POSEIDON_LOG_SIZE: u32 =
    std.math.log2_int_ceil(usize, POSEIDON_CALL_COUNT);

pub const PRODUCTION_ACTIVATION = false;
pub const CHILD_PROOF_VERIFIER_AVAILABLE = false;
pub const COLD_PARENT_PROOF_AVAILABLE = false;

pub const Error = field_public.Error || artifact_mod.Error || error{
    CommonFoldFieldScheduleMismatch,
    CommonFoldPublicInputMismatch,
};

pub const PhaseV2 = enum(u8) {
    statement = 0,
    source = 1,
    subtree = 2,
    output = 3,
};

pub const PhaseRangeV2 = struct {
    phase: PhaseV2,
    first_call: u16,
    call_count: u16,
    output_digest: channel.Digest,
};

pub const PoseidonScheduleV2 = struct {
    parent_coordinate: artifact_mod.TaskCoordinateV1,
    parent: field_public.NodePublicV2,
    phases: [4]PhaseRangeV2,
    calls: [POSEIDON_CALL_COUNT]poseidon_air.Call,

    pub fn build(
        left: *const field_public.NodePublicV2,
        right: *const field_public.NodePublicV2,
        parent_coordinate: artifact_mod.TaskCoordinateV1,
    ) Error!PoseidonScheduleV2 {
        const result = try buildUnchecked(left, right, parent_coordinate);
        try result.validateAgainst(left, right, parent_coordinate);
        return result;
    }

    pub fn validateAgainst(
        self: *const PoseidonScheduleV2,
        left: *const field_public.NodePublicV2,
        right: *const field_public.NodePublicV2,
        parent_coordinate: artifact_mod.TaskCoordinateV1,
    ) Error!void {
        const expected = try buildUnchecked(left, right, parent_coordinate);
        if (!std.meta.eql(self.*, expected))
            return error.CommonFoldFieldScheduleMismatch;
    }

    pub fn callsSlice(self: *const PoseidonScheduleV2) []const poseidon_air.Call {
        return &self.calls;
    }
};

fn buildUnchecked(
    left: *const field_public.NodePublicV2,
    right: *const field_public.NodePublicV2,
    parent_coordinate: artifact_mod.TaskCoordinateV1,
) Error!PoseidonScheduleV2 {
    try left.validate();
    try right.validate();
    const parent = field_public.NodePublicV2.initParent(
        left,
        right,
        parent_coordinate,
    ) catch return error.CommonFoldPublicInputMismatch;
    var result = PoseidonScheduleV2{
        .parent_coordinate = parent_coordinate,
        .parent = parent,
        .phases = undefined,
        .calls = undefined,
    };
    var cursor: usize = 0;
    result.phases[@intFromEnum(PhaseV2.statement)] = appendHash(
        &result.calls,
        &cursor,
        .statement,
        &parent.statement_words,
        field_public.STATEMENT_DIGEST_DOMAIN,
    );
    const source_preimage = parentSourcePreimage(left, right);
    result.phases[@intFromEnum(PhaseV2.source)] = appendHash(
        &result.calls,
        &cursor,
        .source,
        &source_preimage,
        field_public.PARENT_SOURCE_DOMAIN,
    );
    const subtree_preimage = subtreePreimage(&parent);
    result.phases[@intFromEnum(PhaseV2.subtree)] = appendHash(
        &result.calls,
        &cursor,
        .subtree,
        &subtree_preimage,
        field_public.SUBTREE_DIGEST_DOMAIN,
    );
    const output_preimage = outputPreimage(&parent);
    result.phases[@intFromEnum(PhaseV2.output)] = appendHash(
        &result.calls,
        &cursor,
        .output,
        &output_preimage,
        field_public.OUTPUT_DIGEST_DOMAIN,
    );
    if (cursor != result.calls.len or
        !std.meta.eql(
            result.phases[@intFromEnum(PhaseV2.statement)].output_digest,
            parent.statement_digest,
        ) or !std.meta.eql(
        result.phases[@intFromEnum(PhaseV2.source)].output_digest,
        parent.source_digest,
    ) or !std.meta.eql(
        result.phases[@intFromEnum(PhaseV2.subtree)].output_digest,
        parent.subtree_digest,
    ) or !std.meta.eql(
        result.phases[@intFromEnum(PhaseV2.output)].output_digest,
        parent.output_digest,
    )) return error.CommonFoldFieldScheduleMismatch;
    return result;
}

pub fn parentSourcePreimage(
    left: *const field_public.NodePublicV2,
    right: *const field_public.NodePublicV2,
) [SOURCE_PREIMAGE_WORD_COUNT]u32 {
    return left.output_digest ++ left.subtree_digest ++
        right.output_digest ++ right.subtree_digest;
}

fn headerWords(
    value: *const field_public.NodePublicV2,
) [HEADER_WORD_COUNT]u32 {
    return .{
        value.format_version,
        value.schema_version,
        @intFromEnum(value.node_kind),
        value.coordinate.height,
        value.coordinate.index,
        value.coordinate.global_ordinal,
    };
}

fn subtreePreimage(
    value: *const field_public.NodePublicV2,
) [SUBTREE_PREIMAGE_WORD_COUNT]u32 {
    return headerWords(value) ++ value.statement_digest ++ value.source_digest;
}

fn outputPreimage(
    value: *const field_public.NodePublicV2,
) [OUTPUT_PREIMAGE_WORD_COUNT]u32 {
    return headerWords(value) ++ value.statement_words ++
        value.statement_digest ++ value.source_digest ++ value.subtree_digest;
}

fn appendHash(
    calls: *[POSEIDON_CALL_COUNT]poseidon_air.Call,
    cursor: *usize,
    phase: PhaseV2,
    words: []const u32,
    capacity_tag: u32,
) PhaseRangeV2 {
    std.debug.assert(capacity_tag < m31.Modulus);
    const first_call = cursor.*;
    var state = [_]M31{M31.zero()} ** poseidon.WIDTH;
    state[poseidon.WIDTH - 1] = M31.fromCanonical(capacity_tag);
    var filled: usize = 0;
    for (words) |word| {
        std.debug.assert(word < m31.Modulus);
        absorbWord(calls, cursor, &state, &filled, word);
    }
    absorbWord(calls, cursor, &state, &filled, 1);
    if (filled != 0) appendPermutation(calls, cursor, &state);
    var output: channel.Digest = undefined;
    for (&output, state[0..channel.RATE]) |*destination, word|
        destination.* = word.toU32();
    return .{
        .phase = phase,
        .first_call = @intCast(first_call),
        .call_count = @intCast(cursor.* - first_call),
        .output_digest = output,
    };
}

fn absorbWord(
    calls: *[POSEIDON_CALL_COUNT]poseidon_air.Call,
    cursor: *usize,
    state: *[poseidon.WIDTH]M31,
    filled: *usize,
    word: u32,
) void {
    state[filled.*] = state[filled.*].add(M31.fromCanonical(word));
    filled.* += 1;
    if (filled.* == channel.RATE) {
        appendPermutation(calls, cursor, state);
        filled.* = 0;
    }
}

fn appendPermutation(
    calls: *[POSEIDON_CALL_COUNT]poseidon_air.Call,
    cursor: *usize,
    state: *[poseidon.WIDTH]M31,
) void {
    std.debug.assert(cursor.* < calls.len);
    var input: [poseidon.WIDTH]u32 = undefined;
    for (&input, state) |*destination, word| destination.* = word.toU32();
    calls[cursor.*] = .{
        .input = input,
        .wide = false,
        .io = true,
        .narrow_output = null,
    };
    cursor.* += 1;
    poseidon.permute(state);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or CHILD_COUNT != 2 or
        SOURCE_PREIMAGE_WORD_COUNT != 32 or STATEMENT_CALL_COUNT != 52 or
        SOURCE_CALL_COUNT != 5 or SUBTREE_CALL_COUNT != 3 or
        OUTPUT_CALL_COUNT != 56 or POSEIDON_CALL_COUNT != 116 or
        MINIMUM_POSEIDON_LOG_SIZE != 7 or PRODUCTION_ACTIVATION or
        CHILD_PROOF_VERIFIER_AVAILABLE or COLD_PARENT_PROOF_AVAILABLE)
    {
        @compileError("common-fold field-public V2 contract drifted");
    }
}
