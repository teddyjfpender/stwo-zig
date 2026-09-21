//! Field-native canonical-empty public authority and Poseidon call schedule.
//!
//! SHA is intentionally absent.  The role source is a Poseidon digest over an
//! exact empty-statement coordinate, then RecursiveNodePublicV2 supplies the
//! domain-separated statement, subtree, and output digests.  The retained
//! call schedule is exact native provider witness input; it does not by itself
//! claim that a universal AIR owner has constrained or proved those calls.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_mod = @import("recursive_node_artifact_v1.zig");
const field_public_mod = @import("recursive_field_node_public_v2.zig");

const m31 = stwo_core.fields.m31;
const M31 = m31.M31;
const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const poseidon = frontend.air.memory_commitment.poseidon2;
const poseidon_air = frontend.air.memory_commitment.poseidon2_air;

pub const FORMAT_VERSION: u32 = field_public_mod.FORMAT_VERSION;
pub const SCHEMA_VERSION: u32 = field_public_mod.SCHEMA_VERSION;
pub const SOURCE_KIND_CANONICAL_EMPTY: u32 = 2;
pub const SOURCE_DIGEST_DOMAIN: u32 = 0x4345_5632; // "CEV2"
pub const SOURCE_PREIMAGE_WORD_COUNT: usize = 6 + channel.RATE;
pub const HEADER_WORD_COUNT: usize = field_public_mod.HEADER_WORD_COUNT;
pub const STATEMENT_WORD_COUNT: usize = field_public_mod.STATEMENT_WORD_COUNT;
pub const AIR_WORD_COUNT: usize = field_public_mod.AIR_WORD_COUNT;

pub const STATEMENT_CALL_COUNT: usize =
    channel.canonicalWordPermutationCount(STATEMENT_WORD_COUNT);
pub const SOURCE_CALL_COUNT: usize =
    channel.canonicalWordPermutationCount(SOURCE_PREIMAGE_WORD_COUNT);
pub const SUBTREE_PREIMAGE_WORD_COUNT: usize =
    HEADER_WORD_COUNT + 2 * channel.RATE;
pub const SUBTREE_CALL_COUNT: usize =
    channel.canonicalWordPermutationCount(SUBTREE_PREIMAGE_WORD_COUNT);
pub const OUTPUT_PREIMAGE_WORD_COUNT: usize =
    HEADER_WORD_COUNT + STATEMENT_WORD_COUNT + 3 * channel.RATE;
pub const OUTPUT_CALL_COUNT: usize =
    channel.canonicalWordPermutationCount(OUTPUT_PREIMAGE_WORD_COUNT);
pub const POSEIDON_CALL_COUNT: usize = STATEMENT_CALL_COUNT +
    SOURCE_CALL_COUNT + SUBTREE_CALL_COUNT + OUTPUT_CALL_COUNT;
pub const MINIMUM_POSEIDON_LOG_SIZE: u32 =
    std.math.log2_int_ceil(usize, POSEIDON_CALL_COUNT);

pub const PRODUCTION_ACTIVATION = false;
pub const FIELD_PUBLIC_AIR_OWNER_AVAILABLE = false;
pub const COLD_PROOF_AVAILABLE = false;
pub const SHA_IN_RECURSIVE_AIR = false;

pub const Error = field_public_mod.Error || artifact_mod.Error ||
    recursion.span_statement.Error || error{
    CanonicalEmptyFieldAuthorityMismatch,
    CanonicalEmptyFieldScheduleMismatch,
    CanonicalEmptyPublicAirOwnerUnavailable,
    NonCanonicalCanonicalEmptySource,
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

/// Exact field-only authority for the role-specific leaf source.  No digest
/// or boolean supplied by the caller can bypass the empty SpanStatement and
/// coordinate reconstruction in `seal`/`validateAgainst`.
pub const CanonicalEmptySourceAuthorityV2 = struct {
    format_version: u32 = FORMAT_VERSION,
    schema_version: u32 = SCHEMA_VERSION,
    source_kind: u32 = SOURCE_KIND_CANONICAL_EMPTY,
    coordinate: artifact_mod.TaskCoordinateV1,
    statement_digest: channel.Digest,
    source_digest: channel.Digest,

    pub fn seal(
        statement_words: [STATEMENT_WORD_COUNT]u32,
        coordinate: artifact_mod.TaskCoordinateV1,
    ) Error!CanonicalEmptySourceAuthorityV2 {
        try validateCanonicalEmptyStatement(statement_words, coordinate);
        const statement_digest = try field_public_mod.statementDigest(
            statement_words,
        );
        const source_digest = channel.hashCanonicalU32s(
            &sourcePreimageFromDigest(coordinate, statement_digest),
            SOURCE_DIGEST_DOMAIN,
        );
        const result = CanonicalEmptySourceAuthorityV2{
            .coordinate = coordinate,
            .statement_digest = statement_digest,
            .source_digest = source_digest,
        };
        try result.validateAgainst(statement_words, coordinate);
        return result;
    }

    pub fn validateAgainst(
        self: *const CanonicalEmptySourceAuthorityV2,
        statement_words: [STATEMENT_WORD_COUNT]u32,
        coordinate: artifact_mod.TaskCoordinateV1,
    ) Error!void {
        try validateCanonicalEmptyStatement(statement_words, coordinate);
        const expected_statement = try field_public_mod.statementDigest(
            statement_words,
        );
        const expected_source = channel.hashCanonicalU32s(
            &sourcePreimageFromDigest(coordinate, expected_statement),
            SOURCE_DIGEST_DOMAIN,
        );
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.source_kind != SOURCE_KIND_CANONICAL_EMPTY or
            !std.meta.eql(self.coordinate, coordinate) or
            !std.meta.eql(self.statement_digest, expected_statement) or
            !std.meta.eql(self.source_digest, expected_source))
        {
            return error.CanonicalEmptyFieldAuthorityMismatch;
        }
    }

    pub fn preimage(self: *const CanonicalEmptySourceAuthorityV2) Error![
        SOURCE_PREIMAGE_WORD_COUNT
    ]u32 {
        try self.coordinate.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.source_kind != SOURCE_KIND_CANONICAL_EMPTY)
        {
            return error.CanonicalEmptyFieldAuthorityMismatch;
        }
        return sourcePreimageFromDigest(self.coordinate, self.statement_digest);
    }
};

pub fn sourcePreimage(
    statement_words: [STATEMENT_WORD_COUNT]u32,
    coordinate: artifact_mod.TaskCoordinateV1,
) Error![SOURCE_PREIMAGE_WORD_COUNT]u32 {
    try validateCanonicalEmptyStatement(statement_words, coordinate);
    return sourcePreimageFromDigest(
        coordinate,
        try field_public_mod.statementDigest(statement_words),
    );
}

pub fn sourceDigest(
    statement_words: [STATEMENT_WORD_COUNT]u32,
    coordinate: artifact_mod.TaskCoordinateV1,
) Error!channel.Digest {
    return channel.hashCanonicalU32s(
        &try sourcePreimage(statement_words, coordinate),
        SOURCE_DIGEST_DOMAIN,
    );
}

pub fn deriveNodePublic(
    statement_words: [STATEMENT_WORD_COUNT]u32,
    coordinate: artifact_mod.TaskCoordinateV1,
) Error!field_public_mod.NodePublicV2 {
    const source = try CanonicalEmptySourceAuthorityV2.seal(
        statement_words,
        coordinate,
    );
    const result = try field_public_mod.NodePublicV2.initLeaf(
        coordinate,
        statement_words,
        source.source_digest,
    );
    try result.validateLeafSource(source.source_digest);
    return result;
}

/// Exact provider input calls for all four domain-separated public hashes.
/// Calls use atomic IO mode so the universal Poseidon provider publishes both
/// the input and complete 16-word output relation.  The corresponding request
/// AIR owner is the one remaining semantic proof seam.
pub const PoseidonScheduleV2 = struct {
    source: CanonicalEmptySourceAuthorityV2,
    node_public: field_public_mod.NodePublicV2,
    phases: [4]PhaseRangeV2,
    calls: [POSEIDON_CALL_COUNT]poseidon_air.Call,

    pub fn build(
        statement_words: [STATEMENT_WORD_COUNT]u32,
        coordinate: artifact_mod.TaskCoordinateV1,
    ) Error!PoseidonScheduleV2 {
        const result = try buildUnchecked(statement_words, coordinate);
        try result.validateAgainst(statement_words, coordinate);
        return result;
    }

    pub fn validateAgainst(
        self: *const PoseidonScheduleV2,
        statement_words: [STATEMENT_WORD_COUNT]u32,
        coordinate: artifact_mod.TaskCoordinateV1,
    ) Error!void {
        try self.source.validateAgainst(statement_words, coordinate);
        try self.node_public.validateLeafSource(self.source.source_digest);
        const expected = try buildUnchecked(statement_words, coordinate);
        if (!std.meta.eql(self.*, expected))
            return error.CanonicalEmptyFieldScheduleMismatch;
    }

    pub fn callsSlice(self: *const PoseidonScheduleV2) []const poseidon_air.Call {
        return &self.calls;
    }
};

pub fn requireFieldPublicAirOwner() Error!void {
    return error.CanonicalEmptyPublicAirOwnerUnavailable;
}

fn buildUnchecked(
    statement_words: [STATEMENT_WORD_COUNT]u32,
    coordinate: artifact_mod.TaskCoordinateV1,
) Error!PoseidonScheduleV2 {
    const source = try CanonicalEmptySourceAuthorityV2.seal(
        statement_words,
        coordinate,
    );
    const node_public = try field_public_mod.NodePublicV2.initLeaf(
        coordinate,
        statement_words,
        source.source_digest,
    );
    var result = PoseidonScheduleV2{
        .source = source,
        .node_public = node_public,
        .phases = undefined,
        .calls = undefined,
    };
    var cursor: usize = 0;
    result.phases[@intFromEnum(PhaseV2.statement)] = appendHash(
        &result.calls,
        &cursor,
        .statement,
        &statement_words,
        field_public_mod.STATEMENT_DIGEST_DOMAIN,
    );
    const source_preimage = try source.preimage();
    result.phases[@intFromEnum(PhaseV2.source)] = appendHash(
        &result.calls,
        &cursor,
        .source,
        &source_preimage,
        SOURCE_DIGEST_DOMAIN,
    );
    const subtree_preimage = subtreePreimage(&node_public);
    result.phases[@intFromEnum(PhaseV2.subtree)] = appendHash(
        &result.calls,
        &cursor,
        .subtree,
        &subtree_preimage,
        field_public_mod.SUBTREE_DIGEST_DOMAIN,
    );
    const output_preimage = outputPreimage(&node_public);
    result.phases[@intFromEnum(PhaseV2.output)] = appendHash(
        &result.calls,
        &cursor,
        .output,
        &output_preimage,
        field_public_mod.OUTPUT_DIGEST_DOMAIN,
    );
    std.debug.assert(cursor == result.calls.len);
    if (!std.meta.eql(
        result.phases[@intFromEnum(PhaseV2.statement)].output_digest,
        node_public.statement_digest,
    ) or !std.meta.eql(
        result.phases[@intFromEnum(PhaseV2.source)].output_digest,
        node_public.source_digest,
    ) or !std.meta.eql(
        result.phases[@intFromEnum(PhaseV2.subtree)].output_digest,
        node_public.subtree_digest,
    ) or !std.meta.eql(
        result.phases[@intFromEnum(PhaseV2.output)].output_digest,
        node_public.output_digest,
    )) return error.CanonicalEmptyFieldScheduleMismatch;
    return result;
}

fn sourcePreimageFromDigest(
    coordinate: artifact_mod.TaskCoordinateV1,
    statement_digest: channel.Digest,
) [SOURCE_PREIMAGE_WORD_COUNT]u32 {
    return .{
        FORMAT_VERSION,
        SCHEMA_VERSION,
        SOURCE_KIND_CANONICAL_EMPTY,
        coordinate.height,
        coordinate.index,
        coordinate.global_ordinal,
    } ++ statement_digest;
}

fn headerWords(
    value: *const field_public_mod.NodePublicV2,
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
    value: *const field_public_mod.NodePublicV2,
) [SUBTREE_PREIMAGE_WORD_COUNT]u32 {
    return headerWords(value) ++ value.statement_digest ++ value.source_digest;
}

fn outputPreimage(
    value: *const field_public_mod.NodePublicV2,
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

fn validateCanonicalEmptyStatement(
    words: [STATEMENT_WORD_COUNT]u32,
    coordinate: artifact_mod.TaskCoordinateV1,
) Error!void {
    try coordinate.validate();
    if (coordinate.height != 0 or
        coordinate.index < artifact_mod.REAL_LEAF_COUNT or
        coordinate.index >= artifact_mod.PADDED_LEAF_COUNT or
        try artifact_mod.expectedNodeKind(coordinate) != .empty)
    {
        return error.CanonicalEmptyFieldAuthorityMismatch;
    }
    var canonical: recursion.span_statement.StatementWords = undefined;
    for (&canonical, words) |*destination, word| {
        if (word >= m31.Modulus)
            return error.NonCanonicalCanonicalEmptySource;
        destination.* = M31.fromCanonical(word);
    }
    const statement = try recursion.span_statement.SpanStatement
        .fromCanonicalWords(&canonical);
    if (statement.slots.height != 0 or
        statement.slots.nodeIndex() != coordinate.index)
    {
        return error.CanonicalEmptyFieldAuthorityMismatch;
    }
    switch (statement.body) {
        .empty => {},
        .executed => return error.CanonicalEmptyFieldAuthorityMismatch,
    }
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        SOURCE_KIND_CANONICAL_EMPTY != 2 or
        SOURCE_PREIMAGE_WORD_COUNT != 14 or STATEMENT_CALL_COUNT != 52 or
        SOURCE_CALL_COUNT != 2 or SUBTREE_CALL_COUNT != 3 or
        OUTPUT_CALL_COUNT != 56 or POSEIDON_CALL_COUNT != 113 or
        MINIMUM_POSEIDON_LOG_SIZE != 7 or AIR_WORD_COUNT != 450 or
        PRODUCTION_ACTIVATION or FIELD_PUBLIC_AIR_OWNER_AVAILABLE or
        COLD_PROOF_AVAILABLE or SHA_IN_RECURSIVE_AIR)
    {
        @compileError("canonical-empty field-public V2 contract drifted");
    }
}
