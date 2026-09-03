//! Campaign-native canonical-empty public authority and Poseidon schedule.
//!
//! Unlike the frozen legacy role-1 circuit, the source hash commits the full
//! 489-word campaign source projection, including namespace and runtime shape.
//! No legacy coordinate or 210 -> 256 admission is reused.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const source_mod =
    @import("recursive_common_canonical_empty_campaign_source_v2.zig");
const campaign_public = @import("recursive_campaign_node_public_v2.zig");
const field_public = @import("recursive_field_node_public_v2.zig");

const m31 = stwo_core.fields.m31;
const M31 = m31.M31;
const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const poseidon = frontend.air.memory_commitment.poseidon2;
const poseidon_air = frontend.air.memory_commitment.poseidon2_air;

pub const FORMAT_VERSION: u32 = field_public.FORMAT_VERSION;
pub const SCHEMA_VERSION: u32 = 2;
pub const SOURCE_KIND_CANONICAL_EMPTY_CAMPAIGN: u32 = 3;
pub const SOURCE_DIGEST_DOMAIN: u32 = source_mod.SOURCE_DIGEST_DOMAIN;
pub const SOURCE_PREIMAGE_WORD_COUNT: usize = source_mod.SOURCE_FIELD_WORD_COUNT;
pub const HEADER_WORD_COUNT: usize = field_public.HEADER_WORD_COUNT;
pub const STATEMENT_WORD_COUNT: usize = field_public.STATEMENT_WORD_COUNT;
pub const AIR_WORD_COUNT: usize = field_public.AIR_WORD_COUNT;

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
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub const Error = source_mod.Error || campaign_public.Error ||
    field_public.Error || error{
    CampaignEmptyFieldAuthorityMismatch,
    CampaignEmptyFieldScheduleMismatch,
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

pub const CampaignSourceAuthorityV2 = struct {
    format_version: u32 = FORMAT_VERSION,
    schema_version: u32 = SCHEMA_VERSION,
    source_kind: u32 = SOURCE_KIND_CANONICAL_EMPTY_CAMPAIGN,
    campaign_shape_identity_sha256: [32]u8,
    source_content_identity_sha256: [32]u8,
    statement_digest: channel.Digest,
    source_digest: channel.Digest,

    pub fn seal(cold: *const source_mod.ColdInputV2) !CampaignSourceAuthorityV2 {
        try validateCold(cold);
        const source_words = try cold.source.fieldWords(&cold.shape);
        const result = CampaignSourceAuthorityV2{
            .campaign_shape_identity_sha256 = cold.shape.identity_sha256,
            .source_content_identity_sha256 = cold.source.content_identity_sha256,
            .statement_digest = cold.node_public.statement_digest,
            .source_digest = channel.hashCanonicalU32s(
                &source_words,
                SOURCE_DIGEST_DOMAIN,
            ),
        };
        try result.validateAgainst(cold);
        return result;
    }

    pub fn validateAgainst(
        self: *const CampaignSourceAuthorityV2,
        cold: *const source_mod.ColdInputV2,
    ) !void {
        try validateCold(cold);
        const source_words = try cold.source.fieldWords(&cold.shape);
        const expected_source = channel.hashCanonicalU32s(
            &source_words,
            SOURCE_DIGEST_DOMAIN,
        );
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.source_kind != SOURCE_KIND_CANONICAL_EMPTY_CAMPAIGN or
            !std.mem.eql(
                u8,
                &self.campaign_shape_identity_sha256,
                &cold.shape.identity_sha256,
            ) or !std.mem.eql(
            u8,
            &self.source_content_identity_sha256,
            &cold.source.content_identity_sha256,
        ) or !std.meta.eql(
            self.statement_digest,
            cold.node_public.statement_digest,
        ) or !std.meta.eql(self.source_digest, expected_source) or
            !std.meta.eql(self.source_digest, cold.node_public.source_digest))
        {
            return error.CampaignEmptyFieldAuthorityMismatch;
        }
    }

    pub fn preimage(
        self: *const CampaignSourceAuthorityV2,
        cold: *const source_mod.ColdInputV2,
    ) ![SOURCE_PREIMAGE_WORD_COUNT]u32 {
        try self.validateAgainst(cold);
        return cold.source.fieldWords(&cold.shape);
    }
};

pub const PoseidonScheduleV2 = struct {
    source: CampaignSourceAuthorityV2,
    node_public: field_public.NodePublicV2,
    phases: [4]PhaseRangeV2,
    calls: [POSEIDON_CALL_COUNT]poseidon_air.Call,

    pub fn build(cold: *const source_mod.ColdInputV2) !PoseidonScheduleV2 {
        const result = try buildUnchecked(cold);
        try result.validateAgainst(cold);
        return result;
    }

    pub fn validateAgainst(
        self: *const PoseidonScheduleV2,
        cold: *const source_mod.ColdInputV2,
    ) !void {
        try self.source.validateAgainst(cold);
        try campaign_public.validate(&cold.shape, &self.node_public);
        const expected = try buildUnchecked(cold);
        if (!std.meta.eql(self.*, expected))
            return error.CampaignEmptyFieldScheduleMismatch;
    }

    pub fn callsSlice(self: *const PoseidonScheduleV2) []const poseidon_air.Call {
        return &self.calls;
    }
};

fn buildUnchecked(cold: *const source_mod.ColdInputV2) !PoseidonScheduleV2 {
    try validateCold(cold);
    const source = try CampaignSourceAuthorityV2.seal(cold);
    var result = PoseidonScheduleV2{
        .source = source,
        .node_public = cold.node_public,
        .phases = undefined,
        .calls = undefined,
    };
    var cursor: usize = 0;
    result.phases[@intFromEnum(PhaseV2.statement)] = appendHash(
        &result.calls,
        &cursor,
        .statement,
        &cold.source.statement_words,
        field_public.STATEMENT_DIGEST_DOMAIN,
    );
    const source_preimage = try source.preimage(cold);
    result.phases[@intFromEnum(PhaseV2.source)] = appendHash(
        &result.calls,
        &cursor,
        .source,
        &source_preimage,
        SOURCE_DIGEST_DOMAIN,
    );
    const subtree_preimage = subtreePreimage(&result.node_public);
    result.phases[@intFromEnum(PhaseV2.subtree)] = appendHash(
        &result.calls,
        &cursor,
        .subtree,
        &subtree_preimage,
        field_public.SUBTREE_DIGEST_DOMAIN,
    );
    const output_preimage = outputPreimage(&result.node_public);
    result.phases[@intFromEnum(PhaseV2.output)] = appendHash(
        &result.calls,
        &cursor,
        .output,
        &output_preimage,
        field_public.OUTPUT_DIGEST_DOMAIN,
    );
    if (cursor != result.calls.len or
        !std.meta.eql(result.phases[0].output_digest, result.node_public.statement_digest) or
        !std.meta.eql(result.phases[1].output_digest, result.node_public.source_digest) or
        !std.meta.eql(result.phases[2].output_digest, result.node_public.subtree_digest) or
        !std.meta.eql(result.phases[3].output_digest, result.node_public.output_digest))
    {
        return error.CampaignEmptyFieldScheduleMismatch;
    }
    return result;
}

fn validateCold(cold: *const source_mod.ColdInputV2) !void {
    const bytes = try cold.source.encodeCanonical(&cold.shape);
    try cold.validate(&bytes);
    try campaign_public.validate(&cold.shape, &cold.node_public);
}

fn headerWords(value: *const field_public.NodePublicV2) [HEADER_WORD_COUNT]u32 {
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
        state[filled] = state[filled].add(M31.fromCanonical(word));
        filled += 1;
        if (filled == channel.RATE) {
            appendPermutation(calls, cursor, &state);
            filled = 0;
        }
    }
    state[filled] = state[filled].add(M31.one());
    filled += 1;
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
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 2 or
        SOURCE_KIND_CANONICAL_EMPTY_CAMPAIGN != 3 or
        SOURCE_PREIMAGE_WORD_COUNT != 489 or STATEMENT_CALL_COUNT != 52 or
        SOURCE_CALL_COUNT != 62 or SUBTREE_CALL_COUNT != 3 or
        OUTPUT_CALL_COUNT != 56 or POSEIDON_CALL_COUNT != 173 or
        MINIMUM_POSEIDON_LOG_SIZE != 8 or AIR_WORD_COUNT != 450 or
        PRODUCTION_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("campaign canonical-empty field-public contract drifted");
    }
}
