//! Field-native stage-102 public authority for a full Ethereum V4 leaf.
//!
//! The source digest is reconstructed from a live, verifier-owned stage-101
//! capability.  Its preimage contains no SHA-256 value: it binds the exact
//! recursive role/coordinate, canonical SpanStatement, native statement and
//! public-wire authorities, q193 protocol, verifier-final transcript
//! checkpoint, and the four ordered PCS commitments.  SHA remains transport
//! custody outside the recursive AIR.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_mod = @import("recursive_node_artifact_v1.zig");
const field_public_mod = @import("recursive_field_node_public_v2.zig");
const input_mod =
    @import("recursive_common_ethereum_incremental_leaf_input_v4.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

const m31 = stwo_core.fields.m31;
const M31 = m31.M31;
const recursion = frontend.recursion;
const public_data = frontend.air.public_data;
const program_decode = frontend.air.program.decode;
const channel = recursion.poseidon2_channel;
const poseidon = frontend.air.memory_commitment.poseidon2;
const poseidon_air = frontend.air.memory_commitment.poseidon2_air;

pub const FORMAT_VERSION: u32 = 4;
pub const SCHEMA_VERSION: u32 = 2;
pub const SOURCE_KIND_ETHEREUM_INCREMENTAL_LEAF_V4: u32 = 4;
pub const CIRCUIT_ROLE = registry_mod.CircuitRoleV4
    .ethereum_incremental_leaf_wrapper_v4;
pub const COMMITMENT_COUNT: usize = 4;
pub const SOURCE_DIGEST_DOMAIN: u32 = 0x4549_5634; // "EIV4"

pub const SOURCE_HEADER_WORD_COUNT: usize = 8;
pub const COMPLETION_WORD_COUNT: usize = 13;
pub const SOURCE_PREIMAGE_WORD_COUNT: usize = SOURCE_HEADER_WORD_COUNT +
    4 * channel.RATE + COMPLETION_WORD_COUNT + channel.RATE + 1 +
    COMMITMENT_COUNT * channel.RATE;
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
pub const WRAPPER_COLD_PROOF_AVAILABLE = false;
pub const SHA_IN_RECURSIVE_AIR = false;

pub const Error = field_public_mod.Error || artifact_mod.Error || error{
    EthereumIncrementalCompletionProjectionMismatchV4,
    EthereumIncrementalFieldAuthorityMismatchV4,
    EthereumIncrementalFieldScheduleMismatchV4,
    EthereumIncrementalPublicAirOwnerUnavailableV4,
    InvalidEthereumIncrementalFieldWordV4,
};

/// Field-canonical completion authority consumed by the role-0 public
/// semantics circuit. Raw `u32` values use explicit little-endian 16-bit
/// limbs, so a high-bit instruction cannot be truncated or rejected merely
/// because it is not itself an M31 element. `program_values` is the exact
/// Ethereum-profile tuple following the program address in `program_access`.
pub const CompletionProjectionV4 = struct {
    execution_profile: u32 = @intFromEnum(
        program_decode.ExecutionProfile.rv32im_zkvm_ethereum_v1,
    ),
    completion_kind: u32,
    address_limbs: [2]u32,
    value_limbs: [2]u32,
    clock_limbs: [2]u32,
    program_term_present: u32,
    program_values: [4]u32,

    pub fn init(completion: public_data.Completion) !CompletionProjectionV4 {
        const has_program_term = switch (completion.kind) {
            .halt_flag => false,
            .unretired_self_loop, .unretired_program_fetch => true,
        };
        const values = if (has_program_term)
            program_decode.decodeProgramWordForProfile(
                .rv32im_zkvm_ethereum_v1,
                completion.value,
            ) catch return error.EthereumIncrementalCompletionProjectionMismatchV4
        else
            [_]u32{0} ** 4;
        const result = CompletionProjectionV4{
            .completion_kind = @intFromEnum(completion.kind),
            .address_limbs = u32Limbs(completion.address),
            .value_limbs = u32Limbs(completion.value),
            .clock_limbs = u32Limbs(completion.clock),
            .program_term_present = @intFromBool(has_program_term),
            .program_values = values,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: CompletionProjectionV4) Error!void {
        const kind = std.meta.intToEnum(
            public_data.CompletionKind,
            self.completion_kind,
        ) catch return error.EthereumIncrementalCompletionProjectionMismatchV4;
        if (self.execution_profile != @intFromEnum(
            program_decode.ExecutionProfile.rv32im_zkvm_ethereum_v1,
        ) or self.program_term_present > 1) {
            return error.EthereumIncrementalCompletionProjectionMismatchV4;
        }
        inline for (.{
            self.address_limbs,
            self.value_limbs,
            self.clock_limbs,
        }) |limbs| for (limbs) |limb| if (limb > std.math.maxInt(u16))
            return error.EthereumIncrementalCompletionProjectionMismatchV4;
        const value = limbsToU32(self.value_limbs);
        if (limbsToU32(self.address_limbs) >= m31.Modulus or
            limbsToU32(self.clock_limbs) >= m31.Modulus)
        {
            return error.EthereumIncrementalCompletionProjectionMismatchV4;
        }
        const expected_present = kind != .halt_flag;
        if (self.program_term_present != @intFromBool(expected_present))
            return error.EthereumIncrementalCompletionProjectionMismatchV4;
        const expected = if (expected_present)
            program_decode.decodeProgramWordForProfile(
                .rv32im_zkvm_ethereum_v1,
                value,
            ) catch return error.EthereumIncrementalCompletionProjectionMismatchV4
        else
            [_]u32{0} ** 4;
        if (!std.meta.eql(self.program_values, expected))
            return error.EthereumIncrementalCompletionProjectionMismatchV4;
    }

    pub fn words(self: CompletionProjectionV4) Error![COMPLETION_WORD_COUNT]u32 {
        try self.validate();
        return .{
            self.execution_profile,
            self.completion_kind,
            self.address_limbs[0],
            self.address_limbs[1],
            self.value_limbs[0],
            self.value_limbs[1],
            self.clock_limbs[0],
            self.clock_limbs[1],
            self.program_term_present,
            self.program_values[0],
            self.program_values[1],
            self.program_values[2],
            self.program_values[3],
        };
    }
};

pub const PhaseV4 = enum(u8) {
    statement = 0,
    source = 1,
    subtree = 2,
    output = 3,
};

pub const PhaseRangeV4 = struct {
    phase: PhaseV4,
    first_call: u16,
    call_count: u16,
    output_digest: channel.Digest,
};

/// Pointer-free projection of exact values recreated by the future recursive
/// verifier.  This value is not a verifier capability: only `seal`, which
/// accepts `FreshInputV4`, can bind it to a live cold verification.
pub const SourceAuthorityV4 = struct {
    format_version: u32 = FORMAT_VERSION,
    schema_version: u32 = SCHEMA_VERSION,
    source_kind: u32 = SOURCE_KIND_ETHEREUM_INCREMENTAL_LEAF_V4,
    circuit_role: registry_mod.CircuitRoleV4 = CIRCUIT_ROLE,
    coordinate: artifact_mod.TaskCoordinateV1,
    statement_digest: channel.Digest,
    native_statement_authority: channel.Digest,
    public_wire_id: channel.Digest,
    protocol_id: channel.Digest,
    transcript_final_digest: channel.Digest,
    transcript_final_draw_count: u32,
    completion: CompletionProjectionV4,
    commitments: [COMMITMENT_COUNT]channel.Digest,
    source_digest: channel.Digest,

    pub fn seal(
        comptime Engine: type,
        input: *const input_mod.FreshInputV4(Engine),
    ) !SourceAuthorityV4 {
        comptime requirePoseidonEngine(Engine);
        try input.validate();
        const capture = &input.stage101;
        if (capture.proof.commitments.len != COMMITMENT_COUNT)
            return error.EthereumIncrementalFieldAuthorityMismatchV4;
        var commitments: [COMMITMENT_COUNT]channel.Digest = undefined;
        for (&commitments, capture.proof.commitments) |*destination, value|
            destination.* = value;
        var result = SourceAuthorityV4{
            .coordinate = input.coordinate,
            .statement_digest = try field_public_mod.statementDigest(
                input.statement_words,
            ),
            .native_statement_authority = capture.statement.authority_id,
            .public_wire_id = capture.statement.public_data.wireId(),
            .protocol_id = capture.profile.protocol.protocol_id,
            .transcript_final_digest = capture.transcript_final_digest,
            .transcript_final_draw_count = capture.transcript_final_draw_count,
            .completion = try CompletionProjectionV4.init(
                capture.role_aware_public.value.completion orelse
                    return error.EthereumIncrementalCompletionProjectionMismatchV4,
            ),
            .commitments = commitments,
            .source_digest = undefined,
        };
        result.source_digest = try projectedSourceDigest(&result);
        try result.validateStructure();
        return result;
    }

    pub fn validateAgainst(
        self: *const SourceAuthorityV4,
        comptime Engine: type,
        input: *const input_mod.FreshInputV4(Engine),
    ) !void {
        const expected = try seal(Engine, input);
        if (!std.meta.eql(self.*, expected))
            return error.EthereumIncrementalFieldAuthorityMismatchV4;
    }

    pub fn validateStructure(self: *const SourceAuthorityV4) Error!void {
        try validateProjectedFields(self);
        if (!std.meta.eql(
            self.source_digest,
            try projectedSourceDigest(self),
        )) return error.EthereumIncrementalFieldAuthorityMismatchV4;
    }

    pub fn preimage(
        self: *const SourceAuthorityV4,
    ) Error![SOURCE_PREIMAGE_WORD_COUNT]u32 {
        try self.validateStructure();
        return sourcePreimageUnchecked(self);
    }
};

/// Pure field projection helper.  It does not admit a source or mint a live
/// verifier capability; production callers must still use `seal` and
/// `validateAgainst` with `FreshInputV4`.
pub fn projectedSourceDigest(
    value: *const SourceAuthorityV4,
) Error!channel.Digest {
    try validateProjectedFields(value);
    return channel.hashCanonicalU32s(
        &sourcePreimageUnchecked(value),
        SOURCE_DIGEST_DOMAIN,
    );
}

pub fn deriveNodePublic(
    comptime Engine: type,
    input: *const input_mod.FreshInputV4(Engine),
) !field_public_mod.NodePublicV2 {
    const source = try SourceAuthorityV4.seal(Engine, input);
    const result = try field_public_mod.NodePublicV2.initLeaf(
        input.coordinate,
        input.statement_words,
        source.source_digest,
    );
    try result.validateLeafSource(source.source_digest);
    return result;
}

pub const PoseidonScheduleV4 = struct {
    source: SourceAuthorityV4,
    node_public: field_public_mod.NodePublicV2,
    phases: [4]PhaseRangeV4,
    calls: [POSEIDON_CALL_COUNT]poseidon_air.Call,

    pub fn build(
        comptime Engine: type,
        input: *const input_mod.FreshInputV4(Engine),
    ) !PoseidonScheduleV4 {
        const source = try SourceAuthorityV4.seal(Engine, input);
        const result = try buildFromAuthority(
            input.statement_words,
            source,
        );
        try result.validateAgainst(Engine, input);
        return result;
    }

    pub fn validateAgainst(
        self: *const PoseidonScheduleV4,
        comptime Engine: type,
        input: *const input_mod.FreshInputV4(Engine),
    ) !void {
        try self.source.validateAgainst(Engine, input);
        try self.node_public.validateLeafSource(self.source.source_digest);
        const expected = try buildFromAuthority(
            input.statement_words,
            self.source,
        );
        if (!std.meta.eql(self.*, expected))
            return error.EthereumIncrementalFieldScheduleMismatchV4;
    }

    pub fn callsSlice(self: *const PoseidonScheduleV4) []const poseidon_air.Call {
        return &self.calls;
    }
};

pub fn requireFieldPublicAirOwner() Error!void {
    return error.EthereumIncrementalPublicAirOwnerUnavailableV4;
}

/// Structural-only hooks used by compile/mutation tests.  They produce no
/// proof, capture, registry admission, or fresh capability.
pub const testing = struct {
    pub fn buildFromProjectedAuthority(
        statement_words: [STATEMENT_WORD_COUNT]u32,
        source: SourceAuthorityV4,
    ) !PoseidonScheduleV4 {
        try source.validateStructure();
        return buildFromAuthority(statement_words, source);
    }

    pub fn validateProjectedSchedule(
        schedule: *const PoseidonScheduleV4,
        statement_words: [STATEMENT_WORD_COUNT]u32,
        source: SourceAuthorityV4,
    ) !void {
        try source.validateStructure();
        const expected = try buildFromAuthority(statement_words, source);
        if (!std.meta.eql(schedule.*, expected))
            return error.EthereumIncrementalFieldScheduleMismatchV4;
    }
};

fn buildFromAuthority(
    statement_words: [STATEMENT_WORD_COUNT]u32,
    source: SourceAuthorityV4,
) !PoseidonScheduleV4 {
    try source.validateStructure();
    const node_public = try field_public_mod.NodePublicV2.initLeaf(
        source.coordinate,
        statement_words,
        source.source_digest,
    );
    var result = PoseidonScheduleV4{
        .source = source,
        .node_public = node_public,
        .phases = undefined,
        .calls = undefined,
    };
    var cursor: usize = 0;
    result.phases[@intFromEnum(PhaseV4.statement)] = appendHash(
        &result.calls,
        &cursor,
        .statement,
        &statement_words,
        field_public_mod.STATEMENT_DIGEST_DOMAIN,
    );
    const source_preimage = try source.preimage();
    result.phases[@intFromEnum(PhaseV4.source)] = appendHash(
        &result.calls,
        &cursor,
        .source,
        &source_preimage,
        SOURCE_DIGEST_DOMAIN,
    );
    const subtree_preimage = subtreePreimage(&node_public);
    result.phases[@intFromEnum(PhaseV4.subtree)] = appendHash(
        &result.calls,
        &cursor,
        .subtree,
        &subtree_preimage,
        field_public_mod.SUBTREE_DIGEST_DOMAIN,
    );
    const output_preimage = outputPreimage(&node_public);
    result.phases[@intFromEnum(PhaseV4.output)] = appendHash(
        &result.calls,
        &cursor,
        .output,
        &output_preimage,
        field_public_mod.OUTPUT_DIGEST_DOMAIN,
    );
    std.debug.assert(cursor == result.calls.len);
    if (!std.meta.eql(
        result.phases[@intFromEnum(PhaseV4.statement)].output_digest,
        node_public.statement_digest,
    ) or !std.meta.eql(
        result.phases[@intFromEnum(PhaseV4.source)].output_digest,
        node_public.source_digest,
    ) or !std.meta.eql(
        result.phases[@intFromEnum(PhaseV4.subtree)].output_digest,
        node_public.subtree_digest,
    ) or !std.meta.eql(
        result.phases[@intFromEnum(PhaseV4.output)].output_digest,
        node_public.output_digest,
    )) return error.EthereumIncrementalFieldScheduleMismatchV4;
    return result;
}

fn validateProjectedFields(value: *const SourceAuthorityV4) Error!void {
    try value.coordinate.validate();
    if (value.format_version != FORMAT_VERSION or
        value.schema_version != SCHEMA_VERSION or
        value.source_kind != SOURCE_KIND_ETHEREUM_INCREMENTAL_LEAF_V4 or
        value.circuit_role != CIRCUIT_ROLE or
        value.coordinate.height != 0 or
        value.transcript_final_draw_count >= m31.Modulus or
        try artifact_mod.expectedNodeKind(value.coordinate) != .real)
    {
        return error.EthereumIncrementalFieldAuthorityMismatchV4;
    }
    inline for (.{
        value.statement_digest,
        value.native_statement_authority,
        value.public_wire_id,
        value.protocol_id,
        value.transcript_final_digest,
    }) |digest| try validateDigest(digest);
    for (value.commitments) |digest| try validateDigest(digest);
    try value.completion.validate();
}

fn sourcePreimageUnchecked(
    value: *const SourceAuthorityV4,
) [SOURCE_PREIMAGE_WORD_COUNT]u32 {
    var result: [SOURCE_PREIMAGE_WORD_COUNT]u32 = undefined;
    var at: usize = 0;
    inline for (.{
        value.format_version,
        value.schema_version,
        value.source_kind,
        @intFromEnum(value.circuit_role),
        COMMITMENT_COUNT,
        value.coordinate.height,
        value.coordinate.index,
        value.coordinate.global_ordinal,
    }) |word| append(&result, &at, word);
    appendSlice(&result, &at, &value.statement_digest);
    appendSlice(&result, &at, &value.native_statement_authority);
    appendSlice(&result, &at, &value.public_wire_id);
    appendSlice(&result, &at, &value.protocol_id);
    const completion_words = value.completion.words() catch unreachable;
    appendSlice(&result, &at, &completion_words);
    appendSlice(&result, &at, &value.transcript_final_digest);
    append(&result, &at, value.transcript_final_draw_count);
    for (value.commitments) |digest| appendSlice(&result, &at, &digest);
    std.debug.assert(at == result.len);
    return result;
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
    phase: PhaseV4,
    words: []const u32,
    capacity_tag: u32,
) PhaseRangeV4 {
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

fn validateDigest(digest: channel.Digest) Error!void {
    var aggregate: u32 = 0;
    for (digest) |word| {
        if (word >= m31.Modulus)
            return error.InvalidEthereumIncrementalFieldWordV4;
        aggregate |= word;
    }
    if (aggregate == 0)
        return error.EthereumIncrementalFieldAuthorityMismatchV4;
}

fn appendSlice(words: anytype, at: *usize, values: []const u32) void {
    for (values) |value| append(words, at, value);
}

fn append(words: anytype, at: *usize, value: anytype) void {
    std.debug.assert(at.* < words.len);
    words[at.*] = @intCast(value);
    at.* += 1;
}

fn u32Limbs(value: u32) [2]u32 {
    return .{ value & 0xffff, value >> 16 };
}

fn limbsToU32(value: [2]u32) u32 {
    return value[0] | (value[1] << 16);
}

fn requirePoseidonEngine(comptime Engine: type) void {
    if (Engine.Hasher.Hash != channel.Digest or Engine.Channel != channel.Channel)
        @compileError("stage-102 V4 requires the q193 Poseidon2 engine");
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 2 or
        @intFromEnum(CIRCUIT_ROLE) != 0 or COMMITMENT_COUNT != 4 or
        SOURCE_HEADER_WORD_COUNT != 8 or COMPLETION_WORD_COUNT != 13 or
        SOURCE_PREIMAGE_WORD_COUNT != 94 or STATEMENT_CALL_COUNT != 52 or
        SOURCE_CALL_COUNT != 12 or
        SUBTREE_CALL_COUNT != 3 or OUTPUT_CALL_COUNT != 56 or
        POSEIDON_CALL_COUNT != 123 or MINIMUM_POSEIDON_LOG_SIZE != 7 or
        AIR_WORD_COUNT != 450 or PRODUCTION_ACTIVATION or
        FIELD_PUBLIC_AIR_OWNER_AVAILABLE or WRAPPER_COLD_PROOF_AVAILABLE or
        SHA_IN_RECURSIVE_AIR)
    {
        @compileError("Ethereum incremental field-public V4 contract drifted");
    }
}
