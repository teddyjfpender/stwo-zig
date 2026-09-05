//! Exact native-transcript replay for the stage-102 Ethereum V4 wrapper.
//!
//! Construction starts from a live stage-101 cold-verifier capability.  It
//! reruns every Poseidon channel operation in verifier order and records the
//! complete sponge trace consumed by the recursive transcript AIR.  Proof
//! capture values are comparison targets only; none may select an operation
//! or mint a fresh capability.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const input_mod =
    @import("recursive_common_ethereum_incremental_leaf_input_v4.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const recording = recursion.recording_poseidon_channel_v4;
const ethereum_transcript =
    frontend.prover_mod.guest_precompile.ethereum_transcript;
const incremental_bridge = frontend.prover_mod.incremental_bridge_external_v3;
const transcript = frontend.air.transcript;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 2;
pub const COMMITMENT_COUNT: usize = 4;
pub const BASE_RELATION_DRAW_COUNT: usize = 24;
pub const ETHEREUM_RELATION_DRAW_COUNT: usize = 26;
pub const RELATION_DRAW_COUNT: usize =
    BASE_RELATION_DRAW_COUNT + ETHEREUM_RELATION_DRAW_COUNT;
pub const QUERY_WORD_COUNT: usize = 193;

pub const PRODUCTION_ACTIVATION = false;
pub const REPLAY_IS_FRESH_CAPABILITY = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-transcript/v4\x00";

pub const Error = recording.Error || error{
    ArithmeticOverflow,
    EthereumIncrementalTranscriptMismatchV4,
    EthereumIncrementalTranscriptShapeMismatchV4,
};

/// Tags are circuit metadata only. They partition the recorded operations
/// without changing any native Poseidon payload or transcript digest.
pub const ContextV4 = enum(u32) {
    profile_pre_tree0 = 1,
    tree0_commitment = 2,
    tree1_commitment = 3,
    profile_post_tree1 = 4,
    interaction_pow = 5,
    relation_draws = 6,
    interaction_claims = 7,
    tree2_commitment = 8,
    composition_draw = 9,
    tree3_commitment = 10,
    oods_draw = 11,
    sampled_values = 12,
    deep_draw = 13,
    fri = 14,
    last_layer = 15,
    pcs_pow = 16,
    queries = 17,
};

/// Owned raw transcript evidence plus the exact verifier-derived field inputs
/// needed by relation and query rows. This value has no durable codec and is
/// not proof admission.
pub const ReplayV4 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    execution: recording.ExecutionV4,
    stage101_identity_sha256: [32]u8,
    native_statement_authority: recording.Digest,
    relation_draws: [RELATION_DRAW_COUNT]QM31,
    query_words: [QUERY_WORD_COUNT]M31,
    query_log_size: u32,
    final_digest: recording.Digest,
    final_draw_count: u32,
    identity_sha256: [32]u8,

    pub fn deinit(self: *ReplayV4) void {
        self.execution.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const ReplayV4) Error!void {
        try self.execution.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.query_log_size == 0 or self.query_log_size >= 31 or
            !std.meta.eql(self.final_digest, self.execution.final_digest) or
            self.final_draw_count != self.execution.final_draw_count or
            !std.mem.eql(u8, &self.identity_sha256, &replayIdentity(self)))
        {
            return error.EthereumIncrementalTranscriptMismatchV4;
        }
        for (self.relation_draws) |value| try requireQm31(value);
        for (self.query_words) |word| if (word.toU32() >= m31.Modulus)
            return error.EthereumIncrementalTranscriptMismatchV4;
    }

    pub fn validateAgainst(
        self: *const ReplayV4,
        comptime Engine: type,
        input: *const input_mod.FreshInputV4(Engine),
    ) !void {
        try input.validate();
        try self.validate();
        const capture = &input.stage101;
        if (!std.mem.eql(
            u8,
            &self.stage101_identity_sha256,
            &capture.identity_sha256,
        ) or !std.meta.eql(
            self.native_statement_authority,
            capture.statement.authority_id,
        ) or !std.meta.eql(self.relation_draws, relationDraws(capture.relations)) or
            self.query_log_size != try queryLogSize(&capture.proof) or
            !std.meta.eql(self.final_digest, capture.transcript_final_digest) or
            self.final_draw_count != capture.transcript_final_draw_count or
            capture.proof.queries.raw.len != self.query_words.len)
        {
            return error.EthereumIncrementalTranscriptMismatchV4;
        }
        const mask = (@as(u32, 1) << @intCast(self.query_log_size)) - 1;
        for (self.query_words, capture.proof.queries.raw) |full, projected| {
            const projected_u32 = std.math.cast(u32, projected) orelse
                return error.EthereumIncrementalTranscriptShapeMismatchV4;
            if ((full.toU32() & mask) != projected_u32)
                return error.EthereumIncrementalTranscriptMismatchV4;
        }
    }
};

/// Replays the exact successful stage-101 verifier transcript. All proof
/// values are checked at their native draw/absorb position before publication.
pub fn replay(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    input: *const input_mod.FreshInputV4(Engine),
) !ReplayV4 {
    try input.validate();
    const capture = &input.stage101;
    const proof = &capture.proof;
    if (proof.commitments.len != COMMITMENT_COUNT or
        proof.queries.raw.len != QUERY_WORD_COUNT or
        proof.fri.layers.len == 0)
    {
        return error.EthereumIncrementalTranscriptShapeMismatchV4;
    }

    var channel = recording.Channel.init(allocator);
    defer channel.deinit();

    setContext(&channel, .profile_pre_tree0);
    try capture.profile.mixPreTree0(
        &capture.statement,
        &capture.role_aware_public.value,
        &channel,
    );
    setContext(&channel, .tree0_commitment);
    recording.MerkleChannel.mixRoot(&channel, proof.commitments[0]);
    setContext(&channel, .tree1_commitment);
    recording.MerkleChannel.mixRoot(&channel, proof.commitments[1]);

    setContext(&channel, .profile_post_tree1);
    try capture.profile.mixPostTree1(
        &capture.statement,
        &capture.role_aware_public.value,
        &channel,
    );
    setContext(&channel, .interaction_pow);
    if (!channel.verifyPowNonce(
        transcript.INTERACTION_POW_BITS,
        capture.base_claim.interaction_pow,
    )) return error.EthereumIncrementalTranscriptMismatchV4;
    channel.mixU64(capture.base_claim.interaction_pow);

    setContext(&channel, .relation_draws);
    const relations = try ethereum_transcript.Relations.draw(
        allocator,
        &channel,
    );
    if (!std.meta.eql(relations, capture.relations))
        return error.EthereumIncrementalTranscriptMismatchV4;
    const relation_draws = relationDraws(relations);

    setContext(&channel, .interaction_claims);
    try ethereum_transcript.mixInteractionClaimV2(
        &channel,
        &capture.statement.core,
        &capture.manifest,
        &capture.authenticated,
        capture.base_claim,
        &capture.extension_claim,
    );
    incremental_bridge.mixClaim(&channel, capture.bridge_claim);
    setContext(&channel, .tree2_commitment);
    recording.MerkleChannel.mixRoot(&channel, proof.commitments[2]);

    setContext(&channel, .composition_draw);
    if (!channel.drawSecureFelt().eql(proof.composition_randomness))
        return error.EthereumIncrementalTranscriptMismatchV4;
    setContext(&channel, .tree3_commitment);
    recording.MerkleChannel.mixRoot(&channel, proof.commitments[3]);
    setContext(&channel, .oods_draw);
    if (!channel.drawSecureFelt().eql(proof.oods_seed))
        return error.EthereumIncrementalTranscriptMismatchV4;
    setContext(&channel, .sampled_values);
    channel.mixFelts(proof.sampled_values);
    setContext(&channel, .deep_draw);
    if (!channel.drawSecureFelt().eql(proof.deep_randomness))
        return error.EthereumIncrementalTranscriptMismatchV4;

    setContext(&channel, .fri);
    for (proof.fri.layers) |layer| {
        recording.MerkleChannel.mixRoot(&channel, layer.commitment);
        if (!channel.drawSecureFelt().eql(layer.folding_alpha))
            return error.EthereumIncrementalTranscriptMismatchV4;
    }
    setContext(&channel, .last_layer);
    channel.mixFelts(proof.last_layer_coefficients);
    const pcs_config = try capture.profile.pcsConfig();
    setContext(&channel, .pcs_pow);
    if (!channel.verifyPowNonce(pcs_config.pow_bits, proof.proof_of_work))
        return error.EthereumIncrementalTranscriptMismatchV4;
    channel.mixU64(proof.proof_of_work);

    const query_log_size = try queryLogSize(proof);
    const mask = (@as(u32, 1) << @intCast(query_log_size)) - 1;
    var query_words: [QUERY_WORD_COUNT]M31 = undefined;
    setContext(&channel, .queries);
    var query_at: usize = 0;
    while (query_at < query_words.len) {
        const drawn = channel.drawU32s();
        for (drawn) |word| {
            if (query_at == query_words.len) break;
            const captured = std.math.cast(u32, proof.queries.raw[query_at]) orelse
                return error.EthereumIncrementalTranscriptShapeMismatchV4;
            if ((word & mask) != captured)
                return error.EthereumIncrementalTranscriptMismatchV4;
            query_words[query_at] = M31.fromCanonical(word);
            query_at += 1;
        }
    }
    if (!std.meta.eql(channel.digestWords(), capture.transcript_final_digest) or
        channel.inner.n_draws != capture.transcript_final_draw_count)
    {
        return error.EthereumIncrementalTranscriptMismatchV4;
    }

    var execution = try channel.finish();
    errdefer execution.deinit();
    var result = ReplayV4{
        .allocator = allocator,
        .execution = execution,
        .stage101_identity_sha256 = capture.identity_sha256,
        .native_statement_authority = capture.statement.authority_id,
        .relation_draws = relation_draws,
        .query_words = query_words,
        .query_log_size = query_log_size,
        .final_digest = capture.transcript_final_digest,
        .final_draw_count = capture.transcript_final_draw_count,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = replayIdentity(&result);
    try result.validate();
    return result;
}

fn setContext(channel: *recording.Channel, value: ContextV4) void {
    channel.setContextTag(@intFromEnum(value));
}

fn queryLogSize(proof: anytype) Error!u32 {
    var result: u32 = 0;
    for (proof.column_log_sizes) |logs| {
        if (logs.len == 0)
            return error.EthereumIncrementalTranscriptShapeMismatchV4;
        for (logs) |log_size| result = @max(result, log_size);
    }
    if (result == 0 or result >= 31)
        return error.EthereumIncrementalTranscriptShapeMismatchV4;
    return result;
}

fn relationDraws(
    value: ethereum_transcript.Relations,
) [RELATION_DRAW_COUNT]QM31 {
    var result: [RELATION_DRAW_COUNT]QM31 = undefined;
    value.base.writeDraws(result[0..BASE_RELATION_DRAW_COUNT]) catch
        unreachable;
    var at: usize = BASE_RELATION_DRAW_COUNT;
    inline for (.{
        value.keccak.io,
        value.keccak.chi,
        value.keccak.xor5,
        value.secp.product,
        value.secp.linear,
        value.secp.point,
        value.secp.split,
        value.secp.table,
        value.secp.program,
        value.secp.table_root,
        value.secp.ecdsa,
        value.secp.byte,
        value.secp.recovery,
    }) |pair| {
        result[at] = pair.z;
        result[at + 1] = pair.alpha;
        at += 2;
    }
    std.debug.assert(at == result.len);
    return result;
}

fn replayIdentity(value: *const ReplayV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.execution.identity_sha256);
    hash.update(&value.stage101_identity_sha256);
    for (value.native_statement_authority) |word|
        hashInt(&hash, u32, word);
    for (value.relation_draws) |draw| hashQm31(&hash, draw);
    for (value.query_words) |word| hashInt(&hash, u32, word.toU32());
    hashInt(&hash, u32, value.query_log_size);
    for (value.final_digest) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u32, value.final_draw_count);
    return hash.finalResult();
}

fn requireQm31(value: QM31) Error!void {
    for (value.toM31Array()) |word| if (word.toU32() >= m31.Modulus)
        return error.EthereumIncrementalTranscriptMismatchV4;
}

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 2 or
        COMMITMENT_COUNT != 4 or RELATION_DRAW_COUNT != 50 or
        QUERY_WORD_COUNT != 193 or PRODUCTION_ACTIVATION or
        REPLAY_IS_FRESH_CAPABILITY)
    {
        @compileError("Ethereum incremental transcript V4 drifted");
    }
}
