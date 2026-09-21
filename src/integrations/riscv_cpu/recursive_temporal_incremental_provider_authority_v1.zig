//! Recursive bridge compiler authority for narrow-memory provider shards.
//!
//! The core VM proof may omit the physical narrow-memory Poseidon provider.
//! Its ordered requests are then closed by independent provider-shard proofs
//! under the exact same relation challenge. This module consumes the native
//! provider plan/closure authority and the generic PCS residency plan; it does
//! not reimplement either planner and never hard-codes a shard count.
//! A decoded fixed authority is transport custody only. Production admission
//! must reopen every ordered shard proof/claim plus both plans through
//! `validateAgainst`. The wrapper AIR/fresh-verifier path is not yet complete,
//! so production activation remains fail-closed.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const prover_engine = @import("stwo_prover_engine");

const poseidon_air = frontend.air.memory_commitment.poseidon2_air;
const native_provider = frontend.prover_mod.memory_provider_shard_authority;
const residency = prover_engine.pcs.residency_shard_plan;
const channel = frontend.recursion.poseidon2_channel;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const SHARD_ARTIFACT_ENCODED_BYTE_COUNT: usize = 364;
pub const ENCODED_BYTE_COUNT: usize = 576;
pub const PRODUCTION_ACTIVATION = false;

const SHARD_CLAIM_DOMAIN = "stwo-zig/typed-air/provider-shard-claim/v1\x00";
const SHARD_ARTIFACT_DOMAIN = "stwo-zig/typed-air/provider-shard-artifact/v1\x00";
const CORE_CLAIM_DOMAIN = "stwo-zig/typed-air/provider-core-claim/v1\x00";
const MANIFEST_DOMAIN = "stwo-zig/typed-air/provider-shard-manifest/v1\x00";
const CANCELLATION_DOMAIN = "stwo-zig/typed-air/provider-shard-cancellation/v1\x00";
const AUTHORITY_DOMAIN = "stwo-zig/typed-air/provider-shard-compiler/v1\x00";
const SHARD_CLAIM_DIGEST_DOMAIN: u32 = 0x5053_4331; // "PSC1"
const CORE_CLAIM_DIGEST_DOMAIN: u32 = 0x5043_4331; // "PCC1"
const RELATION_DIGEST_DOMAIN: u32 = 0x5052_4331; // "PRC1"
const MANIFEST_DIGEST_DOMAIN: u32 = 0x5053_4d31; // "PSM1"
const CANCELLATION_DIGEST_DOMAIN: u32 = 0x5053_4131; // "PSA1"

pub const KindV1 = enum(u8) {
    narrow_memory_poseidon = 1,
};

pub const ShardArtifactInputV1 = struct {
    ordinal: u32,
    proof_artifact_sha256: [32]u8,
    proof_root_sha256: [32]u8,
    proof_capture_sha256: [32]u8,
    capture_identity: [32]u8,
    air_program_identity: [32]u8,
    verifier_program_authority: [32]u8,
    protocol_profile_sha256: [32]u8,
    preprocessed_commitment_root: channel.Digest,
};

/// Transaction-local identity of one successfully verified provider shard.
/// Per-shard program and preprocessed-root fields permit heterogeneous final
/// shard geometry while preserving exact ordered proof custody.
pub const ShardArtifactV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    kind: KindV1 = .narrow_memory_poseidon,
    reserved: [3]u8 = .{ 0, 0, 0 },
    ordinal: u32,
    proof_artifact_sha256: [32]u8,
    proof_root_sha256: [32]u8,
    proof_capture_sha256: [32]u8,
    capture_identity: [32]u8,
    claim_sha256: [32]u8,
    air_program_identity: [32]u8,
    verifier_program_authority: [32]u8,
    protocol_profile_sha256: [32]u8,
    preprocessed_commitment_root: channel.Digest,
    claim_digest: channel.Digest,
    artifact_identity_sha256: [32]u8,

    pub fn initFromFreshVerifier(
        input: ShardArtifactInputV1,
        claim: native_provider.ProviderShardClaimV1,
    ) !ShardArtifactV1 {
        var result = ShardArtifactV1{
            .ordinal = input.ordinal,
            .proof_artifact_sha256 = input.proof_artifact_sha256,
            .proof_root_sha256 = input.proof_root_sha256,
            .proof_capture_sha256 = input.proof_capture_sha256,
            .capture_identity = input.capture_identity,
            .claim_sha256 = claimSha256(claim),
            .air_program_identity = input.air_program_identity,
            .verifier_program_authority = input.verifier_program_authority,
            .protocol_profile_sha256 = input.protocol_profile_sha256,
            .preprocessed_commitment_root = input.preprocessed_commitment_root,
            .claim_digest = claimDigest(claim),
            .artifact_identity_sha256 = undefined,
        };
        result.artifact_identity_sha256 = shardArtifactIdentity(&result);
        try result.validate();
        return result;
    }
    pub fn validate(self: *const ShardArtifactV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.kind != .narrow_memory_poseidon or
            !std.mem.allEqual(u8, &self.reserved, 0))
        {
            return error.InvalidIncrementalProviderShard;
        }
        inline for (.{
            self.proof_artifact_sha256,
            self.proof_root_sha256,
            self.proof_capture_sha256,
            self.capture_identity,
            self.claim_sha256,
            self.air_program_identity,
            self.verifier_program_authority,
            self.protocol_profile_sha256,
            self.artifact_identity_sha256,
        }) |value| try requireSha(value);
        try requireDigest(self.preprocessed_commitment_root);
        try requireDigest(self.claim_digest);
        if (!std.mem.eql(
            u8,
            &self.artifact_identity_sha256,
            &shardArtifactIdentity(self),
        )) return error.InvalidIncrementalProviderShard;
    }
    pub fn validateAgainst(
        self: *const ShardArtifactV1,
        claim: native_provider.ProviderShardClaimV1,
        descriptor: native_provider.ProviderShardDescriptorV1,
        relation: native_provider.PoseidonRelationContextV1,
        expected_ordinal: usize,
    ) !void {
        try self.validate();
        const ordinal = std.math.cast(u32, expected_ordinal) orelse
            return error.IncrementalProviderShardMismatch;
        if (self.ordinal != ordinal or claim.shard_index != ordinal or
            !std.mem.eql(
                u8,
                &claim.descriptor_identity,
                &descriptor.identity,
            ) or !std.mem.eql(
            u8,
            &claim.relation_context_identity,
            &relation.identity,
        ) or !std.mem.eql(
            u8,
            &self.claim_sha256,
            &claimSha256(claim),
        ) or !std.meta.eql(self.claim_digest, claimDigest(claim))) {
            return error.IncrementalProviderShardMismatch;
        }
    }
    pub fn encodeCanonical(
        self: *const ShardArtifactV1,
    ) ![SHARD_ARTIFACT_ENCODED_BYTE_COUNT]u8 {
        try self.validate();
        var result: [SHARD_ARTIFACT_ENCODED_BYTE_COUNT]u8 = undefined;
        var writer = Writer{ .bytes = &result };
        writeShard(&writer, self);
        std.debug.assert(writer.at == result.len);
        return result;
    }
    pub fn decodeCanonical(bytes: []const u8) !ShardArtifactV1 {
        if (bytes.len != SHARD_ARTIFACT_ENCODED_BYTE_COUNT)
            return error.InvalidIncrementalProviderShard;
        var reader = Reader{ .bytes = bytes };
        const result = readShard(&reader) catch
            return error.InvalidIncrementalProviderShard;
        if (reader.at != bytes.len)
            return error.InvalidIncrementalProviderShard;
        try result.validate();
        const canonical = try result.encodeCanonical();
        if (!std.mem.eql(u8, bytes, &canonical))
            return error.InvalidIncrementalProviderShard;
        return result;
    }
};

pub const CompilerInputV1 = struct {
    entry_continuation_root: u32,
    exit_continuation_root: u32,
    core_proof_artifact_sha256: [32]u8,
    core_proof_capture_sha256: [32]u8,
    core_capture_identity: [32]u8,
    residency_request: residency.Request,
    residency_plan: residency.Plan,
    provider_plan: *const native_provider.ProviderShardPlanV1,
    calls: []const poseidon_air.Call,
    relation: native_provider.PoseidonRelationContextV1,
    core_claim: native_provider.CorePoseidonClaimV1,
    shard_claims: []const native_provider.ProviderShardClaimV1,
    shard_artifacts: []const ShardArtifactV1,
};

/// Fixed projection retained by NodePublicAuthorityV2. The complete provider
/// plan, calls, claims and shard artifacts are separate compiler inputs and
/// must be reopened by `validateAgainst`.
pub const ProviderCompilerAuthorityV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    kind: KindV1 = .narrow_memory_poseidon,
    reserved: [3]u8 = .{ 0, 0, 0 },
    shard_count: u32,
    total_call_count: u64,
    maximum_shard_log_size: u32,
    entry_continuation_root: u32,
    exit_continuation_root: u32,
    residency_request_sha256: [32]u8,
    residency_plan_sha256: [32]u8,
    provider_session_identity: [32]u8,
    provider_plan_identity: [32]u8,
    provider_call_list_identity: [32]u8,
    relation_context_identity: [32]u8,
    relation_context_digest: channel.Digest,
    core_proof_artifact_sha256: [32]u8,
    core_proof_capture_sha256: [32]u8,
    core_capture_identity: [32]u8,
    core_claim_sha256: [32]u8,
    core_claim_digest: channel.Digest,
    shard_manifest_sha256: [32]u8,
    shard_manifest_digest: channel.Digest,
    aggregate_cancellation_sha256: [32]u8,
    aggregate_cancellation_digest: channel.Digest,
    compiler_authority_sha256: [32]u8,

    pub fn compile(input: CompilerInputV1) !ProviderCompilerAuthorityV1 {
        const result = try compileUnchecked(input);
        try result.validateAgainst(input);
        return result;
    }
    /// Structural validation is sufficient only for canonical transport. It
    /// deliberately cannot establish proof or ordered-claim custody.
    pub fn validate(self: *const ProviderCompilerAuthorityV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.kind != .narrow_memory_poseidon or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            self.shard_count == 0 or self.total_call_count == 0 or
            self.maximum_shard_log_size <
                native_provider.minimum_shard_log_size or
            self.maximum_shard_log_size >
                native_provider.maximum_shard_log_size or
            self.entry_continuation_root >= core.fields.m31.Modulus or
            self.exit_continuation_root >= core.fields.m31.Modulus)
        {
            return error.InvalidIncrementalProviderAuthority;
        }
        inline for (.{
            self.residency_request_sha256,
            self.residency_plan_sha256,
            self.provider_session_identity,
            self.provider_plan_identity,
            self.provider_call_list_identity,
            self.relation_context_identity,
            self.core_proof_artifact_sha256,
            self.core_proof_capture_sha256,
            self.core_capture_identity,
            self.core_claim_sha256,
            self.shard_manifest_sha256,
            self.aggregate_cancellation_sha256,
            self.compiler_authority_sha256,
        }) |value| try requireSha(value);
        inline for (.{
            self.relation_context_digest,
            self.core_claim_digest,
            self.shard_manifest_digest,
            self.aggregate_cancellation_digest,
        }) |value| try requireDigest(value);
        if (!std.mem.eql(
            u8,
            &self.aggregate_cancellation_sha256,
            &cancellationSha256(self),
        ) or !std.meta.eql(
            self.aggregate_cancellation_digest,
            cancellationDigest(self),
        ) or !std.mem.eql(
            u8,
            &self.compiler_authority_sha256,
            &authorityIdentity(self),
        )) return error.InvalidIncrementalProviderAuthority;
    }
    pub fn validateAgainst(
        self: *const ProviderCompilerAuthorityV1,
        input: CompilerInputV1,
    ) !void {
        try self.validate();
        const expected = try compileUnchecked(input);
        if (!std.meta.eql(self.*, expected))
            return error.IncrementalProviderAuthorityMismatch;
    }
    pub fn requireProduction(
        self: *const ProviderCompilerAuthorityV1,
        input: CompilerInputV1,
    ) !void {
        try self.validateAgainst(input);
        if (!PRODUCTION_ACTIVATION)
            return error.IncrementalProviderProofUnavailable;
    }

    pub fn encodeCanonical(
        self: *const ProviderCompilerAuthorityV1,
    ) ![ENCODED_BYTE_COUNT]u8 {
        try self.validate();
        var result: [ENCODED_BYTE_COUNT]u8 = undefined;
        var writer = Writer{ .bytes = &result };
        writeAuthority(&writer, self);
        std.debug.assert(writer.at == result.len);
        return result;
    }

    pub fn decodeCanonical(bytes: []const u8) !ProviderCompilerAuthorityV1 {
        if (bytes.len != ENCODED_BYTE_COUNT)
            return error.InvalidIncrementalProviderAuthority;
        var reader = Reader{ .bytes = bytes };
        const result = readAuthority(&reader) catch
            return error.InvalidIncrementalProviderAuthority;
        if (reader.at != bytes.len)
            return error.InvalidIncrementalProviderAuthority;
        try result.validate();
        const canonical = try result.encodeCanonical();
        if (!std.mem.eql(u8, bytes, &canonical))
            return error.InvalidIncrementalProviderAuthority;
        return result;
    }
};

fn compileUnchecked(input: CompilerInputV1) !ProviderCompilerAuthorityV1 {
    try validateCompilerInput(input);
    var result = ProviderCompilerAuthorityV1{
        .shard_count = input.provider_plan.shard_count,
        .total_call_count = input.provider_plan.total_call_count,
        .maximum_shard_log_size = input.provider_plan.residency.result.shard_log_size,
        .entry_continuation_root = input.entry_continuation_root,
        .exit_continuation_root = input.exit_continuation_root,
        .residency_request_sha256 = input.residency_request.identity(),
        .residency_plan_sha256 = input.residency_plan.plan_identity,
        .provider_session_identity = input.provider_plan.session,
        .provider_plan_identity = input.provider_plan.identity,
        .provider_call_list_identity = input.provider_plan.call_list_commitment,
        .relation_context_identity = input.relation.identity,
        .relation_context_digest = relationDigest(input.relation),
        .core_proof_artifact_sha256 = input.core_proof_artifact_sha256,
        .core_proof_capture_sha256 = input.core_proof_capture_sha256,
        .core_capture_identity = input.core_capture_identity,
        .core_claim_sha256 = coreClaimSha256(input.core_claim),
        .core_claim_digest = coreClaimDigest(input.core_claim),
        .shard_manifest_sha256 = manifestSha256(input),
        .shard_manifest_digest = manifestDigest(input),
        .aggregate_cancellation_sha256 = undefined,
        .aggregate_cancellation_digest = undefined,
        .compiler_authority_sha256 = undefined,
    };
    result.aggregate_cancellation_sha256 = cancellationSha256(&result);
    result.aggregate_cancellation_digest = cancellationDigest(&result);
    result.compiler_authority_sha256 = authorityIdentity(&result);
    try result.validate();
    return result;
}

fn validateCompilerInput(input: CompilerInputV1) !void {
    inline for (.{
        input.core_proof_artifact_sha256,
        input.core_proof_capture_sha256,
        input.core_capture_identity,
    }) |value| try requireSha(value);
    if (input.entry_continuation_root >= core.fields.m31.Modulus or
        input.exit_continuation_root >= core.fields.m31.Modulus or
        input.shard_claims.len != input.provider_plan.shards.len or
        input.shard_artifacts.len != input.provider_plan.shards.len)
    {
        return error.InvalidIncrementalProviderAuthority;
    }
    try input.residency_plan.validateAgainst(input.residency_request);
    try input.provider_plan.validate(input.calls);
    try input.relation.validate(input.provider_plan.session);
    const call_count = std.math.cast(u64, input.calls.len) orelse
        return error.IncrementalProviderPlanMismatch;
    if (input.residency_request.logical_row_count != call_count or
        input.residency_request.column_count !=
            native_provider.main_column_count or
        input.residency_plan.shard_count !=
            @as(u64, input.provider_plan.shard_count) or
        input.residency_plan.shard_log_size !=
            input.provider_plan.residency.result.shard_log_size or
        input.residency_plan.final_shard_rows !=
            @as(
                u64,
                input.provider_plan.shards[
                    input.provider_plan.shards.len - 1
                ].call_count,
            ))
    {
        return error.IncrementalProviderPlanMismatch;
    }
    for (
        input.shard_artifacts,
        input.shard_claims,
        input.provider_plan.shards,
        0..,
    ) |*artifact, claim, descriptor, index| {
        try artifact.validateAgainst(claim, descriptor, input.relation, index);
        if (!std.mem.eql(
            u8,
            &claim.plan_identity,
            &input.provider_plan.identity,
        )) return error.IncrementalProviderShardMismatch;
    }
    _ = try native_provider.verifyAggregateClosure(
        input.provider_plan,
        input.calls,
        input.relation,
        input.core_claim,
        input.shard_claims,
    );
}

fn claimSha256(claim: native_provider.ProviderShardClaimV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(SHARD_CLAIM_DOMAIN);
    hash.update(&claim.plan_identity);
    hash.update(&claim.descriptor_identity);
    hashInt(&hash, u32, claim.shard_index);
    hash.update(&claim.relation_context_identity);
    hashQm31(&hash, claim.claims.sums[0]);
    hashQm31(&hash, claim.claims.sums[1]);
    return hash.finalResult();
}

fn claimDigest(claim: native_provider.ProviderShardClaimV1) channel.Digest {
    var hash = FieldHasher.init(SHARD_CLAIM_DIGEST_DOMAIN);
    hash.sha(claim.plan_identity);
    hash.sha(claim.descriptor_identity);
    hash.u32Value(claim.shard_index);
    hash.sha(claim.relation_context_identity);
    hash.qm31(claim.claims.sums[0]);
    hash.qm31(claim.claims.sums[1]);
    return hash.finalize();
}

fn coreClaimSha256(claim: native_provider.CorePoseidonClaimV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(CORE_CLAIM_DOMAIN);
    hash.update(&claim.plan_identity);
    hash.update(&claim.relation_context_identity);
    hashQm31(&hash, claim.claim);
    return hash.finalResult();
}

fn coreClaimDigest(
    claim: native_provider.CorePoseidonClaimV1,
) channel.Digest {
    var hash = FieldHasher.init(CORE_CLAIM_DIGEST_DOMAIN);
    hash.sha(claim.plan_identity);
    hash.sha(claim.relation_context_identity);
    hash.qm31(claim.claim);
    return hash.finalize();
}

fn relationDigest(
    relation: native_provider.PoseidonRelationContextV1,
) channel.Digest {
    var hash = FieldHasher.init(RELATION_DIGEST_DOMAIN);
    hash.sha(relation.session);
    hash.qm31(relation.z);
    hash.qm31(relation.alpha);
    hash.sha(relation.identity);
    return hash.finalize();
}

fn manifestSha256(input: CompilerInputV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(MANIFEST_DOMAIN);
    hash.update(&input.residency_plan.request_identity);
    hash.update(&input.residency_plan.plan_identity);
    hash.update(&input.provider_plan.identity);
    hashInt(&hash, usize, input.shard_artifacts.len);
    for (input.shard_artifacts, input.provider_plan.shards) |artifact, shard| {
        hash.update(&shard.identity);
        hash.update(&artifact.claim_sha256);
        hashDigest(&hash, artifact.claim_digest);
        hash.update(&artifact.artifact_identity_sha256);
    }
    return hash.finalResult();
}

fn manifestDigest(input: CompilerInputV1) channel.Digest {
    var hash = FieldHasher.init(MANIFEST_DIGEST_DOMAIN);
    hash.sha(input.residency_plan.request_identity);
    hash.sha(input.residency_plan.plan_identity);
    hash.sha(input.provider_plan.identity);
    hash.u32Value(@intCast(input.shard_artifacts.len));
    for (input.shard_artifacts, input.provider_plan.shards) |artifact, shard| {
        hash.sha(shard.identity);
        hash.sha(artifact.claim_sha256);
        hash.digest(artifact.claim_digest);
        hash.sha(artifact.artifact_identity_sha256);
    }
    return hash.finalize();
}

fn shardArtifactIdentity(value: *const ShardArtifactV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(SHARD_ARTIFACT_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.kind));
    hash.update(&value.reserved);
    hashInt(&hash, u32, value.ordinal);
    inline for (.{
        value.proof_artifact_sha256,
        value.proof_root_sha256,
        value.proof_capture_sha256,
        value.capture_identity,
        value.claim_sha256,
        value.air_program_identity,
        value.verifier_program_authority,
        value.protocol_profile_sha256,
    }) |item| hash.update(&item);
    hashDigest(&hash, value.preprocessed_commitment_root);
    hashDigest(&hash, value.claim_digest);
    return hash.finalResult();
}

fn cancellationSha256(value: *const ProviderCompilerAuthorityV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(CANCELLATION_DOMAIN);
    hash.update(&value.residency_request_sha256);
    hash.update(&value.residency_plan_sha256);
    hash.update(&value.provider_plan_identity);
    hash.update(&value.relation_context_identity);
    hashDigest(&hash, value.relation_context_digest);
    hash.update(&value.core_claim_sha256);
    hashDigest(&hash, value.core_claim_digest);
    hash.update(&value.shard_manifest_sha256);
    hashDigest(&hash, value.shard_manifest_digest);
    return hash.finalResult();
}

fn cancellationDigest(
    value: *const ProviderCompilerAuthorityV1,
) channel.Digest {
    var hash = FieldHasher.init(CANCELLATION_DIGEST_DOMAIN);
    hash.sha(value.residency_request_sha256);
    hash.sha(value.residency_plan_sha256);
    hash.sha(value.provider_plan_identity);
    hash.sha(value.relation_context_identity);
    hash.digest(value.relation_context_digest);
    hash.sha(value.core_claim_sha256);
    hash.digest(value.core_claim_digest);
    hash.sha(value.shard_manifest_sha256);
    hash.digest(value.shard_manifest_digest);
    return hash.finalize();
}

fn authorityIdentity(value: *const ProviderCompilerAuthorityV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.kind));
    hash.update(&value.reserved);
    hashInt(&hash, u32, value.shard_count);
    hashInt(&hash, u64, value.total_call_count);
    hashInt(&hash, u32, value.maximum_shard_log_size);
    hashInt(&hash, u32, value.entry_continuation_root);
    hashInt(&hash, u32, value.exit_continuation_root);
    inline for (.{
        value.residency_request_sha256,
        value.residency_plan_sha256,
        value.provider_session_identity,
        value.provider_plan_identity,
        value.provider_call_list_identity,
        value.relation_context_identity,
    }) |item| hash.update(&item);
    hashDigest(&hash, value.relation_context_digest);
    inline for (.{
        value.core_proof_artifact_sha256,
        value.core_proof_capture_sha256,
        value.core_capture_identity,
        value.core_claim_sha256,
    }) |item| hash.update(&item);
    hashDigest(&hash, value.core_claim_digest);
    hash.update(&value.shard_manifest_sha256);
    hashDigest(&hash, value.shard_manifest_digest);
    hash.update(&value.aggregate_cancellation_sha256);
    hashDigest(&hash, value.aggregate_cancellation_digest);
    return hash.finalResult();
}

fn writeShard(writer: *Writer, value: *const ShardArtifactV1) void {
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.u8Value(@intFromEnum(value.kind));
    writer.bytesValue(&value.reserved);
    writer.u32Value(value.ordinal);
    inline for (.{
        value.proof_artifact_sha256,
        value.proof_root_sha256,
        value.proof_capture_sha256,
        value.capture_identity,
        value.claim_sha256,
        value.air_program_identity,
        value.verifier_program_authority,
        value.protocol_profile_sha256,
    }) |item| writer.sha(item);
    writer.digest(value.preprocessed_commitment_root);
    writer.digest(value.claim_digest);
    writer.sha(value.artifact_identity_sha256);
}

fn readShard(reader: *Reader) !ShardArtifactV1 {
    return .{
        .format_version = reader.u16Value(),
        .schema_version = reader.u16Value(),
        .kind = std.meta.intToEnum(KindV1, reader.u8Value()) catch
            return error.InvalidIncrementalProviderShard,
        .reserved = reader.take(3)[0..3].*,
        .ordinal = reader.u32Value(),
        .proof_artifact_sha256 = reader.sha(),
        .proof_root_sha256 = reader.sha(),
        .proof_capture_sha256 = reader.sha(),
        .capture_identity = reader.sha(),
        .claim_sha256 = reader.sha(),
        .air_program_identity = reader.sha(),
        .verifier_program_authority = reader.sha(),
        .protocol_profile_sha256 = reader.sha(),
        .preprocessed_commitment_root = reader.digest(),
        .claim_digest = reader.digest(),
        .artifact_identity_sha256 = reader.sha(),
    };
}

fn writeAuthority(
    writer: *Writer,
    value: *const ProviderCompilerAuthorityV1,
) void {
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.u8Value(@intFromEnum(value.kind));
    writer.bytesValue(&value.reserved);
    writer.u32Value(value.shard_count);
    writer.u64Value(value.total_call_count);
    writer.u32Value(value.maximum_shard_log_size);
    writer.u32Value(value.entry_continuation_root);
    writer.u32Value(value.exit_continuation_root);
    inline for (.{
        value.residency_request_sha256,
        value.residency_plan_sha256,
        value.provider_session_identity,
        value.provider_plan_identity,
        value.provider_call_list_identity,
        value.relation_context_identity,
    }) |item| writer.sha(item);
    writer.digest(value.relation_context_digest);
    inline for (.{
        value.core_proof_artifact_sha256,
        value.core_proof_capture_sha256,
        value.core_capture_identity,
        value.core_claim_sha256,
    }) |item| writer.sha(item);
    writer.digest(value.core_claim_digest);
    writer.sha(value.shard_manifest_sha256);
    writer.digest(value.shard_manifest_digest);
    writer.sha(value.aggregate_cancellation_sha256);
    writer.digest(value.aggregate_cancellation_digest);
    writer.sha(value.compiler_authority_sha256);
}

fn readAuthority(reader: *Reader) !ProviderCompilerAuthorityV1 {
    return .{
        .format_version = reader.u16Value(),
        .schema_version = reader.u16Value(),
        .kind = std.meta.intToEnum(KindV1, reader.u8Value()) catch
            return error.InvalidIncrementalProviderAuthority,
        .reserved = reader.take(3)[0..3].*,
        .shard_count = reader.u32Value(),
        .total_call_count = reader.u64Value(),
        .maximum_shard_log_size = reader.u32Value(),
        .entry_continuation_root = reader.u32Value(),
        .exit_continuation_root = reader.u32Value(),
        .residency_request_sha256 = reader.sha(),
        .residency_plan_sha256 = reader.sha(),
        .provider_session_identity = reader.sha(),
        .provider_plan_identity = reader.sha(),
        .provider_call_list_identity = reader.sha(),
        .relation_context_identity = reader.sha(),
        .relation_context_digest = reader.digest(),
        .core_proof_artifact_sha256 = reader.sha(),
        .core_proof_capture_sha256 = reader.sha(),
        .core_capture_identity = reader.sha(),
        .core_claim_sha256 = reader.sha(),
        .core_claim_digest = reader.digest(),
        .shard_manifest_sha256 = reader.sha(),
        .shard_manifest_digest = reader.digest(),
        .aggregate_cancellation_sha256 = reader.sha(),
        .aggregate_cancellation_digest = reader.digest(),
        .compiler_authority_sha256 = reader.sha(),
    };
}

fn hashQm31(hash: *Sha256, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn requireSha(value: [32]u8) !void {
    if (std.mem.allEqual(u8, &value, 0))
        return error.InvalidIncrementalProviderIdentity;
}

fn requireDigest(value: channel.Digest) !void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= core.fields.m31.Modulus)
            return error.InvalidIncrementalProviderIdentity;
        aggregate |= word;
    }
    if (aggregate == 0) return error.InvalidIncrementalProviderIdentity;
}

fn hashDigest(hash: *Sha256, value: channel.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

const FieldHasher = struct {
    inner: channel.CanonicalWordHasher,

    fn init(domain: u32) FieldHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    fn u32Value(self: *FieldHasher, value: u32) void {
        const words = [2]M31{
            M31.fromCanonical(value & 0xffff),
            M31.fromCanonical(value >> 16),
        };
        self.inner.update(&words);
    }

    fn sha(self: *FieldHasher, value: [32]u8) void {
        var words: [16]M31 = undefined;
        for (&words, 0..) |*word, index| {
            const at = 2 * index;
            word.* = M31.fromCanonical(
                @as(u32, value[at]) |
                    (@as(u32, value[at + 1]) << 8),
            );
        }
        self.inner.update(&words);
    }

    fn digest(self: *FieldHasher, value: channel.Digest) void {
        var words: [channel.RATE]M31 = undefined;
        for (&words, value) |*word, item|
            word.* = M31.fromCanonical(item);
        self.inner.update(&words);
    }

    fn qm31(self: *FieldHasher, value: QM31) void {
        const words = value.toM31Array();
        self.inner.update(&words);
    }

    fn finalize(self: *FieldHasher) channel.Digest {
        return self.inner.finalize();
    }
};

const Writer = struct {
    bytes: []u8,
    at: usize = 0,
    fn bytesValue(self: *Writer, value: []const u8) void {
        @memcpy(self.bytes[self.at..][0..value.len], value);
        self.at += value.len;
    }
    fn u8Value(self: *Writer, value: u8) void {
        self.bytes[self.at] = value;
        self.at += 1;
    }
    fn u16Value(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.at..][0..2], value, .little);
        self.at += 2;
    }
    fn u32Value(self: *Writer, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.at..][0..4], value, .little);
        self.at += 4;
    }
    fn u64Value(self: *Writer, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.at..][0..8], value, .little);
        self.at += 8;
    }
    fn sha(self: *Writer, value: [32]u8) void {
        self.bytesValue(&value);
    }
    fn digest(self: *Writer, value: channel.Digest) void {
        for (value) |word| self.u32Value(word);
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    fn take(self: *Reader, count: usize) []const u8 {
        const result = self.bytes[self.at..][0..count];
        self.at += count;
        return result;
    }
    fn u8Value(self: *Reader) u8 {
        return self.take(1)[0];
    }
    fn u16Value(self: *Reader) u16 {
        return std.mem.readInt(u16, self.take(2)[0..2], .little);
    }
    fn u32Value(self: *Reader) u32 {
        return std.mem.readInt(u32, self.take(4)[0..4], .little);
    }
    fn u64Value(self: *Reader) u64 {
        return std.mem.readInt(u64, self.take(8)[0..8], .little);
    }
    fn sha(self: *Reader) [32]u8 {
        return self.take(32)[0..32].*;
    }
    fn digest(self: *Reader) channel.Digest {
        var result: channel.Digest = undefined;
        for (&result) |*word| word.* = self.u32Value();
        return result;
    }
};

comptime {
    if (SHARD_ARTIFACT_ENCODED_BYTE_COUNT != 364 or
        ENCODED_BYTE_COUNT != 576)
    {
        @compileError("incremental provider authority geometry drifted");
    }
}
