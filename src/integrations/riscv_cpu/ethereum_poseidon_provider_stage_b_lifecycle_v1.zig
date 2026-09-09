//! Resource-bounded Stage-B lifecycle for the joint Poseidon provider split.
//!
//! Each call to `proveCoreCreateOnly` or `proveProviderCreateOnly` owns exactly
//! one PCS instance inside the frozen frontend API.  The frontend tears that
//! instance down before returning its small proof value; this integration then
//! publishes the postcard proof first and its nonpromotable metadata second.
//! An orphan proof therefore never asserts completion.
//!
//! Resume and final closure never trust metadata or a prior verification
//! receipt.  They reopen the raw proof with NOFOLLOW custody, reconstruct the
//! verifier-selected shape from the frozen statement, and invoke the fresh
//! verifier again against the independently reopened Stage-A manifest,
//! authenticated call list, plan, and shared relation.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const proof_artifact = @import("ethereum_poseidon_provider_proof_artifact_v1.zig");
const proof_artifact_v2 = @import("ethereum_poseidon_provider_proof_artifact_v2.zig");
const resource = @import("ethereum_poseidon_provider_resource_plan_v1.zig");
const stage_a = @import("ethereum_poseidon_provider_stage_a_checkpoint_v1.zig");
const support = @import("ethereum_block_leaf_support.zig");

const authority = frontend.testing.narrow_memory_provider_shard_authority;
const joint_proof = frontend.testing.narrow_memory_provider_joint_proof;
const provider_v2 = frontend.testing.narrow_memory_provider_joint_proof_v2;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;

const Engine = support.RecursiveEngine;

pub const Context = struct {
    calls: []const poseidon2_air.Call,
    plan: *const authority.ProviderShardPlanV1,
    resource_plan: *const resource.ProviderResourcePlanV1,
    stage_a_checkpoint: evidence.FileIdentity,
    stage_a_checkpoint_content_sha256: [32]u8,
    stage_a_reopened: *const stage_a.Reopened,

    pub fn validate(self: Context) !void {
        try self.resource_plan.validate();
        try self.plan.validate(self.calls);
        try self.stage_a_reopened.manifest.validate(self.plan, self.calls);
        if (self.resource_plan.shard_planning.shard_count !=
            self.plan.shard_count or
            self.resource_plan.shard_planning.logical_row_count !=
                self.plan.total_call_count or
            !std.meta.eql(
                self.resource_plan.shard_planning,
                self.plan.residency.result,
            ) or
            !std.fs.path.isAbsolute(self.stage_a_checkpoint.path) or
            self.stage_a_checkpoint.bytes == 0)
        {
            return error.InvalidProviderStageBContext;
        }
    }
};

pub const Publication = struct {
    metadata: evidence.FileIdentity,
    metadata_content_sha256: [32]u8,
    proof: evidence.FileIdentity,
    prove_timing: evidence.Timing,
};

pub const FreshCore = struct {
    artifact: OwnedFileIdentity,
    artifact_content_sha256: [32]u8,
    claim: joint_proof.CoreWithoutProviderClaimV1,
    proof: OwnedFileIdentity,
    verifier_sha256: [32]u8,
    verify_timing: evidence.Timing,

    pub fn deinit(self: *FreshCore, allocator: std.mem.Allocator) void {
        self.artifact.deinit(allocator);
        self.proof.deinit(allocator);
        self.* = undefined;
    }
};

pub const FreshProvider = struct {
    artifact: OwnedFileIdentity,
    artifact_content_sha256: [32]u8,
    claim: joint_proof.FreshProviderClaimV1,
    proof: OwnedFileIdentity,
    verifier_sha256: [32]u8,
    verify_timing: evidence.Timing,

    pub fn deinit(self: *FreshProvider, allocator: std.mem.Allocator) void {
        self.artifact.deinit(allocator);
        self.proof.deinit(allocator);
        self.* = undefined;
    }
};

/// Production-candidate provider half. Unlike `FreshProvider`, this claim was
/// verified against the V2 Tree2 ordered-call accumulator. The overall joint
/// protocol remains nonproduction until the real RISC-V caller and recursive
/// admission are active.
pub const FreshProviderV2 = struct {
    artifact: OwnedFileIdentity,
    artifact_content_sha256: [32]u8,
    claim: provider_v2.FreshProviderClaimV2,
    proof: OwnedFileIdentity,
    verifier_sha256: [32]u8,
    verify_timing: evidence.Timing,

    pub fn deinit(self: *FreshProviderV2, allocator: std.mem.Allocator) void {
        self.artifact.deinit(allocator);
        self.proof.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedFileIdentity = struct {
    bytes: u64,
    path: []u8,
    sha256: [32]u8,

    pub fn deinit(self: *OwnedFileIdentity, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.* = undefined;
    }

    pub fn borrowed(self: OwnedFileIdentity) evidence.FileIdentity {
        return .{ .bytes = self.bytes, .path = self.path, .sha256 = self.sha256 };
    }
};

pub fn proveCoreCreateOnly(
    allocator: std.mem.Allocator,
    context: Context,
    producer_sha256: [32]u8,
    proof_path: []const u8,
    metadata_path: []const u8,
) !Publication {
    try context.validate();
    try validateOutputPaths(proof_path, metadata_path);

    var clock = try evidence.Clock.start();
    var output = try joint_proof.proveCore(
        Engine,
        allocator,
        support.recursive_pcs_config,
        context.plan,
        context.calls,
        &context.stage_a_reopened.manifest,
        context.stage_a_reopened.shared_relation,
    );
    defer output.proof.deinit(allocator);
    const timing = try clock.finish();
    const shape = try proof_artifact.coreProofShape(output.statement);
    const proof_bytes = try proof_artifact.serializeProofAlloc(
        allocator,
        output.proof,
        shape,
    );
    defer allocator.free(proof_bytes);
    try artifact_io.publishCreateOnlyDurable(proof_path, proof_bytes);
    const proof_identity = evidence.identity(proof_path, proof_bytes);

    const metadata_bytes = try proof_artifact.encodeCore(
        allocator,
        commonInput(
            context,
            producer_sha256,
            proof_identity,
            timing,
        ),
        output.statement,
    );
    defer allocator.free(metadata_bytes);
    try proof_artifact.publishCreateOnly(metadata_path, metadata_bytes);
    return publication(metadata_path, metadata_bytes, proof_identity, timing);
}

pub fn proveProviderCreateOnly(
    allocator: std.mem.Allocator,
    context: Context,
    producer_sha256: [32]u8,
    shard_index: u32,
    proof_path: []const u8,
    metadata_path: []const u8,
) !Publication {
    try context.validate();
    try validateOutputPaths(proof_path, metadata_path);
    if (shard_index >= context.plan.shard_count)
        return error.ShardIndexOutOfRange;

    var clock = try evidence.Clock.start();
    var output = try joint_proof.proveProvider(
        Engine,
        allocator,
        support.recursive_pcs_config,
        context.plan,
        context.calls,
        &context.stage_a_reopened.manifest,
        context.stage_a_reopened.shared_relation,
        shard_index,
    );
    defer output.proof.deinit(allocator);
    const timing = try clock.finish();
    const shape = try proof_artifact.providerProofShape(output.statement);
    const proof_bytes = try proof_artifact.serializeProofAlloc(
        allocator,
        output.proof,
        shape,
    );
    defer allocator.free(proof_bytes);
    try artifact_io.publishCreateOnlyDurable(proof_path, proof_bytes);
    const proof_identity = evidence.identity(proof_path, proof_bytes);

    const metadata_bytes = try proof_artifact.encodeProvider(
        allocator,
        commonInput(
            context,
            producer_sha256,
            proof_identity,
            timing,
        ),
        output.statement,
    );
    defer allocator.free(metadata_bytes);
    try proof_artifact.publishCreateOnly(metadata_path, metadata_bytes);
    return publication(metadata_path, metadata_bytes, proof_identity, timing);
}

pub fn proveProviderV2CreateOnly(
    allocator: std.mem.Allocator,
    context: Context,
    producer_sha256: [32]u8,
    shard_index: u32,
    proof_path: []const u8,
    metadata_path: []const u8,
) !Publication {
    try context.validate();
    try validateOutputPaths(proof_path, metadata_path);
    if (shard_index >= context.plan.shard_count)
        return error.ShardIndexOutOfRange;

    var clock = try evidence.Clock.start();
    var output = try provider_v2.proveProviderV2(
        Engine,
        allocator,
        support.recursive_pcs_config,
        context.plan,
        context.calls,
        &context.stage_a_reopened.manifest,
        context.stage_a_reopened.shared_relation,
        shard_index,
    );
    defer output.proof.deinit(allocator);
    const timing = try clock.finish();
    const shape = try proof_artifact_v2.proofShape(output.statement);
    const proof_bytes = try proof_artifact_v2.serializeProofAlloc(
        allocator,
        output.proof,
        shape,
    );
    defer allocator.free(proof_bytes);
    try artifact_io.publishCreateOnlyDurable(proof_path, proof_bytes);
    const proof_identity = evidence.identity(proof_path, proof_bytes);

    const metadata_bytes = try proof_artifact_v2.encode(
        allocator,
        commonInput(
            context,
            producer_sha256,
            proof_identity,
            timing,
        ),
        output.statement,
    );
    defer allocator.free(metadata_bytes);
    try proof_artifact_v2.publishCreateOnly(metadata_path, metadata_bytes);
    return publication(metadata_path, metadata_bytes, proof_identity, timing);
}

pub fn verifyCoreFresh(
    allocator: std.mem.Allocator,
    context: Context,
    expected_producer_sha256: [32]u8,
    verifier_sha256: [32]u8,
    metadata: evidence.FileIdentity,
) !FreshCore {
    try context.validate();
    var opened = try openMetadata(
        allocator,
        context,
        expected_producer_sha256,
        metadata,
        .core,
    );
    defer allocator.free(opened.bytes);
    defer opened.parsed.deinit();
    const statement = try proof_artifact.coreStatement(
        opened.parsed.value.core_statement.?,
    );
    const proof_bytes = try readArtifactProof(
        allocator,
        opened.parsed.value.proof,
    );
    defer allocator.free(proof_bytes);
    var proof = try proof_artifact.deserializeProof(
        allocator,
        proof_bytes,
        try proof_artifact.coreProofShape(statement),
    );
    var proof_owned = true;
    errdefer if (proof_owned) proof.deinit(allocator);
    var clock = try evidence.Clock.start();
    proof_owned = false;
    const claim = try joint_proof.verifyCoreFresh(
        Engine,
        allocator,
        support.recursive_pcs_config,
        context.plan,
        context.calls,
        &context.stage_a_reopened.manifest,
        context.stage_a_reopened.shared_relation,
        statement,
        proof,
    );
    const timing = try clock.finish();
    var artifact_identity = try ownFileIdentity(allocator, metadata);
    errdefer artifact_identity.deinit(allocator);
    var proof_identity = try ownContractIdentity(
        allocator,
        opened.parsed.value.proof,
    );
    errdefer proof_identity.deinit(allocator);
    return .{
        .artifact = artifact_identity,
        .artifact_content_sha256 = try contract.parseSha256(
            opened.parsed.value.content_sha256,
        ),
        .claim = claim,
        .proof = proof_identity,
        .verifier_sha256 = verifier_sha256,
        .verify_timing = timing,
    };
}

pub fn verifyProviderFresh(
    allocator: std.mem.Allocator,
    context: Context,
    expected_producer_sha256: [32]u8,
    verifier_sha256: [32]u8,
    expected_shard_index: u32,
    metadata: evidence.FileIdentity,
) !FreshProvider {
    try context.validate();
    if (expected_shard_index >= context.plan.shard_count)
        return error.ShardIndexOutOfRange;
    var opened = try openMetadata(
        allocator,
        context,
        expected_producer_sha256,
        metadata,
        .provider,
    );
    defer allocator.free(opened.bytes);
    defer opened.parsed.deinit();
    const statement = try proof_artifact.providerStatement(
        opened.parsed.value.provider_statement.?,
    );
    if (statement.shard_index != expected_shard_index)
        return error.NonCanonicalProviderProofOrder;
    const proof_bytes = try readArtifactProof(
        allocator,
        opened.parsed.value.proof,
    );
    defer allocator.free(proof_bytes);
    var proof = try proof_artifact.deserializeProof(
        allocator,
        proof_bytes,
        try proof_artifact.providerProofShape(statement),
    );
    var proof_owned = true;
    errdefer if (proof_owned) proof.deinit(allocator);
    var clock = try evidence.Clock.start();
    proof_owned = false;
    const claim = try joint_proof.verifyProviderFresh(
        Engine,
        allocator,
        support.recursive_pcs_config,
        context.plan,
        context.calls,
        &context.stage_a_reopened.manifest,
        context.stage_a_reopened.shared_relation,
        statement,
        proof,
    );
    const timing = try clock.finish();
    var artifact_identity = try ownFileIdentity(allocator, metadata);
    errdefer artifact_identity.deinit(allocator);
    var proof_identity = try ownContractIdentity(
        allocator,
        opened.parsed.value.proof,
    );
    errdefer proof_identity.deinit(allocator);
    return .{
        .artifact = artifact_identity,
        .artifact_content_sha256 = try contract.parseSha256(
            opened.parsed.value.content_sha256,
        ),
        .claim = claim,
        .proof = proof_identity,
        .verifier_sha256 = verifier_sha256,
        .verify_timing = timing,
    };
}

pub fn verifyProviderV2Fresh(
    allocator: std.mem.Allocator,
    context: Context,
    expected_producer_sha256: [32]u8,
    verifier_sha256: [32]u8,
    expected_shard_index: u32,
    metadata: evidence.FileIdentity,
) !FreshProviderV2 {
    try context.validate();
    if (expected_shard_index >= context.plan.shard_count)
        return error.ShardIndexOutOfRange;
    var opened = try openMetadataV2(
        allocator,
        context,
        expected_producer_sha256,
        metadata,
    );
    defer allocator.free(opened.bytes);
    defer opened.parsed.deinit();
    const statement = try proof_artifact_v2.statement(
        opened.parsed.value.statement,
    );
    if (statement.shard_index != expected_shard_index)
        return error.NonCanonicalProviderProofOrder;
    const proof_bytes = try readArtifactProof(
        allocator,
        opened.parsed.value.proof,
    );
    defer allocator.free(proof_bytes);
    var proof = try proof_artifact_v2.deserializeProof(
        allocator,
        proof_bytes,
        try proof_artifact_v2.proofShape(statement),
    );
    var proof_owned = true;
    errdefer if (proof_owned) proof.deinit(allocator);
    var clock = try evidence.Clock.start();
    proof_owned = false;
    const claim = try provider_v2.verifyProviderFreshV2(
        Engine,
        allocator,
        support.recursive_pcs_config,
        context.plan,
        context.calls,
        &context.stage_a_reopened.manifest,
        context.stage_a_reopened.shared_relation,
        statement,
        proof,
    );
    const timing = try clock.finish();
    var artifact_identity = try ownFileIdentity(allocator, metadata);
    errdefer artifact_identity.deinit(allocator);
    var proof_identity = try ownContractIdentity(
        allocator,
        opened.parsed.value.proof,
    );
    errdefer proof_identity.deinit(allocator);
    return .{
        .artifact = artifact_identity,
        .artifact_content_sha256 = try contract.parseSha256(
            opened.parsed.value.content_sha256,
        ),
        .claim = claim,
        .proof = proof_identity,
        .verifier_sha256 = verifier_sha256,
        .verify_timing = timing,
    };
}

pub fn closeFresh(
    allocator: std.mem.Allocator,
    context: Context,
    core_claim: joint_proof.CoreWithoutProviderClaimV1,
    provider_claims: []const joint_proof.FreshProviderClaimV1,
) !joint_proof.VerifiedJointClosureV1 {
    try context.validate();
    if (provider_claims.len != context.plan.shard_count)
        return error.IncompleteProviderProofPrefix;
    return joint_proof.closeFreshClaims(
        allocator,
        context.plan,
        context.calls,
        context.stage_a_reopened.manifest.identity,
        context.stage_a_reopened.shared_relation.relation_context,
        core_claim,
        provider_claims,
    );
}

pub fn closeFreshV2(
    allocator: std.mem.Allocator,
    context: Context,
    core_claim: joint_proof.CoreWithoutProviderClaimV1,
    provider_claims: []const provider_v2.FreshProviderClaimV2,
) !provider_v2.VerifiedJointClosureV2 {
    try context.validate();
    if (provider_claims.len != context.plan.shard_count)
        return error.IncompleteProviderProofPrefix;
    return provider_v2.closeFreshClaimsV2(
        allocator,
        context.plan,
        context.calls,
        context.stage_a_reopened.manifest.identity,
        context.stage_a_reopened.shared_relation.relation_context,
        core_claim,
        provider_claims,
    );
}

const OpenedMetadata = struct {
    bytes: []u8,
    parsed: std.json.Parsed(proof_artifact.Artifact),
};

const OpenedMetadataV2 = struct {
    bytes: []u8,
    parsed: std.json.Parsed(proof_artifact_v2.Artifact),
};

fn openMetadata(
    allocator: std.mem.Allocator,
    context: Context,
    expected_producer_sha256: [32]u8,
    metadata: evidence.FileIdentity,
    expected_role: proof_artifact.Role,
) !OpenedMetadata {
    var metadata_sha: [64]u8 = undefined;
    const bytes = try support.readIdentity(
        allocator,
        contractIdentity(metadata, &metadata_sha),
        proof_artifact.max_metadata_bytes,
    );
    errdefer allocator.free(bytes);
    var parsed = try proof_artifact.parse(allocator, bytes);
    errdefer parsed.deinit();
    const value = parsed.value;
    if (!std.mem.eql(u8, value.role, expected_role.text()) or
        !std.mem.eql(
            u8,
            value.producer_sha256,
            &hex(expected_producer_sha256),
        ) or
        !std.mem.eql(
            u8,
            value.resource_plan_identity_sha256,
            &hex(context.resource_plan.identity),
        ) or
        !identityMatches(value.stage_a_checkpoint, context.stage_a_checkpoint) or
        !std.mem.eql(
            u8,
            value.stage_a_checkpoint_content_sha256,
            &hex(context.stage_a_checkpoint_content_sha256),
        ))
    {
        return error.ProviderProofArtifactAuthorityMismatch;
    }
    return .{ .bytes = bytes, .parsed = parsed };
}

fn openMetadataV2(
    allocator: std.mem.Allocator,
    context: Context,
    expected_producer_sha256: [32]u8,
    metadata: evidence.FileIdentity,
) !OpenedMetadataV2 {
    var metadata_sha: [64]u8 = undefined;
    const bytes = try support.readIdentity(
        allocator,
        contractIdentity(metadata, &metadata_sha),
        proof_artifact.max_metadata_bytes,
    );
    errdefer allocator.free(bytes);
    var parsed = try proof_artifact_v2.parse(allocator, bytes);
    errdefer parsed.deinit();
    const value = parsed.value;
    if (!std.mem.eql(
        u8,
        value.producer_sha256,
        &hex(expected_producer_sha256),
    ) or !std.mem.eql(
        u8,
        value.resource_plan_identity_sha256,
        &hex(context.resource_plan.identity),
    ) or !identityMatches(value.stage_a_checkpoint, context.stage_a_checkpoint) or
        !std.mem.eql(
            u8,
            value.stage_a_checkpoint_content_sha256,
            &hex(context.stage_a_checkpoint_content_sha256),
        ))
    {
        return error.ProviderProofArtifactAuthorityMismatch;
    }
    return .{ .bytes = bytes, .parsed = parsed };
}

fn readArtifactProof(
    allocator: std.mem.Allocator,
    identity: contract.Identity,
) ![]u8 {
    return support.readIdentity(allocator, identity, proof_artifact.max_proof_bytes);
}

fn commonInput(
    context: Context,
    producer_sha256: [32]u8,
    proof: evidence.FileIdentity,
    timing: evidence.Timing,
) proof_artifact.CommonInput {
    return .{
        .producer_sha256 = producer_sha256,
        .proof = proof,
        .prove_timing = timing,
        .resource_plan_identity = context.resource_plan.identity,
        .stage_a_checkpoint = context.stage_a_checkpoint,
        .stage_a_checkpoint_content_sha256 = context.stage_a_checkpoint_content_sha256,
    };
}

fn publication(
    metadata_path: []const u8,
    metadata_bytes: []const u8,
    proof: evidence.FileIdentity,
    timing: evidence.Timing,
) Publication {
    const metadata = evidence.identity(metadata_path, metadata_bytes);
    const content_prefix = "{\"content_sha256\":\"";
    const start = content_prefix.len;
    return .{
        .metadata = metadata,
        .metadata_content_sha256 = contract.parseSha256(
            metadata_bytes[start .. start + 64],
        ) catch unreachable,
        .proof = proof,
        .prove_timing = timing,
    };
}

fn ownFileIdentity(
    allocator: std.mem.Allocator,
    value: evidence.FileIdentity,
) !OwnedFileIdentity {
    return .{
        .bytes = value.bytes,
        .path = try allocator.dupe(u8, value.path),
        .sha256 = value.sha256,
    };
}

fn ownContractIdentity(
    allocator: std.mem.Allocator,
    value: contract.Identity,
) !OwnedFileIdentity {
    const digest = try contract.parseSha256(value.sha256);
    return .{
        .bytes = value.bytes,
        .path = try allocator.dupe(u8, value.path),
        .sha256 = digest,
    };
}

fn identityMatches(
    actual: contract.Identity,
    expected: evidence.FileIdentity,
) bool {
    if (actual.bytes != expected.bytes or
        !std.mem.eql(u8, actual.path, expected.path)) return false;
    const digest = contract.parseSha256(actual.sha256) catch return false;
    return std.mem.eql(u8, &digest, &expected.sha256);
}

fn contractIdentity(
    value: evidence.FileIdentity,
    storage: *[64]u8,
) contract.Identity {
    storage.* = hex(value.sha256);
    return .{
        .bytes = value.bytes,
        .path = value.path,
        .sha256 = storage,
    };
}

fn validateOutputPaths(proof_path: []const u8, metadata_path: []const u8) !void {
    if (!std.fs.path.isAbsolute(proof_path) or
        !std.fs.path.isAbsolute(metadata_path) or
        std.mem.eql(u8, proof_path, metadata_path))
    {
        return error.InvalidProviderStageBOutputPath;
    }
}

fn hex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}

comptime {
    if (joint_proof.ACTIVATES_PRODUCTION_PROOF or
        joint_proof.ORDERED_CALL_COMMITMENT_IS_AIR_PROVED or
        joint_proof.FULL_RISCV_CORE_EXTERNALIZED or
        joint_proof.RECURSIVE_VERIFICATION_IMPLEMENTED)
    {
        @compileError("Stage-B nonproduction readiness flags drifted");
    }
    if (provider_v2.ACTIVATES_PRODUCTION_PROOF or
        !provider_v2.PROVIDER_ORDERED_CALL_COMMITMENT_IS_AIR_PROVED or
        !provider_v2.PROVIDER_RANGE_IS_PUBLIC_STATEMENT_BOUND or
        !provider_v2.FRESH_VERIFIER_RECOMPUTES_ORDERED_ENDPOINT or
        provider_v2.FULL_RISCV_CORE_EXTERNALIZED or
        provider_v2.RECURSIVE_VERIFICATION_IMPLEMENTED)
    {
        @compileError("Stage-B V2 readiness flags drifted");
    }
}
