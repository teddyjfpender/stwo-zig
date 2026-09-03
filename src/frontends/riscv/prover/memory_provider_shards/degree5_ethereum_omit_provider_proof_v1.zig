//! Degree-five ordered provider proof under the provider-free Ethereum core
//! transcript.
//!
//! The standalone degree-five proof is useful performance evidence, but it
//! draws an independent relation context.  This sibling commits the 239-column
//! degree-five Stage A into the Ethereum provider manifest, replays the one
//! shared core transcript, and returns the ordinary fresh provider claim used
//! by the exact core-plus-N zero-sum closure.  No 445-column provider geometry
//! is imported or relabelled.

const std = @import("std");
const core_air = @import("stwo_core").air;
const core_pcs = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_verifier = @import("stwo_core").verifier;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const aggregation_hash = @import("../../aggregation/hash.zig");
const candidate_mod = @import("../../air/lang/typed_poseidon2_degree_bounded_candidate.zig");
const component_backend = @import("../../air/lang/typed_poseidon2_degree5_backend.zig");
const component_mod = @import("../../air/lang/typed_poseidon2_degree5_component.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const authority = @import("authority.zig");
const protocol = @import("ethereum_omit_protocol_v1.zig");
const omit_proof = @import("ethereum_omit_provider_proof_v1.zig");
const harness = @import("proof_harness.zig");
const proof_authority = @import("joint_proof_authority.zig");
const relation_challenges = @import("../../air/relation_challenges.zig");
const provider_order = @import("provider_order_component.zig");
const reusable = @import("joint_provider_proof_v2.zig");
const binding = @import("degree5_ethereum_omit_provider_authority_v1.zig");
const stage_a_transaction =
    @import("degree5_provider_stage_a_transaction_v1.zig");
const fresh_capture =
    @import("degree5_ethereum_omit_provider_fresh_capture_v1.zig");

pub const format_version = binding.format_version;
pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const SHARED_CORE_RELATION_CONTEXT_IMPLEMENTED = true;
pub const ORDERED_CALL_COMMITMENT_IS_AIR_PROVED = true;
pub const FRESH_FULL_CLOSURE_REQUIRED = true;
pub const coefficient_retention = harness.CoefficientRetention.always;
pub const tree_count: usize = 3;
pub const proof_commitment_count: usize = tree_count + 1;
pub const tree2_columns = binding.tree2_columns;
pub const Digest = binding.Digest;
pub const VerifierProgramAuthorityV2 = binding.VerifierProgramAuthorityV2;
pub const ExecutionProfileV1 = binding.ExecutionProfileV1;
pub const ExecutionProfileV2 = binding.ExecutionProfileV2;
pub const FreshProviderClaimV2 = binding.FreshProviderClaimV2;
pub const ProviderTree2GeometryV1 = binding.ProviderTree2GeometryV1;
pub const ProviderStatementV1 = binding.ProviderStatementV1;
pub const FreshDegree5ProviderClaimV1 = binding.FreshDegree5ProviderClaimV1;
pub const FreshStrategyV1 = binding.FreshStrategyV1;
pub const ClosedStrategyV1 = binding.ClosedStrategyV1;
pub const ReuseReceiptV1 = stage_a_transaction.ReuseReceiptV1;

pub fn PreparedStageATransactionV1(comptime Engine: type) type {
    return stage_a_transaction.PreparedStageATransactionV1(Engine);
}

pub fn Source(comptime Engine: type) type {
    return omit_proof.Source(Engine);
}

pub fn ProviderProofOutputV1(comptime Engine: type) type {
    return struct {
        statement: ProviderStatementV1,
        execution_profile_identity: Digest,
        proof: @import("stwo_core").proof.StarkProof(Engine.Hasher),
    };
}

pub const FreshDegree5ProviderCaptureV1 = fresh_capture.CaptureV1;
pub const validateFreshProviderRelationDraws =
    fresh_capture.validateRelationDraws;

/// Commits the exact 239-column Stage A used later by the shared proof.  The
/// scratch transcript cannot mint relations and coefficient retention is not
/// part of a Merkle root, so this custody pass releases coefficients eagerly.
pub fn commitStageAV1(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    shard_index: u32,
) !harness.StageACommitment(Engine) {
    var candidate = try candidate_mod.Candidate.init(allocator, .degree5);
    defer candidate.deinit();
    try expected_program.validateCandidate(&candidate);
    const shard_calls = try harness.admittedShard(plan, calls, shard_index);
    const index = std.math.cast(usize, shard_index) orelse
        return error.ShardIndexOutOfRange;
    const descriptor = plan.shards[index];

    var channel = Engine.Channel{};
    pcs_config.mixInto(&channel);
    var scheme = try Engine.init(allocator, pcs_config);
    defer Engine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(.never);
    try stage_a_transaction.commitStageAInto(
        Engine,
        allocator,
        &scheme,
        &channel,
        &candidate,
        shard_calls,
        descriptor,
    );
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 2) return error.InvalidDegree5ProviderStageATrees;
    return .{
        .preprocessed_root = roots.items[0],
        .main_root = roots.items[1],
    };
}

pub fn proveProviderV1(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: ExecutionProfileV1,
    source: Source(Engine),
    shard_index: u32,
) !ProviderProofOutputV1(Engine) {
    return proveProviderWithTranscriptV1(
        Engine,
        OrdinaryTranscriptAdapter,
        allocator,
        pcs_config,
        expected_program,
        execution_profile,
        source,
        shard_index,
    );
}

/// Additive proof engine for a transcript-compatible provider source. The
/// ordinary public entrypoint above instantiates the canonical adapter, while
/// the combined-candidate sibling supplies its larger shared replay. Component
/// geometry, proof bytes, and verifier program authority remain unchanged.
pub fn proveProviderWithTranscriptV1(
    comptime Engine: type,
    comptime TranscriptAdapter: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: ExecutionProfileV1,
    source: anytype,
    shard_index: u32,
) !ProviderProofOutputV1(Engine) {
    return proveProviderWithTranscriptInternalV1(
        Engine,
        TranscriptAdapter,
        allocator,
        pcs_config,
        expected_program,
        execution_profile,
        source,
        shard_index,
        null,
    );
}

/// Consumes the retained Stage-A scheme exactly once after revalidating its
/// live plan/call pointers and its roots against the final shared manifest.
/// The transaction itself must remain live until this function returns because
/// the prover component borrows its compiler-authenticated candidate graph.
pub fn proveProviderPreparedWithTranscriptV1(
    comptime Engine: type,
    comptime TranscriptAdapter: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: ExecutionProfileV1,
    source: anytype,
    shard_index: u32,
    prepared: *PreparedStageATransactionV1(Engine),
) !ProviderProofOutputV1(Engine) {
    return proveProviderWithTranscriptInternalV1(
        Engine,
        TranscriptAdapter,
        allocator,
        pcs_config,
        expected_program,
        execution_profile,
        source,
        shard_index,
        prepared,
    );
}

pub fn proveProviderWithTranscriptV2(
    comptime Engine: type,
    comptime TranscriptAdapter: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: ExecutionProfileV2,
    source: anytype,
    shard_index: u32,
) !ProviderProofOutputV1(Engine) {
    return proveProviderWithTranscriptInternalV1(
        Engine,
        TranscriptAdapter,
        allocator,
        pcs_config,
        expected_program,
        execution_profile,
        source,
        shard_index,
        null,
    );
}

pub fn proveProviderPreparedWithTranscriptV2(
    comptime Engine: type,
    comptime TranscriptAdapter: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: ExecutionProfileV2,
    source: anytype,
    shard_index: u32,
    prepared: *PreparedStageATransactionV1(Engine),
) !ProviderProofOutputV1(Engine) {
    return proveProviderWithTranscriptInternalV1(
        Engine,
        TranscriptAdapter,
        allocator,
        pcs_config,
        expected_program,
        execution_profile,
        source,
        shard_index,
        prepared,
    );
}

fn proveProviderWithTranscriptInternalV1(
    comptime Engine: type,
    comptime TranscriptAdapter: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: anytype,
    source: anytype,
    shard_index: u32,
    prepared: ?*PreparedStageATransactionV1(Engine),
) !ProviderProofOutputV1(Engine) {
    try source.validate();
    try execution_profile.validate(expected_program.base);
    const index = std.math.cast(usize, shard_index) orelse
        return error.ShardIndexOutOfRange;
    if (index >= source.plan.shards.len) return error.ShardIndexOutOfRange;
    const descriptor = source.plan.shards[index];
    const shard_calls = try harness.admittedShard(
        source.plan,
        source.calls,
        shard_index,
    );
    const stage_a = source.provider_stage_a.providers[index];

    var local_candidate: candidate_mod.Candidate = undefined;
    var local_candidate_live = false;
    defer if (local_candidate_live) local_candidate.deinit();
    const candidate: *candidate_mod.Candidate = if (prepared) |transaction| blk: {
        try transaction.validateBorrowed(
            expected_program,
            source.plan,
            source.calls,
            shard_index,
            stage_a.preprocessed_root,
            stage_a.main_root,
        );
        break :blk &transaction.candidate;
    } else blk: {
        local_candidate = try candidate_mod.Candidate.init(allocator, .degree5);
        local_candidate_live = true;
        try expected_program.validateCandidate(&local_candidate);
        break :blk &local_candidate;
    };
    const replay = try TranscriptAdapter.replayShared(
        Engine,
        allocator,
        pcs_config,
        source,
    );

    var scheme = if (prepared) |transaction|
        try transaction.takeScheme(
            expected_program,
            source.plan,
            source.calls,
            shard_index,
            stage_a.preprocessed_root,
            stage_a.main_root,
        )
    else
        try Engine.init(allocator, pcs_config);
    var scheme_owned = true;
    errdefer if (scheme_owned) Engine.deinit(&scheme, allocator);
    if (prepared == null) {
        scheme.setCoefficientRetentionPolicy(.always);
        var scratch = Engine.Channel{};
        try stage_a_transaction.commitStageAInto(
            Engine,
            allocator,
            &scheme,
            &scratch,
            candidate,
            shard_calls,
            descriptor,
        );
        try Engine.flushPendingCommit(&scheme, allocator, &scratch);
        try reusable.requireStageARoots(
            Engine,
            allocator,
            &scheme,
            stage_a.preprocessed_root,
            stage_a.main_root,
        );
    }

    var interaction = try poseidon2_air.generateInteraction(
        allocator,
        shard_calls,
        descriptor.expected_log_size,
        &replay.relations.base,
    );
    var interaction_owned = true;
    defer if (interaction_owned) interaction.deinit(allocator);
    var ordered = try provider_order.generateInteraction(
        allocator,
        descriptor.first_call,
        shard_calls,
        descriptor.expected_log_size,
        &replay.relations.base,
    );
    var ordered_owned = true;
    defer if (ordered_owned) ordered.deinit(allocator);
    const native_claim = authority.ProviderShardClaimV1{
        .plan_identity = source.plan.identity,
        .descriptor_identity = descriptor.identity,
        .shard_index = shard_index,
        .relation_context_identity = source.shared.relation_context.identity,
        .claims = interaction.claims,
    };
    var statement = ProviderStatementV1{
        .format = format_version,
        .air_program_identity = expected_program.air_program_identity,
        .plan_identity = source.plan.identity,
        .manifest_identity = source.provider_stage_a.identity,
        .stage_a_identity = source.provider_stage_a.providers[index].identity,
        .descriptor_identity = descriptor.identity,
        .relation_context_identity = source.shared.relation_context.identity,
        .call_list_commitment = source.plan.call_list_commitment,
        .shard_index = shard_index,
        .first_call = descriptor.first_call,
        .call_count = descriptor.call_count,
        .log_size = descriptor.expected_log_size,
        .geometry = try ProviderTree2GeometryV1.canonical(
            descriptor.expected_log_size,
        ),
        .claims = interaction.claims,
        .ordered_call_claim = ordered.claim,
        .identity = undefined,
    };
    statement.identity = binding.statementIdentity(statement);
    var channel = try TranscriptAdapter.providerLocalPrefix(
        Engine,
        allocator,
        pcs_config,
        source,
        native_claim,
        statement.ordered_call_claim,
    );
    finishLocalPrefix(&channel, expected_program, statement);
    const columns = try reusable.mergeInteractionColumns(
        allocator,
        descriptor.expected_log_size,
        &interaction,
        &ordered,
    );
    interaction_owned = false;
    ordered_owned = false;
    try Engine.commit(&scheme, allocator, columns, null, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);

    const component = try component_mod.Component.init(
        candidate,
        descriptor.expected_log_size,
        descriptor.call_count,
        0,
        1,
        0,
        0,
        &replay.relations.base,
        statement.claims.sums,
    );
    const order_component = try provider_order.ProviderOrderComponent.initProjected(
        descriptor.expected_log_size,
        descriptor.call_count,
        descriptor.first_call,
        0,
        1,
        0,
        component_mod.MAIN_COLUMNS,
        expected_program.selected_main_columns,
        expected_program.order_composition_log_split,
        component_mod.INTERACTION_COLUMNS,
        &replay.relations.base,
        statement.ordered_call_claim,
    );
    const components = [_]@import("stwo_prover_engine").air.component_prover.ComponentProver{
        component_backend.asProverComponent(&component),
        order_component.asProverComponent(),
    };
    const workers = std.math.cast(
        usize,
        execution_profile.composition_workers_per_provider,
    ) orelse return error.InvalidDegree5ExecutionProfile;
    const host_budget = std.math.cast(
        usize,
        execution_profile.composition_host_byte_budget,
    ) orelse return error.InvalidDegree5ExecutionProfile;
    scheme_owned = false;
    var extended = try Engine.prove(
        allocator,
        &components,
        &channel,
        scheme,
        .{ .cpu_composition_execution = .{
            .worker_count = workers,
            .host_byte_budget = host_budget,
            .contention_policy = .strict,
        } },
    );
    const proof = extended.proof;
    extended.aux.deinit(allocator);
    return .{
        .statement = statement,
        .execution_profile_identity = execution_profile.identity,
        .proof = proof,
    };
}

pub fn verifyProviderFreshV1(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    expected_execution_profile: ExecutionProfileV1,
    source: Source(Engine),
    statement: ProviderStatementV1,
    proof_in: @import("stwo_core").proof.StarkProof(Engine.Hasher),
) !FreshDegree5ProviderClaimV1 {
    return verifyProviderFreshWithTranscriptInternalV1(
        Engine,
        OrdinaryTranscriptAdapter,
        allocator,
        pcs_config,
        expected_program,
        expected_execution_profile,
        source,
        statement,
        proof_in,
        null,
    );
}

pub fn verifyProviderFreshWithCaptureV1(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    expected_execution_profile: ExecutionProfileV1,
    source: Source(Engine),
    statement: ProviderStatementV1,
    proof_in: @import("stwo_core").proof.StarkProof(Engine.Hasher),
    capture_out: *FreshDegree5ProviderCaptureV1(Engine),
) !FreshDegree5ProviderClaimV1 {
    return verifyProviderFreshWithTranscriptInternalV1(
        Engine,
        OrdinaryTranscriptAdapter,
        allocator,
        pcs_config,
        expected_program,
        expected_execution_profile,
        source,
        statement,
        proof_in,
        capture_out,
    );
}

pub fn verifyProviderFreshWithTranscriptV1(
    comptime Engine: type,
    comptime TranscriptAdapter: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    expected_execution_profile: ExecutionProfileV1,
    source: anytype,
    statement: ProviderStatementV1,
    proof_in: @import("stwo_core").proof.StarkProof(Engine.Hasher),
) !FreshDegree5ProviderClaimV1 {
    return verifyProviderFreshWithTranscriptInternalV1(
        Engine,
        TranscriptAdapter,
        allocator,
        pcs_config,
        expected_program,
        expected_execution_profile,
        source,
        statement,
        proof_in,
        null,
    );
}

pub fn verifyProviderFreshWithTranscriptV2(
    comptime Engine: type,
    comptime TranscriptAdapter: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    expected_execution_profile: ExecutionProfileV2,
    source: anytype,
    statement: ProviderStatementV1,
    proof_in: @import("stwo_core").proof.StarkProof(Engine.Hasher),
) !FreshDegree5ProviderClaimV1 {
    return verifyProviderFreshWithTranscriptInternalV1(
        Engine,
        TranscriptAdapter,
        allocator,
        pcs_config,
        expected_program,
        expected_execution_profile,
        source,
        statement,
        proof_in,
        null,
    );
}

fn verifyProviderFreshWithTranscriptInternalV1(
    comptime Engine: type,
    comptime TranscriptAdapter: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    expected_execution_profile: anytype,
    source: anytype,
    statement: ProviderStatementV1,
    proof_in: @import("stwo_core").proof.StarkProof(Engine.Hasher),
    capture_out: ?*FreshDegree5ProviderCaptureV1(Engine),
) !FreshDegree5ProviderClaimV1 {
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    var candidate = try candidate_mod.Candidate.init(allocator, .degree5);
    defer candidate.deinit();
    try expected_program.validateCandidate(&candidate);
    try expected_execution_profile.validate(expected_program.base);
    try validateStatement(source, expected_program, statement);
    const index: usize = @intCast(statement.shard_index);
    const descriptor = source.plan.shards[index];
    const shard_calls = try harness.admittedShard(
        source.plan,
        source.calls,
        statement.shard_index,
    );
    const commitments = proof.commitment_scheme_proof.commitments.items;
    if (commitments.len != proof_commitment_count)
        return core_verifier.VerificationError.InvalidStructure;
    if (!std.meta.eql(
        commitments[0],
        source.provider_stage_a.providers[index].preprocessed_root,
    ) or !std.meta.eql(
        commitments[1],
        source.provider_stage_a.providers[index].main_root,
    )) return error.ProviderStageARootMismatch;
    const commitments_identity = proof_authority.commitmentsIdentity(
        Engine,
        commitments,
    );
    try harness.verifyPreprocessedRoot(
        Engine,
        allocator,
        pcs_config,
        statement.log_size,
        statement.call_count,
        commitments[0],
    );
    const replay = try TranscriptAdapter.replayShared(
        Engine,
        allocator,
        pcs_config,
        source,
    );
    const expected_order = try provider_order.expectedClaim(
        descriptor.first_call,
        shard_calls,
        &replay.relations.base,
    );
    if (!std.meta.eql(expected_order, statement.ordered_call_claim))
        return error.ProviderOrderClaimMismatch;

    var scheme = try pcs_verifier.CommitmentSchemeVerifier(
        Engine.Hasher,
        Engine.MerkleChannel,
    ).init(allocator, pcs_config);
    defer scheme.deinit(allocator);
    var scratch = Engine.Channel{};
    try scheme.commit(
        allocator,
        commitments[0],
        &[_]u32{ statement.log_size, statement.log_size },
        &scratch,
    );
    try scheme.commit(
        allocator,
        commitments[1],
        &([_]u32{statement.log_size} ** component_mod.MAIN_COLUMNS),
        &scratch,
    );
    const native_claim = authority.ProviderShardClaimV1{
        .plan_identity = source.plan.identity,
        .descriptor_identity = descriptor.identity,
        .shard_index = statement.shard_index,
        .relation_context_identity = source.shared.relation_context.identity,
        .claims = statement.claims,
    };
    var channel = try TranscriptAdapter.providerLocalPrefix(
        Engine,
        allocator,
        pcs_config,
        source,
        native_claim,
        statement.ordered_call_claim,
    );
    finishLocalPrefix(&channel, expected_program, statement);
    try scheme.commit(
        allocator,
        commitments[2],
        &([_]u32{statement.log_size} ** tree2_columns),
        &channel,
    );
    const component = try component_mod.Component.init(
        &candidate,
        statement.log_size,
        statement.call_count,
        0,
        1,
        0,
        0,
        &replay.relations.base,
        statement.claims.sums,
    );
    const order_component = try provider_order.ProviderOrderComponent.initProjected(
        statement.log_size,
        statement.call_count,
        statement.first_call,
        0,
        1,
        0,
        component_mod.MAIN_COLUMNS,
        expected_program.selected_main_columns,
        expected_program.order_composition_log_split,
        component_mod.INTERACTION_COLUMNS,
        &replay.relations.base,
        statement.ordered_call_claim,
    );
    const components = [_]core_air.components.Component{
        component.asVerifierComponent(),
        order_component.asVerifierComponent(),
    };
    var proof_capture: core_verifier.ProofCapture(Engine.Hasher) = undefined;
    var proof_capture_owned = false;
    defer if (proof_capture_owned) proof_capture.deinit(allocator);
    proof_moved = true;
    if (capture_out != null) {
        try core_verifier.verifyWithProofCapture(
            Engine.Hasher,
            Engine.MerkleChannel,
            allocator,
            &components,
            &channel,
            &scheme,
            proof,
            &proof_capture,
        );
        proof_capture_owned = true;
    } else {
        try core_verifier.verify(
            Engine.Hasher,
            Engine.MerkleChannel,
            allocator,
            &components,
            &channel,
            &scheme,
            proof,
        );
    }
    var provider = FreshProviderClaimV2{
        .format = proof_authority.provider_format_version_v2,
        .manifest_identity = source.provider_stage_a.identity,
        .statement_identity = statement.identity,
        .proof_commitments_identity = commitments_identity,
        .fresh_provider_stark_verified = true,
        .ordered_call_air_verified = true,
        .ordered_call_claim_recomputed = true,
        .native_claim = native_claim,
        .ordered_call_claim = statement.ordered_call_claim,
        .identity = undefined,
    };
    provider.identity = proof_authority.providerClaimIdentityV2(provider);
    try provider.validate();
    var result = FreshDegree5ProviderClaimV1{
        .format = format_version,
        .air_program_identity = expected_program.air_program_identity,
        .execution_profile_identity = expected_execution_profile.identity,
        .relation_context_identity = source.shared.relation_context.identity,
        .provider = provider,
        .shared_core_relation_context_verified = true,
        .global_degree5_domain_verified = true,
        .identity = undefined,
    };
    result.identity = binding.freshClaimIdentity(result);
    try result.validate();
    if (capture_out) |destination| {
        var relation_draws: [relation_challenges.DRAW_COUNT]QM31 = undefined;
        try replay.relations.base.writeDraws(&relation_draws);
        const capture = try fresh_capture.init(
            Engine,
            proof_capture,
            relation_draws,
            statement,
            result,
            expected_program,
            expected_execution_profile,
        );
        destination.* = capture;
        proof_capture_owned = false;
    }
    return result;
}

pub fn closeFreshClaimsV1(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: ExecutionProfileV1,
    source: Source(Engine),
    core: protocol.FreshCoreResidualV1,
    providers: []const FreshDegree5ProviderClaimV1,
) !ClosedStrategyV1 {
    return closeFreshClaimsInternal(
        Engine,
        allocator,
        expected_program,
        execution_profile,
        source,
        core,
        providers,
    );
}

pub fn closeFreshClaimsV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: ExecutionProfileV2,
    source: Source(Engine),
    core: protocol.FreshCoreResidualV1,
    providers: []const FreshDegree5ProviderClaimV1,
) !ClosedStrategyV1 {
    return closeFreshClaimsInternal(
        Engine,
        allocator,
        expected_program,
        execution_profile,
        source,
        core,
        providers,
    );
}

fn closeFreshClaimsInternal(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: anytype,
    source: Source(Engine),
    core: protocol.FreshCoreResidualV1,
    providers: []const FreshDegree5ProviderClaimV1,
) !ClosedStrategyV1 {
    try expected_program.validateCold(allocator);
    try execution_profile.validate(expected_program.base);
    if (providers.len != source.plan.shards.len)
        return error.InvalidDegree5EthereumProviderClaimCount;
    const native = try allocator.alloc(FreshProviderClaimV2, providers.len);
    defer allocator.free(native);
    for (providers, native, 0..) |provider, *claim, index| {
        try provider.validate();
        if (!aggregation_hash.eql(
            provider.air_program_identity,
            expected_program.air_program_identity,
        ) or !aggregation_hash.eql(
            provider.execution_profile_identity,
            execution_profile.identity,
        ) or !aggregation_hash.eql(
            provider.relation_context_identity,
            source.shared.relation_context.identity,
        ) or provider.provider.native_claim.shard_index != index) {
            return error.NonCanonicalDegree5EthereumProviderClaim;
        }
        claim.* = provider.provider;
    }
    const closure = try omit_proof.closeFreshClaimsV1(
        allocator,
        source,
        core,
        native,
    );
    const preprocessed_identity = binding.preprocessedCommitmentIdentity(
        Engine,
        expected_program,
        source.provider_stage_a,
    );
    var strategy = FreshStrategyV1{
        .format = format_version,
        .air_program_identity = expected_program.air_program_identity,
        .execution_profile_identity = execution_profile.identity,
        .plan_identity = source.plan.identity,
        .manifest_identity = source.provider_stage_a.identity,
        .preprocessed_commitment_identity = preprocessed_identity,
        .relation_context_identity = source.shared.relation_context.identity,
        .closure_identity = closure.identity,
        .ordered_provider_claims_identity = closure.ordered_provider_claims_identity,
        .shard_count = closure.shard_count,
        .every_provider_degree5_fresh_verified = true,
        .shared_core_zero_sum_verified = closure.closed_sum.isZero(),
        .production_eligible = false,
        .identity = undefined,
    };
    strategy.identity = binding.strategyIdentity(strategy);
    try strategy.validate();
    return .{ .closure = closure, .strategy = strategy };
}

fn replaySharedOrdinary(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    source: Source(Engine),
) !protocol.Replay(Engine) {
    return protocol.replaySharedTranscript(
        Engine,
        allocator,
        pcs_config,
        source.native,
        source.extension,
        source.lookup_manifest,
        source.authenticated_lookup,
        source.projection,
        source.plan,
        source.calls,
        source.provider_stage_a,
        source.shared,
    );
}

fn providerLocalPrefixOrdinary(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    source: Source(Engine),
    claim: authority.ProviderShardClaimV1,
    ordered: provider_order.ClaimV1,
) !Engine.Channel {
    return protocol.providerLocalPrefixV2(
        Engine,
        allocator,
        pcs_config,
        source.native,
        source.extension,
        source.lookup_manifest,
        source.authenticated_lookup,
        source.projection,
        source.plan,
        source.calls,
        source.provider_stage_a,
        source.shared,
        claim,
        ordered,
    );
}

const OrdinaryTranscriptAdapter = struct {
    pub fn replayShared(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: core_pcs.PcsConfig,
        source: Source(Engine),
    ) !protocol.Replay(Engine) {
        return replaySharedOrdinary(Engine, allocator, pcs_config, source);
    }

    pub fn providerLocalPrefix(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: core_pcs.PcsConfig,
        source: Source(Engine),
        claim: authority.ProviderShardClaimV1,
        ordered: provider_order.ClaimV1,
    ) !Engine.Channel {
        return providerLocalPrefixOrdinary(
            Engine,
            allocator,
            pcs_config,
            source,
            claim,
            ordered,
        );
    }
};

fn finishLocalPrefix(
    channel: anytype,
    program: VerifierProgramAuthorityV2,
    statement: ProviderStatementV1,
) void {
    channel.mixU32s(&strategy_domain);
    mixDigest(channel, program.air_program_identity);
    mixDigest(channel, statement.identity);
}

fn validateStatement(
    source: anytype,
    program: VerifierProgramAuthorityV2,
    value: ProviderStatementV1,
) !void {
    try source.validate();
    const index = std.math.cast(usize, value.shard_index) orelse
        return error.ShardIndexOutOfRange;
    if (index >= source.plan.shards.len) return error.ShardIndexOutOfRange;
    const descriptor = source.plan.shards[index];
    const geometry = try ProviderTree2GeometryV1.canonical(
        descriptor.expected_log_size,
    );
    if (value.format != format_version or
        !aggregation_hash.eql(
            value.air_program_identity,
            program.air_program_identity,
        ) or !aggregation_hash.eql(value.plan_identity, source.plan.identity) or
        !aggregation_hash.eql(
            value.manifest_identity,
            source.provider_stage_a.identity,
        ) or !aggregation_hash.eql(
        value.stage_a_identity,
        source.provider_stage_a.providers[index].identity,
    ) or !aggregation_hash.eql(value.descriptor_identity, descriptor.identity) or
        !aggregation_hash.eql(
            value.relation_context_identity,
            source.shared.relation_context.identity,
        ) or !aggregation_hash.eql(
        value.call_list_commitment,
        source.plan.call_list_commitment,
    ) or value.shard_index != descriptor.shard_index or
        value.first_call != descriptor.first_call or
        value.call_count != descriptor.call_count or
        value.log_size != descriptor.expected_log_size or
        !std.meta.eql(value.geometry, geometry) or
        value.ordered_call_claim.format != provider_order.format_version or
        value.ordered_call_claim.first_call != descriptor.first_call or
        value.ordered_call_claim.call_count != descriptor.call_count or
        !aggregation_hash.eql(value.identity, binding.statementIdentity(value)))
    {
        return error.InvalidDegree5EthereumProviderStatement;
    }
}

fn mixDigest(channel: anytype, value: Digest) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index|
        word.* = std.mem.readInt(u32, value[index * 4 ..][0..4], .little);
    channel.mixU32s(&words);
}

pub const verifierProgramAuthoritySha256 =
    fresh_capture.verifierProgramAuthoritySha256;
pub const executionProfileSha256 = fresh_capture.executionProfileSha256;
pub const commitmentsSha256 = fresh_capture.commitmentsSha256;

const strategy_domain = [8]u32{
    0x5354_5742, // STWB
    0x4535_4f50, // E5OP
    format_version,
    component_mod.MAIN_COLUMNS,
    tree2_columns,
    component_mod.COMPOSITION_LOG_SPLIT,
    provider_order.constraint_count,
    @intFromBool(ACTIVATES_PRODUCTION_PROOF),
};

comptime {
    if (component_mod.MAIN_COLUMNS != 239 or
        component_mod.INTERACTION_COLUMNS != poseidon2_air.N_INTERACTION_COLUMNS or
        tree2_columns != 12 or provider_order.selected_main_count != 17 or
        provider_order.constraint_count != 4 or
        component_mod.COMPOSITION_LOG_SPLIT != 2 or
        coefficient_retention != .always or ACTIVATES_PRODUCTION_PROOF or
        !SHARED_CORE_RELATION_CONTEXT_IMPLEMENTED or
        !ORDERED_CALL_COMMITMENT_IS_AIR_PROVED or !FRESH_FULL_CLOSURE_REQUIRED)
    {
        @compileError("Ethereum shared-context degree-five provider drifted");
    }
}
