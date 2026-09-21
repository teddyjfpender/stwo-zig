//! Freshly verified caller+N proof protocol for base narrow-memory Poseidon.
//!
//! All Tree0/Tree1 roots enter one ordered Stage-A manifest before one shared
//! interaction PoW and relation draw.  The base Merkle caller and every
//! provider shard then commit Tree2 under role-local suffixes of that common
//! prefix.  Fresh verification mints the only claims accepted by the final
//! exact closure.
//!
//! This remains non-production: the tiny caller proves the real Merkle AIR and
//! an externalization shell, but the ordered call-list commitment is transcript
//! custody rather than an AIR/public-statement commitment, and the full RISC-V
//! component set and recursive verifier do not yet admit this split.

const std = @import("std");
const core_air = @import("stwo_core").air;
const core_pcs = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_verifier = @import("stwo_core").verifier;
const aggregation_hash = @import("../../aggregation/hash.zig");
const hash_component = @import("../../air/memory_commitment/hash_component.zig");
const merkle_node = @import("../../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const authority = @import("authority.zig");
const harness = @import("proof_harness.zig");
const joint = @import("joint_protocol.zig");
const proof_authority = @import("joint_proof_authority.zig");
const standalone = @import("standalone_component.zig");

pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const FRESH_CORE_VERIFICATION_MINTS_RESIDUAL = true;
pub const ALL_NON_POSEIDON_BUSES_CLOSE = true;
pub const JOINT_STAGE_A_PREFIX_ADOPTED = true;
pub const ONE_SHARED_INTERACTION_POW = true;
pub const EVERY_PROVIDER_SHARD_FRESHLY_VERIFIED = true;
pub const ORDERED_CALL_RANGES_ARE_CUSTODY_ONLY = true;
pub const ORDERED_CALL_COMMITMENT_IS_AIR_PROVED = false;
pub const FULL_RISCV_CORE_EXTERNALIZED = false;
pub const RECURSIVE_VERIFICATION_IMPLEMENTED = false;

pub const format_version = proof_authority.format_version;
pub const tree_count: usize = 3;
pub const proof_commitment_count: usize = tree_count + 1;

pub const CoreResidencyGeometryV1 = proof_authority.CoreResidencyGeometryV1;
pub const CoreStatementV1 = proof_authority.CoreStatementV1;
pub const ProviderStatementV1 = proof_authority.ProviderStatementV1;

pub fn CoreProofOutput(comptime Engine: type) type {
    return struct {
        statement: CoreStatementV1,
        proof: @import("stwo_core").proof.StarkProof(Engine.Hasher),
    };
}

pub fn ProviderProofOutput(comptime Engine: type) type {
    return struct {
        statement: ProviderStatementV1,
        proof: @import("stwo_core").proof.StarkProof(Engine.Hasher),
    };
}

pub const CoreWithoutProviderClaimV1 = proof_authority.CoreWithoutProviderClaimV1;
pub const FreshProviderClaimV1 = proof_authority.FreshProviderClaimV1;
pub const VerifiedJointClosureV1 = proof_authority.VerifiedJointClosureV1;

/// Commits the real base Merkle caller before the shared draw.  Canonical test
/// rows intentionally carry zero Merkle multiplicities; the proof shell below
/// enforces those zeros rather than trusting this materializer.
pub fn commitCoreStageA(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
) !harness.StageACommitment(Engine) {
    try plan.validate(calls);
    const rows = try coreRows(allocator, calls);
    defer allocator.free(rows);
    const geometry = try CoreResidencyGeometryV1.canonical(
        expectedLogSize(calls.len),
        @intCast(calls.len),
    );
    var scheme = try Engine.init(allocator, pcs_config);
    defer Engine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(.never);
    var scratch = Engine.Channel{};
    try commitCoreStageAInto(
        Engine,
        allocator,
        &scheme,
        &scratch,
        rows,
        geometry,
    );
    try Engine.flushPendingCommit(&scheme, allocator, &scratch);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 2) return error.InvalidCoreStageATreeCount;
    return .{
        .preprocessed_root = roots.items[0],
        .main_root = roots.items[1],
    };
}

pub fn proveCore(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    manifest: *const joint.JointManifest(Engine),
    shared: joint.SharedRelationAuthorityV1,
) !CoreProofOutput(Engine) {
    try manifest.validate(plan, calls);
    const replay = try joint.replaySharedTranscript(
        Engine,
        allocator,
        pcs_config,
        plan,
        calls,
        manifest,
        shared,
    );
    const rows = try coreRows(allocator, calls);
    defer allocator.free(rows);
    const geometry = try CoreResidencyGeometryV1.canonical(
        manifest.core.log_size,
        manifest.core.n_rows,
    );

    var scheme = try Engine.init(allocator, pcs_config);
    var scheme_owned = true;
    errdefer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(.never);
    var scratch = Engine.Channel{};
    try commitCoreStageAInto(
        Engine,
        allocator,
        &scheme,
        &scratch,
        rows,
        geometry,
    );
    try Engine.flushPendingCommit(&scheme, allocator, &scratch);
    try requireStageARoots(
        Engine,
        allocator,
        &scheme,
        manifest.core.preprocessed_root,
        manifest.core.main_root,
    );

    var interaction = try merkle_node.generateInteraction(
        allocator,
        rows,
        geometry.log_size,
        &replay.relations,
    );
    var interaction_owned = true;
    defer if (interaction_owned) interaction.deinit(allocator);
    if (!interaction.claims.sums[0].isZero())
        return error.NonPoseidonCallerRelationNotClosed;
    var statement = CoreStatementV1{
        .format = format_version,
        .plan_identity = plan.identity,
        .manifest_identity = manifest.identity,
        .core_stage_a_identity = manifest.core.identity,
        .relation_context_identity = shared.relation_context.identity,
        .call_list_commitment = plan.call_list_commitment,
        .geometry = geometry,
        .claims = interaction.claims,
        .identity = undefined,
    };
    statement.identity = proof_authority.coreStatementIdentity(statement);
    var channel = try joint.coreLocalPrefix(
        Engine,
        allocator,
        pcs_config,
        plan,
        calls,
        manifest,
        shared,
        statement.claims,
    );
    const columns = try harness.takeColumns(
        merkle_node.N_INTERACTION_COLUMNS,
        allocator,
        &interaction.columns,
        geometry.log_size,
    );
    interaction_owned = false;
    try Engine.commit(&scheme, allocator, columns, null, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);

    const component = externalizedMerkleComponent(
        geometry,
        &replay.relations,
        statement.claims,
    );
    var lifted = standalone.Prover{ .inner = component.asProverComponent() };
    const components = [_]@import("stwo_prover_engine").air.component_prover.ComponentProver{
        lifted.asComponent(),
    };
    scheme_owned = false;
    var extended = try Engine.prove(
        allocator,
        &components,
        &channel,
        scheme,
        .{},
    );
    const proof = extended.proof;
    extended.aux.deinit(allocator);
    return .{ .statement = statement, .proof = proof };
}

/// The only minting path for `CoreWithoutProviderClaimV1` consumes and freshly
/// verifies the complete caller proof before publishing its exact residual.
pub fn verifyCoreFresh(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    manifest: *const joint.JointManifest(Engine),
    shared: joint.SharedRelationAuthorityV1,
    statement: CoreStatementV1,
    proof_in: @import("stwo_core").proof.StarkProof(Engine.Hasher),
) !CoreWithoutProviderClaimV1 {
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    try validateCoreStatement(plan, calls, manifest, shared, statement);
    const commitments = proof.commitment_scheme_proof.commitments.items;
    if (commitments.len != proof_commitment_count)
        return core_verifier.VerificationError.InvalidStructure;
    if (!std.meta.eql(commitments[0], manifest.core.preprocessed_root) or
        !std.meta.eql(commitments[1], manifest.core.main_root))
    {
        return error.CoreStageARootMismatch;
    }
    const commitments_identity = proof_authority.commitmentsIdentity(Engine, commitments);
    try verifyCorePreprocessedRoot(
        Engine,
        allocator,
        pcs_config,
        statement.geometry,
        commitments[0],
    );
    const replay = try joint.replaySharedTranscript(
        Engine,
        allocator,
        pcs_config,
        plan,
        calls,
        manifest,
        shared,
    );
    var scheme = try pcs_verifier.CommitmentSchemeVerifier(
        Engine.Hasher,
        Engine.MerkleChannel,
    ).init(allocator, pcs_config);
    defer scheme.deinit(allocator);
    var scratch = Engine.Channel{};
    try scheme.commit(allocator, commitments[0], &([_]u32{statement.geometry.log_size} ** 2), &scratch);
    try scheme.commit(
        allocator,
        commitments[1],
        &([_]u32{statement.geometry.log_size} ** merkle_node.N_MAIN_COLUMNS),
        &scratch,
    );
    var channel = try joint.coreLocalPrefix(
        Engine,
        allocator,
        pcs_config,
        plan,
        calls,
        manifest,
        shared,
        statement.claims,
    );
    try scheme.commit(
        allocator,
        commitments[2],
        &([_]u32{statement.geometry.log_size} ** merkle_node.N_INTERACTION_COLUMNS),
        &channel,
    );
    const component = externalizedMerkleComponent(
        statement.geometry,
        &replay.relations,
        statement.claims,
    );
    var lifted = standalone.Verifier{ .inner = component.asVerifierComponent() };
    const components = [_]core_air.components.Component{lifted.asComponent()};
    proof_moved = true;
    try core_verifier.verify(
        Engine.Hasher,
        Engine.MerkleChannel,
        allocator,
        &components,
        &channel,
        &scheme,
        proof,
    );
    if (!statement.claims.sums[0].isZero())
        return error.NonPoseidonCallerRelationNotClosed;
    var result = CoreWithoutProviderClaimV1{
        .format = format_version,
        .plan_identity = plan.identity,
        .manifest_identity = manifest.identity,
        .statement_identity = statement.identity,
        .relation_context_identity = shared.relation_context.identity,
        .proof_commitments_identity = commitments_identity,
        .fresh_core_stark_verified = true,
        .non_poseidon_buses_closed = true,
        .poseidon2_residual = statement.claims.sums[1].add(statement.claims.sums[2]),
        .identity = undefined,
    };
    result.identity = proof_authority.coreClaimIdentity(result);
    try result.validate();
    return result;
}

pub fn proveProvider(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    manifest: *const joint.JointManifest(Engine),
    shared: joint.SharedRelationAuthorityV1,
    shard_index: u32,
) !ProviderProofOutput(Engine) {
    try manifest.validate(plan, calls);
    const index: usize = @intCast(shard_index);
    if (index >= plan.shards.len) return error.ShardIndexOutOfRange;
    const descriptor = plan.shards[index];
    const shard_calls = try harness.admittedShard(plan, calls, shard_index);
    const replay = try joint.replaySharedTranscript(
        Engine,
        allocator,
        pcs_config,
        plan,
        calls,
        manifest,
        shared,
    );
    var scheme = try Engine.init(allocator, pcs_config);
    var scheme_owned = true;
    errdefer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(.never);
    var scratch = Engine.Channel{};
    try commitProviderStageAInto(
        Engine,
        allocator,
        &scheme,
        &scratch,
        shard_calls,
        descriptor,
    );
    try Engine.flushPendingCommit(&scheme, allocator, &scratch);
    try requireStageARoots(
        Engine,
        allocator,
        &scheme,
        manifest.providers[index].preprocessed_root,
        manifest.providers[index].main_root,
    );
    var interaction = try poseidon2_air.generateInteraction(
        allocator,
        shard_calls,
        descriptor.expected_log_size,
        &replay.relations,
    );
    var interaction_owned = true;
    defer if (interaction_owned) interaction.deinit(allocator);
    const native_claim = authority.ProviderShardClaimV1{
        .plan_identity = plan.identity,
        .descriptor_identity = descriptor.identity,
        .shard_index = shard_index,
        .relation_context_identity = shared.relation_context.identity,
        .claims = interaction.claims,
    };
    var statement = ProviderStatementV1{
        .format = format_version,
        .plan_identity = plan.identity,
        .manifest_identity = manifest.identity,
        .stage_a_identity = manifest.providers[index].identity,
        .descriptor_identity = descriptor.identity,
        .relation_context_identity = shared.relation_context.identity,
        .shard_index = shard_index,
        .first_call = descriptor.first_call,
        .call_count = descriptor.call_count,
        .log_size = descriptor.expected_log_size,
        .claims = interaction.claims,
        .identity = undefined,
    };
    statement.identity = proof_authority.providerStatementIdentity(statement);
    var channel = try joint.providerLocalPrefix(
        Engine,
        allocator,
        pcs_config,
        plan,
        calls,
        manifest,
        shared,
        native_claim,
    );
    const columns = try harness.takeColumns(
        poseidon2_air.N_INTERACTION_COLUMNS,
        allocator,
        &interaction.columns,
        descriptor.expected_log_size,
    );
    interaction_owned = false;
    try Engine.commit(&scheme, allocator, columns, null, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    const component = providerComponent(descriptor, &replay.relations, statement.claims);
    var lifted = standalone.Prover{ .inner = component.asProverComponent() };
    const components = [_]@import("stwo_prover_engine").air.component_prover.ComponentProver{
        lifted.asComponent(),
    };
    scheme_owned = false;
    var extended = try Engine.prove(allocator, &components, &channel, scheme, .{});
    const proof = extended.proof;
    extended.aux.deinit(allocator);
    return .{ .statement = statement, .proof = proof };
}

pub fn verifyProviderFresh(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    manifest: *const joint.JointManifest(Engine),
    shared: joint.SharedRelationAuthorityV1,
    statement: ProviderStatementV1,
    proof_in: @import("stwo_core").proof.StarkProof(Engine.Hasher),
) !FreshProviderClaimV1 {
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    try validateProviderStatement(plan, calls, manifest, shared, statement);
    const index: usize = @intCast(statement.shard_index);
    const descriptor = plan.shards[index];
    const commitments = proof.commitment_scheme_proof.commitments.items;
    if (commitments.len != proof_commitment_count)
        return core_verifier.VerificationError.InvalidStructure;
    if (!std.meta.eql(commitments[0], manifest.providers[index].preprocessed_root) or
        !std.meta.eql(commitments[1], manifest.providers[index].main_root))
    {
        return error.ProviderStageARootMismatch;
    }
    const commitments_identity = proof_authority.commitmentsIdentity(Engine, commitments);
    try harness.verifyPreprocessedRoot(
        Engine,
        allocator,
        pcs_config,
        statement.log_size,
        statement.call_count,
        commitments[0],
    );
    const replay = try joint.replaySharedTranscript(
        Engine,
        allocator,
        pcs_config,
        plan,
        calls,
        manifest,
        shared,
    );
    var scheme = try pcs_verifier.CommitmentSchemeVerifier(
        Engine.Hasher,
        Engine.MerkleChannel,
    ).init(allocator, pcs_config);
    defer scheme.deinit(allocator);
    var scratch = Engine.Channel{};
    try scheme.commit(allocator, commitments[0], &([_]u32{statement.log_size} ** 2), &scratch);
    try scheme.commit(
        allocator,
        commitments[1],
        &([_]u32{statement.log_size} ** poseidon2_air.N_MAIN_COLUMNS),
        &scratch,
    );
    const native_claim = authority.ProviderShardClaimV1{
        .plan_identity = plan.identity,
        .descriptor_identity = descriptor.identity,
        .shard_index = statement.shard_index,
        .relation_context_identity = shared.relation_context.identity,
        .claims = statement.claims,
    };
    var channel = try joint.providerLocalPrefix(
        Engine,
        allocator,
        pcs_config,
        plan,
        calls,
        manifest,
        shared,
        native_claim,
    );
    try scheme.commit(
        allocator,
        commitments[2],
        &([_]u32{statement.log_size} ** poseidon2_air.N_INTERACTION_COLUMNS),
        &channel,
    );
    const component = providerComponent(descriptor, &replay.relations, statement.claims);
    var lifted = standalone.Verifier{ .inner = component.asVerifierComponent() };
    const components = [_]core_air.components.Component{lifted.asComponent()};
    proof_moved = true;
    try core_verifier.verify(
        Engine.Hasher,
        Engine.MerkleChannel,
        allocator,
        &components,
        &channel,
        &scheme,
        proof,
    );
    var result = FreshProviderClaimV1{
        .format = format_version,
        .manifest_identity = manifest.identity,
        .statement_identity = statement.identity,
        .proof_commitments_identity = commitments_identity,
        .fresh_provider_stark_verified = true,
        .native_claim = native_claim,
        .identity = undefined,
    };
    result.identity = proof_authority.providerClaimIdentity(result);
    try result.validate();
    return result;
}

pub fn closeFreshClaims(
    allocator: std.mem.Allocator,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    manifest_identity: authority.Digest,
    relation: authority.PoseidonRelationContextV1,
    core: CoreWithoutProviderClaimV1,
    providers: []const FreshProviderClaimV1,
) !VerifiedJointClosureV1 {
    try core.validate();
    if (!aggregation_hash.eql(core.manifest_identity, manifest_identity))
        return error.JointManifestIdentityMismatch;
    const native = try allocator.alloc(
        authority.ProviderShardClaimV1,
        providers.len,
    );
    defer allocator.free(native);
    for (providers, native, 0..) |receipt, *claim, index| {
        try receipt.validate();
        if (!aggregation_hash.eql(receipt.manifest_identity, manifest_identity) or
            receipt.native_claim.shard_index != index)
        {
            return error.NonCanonicalFreshProviderOrder;
        }
        claim.* = receipt.native_claim;
    }
    const aggregate = try authority.verifyAggregateClosure(
        plan,
        calls,
        relation,
        core.native(),
        native,
    );
    var result = VerifiedJointClosureV1{
        .format = format_version,
        .plan_identity = plan.identity,
        .manifest_identity = manifest_identity,
        .relation_context_identity = relation.identity,
        .core_claim_identity = core.identity,
        .ordered_provider_claims_identity = proof_authority.orderedProviderClaimsIdentity(providers),
        .shard_count = aggregate.shard_count,
        .core_claim = aggregate.core_claim,
        .provider_claim = aggregate.provider_claim,
        .closed_sum = aggregate.closed_sum,
        .every_proof_freshly_verified = true,
        .complete_ordered_coverage = true,
        .one_shared_relation_context = true,
        .production_eligible = false,
        .identity = undefined,
    };
    result.identity = proof_authority.closureIdentity(result);
    try result.validate();
    return result;
}

fn coreRows(
    allocator: std.mem.Allocator,
    calls: []const poseidon2_air.Call,
) ![]merkle_node.NodeRow {
    if (calls.len == 0) return error.EmptyCallAuthority;
    const rows = try allocator.alloc(merkle_node.NodeRow, calls.len);
    errdefer allocator.free(rows);
    for (calls, rows, 0..) |call, *row, index| {
        if (call.wide or call.io or call.narrow_output == null)
            return error.NonCanonicalNarrowCall;
        row.* = .{
            .index = @intCast(index * 2),
            .depth = 1,
            .lhs = call.input[0],
            .rhs = call.input[1],
            .cur = call.narrow_output.?,
            .lhs_mult = 0,
            .rhs_mult = 0,
            .cur_mult = 0,
            .root = call.narrow_output.?,
        };
    }
    return rows;
}

fn commitCoreStageAInto(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    rows: []const merkle_node.NodeRow,
    geometry: CoreResidencyGeometryV1,
) !void {
    const selectors = try harness.generateSelectors(
        allocator,
        geometry.log_size,
        geometry.n_rows,
    );
    try Engine.commit(scheme, allocator, selectors, null, channel);
    var main = try merkle_node.generateMain(allocator, rows, geometry.log_size);
    var main_owned = true;
    defer if (main_owned) main.deinit(allocator);
    const columns = try harness.takeColumns(
        merkle_node.N_MAIN_COLUMNS,
        allocator,
        &main.values,
        geometry.log_size,
    );
    main_owned = false;
    try Engine.commit(scheme, allocator, columns, null, channel);
}

fn commitProviderStageAInto(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    calls: []const poseidon2_air.Call,
    descriptor: authority.ProviderShardDescriptorV1,
) !void {
    const selectors = try harness.generateSelectors(
        allocator,
        descriptor.expected_log_size,
        descriptor.call_count,
    );
    try Engine.commit(scheme, allocator, selectors, null, channel);
    var main = try poseidon2_air.generateMain(
        allocator,
        calls,
        descriptor.expected_log_size,
    );
    var main_owned = true;
    defer if (main_owned) main.deinit(allocator);
    const columns = try harness.takeColumns(
        poseidon2_air.N_MAIN_COLUMNS,
        allocator,
        &main.values,
        descriptor.expected_log_size,
    );
    main_owned = false;
    try Engine.commit(scheme, allocator, columns, null, channel);
}

fn externalizedMerkleComponent(
    geometry: CoreResidencyGeometryV1,
    relations: anytype,
    claims: merkle_node.Claims,
) hash_component.HashComponent {
    return .{
        .kind = .merkle,
        .log_size = geometry.log_size,
        .n_rows = geometry.n_rows,
        .is_first_col_idx = 0,
        .is_active_col_idx = 1,
        .main_col_offset = 0,
        .interaction_col_offset = 0,
        .relations = relations,
        .merkle_shell = .externalized_poseidon_provider,
        .merkle_claims = claims.sums,
    };
}

fn providerComponent(
    descriptor: authority.ProviderShardDescriptorV1,
    relations: anytype,
    claims: poseidon2_air.Claims,
) hash_component.HashComponent {
    return .{
        .kind = .poseidon2,
        .log_size = descriptor.expected_log_size,
        .n_rows = descriptor.call_count,
        .is_first_col_idx = 0,
        .is_active_col_idx = 1,
        .main_col_offset = 0,
        .interaction_col_offset = 0,
        .relations = relations,
        .poseidon_shell = .narrow_memory,
        .poseidon_claims = claims.sums,
    };
}

fn validateCoreStatement(
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    manifest: anytype,
    shared: joint.SharedRelationAuthorityV1,
    statement: CoreStatementV1,
) !void {
    try manifest.validate(plan, calls);
    const expected = try CoreResidencyGeometryV1.canonical(
        manifest.core.log_size,
        manifest.core.n_rows,
    );
    if (statement.format != format_version or
        !aggregation_hash.eql(statement.plan_identity, plan.identity) or
        !aggregation_hash.eql(statement.manifest_identity, manifest.identity) or
        !aggregation_hash.eql(statement.core_stage_a_identity, manifest.core.identity) or
        !aggregation_hash.eql(statement.relation_context_identity, shared.relation_context.identity) or
        !aggregation_hash.eql(statement.call_list_commitment, plan.call_list_commitment) or
        !std.meta.eql(statement.geometry, expected) or
        !aggregation_hash.eql(
            statement.identity,
            proof_authority.coreStatementIdentity(statement),
        ))
    {
        return error.InvalidCoreStatement;
    }
}

fn validateProviderStatement(
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    manifest: anytype,
    shared: joint.SharedRelationAuthorityV1,
    statement: ProviderStatementV1,
) !void {
    try manifest.validate(plan, calls);
    const index: usize = @intCast(statement.shard_index);
    if (index >= plan.shards.len) return error.ShardIndexOutOfRange;
    const descriptor = plan.shards[index];
    if (statement.format != format_version or
        !aggregation_hash.eql(statement.plan_identity, plan.identity) or
        !aggregation_hash.eql(statement.manifest_identity, manifest.identity) or
        !aggregation_hash.eql(statement.stage_a_identity, manifest.providers[index].identity) or
        !aggregation_hash.eql(statement.descriptor_identity, descriptor.identity) or
        !aggregation_hash.eql(statement.relation_context_identity, shared.relation_context.identity) or
        statement.first_call != descriptor.first_call or
        statement.call_count != descriptor.call_count or
        statement.log_size != descriptor.expected_log_size or
        !aggregation_hash.eql(
            statement.identity,
            proof_authority.providerStatementIdentity(statement),
        ))
    {
        return error.InvalidProviderStatement;
    }
}

fn verifyCorePreprocessedRoot(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    geometry: CoreResidencyGeometryV1,
    expected: Engine.Hasher.Hash,
) !void {
    return harness.verifyPreprocessedRoot(
        Engine,
        allocator,
        pcs_config,
        geometry.log_size,
        geometry.n_rows,
        expected,
    );
}

fn requireStageARoots(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    scheme: *Engine.Scheme,
    tree0: Engine.Hasher.Hash,
    tree1: Engine.Hasher.Hash,
) !void {
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 2 or
        !std.meta.eql(roots.items[0], tree0) or
        !std.meta.eql(roots.items[1], tree1))
    {
        return error.StageARootMismatch;
    }
}

fn expectedLogSize(count: usize) u32 {
    return @max(@as(u32, 4), std.math.log2_int_ceil(usize, count));
}

comptime {
    if (merkle_node.N_MAIN_COLUMNS != 10 or
        merkle_node.N_INTERACTION_COLUMNS != 12 or
        merkle_node.N_EXTERNAL_PROVIDER_CONSTRAINTS != 13 or
        poseidon2_air.N_MAIN_COLUMNS != authority.main_column_count or
        poseidon2_air.N_INTERACTION_COLUMNS != authority.interaction_column_count or
        standalone.composition_log_lift != 1)
    {
        @compileError("joint base caller/provider proof geometry drifted");
    }
}
