//! V2 provider half of the joint base-Poseidon caller+N proof protocol.
//!
//! This append-only sibling leaves retained V1 provider artifacts and APIs
//! byte-stable.  It adds a four-M31 ordered-call accumulator to the existing
//! eight-column Poseidon LogUp Tree 2, binds its exact range and endpoint in
//! the provider statement, and lets only a fresh verifier mint V2 claims.

const std = @import("std");
const core_air = @import("stwo_core").air;
const core_pcs = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_verifier = @import("stwo_core").verifier;
const prover_pcs = @import("stwo_prover_engine").pcs;
const aggregation_hash = @import("../../aggregation/hash.zig");
const hash_component = @import("../../air/memory_commitment/hash_component.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const authority = @import("authority.zig");
const harness = @import("proof_harness.zig");
const joint = @import("joint_protocol.zig");
const proof_v1 = @import("joint_proof.zig");
const proof_authority = @import("joint_proof_authority.zig");
const provider_order = @import("provider_order_component.zig");
const standalone = @import("standalone_component.zig");

pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const PROVIDER_ORDERED_CALL_COMMITMENT_IS_AIR_PROVED = true;
pub const PROVIDER_RANGE_IS_PUBLIC_STATEMENT_BOUND = true;
pub const FRESH_VERIFIER_RECOMPUTES_ORDERED_ENDPOINT = true;
pub const FULL_RISCV_CORE_EXTERNALIZED = false;
pub const NATIVE_PROVIDER_RETAINED_CORRECTNESS_BRIDGE = true;
pub const OMIT_RECOMPUTE_OWNER_IMPLEMENTED = false;
pub const RECURSIVE_VERIFICATION_IMPLEMENTED = false;

pub const format_version = proof_authority.provider_format_version_v2;
pub const tree_count: usize = 3;
pub const proof_commitment_count: usize = tree_count + 1;
pub const provider_tree2_columns: usize =
    poseidon2_air.N_INTERACTION_COLUMNS + provider_order.interaction_column_count;

pub const ProviderTree2GeometryV2 = proof_authority.ProviderTree2GeometryV2;
pub const ProviderStatementV2 = proof_authority.ProviderStatementV2;
pub const FreshProviderClaimV2 = proof_authority.FreshProviderClaimV2;
pub const VerifiedJointClosureV2 = proof_authority.VerifiedJointClosureV2;
pub const OrderedCallClaimV1 = provider_order.ClaimV1;
pub const providerStatementIdentity = proof_authority.providerStatementIdentityV2;

pub fn expectedOrderedCallClaim(
    first_call: u64,
    calls: []const poseidon2_air.Call,
    relations: anytype,
) !OrderedCallClaimV1 {
    return provider_order.expectedClaim(first_call, calls, relations);
}

pub fn ProviderProofOutputV2(comptime Engine: type) type {
    return struct {
        statement: ProviderStatementV2,
        proof: @import("stwo_core").proof.StarkProof(Engine.Hasher),
    };
}

pub fn proveProviderV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    manifest: *const joint.JointManifest(Engine),
    shared: joint.SharedRelationAuthorityV1,
    shard_index: u32,
) !ProviderProofOutputV2(Engine) {
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
    scheme.setCoefficientRetentionPolicy(
        plan.residency.request.retention_policy,
    );
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
    var ordered = try provider_order.generateInteraction(
        allocator,
        descriptor.first_call,
        shard_calls,
        descriptor.expected_log_size,
        &replay.relations,
    );
    var ordered_owned = true;
    defer if (ordered_owned) ordered.deinit(allocator);

    const native_claim = authority.ProviderShardClaimV1{
        .plan_identity = plan.identity,
        .descriptor_identity = descriptor.identity,
        .shard_index = shard_index,
        .relation_context_identity = shared.relation_context.identity,
        .claims = interaction.claims,
    };
    var statement = ProviderStatementV2{
        .format = format_version,
        .plan_identity = plan.identity,
        .manifest_identity = manifest.identity,
        .stage_a_identity = manifest.providers[index].identity,
        .descriptor_identity = descriptor.identity,
        .relation_context_identity = shared.relation_context.identity,
        .call_list_commitment = plan.call_list_commitment,
        .shard_index = shard_index,
        .first_call = descriptor.first_call,
        .call_count = descriptor.call_count,
        .log_size = descriptor.expected_log_size,
        .tree2_geometry = try ProviderTree2GeometryV2.canonical(
            descriptor.expected_log_size,
        ),
        .claims = interaction.claims,
        .ordered_call_claim = ordered.claim,
        .identity = undefined,
    };
    statement.identity = proof_authority.providerStatementIdentityV2(statement);
    var channel = try joint.providerLocalPrefixV2(
        Engine,
        allocator,
        pcs_config,
        plan,
        calls,
        manifest,
        shared,
        native_claim,
        statement.ordered_call_claim,
    );
    const columns = try mergeInteractionColumns(
        allocator,
        descriptor.expected_log_size,
        &interaction,
        &ordered,
    );
    interaction_owned = false;
    ordered_owned = false;
    try Engine.commit(&scheme, allocator, columns, null, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);

    const component = providerComponent(descriptor, &replay.relations, statement.claims);
    const order_component = try provider_order.ProviderOrderComponent.init(
        descriptor.expected_log_size,
        descriptor.call_count,
        descriptor.first_call,
        0,
        1,
        0,
        poseidon2_air.N_INTERACTION_COLUMNS,
        &replay.relations,
        statement.ordered_call_claim,
    );
    var lifted = standalone.Prover{ .inner = component.asProverComponent() };
    var order_lifted = standalone.Prover{ .inner = order_component.asProverComponent() };
    const components = [_]@import("stwo_prover_engine").air.component_prover.ComponentProver{
        lifted.asComponent(),
        order_lifted.asComponent(),
    };
    scheme_owned = false;
    var extended = try Engine.prove(allocator, &components, &channel, scheme, .{});
    const proof = extended.proof;
    extended.aux.deinit(allocator);
    return .{ .statement = statement, .proof = proof };
}

pub fn verifyProviderFreshV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    manifest: *const joint.JointManifest(Engine),
    shared: joint.SharedRelationAuthorityV1,
    statement: ProviderStatementV2,
    proof_in: @import("stwo_core").proof.StarkProof(Engine.Hasher),
) !FreshProviderClaimV2 {
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    try validateProviderStatement(plan, calls, manifest, shared, statement);
    const index: usize = @intCast(statement.shard_index);
    const descriptor = plan.shards[index];
    const shard_calls = try harness.admittedShard(plan, calls, statement.shard_index);
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
    const expected_order = try provider_order.expectedClaim(
        descriptor.first_call,
        shard_calls,
        &replay.relations,
    );
    if (!std.meta.eql(expected_order, statement.ordered_call_claim))
        return error.ProviderOrderClaimMismatch;

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
    var channel = try joint.providerLocalPrefixV2(
        Engine,
        allocator,
        pcs_config,
        plan,
        calls,
        manifest,
        shared,
        native_claim,
        statement.ordered_call_claim,
    );
    try scheme.commit(
        allocator,
        commitments[2],
        &([_]u32{statement.log_size} ** provider_tree2_columns),
        &channel,
    );
    const component = providerComponent(descriptor, &replay.relations, statement.claims);
    const order_component = try provider_order.ProviderOrderComponent.init(
        descriptor.expected_log_size,
        descriptor.call_count,
        descriptor.first_call,
        0,
        1,
        0,
        poseidon2_air.N_INTERACTION_COLUMNS,
        &replay.relations,
        statement.ordered_call_claim,
    );
    var lifted = standalone.Verifier{ .inner = component.asVerifierComponent() };
    var order_lifted = standalone.Verifier{ .inner = order_component.asVerifierComponent() };
    const components = [_]core_air.components.Component{
        lifted.asComponent(),
        order_lifted.asComponent(),
    };
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
    var result = FreshProviderClaimV2{
        .format = format_version,
        .manifest_identity = manifest.identity,
        .statement_identity = statement.identity,
        .proof_commitments_identity = commitments_identity,
        .fresh_provider_stark_verified = true,
        .ordered_call_air_verified = true,
        .ordered_call_claim_recomputed = true,
        .native_claim = native_claim,
        .ordered_call_claim = statement.ordered_call_claim,
        .identity = undefined,
    };
    result.identity = proof_authority.providerClaimIdentityV2(result);
    try result.validate();
    return result;
}

pub fn closeFreshClaimsV2(
    allocator: std.mem.Allocator,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    manifest_identity: authority.Digest,
    relation: authority.PoseidonRelationContextV1,
    core: proof_v1.CoreWithoutProviderClaimV1,
    providers: []const FreshProviderClaimV2,
) !VerifiedJointClosureV2 {
    try core.validate();
    if (!aggregation_hash.eql(core.manifest_identity, manifest_identity))
        return error.JointManifestIdentityMismatch;
    const native = try allocator.alloc(authority.ProviderShardClaimV1, providers.len);
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
    var result = VerifiedJointClosureV2{
        .format = format_version,
        .plan_identity = plan.identity,
        .manifest_identity = manifest_identity,
        .relation_context_identity = relation.identity,
        .core_claim_identity = core.identity,
        .ordered_provider_claims_identity = proof_authority.orderedProviderClaimsIdentityV2(providers),
        .shard_count = aggregate.shard_count,
        .core_claim = aggregate.core_claim,
        .provider_claim = aggregate.provider_claim,
        .closed_sum = aggregate.closed_sum,
        .every_proof_freshly_verified = true,
        .every_ordered_call_air_verified = true,
        .complete_ordered_coverage = true,
        .one_shared_relation_context = true,
        .production_eligible = false,
        .identity = undefined,
    };
    result.identity = proof_authority.closureIdentityV2(result);
    try result.validate();
    return result;
}

pub fn mergeInteractionColumns(
    allocator: std.mem.Allocator,
    log_size: u32,
    poseidon: *poseidon2_air.Interaction,
    ordered: *provider_order.Interaction,
) ![]prover_pcs.ColumnEvaluation {
    const columns = try allocator.alloc(prover_pcs.ColumnEvaluation, provider_tree2_columns);
    for (poseidon.columns, 0..) |values, index| columns[index] = .{
        .log_size = log_size,
        .values = values,
    };
    for (ordered.columns, 0..) |values, index| columns[poseidon2_air.N_INTERACTION_COLUMNS + index] = .{
        .log_size = log_size,
        .values = values,
    };
    return columns;
}

pub fn commitProviderStageAInto(
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
    var main = try poseidon2_air.generateMain(allocator, calls, descriptor.expected_log_size);
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

pub fn providerComponent(
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

fn validateProviderStatement(
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    manifest: anytype,
    shared: joint.SharedRelationAuthorityV1,
    statement: ProviderStatementV2,
) !void {
    try manifest.validate(plan, calls);
    const index: usize = @intCast(statement.shard_index);
    if (index >= plan.shards.len) return error.ShardIndexOutOfRange;
    const descriptor = plan.shards[index];
    const geometry = try ProviderTree2GeometryV2.canonical(descriptor.expected_log_size);
    if (statement.format != format_version or
        !aggregation_hash.eql(statement.plan_identity, plan.identity) or
        !aggregation_hash.eql(statement.manifest_identity, manifest.identity) or
        !aggregation_hash.eql(statement.stage_a_identity, manifest.providers[index].identity) or
        !aggregation_hash.eql(statement.descriptor_identity, descriptor.identity) or
        !aggregation_hash.eql(statement.relation_context_identity, shared.relation_context.identity) or
        !aggregation_hash.eql(statement.call_list_commitment, plan.call_list_commitment) or
        statement.first_call != descriptor.first_call or
        statement.call_count != descriptor.call_count or
        statement.log_size != descriptor.expected_log_size or
        !std.meta.eql(statement.tree2_geometry, geometry) or
        statement.ordered_call_claim.format != provider_order.format_version or
        statement.ordered_call_claim.first_call != descriptor.first_call or
        statement.ordered_call_claim.call_count != descriptor.call_count or
        !aggregation_hash.eql(
            statement.identity,
            proof_authority.providerStatementIdentityV2(statement),
        ))
    {
        return error.InvalidProviderStatement;
    }
}

pub fn requireStageARoots(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    scheme: *Engine.Scheme,
    tree0: Engine.Hasher.Hash,
    tree1: Engine.Hasher.Hash,
) !void {
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 2 or !std.meta.eql(roots.items[0], tree0) or
        !std.meta.eql(roots.items[1], tree1))
    {
        return error.StageARootMismatch;
    }
}

comptime {
    if (provider_tree2_columns != 12 or
        poseidon2_air.N_MAIN_COLUMNS != authority.main_column_count or
        standalone.composition_log_lift != 1)
    {
        @compileError("V2 provider proof geometry drifted");
    }
}
