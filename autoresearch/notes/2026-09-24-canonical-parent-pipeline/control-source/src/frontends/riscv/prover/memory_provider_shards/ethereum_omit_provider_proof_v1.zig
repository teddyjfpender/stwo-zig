//! Independent ordered provider proof under the provider-free Ethereum core
//! transcript.  Every ordinal replays the same full admitted statement,
//! projection, joined Tree0/Tree1 roots, provider Stage-A manifest, and shared
//! relation draw; it has no dependency on a Stage-B prefix.

const std = @import("std");
const core_air = @import("stwo_core").air;
const core_pcs = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_verifier = @import("stwo_core").verifier;
const aggregation_hash = @import("../../aggregation/hash.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const authority = @import("authority.zig");
const protocol = @import("ethereum_omit_protocol_v1.zig");
const omission = @import("native_provider_omit_v1.zig");
const statement_validation = @import("../statement_validation.zig");
const harness = @import("proof_harness.zig");
const proof_authority = @import("joint_proof_authority.zig");
const provider_order = @import("provider_order_component.zig");
const reusable = @import("joint_provider_proof_v2.zig");
const standalone = @import("standalone_component.zig");

pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const OMITTED_ETHEREUM_CORE_FRESHLY_VERIFIED = true;
pub const PROVIDER_ORDERED_CALL_COMMITMENT_IS_AIR_PROVED = true;
pub const RECURSIVE_VERIFICATION_IMPLEMENTED = false;
pub const format_version = proof_authority.provider_format_version_v2;
pub const tree_count: usize = 3;
pub const proof_commitment_count: usize = tree_count + 1;
pub const provider_tree2_columns: usize =
    poseidon2_air.N_INTERACTION_COLUMNS + provider_order.interaction_column_count;

pub const ProviderStatementV2 = proof_authority.ProviderStatementV2;
pub const FreshProviderClaimV2 = proof_authority.FreshProviderClaimV2;
pub const ProviderTree2GeometryV2 = proof_authority.ProviderTree2GeometryV2;

pub fn ProviderProofOutputV2(comptime Engine: type) type {
    return struct {
        statement: ProviderStatementV2,
        proof: @import("stwo_core").proof.StarkProof(Engine.Hasher),
    };
}

pub fn Source(comptime Engine: type) type {
    return struct {
        native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        lookup_manifest: *const lookup_physical_v2.Manifest,
        authenticated_lookup: *const lookup_physical_v2.AuthenticatedStatement,
        projection: *const omission.ProjectionV1,
        plan: *const authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        provider_stage_a: *const protocol.ProviderStageAManifestV1(Engine),
        shared: protocol.SharedRelationAuthorityV1(Engine),
        /// Present only for a typed combined-profile adapter whose full native
        /// statement has already authenticated heterogeneous retirements.
        retirement_supplement: ?statement_validation.RetirementSupplementV2 = null,
        /// Optional O(1) readmission authority for `plan`/`calls`. Every
        /// corpus readmission this source drives - its own `validate`, the
        /// shared transcript replay, the provider-local prefix, the admitted
        /// shard slice, and the aggregate closure - becomes a pointer-closed
        /// check when it is present. No transcript value, claim, or proof byte
        /// depends on it.
        validated_calls: ?*const authority.OwnedValidatedPlanCallAuthorityV1 = null,

        pub fn validate(self: @This()) !void {
            if (self.validated_calls) |token| {
                try self.provider_stage_a.validateBorrowedValidated(
                    self.plan,
                    self.calls,
                    token,
                );
                if (self.retirement_supplement) |supplement| {
                    try self.projection
                        .validateAgainstWithRetirementSupplementV2Validated(
                        self.native,
                        self.extension,
                        .proof,
                        supplement,
                        self.lookup_manifest,
                        self.authenticated_lookup,
                        self.plan,
                        self.calls,
                        token,
                        try omission.deriveFullGeometry(self.native),
                    );
                } else {
                    try self.projection.validateAgainstValidated(
                        self.native,
                        self.extension,
                        .proof,
                        self.lookup_manifest,
                        self.authenticated_lookup,
                        self.plan,
                        self.calls,
                        token,
                        try omission.deriveFullGeometry(self.native),
                    );
                }
            } else {
                try self.provider_stage_a.validate(self.plan, self.calls);
                if (self.retirement_supplement) |supplement| {
                    try self.projection
                        .validateAgainstWithRetirementSupplementV2(
                        self.native,
                        self.extension,
                        .proof,
                        supplement,
                        self.lookup_manifest,
                        self.authenticated_lookup,
                        self.plan,
                        self.calls,
                        try omission.deriveFullGeometry(self.native),
                    );
                } else {
                    try self.projection.validateAgainst(
                        self.native,
                        self.extension,
                        .proof,
                        self.lookup_manifest,
                        self.authenticated_lookup,
                        self.plan,
                        self.calls,
                        try omission.deriveFullGeometry(self.native),
                    );
                }
            }
            try self.shared.validate(
                self.plan,
                self.provider_stage_a,
                self.projection,
            );
        }
    };
}

/// The optional O(1) corpus authority a provider source carries, or `null` for
/// a source type that has none. Reading it here keeps every seam in this
/// module on one rule and leaves adapters that predate the token untouched.
pub fn validatedCallsOf(
    source: anytype,
) ?*const authority.OwnedValidatedPlanCallAuthorityV1 {
    const Source_ = @TypeOf(source);
    if (comptime !@hasField(Source_, "validated_calls")) return null;
    return source.validated_calls;
}

/// Admits one shard's contiguous call slice, using the source's O(1) authority
/// when it carries one. Both branches return the identical slice.
pub fn admittedShardForSource(
    source: anytype,
    shard_index: u32,
) ![]const poseidon2_air.Call {
    if (validatedCallsOf(source)) |token|
        return harness.admittedShardValidated(
            token,
            source.plan,
            source.calls,
            shard_index,
        );
    return harness.admittedShard(source.plan, source.calls, shard_index);
}

pub fn proveProviderV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    source: Source(Engine),
    shard_index: u32,
) !ProviderProofOutputV2(Engine) {
    try source.validate();
    const index: usize = @intCast(shard_index);
    if (index >= source.plan.shards.len) return error.ShardIndexOutOfRange;
    const descriptor = source.plan.shards[index];
    const shard_calls = try admittedShardForSource(source, shard_index);
    const transcript_replay = try replay(Engine, allocator, pcs_config, source);

    var scheme = try Engine.init(allocator, pcs_config);
    var scheme_owned = true;
    errdefer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(
        source.plan.residency.request.retention_policy,
    );
    var scratch = Engine.Channel{};
    try reusable.commitProviderStageAInto(
        Engine,
        allocator,
        &scheme,
        &scratch,
        shard_calls,
        descriptor,
    );
    try Engine.flushPendingCommit(&scheme, allocator, &scratch);
    try reusable.requireStageARoots(
        Engine,
        allocator,
        &scheme,
        source.provider_stage_a.providers[index].preprocessed_root,
        source.provider_stage_a.providers[index].main_root,
    );

    var interaction = try poseidon2_air.generateInteraction(
        allocator,
        shard_calls,
        descriptor.expected_log_size,
        &transcript_replay.relations.base,
    );
    var interaction_owned = true;
    defer if (interaction_owned) interaction.deinit(allocator);
    var ordered = try provider_order.generateInteraction(
        allocator,
        descriptor.first_call,
        shard_calls,
        descriptor.expected_log_size,
        &transcript_replay.relations.base,
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
    var statement = ProviderStatementV2{
        .format = format_version,
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
        .tree2_geometry = try ProviderTree2GeometryV2.canonical(
            descriptor.expected_log_size,
        ),
        .claims = interaction.claims,
        .ordered_call_claim = ordered.claim,
        .identity = undefined,
    };
    statement.identity = proof_authority.providerStatementIdentityV2(statement);
    var channel = try localPrefix(
        Engine,
        allocator,
        pcs_config,
        source,
        native_claim,
        statement.ordered_call_claim,
    );
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
    const component = reusable.providerComponent(
        descriptor,
        &transcript_replay.relations.base,
        statement.claims,
    );
    const order_component = try provider_order.ProviderOrderComponent.init(
        descriptor.expected_log_size,
        descriptor.call_count,
        descriptor.first_call,
        0,
        1,
        0,
        poseidon2_air.N_INTERACTION_COLUMNS,
        &transcript_replay.relations.base,
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
    source: Source(Engine),
    statement: ProviderStatementV2,
    proof_in: @import("stwo_core").proof.StarkProof(Engine.Hasher),
) !FreshProviderClaimV2 {
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    try validateStatement(Engine, source, statement);
    const index: usize = @intCast(statement.shard_index);
    const descriptor = source.plan.shards[index];
    const shard_calls = try admittedShardForSource(
        source,
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
    const transcript_replay = try replay(Engine, allocator, pcs_config, source);
    const expected_order = try provider_order.expectedClaim(
        descriptor.first_call,
        shard_calls,
        &transcript_replay.relations.base,
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
        .plan_identity = source.plan.identity,
        .descriptor_identity = descriptor.identity,
        .shard_index = statement.shard_index,
        .relation_context_identity = source.shared.relation_context.identity,
        .claims = statement.claims,
    };
    var channel = try localPrefix(
        Engine,
        allocator,
        pcs_config,
        source,
        native_claim,
        statement.ordered_call_claim,
    );
    try scheme.commit(
        allocator,
        commitments[2],
        &([_]u32{statement.log_size} ** provider_tree2_columns),
        &channel,
    );
    const component = reusable.providerComponent(
        descriptor,
        &transcript_replay.relations.base,
        statement.claims,
    );
    const order_component = try provider_order.ProviderOrderComponent.init(
        descriptor.expected_log_size,
        descriptor.call_count,
        descriptor.first_call,
        0,
        1,
        0,
        poseidon2_air.N_INTERACTION_COLUMNS,
        &transcript_replay.relations.base,
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
    result.identity = proof_authority.providerClaimIdentityV2(result);
    try result.validate();
    return result;
}

pub fn closeFreshClaimsV1(
    allocator: std.mem.Allocator,
    source: anytype,
    core: protocol.FreshCoreResidualV1,
    providers: []const FreshProviderClaimV2,
) !protocol.VerifiedJointClosureV1 {
    try source.validate();
    try core.validate();
    if (providers.len != source.plan.shard_count or
        !aggregation_hash.eql(core.plan_identity, source.plan.identity) or
        !aggregation_hash.eql(
            core.manifest_identity,
            source.provider_stage_a.identity,
        ) or
        !aggregation_hash.eql(
            core.projection_identity,
            source.projection.identity,
        ) or
        !aggregation_hash.eql(
            core.relation_context_identity,
            source.shared.relation_context.identity,
        ))
    {
        return error.EthereumProviderClosureAuthorityMismatch;
    }
    const native = try allocator.alloc(
        authority.ProviderShardClaimV1,
        providers.len,
    );
    defer allocator.free(native);
    for (providers, native, 0..) |receipt, *claim, index| {
        try receipt.validate();
        if (!aggregation_hash.eql(
            receipt.manifest_identity,
            source.provider_stage_a.identity,
        ) or receipt.native_claim.shard_index != index or
            !receipt.ordered_call_air_verified or
            !receipt.ordered_call_claim_recomputed)
        {
            return error.NonCanonicalFreshProviderOrder;
        }
        claim.* = receipt.native_claim;
    }
    const aggregate = if (validatedCallsOf(source)) |token|
        try authority.verifyAggregateClosureValidated(
            token,
            source.plan,
            source.calls,
            source.shared.relation_context,
            core.native(),
            native,
        )
    else
        try authority.verifyAggregateClosure(
            source.plan,
            source.calls,
            source.shared.relation_context,
            core.native(),
            native,
        );
    var result = protocol.VerifiedJointClosureV1{
        .format = format_version,
        .plan_identity = source.plan.identity,
        .manifest_identity = source.provider_stage_a.identity,
        .relation_context_identity = source.shared.relation_context.identity,
        .core_claim_identity = core.identity,
        .ordered_provider_claims_identity = proof_authority.orderedProviderClaimsIdentityV2(providers),
        .shard_count = aggregate.shard_count,
        .core_claim = aggregate.core_claim,
        .provider_claim = aggregate.provider_claim,
        .closed_sum = aggregate.closed_sum,
        .core_freshly_verified = true,
        .every_provider_freshly_verified = true,
        .every_ordered_call_air_verified = true,
        .complete_ordered_coverage = true,
        .one_shared_relation_context = true,
        .omit_recompute_owner_verified = true,
        .production_eligible = false,
        .recursive_admissible = false,
        .identity = undefined,
    };
    result.identity = protocol.closureIdentity(result);
    try result.validate();
    return result;
}

fn replay(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    source: Source(Engine),
) !protocol.Replay(Engine) {
    if (source.validated_calls) |token|
        return protocol.replaySharedTranscriptValidated(
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
            token,
            source.provider_stage_a,
            source.shared,
        );
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

fn localPrefix(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    source: Source(Engine),
    claim: authority.ProviderShardClaimV1,
    ordered: provider_order.ClaimV1,
) !Engine.Channel {
    if (source.validated_calls) |token|
        return protocol.providerLocalPrefixValidatedV2(
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
            token,
            source.provider_stage_a,
            source.shared,
            claim,
            ordered,
        );
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

fn validateStatement(
    comptime Engine: type,
    source: Source(Engine),
    value: ProviderStatementV2,
) !void {
    try source.validate();
    const index: usize = @intCast(value.shard_index);
    if (index >= source.plan.shards.len) return error.ShardIndexOutOfRange;
    const descriptor = source.plan.shards[index];
    const geometry = try ProviderTree2GeometryV2.canonical(
        descriptor.expected_log_size,
    );
    if (value.format != format_version or
        !aggregation_hash.eql(value.plan_identity, source.plan.identity) or
        !aggregation_hash.eql(
            value.manifest_identity,
            source.provider_stage_a.identity,
        ) or
        !aggregation_hash.eql(
            value.stage_a_identity,
            source.provider_stage_a.providers[index].identity,
        ) or
        !aggregation_hash.eql(value.descriptor_identity, descriptor.identity) or
        !aggregation_hash.eql(
            value.relation_context_identity,
            source.shared.relation_context.identity,
        ) or
        !aggregation_hash.eql(
            value.call_list_commitment,
            source.plan.call_list_commitment,
        ) or value.shard_index != @as(u32, @intCast(index)) or
        value.first_call != descriptor.first_call or
        value.call_count != descriptor.call_count or
        value.log_size != descriptor.expected_log_size or
        !std.meta.eql(value.tree2_geometry, geometry) or
        value.ordered_call_claim.format != provider_order.format_version or
        value.ordered_call_claim.first_call != descriptor.first_call or
        value.ordered_call_claim.call_count != descriptor.call_count or
        !aggregation_hash.eql(
            value.identity,
            proof_authority.providerStatementIdentityV2(value),
        )) return error.InvalidProviderStatement;
}

comptime {
    // Cross-check against the generic shard authority: that module is planning
    // and algebra only and still declares no AIR-proved ordered call
    // commitment, while this route proves one. The pair must not silently
    // converge, which would hide either a lost proof or a stale constant.
    if (authority.ORDERED_CALL_COMMITMENT_IS_AIR_PROVED ==
        PROVIDER_ORDERED_CALL_COMMITMENT_IS_AIR_PROVED or
        authority.CALLER_N_MANIFEST_IMPLEMENTED)
    {
        @compileError("ordered-call AIR authority drifted between route and plan");
    }
    if (provider_tree2_columns != 12 or
        poseidon2_air.N_MAIN_COLUMNS != authority.main_column_count or
        standalone.composition_log_lift != 1 or ACTIVATES_PRODUCTION_PROOF or
        !OMITTED_ETHEREUM_CORE_FRESHLY_VERIFIED or
        !PROVIDER_ORDERED_CALL_COMMITMENT_IS_AIR_PROVED or
        RECURSIVE_VERIFICATION_IMPLEMENTED)
    {
        @compileError("Ethereum omitted-core provider proof authority drifted");
    }
}
