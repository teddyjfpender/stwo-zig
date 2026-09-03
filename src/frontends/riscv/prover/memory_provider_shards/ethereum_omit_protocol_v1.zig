//! The provider Stage-A roots and exact dynamic shard plan are bound after the
//! joined Ethereum Tree0/Tree1 roots and before the one shared relation draw.
//! This module deliberately returns only diagnostic prover/fresh-verifier
//! residuals; production remains false until fresh ordered-provider closure.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const aggregation_hash = @import("../../aggregation/hash.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const statement = @import("../../air/statement.zig");
const statement_geometry = @import("../statement_geometry.zig");
const statement_validation = @import("../statement_validation.zig");
const ethereum_transcript = @import("../guest_precompile/ethereum_transcript.zig");
const authority = @import("authority.zig");
const joint = @import("joint_protocol.zig");
const harness = @import("proof_harness.zig");
const proof_authority = @import("joint_proof_authority.zig");
const provider_order = @import("provider_order_component.zig");
const omission = @import("native_provider_omit_v1.zig");

pub const format_version: u32 = 1;
pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const OMIT_RECOMPUTE_CORE_IMPLEMENTED = true;
pub const FRESH_PROVIDER_CLOSURE_REQUIRED = true;
pub const Digest = aggregation_hash.Digest;
const interaction_pow_bits = @import("../../air/transcript/mod.zig").INTERACTION_POW_BITS;

pub fn SharedRelationAuthorityV1(comptime Engine: type) type {
    return struct {
        format: u32,
        plan_identity: Digest,
        manifest_identity: Digest,
        projection_identity: Digest,
        tree0_root: Engine.Hasher.Hash,
        tree1_root: Engine.Hasher.Hash,
        interaction_pow_bits: u32,
        interaction_pow: u64,
        relation_context: authority.PoseidonRelationContextV1,
        identity: Digest,

        const Self = @This();

        pub fn validate(
            self: Self,
            plan: *const authority.ProviderShardPlanV1,
            provider_stage_a: *const ProviderStageAManifestV1(Engine),
            projection: *const omission.ProjectionV1,
        ) !void {
            if (self.format != format_version or
                self.interaction_pow_bits != interaction_pow_bits or
                !aggregation_hash.eql(self.plan_identity, plan.identity) or
                !aggregation_hash.eql(
                    self.manifest_identity,
                    provider_stage_a.identity,
                ) or
                !aggregation_hash.eql(
                    self.projection_identity,
                    projection.identity,
                ))
            {
                return error.InvalidEthereumProviderSharedAuthority;
            }
            try self.relation_context.validate(plan.session);
            if (!aggregation_hash.eql(self.identity, sharedRelationIdentity(
                Engine,
                self,
            ))) return error.EthereumProviderSharedAuthorityIdentityMismatch;
        }
    };
}

pub const FreshCoreResidualV1 = struct {
    format: u32,
    plan_identity: Digest,
    manifest_identity: Digest,
    projection_identity: Digest,
    relation_context_identity: Digest,
    proof_commitments_identity: Digest,
    fresh_core_stark_verified: bool,
    non_poseidon_buses_closed: bool,
    poseidon2_residual: QM31,
    production_eligible: bool,
    recursive_admissible: bool,
    identity: Digest,

    pub fn validate(self: @This()) !void {
        if (self.format != format_version or
            !self.fresh_core_stark_verified or
            !self.non_poseidon_buses_closed or
            self.production_eligible or self.recursive_admissible or
            !aggregation_hash.eql(self.identity, freshCoreResidualIdentity(self)))
        {
            return error.InvalidEthereumProviderFreshCoreResidual;
        }
    }

    pub fn native(self: @This()) authority.CorePoseidonClaimV1 {
        return .{
            .plan_identity = self.plan_identity,
            .relation_context_identity = self.relation_context_identity,
            .claim = self.poseidon2_residual,
        };
    }
};

pub const VerifiedJointClosureV1 = struct {
    format: u32,
    plan_identity: Digest,
    manifest_identity: Digest,
    relation_context_identity: Digest,
    core_claim_identity: Digest,
    ordered_provider_claims_identity: Digest,
    shard_count: u32,
    core_claim: QM31,
    provider_claim: QM31,
    closed_sum: QM31,
    core_freshly_verified: bool,
    every_provider_freshly_verified: bool,
    every_ordered_call_air_verified: bool,
    complete_ordered_coverage: bool,
    one_shared_relation_context: bool,
    omit_recompute_owner_verified: bool,
    production_eligible: bool,
    recursive_admissible: bool,
    identity: Digest,

    pub fn validate(self: @This()) !void {
        if (self.format != proof_authority.provider_format_version_v2 or
            self.shard_count == 0 or !self.core_freshly_verified or
            !self.every_provider_freshly_verified or
            !self.every_ordered_call_air_verified or
            !self.complete_ordered_coverage or
            !self.one_shared_relation_context or
            !self.omit_recompute_owner_verified or self.production_eligible or
            self.recursive_admissible or !self.closed_sum.isZero() or
            !aggregation_hash.eql(self.identity, closureIdentity(self)))
        {
            return error.InvalidEthereumProviderJointClosure;
        }
    }
};

pub fn ProviderStageAManifestV1(comptime Engine: type) type {
    return struct {
        format: u32,
        plan_identity: Digest,
        session: Digest,
        call_list_commitment: Digest,
        providers: []const joint.ProviderStageARecord(Engine),
        identity: Digest,

        const Self = @This();

        pub fn init(
            plan: *const authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            providers: []const joint.ProviderStageARecord(Engine),
        ) !Self {
            try plan.validate(calls);
            var result = Self{
                .format = format_version,
                .plan_identity = plan.identity,
                .session = plan.session,
                .call_list_commitment = plan.call_list_commitment,
                .providers = providers,
                .identity = undefined,
            };
            result.identity = providerManifestIdentity(Engine, &result);
            try result.validate(plan, calls);
            return result;
        }

        pub fn createFromRoots(
            allocator: std.mem.Allocator,
            plan: *const authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            roots: []const harness.StageACommitment(Engine),
        ) !OwnedProviderStageAManifestV1(Engine) {
            try plan.validate(calls);
            if (roots.len != plan.shards.len)
                return error.InvalidEthereumProviderStageARootCount;
            const providers = try allocator.alloc(
                joint.ProviderStageARecord(Engine),
                roots.len,
            );
            errdefer allocator.free(providers);
            for (providers, roots, 0..) |*record, root, index|
                record.* = joint.ProviderStageARecord(Engine).canonical(
                    plan,
                    index,
                    root,
                );
            const manifest = try Self.init(plan, calls, providers);
            return .{ .providers = providers, .manifest = manifest };
        }

        pub fn validate(
            self: *const Self,
            plan: *const authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
        ) !void {
            try plan.validate(calls);
            if (self.format != format_version or
                !aggregation_hash.eql(self.plan_identity, plan.identity) or
                !aggregation_hash.eql(self.session, plan.session) or
                !aggregation_hash.eql(
                    self.call_list_commitment,
                    plan.call_list_commitment,
                ) or self.providers.len != plan.shards.len)
            {
                return error.InvalidEthereumProviderStageAManifest;
            }
            for (self.providers, 0..) |record, index|
                try record.validate(plan, index);
            if (!aggregation_hash.eql(
                self.identity,
                providerManifestIdentity(Engine, self),
            )) return error.EthereumProviderStageAManifestIdentityMismatch;
        }
    };
}

pub fn OwnedProviderStageAManifestV1(comptime Engine: type) type {
    return struct {
        providers: []joint.ProviderStageARecord(Engine),
        manifest: ProviderStageAManifestV1(Engine),

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            allocator.free(self.providers);
            self.* = undefined;
        }
    };
}

pub fn Extension(comptime Engine: type) type {
    return struct {
        plan: *const authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        provider_stage_a: *const ProviderStageAManifestV1(Engine),
        projection: omission.ProjectionV1 = undefined,
        projection_ready: bool = false,
        prover_residual: ?QM31 = null,
        fresh_verifier_residual: ?QM31 = null,
        shared_relation: ?SharedRelationAuthorityV1(Engine) = null,
        expected_shared_relation: ?SharedRelationAuthorityV1(Engine) = null,
        fresh_core: ?FreshCoreResidualV1 = null,

        const Self = @This();

        pub fn init(
            plan: *const authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            provider_stage_a: *const ProviderStageAManifestV1(Engine),
        ) !Self {
            try provider_stage_a.validate(plan, calls);
            return .{
                .plan = plan,
                .calls = calls,
                .provider_stage_a = provider_stage_a,
            };
        }

        pub fn initForFreshVerify(
            plan: *const authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            provider_stage_a: *const ProviderStageAManifestV1(Engine),
            expected_shared_relation: SharedRelationAuthorityV1(Engine),
        ) !Self {
            var result = try init(plan, calls, provider_stage_a);
            result.expected_shared_relation = expected_shared_relation;
            return result;
        }

        pub fn prepareProjectedCore(
            self: *Self,
            native: *const statement_v2.RiscVStatementV2,
            extension: *const ethereum_statement.Statement,
            manifest: *const lookup_physical_v2.Manifest,
            authenticated: *const lookup_physical_v2.AuthenticatedStatement,
            workspace_core: *statement.RiscVStatement,
            full_geometry: statement_geometry.Geometry,
        ) !void {
            if (self.projection_ready) return error.ProjectionAlreadyPrepared;
            self.projection = try omission.ProjectionV1.init(
                native,
                extension,
                .proof,
                manifest,
                authenticated,
                self.plan,
                self.calls,
                full_geometry,
            );
            try self.projection.installProjectedCore(
                workspace_core,
                native,
                extension,
            );
            self.projection_ready = true;
        }

        pub fn prepareProjectedVerifierCore(
            self: *Self,
            native: *const statement_v2.RiscVStatementV2,
            extension: *const ethereum_statement.Statement,
            manifest: *const lookup_physical_v2.Manifest,
            authenticated: *const lookup_physical_v2.AuthenticatedStatement,
            workspace_core: *statement.RiscVStatement,
        ) !void {
            return self.prepareProjectedCore(
                native,
                extension,
                manifest,
                authenticated,
                workspace_core,
                try omission.deriveFullGeometry(native),
            );
        }

        /// Candidate-only projection route whose full statement carries a
        /// heterogeneous retirement supplement. The ordinary Ethereum route
        /// above remains unchanged.
        pub fn prepareProjectedCoreWithRetirementSupplementV2(
            self: *Self,
            native: *const statement_v2.RiscVStatementV2,
            extension: *const ethereum_statement.Statement,
            manifest: *const lookup_physical_v2.Manifest,
            authenticated: *const lookup_physical_v2.AuthenticatedStatement,
            workspace_core: *statement.RiscVStatement,
            full_geometry: statement_geometry.Geometry,
            supplement: statement_validation.RetirementSupplementV2,
        ) !void {
            if (self.projection_ready) return error.ProjectionAlreadyPrepared;
            self.projection = try omission.ProjectionV1
                .initWithRetirementSupplementV2(
                native,
                extension,
                .proof,
                supplement,
                manifest,
                authenticated,
                self.plan,
                self.calls,
                full_geometry,
            );
            try self.projection.installProjectedCore(
                workspace_core,
                native,
                extension,
            );
            self.projection_ready = true;
        }

        pub fn prepareProjectedVerifierCoreWithRetirementSupplementV2(
            self: *Self,
            native: *const statement_v2.RiscVStatementV2,
            extension: *const ethereum_statement.Statement,
            manifest: *const lookup_physical_v2.Manifest,
            authenticated: *const lookup_physical_v2.AuthenticatedStatement,
            workspace_core: *statement.RiscVStatement,
            supplement: statement_validation.RetirementSupplementV2,
        ) !void {
            return self.prepareProjectedCoreWithRetirementSupplementV2(
                native,
                extension,
                manifest,
                authenticated,
                workspace_core,
                try omission.deriveFullGeometry(native),
                supplement,
            );
        }

        pub fn providerProjection(self: *const Self) !*const omission.ProjectionV1 {
            if (!self.projection_ready) return error.ProjectionNotPrepared;
            return &self.projection;
        }

        pub fn providerPlan(self: *const Self) *const authority.ProviderShardPlanV1 {
            return self.plan;
        }

        pub fn providerCalls(self: *const Self) []const poseidon2_air.Call {
            return self.calls;
        }

        pub fn recordProverResidual(self: *Self, residual: QM31) !void {
            if (self.prover_residual != null)
                return error.DuplicateProverResidual;
            self.prover_residual = residual;
        }

        pub fn recordFreshVerifierResidual(self: *Self, residual: QM31) !void {
            if (self.fresh_verifier_residual != null)
                return error.DuplicateFreshVerifierResidual;
            self.fresh_verifier_residual = residual;
        }

        pub fn recordFreshVerifierAuthority(
            self: *Self,
            residual: QM31,
            proof_commitments_identity: Digest,
        ) !void {
            try self.recordFreshVerifierResidual(residual);
            const shared = self.shared_relation orelse
                return error.MissingEthereumProviderSharedAuthority;
            if (self.fresh_core != null) return error.DuplicateFreshCoreAuthority;
            var result = FreshCoreResidualV1{
                .format = format_version,
                .plan_identity = self.plan.identity,
                .manifest_identity = self.provider_stage_a.identity,
                .projection_identity = self.projection.identity,
                .relation_context_identity = shared.relation_context.identity,
                .proof_commitments_identity = proof_commitments_identity,
                .fresh_core_stark_verified = true,
                .non_poseidon_buses_closed = true,
                .poseidon2_residual = residual,
                .production_eligible = false,
                .recursive_admissible = false,
                .identity = undefined,
            };
            result.identity = freshCoreResidualIdentity(result);
            try result.validate();
            self.fresh_core = result;
        }

        pub fn proofCommitmentsIdentity(
            self: *const Self,
            commitments: []const Engine.Hasher.Hash,
        ) Digest {
            _ = self;
            return proof_authority.commitmentsIdentity(Engine, commitments);
        }

        pub fn drawChallenges(
            self: *Self,
            allocator: std.mem.Allocator,
            scheme: *Engine.Scheme,
            channel: *Engine.Channel,
            native: *const statement_v2.RiscVStatementV2,
            core: *const statement.RiscVStatement,
            extension: *const ethereum_statement.Statement,
            manifest: *const lookup_physical_v2.Manifest,
            authenticated: *const lookup_physical_v2.AuthenticatedStatement,
            recorder: anytype,
        ) !ethereum_transcript.Prefix {
            _ = recorder;
            try self.validateProjectedAuthority(
                native,
                core,
                extension,
                manifest,
                authenticated,
            );
            return self.drawChallengesAfterValidation(
                allocator,
                scheme,
                channel,
                core,
            );
        }

        /// Candidate-only draw path for a full statement with heterogeneous
        /// external retirements. Validation completes before roots are read or
        /// the channel is mutated; the draw transaction below is shared with
        /// the ordinary path byte-for-byte.
        pub fn drawChallengesWithRetirementSupplementV2(
            self: *Self,
            allocator: std.mem.Allocator,
            scheme: *Engine.Scheme,
            channel: *Engine.Channel,
            native: *const statement_v2.RiscVStatementV2,
            core: *const statement.RiscVStatement,
            extension: *const ethereum_statement.Statement,
            manifest: *const lookup_physical_v2.Manifest,
            authenticated: *const lookup_physical_v2.AuthenticatedStatement,
            supplement: statement_validation.RetirementSupplementV2,
            recorder: anytype,
        ) !ethereum_transcript.Prefix {
            _ = recorder;
            try self.validateProjectedAuthorityWithRetirementSupplementV2(
                native,
                core,
                extension,
                manifest,
                authenticated,
                supplement,
            );
            return self.drawChallengesAfterValidation(
                allocator,
                scheme,
                channel,
                core,
            );
        }

        fn drawChallengesAfterValidation(
            self: *Self,
            allocator: std.mem.Allocator,
            scheme: *Engine.Scheme,
            channel: *Engine.Channel,
            core: *const statement.RiscVStatement,
        ) !ethereum_transcript.Prefix {
            var roots = try scheme.roots(allocator);
            defer roots.deinit(allocator);
            if (roots.items.len != 2)
                return error.InvalidEthereumProviderStageATreeCount;
            const prefix = try ethereum_transcript.proveToRelationsWithExtension(
                allocator,
                channel,
                core,
                Frame(Engine){
                    .projection_identity = self.projection.identity,
                    .provider_stage_a = self.provider_stage_a,
                    .tree0_root = roots.items[0],
                    .tree1_root = roots.items[1],
                },
            );
            self.shared_relation = try makeSharedRelation(
                Engine,
                self,
                roots.items[0],
                roots.items[1],
                prefix,
            );
            return prefix;
        }

        pub fn verifyRelations(
            self: *Self,
            allocator: std.mem.Allocator,
            pcs_config: pcs_core.PcsConfig,
            channel: *Engine.Channel,
            native: *const statement_v2.RiscVStatementV2,
            core: *const statement.RiscVStatement,
            extension: *const ethereum_statement.Statement,
            manifest: *const lookup_physical_v2.Manifest,
            authenticated: *const lookup_physical_v2.AuthenticatedStatement,
            interaction_pow: u64,
            tree0_root: Engine.Hasher.Hash,
            tree1_root: Engine.Hasher.Hash,
        ) !ethereum_transcript.Relations {
            _ = pcs_config;
            try self.validateProjectedAuthority(
                native,
                core,
                extension,
                manifest,
                authenticated,
            );
            return self.verifyRelationsAfterValidation(
                allocator,
                channel,
                core,
                interaction_pow,
                tree0_root,
                tree1_root,
            );
        }

        pub fn verifyRelationsWithRetirementSupplementV2(
            self: *Self,
            allocator: std.mem.Allocator,
            pcs_config: pcs_core.PcsConfig,
            channel: *Engine.Channel,
            native: *const statement_v2.RiscVStatementV2,
            core: *const statement.RiscVStatement,
            extension: *const ethereum_statement.Statement,
            manifest: *const lookup_physical_v2.Manifest,
            authenticated: *const lookup_physical_v2.AuthenticatedStatement,
            supplement: statement_validation.RetirementSupplementV2,
            interaction_pow: u64,
            tree0_root: Engine.Hasher.Hash,
            tree1_root: Engine.Hasher.Hash,
        ) !ethereum_transcript.Relations {
            _ = pcs_config;
            try self.validateProjectedAuthorityWithRetirementSupplementV2(
                native,
                core,
                extension,
                manifest,
                authenticated,
                supplement,
            );
            return self.verifyRelationsAfterValidation(
                allocator,
                channel,
                core,
                interaction_pow,
                tree0_root,
                tree1_root,
            );
        }

        fn verifyRelationsAfterValidation(
            self: *Self,
            allocator: std.mem.Allocator,
            channel: *Engine.Channel,
            core: *const statement.RiscVStatement,
            interaction_pow: u64,
            tree0_root: Engine.Hasher.Hash,
            tree1_root: Engine.Hasher.Hash,
        ) !ethereum_transcript.Relations {
            const relations = try ethereum_transcript.verifyToRelationsWithExtension(
                allocator,
                channel,
                core,
                interaction_pow,
                Frame(Engine){
                    .projection_identity = self.projection.identity,
                    .provider_stage_a = self.provider_stage_a,
                    .tree0_root = tree0_root,
                    .tree1_root = tree1_root,
                },
            );
            const shared = try makeSharedRelationFromRelations(
                Engine,
                self,
                tree0_root,
                tree1_root,
                interaction_pow,
                relations,
            );
            if (self.expected_shared_relation) |expected| {
                try expected.validate(
                    self.plan,
                    self.provider_stage_a,
                    &self.projection,
                );
                if (!std.meta.eql(expected, shared))
                    return error.EthereumProviderSharedAuthorityMismatch;
            }
            self.shared_relation = shared;
            return relations;
        }

        fn validateProjectedAuthority(
            self: *const Self,
            native: *const statement_v2.RiscVStatementV2,
            core: *const statement.RiscVStatement,
            extension: *const ethereum_statement.Statement,
            manifest: *const lookup_physical_v2.Manifest,
            authenticated: *const lookup_physical_v2.AuthenticatedStatement,
        ) !void {
            try self.provider_stage_a.validate(self.plan, self.calls);
            const projection = try self.providerProjection();
            try projection.validateAgainst(
                native,
                extension,
                .proof,
                manifest,
                authenticated,
                self.plan,
                self.calls,
                try omission.deriveFullGeometry(native),
            );
            if (!std.meta.eql(core.*, projection.projected_native.core))
                return error.ProjectedCoreMismatch;
        }

        fn validateProjectedAuthorityWithRetirementSupplementV2(
            self: *const Self,
            native: *const statement_v2.RiscVStatementV2,
            core: *const statement.RiscVStatement,
            extension: *const ethereum_statement.Statement,
            manifest: *const lookup_physical_v2.Manifest,
            authenticated: *const lookup_physical_v2.AuthenticatedStatement,
            supplement: statement_validation.RetirementSupplementV2,
        ) !void {
            try self.provider_stage_a.validate(self.plan, self.calls);
            const projection = try self.providerProjection();
            try projection.validateAgainstWithRetirementSupplementV2(
                native,
                extension,
                .proof,
                supplement,
                manifest,
                authenticated,
                self.plan,
                self.calls,
                try omission.deriveFullGeometry(native),
            );
            if (!std.meta.eql(core.*, projection.projected_native.core))
                return error.ProjectedCoreMismatch;
        }
    };
}

pub fn Replay(comptime Engine: type) type {
    return struct {
        channel: Engine.Channel,
        relations: ethereum_transcript.Relations,
        authority_value: SharedRelationAuthorityV1(Engine),
    };
}

pub fn replaySharedTranscript(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    native: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    projection: *const omission.ProjectionV1,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    provider_stage_a: *const ProviderStageAManifestV1(Engine),
    shared: SharedRelationAuthorityV1(Engine),
) !Replay(Engine) {
    try provider_stage_a.validate(plan, calls);
    try projection.validateAgainst(
        native,
        extension,
        .proof,
        manifest,
        authenticated,
        plan,
        calls,
        try omission.deriveFullGeometry(native),
    );
    try shared.validate(plan, provider_stage_a, projection);
    var channel = Engine.Channel{};
    pcs_config.mixInto(&channel);
    try statement_v2.mixIntoNativeTranscript(&native.public_data, &channel);
    authenticated.mixInto(&channel);
    try extension.mixIntoV2(native, &channel);
    Engine.MerkleChannel.mixRoot(&channel, shared.tree0_root);
    Engine.MerkleChannel.mixRoot(&channel, shared.tree1_root);
    const relations = try ethereum_transcript.verifyToRelationsWithExtension(
        allocator,
        &channel,
        &projection.projected_native.core,
        shared.interaction_pow,
        Frame(Engine){
            .projection_identity = projection.identity,
            .provider_stage_a = provider_stage_a,
            .tree0_root = shared.tree0_root,
            .tree1_root = shared.tree1_root,
        },
    );
    const relation_context = try authority.PoseidonRelationContextV1.canonical(
        plan.session,
        relations.base.poseidon2.z,
        relations.base.poseidon2.alpha,
    );
    if (!std.meta.eql(relation_context, shared.relation_context))
        return error.EthereumProviderRelationContextMismatch;
    return .{
        .channel = channel,
        .relations = relations,
        .authority_value = shared,
    };
}

pub fn providerLocalPrefixV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    native: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    projection: *const omission.ProjectionV1,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    provider_stage_a: *const ProviderStageAManifestV1(Engine),
    shared: SharedRelationAuthorityV1(Engine),
    claim: authority.ProviderShardClaimV1,
    ordered_call_claim: provider_order.ClaimV1,
) !Engine.Channel {
    var replay = try replaySharedTranscript(
        Engine,
        allocator,
        pcs_config,
        native,
        extension,
        manifest,
        authenticated,
        projection,
        plan,
        calls,
        provider_stage_a,
        shared,
    );
    const index = std.math.cast(usize, claim.shard_index) orelse
        return error.ShardIndexOutOfRange;
    if (index >= plan.shards.len) return error.ShardIndexOutOfRange;
    const descriptor = plan.shards[index];
    const record = provider_stage_a.providers[index];
    if (!aggregation_hash.eql(claim.plan_identity, plan.identity) or
        !aggregation_hash.eql(claim.descriptor_identity, descriptor.identity) or
        !aggregation_hash.eql(
            claim.relation_context_identity,
            shared.relation_context.identity,
        )) return error.InvalidEthereumProviderClaimAuthority;
    if (ordered_call_claim.format != provider_order.format_version or
        ordered_call_claim.first_call != descriptor.first_call or
        ordered_call_claim.call_count != descriptor.call_count)
    {
        return error.InvalidProviderOrderClaim;
    }
    replay.channel.mixU32s(&provider_local_v2_domain_words);
    mixDigest(&replay.channel, provider_stage_a.identity);
    mixDigest(&replay.channel, record.identity);
    mixDigest(&replay.channel, plan.call_list_commitment);
    replay.channel.mixU64(claim.shard_index);
    replay.channel.mixU64(descriptor.first_call);
    replay.channel.mixU64(descriptor.call_count);
    replay.channel.mixU64(provider_order.interaction_column_count);
    replay.channel.mixFelts(&claim.claims.sums);
    replay.channel.mixU64(ordered_call_claim.format);
    replay.channel.mixU64(ordered_call_claim.first_call);
    replay.channel.mixU64(ordered_call_claim.call_count);
    replay.channel.mixFelts(&.{ordered_call_claim.terminal});
    return replay.channel;
}

/// Appends the provider-local V2 statement frame to a caller-owned replay
/// channel. Candidate leaf protocols use this after replaying their larger
/// pre-Tree0 authority; the ordinary entrypoint above remains byte-identical.
pub fn appendProviderLocalFrameV2(
    channel: anytype,
    plan: *const authority.ProviderShardPlanV1,
    provider_stage_a: anytype,
    shared_relation_context_identity: Digest,
    claim: authority.ProviderShardClaimV1,
    ordered_call_claim: provider_order.ClaimV1,
) !void {
    const index = std.math.cast(usize, claim.shard_index) orelse
        return error.ShardIndexOutOfRange;
    if (index >= plan.shards.len or index >= provider_stage_a.providers.len)
        return error.ShardIndexOutOfRange;
    const descriptor = plan.shards[index];
    const record = provider_stage_a.providers[index];
    if (!aggregation_hash.eql(claim.plan_identity, plan.identity) or
        !aggregation_hash.eql(claim.descriptor_identity, descriptor.identity) or
        !aggregation_hash.eql(
            claim.relation_context_identity,
            shared_relation_context_identity,
        )) return error.InvalidEthereumProviderClaimAuthority;
    if (ordered_call_claim.format != provider_order.format_version or
        ordered_call_claim.first_call != descriptor.first_call or
        ordered_call_claim.call_count != descriptor.call_count)
    {
        return error.InvalidProviderOrderClaim;
    }
    channel.mixU32s(&provider_local_v2_domain_words);
    mixDigest(channel, provider_stage_a.identity);
    mixDigest(channel, record.identity);
    mixDigest(channel, plan.call_list_commitment);
    channel.mixU64(claim.shard_index);
    channel.mixU64(descriptor.first_call);
    channel.mixU64(descriptor.call_count);
    channel.mixU64(provider_order.interaction_column_count);
    channel.mixFelts(&claim.claims.sums);
    channel.mixU64(ordered_call_claim.format);
    channel.mixU64(ordered_call_claim.first_call);
    channel.mixU64(ordered_call_claim.call_count);
    channel.mixFelts(&.{ordered_call_claim.terminal});
}

/// Public type alias for the canonical provider Stage-A frame. It permits an
/// additive candidate transcript replay without duplicating the root/order
/// schedule; ordinary callers continue to instantiate the private alias.
pub fn ProviderFrameV1(comptime Engine: type) type {
    return Frame(Engine);
}

fn Frame(comptime Engine: type) type {
    return struct {
        projection_identity: Digest,
        provider_stage_a: *const ProviderStageAManifestV1(Engine),
        tree0_root: Engine.Hasher.Hash,
        tree1_root: Engine.Hasher.Hash,

        pub fn mixInto(self: @This(), channel: anytype) void {
            channel.mixU32s(&frame_domain_words);
            mixDigest(channel, self.projection_identity);
            mixDigest(channel, self.provider_stage_a.identity);
            mixDigest(channel, self.provider_stage_a.plan_identity);
            mixDigest(channel, self.provider_stage_a.session);
            mixDigest(channel, self.provider_stage_a.call_list_commitment);
            channel.mixU64(self.provider_stage_a.providers.len);
            for (self.provider_stage_a.providers) |record| {
                mixDigest(channel, record.identity);
                mixDigest(channel, record.descriptor_identity);
                channel.mixU64(record.shard_index);
                channel.mixU64(record.shard_count);
                channel.mixU64(record.first_call);
                channel.mixU64(record.call_count);
                channel.mixU64(record.expected_log_size);
                Engine.MerkleChannel.mixRoot(channel, record.preprocessed_root);
                Engine.MerkleChannel.mixRoot(channel, record.main_root);
            }
            Engine.MerkleChannel.mixRoot(channel, self.tree0_root);
            Engine.MerkleChannel.mixRoot(channel, self.tree1_root);
        }
    };
}

fn providerManifestIdentity(
    comptime Engine: type,
    value: *const ProviderStageAManifestV1(Engine),
) Digest {
    var sink = aggregation_hash.HashSink.init(provider_manifest_domain);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.plan_identity) catch unreachable;
    sink.writeAll(&value.session) catch unreachable;
    sink.writeAll(&value.call_list_commitment) catch unreachable;
    aggregation_hash.writeU32(&sink, @intCast(value.providers.len)) catch unreachable;
    for (value.providers) |record| {
        sink.writeAll(&record.identity) catch unreachable;
        writeRoot(&sink, record.preprocessed_root);
        writeRoot(&sink, record.main_root);
    }
    return sink.finalize();
}

fn makeSharedRelation(
    comptime Engine: type,
    extension: *const Extension(Engine),
    tree0_root: Engine.Hasher.Hash,
    tree1_root: Engine.Hasher.Hash,
    prefix: ethereum_transcript.Prefix,
) !SharedRelationAuthorityV1(Engine) {
    return makeSharedRelationFromRelations(
        Engine,
        extension,
        tree0_root,
        tree1_root,
        prefix.interaction_pow,
        prefix.relations,
    );
}

fn makeSharedRelationFromRelations(
    comptime Engine: type,
    extension: *const Extension(Engine),
    tree0_root: Engine.Hasher.Hash,
    tree1_root: Engine.Hasher.Hash,
    interaction_pow: u64,
    relations: ethereum_transcript.Relations,
) !SharedRelationAuthorityV1(Engine) {
    var result = SharedRelationAuthorityV1(Engine){
        .format = format_version,
        .plan_identity = extension.plan.identity,
        .manifest_identity = extension.provider_stage_a.identity,
        .projection_identity = extension.projection.identity,
        .tree0_root = tree0_root,
        .tree1_root = tree1_root,
        .interaction_pow_bits = interaction_pow_bits,
        .interaction_pow = interaction_pow,
        .relation_context = try authority.PoseidonRelationContextV1.canonical(
            extension.plan.session,
            relations.base.poseidon2.z,
            relations.base.poseidon2.alpha,
        ),
        .identity = undefined,
    };
    result.identity = sharedRelationIdentity(Engine, result);
    try result.validate(
        extension.plan,
        extension.provider_stage_a,
        &extension.projection,
    );
    return result;
}

fn sharedRelationIdentity(
    comptime Engine: type,
    value: SharedRelationAuthorityV1(Engine),
) Digest {
    var sink = aggregation_hash.HashSink.init(shared_relation_domain);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.plan_identity) catch unreachable;
    sink.writeAll(&value.manifest_identity) catch unreachable;
    sink.writeAll(&value.projection_identity) catch unreachable;
    writeRoot(&sink, value.tree0_root);
    writeRoot(&sink, value.tree1_root);
    aggregation_hash.writeU32(&sink, value.interaction_pow_bits) catch unreachable;
    aggregation_hash.writeU64(&sink, value.interaction_pow) catch unreachable;
    sink.writeAll(&value.relation_context.identity) catch unreachable;
    return sink.finalize();
}

pub fn freshCoreResidualIdentity(value: FreshCoreResidualV1) Digest {
    var sink = aggregation_hash.HashSink.init(fresh_core_residual_domain);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.plan_identity) catch unreachable;
    sink.writeAll(&value.manifest_identity) catch unreachable;
    sink.writeAll(&value.projection_identity) catch unreachable;
    sink.writeAll(&value.relation_context_identity) catch unreachable;
    sink.writeAll(&value.proof_commitments_identity) catch unreachable;
    sink.writeAll(&.{
        @intFromBool(value.fresh_core_stark_verified),
        @intFromBool(value.non_poseidon_buses_closed),
        @intFromBool(value.production_eligible),
        @intFromBool(value.recursive_admissible),
    }) catch unreachable;
    hashQm31(&sink, value.poseidon2_residual);
    return sink.finalize();
}

pub fn closureIdentity(value: VerifiedJointClosureV1) Digest {
    var sink = aggregation_hash.HashSink.init(closure_domain);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.plan_identity) catch unreachable;
    sink.writeAll(&value.manifest_identity) catch unreachable;
    sink.writeAll(&value.relation_context_identity) catch unreachable;
    sink.writeAll(&value.core_claim_identity) catch unreachable;
    sink.writeAll(&value.ordered_provider_claims_identity) catch unreachable;
    aggregation_hash.writeU32(&sink, value.shard_count) catch unreachable;
    hashQm31(&sink, value.core_claim);
    hashQm31(&sink, value.provider_claim);
    hashQm31(&sink, value.closed_sum);
    sink.writeAll(&.{
        @intFromBool(value.core_freshly_verified),
        @intFromBool(value.every_provider_freshly_verified),
        @intFromBool(value.every_ordered_call_air_verified),
        @intFromBool(value.complete_ordered_coverage),
        @intFromBool(value.one_shared_relation_context),
        @intFromBool(value.omit_recompute_owner_verified),
        @intFromBool(value.production_eligible),
        @intFromBool(value.recursive_admissible),
    }) catch unreachable;
    return sink.finalize();
}

fn hashQm31(sink: anytype, value: QM31) void {
    for (value.toM31Array()) |word|
        aggregation_hash.writeU32(sink, word.toU32()) catch unreachable;
}

fn writeRoot(sink: anytype, root: anytype) void {
    const bytes = std.mem.asBytes(&root);
    aggregation_hash.writeU32(sink, bytes.len) catch unreachable;
    sink.writeAll(bytes) catch unreachable;
}

fn mixDigest(channel: anytype, digest: Digest) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index|
        word.* = std.mem.readInt(u32, digest[index * 4 ..][0..4], .little);
    channel.mixU32s(&words);
}

const provider_manifest_domain =
    "stwo-zig/riscv/ethereum/native-provider-stage-a-manifest/v1\x00";
const shared_relation_domain =
    "stwo-zig/riscv/ethereum/native-provider-shared-relation/v1\x00";
const fresh_core_residual_domain =
    "stwo-zig/riscv/ethereum/native-provider-fresh-core-residual/v1\x00";
const closure_domain =
    "stwo-zig/riscv/ethereum/native-provider-joint-closure/v1\x00";
const frame_domain_words = [7]u32{
    0x5354_5742, // STWB
    0x4d4f_4854, // THOM
    0x4d45_5254, // TREM
    format_version,
    @intFromBool(OMIT_RECOMPUTE_CORE_IMPLEMENTED),
    @intFromBool(FRESH_PROVIDER_CLOSURE_REQUIRED),
    @intFromBool(ACTIVATES_PRODUCTION_PROOF),
};
const provider_local_v2_domain_words = [4]u32{
    0x5354_5745, // STWE
    0x5052_5632, // PRV2
    format_version,
    12,
};

comptime {
    if (!OMIT_RECOMPUTE_CORE_IMPLEMENTED or !FRESH_PROVIDER_CLOSURE_REQUIRED or
        ACTIVATES_PRODUCTION_PROOF)
    {
        @compileError("Ethereum provider omission remains nonproduction until fresh closure");
    }
}
