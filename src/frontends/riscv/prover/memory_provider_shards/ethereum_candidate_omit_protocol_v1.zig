//! Candidate-only shared transcript for a provider-omitted Ethereum leaf.
//!
//! The canonical provider frame remains unchanged. This sibling additionally
//! replays the full candidate Profile and verifier-derived Admission before
//! Tree 0, then draws the bulk-memcpy and stack-SWAP call relations after the
//! ordinary Ethereum relation suite. Provider proofs consume the same base
//! Poseidon relation context, but their authority is explicitly bound to the
//! larger transcript and cannot be relabelled as an ordinary Ethereum proof.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const aggregation_hash = @import("../../aggregation/hash.zig");
const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const base_statement = @import("../../air/statement.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const combined_authority =
    @import("../../isa/ethereum_candidate_combined_authority_v1.zig");
const candidate_admission = @import("../guest_precompile/ethereum_candidate_leaf_admission_v1.zig");
const candidate_integration = @import("../guest_precompile/ethereum_candidate_leaf_integration_v1.zig");
const candidate_profile = @import("../guest_precompile/ethereum_candidate_leaf_profile_v1.zig");
const ethereum_transcript = @import("../guest_precompile/ethereum_transcript.zig");
const provider_authority = @import("authority.zig");
const omission = @import("native_provider_omit_v1.zig");
const ordinary = @import("ethereum_omit_protocol_v1.zig");
const provider_order = @import("provider_order_component.zig");

pub const format_version: u32 = 1;
pub const production_active = false;
pub const Digest = aggregation_hash.Digest;

const DerivedProfileV1 = struct {
    authority: combined_authority.Authority,
    bulk_memcpy_call_count: u32,
    bulk_memcpy_word_row_count: u32,
    stack_swap_call_count: u32,
};

/// Exact field-native authority for the four appended challenge draws. The
/// digest is custody only; validation and replay compare every QM31 value.
pub const CandidateCallRelationAuthorityV1 = struct {
    format: u32 = format_version,
    bulk_memcpy_z: QM31,
    bulk_memcpy_alpha: QM31,
    stack_swap_z: QM31,
    stack_swap_alpha: QM31,
    identity: Digest,

    pub fn create(
        relations: candidate_integration.Relations,
    ) !CandidateCallRelationAuthorityV1 {
        try relations.validate();
        var result = CandidateCallRelationAuthorityV1{
            .bulk_memcpy_z = relations.bulk_memcpy.call.z,
            .bulk_memcpy_alpha = relations.bulk_memcpy.call.alpha,
            .stack_swap_z = relations.stack_swap.call.z,
            .stack_swap_alpha = relations.stack_swap.call.alpha,
            .identity = undefined,
        };
        result.identity = candidateCallRelationIdentity(result);
        try result.validateAgainst(relations);
        return result;
    }

    pub fn validateAgainst(
        self: CandidateCallRelationAuthorityV1,
        relations: candidate_integration.Relations,
    ) !void {
        try relations.validate();
        if (self.format != format_version or
            !self.bulk_memcpy_z.eql(relations.bulk_memcpy.call.z) or
            !self.bulk_memcpy_alpha.eql(relations.bulk_memcpy.call.alpha) or
            !self.stack_swap_z.eql(relations.stack_swap.call.z) or
            !self.stack_swap_alpha.eql(relations.stack_swap.call.alpha) or
            !aggregation_hash.eql(
                self.identity,
                candidateCallRelationIdentity(self),
            ))
        {
            return error.InvalidEthereumCandidateCallRelationAuthority;
        }
    }
};

pub fn SharedRelationAuthorityV1(comptime Engine: type) type {
    return struct {
        format: u32 = format_version,
        ordinary: ordinary.SharedRelationAuthorityV1(Engine),
        profile_identity: Digest,
        admission: candidate_admission.Admission,
        candidate_call_relations: CandidateCallRelationAuthorityV1,
        relation_context: provider_authority.PoseidonRelationContextV1,
        identity: Digest,

        const Self = @This();

        pub fn create(
            ordinary_authority: ordinary.SharedRelationAuthorityV1(Engine),
            profile: *const candidate_profile.Profile,
            admission: candidate_admission.Admission,
            relations: candidate_integration.Relations,
        ) !Self {
            var result = Self{
                .ordinary = ordinary_authority,
                .profile_identity = profile.identity,
                .admission = admission,
                .candidate_call_relations = try .create(relations),
                .relation_context = ordinary_authority.relation_context,
                .identity = undefined,
            };
            result.identity = sharedRelationIdentity(Engine, result);
            return result;
        }

        pub fn validate(
            self: Self,
            native: *const statement_v2.RiscVStatementV2,
            extension: *const ethereum_statement.Statement,
            base_interaction_columns: u32,
            profile: *const candidate_profile.Profile,
            plan: *const provider_authority.ProviderShardPlanV1,
            provider_stage_a: *const ordinary.ProviderStageAManifestV1(Engine),
            projection: *const omission.ProjectionV1,
        ) !void {
            try self.ordinary.validate(plan, provider_stage_a, projection);
            try profile.validate(
                &projection.projected_native.core,
                extension,
                base_interaction_columns,
            );
            const expected_admission = try candidate_admission
                .validateProjectedV2(
                native,
                &projection.projected_native.core,
                extension,
                base_interaction_columns,
                profile,
                .proof,
            );
            if (!std.meta.eql(self.admission, expected_admission) or
                self.format != format_version or
                !aggregation_hash.eql(self.profile_identity, profile.identity) or
                !std.meta.eql(
                    self.relation_context,
                    self.ordinary.relation_context,
                ) or !aggregation_hash.eql(
                self.identity,
                sharedRelationIdentity(Engine, self),
            )) {
                return error.InvalidEthereumCandidateSharedAuthority;
            }
        }
    };
}

pub fn Replay(comptime Engine: type) type {
    return struct {
        channel: Engine.Channel,
        /// Ordinary relations are exposed for the d5 provider component.
        relations: ethereum_transcript.Relations,
        candidate_relations: candidate_integration.Relations,
        authority_value: SharedRelationAuthorityV1(Engine),
    };
}

/// Transaction-local extension installed in the candidate leaf prover and
/// fresh verifier. Tree-0 generation is the sole owner of Profile+Admission
/// mixing; this hook appends challenge draws and mints their exact authority.
pub fn Extension(comptime Engine: type) type {
    return struct {
        inner: ordinary.Extension(Engine),
        profile: candidate_profile.Profile = undefined,
        profile_ready: bool = false,
        derived_profile: ?DerivedProfileV1 = null,
        shared_relation: ?SharedRelationAuthorityV1(Engine) = null,
        expected_shared_relation: ?SharedRelationAuthorityV1(Engine) = null,

        const Self = @This();

        pub fn init(
            plan: *const provider_authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            provider_stage_a: *const ordinary.ProviderStageAManifestV1(Engine),
            profile: *const candidate_profile.Profile,
        ) !Self {
            return .{
                .inner = try .init(plan, calls, provider_stage_a),
                .profile = profile.*,
                .profile_ready = true,
            };
        }

        /// Prover-only initialization before the projected core exists. The
        /// exact profile is derived immediately after provider omission and
        /// before Tree 0 or any candidate transcript field is consumed.
        pub fn initDerivedForProver(
            plan: *const provider_authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            provider_stage_a: *const ordinary.ProviderStageAManifestV1(Engine),
            authority: combined_authority.Authority,
            bulk_memcpy_call_count: u32,
            bulk_memcpy_word_row_count: u32,
            stack_swap_call_count: u32,
        ) !Self {
            try authority.validate();
            return .{
                .inner = try .init(plan, calls, provider_stage_a),
                .derived_profile = .{
                    .authority = authority,
                    .bulk_memcpy_call_count = bulk_memcpy_call_count,
                    .bulk_memcpy_word_row_count = bulk_memcpy_word_row_count,
                    .stack_swap_call_count = stack_swap_call_count,
                },
            };
        }

        pub fn initForFreshVerify(
            plan: *const provider_authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            provider_stage_a: *const ordinary.ProviderStageAManifestV1(Engine),
            profile: *const candidate_profile.Profile,
            expected: SharedRelationAuthorityV1(Engine),
        ) !Self {
            return .{
                .inner = try .initForFreshVerify(
                    plan,
                    calls,
                    provider_stage_a,
                    expected.ordinary,
                ),
                .profile = profile.*,
                .profile_ready = true,
                .expected_shared_relation = expected,
            };
        }

        pub fn profileValue(self: *const Self) !*const candidate_profile.Profile {
            if (!self.profile_ready)
                return error.EthereumCandidateProfileNotReady;
            return &self.profile;
        }

        pub fn prepareProjectedCore(
            self: *Self,
            native: *const statement_v2.RiscVStatementV2,
            extension: *const ethereum_statement.Statement,
            manifest: *const lookup_physical_v2.Manifest,
            authenticated: *const lookup_physical_v2.AuthenticatedStatement,
            workspace_core: *base_statement.RiscVStatement,
            full_geometry: @import("../statement_geometry.zig").Geometry,
        ) !void {
            const full_base_columns: u32 = @intCast(
                try authenticated.totalInteractionColumns(
                    &native.core,
                    manifest,
                ),
            );
            const preprojection_profile = try self.preprojectionProfile(
                &native.core,
                extension,
                full_base_columns,
            );
            const preprojection_admission = try candidate_admission.validateV2(
                native,
                extension,
                full_base_columns,
                &preprojection_profile,
                .proof,
            );
            try self.inner.prepareProjectedCoreWithRetirementSupplementV2(
                native,
                extension,
                manifest,
                authenticated,
                workspace_core,
                full_geometry,
                preprojection_admission.retirementSupplementV2(),
            );
            if (self.derived_profile) |derived| {
                const base_columns: u32 = @intCast(
                    try authenticated.totalInteractionColumns(
                        &self.inner.projection.projected_native.core,
                        manifest,
                    ),
                );
                self.profile = try candidate_profile.Profile.create(
                    &self.inner.projection.projected_native.core,
                    extension,
                    base_columns,
                    derived.authority,
                    derived.bulk_memcpy_call_count,
                    derived.bulk_memcpy_word_row_count,
                    derived.stack_swap_call_count,
                );
                self.profile_ready = true;
            }
            const projected_base_columns: u32 = @intCast(
                try authenticated.totalInteractionColumns(
                    &self.inner.projection.projected_native.core,
                    manifest,
                ),
            );
            const projected_admission = try candidate_admission
                .validateProjectedV2(
                native,
                &self.inner.projection.projected_native.core,
                extension,
                projected_base_columns,
                try self.profileValue(),
                .proof,
            );
            if (!std.meta.eql(preprojection_admission, projected_admission))
                return error.EthereumCandidateAdmissionAuthorityMismatch;
        }

        pub fn prepareProjectedVerifierCore(
            self: *Self,
            native: *const statement_v2.RiscVStatementV2,
            extension: *const ethereum_statement.Statement,
            manifest: *const lookup_physical_v2.Manifest,
            authenticated: *const lookup_physical_v2.AuthenticatedStatement,
            workspace_core: *base_statement.RiscVStatement,
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

        fn preprojectionProfile(
            self: *const Self,
            full_core: *const base_statement.RiscVStatement,
            extension: *const ethereum_statement.Statement,
            base_interaction_columns: u32,
        ) !candidate_profile.Profile {
            if (self.derived_profile) |derived| return candidate_profile.Profile
                .create(
                full_core,
                extension,
                base_interaction_columns,
                derived.authority,
                derived.bulk_memcpy_call_count,
                derived.bulk_memcpy_word_row_count,
                derived.stack_swap_call_count,
            );
            const profile = try self.profileValue();
            return candidate_profile.Profile.create(
                full_core,
                extension,
                base_interaction_columns,
                profile.authority,
                profile.bulk_memcpy_call_count,
                profile.bulk_memcpy_word_row_count,
                profile.stack_swap_call_count,
            );
        }

        pub fn providerProjection(self: *const Self) !*const omission.ProjectionV1 {
            return self.inner.providerProjection();
        }

        pub fn providerPlan(self: *const Self) *const provider_authority.ProviderShardPlanV1 {
            return self.inner.providerPlan();
        }

        pub fn providerCalls(self: *const Self) []const poseidon2_air.Call {
            return self.inner.providerCalls();
        }

        pub fn recordProverResidual(self: *Self, residual: QM31) !void {
            return self.inner.recordProverResidual(residual);
        }

        pub fn recordFreshVerifierResidual(self: *Self, residual: QM31) !void {
            return self.inner.recordFreshVerifierResidual(residual);
        }

        pub fn recordFreshVerifierAuthority(
            self: *Self,
            residual: QM31,
            proof_commitments_identity: Digest,
        ) !void {
            return self.inner.recordFreshVerifierAuthority(
                residual,
                proof_commitments_identity,
            );
        }

        pub fn proofCommitmentsIdentity(
            self: *const Self,
            commitments: []const Engine.Hasher.Hash,
        ) Digest {
            return self.inner.proofCommitmentsIdentity(commitments);
        }

        pub fn drawChallenges(
            self: *Self,
            allocator: std.mem.Allocator,
            scheme: *Engine.Scheme,
            channel: *Engine.Channel,
            native: *const statement_v2.RiscVStatementV2,
            core: *const base_statement.RiscVStatement,
            extension: *const ethereum_statement.Statement,
            manifest: *const lookup_physical_v2.Manifest,
            authenticated: *const lookup_physical_v2.AuthenticatedStatement,
            recorder: anytype,
        ) !candidate_integration.Prefix {
            const base_columns: u32 = @intCast(
                try authenticated.totalInteractionColumns(core, manifest),
            );
            const admission = try candidate_admission.validateProjectedV2(
                native,
                core,
                extension,
                base_columns,
                try self.profileValue(),
                .proof,
            );
            const prefix = try candidate_integration.appendCandidateRelations(
                allocator,
                channel,
                try self.inner.drawChallengesWithRetirementSupplementV2(
                    allocator,
                    scheme,
                    channel,
                    native,
                    core,
                    extension,
                    manifest,
                    authenticated,
                    admission.retirementSupplementV2(),
                    recorder,
                ),
            );
            const ordinary_shared = self.inner.shared_relation orelse
                return error.MissingEthereumProviderSharedAuthority;
            self.shared_relation = try .create(
                ordinary_shared,
                try self.profileValue(),
                admission,
                prefix.relations,
            );
            return prefix;
        }

        pub fn verifyRelations(
            self: *Self,
            allocator: std.mem.Allocator,
            pcs_config: pcs_core.PcsConfig,
            channel: *Engine.Channel,
            native: *const statement_v2.RiscVStatementV2,
            core: *const base_statement.RiscVStatement,
            extension: *const ethereum_statement.Statement,
            manifest: *const lookup_physical_v2.Manifest,
            authenticated: *const lookup_physical_v2.AuthenticatedStatement,
            interaction_pow: u64,
            tree0_root: Engine.Hasher.Hash,
            tree1_root: Engine.Hasher.Hash,
        ) !candidate_integration.Relations {
            const base_columns: u32 = @intCast(
                try authenticated.totalInteractionColumns(core, manifest),
            );
            const admission = try candidate_admission.validateProjectedV2(
                native,
                core,
                extension,
                base_columns,
                try self.profileValue(),
                .proof,
            );
            const relations = try candidate_integration
                .appendCandidateRelationsAfterVerify(
                allocator,
                channel,
                try self.inner.verifyRelationsWithRetirementSupplementV2(
                    allocator,
                    pcs_config,
                    channel,
                    native,
                    core,
                    extension,
                    manifest,
                    authenticated,
                    admission.retirementSupplementV2(),
                    interaction_pow,
                    tree0_root,
                    tree1_root,
                ),
            );
            const ordinary_shared = self.inner.shared_relation orelse
                return error.MissingEthereumProviderSharedAuthority;
            const actual = try SharedRelationAuthorityV1(Engine).create(
                ordinary_shared,
                try self.profileValue(),
                admission,
                relations,
            );
            if (self.expected_shared_relation) |expected| {
                try expected.validate(
                    native,
                    extension,
                    base_columns,
                    try self.profileValue(),
                    self.inner.plan,
                    self.inner.provider_stage_a,
                    &self.inner.projection,
                );
                if (!std.meta.eql(expected, actual))
                    return error.EthereumCandidateSharedAuthorityMismatch;
            }
            self.shared_relation = actual;
            return relations;
        }
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
    profile: *const candidate_profile.Profile,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    provider_stage_a: *const ordinary.ProviderStageAManifestV1(Engine),
    shared: SharedRelationAuthorityV1(Engine),
) !Replay(Engine) {
    try provider_stage_a.validate(plan, calls);
    const base_columns: u32 = @intCast(
        try authenticated.totalInteractionColumns(
            &projection.projected_native.core,
            manifest,
        ),
    );
    const admission = try candidate_admission.validateProjectedV2(
        native,
        &projection.projected_native.core,
        extension,
        base_columns,
        profile,
        .proof,
    );
    try projection.validateAgainstWithRetirementSupplementV2(
        native,
        extension,
        .proof,
        admission.retirementSupplementV2(),
        manifest,
        authenticated,
        plan,
        calls,
        try omission.deriveFullGeometry(native),
    );
    try shared.validate(
        native,
        extension,
        base_columns,
        profile,
        plan,
        provider_stage_a,
        projection,
    );
    if (!std.meta.eql(shared.admission, admission))
        return error.EthereumCandidateAdmissionAuthorityMismatch;

    var channel = Engine.Channel{};
    pcs_config.mixInto(&channel);
    try statement_v2.mixIntoNativeTranscript(&native.public_data, &channel);
    authenticated.mixInto(&channel);
    try extension.mixIntoV2(native, &channel);
    try candidate_integration.mixPreTree0Authority(
        &channel,
        &projection.projected_native.core,
        extension,
        base_columns,
        profile,
    );
    admission.mixInto(&channel);
    Engine.MerkleChannel.mixRoot(&channel, shared.ordinary.tree0_root);
    Engine.MerkleChannel.mixRoot(&channel, shared.ordinary.tree1_root);
    const ethereum_relations = try ethereum_transcript
        .verifyToRelationsWithExtension(
        allocator,
        &channel,
        &projection.projected_native.core,
        shared.ordinary.interaction_pow,
        ordinary.ProviderFrameV1(Engine){
            .projection_identity = projection.identity,
            .provider_stage_a = provider_stage_a,
            .tree0_root = shared.ordinary.tree0_root,
            .tree1_root = shared.ordinary.tree1_root,
        },
    );
    const relations = try candidate_integration
        .appendCandidateRelationsAfterVerify(
        allocator,
        &channel,
        ethereum_relations,
    );
    try shared.candidate_call_relations.validateAgainst(relations);
    const relation_context = try provider_authority.PoseidonRelationContextV1
        .canonical(
        plan.session,
        relations.ethereum.base.poseidon2.z,
        relations.ethereum.base.poseidon2.alpha,
    );
    if (!std.meta.eql(relation_context, shared.relation_context))
        return error.EthereumProviderRelationContextMismatch;
    return .{
        .channel = channel,
        .relations = ethereum_relations,
        .candidate_relations = relations,
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
    profile: *const candidate_profile.Profile,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    provider_stage_a: *const ordinary.ProviderStageAManifestV1(Engine),
    shared: SharedRelationAuthorityV1(Engine),
    claim: provider_authority.ProviderShardClaimV1,
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
        profile,
        plan,
        calls,
        provider_stage_a,
        shared,
    );
    try ordinary.appendProviderLocalFrameV2(
        &replay.channel,
        plan,
        provider_stage_a,
        shared.relation_context.identity,
        claim,
        ordered_call_claim,
    );
    return replay.channel;
}

fn candidateCallRelationIdentity(
    value: CandidateCallRelationAuthorityV1,
) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/ethereum-candidate-call-relations/v1\x00",
    );
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    writeQm31(&sink, value.bulk_memcpy_z);
    writeQm31(&sink, value.bulk_memcpy_alpha);
    writeQm31(&sink, value.stack_swap_z);
    writeQm31(&sink, value.stack_swap_alpha);
    return sink.finalize();
}

fn sharedRelationIdentity(
    comptime Engine: type,
    value: SharedRelationAuthorityV1(Engine),
) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/ethereum-candidate-shared-relation/v1\x00",
    );
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.ordinary.identity) catch unreachable;
    sink.writeAll(&value.profile_identity) catch unreachable;
    writeAdmission(&sink, value.admission);
    sink.writeAll(&value.candidate_call_relations.identity) catch unreachable;
    sink.writeAll(&value.relation_context.identity) catch unreachable;
    return sink.finalize();
}

fn writeAdmission(sink: anytype, value: candidate_admission.Admission) void {
    aggregation_hash.writeU16(sink, value.format) catch unreachable;
    aggregation_hash.writeU32(sink, value.candidate_retirements) catch unreachable;
    aggregation_hash.writeU32(sink, value.total_external_retirements) catch unreachable;
    aggregation_hash.writeU64(sink, value.candidate_extra_memory_terms) catch unreachable;
    aggregation_hash.writeU64(sink, value.total_extra_memory_terms) catch unreachable;
    aggregation_hash.writeU64(sink, value.expected_memory_relation_terms) catch unreachable;
    for (value.extended_fixed_table_bounds) |bound|
        aggregation_hash.writeU64(sink, bound) catch unreachable;
    sink.writeAll(&.{@intFromBool(value.production_eligible)}) catch unreachable;
}

fn writeQm31(sink: anytype, value: QM31) void {
    for (value.toM31Array()) |limb|
        aggregation_hash.writeU32(sink, limb.v) catch unreachable;
}

comptime {
    if (production_active or ordinary.ACTIVATES_PRODUCTION_PROOF or
        candidate_profile.production_active or
        candidate_admission.production_active or
        candidate_integration.production_active)
    {
        @compileError("candidate provider transcript became active");
    }
}

test "candidate provider transcript binds all four call-relation fields" {
    const base = @import("../../air/relation_challenges.zig").Relations.dummy();
    const ethereum = ethereum_transcript.Relations{
        .base = base,
        .keccak = @import("../../air/guest_precompile/keccakf_relations.zig")
            .Relations.dummy(),
        .secp = @import("../../air/guest_precompile/secp256k1_relations.zig")
            .Relations.dummy(),
    };
    const relations = candidate_integration.Relations{
        .ethereum = ethereum,
        .bulk_memcpy = .{ .base = base, .call = .dummy() },
        .stack_swap = .{ .base = base, .call = .dummy() },
    };
    const authority_value = try CandidateCallRelationAuthorityV1.create(
        relations,
    );
    try authority_value.validateAgainst(relations);

    var wrong = authority_value;
    wrong.stack_swap_alpha = wrong.stack_swap_alpha.add(QM31.one());
    try std.testing.expectError(
        error.InvalidEthereumCandidateCallRelationAuthority,
        wrong.validateAgainst(relations),
    );
}
