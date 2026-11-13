//! Live provider omission extension; canonical manifest and closure records stay in ethereum_omit_protocol.
const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const statement_v2 = @import("stwo_riscv_rv32").air.statement_v2;
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const poseidon2_air = @import("stwo_riscv_memory").air.poseidon2_air;
const lookup_physical_v2 = @import("stwo_riscv_rv32").air.lang.lookup_physical_manifest;
const statement = @import("stwo_riscv_rv32").air.statement;
const statement_geometry = @import("stwo_riscv_rv32").prover.statement_geometry;
const statement_validation = @import("stwo_riscv_rv32").prover.statement_validation;
const ethereum_transcript = @import("../guest_precompile/ethereum_transcript.zig");
const authority = @import("stwo_riscv_memory").prover.authority;
const proof_authority = @import("stwo_riscv_rv32").prover.memory_provider_shards.joint_proof_authority;
const omission = @import("native_provider_omit.zig");
const Frame = @import("ethereum_omit_shared_relation.zig").Frame;
const makeSharedRelation = @import("ethereum_omit_shared_relation.zig").makeSharedRelation;
const makeSharedRelationFromRelations = @import("ethereum_omit_shared_relation.zig").makeSharedRelationFromRelations;
const Digest = @import("ethereum_omit_protocol.zig").Digest;
const FreshCoreResidualV1 = @import("ethereum_omit_protocol.zig").FreshCoreResidualV1;
const ProviderStageAManifestV1 = @import("ethereum_omit_protocol.zig").ProviderStageAManifestV1;
const SharedRelationAuthorityV1 = @import("ethereum_omit_protocol.zig").SharedRelationAuthorityV1;
const format_version = @import("ethereum_omit_protocol.zig").format_version;
const freshCoreResidualIdentity = @import("ethereum_omit_protocol.zig").freshCoreResidualIdentity;

pub fn Extension(comptime Engine: type) type {
    return struct {
        plan: *const authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        provider_stage_a: *const ProviderStageAManifestV1(Engine),
        /// Optional O(1) readmission authority for `plan`/`calls`. When it is
        /// present every corpus readmission this extension performs is a
        /// pointer-closed check instead of a full rehash; nothing else about
        /// the extension changes.
        validated: ?*const authority.OwnedValidatedPlanCallAuthorityV1 = null,
        projection: omission.ProjectionV1 = undefined,
        projection_ready: bool = false,
        prover_residual: ?QM31 = null,
        fresh_verifier_residual: ?QM31 = null,
        shared_relation: ?SharedRelationAuthorityV1(Engine) = null,
        expected_shared_relation: ?SharedRelationAuthorityV1(Engine) = null,
        fresh_core: ?FreshCoreResidualV1 = null,

        const Self = @This();

        fn validateManifest(manifest: *const ProviderStageAManifestV1(Engine), plan: *const authority.ProviderShardPlanV1, calls: []const poseidon2_air.Call, validated: ?*const authority.OwnedValidatedPlanCallAuthorityV1) !void {
            if (validated) |token| return manifest.validateBorrowedValidated(plan, calls, token);
            return manifest.validate(plan, calls);
        }

        pub fn init(
            plan: *const authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            provider_stage_a: *const ProviderStageAManifestV1(Engine),
        ) !Self {
            return initInternal(plan, calls, null, provider_stage_a);
        }

        /// Identity-neutral sibling of `init`. The token is retained so every
        /// later corpus readmission on this extension is O(1).
        pub fn initValidated(
            plan: *const authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            validated: *const authority.OwnedValidatedPlanCallAuthorityV1,
            provider_stage_a: *const ProviderStageAManifestV1(Engine),
        ) !Self {
            return initInternal(plan, calls, validated, provider_stage_a);
        }

        fn initInternal(
            plan: *const authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            validated: ?*const authority.OwnedValidatedPlanCallAuthorityV1,
            provider_stage_a: *const ProviderStageAManifestV1(Engine),
        ) !Self {
            try validateManifest(provider_stage_a, plan, calls, validated);
            return .{
                .plan = plan,
                .calls = calls,
                .provider_stage_a = provider_stage_a,
                .validated = validated,
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

        /// Identity-neutral sibling of `initForFreshVerify`.
        pub fn initForFreshVerifyValidated(
            plan: *const authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            validated: *const authority.OwnedValidatedPlanCallAuthorityV1,
            provider_stage_a: *const ProviderStageAManifestV1(Engine),
            expected_shared_relation: SharedRelationAuthorityV1(Engine),
        ) !Self {
            var result = try initValidated(
                plan,
                calls,
                validated,
                provider_stage_a,
            );
            result.expected_shared_relation = expected_shared_relation;
            return result;
        }

        /// Explicit validated entry to `prepareProjectedCore`. The retained
        /// token must be the one this extension was built with; the projected
        /// core, its identity, and the installed workspace are unchanged.
        pub fn prepareProjectedCoreValidated(
            self: *Self,
            native: *const statement_v2.RiscVStatementV2,
            extension: *const ethereum_statement.Statement,
            manifest: *const lookup_physical_v2.Manifest,
            authenticated: *const lookup_physical_v2.AuthenticatedStatement,
            validated: *const authority.OwnedValidatedPlanCallAuthorityV1,
            workspace_core: *statement.RiscVStatement,
            full_geometry: statement_geometry.Geometry,
        ) !void {
            if (self.validated != validated)
                return error.InvalidValidatedProviderPlanCallAuthority;
            return self.prepareProjectedCore(
                native,
                extension,
                manifest,
                authenticated,
                workspace_core,
                full_geometry,
            );
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
            self.projection = if (self.validated) |token|
                try omission.ProjectionV1.initValidated(
                    native,
                    extension,
                    .proof,
                    manifest,
                    authenticated,
                    self.plan,
                    self.calls,
                    token,
                    full_geometry,
                )
            else
                try omission.ProjectionV1.init(
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
            self.projection = if (self.validated) |token|
                try omission.ProjectionV1
                    .initWithRetirementSupplementV2Validated(
                    native,
                    extension,
                    .proof,
                    supplement,
                    manifest,
                    authenticated,
                    self.plan,
                    self.calls,
                    token,
                    full_geometry,
                )
            else
                try omission.ProjectionV1.initWithRetirementSupplementV2(
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
            try validateManifest(
                self.provider_stage_a,
                self.plan,
                self.calls,
                self.validated,
            );
            const projection = try self.providerProjection();
            if (self.validated) |token|
                try projection.validateAgainstValidated(
                    native,
                    extension,
                    .proof,
                    manifest,
                    authenticated,
                    self.plan,
                    self.calls,
                    token,
                    try omission.deriveFullGeometry(native),
                )
            else
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
            try validateManifest(
                self.provider_stage_a,
                self.plan,
                self.calls,
                self.validated,
            );
            const projection = try self.providerProjection();
            if (self.validated) |token|
                try projection
                    .validateAgainstWithRetirementSupplementV2Validated(
                    native,
                    extension,
                    .proof,
                    supplement,
                    manifest,
                    authenticated,
                    self.plan,
                    self.calls,
                    token,
                    try omission.deriveFullGeometry(native),
                )
            else
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
