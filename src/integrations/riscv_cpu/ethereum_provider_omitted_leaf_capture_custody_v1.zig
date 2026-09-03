//! Cold-derived custody and ordinary-H1 projection for an omitted-provider
//! Ethereum leaf. None of these values can be minted from artifact hashes
//! alone: callers must retain the verifier-owned proof captures.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const support =
    @import("ethereum_provider_omitted_leaf_bundle_v1_support.zig");
const leaf_descriptor =
    @import("recursive_temporal_ethereum_leaf_descriptor_v1.zig");
const incremental_provider =
    @import("recursive_temporal_incremental_provider_authority_v1.zig");

const guest = frontend.prover_mod.guest_precompile;
const d5 = frontend.testing
    .narrow_memory_provider_degree5_ethereum_omit_proof_v1;
const provider_authority = frontend.testing
    .narrow_memory_provider_shard_authority;
const omit_protocol = guest.ethereum_native_provider_omit_protocol_v1;
const native_omit = guest.native_provider_omit_v1;
const source_wire = guest.ethereum_segment_source_wire;
const statement_v1 = frontend.air.statement;
const statement_v2 = frontend.air.statement_v2;
const transcript_claims = frontend.air.transcript;
const ethereum_statement = frontend.air.guest_precompile.ethereum_statement;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const verified_link_mod = frontend.recursion.segment_leaf_local_verified_link_v3;
const program_descriptor =
    frontend.recursion.ethereum_vm_verified_program_descriptor_v1;

const QM31 = core.fields.qm31.QM31;
const transcript_claim_count: usize =
    transcript_claims.COMPONENT_COUNT + ethereum_statement.component_count;

pub fn Tree0AuthorityV1(comptime Engine: type) type {
    return struct {
        projected_core_root: Engine.Hasher.Hash,
        provider_preprocessed_roots: []Engine.Hasher.Hash,
        projection_identity: [32]u8,
        provider_manifest_identity: [32]u8,
        omitted_infra_index: u32,
        omitted_descriptor: statement_v1.InfraComponentDesc,
        identity: [32]u8,

        const Self = @This();

        pub fn validate(
            self: *const Self,
            projection: *const native_omit.ProjectionV1,
            plan: *const provider_authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            manifest: *const omit_protocol.ProviderStageAManifestV1(Engine),
        ) !void {
            try manifest.validate(plan, calls);
            if (self.provider_preprocessed_roots.len != manifest.providers.len or
                !std.meta.eql(self.projection_identity, projection.identity) or
                !std.meta.eql(
                    self.provider_manifest_identity,
                    manifest.identity,
                ) or self.omitted_infra_index != projection.omitted_infra_index or
                !std.meta.eql(
                    self.omitted_descriptor,
                    projection.omitted_descriptor,
                )) return error.InvalidOmittedLeafTree0Authority;
            for (self.provider_preprocessed_roots, manifest.providers) |
                actual,
                expected,
            | if (!std.meta.eql(actual, expected.preprocessed_root))
                return error.InvalidOmittedLeafTree0Authority;
            if (!std.mem.eql(
                u8,
                &self.identity,
                &support.tree0Identity(Engine, self),
            )) return error.InvalidOmittedLeafTree0Authority;
        }
    };
}

pub const ProviderCompilerCustodyV1 = struct {
    entry_continuation_root: u32,
    exit_continuation_root: u32,
    core_proof_artifact_sha256: [32]u8,
    core_proof_capture_sha256: [32]u8,
    core_capture_identity: [32]u8,
    residency_request: @import("stwo_prover_engine").pcs.residency_shard_plan.Request,
    residency_plan: @import("stwo_prover_engine").pcs.residency_shard_plan.Plan,
    provider_claims: []const provider_authority.ProviderShardClaimV1,
    shard_artifacts: []const incremental_provider.ShardArtifactV1,
    compiler: incremental_provider.ProviderCompilerAuthorityV1,

    pub fn input(
        self: *const ProviderCompilerCustodyV1,
        authority: anytype,
        fresh_core: omit_protocol.FreshCoreResidualV1,
    ) incremental_provider.CompilerInputV1 {
        return .{
            .entry_continuation_root = self.entry_continuation_root,
            .exit_continuation_root = self.exit_continuation_root,
            .core_proof_artifact_sha256 = self.core_proof_artifact_sha256,
            .core_proof_capture_sha256 = self.core_proof_capture_sha256,
            .core_capture_identity = self.core_capture_identity,
            .residency_request = self.residency_request,
            .residency_plan = self.residency_plan,
            .provider_plan = authority.plan,
            .calls = authority.calls.calls,
            .relation = authority.shared.relation_context,
            .core_claim = fresh_core.native(),
            .shard_claims = self.provider_claims,
            .shard_artifacts = self.shard_artifacts,
        };
    }

    pub fn validateAgainst(
        self: *const ProviderCompilerCustodyV1,
        authority: anytype,
        fresh_core: omit_protocol.FreshCoreResidualV1,
    ) !void {
        try self.compiler.validateAgainst(self.input(authority, fresh_core));
    }
};

pub const CoreCaptureLinkV1 = struct {
    capture_identity: [32]u8,
    descriptor_capture_identity: [32]u8,
    proof_capture_sha256: [32]u8,
    descriptor_proof_capture_sha256: [32]u8,

    pub fn validate(self: CoreCaptureLinkV1) !void {
        if (std.mem.allEqual(u8, &self.capture_identity, 0) or
            std.mem.allEqual(u8, &self.proof_capture_sha256, 0) or
            !std.mem.eql(
                u8,
                &self.capture_identity,
                &self.descriptor_capture_identity,
            ) or !std.mem.eql(
            u8,
            &self.proof_capture_sha256,
            &self.descriptor_proof_capture_sha256,
        )) return error.OmittedLeafCoreCaptureLinkMismatch;
    }
};

pub const ProviderCaptureLinkV1 = struct {
    ordinal: u32,
    artifact_ordinal: u32,
    capture_identity: [32]u8,
    artifact_capture_identity: [32]u8,
    proof_root_sha256: [32]u8,
    artifact_proof_root_sha256: [32]u8,
    proof_capture_sha256: [32]u8,
    artifact_proof_capture_sha256: [32]u8,

    pub fn validate(self: ProviderCaptureLinkV1) !void {
        if (self.ordinal != self.artifact_ordinal or
            std.mem.allEqual(u8, &self.capture_identity, 0) or
            std.mem.allEqual(u8, &self.proof_root_sha256, 0) or
            std.mem.allEqual(u8, &self.proof_capture_sha256, 0) or
            !std.mem.eql(
                u8,
                &self.capture_identity,
                &self.artifact_capture_identity,
            ) or !std.mem.eql(
            u8,
            &self.proof_root_sha256,
            &self.artifact_proof_root_sha256,
        ) or !std.mem.eql(
            u8,
            &self.proof_capture_sha256,
            &self.artifact_proof_capture_sha256,
        )) return error.OmittedLeafProviderCaptureLinkMismatch;
    }
};

pub fn OrdinaryH1ViewV1(comptime Engine: type) type {
    return struct {
        public_data: *const frontend.air.public_data_v2.PublicDataV2,
        receipt: *const statement_v2.VerifiedReceipt,
        verified_link: verified_link_mod.VerifiedLinkV3,
        tree0: *const Tree0AuthorityV1(Engine),
        core_capture: *const guest.ethereum_omitted_provider_fresh_capture_v1
            .CaptureV1(Engine),
        program: *const program_descriptor.DescriptorV1,
        provider_statements: []const d5.ProviderStatementV1,
        provider_claims: []const d5.FreshDegree5ProviderClaimV1,
        provider_captures: []const d5.FreshDegree5ProviderCaptureV1(Engine),
        provider: *const ProviderCompilerCustodyV1,
        fresh_core: *const omit_protocol.FreshCoreResidualV1,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
        ethereum_descs: []const ethereum_statement.Descriptor,
        transcript_claimed_sums: *const [transcript_claim_count]QM31,
        closure: *const guest.ethereum_matched_ab_omitted_provider_policy_v1
            .FreshClosureAdmissionV1,
        proof_artifact_byte_count: u64,
        proof_artifact_sha256: [32]u8,
        proof_root_sha256: [32]u8,
        transcript_state_sha256: [32]u8,

        pub fn validateCaptureCustody(
            self: @This(),
            authority: anytype,
        ) !void {
            try self.core_capture.validate(
                authority.plan,
                authority.calls.calls,
                authority.provider_stage_a,
            );
            try self.program.validate();
            try (CoreCaptureLinkV1{
                .capture_identity = self.core_capture.identity,
                .descriptor_capture_identity = self.program.capture_identity,
                .proof_capture_sha256 = self.core_capture.projected_base.vm_air.proof_capture_sha256,
                .descriptor_proof_capture_sha256 = self.program.proof_capture_sha256,
            }).validate();
            if (self.provider_claims.len != authority.plan.shards.len or
                self.provider_statements.len != self.provider_claims.len or
                self.provider_captures.len != self.provider_claims.len or
                self.provider.provider_claims.len != self.provider_claims.len or
                self.provider.shard_artifacts.len != self.provider_claims.len)
            {
                return error.InvalidOmittedLeafCaptureCustody;
            }
            for (self.provider_claims, 0..) |claim, index| {
                try claim.validate();
                if (claim.provider.native_claim.shard_index !=
                    @as(u32, @intCast(index)))
                    return error.InvalidOmittedLeafCaptureCustody;
                try self.provider_captures[index].validateAgainst(
                    self.provider_statements[index],
                    claim,
                    authority.expected_program,
                    authority.execution_profile,
                    &self.core_capture.projected_base.vm_air.relation_draws,
                );
                try (ProviderCaptureLinkV1{
                    .ordinal = @intCast(index),
                    .artifact_ordinal = self.provider.shard_artifacts[index].ordinal,
                    .capture_identity = self.provider_captures[index].identity,
                    .artifact_capture_identity = self.provider
                        .shard_artifacts[index].capture_identity,
                    .proof_root_sha256 = self.provider_captures[index].proof_root_sha256,
                    .artifact_proof_root_sha256 = self.provider
                        .shard_artifacts[index].proof_root_sha256,
                    .proof_capture_sha256 = self.provider_captures[index].proof_capture_sha256,
                    .artifact_proof_capture_sha256 = self.provider
                        .shard_artifacts[index].proof_capture_sha256,
                }).validate();
                try self.provider.shard_artifacts[index].validateAgainst(
                    claim.provider.native_claim,
                    authority.plan.shards[index],
                    authority.shared.relation_context,
                    index,
                );
            }
            try self.provider.validateAgainst(authority, self.fresh_core.*);
        }

        pub fn descriptorMintInput(
            self: @This(),
            program: program_descriptor.DescriptorV1,
            source: *const source_wire.Source,
        ) !leaf_descriptor.MintInputV1 {
            if (!std.meta.eql(program, self.program.*))
                return error.OmittedLeafProgramDescriptorMismatch;
            return self.descriptorMintInputColdDerived(source);
        }

        pub fn descriptorMintInputColdDerived(
            self: @This(),
            source: *const source_wire.Source,
        ) !leaf_descriptor.MintInputV1 {
            try source.validate();
            try self.program.validate();
            try self.verified_link.validateAgainst(
                &source.metadata,
                self.public_data,
                self.receipt,
            );
            return .{
                .program = self.program.*,
                .source = source,
                .verified_link = self.verified_link,
                .proof_artifact_byte_count = self.proof_artifact_byte_count,
                .proof_artifact_sha256 = self.proof_artifact_sha256,
                .proof_root_sha256 = self.proof_root_sha256,
                .transcript_state_sha256 = self.transcript_state_sha256,
            };
        }

        pub fn providerCompilerInput(
            self: @This(),
            authority: anytype,
        ) !incremental_provider.CompilerInputV1 {
            try self.validateCaptureCustody(authority);
            return self.provider.input(authority, self.fresh_core.*);
        }
    };
}

comptime {
    if (transcript_claim_count != 42)
        @compileError("ordinary omitted-provider H1 view roster drifted");
}
