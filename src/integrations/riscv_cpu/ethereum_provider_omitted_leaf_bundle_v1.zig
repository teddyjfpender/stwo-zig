//! Cold, non-relabeling custody for an ordinary Ethereum leaf whose native
//! Poseidon provider is replaced by ordered degree-five shard proofs.
//!
//! The bundle carries both full and projected statements, every active claim,
//! the projected-core proof, and each canonical d5 provider artifact. Decoding
//! is transport admission only. `coldVerify` reruns the omitted-core STARK,
//! every provider STARK in ordinal order, and the shared zero-sum closure
//! before publishing `FreshVerifiedOmittedLeafV1`.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const provider_artifact =
    @import("ethereum_degree5_provider_proof_artifact_v1.zig");
const support =
    @import("ethereum_provider_omitted_leaf_bundle_v1_support.zig");
const capture_custody =
    @import("ethereum_provider_omitted_leaf_capture_custody_v1.zig");
const incremental_provider =
    @import("recursive_temporal_incremental_provider_authority_v1.zig");

const guest = frontend.prover_mod.guest_precompile;
const d5 = frontend.testing
    .narrow_memory_provider_degree5_ethereum_omit_proof_v1;
const provider_authority = frontend.testing
    .narrow_memory_provider_shard_authority;
const omit_protocol = guest.ethereum_native_provider_omit_protocol_v1;
const native_omit = guest.native_provider_omit_v1;
const policy = guest.ethereum_matched_ab_omitted_provider_policy_v1;
const segment_verifier = guest.ethereum_segment_verifier;
const source_wire = guest.ethereum_segment_source_wire;
const ethereum_types = guest.ethereum_types;
const core_artifact = guest.ethereum_segment_poseidon2_proof_artifact;
const lookup_physical_v2 = frontend.air.lookup_physical_manifest_v2;
const statement_v2 = frontend.air.statement_v2;
const transcript_claims = frontend.air.transcript;
const ethereum_statement = frontend.air.guest_precompile.ethereum_statement;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const global_v3 = frontend.recursion.segment_leaf_local_authority_v3;
const verified_link_mod = frontend.recursion.segment_leaf_local_verified_link_v3;
const program_v2 = frontend.recursion.ethereum_vm_composition_program_v2;
const program_descriptor =
    frontend.recursion.ethereum_vm_verified_program_descriptor_v1;
const omitted_capture = guest.ethereum_omitted_provider_fresh_capture_v1;

const native_artifact = guest.ethereum_segment_proof_artifact;
const proof_authority = frontend.prover_mod
    .memory_provider_shard_joint_proof_authority;

const QM31 = core.fields.qm31.QM31;

pub const format_version: u16 = 1;
pub const schema_version: u16 = 1;
pub const magic = provider_artifact.bundle_magic;
pub const header_size = provider_artifact.bundle_header_size;
pub const section_count = provider_artifact.bundle_section_count;
pub const transcript_claim_count: usize =
    transcript_claims.COMPONENT_COUNT + ethereum_statement.component_count;
pub const production_active = false;
pub const recursive_admissible = false;

pub const Limits = provider_artifact.BundleLimits;

pub fn Authority(comptime Engine: type) type {
    return struct {
        expected_program: d5.VerifierProgramAuthorityV2,
        execution_profile: d5.ExecutionProfileV1,
        plan: *const provider_authority.ProviderShardPlanV1,
        calls: *const policy.ProviderCallAuthorityV1,
        provider_stage_a: *const omit_protocol.ProviderStageAManifestV1(Engine),
        shared: omit_protocol.SharedRelationAuthorityV1(Engine),
        omitted_core: policy.OmittedCoreEstimateV1,
        plan_admission: policy.ProviderPlanAdmissionV1,
        source: *const source_wire.Source,
        core_security_identity_sha256: [32]u8,

        const Self = @This();

        pub fn validate(self: Self, allocator: std.mem.Allocator) !void {
            try self.expected_program.validateCold(allocator);
            try self.execution_profile.validate(self.expected_program.base);
            try self.source.validate();
            if (std.mem.allEqual(
                u8,
                &self.core_security_identity_sha256,
                0,
            )) return error.OmittedLeafProviderAuthorityMismatch;
            try self.omitted_core.validate();
            const execution = policy.MatchedExecutionAuthorityV1.canonical();
            try self.plan_admission.validateAgainst(
                self.plan,
                self.calls,
                execution,
            );
            try self.provider_stage_a.validate(self.plan, self.calls.calls);
            if (self.plan.shards.len == 0 or
                self.plan.shards.len != self.provider_stage_a.providers.len or
                self.plan.shards.len !=
                    @as(usize, self.plan_admission.shard_count))
            {
                return error.OmittedLeafProviderAuthorityMismatch;
            }
        }
    };
}

pub fn EncodeInput(comptime Engine: type) type {
    return struct {
        authority: Authority(Engine),
        full_statement: *const statement_v2.RiscVStatementV2,
        core_artifact: []const u8,
        provider_artifacts: []const []const u8,
    };
}

pub fn Decoded(comptime Engine: type) type {
    return provider_artifact.BundleDecoded(Engine);
}

pub fn Tree0AuthorityV1(comptime Engine: type) type {
    return capture_custody.Tree0AuthorityV1(Engine);
}

pub const ProviderCompilerCustodyV1 =
    capture_custody.ProviderCompilerCustodyV1;
pub const CoreCaptureLinkV1 = capture_custody.CoreCaptureLinkV1;
pub const ProviderCaptureLinkV1 = capture_custody.ProviderCaptureLinkV1;

pub fn OrdinaryH1ViewV1(comptime Engine: type) type {
    return capture_custody.OrdinaryH1ViewV1(Engine);
}

pub fn FreshVerifiedOmittedLeafV1(comptime Engine: type) type {
    return struct {
        allocator: std.mem.Allocator,
        public_data: statement_v2.OwnedPublicDataV2,
        full_statement: statement_v2.RiscVStatementV2,
        projected_statement: statement_v2.RiscVStatementV2,
        extension: ethereum_statement.Statement,
        extension_claim: ethereum_types.ExtensionClaim,
        global: global_v3.MetadataV3,
        receipt: statement_v2.VerifiedReceipt,
        verified_link: verified_link_mod.VerifiedLinkV3,
        core_commitments: [4]Engine.Hasher.Hash,
        core_capture: omitted_capture.CaptureV1(Engine),
        vm_program: program_v2.EthereumVmCompositionProgramV2,
        program_descriptor: program_descriptor.DescriptorV1,
        tree0: Tree0AuthorityV1(Engine),
        base_claim: *frontend.prover_mod.RiscVInteractionClaim,
        provider_statements: []d5.ProviderStatementV1,
        provider_claims: []d5.FreshDegree5ProviderClaimV1,
        provider_captures: []d5.FreshDegree5ProviderCaptureV1(Engine),
        provider_custody: ProviderCompilerCustodyV1,
        shared: omit_protocol.SharedRelationAuthorityV1(Engine),
        fresh_core: omit_protocol.FreshCoreResidualV1,
        closure: policy.FreshClosureAdmissionV1,
        transcript_claimed_sums: [transcript_claim_count]QM31,
        authority_identity: [32]u8,
        proof_artifact_byte_count: u64,
        proof_artifact_sha256: [32]u8,
        proof_root_sha256: [32]u8,
        transcript_state_sha256: [32]u8,
        identity: [32]u8,

        const Self = @This();

        pub fn deinit(self: *Self) void {
            for (self.provider_captures) |*capture|
                capture.deinit(self.allocator);
            self.allocator.free(self.provider_captures);
            self.allocator.free(self.provider_custody.shard_artifacts);
            self.allocator.free(self.provider_custody.provider_claims);
            self.allocator.free(self.provider_statements);
            self.allocator.free(self.tree0.provider_preprocessed_roots);
            self.allocator.free(self.provider_claims);
            self.allocator.destroy(self.base_claim);
            self.vm_program.deinit();
            self.core_capture.deinit(self.allocator);
            self.public_data.deinit();
            self.* = undefined;
        }

        pub fn ordinaryH1View(self: *const Self) OrdinaryH1ViewV1(Engine) {
            const core_statement = &self.full_statement.core;
            return .{
                .public_data = &self.public_data.data,
                .receipt = &self.receipt,
                .verified_link = self.verified_link,
                .tree0 = &self.tree0,
                .core_capture = &self.core_capture,
                .program = &self.program_descriptor,
                .provider_statements = self.provider_statements,
                .provider_claims = self.provider_claims,
                .provider_captures = self.provider_captures,
                .provider = &self.provider_custody,
                .fresh_core = &self.fresh_core,
                .component_descs = core_statement.component_descs[0..@as(usize, @intCast(core_statement.n_components))],
                .infra_descs = core_statement.infra_descs[0..@as(usize, @intCast(core_statement.n_infra))],
                .ethereum_descs = &self.extension.components,
                .transcript_claimed_sums = &self.transcript_claimed_sums,
                .closure = &self.closure,
                .proof_artifact_byte_count = self.proof_artifact_byte_count,
                .proof_artifact_sha256 = self.proof_artifact_sha256,
                .proof_root_sha256 = self.proof_root_sha256,
                .transcript_state_sha256 = self.transcript_state_sha256,
            };
        }

        pub fn validateAgainstArtifact(
            self: *const Self,
            authority: Authority(Engine),
            artifact_bytes: []const u8,
        ) !void {
            try self.validate(authority);
            if (self.proof_artifact_byte_count !=
                @as(u64, @intCast(artifact_bytes.len)) or
                !std.mem.eql(
                    u8,
                    &self.proof_artifact_sha256,
                    &support.sha256(artifact_bytes),
                )) return error.OmittedLeafProofArtifactMismatch;
        }

        pub fn validate(self: *const Self, authority: Authority(Engine)) !void {
            try authority.validate(self.allocator);
            try self.public_data.validate();
            try self.full_statement.validate();
            try self.projected_statement.validate();
            try self.extension.validateV2(&self.full_statement);
            try self.extension_claim.validate(&self.extension);
            var program_manifest = lookup_physical_v2.Manifest.native();
            const program_authenticated = try lookup_physical_v2
                .AuthenticatedStatement.init(
                &self.core_capture.projection.projected_native.core,
                &program_manifest,
            );
            try self.vm_program.validateAgainst(.{
                .core_statement = &self.core_capture.projection.projected_native.core,
                .extension_statement = &self.core_capture.extension_statement,
                .lookup_manifest = &program_manifest,
                .authenticated_lookup = &program_authenticated,
                .base_profile = &self.core_capture.projected_base.vm_air.profile,
            });
            try self.program_descriptor.validateAgainstProgram(
                &self.vm_program,
            );
            if (self.full_statement.public_data.words().ptr !=
                self.public_data.data.words().ptr or
                self.projected_statement.public_data.words().ptr !=
                    self.public_data.data.words().ptr or
                !std.meta.eql(self.global, authority.source.metadata) or
                !std.mem.eql(
                    u8,
                    &self.authority_identity,
                    &try support.authorityIdentity(authority),
                ) or self.proof_artifact_byte_count == 0 or
                std.mem.allEqual(u8, &self.proof_artifact_sha256, 0) or
                !std.meta.eql(
                    self.core_capture.proof_commitments,
                    self.core_commitments,
                ) or !std.meta.eql(
                self.program_descriptor.preprocessed_commitment_root,
                self.core_commitments[0],
            ) or !std.mem.eql(
                u8,
                &self.program_descriptor.proof_capture_sha256,
                &self.core_capture.projected_base.vm_air.proof_capture_sha256,
            ) or !std.mem.eql(
                u8,
                &self.program_descriptor.capture_identity,
                &self.core_capture.identity,
            )) {
                return error.InvalidFreshVerifiedOmittedLeaf;
            }
            try native_artifact.validateGlobalMetadataMapping(
                &self.full_statement,
                &self.global,
            );
            try self.receipt.validateAgainst(&self.public_data.data);
            try self.verified_link.validateAgainst(
                &self.global,
                &self.public_data.data,
                &self.receipt,
            );
            var manifest = lookup_physical_v2.Manifest.native();
            const authenticated = try lookup_physical_v2.AuthenticatedStatement
                .init(&self.full_statement.core, &manifest);
            const projection = try native_omit.ProjectionV1.init(
                &self.full_statement,
                &self.extension,
                .proof,
                &manifest,
                &authenticated,
                authority.plan,
                authority.calls.calls,
                try native_omit.deriveFullGeometry(&self.full_statement),
            );
            if (!std.meta.eql(
                projection.projected_native.core,
                self.projected_statement.core,
            )) return error.InvalidFreshVerifiedOmittedLeaf;
            try self.shared.validate(
                authority.plan,
                authority.provider_stage_a,
                &projection,
            );
            try self.fresh_core.validate();
            try self.closure.validateAgainst(
                &authority.omitted_core,
                &authority.plan_admission,
            );
            try self.tree0.validate(
                &projection,
                authority.plan,
                authority.calls.calls,
                authority.provider_stage_a,
            );
            if (!std.meta.eql(
                self.tree0.projected_core_root,
                self.core_commitments[0],
            ) or !std.mem.eql(
                u8,
                &self.fresh_core.proof_commitments_identity,
                &proof_authority.commitmentsIdentity(
                    Engine,
                    &self.core_commitments,
                ),
            )) {
                return error.InvalidFreshVerifiedOmittedLeaf;
            }
            try self.ordinaryH1View().validateCaptureCustody(authority);
            const projected_canonical = try self.base_claim.canonical(
                &self.projected_statement.core,
            );
            const expected_claims = try support.claimedSums(
                projected_canonical.claimed_sums,
                self.provider_claims,
                &self.extension,
                &self.extension_claim,
            );
            if (!std.meta.eql(expected_claims, self.transcript_claimed_sums) or
                !std.mem.eql(
                    u8,
                    &self.proof_root_sha256,
                    &support.proofRootIdentity(Engine, self),
                ) or !std.mem.eql(
                u8,
                &self.transcript_state_sha256,
                &support.transcriptStateIdentity(Engine, self),
            ) or !std.mem.eql(
                u8,
                &self.identity,
                &support.freshCaptureIdentity(Engine, self),
            )) return error.InvalidFreshVerifiedOmittedLeaf;
        }
    };
}

pub fn BuildResultV1(comptime Engine: type) type {
    return struct {
        allocator: std.mem.Allocator,
        artifact_bytes: []u8,
        fresh: FreshVerifiedOmittedLeafV1(Engine),

        pub fn deinit(self: *@This()) void {
            self.fresh.deinit();
            self.allocator.free(self.artifact_bytes);
            self.* = undefined;
        }
    };
}

/// Encodes only already-canonical child artifacts. Fresh verification remains
/// mandatory and is performed by `coldVerify` after reopening these bytes.
pub fn encodeAlloc(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    input: EncodeInput(Engine),
    limits: Limits,
) ![]u8 {
    try limits.validate();
    try input.authority.validate(allocator);
    if (input.provider_artifacts.len != input.authority.plan.shards.len)
        return error.InvalidOmittedLeafBundleInput;
    return provider_artifact.encodeBundleAlloc(allocator, .{
        .authority_identity = try support.authorityIdentity(input.authority),
        .full_statement = input.full_statement,
        .core_artifact_bytes = input.core_artifact,
        .provider_artifacts = input.provider_artifacts,
    }, limits);
}

pub fn decodeAlloc(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    bytes: []const u8,
    authority: Authority(Engine),
    limits: Limits,
) !Decoded(Engine) {
    try limits.validate();
    try authority.validate(allocator);
    var result = try provider_artifact.decodeBundleAlloc(
        Engine,
        allocator,
        bytes,
        try support.authorityIdentity(authority),
        authority.core_security_identity_sha256,
        authority.execution_profile.identity,
        authority.plan.shards.len,
        limits,
    );
    errdefer result.deinit(allocator);
    try support.validateCoreMetadata(
        Engine,
        &result.full.value,
        &result.core,
        authority,
    );
    return result;
}

/// Reopens and verifies every proof. No field of the returned value is minted
/// by the decoder or by a producer-supplied digest.
pub fn coldVerify(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    bytes: []const u8,
    authority: Authority(Engine),
    limits: Limits,
) !FreshVerifiedOmittedLeafV1(Engine) {
    var decoded = try decodeAlloc(Engine, allocator, bytes, authority, limits);
    defer decoded.deinit(allocator);
    var commitments: [4]Engine.Hasher.Hash = undefined;
    if (decoded.core.proof.commitment_scheme_proof.commitments.items.len !=
        commitments.len)
    {
        return error.InvalidOmittedLeafCoreCommitmentCount;
    }
    @memcpy(
        &commitments,
        decoded.core.proof.commitment_scheme_proof.commitments.items,
    );
    var transcript_extension = try omit_protocol.Extension(Engine)
        .initForFreshVerify(
        authority.plan,
        authority.calls.calls,
        authority.provider_stage_a,
        authority.shared,
    );
    var channel = Engine.Channel{};
    var core_capture: omitted_capture.CaptureV1(Engine) = undefined;
    var core_capture_owned = false;
    errdefer if (core_capture_owned) core_capture.deinit(allocator);
    decoded.core_proof_moved = true;
    try guest.verifyEthereumSegmentWithEngineUsingChannelAndNativeProviderOmissionCapture(
        Engine,
        allocator,
        core_artifact.pcs_config,
        decoded.full.value,
        decoded.core.extension,
        decoded.core.proof,
        decoded.core.base_claim,
        &decoded.core.extension_claim,
        &channel,
        &transcript_extension,
        &core_capture,
    );
    core_capture_owned = true;
    const projection = &core_capture.projection;
    if (!std.meta.eql(
        projection.projected_native.core,
        decoded.core.statement.core,
    )) return error.OmittedLeafProjectedStatementMismatch;
    const shared = core_capture.shared;
    if (!std.meta.eql(shared, authority.shared))
        return error.OmittedLeafSharedAuthorityMismatch;
    const fresh_core = core_capture.fresh_core;

    var manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        &decoded.full.value.core,
        &manifest,
    );
    const source = d5.Source(Engine){
        .native = &decoded.full.value,
        .extension = &decoded.core.extension,
        .lookup_manifest = &manifest,
        .authenticated_lookup = &authenticated,
        .projection = projection,
        .plan = authority.plan,
        .calls = authority.calls.calls,
        .provider_stage_a = authority.provider_stage_a,
        .shared = shared,
    };
    try source.validate();
    const fresh_providers = try allocator.alloc(
        d5.FreshDegree5ProviderClaimV1,
        decoded.providers.len,
    );
    errdefer allocator.free(fresh_providers);
    const provider_statements = try allocator.alloc(
        d5.ProviderStatementV1,
        decoded.providers.len,
    );
    errdefer allocator.free(provider_statements);
    const provider_captures = try allocator.alloc(
        d5.FreshDegree5ProviderCaptureV1(Engine),
        decoded.providers.len,
    );
    var provider_captures_initialized: usize = 0;
    errdefer {
        for (provider_captures[0..provider_captures_initialized]) |*capture|
            capture.deinit(allocator);
        allocator.free(provider_captures);
    }
    for (decoded.providers, fresh_providers, 0..) |*artifact, *fresh, index| {
        provider_statements[index] = artifact.statement;
        decoded.provider_proofs_moved = index + 1;
        fresh.* = try d5.verifyProviderFreshWithCaptureV1(
            Engine,
            allocator,
            core_artifact.pcs_config,
            authority.expected_program,
            authority.execution_profile,
            source,
            artifact.statement,
            artifact.proof,
            &provider_captures[index],
        );
        provider_captures_initialized += 1;
    }
    const closed = try d5.closeFreshClaimsV1(
        Engine,
        allocator,
        authority.expected_program,
        authority.execution_profile,
        source,
        fresh_core,
        fresh_providers,
    );
    const closure = try policy.FreshClosureAdmissionV1.canonical(
        &authority.omitted_core,
        &authority.plan_admission,
        closed.strategy,
        closed.closure,
    );
    const projected_canonical = try decoded.core.base_claim.canonical(
        &decoded.core.statement.core,
    );
    const sums = try support.claimedSums(
        projected_canonical.claimed_sums,
        fresh_providers,
        &decoded.core.extension,
        &decoded.core.extension_claim,
    );
    var program_manifest = lookup_physical_v2.Manifest.native();
    const program_authenticated = try lookup_physical_v2.AuthenticatedStatement
        .init(&projection.projected_native.core, &program_manifest);
    var vm_program = try program_v2.compile(allocator, .{
        .core_statement = &projection.projected_native.core,
        .extension_statement = &decoded.core.extension,
        .lookup_manifest = &program_manifest,
        .authenticated_lookup = &program_authenticated,
        .base_profile = &core_capture.projected_base.vm_air.profile,
    });
    errdefer vm_program.deinit();
    const verified_program = program_descriptor.project(
        &vm_program,
        commitments[0],
        core_capture.projected_base.vm_air.proof_capture_sha256,
        core_capture.identity,
    );
    try verified_program.validateAgainstProgram(&vm_program);

    const provider_native_claims = try allocator.alloc(
        provider_authority.ProviderShardClaimV1,
        fresh_providers.len,
    );
    errdefer allocator.free(provider_native_claims);
    const provider_shard_artifacts = try allocator.alloc(
        incremental_provider.ShardArtifactV1,
        fresh_providers.len,
    );
    errdefer allocator.free(provider_shard_artifacts);
    for (
        fresh_providers,
        provider_captures,
        decoded.providers,
        provider_native_claims,
        provider_shard_artifacts,
        0..,
    ) |fresh, *capture, decoded_provider, *native_claim, *shard, index| {
        native_claim.* = fresh.provider.native_claim;
        shard.* = try incremental_provider.ShardArtifactV1
            .initFromFreshVerifier(.{
            .ordinal = @intCast(index),
            .proof_artifact_sha256 = decoded_provider.artifact_sha256,
            .proof_root_sha256 = capture.proof_root_sha256,
            .proof_capture_sha256 = capture.proof_capture_sha256,
            .capture_identity = capture.identity,
            .air_program_identity = authority.expected_program.air_program_identity,
            .verifier_program_authority = capture.verifier_program_authority_sha256,
            .protocol_profile_sha256 = capture.protocol_profile_sha256,
            .preprocessed_commitment_root = capture.proof.commitments[0],
        }, native_claim.*);
    }
    var provider_custody = ProviderCompilerCustodyV1{
        .entry_continuation_root = authority.source.metadata.entry.continuation_root,
        .exit_continuation_root = authority.source.metadata.exit.continuation_root,
        .core_proof_artifact_sha256 = decoded.core_artifact_sha256,
        .core_proof_capture_sha256 = core_capture.projected_base.vm_air.proof_capture_sha256,
        .core_capture_identity = core_capture.identity,
        .residency_request = authority.plan_admission.residency.request,
        .residency_plan = authority.plan_admission.residency.result,
        .provider_claims = provider_native_claims,
        .shard_artifacts = provider_shard_artifacts,
        .compiler = undefined,
    };
    provider_custody.compiler = try incremental_provider
        .ProviderCompilerAuthorityV1.compile(
        provider_custody.input(authority, fresh_core),
    );
    try provider_custody.validateAgainst(authority, fresh_core);
    var owned_public = try statement_v2.OwnedPublicDataV2.initVerified(
        allocator,
        &decoded.core.statement.public_data,
    );
    errdefer owned_public.deinit();
    const full_statement = try statement_v2.RiscVStatementV2.init(
        decoded.full.value.core,
        owned_public.data,
    );
    const projected_statement = try statement_v2.RiscVStatementV2.init(
        decoded.core.statement.core,
        owned_public.data,
    );
    const receipt = try projected_statement.verifiedReceipt();
    const verified_link = try verified_link_mod.VerifiedLinkV3.init(
        &decoded.core.global,
        &owned_public.data,
        &receipt,
    );
    const provider_roots = try allocator.alloc(
        Engine.Hasher.Hash,
        authority.provider_stage_a.providers.len,
    );
    errdefer allocator.free(provider_roots);
    for (provider_roots, authority.provider_stage_a.providers) |*root, item|
        root.* = item.preprocessed_root;
    const base_claim = try allocator.create(
        frontend.prover_mod.RiscVInteractionClaim,
    );
    errdefer allocator.destroy(base_claim);
    base_claim.* = decoded.core.base_claim.*;
    var tree0 = Tree0AuthorityV1(Engine){
        .projected_core_root = commitments[0],
        .provider_preprocessed_roots = provider_roots,
        .projection_identity = projection.identity,
        .provider_manifest_identity = authority.provider_stage_a.identity,
        .omitted_infra_index = projection.omitted_infra_index,
        .omitted_descriptor = projection.omitted_descriptor,
        .identity = undefined,
    };
    tree0.identity = support.tree0Identity(Engine, &tree0);
    var result = FreshVerifiedOmittedLeafV1(Engine){
        .allocator = allocator,
        .public_data = owned_public,
        .full_statement = full_statement,
        .projected_statement = projected_statement,
        .extension = decoded.core.extension,
        .extension_claim = decoded.core.extension_claim,
        .global = decoded.core.global,
        .receipt = receipt,
        .verified_link = verified_link,
        .core_commitments = commitments,
        .core_capture = core_capture,
        .vm_program = vm_program,
        .program_descriptor = verified_program,
        .tree0 = tree0,
        .base_claim = base_claim,
        .provider_statements = provider_statements,
        .provider_claims = fresh_providers,
        .provider_captures = provider_captures,
        .provider_custody = provider_custody,
        .shared = shared,
        .fresh_core = fresh_core,
        .closure = closure,
        .transcript_claimed_sums = sums,
        .authority_identity = decoded.authority_identity,
        .proof_artifact_byte_count = @intCast(bytes.len),
        .proof_artifact_sha256 = decoded.artifact_sha256,
        .proof_root_sha256 = undefined,
        .transcript_state_sha256 = undefined,
        .identity = undefined,
    };
    result.proof_root_sha256 = support.proofRootIdentity(Engine, &result);
    result.transcript_state_sha256 = support.transcriptStateIdentity(
        Engine,
        &result,
    );
    result.identity = support.freshCaptureIdentity(Engine, &result);
    try result.validateAgainstArtifact(authority, bytes);
    core_capture_owned = false;
    return result;
}

/// Consumes `core_output` on every path. Its witness and ordered call list are
/// not rebuilt: the caller supplies the exact live provider source used by the
/// omitted-core transaction.
pub fn createDestroyAndColdVerify(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    core_output: *ethereum_types.SegmentProveOutputForEngine(Engine),
    provider_source: d5.Source(Engine),
    authority: Authority(Engine),
    limits: Limits,
) !BuildResultV1(Engine) {
    var core_output_owned = true;
    defer if (core_output_owned) core_output.deinit(allocator);
    try authority.validate(allocator);
    try provider_source.validate();
    if (!std.meta.eql(core_output.statement, provider_source.native.*) or
        !std.meta.eql(core_output.extension, provider_source.extension.*) or
        provider_source.plan != authority.plan or
        provider_source.calls.ptr != authority.calls.calls.ptr or
        provider_source.calls.len != authority.calls.calls.len or
        provider_source.provider_stage_a != authority.provider_stage_a or
        !std.meta.eql(provider_source.shared, authority.shared))
    {
        return error.OmittedLeafProducerAuthorityMismatch;
    }
    const core_bytes = try core_artifact.encodeAllocWithLimits(allocator, .{
        .security_identity_sha256 = authority.core_security_identity_sha256,
        .statement = &provider_source.projection.projected_native,
        .extension = &core_output.extension,
        .global = &authority.source.metadata,
        .base_claim = core_output.base_claim,
        .extension_claim = &core_output.extension_claim,
        .proof = &core_output.proof,
    }, limits.core);
    defer allocator.free(core_bytes);
    const provider_bytes = try allocator.alloc([]u8, authority.plan.shards.len);
    var provider_count: usize = 0;
    defer {
        for (provider_bytes[0..provider_count]) |bytes| allocator.free(bytes);
        allocator.free(provider_bytes);
    }
    for (provider_bytes, 0..) |*destination, index| {
        var output = try d5.proveProviderV1(
            Engine,
            allocator,
            core_artifact.pcs_config,
            authority.expected_program,
            authority.execution_profile,
            provider_source,
            @intCast(index),
        );
        defer output.proof.deinit(allocator);
        destination.* = try provider_artifact.encodeAlloc(
            Engine,
            allocator,
            core_artifact.pcs_config,
            output.execution_profile_identity,
            output.statement,
            output.proof,
            limits.provider,
        );
        provider_count += 1;
    }
    const artifact_bytes = try encodeAlloc(Engine, allocator, .{
        .authority = authority,
        .full_statement = &core_output.statement,
        .core_artifact = core_bytes,
        .provider_artifacts = provider_bytes,
    }, limits);
    errdefer allocator.free(artifact_bytes);
    core_output.deinit(allocator);
    core_output_owned = false;
    const fresh = try coldVerify(
        Engine,
        allocator,
        artifact_bytes,
        authority,
        limits,
    );
    return .{
        .allocator = allocator,
        .artifact_bytes = artifact_bytes,
        .fresh = fresh,
    };
}

comptime {
    if (transcript_claim_count != 42 or transcript_claims.COMPONENT_COUNT != 28 or
        ethereum_statement.component_count != 14 or poseidon2_air.N_SUMS != 2)
    {
        @compileError("ordinary omitted-provider H1 claim roster drifted");
    }
}
