//! Cold verifier and transactional capture for the combined candidate leaf.
//!
//! This research-only sibling preserves the ordinary Ethereum verifier and
//! provider-omission routes. It reconstructs the candidate fixed columns from
//! the admitted Profile, replays the provider frame, verifies the projected
//! base + Ethereum + four candidate AIR components, and publishes a capture
//! only after the residual and every retained authority close.

const std = @import("std");

const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_verifier = @import("stwo_core").verifier;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_pcs = @import("stwo_prover_engine").pcs;

const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const ethereum_context = @import("../../recursion/ethereum_leaf_context_v1.zig");
const vm_leaf_context_v2 = @import("../../recursion/vm_leaf_context_v2.zig");
const proof_workspace = @import("../proof_workspace.zig");
const base_types = @import("../types.zig");
const base_verifier = @import("../verifier.zig");
const provider_authority = @import("../memory_provider_shards/authority.zig");
const native_provider_omit = @import("../memory_provider_shards/native_provider_omit_v1.zig");
const ordinary_omit = @import("../memory_provider_shards/ethereum_omit_protocol_v1.zig");
const candidate_omit = @import("../memory_provider_shards/ethereum_candidate_omit_protocol_v1.zig");
const proof_authority = @import("../memory_provider_shards/joint_proof_authority.zig");
const admission_mod = @import("ethereum_candidate_leaf_admission_v1.zig");
const integration = @import("ethereum_candidate_leaf_integration_v1.zig");
const profile_mod = @import("ethereum_candidate_leaf_profile_v1.zig");
const tree_mod = @import("ethereum_candidate_leaf_tree_v1.zig");

pub const format_version: u16 = 1;
pub const schema_version: u16 = 1;
pub const production_active = false;
const capture_domain =
    "stwo-zig/riscv/ethereum-candidate-leaf-fresh-capture/v1\x00";

pub fn FreshVerifiedCandidateLeafCaptureV1(comptime Engine: type) type {
    return struct {
        format: u16 = format_version,
        schema: u16 = schema_version,
        projected_base: base_verifier.VerifiedSegmentV2CaptureForEngine(Engine),
        full_statement: statement_v2.RiscVStatementV2,
        projection: native_provider_omit.ProjectionV1,
        extension_statement: ethereum_statement.Statement,
        ethereum_context: ethereum_context.ContextV1,
        profile: profile_mod.Profile,
        admission: admission_mod.Admission,
        relations: integration.Relations,
        interaction_claims: tree_mod.InteractionClaims,
        provider_shared_authority: candidate_omit.SharedRelationAuthorityV1(Engine),
        fresh_core: ordinary_omit.FreshCoreResidualV1,
        proof_commitments: [4]Engine.Hasher.Hash,
        proof_commitments_identity: provider_authority.Digest,
        interaction_pow: u64,
        fresh_core_stark_verified: bool = true,
        production_eligible: bool = false,
        recursive_admissible: bool = false,
        identity: [32]u8,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.projected_base.deinit(allocator);
            self.* = undefined;
        }

        /// Reopens all capture-owned authority without caller-owned plan or
        /// call storage. `validateAgainst` performs the complete external
        /// provider and claim comparison before publication/consumption.
        pub fn validate(self: *const Self) !void {
            if (self.format != format_version or self.schema != schema_version or
                !self.fresh_core_stark_verified or self.production_eligible or
                self.recursive_admissible)
            {
                return error.InvalidFreshVerifiedCandidateLeafCapture;
            }
            try self.projected_base.validate();
            try self.full_statement.validate();
            try self.extension_statement.validateV2(&self.full_statement);
            try self.projection.validateSealAndFull(
                &self.full_statement,
                &self.extension_statement,
            );
            if (self.full_statement.public_data.words().ptr !=
                self.projected_base.public_data.data.words().ptr or
                self.full_statement.public_data.words().len !=
                    self.projected_base.public_data.data.words().len or
                self.projection.projected_native.public_data.words().ptr !=
                    self.projected_base.public_data.data.words().ptr or
                self.projection.projected_native.public_data.words().len !=
                    self.projected_base.public_data.data.words().len)
            {
                return error.InvalidFreshVerifiedCandidateLeafCapture;
            }

            var manifest = lookup_physical_v2.Manifest.native();
            const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
                &self.full_statement.core,
                &manifest,
            );
            try authenticated.validateAgainst(
                &self.projection.projected_native.core,
                &manifest,
            );
            const base_interaction_columns: u32 = @intCast(
                try authenticated.totalInteractionColumns(
                    &self.projection.projected_native.core,
                    &manifest,
                ),
            );
            try self.profile.validate(
                &self.projection.projected_native.core,
                &self.extension_statement,
                base_interaction_columns,
            );
            const expected_admission = try admission_mod.validateProjectedV2(
                &self.full_statement,
                &self.projection.projected_native.core,
                &self.extension_statement,
                base_interaction_columns,
                &self.profile,
                .proof,
            );
            try self.interaction_claims.validate(
                &self.extension_statement,
                &self.profile,
            );
            try self.relations.validate();
            try self.provider_shared_authority.candidate_call_relations
                .validateAgainst(self.relations);
            try self.fresh_core.validate();
            if (!std.meta.eql(self.admission, expected_admission) or
                !std.meta.eql(
                    self.admission,
                    self.provider_shared_authority.admission,
                ) or !std.mem.eql(
                u8,
                &self.profile.identity,
                &self.provider_shared_authority.profile_identity,
            ) or !std.mem.eql(
                u8,
                &self.proof_commitments_identity,
                &proof_authority.commitmentsIdentity(
                    Engine,
                    &self.proof_commitments,
                ),
            ) or !std.mem.eql(
                u8,
                &self.proof_commitments_identity,
                &self.fresh_core.proof_commitments_identity,
            ) or !std.mem.eql(
                u8,
                &self.projection.identity,
                &self.fresh_core.projection_identity,
            ) or !std.mem.eql(
                u8,
                &self.provider_shared_authority.relation_context.identity,
                &self.fresh_core.relation_context_identity,
            ) or self.interaction_pow !=
                self.provider_shared_authority.ordinary.interaction_pow or
                !std.meta.eql(
                    self.projected_base.receipt.authority_id,
                    self.projection.projected_native.authority_id,
                ))
            {
                return error.InvalidFreshVerifiedCandidateLeafCapture;
            }
            try self.ethereum_context.validateAgainstVmContextV2(
                &self.projection.projected_native,
                &self.extension_statement,
                &self.interaction_claims.ethereum,
                &self.projected_base.vm_air,
            );
            if (!std.mem.eql(u8, &self.identity, &captureIdentity(Engine, self)))
                return error.InvalidFreshVerifiedCandidateLeafCapture;
        }

        pub fn validateAgainst(
            self: *const Self,
            full_statement: *const statement_v2.RiscVStatementV2,
            extension: *const ethereum_statement.Statement,
            base_claim: *const base_types.RiscVInteractionClaim,
            interaction_claims: *const tree_mod.InteractionClaims,
            profile: *const profile_mod.Profile,
            plan: *const provider_authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            provider_stage_a: *const ordinary_omit.ProviderStageAManifestV1(Engine),
            expected_shared: candidate_omit.SharedRelationAuthorityV1(Engine),
            expected_commitments: *const [4]Engine.Hasher.Hash,
        ) !void {
            try self.validate();
            try provider_stage_a.validate(plan, calls);
            if (!std.meta.eql(self.full_statement.authority_id, full_statement.authority_id) or
                !std.meta.eql(
                    self.full_statement.public_data.wireId(),
                    full_statement.public_data.wireId(),
                ) or !std.meta.eql(self.extension_statement, extension.*) or
                !std.meta.eql(self.profile, profile.*) or
                !std.meta.eql(self.interaction_claims, interaction_claims.*) or
                !std.meta.eql(self.provider_shared_authority, expected_shared) or
                !std.meta.eql(self.proof_commitments, expected_commitments.*) or
                self.interaction_pow != base_claim.interaction_pow)
            {
                return error.FreshVerifiedCandidateLeafCaptureMismatch;
            }

            var manifest = lookup_physical_v2.Manifest.native();
            const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
                &self.full_statement.core,
                &manifest,
            );
            try self.projection.validateAgainstWithRetirementSupplementV2(
                &self.full_statement,
                &self.extension_statement,
                .proof,
                self.admission.retirementSupplementV2(),
                &manifest,
                &authenticated,
                plan,
                calls,
                try native_provider_omit.deriveFullGeometry(&self.full_statement),
            );
            const base_interaction_columns: u32 = @intCast(
                try authenticated.totalInteractionColumns(
                    &self.projection.projected_native.core,
                    &manifest,
                ),
            );
            try self.provider_shared_authority.validate(
                &self.full_statement,
                &self.extension_statement,
                base_interaction_columns,
                &self.profile,
                plan,
                provider_stage_a,
                &self.projection,
            );
            const relation_context = try provider_authority.PoseidonRelationContextV1
                .canonical(
                plan.session,
                self.relations.ethereum.base.poseidon2.z,
                self.relations.ethereum.base.poseidon2.alpha,
            );
            const canonical_base = try authenticated.canonicalInteractionClaim(
                &self.projection.projected_native.core,
                &manifest,
                base_claim,
            );
            const residual = try integration.residualWithoutNativePoseidonV2(
                &self.projection,
                &self.full_statement,
                &self.extension_statement,
                .proof,
                &manifest,
                &authenticated,
                plan,
                calls,
                try native_provider_omit.deriveFullGeometry(&self.full_statement),
                &self.relations,
                base_claim,
                &self.interaction_claims.ethereum,
                &self.profile,
                self.interaction_claims.candidate,
            );
            if (!std.meta.eql(
                relation_context,
                self.provider_shared_authority.relation_context,
            ) or !std.meta.eql(
                canonical_base.claimed_sums,
                self.projected_base.vm_air.canonical_claims,
            ) or !self.fresh_core.poseidon2_residual.eql(residual)) {
                return error.FreshVerifiedCandidateLeafCaptureMismatch;
            }
        }
    };
}

pub fn verifyWithEngineAndCapture(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    extension: ethereum_statement.Statement,
    proof_in: base_types.ProofForEngine(Engine),
    base_claim: *const base_types.RiscVInteractionClaim,
    interaction_claims: *const tree_mod.InteractionClaims,
    profile: *const profile_mod.Profile,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    provider_stage_a: *const ordinary_omit.ProviderStageAManifestV1(Engine),
    expected_shared: candidate_omit.SharedRelationAuthorityV1(Engine),
    capture_out: *FreshVerifiedCandidateLeafCaptureV1(Engine),
) !void {
    var channel = Engine.Channel{};
    return verifyWithEngineAndCaptureUsingChannel(
        Engine,
        allocator,
        pcs_config,
        statement,
        extension,
        proof_in,
        base_claim,
        interaction_claims,
        profile,
        plan,
        calls,
        provider_stage_a,
        expected_shared,
        &channel,
        capture_out,
    );
}

pub fn verifyWithEngineAndCaptureUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    extension: ethereum_statement.Statement,
    proof_in: base_types.ProofForEngine(Engine),
    base_claim: *const base_types.RiscVInteractionClaim,
    interaction_claims: *const tree_mod.InteractionClaims,
    profile: *const profile_mod.Profile,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    provider_stage_a: *const ordinary_omit.ProviderStageAManifestV1(Engine),
    expected_shared: candidate_omit.SharedRelationAuthorityV1(Engine),
    channel: *Engine.Channel,
    capture_out: *FreshVerifiedCandidateLeafCaptureV1(Engine),
) !void {
    comptime @import("stwo_prover_api").assertProverEngine(Engine);
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);

    try statement.validate();
    try interaction_claims.validate(&extension, profile);
    try provider_stage_a.validate(plan, calls);
    if (proof.commitment_scheme_proof.commitments.items.len != 4)
        return core_verifier.VerificationError.InvalidStructure;

    var transcript_extension = try candidate_omit.Extension(Engine)
        .initForFreshVerify(
        plan,
        calls,
        provider_stage_a,
        profile,
        expected_shared,
    );
    const admitted_profile = try transcript_extension.profileValue();
    var manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        &statement.core,
        &manifest,
    );
    var projected_core = statement.core;
    try transcript_extension.prepareProjectedVerifierCore(
        &statement,
        &extension,
        &manifest,
        &authenticated,
        &projected_core,
    );
    const projection = try transcript_extension.providerProjection();
    try projection.validateSealAndFull(&statement, &extension);
    if (!std.meta.eql(projected_core, projection.projected_native.core))
        return error.ProjectedCoreInstallMismatch;
    if (base_claim.n_components != projected_core.n_components or
        base_claim.n_infra != projected_core.n_infra)
    {
        return core_verifier.VerificationError.InvalidStructure;
    }
    const base_interaction_columns: u32 = @intCast(
        try authenticated.totalInteractionColumns(
            &projected_core,
            &manifest,
        ),
    );
    try admitted_profile.validate(
        &projected_core,
        &extension,
        base_interaction_columns,
    );
    const admission = try admission_mod.validateProjectedV2(
        &statement,
        &projected_core,
        &extension,
        base_interaction_columns,
        admitted_profile,
        .proof,
    );

    pcs_config.mixInto(channel);
    try statement_v2.mixIntoNativeTranscript(&statement.public_data, channel);
    authenticated.mixInto(channel);
    try extension.mixIntoV2(&statement, channel);

    const tree0_columns = try tree_mod.mixAndGenerateTree0ForVerifier(
        allocator,
        channel,
        projection,
        &statement,
        &extension,
        &manifest,
        &authenticated,
        admitted_profile,
    );
    try verifyPreprocessedRoot(
        Engine,
        allocator,
        pcs_config,
        tree0_columns,
        proof.commitment_scheme_proof.commitments.items[0],
    );

    var scheme = try pcs_verifier.CommitmentSchemeVerifier(
        base_types.HasherForEngine(Engine),
        Engine.MerkleChannel,
    ).init(allocator, pcs_config);
    defer scheme.deinit(allocator);
    var tree_logs = try tree_mod.logSizes(
        allocator,
        &projected_core,
        &extension,
        &manifest,
        &authenticated,
        admitted_profile,
    );
    defer tree_logs.deinit(allocator);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[0],
        tree_logs.tree0,
        channel,
    );
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        tree_logs.tree1,
        channel,
    );

    const relations = try transcript_extension.verifyRelations(
        allocator,
        pcs_config,
        channel,
        &statement,
        &projected_core,
        &extension,
        &manifest,
        &authenticated,
        base_claim.interaction_pow,
        proof.commitment_scheme_proof.commitments.items[0],
        proof.commitment_scheme_proof.commitments.items[1],
    );
    try integration.mixInteractionClaimV2(
        channel,
        &projected_core,
        &manifest,
        &authenticated,
        base_claim,
        &interaction_claims.ethereum,
        admitted_profile,
        interaction_claims.candidate,
    );
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[2],
        tree_logs.tree2,
        channel,
    );

    const residual = try integration.residualWithoutNativePoseidonV2(
        projection,
        &statement,
        &extension,
        .proof,
        &manifest,
        &authenticated,
        plan,
        calls,
        try native_provider_omit.deriveFullGeometry(&statement),
        &relations,
        base_claim,
        &interaction_claims.ethereum,
        admitted_profile,
        interaction_claims.candidate,
    );
    const workspace = try proof_workspace.VerificationWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    workspace.canonical = try authenticated.canonicalInteractionClaim(
        &projected_core,
        &manifest,
        base_claim,
    );
    const base_components = try base_verifier
        .assembleComponentsAuthenticatedLookupV2(
        workspace,
        &projected_core,
        base_claim,
        &relations.ethereum.base,
        projected_core.nMainColumns(),
        base_interaction_columns,
        &manifest,
        &authenticated,
    );
    const assembly = try integration.Assembly(.verifier)
        .createWithoutNativePoseidonAuthenticatedLookupV2(
        allocator,
        projection,
        &statement,
        &extension,
        &relations,
        base_components,
        &interaction_claims.ethereum,
        interaction_claims.candidate,
        &manifest,
        &authenticated,
        admitted_profile,
    );
    defer assembly.destroy(allocator);

    var commitments: [4]Engine.Hasher.Hash = undefined;
    @memcpy(&commitments, proof.commitment_scheme_proof.commitments.items[0..4]);
    const commitments_identity = proof_authority.commitmentsIdentity(
        Engine,
        &commitments,
    );
    var proof_capture: base_verifier.ProofCaptureForEngine(Engine) = undefined;
    var proof_capture_owned = false;
    defer if (proof_capture_owned) proof_capture.deinit(allocator);
    proof_moved = true;
    try core_verifier.verifyWithProofCapture(
        base_types.HasherForEngine(Engine),
        Engine.MerkleChannel,
        allocator,
        assembly.active(),
        channel,
        &scheme,
        proof,
        &proof_capture,
    );
    proof_capture_owned = true;
    try transcript_extension.recordFreshVerifierAuthority(
        residual,
        commitments_identity,
    );
    const fresh_core = transcript_extension.inner.fresh_core orelse
        return error.MissingEthereumProviderFreshCoreAuthority;
    try fresh_core.validate();
    const shared = transcript_extension.shared_relation orelse
        return error.MissingEthereumCandidateSharedAuthority;

    var owned_public = try statement_v2.OwnedPublicDataV2.initVerified(
        allocator,
        &statement.public_data,
    );
    var owned_public_moved = false;
    defer if (!owned_public_moved) owned_public.deinit();
    const projected_owned = try statement_v2.RiscVStatementV2.init(
        projected_core,
        owned_public.data,
    );
    const native_sums = try statement_v2.NativePublicSums.init(
        &owned_public.data,
        &relations.ethereum.base,
    );
    const receipt = try projected_owned.verifiedReceipt();
    var vm_air = try vm_leaf_context_v2.ContextV2.initVerified(
        allocator,
        &projected_owned,
        base_claim,
        &relations.ethereum.base,
        &manifest,
        &authenticated,
        base_components,
        &proof_capture,
        &receipt,
        &native_sums,
    );
    var vm_air_moved = false;
    defer if (!vm_air_moved) vm_air.deinit();
    const extension_context = try ethereum_context.ContextV1
        .initVerifiedWithVmContextV2(
        &projected_owned,
        &extension,
        &interaction_claims.ethereum,
        &relations.ethereum,
        assembly.ethereum,
        &vm_air,
    );
    var base_capture = base_verifier.VerifiedSegmentV2CaptureForEngine(Engine){
        .proof = proof_capture,
        .vm_air = vm_air,
        .public_data = owned_public,
        .native_public_sums = native_sums,
        .receipt = receipt,
    };
    var base_capture_moved = false;
    defer if (!base_capture_moved) base_capture.deinit(allocator);
    proof_capture_owned = false;
    vm_air_moved = true;
    owned_public_moved = true;

    const owned_full = try statement_v2.RiscVStatementV2.init(
        statement.core,
        base_capture.public_data.data,
    );
    var owned_projection = projection.*;
    owned_projection.projected_native = try statement_v2.RiscVStatementV2.init(
        projected_core,
        base_capture.public_data.data,
    );
    var capture = FreshVerifiedCandidateLeafCaptureV1(Engine){
        .projected_base = base_capture,
        .full_statement = owned_full,
        .projection = owned_projection,
        .extension_statement = extension,
        .ethereum_context = extension_context,
        .profile = admitted_profile.*,
        .admission = admission,
        .relations = relations,
        .interaction_claims = interaction_claims.*,
        .provider_shared_authority = shared,
        .fresh_core = fresh_core,
        .proof_commitments = commitments,
        .proof_commitments_identity = commitments_identity,
        .interaction_pow = base_claim.interaction_pow,
        .identity = undefined,
    };
    capture.identity = captureIdentity(Engine, &capture);
    try capture.validateAgainst(
        &statement,
        &extension,
        base_claim,
        interaction_claims,
        admitted_profile,
        plan,
        calls,
        provider_stage_a,
        expected_shared,
        &commitments,
    );
    capture_out.* = capture;
    base_capture_moved = true;
}

fn verifyPreprocessedRoot(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    columns: []prover_pcs.ColumnEvaluation,
    actual: Engine.Hasher.Hash,
) !void {
    var moved = false;
    errdefer if (!moved) freeColumns(allocator, columns);
    var scheme = try Engine.init(allocator, pcs_config);
    defer Engine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(.never);
    var channel = Engine.Channel{};
    moved = true;
    try Engine.commit(&scheme, allocator, columns, null, &channel);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 1 or !std.meta.eql(roots.items[0], actual))
        return base_types.ProverError.InvalidPreprocessedCommitment;
}

fn freeColumns(
    allocator: std.mem.Allocator,
    columns: []prover_pcs.ColumnEvaluation,
) void {
    for (columns) |column| allocator.free(@constCast(column.values));
    allocator.free(columns);
}

fn captureIdentity(
    comptime Engine: type,
    capture: *const FreshVerifiedCandidateLeafCaptureV1(Engine),
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(capture_domain);
    hashInt(&hash, u16, capture.format);
    hashInt(&hash, u16, capture.schema);
    hash.update(&capture.projected_base.vm_air.identity_digest);
    hash.update(&capture.ethereum_context.identity_digest);
    hashU32Digest(&hash, capture.full_statement.authority_id);
    hash.update(&capture.projection.identity);
    hash.update(&capture.profile.identity);
    hashAdmission(&hash, capture.admission);
    hash.update(&capture.provider_shared_authority.identity);
    hash.update(&capture.fresh_core.identity);
    hash.update(&capture.proof_commitments_identity);
    hashInt(&hash, u64, capture.interaction_pow);
    hashCandidateClaims(&hash, capture.interaction_claims.candidate);
    hash.update(&.{
        @intFromBool(capture.fresh_core_stark_verified),
        @intFromBool(capture.production_eligible),
        @intFromBool(capture.recursive_admissible),
    });
    return hash.finalResult();
}

fn hashAdmission(
    hash: *std.crypto.hash.sha2.Sha256,
    admission: admission_mod.Admission,
) void {
    hashInt(hash, u16, admission.format);
    hashInt(hash, u32, admission.candidate_retirements);
    hashInt(hash, u32, admission.total_external_retirements);
    hashInt(hash, u64, admission.candidate_extra_memory_terms);
    hashInt(hash, u64, admission.total_extra_memory_terms);
    hashInt(hash, u64, admission.expected_memory_relation_terms);
    for (admission.extended_fixed_table_bounds) |bound|
        hashInt(hash, u64, bound);
    hash.update(&.{@intFromBool(admission.production_eligible)});
}

fn hashCandidateClaims(
    hash: *std.crypto.hash.sha2.Sha256,
    claims: integration.Claims,
) void {
    inline for (.{
        claims.bulk_memcpy_caller,
        claims.bulk_memcpy_words,
        claims.stack_swap_caller,
        claims.stack_swap_words,
    }) |claim| {
        hashInt(hash, u32, claim.log_size);
        hashInt(hash, u32, claim.n_rows);
        for (claim.batch_sums) |sum| hashQm31(hash, sum);
        hashQm31(hash, claim.component_sum);
    }
}

fn hashQm31(hash: *std.crypto.hash.sha2.Sha256, value: QM31) void {
    for (value.toM31Array()) |limb| hashInt(hash, u32, limb.v);
}

fn hashU32Digest(
    hash: *std.crypto.hash.sha2.Sha256,
    value: [8]u32,
) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

comptime {
    if (production_active or profile_mod.production_active or
        admission_mod.production_active or integration.production_active or
        candidate_omit.production_active or ordinary_omit.ACTIVATES_PRODUCTION_PROOF)
    {
        @compileError("candidate leaf verifier became production-active");
    }
}
