//! Independent verifier for append-only Ethereum SegmentV2 leaf proofs.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_verifier = @import("stwo_core").verifier;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const proof_admission = @import("../../air/guest_precompile/ethereum_proof_admission.zig");
const statement_mod = @import("../../air/guest_precompile/ethereum_statement.zig");
const global_v3 = @import("../../recursion/segment_leaf_local_authority_v3.zig");
const ethereum_context = @import("../../recursion/ethereum_leaf_context_v1.zig");
const vm_leaf_context_v2 = @import("../../recursion/vm_leaf_context_v2.zig");
const proof_workspace = @import("../proof_workspace.zig");
const base_types = @import("../types.zig");
const base_verifier = @import("../verifier.zig");
const native_provider_omit = @import("../memory_provider_shards/native_provider_omit_v1.zig");
const ethereum_assembly = @import("ethereum_assembly.zig");
const ethereum_cancellation = @import("ethereum_cancellation.zig");
const ethereum_interaction = @import("ethereum_interaction.zig");
const ethereum_main = @import("ethereum_main.zig");
const ethereum_preprocessed = @import("ethereum_preprocessed.zig");
const ethereum_capture_v3 = @import("ethereum_segment_capture_v3.zig");
const ethereum_transcript = @import("ethereum_transcript.zig");
const ethereum_types = @import("ethereum_types.zig");

pub fn CaptureForEngine(comptime Engine: type) type {
    return base_verifier.VerifiedSegmentV2CaptureForEngine(Engine);
}

pub fn VerifiedEthereumSegmentV3CaptureForEngine(comptime Engine: type) type {
    return ethereum_capture_v3.VerifiedEthereumSegmentV3CaptureForEngine(Engine);
}

pub fn verifyWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    extension: statement_mod.Statement,
    proof_in: base_types.ProofForEngine(Engine),
    base_claim: *const base_types.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
) !void {
    var channel = Engine.Channel{};
    return verifyInternal(
        Engine,
        false,
        false,
        @as(void, {}),
        allocator,
        pcs_config,
        statement,
        extension,
        proof_in,
        base_claim,
        extension_claim,
        &channel,
        null,
        null,
    );
}

pub fn verifyWithEngineUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    extension: statement_mod.Statement,
    proof_in: base_types.ProofForEngine(Engine),
    base_claim: *const base_types.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    channel: *Engine.Channel,
) !void {
    return verifyInternal(
        Engine,
        false,
        false,
        @as(void, {}),
        allocator,
        pcs_config,
        statement,
        extension,
        proof_in,
        base_claim,
        extension_claim,
        channel,
        null,
        null,
    );
}

pub fn verifyWithEngineAndCapture(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    extension: statement_mod.Statement,
    proof_in: base_types.ProofForEngine(Engine),
    base_claim: *const base_types.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    capture: *CaptureForEngine(Engine),
) !void {
    var channel = Engine.Channel{};
    return verifyInternal(
        Engine,
        false,
        false,
        @as(void, {}),
        allocator,
        pcs_config,
        statement,
        extension,
        proof_in,
        base_claim,
        extension_claim,
        &channel,
        capture,
        null,
    );
}

pub fn verifyWithEngineAndCaptureUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    extension: statement_mod.Statement,
    proof_in: base_types.ProofForEngine(Engine),
    base_claim: *const base_types.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    channel: *Engine.Channel,
    capture: *CaptureForEngine(Engine),
) !void {
    return verifyInternal(
        Engine,
        false,
        false,
        @as(void, {}),
        allocator,
        pcs_config,
        statement,
        extension,
        proof_in,
        base_claim,
        extension_claim,
        channel,
        capture,
        null,
    );
}

/// Full recursive-ingress capture. Caller publication is transactional: the
/// base capture, fourteen-component context, global link and aggregate seal
/// are assembled in locals and assigned only after every check succeeds.
pub fn verifyWithEngineAndEthereumV3Capture(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    extension: statement_mod.Statement,
    proof_in: base_types.ProofForEngine(Engine),
    base_claim: *const base_types.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    global: *const global_v3.MetadataV3,
    capture_out: *VerifiedEthereumSegmentV3CaptureForEngine(Engine),
) !void {
    var channel = Engine.Channel{};
    return verifyWithEngineAndEthereumV3CaptureUsingChannel(
        Engine,
        allocator,
        pcs_config,
        statement,
        extension,
        proof_in,
        base_claim,
        extension_claim,
        global,
        &channel,
        capture_out,
    );
}

pub fn verifyWithEngineAndEthereumV3CaptureUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    extension: statement_mod.Statement,
    proof_in: base_types.ProofForEngine(Engine),
    base_claim: *const base_types.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    global: *const global_v3.MetadataV3,
    channel: *Engine.Channel,
    capture_out: *VerifiedEthereumSegmentV3CaptureForEngine(Engine),
) !void {
    try global.validate();
    var base_capture: CaptureForEngine(Engine) = undefined;
    var base_owned = false;
    defer if (base_owned) base_capture.deinit(allocator);
    var extension_context: ethereum_context.ContextV1 = undefined;
    try verifyInternal(
        Engine,
        false,
        false,
        @as(void, {}),
        allocator,
        pcs_config,
        statement,
        extension,
        proof_in,
        base_claim,
        extension_claim,
        channel,
        &base_capture,
        &extension_context,
    );
    base_owned = true;
    const capture = try VerifiedEthereumSegmentV3CaptureForEngine(Engine)
        .initVerified(
        base_capture,
        statement.core,
        extension,
        extension_claim.*,
        extension_context,
        global.*,
    );
    capture_out.* = capture;
    base_owned = false;
}

pub fn verifyInternal(
    comptime Engine: type,
    comptime use_transcript_extension: bool,
    comptime omit_native_provider: bool,
    transcript_extension: anytype,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    extension: statement_mod.Statement,
    proof_in: base_types.ProofForEngine(Engine),
    base_claim: *const base_types.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    channel: *Engine.Channel,
    capture_out: ?*CaptureForEngine(Engine),
    extension_context_out: ?*ethereum_context.ContextV1,
) !void {
    comptime @import("stwo_prover_api").assertProverEngine(Engine);
    comptime if (omit_native_provider and !use_transcript_extension)
        @compileError("native provider omission requires a transcript extension");
    if ((capture_out == null) != (extension_context_out == null))
        return error.InvalidEthereumCaptureRequest;
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);

    try statement.validate();
    try proof_admission.validateV2(&statement, &extension, .proof);
    try extension_claim.validate(&extension);
    const full_core = &statement.core;
    var manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        full_core,
        &manifest,
    );
    var projected_core = full_core.*;
    const core = if (comptime omit_native_provider) blk: {
        try transcript_extension.prepareProjectedVerifierCore(
            &statement,
            &extension,
            &manifest,
            &authenticated,
            &projected_core,
        );
        const projection: *const native_provider_omit.ProjectionV1 =
            try transcript_extension.providerProjection();
        try projection.validateSealAndFull(&statement, &extension);
        if (!std.meta.eql(projected_core, projection.projected_native.core))
            return error.ProjectedCoreInstallMismatch;
        break :blk &projected_core;
    } else full_core;
    if (base_claim.n_components != core.n_components or
        base_claim.n_infra != core.n_infra or
        proof.commitment_scheme_proof.commitments.items.len != 4)
    {
        return core_verifier.VerificationError.InvalidStructure;
    }

    if (comptime omit_native_provider) {
        try verifyPreprocessedRootWithoutNativePoseidon(
            Engine,
            allocator,
            pcs_config,
            try transcript_extension.providerProjection(),
            &statement,
            &extension,
            proof.commitment_scheme_proof.commitments.items[0],
        );
    } else {
        try verifyPreprocessedRoot(
            Engine,
            allocator,
            pcs_config,
            core,
            &extension,
            proof.commitment_scheme_proof.commitments.items[0],
        );
    }

    pcs_config.mixInto(channel);
    try statement_v2.mixIntoNativeTranscript(&statement.public_data, channel);
    authenticated.mixInto(channel);
    try extension.mixIntoV2(&statement, channel);

    var scheme = try pcs_verifier.CommitmentSchemeVerifier(
        base_types.HasherForEngine(Engine),
        Engine.MerkleChannel,
    ).init(allocator, pcs_config);
    defer scheme.deinit(allocator);

    const tree0 = try ethereum_preprocessed.logSizes(allocator, core, &extension);
    defer allocator.free(tree0);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[0],
        tree0,
        channel,
    );
    const tree1 = try ethereum_main.logSizes(allocator, core, &extension);
    defer allocator.free(tree1);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        tree1,
        channel,
    );

    const relations = if (comptime use_transcript_extension)
        try transcript_extension.verifyRelations(
            allocator,
            pcs_config,
            channel,
            &statement,
            core,
            &extension,
            &manifest,
            &authenticated,
            base_claim.interaction_pow,
            proof.commitment_scheme_proof.commitments.items[0],
            proof.commitment_scheme_proof.commitments.items[1],
        )
    else
        try ethereum_transcript.verifyToRelations(
            allocator,
            channel,
            core,
            base_claim.interaction_pow,
        );
    try ethereum_transcript.mixInteractionClaimV2(
        channel,
        core,
        &manifest,
        &authenticated,
        base_claim,
        extension_claim,
    );
    const tree2 = try ethereum_interaction.logSizesAuthenticatedLookupV2(
        allocator,
        core,
        &extension,
        &manifest,
        &authenticated,
    );
    defer allocator.free(tree2);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[2],
        tree2,
        channel,
    );

    var fresh_residual: ?QM31 = null;
    if (comptime omit_native_provider) {
        fresh_residual = try ethereum_cancellation.residualWithoutNativePoseidonV2(
            try transcript_extension.providerProjection(),
            &statement,
            &extension,
            .proof,
            &manifest,
            &authenticated,
            transcript_extension.providerPlan(),
            transcript_extension.providerCalls(),
            try native_provider_omit.deriveFullGeometry(&statement),
            &relations,
            base_claim,
            extension_claim,
        );
    } else {
        try ethereum_cancellation.verifyV2(
            &statement,
            &manifest,
            &authenticated,
            &relations,
            base_claim,
            extension_claim,
        );
    }
    const workspace = try proof_workspace.VerificationWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    workspace.canonical = try authenticated.canonicalInteractionClaim(
        core,
        &manifest,
        base_claim,
    );
    const base_interaction_count = try authenticated.totalInteractionColumns(
        core,
        &manifest,
    );
    const base_components = try base_verifier
        .assembleComponentsAuthenticatedLookupV2(
        workspace,
        core,
        base_claim,
        &relations.base,
        core.nMainColumns(),
        base_interaction_count,
        &manifest,
        &authenticated,
    );
    const assembly = if (comptime omit_native_provider)
        try ethereum_assembly.Assembly(.verifier)
            .createWithoutNativePoseidonAuthenticatedLookupV2(
            allocator,
            try transcript_extension.providerProjection(),
            &statement,
            &extension,
            &relations,
            base_components,
            extension_claim,
            &manifest,
            &authenticated,
        )
    else
        try ethereum_assembly.Assembly(.verifier).createAuthenticatedLookupV2(
            allocator,
            &statement,
            &extension,
            &relations,
            base_components,
            extension_claim,
            &manifest,
            &authenticated,
        );
    defer assembly.destroy(allocator);

    const records_fresh_omission_authority = comptime omit_native_provider and
        @hasDecl(
            @TypeOf(transcript_extension.*),
            "recordFreshVerifierAuthority",
        );
    const omission_commitments_identity = if (records_fresh_omission_authority)
        transcript_extension.proofCommitmentsIdentity(
            proof.commitment_scheme_proof.commitments.items,
        )
    else {};
    proof_moved = true;
    if (comptime omit_native_provider) {
        var proof_capture: base_verifier.ProofCaptureForEngine(Engine) = undefined;
        var proof_capture_owned = false;
        defer if (proof_capture_owned) proof_capture.deinit(allocator);
        if (capture_out != null) {
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
        } else {
            try core_verifier.verify(
                base_types.HasherForEngine(Engine),
                Engine.MerkleChannel,
                allocator,
                assembly.active(),
                channel,
                &scheme,
                proof,
            );
        }
        const verified_residual = fresh_residual orelse
            return error.MissingProjectedCoreResidual;
        if (capture_out) |capture| {
            var owned_public = try statement_v2.OwnedPublicDataV2.initVerified(
                allocator,
                &statement.public_data,
            );
            errdefer owned_public.deinit();
            const projected_statement = try statement_v2.RiscVStatementV2.init(
                projected_core,
                owned_public.data,
            );
            const native_sums = try statement_v2.NativePublicSums.init(
                &owned_public.data,
                &relations.base,
            );
            const receipt = try projected_statement.verifiedReceipt();
            var vm_air = try vm_leaf_context_v2.ContextV2.initVerified(
                allocator,
                &projected_statement,
                base_claim,
                &relations.base,
                &manifest,
                &authenticated,
                base_components,
                &proof_capture,
                &receipt,
                &native_sums,
            );
            errdefer vm_air.deinit();
            const extension_context = try ethereum_context.ContextV1
                .initVerifiedWithVmContextV2(
                &projected_statement,
                &extension,
                extension_claim,
                &relations,
                assembly,
                &vm_air,
            );
            if (records_fresh_omission_authority) {
                try transcript_extension.recordFreshVerifierAuthority(
                    verified_residual,
                    omission_commitments_identity,
                );
            } else {
                try transcript_extension.recordFreshVerifierResidual(
                    verified_residual,
                );
            }
            capture.* = .{
                .proof = proof_capture,
                .vm_air = vm_air,
                .public_data = owned_public,
                .native_public_sums = native_sums,
                .receipt = receipt,
            };
            extension_context_out.?.* = extension_context;
            proof_capture_owned = false;
            return;
        }
        if (records_fresh_omission_authority) {
            try transcript_extension.recordFreshVerifierAuthority(
                verified_residual,
                omission_commitments_identity,
            );
        } else {
            try transcript_extension.recordFreshVerifierResidual(
                verified_residual,
            );
        }
        return;
    }
    if (capture_out) |capture| {
        var proof_capture: base_verifier.ProofCaptureForEngine(Engine) = undefined;
        var proof_capture_owned = false;
        defer if (proof_capture_owned) proof_capture.deinit(allocator);
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
        var owned_public = try statement_v2.OwnedPublicDataV2.initVerified(
            allocator,
            &statement.public_data,
        );
        errdefer owned_public.deinit();
        const native_sums = try statement_v2.NativePublicSums.init(
            &owned_public.data,
            &relations.base,
        );
        const receipt = try statement.verifiedReceipt();
        var vm_air = try vm_leaf_context_v2.ContextV2.initVerified(
            allocator,
            &statement,
            base_claim,
            &relations.base,
            &manifest,
            &authenticated,
            base_components,
            &proof_capture,
            &receipt,
            &native_sums,
        );
        errdefer vm_air.deinit();
        const extension_context = try ethereum_context.ContextV1
            .initVerifiedWithVmContextV2(
            &statement,
            &extension,
            extension_claim,
            &relations,
            assembly,
            &vm_air,
        );
        capture.* = .{
            .proof = proof_capture,
            .vm_air = vm_air,
            .public_data = owned_public,
            .native_public_sums = native_sums,
            .receipt = receipt,
        };
        extension_context_out.?.* = extension_context;
        proof_capture_owned = false;
    } else {
        try core_verifier.verify(
            base_types.HasherForEngine(Engine),
            Engine.MerkleChannel,
            allocator,
            assembly.active(),
            channel,
            &scheme,
            proof,
        );
    }
}

fn verifyPreprocessedRoot(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: *const base_types.RiscVStatement,
    extension: *const statement_mod.Statement,
    actual: base_types.HasherForEngine(Engine).Hash,
) !void {
    const columns = try ethereum_preprocessed.generate(
        allocator,
        statement,
        extension,
    );
    var moved = false;
    errdefer if (!moved) freeColumns(allocator, columns);
    var scheme = try Engine.init(allocator, pcs_config);
    defer Engine.deinit(&scheme, allocator);
    var channel = Engine.Channel{};
    moved = true;
    try Engine.commit(&scheme, allocator, columns, null, &channel);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 1 or !std.meta.eql(roots.items[0], actual))
        return base_types.ProverError.InvalidPreprocessedCommitment;
}

fn verifyPreprocessedRootWithoutNativePoseidon(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    projection: *const native_provider_omit.ProjectionV1,
    statement: *const statement_v2.RiscVStatementV2,
    extension: *const statement_mod.Statement,
    actual: base_types.HasherForEngine(Engine).Hash,
) !void {
    const columns = try ethereum_preprocessed.generateWithoutNativePoseidonV2(
        allocator,
        projection,
        statement,
        extension,
    );
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
    columns: []@import("stwo_prover_engine").pcs.ColumnEvaluation,
) void {
    for (columns) |column| allocator.free(@constCast(column.values));
    allocator.free(columns);
}
