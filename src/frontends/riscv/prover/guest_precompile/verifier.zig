//! Independent transcript reconstruction and verification for Poseidon2 proofs.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_verifier = @import("stwo_core").verifier;
const proof_admission = @import("../../air/guest_precompile/proof_admission.zig");
const proof_transcript = @import("../../air/guest_precompile/proof_transcript.zig");
const artifact_identity = @import("../../air/guest_precompile/artifact_identity.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const proof_workspace = @import("../proof_workspace.zig");
const base_types = @import("../types.zig");
const base_verifier = @import("../verifier.zig");
const cancellation = @import("cancellation.zig");
const component_assembly = @import("component_assembly.zig");
const trace_geometry = @import("trace_geometry.zig");
const profile_types = @import("types.zig");

pub fn verifyPoseidon2WithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: base_types.RiscVStatement,
    extension: guest_statement.ExtensionStatement,
    artifact: artifact_identity.Identity,
    proof_in: base_types.Proof,
    claim: *const profile_types.InteractionClaim,
) !void {
    var channel = Engine.Channel{};
    return verifyPoseidon2WithEngineUsingChannel(
        Engine,
        allocator,
        pcs_config,
        statement,
        extension,
        artifact,
        proof_in,
        claim,
        &channel,
    );
}

/// Verifier-channel substitution point for transcript parity tests. Consumes
/// `proof_in` on every success and failure path, matching the base verifier.
pub fn verifyPoseidon2WithEngineUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: base_types.RiscVStatement,
    extension: guest_statement.ExtensionStatement,
    artifact: artifact_identity.Identity,
    proof_in: base_types.Proof,
    claim: *const profile_types.InteractionClaim,
    channel: *Engine.Channel,
) !void {
    comptime @import("stwo_prover_api").assertProverEngine(Engine);
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);

    // Every prover-supplied authority is rejected before transcript mutation or
    // verifier commitment allocation. The transcript helper repeats admission
    // at its own boundary as defense in depth.
    try proof_admission.validate(&statement, &extension, artifact, .proof);
    try claim.validate(&statement, &extension);
    if (proof.commitment_scheme_proof.commitments.items.len != 4)
        return core_verifier.VerificationError.InvalidStructure;
    try trace_geometry.verifyPreprocessedRoot(
        Engine,
        allocator,
        pcs_config,
        &statement,
        &extension,
        proof.commitment_scheme_proof.commitments.items[0],
    );

    pcs_config.mixInto(channel);
    statement.public_data.mixInto(channel);
    try proof_transcript.mixProfileIdentity(
        channel,
        &statement,
        &extension,
        artifact,
    );

    var commitment_scheme = try pcs_verifier.CommitmentSchemeVerifier(
        base_types.Hasher,
        Engine.MerkleChannel,
    ).init(allocator, pcs_config);
    defer commitment_scheme.deinit(allocator);

    var tree0 = try trace_geometry.tree0LogSizes(allocator, &statement, &extension);
    defer tree0.deinit(allocator);
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[0],
        tree0.values,
        channel,
    );

    var tree1 = try trace_geometry.tree1LogSizes(allocator, &statement, &extension);
    defer tree1.deinit(allocator);
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        tree1.values,
        channel,
    );

    const relations = try proof_transcript.verifyToRelations(
        allocator,
        channel,
        &statement,
        &extension,
        claim.interactionPow(),
    );

    const workspace = try proof_workspace.VerificationWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    const aggregate = try claim.canonicalStatementClaim(
        &statement,
        &extension,
        &workspace.canonical,
    );
    var tree2 = try trace_geometry.tree2LogSizes(allocator, &statement, &extension);
    defer tree2.deinit(allocator);
    try proof_transcript.mixInteractionClaim(
        channel,
        &statement,
        &extension,
        &aggregate,
        .{
            .base = &claim.base,
            .caller = &claim.caller.batch_sums,
            .provider = &claim.provider.batch_sums,
        },
    );
    try commitment_scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[2],
        tree2.values,
        channel,
    );

    try cancellation.verifyCanonical(
        &statement,
        &relations,
        workspace.canonical.view(),
        claim.caller,
        claim.provider,
    );
    const base_components = try base_verifier.assembleComponents(
        workspace,
        &statement,
        &claim.base,
        &relations.base,
        statement.nMainColumns(),
        statement.nInteractionColumns(),
    );
    const assembly = try component_assembly.VerifierAssembly.create(
        allocator,
        &statement,
        &extension,
        &relations,
        base_components,
        claim.caller,
        claim.provider,
    );
    defer assembly.destroy(allocator);

    proof_moved = true;
    try core_verifier.verify(
        base_types.Hasher,
        Engine.MerkleChannel,
        allocator,
        assembly.active(),
        channel,
        &commitment_scheme,
        proof,
    );
}
