//! Independent verification for combined Ethereum leaf proofs.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_verifier = @import("stwo_core").verifier;
const proof_admission = @import("../../air/guest_precompile/ethereum_proof_admission.zig");
const statement_mod = @import("../../air/guest_precompile/ethereum_statement.zig");
const proof_workspace = @import("../proof_workspace.zig");
const base_types = @import("../types.zig");
const base_verifier = @import("../verifier.zig");
const ethereum_assembly = @import("ethereum_assembly.zig");
const ethereum_cancellation = @import("ethereum_cancellation.zig");
const ethereum_interaction = @import("ethereum_interaction.zig");
const ethereum_main = @import("ethereum_main.zig");
const ethereum_preprocessed = @import("ethereum_preprocessed.zig");
const ethereum_transcript = @import("ethereum_transcript.zig");
const ethereum_types = @import("ethereum_types.zig");

pub fn verifyWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: base_types.RiscVStatement,
    extension: statement_mod.Statement,
    proof_in: base_types.ProofForEngine(Engine),
    base_claim: *const base_types.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
) !void {
    var channel = Engine.Channel{};
    return verifyWithEngineUsingChannel(
        Engine,
        allocator,
        pcs_config,
        statement,
        extension,
        proof_in,
        base_claim,
        extension_claim,
        &channel,
    );
}

pub fn verifyWithEngineUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: base_types.RiscVStatement,
    extension: statement_mod.Statement,
    proof_in: base_types.ProofForEngine(Engine),
    base_claim: *const base_types.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    channel: *Engine.Channel,
) !void {
    comptime @import("stwo_prover_api").assertProverEngine(Engine);
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);

    try proof_admission.validate(&statement, &extension, .proof);
    try extension_claim.validate(&extension);
    if (proof.commitment_scheme_proof.commitments.items.len != 4)
        return core_verifier.VerificationError.InvalidStructure;
    try verifyPreprocessedRoot(
        Engine,
        allocator,
        pcs_config,
        &statement,
        &extension,
        proof.commitment_scheme_proof.commitments.items[0],
    );

    pcs_config.mixInto(channel);
    statement.public_data.mixInto(channel);
    try extension.mixInto(&statement, channel);

    var scheme = try pcs_verifier.CommitmentSchemeVerifier(
        base_types.HasherForEngine(Engine),
        Engine.MerkleChannel,
    ).init(allocator, pcs_config);
    defer scheme.deinit(allocator);

    const tree0 = try ethereum_preprocessed.logSizes(allocator, &statement, &extension);
    defer allocator.free(tree0);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[0],
        tree0,
        channel,
    );
    const tree1 = try ethereum_main.logSizes(allocator, &statement, &extension);
    defer allocator.free(tree1);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        tree1,
        channel,
    );

    const relations = try ethereum_transcript.verifyToRelations(
        allocator,
        channel,
        &statement,
        base_claim.interaction_pow,
    );
    try ethereum_transcript.mixInteractionClaim(
        channel,
        &statement,
        base_claim,
        extension_claim,
    );
    const tree2 = try ethereum_interaction.logSizes(allocator, &statement, &extension);
    defer allocator.free(tree2);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[2],
        tree2,
        channel,
    );

    const workspace = try proof_workspace.VerificationWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    try workspace.canonicalize(base_claim, &statement);
    try ethereum_cancellation.verifyCanonical(
        &statement,
        &relations,
        workspace.canonical.view(),
        extension_claim,
    );
    const base_components = try base_verifier.assembleComponents(
        workspace,
        &statement,
        base_claim,
        &relations.base,
        statement.nMainColumns(),
        statement.nInteractionColumns(),
    );
    const assembly = try ethereum_assembly.Assembly(.verifier).create(
        allocator,
        &statement,
        &extension,
        &relations,
        base_components,
        extension_claim,
    );
    defer assembly.destroy(allocator);

    proof_moved = true;
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

fn verifyPreprocessedRoot(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: *const base_types.RiscVStatement,
    extension: *const statement_mod.Statement,
    actual: base_types.HasherForEngine(Engine).Hash,
) !void {
    const columns = try ethereum_preprocessed.generate(allocator, statement, extension);
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

fn freeColumns(
    allocator: std.mem.Allocator,
    columns: []@import("stwo_prover_engine").pcs.ColumnEvaluation,
) void {
    for (columns) |column| allocator.free(@constCast(column.values));
    allocator.free(columns);
}
