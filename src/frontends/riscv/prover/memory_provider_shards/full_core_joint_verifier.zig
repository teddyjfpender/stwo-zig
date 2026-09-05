//! Fresh verifier mint for the additive full-RISC-V + N-provider protocol.
//!
//! The native full-core proof still contains its ordinary Poseidon provider.
//! After complete STARK/PCS/FRI and global LogUp verification, its authenticated
//! provider total is negated to expose the caller residual that independent
//! provider shards must close. This is a correctness bridge only; the retained
//! native provider prevents the route from satisfying the bounded-memory
//! production predicate.

const std = @import("std");
const core_pcs = @import("stwo_core").pcs;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const statement_mod = @import("../../air/statement.zig");
const types = @import("../types.zig");
const verifier = @import("../verifier.zig");
const full_core = @import("full_core_joint_protocol.zig");
const proof_authority = @import("joint_proof_authority.zig");

pub const format_version: u32 = full_core.format_version;
pub const ACTIVATES_PRODUCTION_PROOF = false;

/// Consumes `proof_in` on success and failure. No residual authority is
/// returned until the ordinary full-core verifier has independently checked
/// every AIR/PCS/Merkle/FRI obligation under the extended Stage-A prefix.
pub fn verifyFreshAndMintResidual(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    source: *const full_core.ProviderStageASource(Engine),
    manifest: *const full_core.FullCoreManifestV1(Engine),
    shared: full_core.SharedRelationAuthorityV1,
    statement: statement_mod.RiscVStatement,
    proof_in: types.ProofForEngine(Engine),
    claim: *const statement_mod.RiscVInteractionClaim,
) !full_core.FreshFullCoreResidualV1 {
    try manifest.validate(source, &statement);
    try shared.validate(manifest.identity);

    const commitments = proof_in.commitment_scheme_proof.commitments.items;
    if (commitments.len != 4)
        return error.InvalidFullCoreProofCommitmentCount;
    if (!std.meta.eql(commitments[0], manifest.core_preprocessed_root) or
        !std.meta.eql(commitments[1], manifest.core_main_root))
    {
        return error.FullCoreStageARootMismatch;
    }
    const commitments_identity = proof_authority.commitmentsIdentity(
        Engine,
        commitments,
    );

    var channel = Engine.Channel{};
    try verifier.verifyRiscVWithEngineUsingChannelImpl(
        verifier.V1Protocol,
        Engine,
        .compatibility,
        allocator,
        pcs_config,
        statement,
        proof_in,
        claim,
        &channel,
        manifest,
        null,
        null,
        null,
        null,
    );

    // Replay after fresh proof verification independently binds the published
    // shared relation authority to the exact statement, Stage-A roots, nonce,
    // and provider manifest. It cannot mint a claim from a caller-supplied
    // challenge tuple.
    const replay = try full_core.replaySharedTranscript(
        Engine,
        allocator,
        pcs_config,
        source,
        &statement,
        manifest,
        shared,
    );
    _ = replay;

    const provider_total = try nativePoseidonProviderTotal(&statement, claim);
    var result = full_core.FreshFullCoreResidualV1{
        .format = format_version,
        .plan_identity = source.plan.identity,
        .manifest_identity = manifest.identity,
        .core_statement_identity = full_core.statementTranscriptIdentity(&statement),
        .relation_context_identity = shared.relation_context.identity,
        .proof_commitments_identity = commitments_identity,
        .fresh_core_stark_verified = true,
        .global_relation_closure_verified = true,
        .native_provider_retained = true,
        .poseidon2_residual = provider_total.neg(),
        .production_eligible = false,
        .identity = undefined,
    };
    result.identity = full_core.freshCoreResidualIdentity(result);
    try result.validate();
    return result;
}

/// Verifier-derived total of every admitted native Poseidon infrastructure
/// component. The interaction claim owns two QM31 sums per physical component;
/// neither is discarded or reinterpreted by the externalization boundary.
pub fn nativePoseidonProviderTotal(
    statement: *const statement_mod.RiscVStatement,
    claim: *const statement_mod.RiscVInteractionClaim,
) !QM31 {
    if (claim.n_infra != statement.n_infra)
        return error.InvalidFullCoreInteractionClaim;
    var total = QM31.zero();
    var count: usize = 0;
    for (statement.infra_descs[0..@intCast(statement.n_infra)], 0..) |descriptor, index| {
        if (descriptor.kind != .poseidon2) continue;
        total = total.add(try claim.infraClaimTotal(.poseidon2, index));
        count += 1;
    }
    if (count == 0) return error.MissingNativePoseidonProvider;
    return total;
}

comptime {
    if (full_core.OMIT_RECOMPUTE_OWNER_IMPLEMENTED or
        !full_core.NATIVE_PROVIDER_RETAINED_CORRECTNESS_BRIDGE or
        ACTIVATES_PRODUCTION_PROOF)
    {
        @compileError("full-core residual verifier is a retained-provider correctness bridge");
    }
}
