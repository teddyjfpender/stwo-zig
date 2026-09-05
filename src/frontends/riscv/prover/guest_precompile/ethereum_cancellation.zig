//! One global LogUp closure for the base plus combined Ethereum components.

const std = @import("std");
const logup = @import("../../air/logup.zig");
const public_logup = @import("../../air/public_logup.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const base_statement = @import("../../air/statement.zig");
const base_claims = @import("../../air/transcript/claims.zig");
const base_types = @import("../types.zig");
const ethereum_transcript = @import("ethereum_transcript.zig");
const ethereum_types = @import("ethereum_types.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const statement_geometry = @import("../statement_geometry.zig");
const statement_validation = @import("../statement_validation.zig");
const native_provider_omit = @import("../memory_provider_shards/native_provider_omit_v1.zig");
const provider_authority = @import("../memory_provider_shards/authority.zig");

pub fn verifyDetailed(
    allocator: std.mem.Allocator,
    core: *const base_statement.RiscVStatement,
    relations: *const ethereum_transcript.Relations,
    base: *const base_types.RiscVInteractionClaim,
    extension: *const ethereum_types.ExtensionClaim,
) !void {
    const canonical = try allocator.create(base_statement.CanonicalInteractionClaim);
    defer allocator.destroy(canonical);
    canonical.* = try base.canonical(core);
    return verifyCanonical(core, relations, canonical.view(), extension);
}

pub fn verifyCanonical(
    core: *const base_statement.RiscVStatement,
    relations: *const ethereum_transcript.Relations,
    base: base_claims.InteractionClaim,
    extension: *const ethereum_types.ExtensionClaim,
) !void {
    const public_boundary = try public_logup.sum(&core.public_data, &relations.base);
    try logup.verifyGlobalCancellation(
        &.{ base.total(), extension.componentSum() },
        public_boundary,
    );
}

pub fn verifyV2(
    native: *const statement_v2.RiscVStatementV2,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    relations: *const ethereum_transcript.Relations,
    base: *const base_types.RiscVInteractionClaim,
    extension: *const ethereum_types.ExtensionClaim,
) !void {
    try native.validate();
    const canonical = try authenticated.canonicalInteractionClaim(
        &native.core,
        manifest,
        base,
    );
    const public_boundary = try statement_v2.nativeRelationSum(
        &native.public_data,
        &relations.base,
    );
    try logup.verifyGlobalCancellation(
        &.{ canonical.view().total(), extension.componentSum() },
        public_boundary,
    );
}

/// Returns the verifier-recomputable global residual after the native
/// narrow-memory Poseidon provider has been physically omitted. The residual
/// is not accepted here: ordered provider proofs must close it under the same
/// relation draw before any production capability can be minted.
pub fn residualWithoutNativePoseidonV2(
    projection: *const native_provider_omit.ProjectionV1,
    full_native: *const statement_v2.RiscVStatementV2,
    extension_statement: *const ethereum_statement.Statement,
    policy: statement_validation.AdmissionPolicy,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    full_geometry: statement_geometry.Geometry,
    relations: *const ethereum_transcript.Relations,
    base: *const base_types.RiscVInteractionClaim,
    extension: *const ethereum_types.ExtensionClaim,
) !@import("stwo_core").fields.qm31.QM31 {
    try projection.validateAgainst(
        full_native,
        extension_statement,
        policy,
        manifest,
        authenticated,
        plan,
        calls,
        full_geometry,
    );
    return residualWithoutNativePoseidonAfterProjectionValidationV2(
        projection,
        full_native,
        extension_statement,
        manifest,
        authenticated,
        relations,
        base,
        extension,
    );
}

/// Candidate-only residual sibling for a full statement with heterogeneous
/// external retirements. The exact caller-derived supplement is validated by
/// the projection authority before entering the unchanged residual body.
pub fn residualWithoutNativePoseidonWithRetirementSupplementV2(
    projection: *const native_provider_omit.ProjectionV1,
    full_native: *const statement_v2.RiscVStatementV2,
    extension_statement: *const ethereum_statement.Statement,
    policy: statement_validation.AdmissionPolicy,
    supplement: statement_validation.RetirementSupplementV2,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    full_geometry: statement_geometry.Geometry,
    relations: *const ethereum_transcript.Relations,
    base: *const base_types.RiscVInteractionClaim,
    extension: *const ethereum_types.ExtensionClaim,
) !@import("stwo_core").fields.qm31.QM31 {
    try projection.validateAgainstWithRetirementSupplementV2(
        full_native,
        extension_statement,
        policy,
        supplement,
        manifest,
        authenticated,
        plan,
        calls,
        full_geometry,
    );
    return residualWithoutNativePoseidonAfterProjectionValidationV2(
        projection,
        full_native,
        extension_statement,
        manifest,
        authenticated,
        relations,
        base,
        extension,
    );
}

fn residualWithoutNativePoseidonAfterProjectionValidationV2(
    projection: *const native_provider_omit.ProjectionV1,
    full_native: *const statement_v2.RiscVStatementV2,
    extension_statement: *const ethereum_statement.Statement,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    relations: *const ethereum_transcript.Relations,
    base: *const base_types.RiscVInteractionClaim,
    extension: *const ethereum_types.ExtensionClaim,
) !@import("stwo_core").fields.qm31.QM31 {
    try extension.validate(extension_statement);
    const canonical = try authenticated.canonicalInteractionClaim(
        &projection.projected_native.core,
        manifest,
        base,
    );
    const public_boundary = try statement_v2.nativeRelationSum(
        &full_native.public_data,
        &relations.base,
    );
    return public_boundary.add(canonical.view().total()).add(extension.componentSum());
}
