//! Shared cold admission for native prover and verifier provider components.
const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const geometry = @import("universal_shared_geometry.zig");
const universal = @import("universal_challenges.zig");
const range_contract = @import("range_check_8_8_contract.zig");
const compact_identity = @import("../../air/memory_commitment/poseidon2_universal_identity_v2.zig");
const PoseidonSourceAuthority = @import("universal_provider_authority.zig").PoseidonSourceAuthority;
const SharedProviderRelations = @import("universal_provider_relations.zig").SharedProviderRelations;
const secureIsCanonical = @import("universal_provider_relations.zig").secureIsCanonical;
const POSEIDON_LOG_SIZE_EXCLUSIVE_LIMIT = geometry.POSEIDON_LOG_SIZE_EXCLUSIVE_LIMIT;

pub fn poseidon(
    comptime manifest_contract: type,
    comptime compact: bool,
    comptime compatibility: compact_identity.Compatibility,
    allocator: std.mem.Allocator,
    manifest: *const manifest_contract.Manifest,
    log_size: u32,
    n_rows: u32,
    provider_relations: *const SharedProviderRelations,
    universal_relations: *const universal.UniversalRelations,
    claims: [geometry.POSEIDON_INTERACTION_BATCH_COUNT]QM31,
) !manifest_contract.Placement {
    try manifest.validate();
    try provider_relations.validateAgainst(universal_relations);
    if (!compact) try PoseidonSourceAuthority.pinned().validate();
    for (&claims) |*claim| if (!secureIsCanonical(claim))
        return error.ChallengeBindingMismatch;
    if (log_size == 0 or log_size >= POSEIDON_LOG_SIZE_EXCLUSIVE_LIMIT)
        return error.ProviderTraceShapeMismatch;
    const trace_size = @as(u64, 1) << @intCast(log_size);
    if (n_rows > trace_size) return error.ProviderTraceShapeMismatch;
    const placement = try manifest.placement(.poseidon2);
    if (placement.geometry.log_size != log_size or !geometry.PoseidonForManifest(manifest_contract, compact, compatibility).acceptsGeometry(placement.geometry))
        return error.ProviderGeometryMismatch;
    if (compact) try compact_identity.validateAdmission(allocator, placement.geometry.semantic_digest, compatibility);
    return placement;
}

pub fn rangeCheck(
    comptime manifest_contract: type,
    definition: *const range_contract.Definition,
    binding: *const range_contract.Binding,
    manifest: *const manifest_contract.Manifest,
    provider_relations: *const SharedProviderRelations,
    universal_relations: *const universal.UniversalRelations,
    claim: QM31,
) !manifest_contract.Placement {
    try manifest.validate();
    try provider_relations.validateAgainst(universal_relations);
    if (!secureIsCanonical(&claim)) return error.ChallengeBindingMismatch;
    try definition.validate();
    const canonical = try range_contract.Binding.canonical(definition);
    if (!std.meta.eql(canonical, binding.*))
        return error.ProviderAuthorityMismatch;
    const placement = try manifest.placement(.range_check_8_8);
    if (!std.meta.eql(placement.geometry, geometry.RangeForManifest(manifest_contract).manifestGeometry()))
        return error.ProviderGeometryMismatch;
    return placement;
}
