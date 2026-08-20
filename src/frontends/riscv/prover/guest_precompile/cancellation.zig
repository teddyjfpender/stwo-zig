//! Global LogUp cancellation for the Poseidon2 profile.

const std = @import("std");
const caller_component = @import("../../air/guest_precompile/caller_component.zig");
const provider_component = @import("../../air/guest_precompile/provider_component.zig");
const guest_relations = @import("../../air/guest_precompile/relation_challenges.zig");
const base_claims = @import("../../air/transcript/claims.zig");
const logup = @import("../../air/logup.zig");
const public_logup = @import("../../air/public_logup.zig");
const base_statement = @import("../../air/statement.zig");
const types = @import("../types.zig");

/// Canonicalizes the fixed-capacity base claim in heap scratch, then checks one
/// global equation over base slots 0..27, profile slots 28..29, and the public
/// boundary. This is run before proving so an unbalanced witness never reaches
/// the expensive composition phase.
pub fn verifyDetailed(
    allocator: std.mem.Allocator,
    core: *const base_statement.RiscVStatement,
    relations: *const guest_relations.Poseidon2V1Relations,
    base: *const types.RiscVInteractionClaim,
    caller: caller_component.Claim,
    provider: provider_component.Claim,
) !void {
    const canonical = try allocator.create(base_statement.CanonicalInteractionClaim);
    defer allocator.destroy(canonical);
    canonical.* = try base.canonical(core);
    return verifyCanonical(core, relations, canonical.view(), caller, provider);
}

/// Allocation-free form for verifiers that already own canonical base storage.
pub fn verifyCanonical(
    core: *const base_statement.RiscVStatement,
    relations: *const guest_relations.Poseidon2V1Relations,
    base: base_claims.InteractionClaim,
    caller: caller_component.Claim,
    provider: provider_component.Claim,
) !void {
    const public_boundary = try public_logup.sum(&core.public_data, &relations.base);
    try logup.verifyGlobalCancellation(
        &.{ base.total(), caller.total(), provider.total() },
        public_boundary,
    );
}
