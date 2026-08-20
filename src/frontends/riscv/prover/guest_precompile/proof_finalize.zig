//! Final proof construction for the Poseidon2 extension profile.

const std = @import("std");
const stage_profile = @import("stwo_prover_api").stage_profile;
const caller_component = @import("../../air/guest_precompile/caller_component.zig");
const provider_component = @import("../../air/guest_precompile/provider_component.zig");
const guest_relations = @import("../../air/guest_precompile/relation_challenges.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const base_finalize = @import("../proof_finalize.zig");
const proof_workspace = @import("../proof_workspace.zig");
const types = @import("../types.zig");
const component_assembly = @import("component_assembly.zig");

/// Takes ownership of `scheme`, releasing it if either base or profile
/// component assembly fails. After appending the two authenticated profile
/// components, the single engine invocation consumes it on every return path.
pub fn prove(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    recorder: ?*stage_profile.Recorder,
    scheme: Engine.Scheme,
    channel: *Engine.Channel,
    workspace: *proof_workspace.ProofWorkspace,
    extension: *const guest_statement.ExtensionStatement,
    relations: *const guest_relations.Poseidon2V1Relations,
    base_claim: *const types.RiscVInteractionClaim,
    caller_claim: caller_component.Claim,
    provider_claim: provider_component.Claim,
) !types.Proof {
    var owned_scheme = scheme;
    var scheme_transferred = false;
    defer if (!scheme_transferred) Engine.deinit(&owned_scheme, allocator);

    const core = &workspace.statement;
    const base_components = try base_finalize.assemble(
        workspace,
        &relations.base,
        base_claim,
        core.nMainColumns(),
        core.nInteractionColumns(),
    );
    const assembly = try component_assembly.ProverAssembly.create(
        allocator,
        core,
        extension,
        relations,
        base_components,
        caller_claim,
        provider_claim,
    );
    defer assembly.destroy(allocator);

    // `Engine.prove` consumes the scheme on both success and failure. Keep the
    // wrapper-owned rollback live through every fallible assembly operation.
    scheme_transferred = true;
    var extended = try Engine.prove(
        allocator,
        assembly.active(),
        channel,
        owned_scheme,
        .{ .recorder = recorder },
    );
    const proof = extended.proof;
    extended.aux.deinit(allocator);
    return proof;
}
