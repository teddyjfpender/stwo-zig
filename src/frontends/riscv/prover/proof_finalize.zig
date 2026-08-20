//! Prover component assembly and final proof construction.
//!
//! Component values are assembled into the caller's `ProofWorkspace` because
//! `Engine.prove` consumes a `[]const ComponentProver` of fat pointers that
//! borrow them: they must stay addressable until proving returns, and their
//! declaration order is protocol-visible. Interaction results and shifted
//! cumulative columns are read from the same workspace, so this module no
//! longer restates the prover's storage layout.

const std = @import("std");
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_api = @import("stwo_prover_api");
const stage_profile = @import("stwo_prover_api").stage_profile;
const lookup_physical_v2 = @import("../air/lang/lookup_physical_manifest_v2.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const base_component_assembly = @import("base_component_assembly.zig");
const proof_workspace = @import("proof_workspace.zig");
const types = @import("types.zig");

const ProofWorkspace = proof_workspace.ProofWorkspace;

/// Assembles declaration-ordered prover components in `workspace` and produces
/// the proof.
///
/// `scheme` is **transferred** to this wrapper. The wrapper releases it if
/// component assembly fails; after successful assembly, `Engine.prove`
/// consumes it on both success and failure. Component values are **borrowed**
/// from `workspace` for the duration of the call and remain valid until the
/// workspace is destroyed by the proving boundary.
pub fn prove(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    recorder: ?*stage_profile.Recorder,
    scheme: Engine.Scheme,
    channel: *Engine.Channel,
    workspace: *ProofWorkspace,
    relations: *const relation_challenges.Relations,
    interaction_claim: *const types.RiscVInteractionClaim,
    n_main: usize,
    n_interaction: usize,
) !types.ProofForEngine(Engine) {
    return proveWithOptions(
        Engine,
        allocator,
        .{ .recorder = recorder },
        scheme,
        channel,
        workspace,
        relations,
        interaction_claim,
        n_main,
        n_interaction,
    );
}

pub fn proveWithOptions(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    options: prover_api.ProveOptions,
    scheme: Engine.Scheme,
    channel: *Engine.Channel,
    workspace: *ProofWorkspace,
    relations: *const relation_challenges.Relations,
    interaction_claim: *const types.RiscVInteractionClaim,
    n_main: usize,
    n_interaction: usize,
) !types.ProofForEngine(Engine) {
    var owned_scheme = scheme;
    var scheme_transferred = false;
    defer if (!scheme_transferred) Engine.deinit(&owned_scheme, allocator);

    const active = try assemble(
        workspace,
        relations,
        interaction_claim,
        n_main,
        n_interaction,
    );

    // `Engine.prove` consumes the scheme on both success and failure. Transfer
    // only after the complete component assembly has succeeded.
    scheme_transferred = true;
    var extended = try Engine.prove(
        allocator,
        active,
        channel,
        owned_scheme,
        options,
    );
    const proof = extended.proof;
    extended.aux.deinit(allocator);
    return proof;
}

/// Complete append-only proving boundary for the authenticated physical lookup
/// statement. V1 wrappers never call this function, so their registry,
/// transcript, options, and proof bytes remain unchanged.
pub fn proveAuthenticatedLookupV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    options: prover_api.ProveOptions,
    scheme: Engine.Scheme,
    channel: *Engine.Channel,
    workspace: *ProofWorkspace,
    relations: *const relation_challenges.Relations,
    interaction_claim: *const types.RiscVInteractionClaim,
    n_main: usize,
    n_interaction: usize,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated_statement: *const lookup_physical_v2.AuthenticatedStatement,
) !types.ProofForEngine(Engine) {
    var owned_scheme = scheme;
    var scheme_transferred = false;
    defer if (!scheme_transferred) Engine.deinit(&owned_scheme, allocator);

    const active = try assembleAuthenticatedLookupV2(
        workspace,
        relations,
        interaction_claim,
        n_main,
        n_interaction,
        manifest,
        authenticated_statement,
    );
    scheme_transferred = true;
    var extended = try Engine.prove(
        allocator,
        active,
        channel,
        owned_scheme,
        options,
    );
    const proof = extended.proof;
    extended.aux.deinit(allocator);
    return proof;
}

/// Builds the unchanged base component prefix and returns its borrowed handle
/// slice without consuming a commitment scheme. Extension profiles use this
/// seam to append authenticated components while keeping the base registry,
/// storage, and declaration walk single-source.
pub fn assemble(
    workspace: *ProofWorkspace,
    relations: *const relation_challenges.Relations,
    interaction_claim: *const types.RiscVInteractionClaim,
    n_main: usize,
    n_interaction: usize,
) ![]const prover_component.ComponentProver {
    try base_component_assembly.assembleInto(
        .prover,
        workspace,
        &workspace.statement,
        interaction_claim,
        relations,
        n_main,
        n_interaction,
    );
    return workspace.components.active();
}

/// Dormant V2 construction seam. Callers must present a statement-scoped
/// activation derived from the exact fixed manifest; the ordinary `assemble`
/// entry point above remains permanently compatibility-only.
pub fn assembleAuthenticatedLookupV2(
    workspace: *ProofWorkspace,
    relations: *const relation_challenges.Relations,
    interaction_claim: *const types.RiscVInteractionClaim,
    n_main: usize,
    n_interaction: usize,
    manifest: *const lookup_physical_v2.Manifest,
    authenticated_statement: *const lookup_physical_v2.AuthenticatedStatement,
) ![]const prover_component.ComponentProver {
    try base_component_assembly.assembleIntoAuthenticatedLookupV2(
        .prover,
        workspace,
        &workspace.statement,
        interaction_claim,
        relations,
        n_main,
        n_interaction,
        manifest,
        authenticated_statement,
    );
    return workspace.components.active();
}
