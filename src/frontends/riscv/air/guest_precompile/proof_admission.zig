//! Fail-closed, pre-transcript admission for the Poseidon2 proof profile.
//!
//! The base statement type remains unchanged.  This boundary first
//! authenticates the profile extension and its coefficient certificate, then
//! asks the common structural validator to account for the guest retirements
//! which deliberately do not occupy base opcode-family shards.  No channel,
//! commitment scheme, witness storage, or prover-supplied construction handle
//! is accepted here.

const components = @import("component_registry.zig");
const artifact = @import("artifact_identity.zig");
const statement_mod = @import("statement.zig");
const base_statement = @import("../statement.zig");
const statement_validation = @import("../../prover/statement_validation.zig");
const prover_types = @import("../../prover/types.zig");

pub const extra_memory_terms_per_guest_row: u8 = 14;

pub const Error = statement_mod.Error || artifact.Error || components.Error ||
    prover_types.ProverError;

/// Reconstruct and authenticate every verifier-visible profile authority.
///
/// Returning the canonical artifact rather than accepting one from the prover
/// makes the ownership direction explicit.  A wire adapter may compare its
/// decoded envelope to this value afterwards.
pub fn canonical(
    core: *const base_statement.RiscVStatement,
    extension: *const statement_mod.ExtensionStatement,
    policy: statement_validation.AdmissionPolicy,
) Error!artifact.Identity {
    try extension.validate(core);
    try validateConstructions(extension);
    try statement_validation.validateWithRetirementSupplement(core.*, policy, .{
        .rows = extension.counts.n_guest,
        .extra_memory_terms_per_row = extra_memory_terms_per_guest_row,
        .expected_memory_relation_terms = extension.admission.memory_relation_terms,
    });
    return artifact.Identity.canonical(core, extension);
}

/// Validate a decoded artifact against independently reconstructed authority.
pub fn validate(
    core: *const base_statement.RiscVStatement,
    extension: *const statement_mod.ExtensionStatement,
    identity: artifact.Identity,
    policy: statement_validation.AdmissionPolicy,
) Error!void {
    const expected = try canonical(core, extension, policy);
    // `Identity.validate` reconstructs the canonical value again and reports a
    // stable field-specific error.  The direct equality below protects this
    // boundary if that diagnostic comparison ever becomes partial.
    try identity.validate(core, extension);
    if (!@import("std").meta.eql(identity, expected))
        return error.StatementDigestMismatch;
}

fn validateConstructions(
    extension: *const statement_mod.ExtensionStatement,
) components.Error!void {
    const registry = components.Registry.forProfile(extension.profile);
    for (extension.components) |descriptor| {
        const construction = try registry.verifierConstruction(descriptor);
        try construction.validate();
    }
}

comptime {
    // ADR-0025 gives a guest row seventeen possible memory-relation terms.
    // The common base bound already budgets three for every retirement, so the
    // profile supplement is the exact remaining fourteen.
    if (extra_memory_terms_per_guest_row + 3 != 17)
        @compileError("guest memory coefficient supplement drifted");
}
