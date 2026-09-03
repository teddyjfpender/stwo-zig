//! Fail-closed pre-transcript admission for the combined Ethereum profile.

const statement_mod = @import("ethereum_statement.zig");
const base_statement = @import("../statement.zig");
const statement_v2 = @import("../statement_v2.zig");
const statement_validation = @import("../../prover/statement_validation.zig");
const prover_types = @import("../../prover/types.zig");

pub const Error = statement_mod.Error || prover_types.ProverError;

/// Authenticates the append-only extension statement and then asks the common
/// base validator to account for its heterogeneous external retirements. This
/// runs before transcript mutation, commitment allocation, or witness use on
/// both prover and verifier paths.
pub fn validate(
    core: *const base_statement.RiscVStatement,
    extension: *const statement_mod.Statement,
    policy: statement_validation.AdmissionPolicy,
) Error!void {
    try extension.validate(core);
    if (extension.counts.external_retirements == 0) {
        if (extension.admission.extra_memory_terms != 0)
            return prover_types.ProverError.InvalidStatement;
        return statement_validation.validate(core.*, policy);
    }
    try statement_validation.validateWithRetirementSupplementV2(
        core.*,
        policy,
        .{
            .rows = extension.counts.external_retirements,
            .extra_memory_terms = extension.admission.extra_memory_terms,
            .expected_memory_relation_terms = extension.admission.memory_relation_terms,
        },
    );
}

/// SegmentV2 admission authenticates the complete V2 boundary before using
/// its exact public event counts for coefficient lifting. The compatibility
/// core is geometry only and is never passed through V1 completion rules.
pub fn validateV2(
    native: *const statement_v2.RiscVStatementV2,
    extension: *const statement_mod.Statement,
    policy: statement_validation.AdmissionPolicy,
) Error!void {
    try extension.validateV2(native);
    if (extension.counts.external_retirements == 0) {
        if (extension.admission.extra_memory_terms != 0)
            return prover_types.ProverError.InvalidStatement;
        return statement_validation.validateV2(native, policy);
    }
    try statement_validation.validateV2WithRetirementSupplementV2(
        native,
        policy,
        .{
            .rows = extension.counts.external_retirements,
            .extra_memory_terms = extension.admission.extra_memory_terms,
            .expected_memory_relation_terms = extension.admission.memory_relation_terms,
        },
    );
}
