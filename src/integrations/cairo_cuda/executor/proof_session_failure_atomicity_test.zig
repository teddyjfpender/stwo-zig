//! failure atomicity contract cases for proof_session.
//! Direct, single-request Cairo CUDA proof-session sequencing.
//!
//! This coordinator is intentionally not a generic graph runner. It executes
//! each authenticated Cairo phase exactly once, in transcript order, and
//! delegates only the two controller boundaries that are not yet complete:
//! interaction-tree commitment and constraint evaluation/composition commit.

const std = @import("std");

const Owner = @import("proof_session.zig");
const Gap = Owner.Gap;
const gaps = Owner.gaps;
const requireProductionReady = Owner.requireProductionReady;
const compileConcreteExecution = Owner.compileConcreteExecution;

test "production coordinator names every remaining root boundary" {
    try std.testing.expectEqualSlices(
        Gap,
        &.{
            .production_ingress_binding_compiler,
            .statement_bootstrap_payload_binding,
            .oracle_verification,
        },
        &gaps,
    );
    try std.testing.expectError(
        error.MissingProductionIngressBindingCompiler,
        requireProductionReady(),
    );
    _ = &compileConcreteExecution;
}

test {
    std.testing.refAllDeclsRecursive(@This());
}
