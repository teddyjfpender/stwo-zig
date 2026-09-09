//! Focused nonproduction combined-candidate capability/journal/product gate.

test {
    _ = @import("isa/ethereum_candidate_private_registry_v1.zig");
    _ = @import(
        "runner/guest_precompile/ethereum_candidate_execution_capability_v1.zig",
    );
    _ = @import(
        "runner/guest_precompile/ethereum_candidate_execution_journal_v1.zig",
    );
    _ = @import(
        "runner/guest_precompile/ethereum_candidate_observed_journal_v1.zig",
    );
    _ = @import(
        "prover/guest_precompile/ethereum_candidate_execution_product_v1.zig",
    );
}
