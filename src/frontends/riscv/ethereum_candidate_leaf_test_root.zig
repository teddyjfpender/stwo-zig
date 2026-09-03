//! Focused nonproduction candidate-leaf profile/tree/admission gate.

test {
    _ = @import(
        "prover/guest_precompile/ethereum_candidate_leaf_integration_v1_test.zig",
    );
    _ = @import(
        "prover/guest_precompile/ethereum_candidate_leaf_tree_v1_test.zig",
    );
}
