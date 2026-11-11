//! One required compilation partition of the complete focused target.

test {
    _ = @import("prover/guest_precompile/tests/split_pcs_prepare_test.zig");
    _ = @import("prover/guest_precompile/tests/proof_artifact_test.zig");
    _ = @import("prover/guest_precompile/tests/proof_finalize_test.zig");
    _ = @import("prover/guest_precompile/tests/trace_geometry_test.zig");
    _ = @import("prover/guest_precompile/tests/types_test.zig");
    _ = @import("runner/guest_precompile/tests/c011_semantic_equivalence_test.zig");
}
