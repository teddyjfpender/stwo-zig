//! Focused proof-side guest-precompile test root.

test {
    _ = @import("air/guest_precompile/tests/keccakf_authority_test.zig");
    _ = @import("air/guest_precompile/tests/caller_component_test.zig");
    _ = @import("air/guest_precompile/tests/caller_component_prepared_test.zig");
    _ = @import("air/guest_precompile/tests/direct_constraints_test.zig");
    _ = @import("air/guest_precompile/tests/interaction_chunk_test.zig");
    _ = @import("air/guest_precompile/tests/interaction_test.zig");
    _ = @import("air/guest_precompile/tests/main_trace_test.zig");
    _ = @import("air/guest_precompile/tests/lookup_registration_test.zig");
    _ = @import("air/guest_precompile/tests/proof_admission_test.zig");
    _ = @import("air/guest_precompile/tests/proof_transcript_test.zig");
    _ = @import("air/guest_precompile/tests/proof_transcript_security_test.zig");
    _ = @import("air/guest_precompile/tests/program_commitment_test.zig");
    _ = @import("air/guest_precompile/tests/provider_component_test.zig");
    _ = @import("air/guest_precompile/tests/relation_test.zig");
    _ = @import("prover/guest_precompile/tests/component_assembly_test.zig");
    _ = @import("prover/guest_precompile/tests/split_component_assembly_test.zig");
    _ = @import("prover/guest_precompile/tests/split_leaf_statement_test.zig");
    _ = @import("prover/guest_precompile/tests/split_leaf_prepare_test.zig");
    _ = @import("prover/guest_precompile/tests/split_main_trace_test.zig");
    _ = @import("prover/guest_precompile/tests/split_joint_pow_test.zig");
    _ = @import("prover/guest_precompile/tests/split_pcs_prepare_test.zig");
    _ = @import("prover/guest_precompile/tests/proof_artifact_test.zig");
    _ = @import("prover/guest_precompile/tests/proof_finalize_test.zig");
    _ = @import("prover/guest_precompile/tests/trace_geometry_test.zig");
    _ = @import("prover/guest_precompile/tests/types_test.zig");
    _ = @import("runner/guest_precompile/tests/c011_semantic_equivalence_test.zig");
}
