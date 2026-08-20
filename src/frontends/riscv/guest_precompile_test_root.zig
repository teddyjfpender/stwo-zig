//! Focused proof-side guest-precompile test root.

test {
    _ = @import("air/guest_precompile/caller_component_test.zig");
    _ = @import("air/guest_precompile/caller_component_prepared_test.zig");
    _ = @import("air/guest_precompile/direct_constraints_test.zig");
    _ = @import("air/guest_precompile/interaction_chunk_test.zig");
    _ = @import("air/guest_precompile/interaction_test.zig");
    _ = @import("air/guest_precompile/main_trace_test.zig");
    _ = @import("air/guest_precompile/lookup_registration_test.zig");
    _ = @import("air/guest_precompile/proof_admission_test.zig");
    _ = @import("air/guest_precompile/proof_transcript_test.zig");
    _ = @import("air/guest_precompile/proof_transcript_security_test.zig");
    _ = @import("air/guest_precompile/program_commitment_test.zig");
    _ = @import("air/guest_precompile/provider_component_test.zig");
    _ = @import("air/guest_precompile/relation_test.zig");
    _ = @import("prover/guest_precompile/component_assembly_test.zig");
    _ = @import("prover/guest_precompile/split_component_assembly_test.zig");
    _ = @import("prover/guest_precompile/split_leaf_statement_test.zig");
    _ = @import("prover/guest_precompile/split_leaf_prepare_test.zig");
    _ = @import("prover/guest_precompile/split_main_trace_test.zig");
    _ = @import("prover/guest_precompile/split_joint_pow_test.zig");
    _ = @import("prover/guest_precompile/split_pcs_prepare_test.zig");
    _ = @import("prover/guest_precompile/proof_artifact_test.zig");
    _ = @import("prover/guest_precompile/proof_finalize_test.zig");
    _ = @import("prover/guest_precompile/trace_geometry_test.zig");
    _ = @import("prover/guest_precompile/types_test.zig");
    _ = @import("runner/guest_precompile/c011_semantic_equivalence_test.zig");
}
