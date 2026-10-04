//! Focused native-execution and full-width commitment integration gate.
comptime {
    _ = @import("prover/tests/blake3_ethereum_sha_proof_test.zig");
    _ = @import("prover/tests/blake3_ethereum_sha_witness_test.zig");
    _ = @import("prover/tests/blake3_paired_memory_test.zig");
    _ = @import("prover/tests/blake3_partial_input_test.zig");
    _ = @import("air/memory_commitment/blake3_subtree_test.zig");
    // Guest semantics must survive replacement of their execution commitments.
    _ = @import("air/guest_precompile/tests/main_trace_test.zig");
    _ = @import("air/guest_precompile/tests/interaction_test.zig");
    _ = @import("air/guest_precompile/tests/lookup_registration_test.zig");
    _ = @import("air/guest_precompile/tests/proof_admission_test.zig");
    _ = @import("air/guest_precompile/tests/relation_test.zig");
    _ = @import("prover/tests/blake3_poseidon_witness_test.zig");
    _ = @import("recursion/air/framework_device_interaction.zig");
    _ = @import("prover/tests/blake3_allocator_authority_test.zig");
    _ = @import("prover/tests/blake3_ethereum_witness_test.zig");
    _ = @import("prover/tests/blake3_execution_trace_test.zig");
    _ = @import("prover/tests/blake3_commitment_witness_test.zig");
}
