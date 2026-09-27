//! Focused native-execution and full-width commitment integration gate.
comptime {
    _ = @import("air/memory_commitment/blake3_subtree_test.zig");
    // Guest semantics must survive replacement of their execution commitments.
    _ = @import("air/guest_precompile/main_trace_test.zig");
    _ = @import("air/guest_precompile/interaction_test.zig");
    _ = @import("air/guest_precompile/lookup_registration_test.zig");
    _ = @import("air/guest_precompile/proof_admission_test.zig");
    _ = @import("air/guest_precompile/relation_test.zig");
    _ = @import("prover/blake3_poseidon_witness_test.zig");
    _ = @import("recursion/air/framework_device_interaction.zig");
    _ = @import("prover/blake3_allocator_authority_test.zig");
    _ = @import("prover/blake3_ethereum_witness_test.zig");
    _ = @import("prover/blake3_execution_trace_test.zig");
    _ = @import("prover/blake3_commitment_witness_test.zig");
}
