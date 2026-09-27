//! Focused statement format gate; no prover or GPU build is required.
test {
    _ = @import("prover/blake3_commitment_components_test.zig");
    _ = @import("air/program/commitment.zig");
    _ = @import("prover/blake3_commitment_witness_test.zig");
    _ = @import("air/public_logup.zig");
    _ = @import("air/public_data.zig");
    _ = @import("recursion/air/blake3_memory_runner_test.zig");
    _ = @import("recursion/air/blake3_memory_snapshot_test.zig");
    _ = @import("recursion/air/blake3_memory_word_test.zig");
    _ = @import("recursion/air/blake3_memory_boundary_test.zig");
    _ = @import("recursion/blake3_byte_tree_test.zig");
    _ = @import("recursion/air/blake3_frame_witness_test.zig");
    _ = @import("recursion/air/blake3_frame_test.zig");
    _ = @import("recursion/span_identity_blake3_test.zig");
    _ = @import("recursion/air/blake3_span_identity_inputs_test.zig");
    _ = @import("recursion/air/blake3_span_identity_join_test.zig");
    _ = @import("recursion/air/blake3_span_identity_constraints_test.zig");
    _ = @import("recursion/air/vm_air_composition_input_test.zig");
    _ = @import("recursion/air/vm_air_composition_input_blake3_test.zig");
    _ = @import("recursion/air/composition_circuit_test.zig");
    _ = @import("recursion/air/composition_circuit_blake3_test.zig");
    _ = @import("recursion/air/statement_input_test.zig");
    _ = @import("recursion/air/statement_input_blake3_test.zig");
    _ = @import("recursion/statement_semantics_circuit_test.zig");
    _ = @import("recursion/statement_semantics_circuit_blake3_test.zig");
    _ = @import("recursion/air/statement_semantics_input_blake3_test.zig");
    _ = @import("recursion/air/statement_semantics_input_test.zig");
    _ = @import("recursion/span_statement_test.zig");
    _ = @import("recursion/span_statement_blake3_test.zig");
    _ = @import("recursion/blake3_identity_digest.zig");
}
