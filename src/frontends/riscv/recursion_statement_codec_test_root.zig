//! Focused statement format gate; no prover or GPU build is required.
test {
    _ = @import("prover/tests/compact_extension_test.zig");
    _ = @import("prover/tests/compact_range_execution_test.zig");
    _ = @import("prover/tests/compact_range_set_test.zig");
    _ = @import("recursion/air/tests/compact_range_provider_test.zig");
    _ = @import("prover/tests/blake3_commitment_components_test.zig");
    _ = @import("air/program/commitment.zig");
    _ = @import("prover/tests/blake3_commitment_witness_test.zig");
    _ = @import("air/public_logup.zig");
    _ = @import("air/public_data.zig");
    _ = @import("recursion/air/tests/blake3_memory_runner_test.zig");
    _ = @import("recursion/air/tests/blake3_memory_snapshot_test.zig");
    _ = @import("recursion/air/tests/blake3_memory_word_test.zig");
    _ = @import("recursion/air/tests/blake3_memory_boundary_test.zig");
    _ = @import("recursion/tests/blake3_byte_tree_test.zig");
    _ = @import("recursion/air/tests/blake3_frame_witness_test.zig");
    _ = @import("recursion/air/tests/blake3_frame_test.zig");
    _ = @import("recursion/tests/span_identity_blake3_test.zig");
    _ = @import("recursion/air/tests/blake3_span_identity_inputs_test.zig");
    _ = @import("recursion/air/tests/blake3_span_identity_join_test.zig");
    _ = @import("recursion/air/tests/blake3_span_identity_constraints_test.zig");
    _ = @import("recursion/air/tests/vm_air_composition_input_test.zig");
    _ = @import("recursion/air/tests/vm_air_composition_input_blake3_test.zig");
    _ = @import("recursion/air/tests/composition_circuit_test.zig");
    _ = @import("recursion/air/tests/composition_circuit_blake3_test.zig");
    _ = @import("recursion/air/tests/statement_input_test.zig");
    _ = @import("recursion/air/tests/statement_input_blake3_test.zig");
    _ = @import("recursion/tests/statement_semantics_circuit_test.zig");
    _ = @import("recursion/tests/statement_semantics_circuit_blake3_test.zig");
    _ = @import("recursion/air/tests/statement_semantics_input_blake3_test.zig");
    _ = @import("recursion/air/tests/statement_semantics_input_test.zig");
    _ = @import("recursion/tests/span_statement_test.zig");
    _ = @import("recursion/tests/span_statement_blake3_test.zig");
    _ = @import("recursion/blake3_identity_digest.zig");
}
