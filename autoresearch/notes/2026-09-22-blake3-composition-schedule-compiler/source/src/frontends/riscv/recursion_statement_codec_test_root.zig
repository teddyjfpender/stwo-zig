//! Focused statement format gate; no prover or GPU build is required.
test {
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
