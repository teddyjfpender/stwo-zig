//! Small ownership/finalization loop; no outer prover or controller imports.
test {
    _ = @import("recursion/segment_statement_v2_identity_preimage.zig");
    _ = @import("recursion/air/ethereum_public_logup_input_v1_test.zig");
    _ = @import("recursion/air/ethereum_publication_transcript_v1_test.zig");
    _ = @import("recursion/air/ethereum_publication_hash_v1_test.zig");
    _ = @import("recursion/air/ethereum_publication_control_v1_test.zig");
    _ = @import("recursion/air/ethereum_vm_public_claim_input_v1_test.zig");
    _ = @import("recursion/vm_public_semantics_circuit_test.zig");
    _ = @import("recursion/vm_composition_preparation.zig");
    _ = @import("recursion/air/vm_statement_roots_test.zig");
    _ = @import("recursion/air/statement_input_roots_v3_test.zig");
    _ = @import("recursion/air/statement_input_test.zig");
    _ = @import("recursion/air/statement_semantics_input_test.zig");
    _ = @import("recursion/air/statement_root_physical_audit.zig");
}
