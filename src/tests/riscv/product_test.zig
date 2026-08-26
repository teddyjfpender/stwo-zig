//! Focused RISC-V product checks kept inside the normal package touchpoint.

test {
    _ = @import("unit_test.zig");
    _ = @import("diagnostic_hints_test.zig");
    _ = @import("opcode_family_precondition_test.zig");
    _ = @import("proof_admission_test.zig");
    _ = @import("prove_admission_gate_test.zig");
    _ = @import("public_relation_binding_test.zig");
    _ = @import("typed_poseidon2_proof_equivalence_test.zig");
}
