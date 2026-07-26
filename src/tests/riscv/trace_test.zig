//! Exhaustive RISC-V release tests, consumed by `test-riscv-prover` and CP-13.

test {
    _ = @import("unit_test.zig");
    _ = @import("malicious_witness_test.zig");
    _ = @import("main_witness_rejection_test.zig");
    _ = @import("mulh_soundness_test.zig");
    _ = @import("proof_admission_test.zig");
    _ = @import("prover_test.zig");
    _ = @import("public_relation_binding_test.zig");
    _ = @import("transcript_path_test.zig");
}
