//! Fast edit-loop root for the secp256k1 precompile authority.

test {
    _ = @import("stwo_riscv_precompiles");
    _ = @import("stwo_riscv_precompiles");
    _ = @import("stwo_riscv_precompiles");
    _ = @import("stwo_riscv_precompiles");
    _ = @import("stwo_riscv_precompiles");
    _ = @import("stwo_riscv_precompiles");
    _ = @import("stwo_riscv_precompiles");
    _ = @import("stwo_riscv_precompiles");
    _ = @import("stwo_riscv_precompiles");
    _ = @import("stwo_riscv_precompiles");
    _ = @import("air/guest_precompile/tests/secp256k1_recovery_caller_test.zig");
    _ = @import("air/guest_precompile/tests/secp256k1_component_test.zig");
    _ = @import("stwo_riscv_frontend").modules.air_guest_precompile_tests_ethereum_statement_test;
    _ = @import("stwo_riscv_frontend").modules.air_guest_precompile_ethereum_lookup_registration;
    _ = @import("stwo_riscv_frontend").modules.prover_guest_precompile_ethereum_witness;
    _ = @import("stwo_riscv_frontend").modules.prover_guest_precompile_ethereum_types;
    _ = @import("stwo_riscv_frontend").modules.prover_guest_precompile_ethereum_transcript;
    _ = @import("stwo_riscv_frontend").modules.prover_guest_precompile_ethereum_preprocessed;
    _ = @import("stwo_riscv_frontend").modules.prover_guest_precompile_ethereum_main;
    _ = @import("stwo_riscv_frontend").modules.prover_guest_precompile_ethereum_interaction;
    _ = @import("stwo_riscv_frontend").modules.prover_guest_precompile_ethereum_assembly;
    _ = @import("stwo_riscv_frontend").modules.prover_guest_precompile_ethereum_cancellation;
    _ = @import("stwo_riscv_frontend").modules.prover_guest_precompile_ethereum_orchestration;
    _ = @import("stwo_riscv_frontend").modules.prover_guest_precompile_ethereum_verifier;
}
