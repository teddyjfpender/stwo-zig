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
    _ = @import("stwo_riscv_testing");
    _ = @import("stwo_riscv_testing");
    _ = @import("../../../../air/guest_precompile/tests/ethereum_statement_test.zig");
    _ = @import("../../../../air/guest_precompile/ethereum_lookup_registration.zig");
    _ = @import("stwo_riscv_frontend").prover_mod.guest_precompile.ethereum_witness;
    _ = @import("stwo_riscv_frontend").prover_mod.guest_precompile.ethereum_types;
    _ = @import("stwo_riscv_frontend").prover_mod.guest_precompile.ethereum_transcript;
    _ = @import("stwo_riscv_frontend").prover_mod.guest_precompile.ethereum_preprocessed;
    _ = @import("stwo_riscv_frontend").prover_mod.guest_precompile.ethereum_main;
    _ = @import("stwo_riscv_frontend").prover_mod.guest_precompile.ethereum_interaction;
    _ = @import("stwo_riscv_frontend").prover_mod.guest_precompile.ethereum_assembly;
    _ = @import("stwo_riscv_frontend").prover_mod.guest_precompile.ethereum_cancellation;
    _ = @import("stwo_riscv_frontend").prover_mod.guest_precompile.ethereum_orchestration;
    _ = @import("stwo_riscv_frontend").prover_mod.guest_precompile.ethereum_verifier;
}
