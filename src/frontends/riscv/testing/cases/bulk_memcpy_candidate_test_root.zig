//! Fast nonproduction edit loop for the word-granular memcpy candidate.

test {
    _ = @import("stwo_riscv_precompiles").modules.air_tests_bulk_memcpy_caller_candidate_test;
    _ = @import("stwo_riscv_isa").modules.bulk_memcpy_candidate;
    _ = @import("stwo_riscv_isa").modules.bulk_memcpy_private_registry;
    _ = @import("stwo_riscv_frontend").modules.isa_ethereum_bulk_memcpy_candidate;
    _ = @import("stwo_riscv_frontend").modules.runner_ethereum_bulk_memcpy_candidate_result;
    _ = @import("stwo_riscv_frontend").modules.runner_ethereum_candidate_combined_result;
    _ = @import("stwo_riscv_rv32").modules.runner_guest_precompile_bulk_memcpy_candidate_dispatch;
    _ = @import("stwo_riscv_frontend").modules.runner_guest_precompile_ethereum_bulk_memcpy_candidate;
    _ = @import("stwo_riscv_frontend").modules.runner_guest_precompile_tests_ethereum_bulk_memcpy_candidate_test;
    _ = @import("stwo_riscv_frontend").modules.runner_guest_precompile_ethereum_candidate_combined_dispatch;
    _ = @import("stwo_riscv_frontend").modules.runner_guest_precompile_ethereum_candidate_combined_elf_receipt;
    _ = @import("stwo_riscv_frontend").modules.runner_guest_precompile_tests_ethereum_candidate_combined_test;
    _ = @import("stwo_riscv_frontend").modules.runner_guest_precompile_ethereum_candidate_combined;
    _ = @import("runner/guest_precompile/tests/bulk_memcpy_test.zig");
}
