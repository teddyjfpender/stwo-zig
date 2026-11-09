//! Fast nonproduction edit loop for the word-granular memcpy candidate.

test {
    _ = @import("stwo_riscv_precompiles");
    _ = @import("stwo_riscv_isa");
    _ = @import("stwo_riscv_isa");
    _ = @import("stwo_riscv_frontend").modules.compat_product_tree_isa_ethereum_bulk_memcpy_candidate;
    _ = @import("stwo_riscv_frontend").modules.runner_ethereum_bulk_memcpy_candidate_result;
    _ = @import("stwo_riscv_frontend").modules.runner_ethereum_candidate_combined_result;
    _ = @import("stwo_riscv_rv32");
    _ = @import("stwo_riscv_frontend").modules.runner_guest_precompile_ethereum_bulk_memcpy_candidate;
    _ = @import("stwo_riscv_frontend").modules.runner_guest_precompile_tests_ethereum_bulk_memcpy_candidate_test;
    _ = @import("stwo_riscv_frontend").modules.runner_guest_precompile_ethereum_candidate_combined_dispatch;
    _ = @import("stwo_riscv_frontend").modules.runner_guest_precompile_ethereum_candidate_combined_elf_receipt;
    _ = @import("stwo_riscv_frontend").modules.runner_guest_precompile_tests_ethereum_candidate_combined_test;
    _ = @import("stwo_riscv_frontend").modules.runner_guest_precompile_ethereum_candidate_combined;
    _ = @import("runner/guest_precompile/tests/bulk_memcpy_test.zig");
}
