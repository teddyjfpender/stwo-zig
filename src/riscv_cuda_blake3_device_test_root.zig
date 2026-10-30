test "actual NVIDIA resident BLAKE3 canonical commitments transcript and minimum nonce" {
    try @import("integrations/riscv_cuda/tests/resident_blake3_test_v1.zig").run();
}
