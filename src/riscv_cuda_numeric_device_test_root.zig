test "actual NVIDIA CUDA DEEP output equals independent CPU quotient oracle" {
    try @import("integrations/riscv_cuda/tests/hybrid_quotient_test_v1.zig").run(true);
}
