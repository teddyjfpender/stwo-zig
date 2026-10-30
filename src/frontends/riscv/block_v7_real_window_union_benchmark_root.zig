test "retained Ethereum shared union original STARK benchmark" {
    try @import("prover/tests/block_v7_real_window_v2_benchmark.zig").runUnion();
}
