test "retained Ethereum shared union recursive root benchmark" {
    try @import("prover/tests/block_v7_real_window_v2_benchmark.zig").runUnionRoot();
}
