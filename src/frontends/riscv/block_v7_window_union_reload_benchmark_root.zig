test "reload saved shared union proof from pinned complete endpoints" {
    try @import("prover/tests/block_v7_real_window_v2_benchmark.zig").runReload();
}
