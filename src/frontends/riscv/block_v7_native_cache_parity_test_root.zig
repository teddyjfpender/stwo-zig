test {
    _ = @import("prover/tests/block_v7_native_cache_parity_test.zig");
}
test {
    _ = @import("prover/tests/block_v7_native_mul_q3_test.zig");
    _ = @import("prover/tests/block_v5_native_projection_fused_unit_test.zig");
}
test {
    _ = @import("prover/tests/block_v7_shared_quotient_cache_test.zig");
    _ = @import("prover/tests/block_v7_native_access_interaction_test.zig");
}
