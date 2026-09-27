test {
    _ = @import("prover/block_v5_page_expected_setup_test_v1.zig");
    _ = @import("prover/block_v5_memory_source_page_durable_test_v1.zig");
    _ = @import("prover/block_v5_native_recursive_setup_cache_v1.zig");
}
test "PAGE expected setup: actual default policy owner original freshness fixed factory node cache and stage bodies retained" {
    @import("block_v5_page_expected_setup_codegen_v1.zig").stwo_page_expected_setup_body_gate();
}
