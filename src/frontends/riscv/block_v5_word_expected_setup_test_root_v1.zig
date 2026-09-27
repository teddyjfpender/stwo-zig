test {
    _ = @import("prover/block_v5_word_expected_setup_test_v1.zig");
    _ = @import("prover/block_v5_cpu_recursive_publication_test_v1.zig");
    _ = @import("prover/block_v5_cpu_recursive_publication_rollback_test_v1.zig");
    _ = @import("prover/block_v5_ram_range_forest_owned_test_v1.zig");
    _ = @import("prover/block_v5_cpu_recursive_completion_test_v1.zig");
}
test "word expected setup: actual independent key cache canonical CPU receiver and memory forest bodies retained" {
    @import("block_v5_word_expected_setup_codegen_v1.zig").stwo_word_expected_setup_body_gate();
}
