test {
    _ = @import("stwo_riscv_recursion").modules.tests_temporal_pair_node_test;
    _ = @import("recursion/tests/segment_statement_test.zig");
    _ = @import("recursion/tests/segment_statement_runner_e2e_test.zig");
    _ = @import("recursion/tests/segment_leaf_local_authority_test.zig");
    _ = @import("stwo_riscv_recursion").modules.tests_segment_leaf_authority_v2_test;
    _ = @import("air/tests/public_data_test.zig");
    _ = @import("air/tests/public_logup_test.zig");
}
