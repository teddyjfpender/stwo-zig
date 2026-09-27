pub const BLOCK_V5_EXECUTION_RECIPE: u32 = 1;
test {
    _ = @import("prover/block_v5_caller_readonly_global_recursive_test_v2.zig");
    _ = @import("prover/block_v5_caller_readonly_recursive_test_v1.zig");
}
test "caller readonly global recursion: actual original global2 producer capture all cohorts stage fresh receiver bodies retained" {
    @import("block_v5_caller_readonly_global_recursive_codegen.zig").stwo_caller_readonly_global_recursive_body_gate();
    @import("block_v5_caller_readonly_recursive_codegen.zig").stwo_caller_readonly_recursive_body_gate();
}
