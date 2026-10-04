test {
    _ = @import("prover/block_v5_caller_readonly_recursive_test_v1.zig");
    _ = @import("prover/tests/block_v5_caller_readonly_unit_test.zig");
}
test "caller readonly recursion: actual original capture all cohorts publication and receiver bodies retained" {
    @import("block_v5_caller_readonly_recursive_codegen.zig").stwo_caller_readonly_recursive_body_gate();
}
