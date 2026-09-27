test {
    _ = @import("prover/block_v5_heterogeneous_child_test_v1.zig");
}
test "heterogeneous recursion: actual original typed leaf and common parent bodies are retained" {
    @import("block_v5_heterogeneous_recursive_codegen_v1.zig").stwo_heterogeneous_recursive_body_gate();
}
