test {
    _ = @import("prover/block_v5_recursive_parent_fixed_roster_test_v1.zig");
    _ = @import("recursion/air/native_pcs_fusion_rows.zig");
}
test "recursive fixed roster: actual full fixed roster and original live bodies retained" {
    @import("block_v5_recursive_parent_fixed_roster_codegen_v1.zig").stwo_recursive_parent_fixed_roster_body_gate();
}
