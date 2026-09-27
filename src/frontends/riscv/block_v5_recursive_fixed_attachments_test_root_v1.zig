test {
    _ = @import("prover/block_v5_recursive_fixed_attachments_test_v1.zig");
    _ = @import("prover/block_v5_recursive_parent_fixed_roster_test_v1.zig");
}
test "recursive fixed attachment: actual attachment and original production bodies retained" {
    @import("block_v5_recursive_fixed_attachments_codegen_v1.zig").stwo_recursive_fixed_attachments_body_gate();
}
