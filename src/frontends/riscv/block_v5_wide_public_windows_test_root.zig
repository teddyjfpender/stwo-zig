comptime {
    _ = @import("prover/block_v5_wide_public_windows_test_v1.zig");
}
test "wide public windows body: actual legacy and selected channel parent producer receiver and higher rows retention" {
    @import("block_v5_wide_public_windows_codegen_v1.zig").stwo_wide_public_windows_body_gate();
}
