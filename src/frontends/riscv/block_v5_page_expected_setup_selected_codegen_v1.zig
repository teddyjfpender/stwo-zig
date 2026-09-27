pub const BLOCK_V5_EXECUTION_RECIPE: u32 = 1;
pub export fn stwo_page_expected_setup_selected_body_gate() void {
    @setEvalBranchQuota(1_000_000);
    @import("block_v5_page_expected_setup_codegen_v1.zig").stwo_page_expected_setup_body_gate();
}
