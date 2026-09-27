pub const BLOCK_V5_EXECUTION_RECIPE: u32 = 1;
pub export fn stwo_supplemental_recursive_lifetime_selected_body_gate() void {
    @setEvalBranchQuota(1_000_000);
    @import("block_v5_supplemental_recursive_lifetime_codegen_v1.zig").stwo_supplemental_recursive_lifetime_body_gate();
}
