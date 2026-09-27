pub export fn stwo_scoped_parent_admission_body_gate() void {
    @setEvalBranchQuota(1_000_000);
    @import("block_v5_scoped_parent_admission_isolated_codegen_v1.zig").stwo_scoped_parent_admission_isolated_body_gate();
    @import("block_v5_supplemental_recursive_lifetime_codegen_v1.zig").stwo_supplemental_recursive_lifetime_body_gate();
}
