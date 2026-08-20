//! Compile-isolated performance recheck for production geometry consumers
//! touched by the E-022 manifest cutover.

test {
    _ = @import("air/lang/typed_base_alu_reg_witness_performance_test.zig");
    _ = @import("air/lang/typed_branch_eq_authority_test.zig");
    _ = @import("air/lang/typed_jal_authority_test.zig");
    _ = @import("air/lang/typed_jalr_authority_test.zig");
    _ = @import("air/lang/typed_shifts_reg_witness_performance_test.zig");
}
