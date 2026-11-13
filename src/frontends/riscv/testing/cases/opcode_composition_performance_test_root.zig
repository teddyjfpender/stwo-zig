//! Compile-isolated performance recheck for production geometry consumers
//! touched by the E-022 manifest cutover.

test {
    _ = @import("air/lang/tests/typed_branch_eq_authority_test.zig");
    _ = @import("air/lang/tests/typed_jal_authority_test.zig");
    _ = @import("air/lang/tests/typed_jalr_authority_test.zig");
}
