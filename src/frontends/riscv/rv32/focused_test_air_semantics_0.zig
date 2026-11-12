//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("air/interaction_legacy_test_oracle.zig");
    _ = @import("air/semantics/auipc_legacy_test_oracle.zig");
    _ = @import("air/semantics/base_alu_imm_legacy_test_oracle.zig");
    _ = @import("air/semantics/base_alu_reg_legacy_test_oracle.zig");
    _ = @import("air/semantics/branch_eq_legacy_test_oracle.zig");
    _ = @import("air/semantics/branch_lt_legacy_test_oracle.zig");
    _ = @import("air/semantics/div_legacy_test_oracle.zig");
    _ = @import("air/semantics/fence_legacy_test_oracle.zig");
    _ = @import("air/semantics/jal_legacy_test_oracle.zig");
    _ = @import("air/semantics/jalr_legacy_test_oracle.zig");
    _ = @import("air/semantics/load_store_legacy_test_oracle.zig");
    _ = @import("air/semantics/lt_imm_legacy_test_oracle.zig");
    _ = @import("air/semantics/lt_reg_legacy_test_oracle.zig");
    _ = @import("air/semantics/lui_legacy_test_oracle.zig");
    _ = @import("air/semantics/mod.zig");
    _ = @import("air/semantics/mul_legacy_test_oracle.zig");
    _ = @import("air/semantics/mulh_legacy_test_oracle.zig");
    _ = @import("air/semantics/shift_common.zig");
    _ = @import("air/semantics/shifts_imm_legacy_test_oracle.zig");
    _ = @import("air/semantics/shifts_reg_legacy_test_oracle.zig");
    _ = @import("runner/tests/fence_retirement_test.zig");
}
