//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("../../air/interaction_reference_oracle.zig");
    _ = @import("../../air/semantics/auipc_reference_oracle.zig");
    _ = @import("../../air/semantics/base_alu_imm_reference_oracle.zig");
    _ = @import("../../air/semantics/base_alu_reg_reference_oracle.zig");
    _ = @import("../../air/semantics/branch_eq_reference_oracle.zig");
    _ = @import("../../air/semantics/branch_lt_reference_oracle.zig");
    _ = @import("../../air/semantics/div_reference_oracle.zig");
    _ = @import("../../air/semantics/fence_reference_oracle.zig");
    _ = @import("../../air/semantics/jal_reference_oracle.zig");
    _ = @import("../../air/semantics/jalr_reference_oracle.zig");
    _ = @import("../../air/semantics/load_store_reference_oracle.zig");
    _ = @import("../../air/semantics/lt_imm_reference_oracle.zig");
    _ = @import("../../air/semantics/lt_reg_reference_oracle.zig");
    _ = @import("../../air/semantics/lui_reference_oracle.zig");
    _ = @import("../../air/semantics/mod.zig");
    _ = @import("../../air/semantics/mul_reference_oracle.zig");
    _ = @import("../../air/semantics/mulh_reference_oracle.zig");
    _ = @import("../../air/semantics/shift_common.zig");
    _ = @import("../../air/semantics/shifts_imm_reference_oracle.zig");
    _ = @import("../../air/semantics/shifts_reg_reference_oracle.zig");
    _ = @import("../../runner/tests/fence_retirement_test.zig");
}
