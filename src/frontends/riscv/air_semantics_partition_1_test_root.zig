//! One required compilation partition of the complete focused target.

test {
    _ = @import("runner/tests/lui_retirement_test.zig");
    _ = @import("air/lang/tests/typed_addi_adversarial_test.zig");
    _ = @import("air/lang/tests/typed_addi_test.zig");
    _ = @import("air/lang/tests/typed_addi_witness_adversarial_test.zig");
    _ = @import("air/lang/tests/typed_addi_witness_test.zig");
    _ = @import("air/lang/tests/typed_base_alu_imm_witness_test.zig");
    _ = @import("air/lang/tests/typed_base_alu_imm_witness_adversarial_test.zig");
    _ = @import("air/lang/typed_base_alu_imm_authority.zig");
    _ = @import("air/lang/tests/typed_base_alu_imm_authority_test.zig");
    _ = @import("air/lang/tests/typed_base_alu_reg_test.zig");
    _ = @import("air/lang/typed_base_alu_reg_authority.zig");
    _ = @import("air/lang/tests/typed_base_alu_reg_authority_test.zig");
    _ = @import("air/lang/tests/typed_base_alu_reg_witness_test.zig");
    _ = @import("air/lang/tests/typed_base_alu_reg_witness_adversarial_test.zig");
    _ = @import("air/lang/tests/typed_auipc_test.zig");
    _ = @import("air/lang/tests/typed_auipc_witness_test.zig");
    _ = @import("air/lang/tests/typed_auipc_witness_adversarial_test.zig");
    _ = @import("air/lang/tests/typed_branch_eq_test.zig");
    _ = @import("air/lang/tests/typed_branch_eq_witness_test.zig");
    _ = @import("air/lang/tests/typed_branch_eq_witness_adversarial_test.zig");
    _ = @import("air/lang/typed_branch_eq_authority.zig");
    _ = @import("air/lang/tests/typed_branch_eq_authority_test.zig");
    _ = @import("air/lang/tests/typed_branch_lt_test.zig");
    _ = @import("air/lang/tests/typed_branch_lt_witness_test.zig");
    _ = @import("air/lang/tests/typed_branch_lt_witness_adversarial_test.zig");
    _ = @import("air/lang/typed_branch_lt_authority.zig");
    _ = @import("air/lang/tests/typed_branch_lt_authority_test.zig");
}
