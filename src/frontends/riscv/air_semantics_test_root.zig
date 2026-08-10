test {
    _ = @import("air/semantics/auipc.zig");
    _ = @import("air/semantics/base_alu_imm.zig");
    _ = @import("air/semantics/base_alu_reg.zig");
    _ = @import("air/semantics/branch_eq.zig");
    _ = @import("air/semantics/branch_lt.zig");
    _ = @import("air/semantics/common.zig");
    _ = @import("air/semantics/control_common.zig");
    _ = @import("air/semantics/div.zig");
    _ = @import("air/semantics/fence.zig");
    _ = @import("air/semantics/jal.zig");
    _ = @import("air/semantics/jalr.zig");
    _ = @import("air/semantics/load_store.zig");
    _ = @import("air/semantics/lt_imm.zig");
    _ = @import("air/semantics/lt_reg.zig");
    _ = @import("air/semantics/lui.zig");
    _ = @import("air/semantics/mod.zig");
    _ = @import("air/semantics/mul.zig");
    _ = @import("air/semantics/mulh.zig");
    _ = @import("air/semantics/shift_common.zig");
    _ = @import("air/semantics/shifts_imm.zig");
    _ = @import("air/semantics/shifts_reg.zig");
    _ = @import("air/lang/typed_lui_adversarial_test.zig");
    _ = @import("air/lang/typed_lui_test.zig");
}
