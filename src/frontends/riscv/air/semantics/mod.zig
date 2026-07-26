//! Compositional opcode semantic evaluators.
//!
//! Direct polynomial constraints and sibling lookup requests live together per
//! family, while transcript orchestration and LogUp accumulation remain in the
//! component layer. This keeps semantic review independent of PCS machinery.

pub const common = @import("common.zig");
pub const control_common = @import("control_common.zig");
pub const base_alu_reg = @import("base_alu_reg.zig");
pub const base_alu_imm = @import("base_alu_imm.zig");
pub const shifts_reg = @import("shifts_reg.zig");
pub const shifts_imm = @import("shifts_imm.zig");
pub const lt_reg = @import("lt_reg.zig");
pub const lt_imm = @import("lt_imm.zig");
pub const branch_eq = @import("branch_eq.zig");
pub const branch_lt = @import("branch_lt.zig");
pub const lui = @import("lui.zig");
pub const auipc = @import("auipc.zig");
pub const jalr = @import("jalr.zig");
pub const jal = @import("jal.zig");
pub const load_store = @import("load_store.zig");
pub const mul = @import("mul.zig");
pub const mulh = @import("mulh.zig");
pub const div = @import("div.zig");
pub const fence = @import("fence.zig");

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
