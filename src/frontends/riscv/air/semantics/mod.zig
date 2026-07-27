//! Compositional opcode semantic evaluators.
//!
//! Direct polynomial constraints and sibling lookup requests live together per
//! family, while transcript orchestration and LogUp accumulation remain in the
//! component layer. This keeps semantic review independent of PCS machinery.
//!
//! Every family is generic over its scalar type.  The instantiation that ships
//! is `QM31`; `Families(Symbolic)` re-runs the same source to build the SMT
//! model checked by `scripts/air_uniqueness.py`, so the verified model and the
//! committed constraints cannot drift apart.  The scalar interface is exactly
//! `zero`, `one`, `fromBase`, `add`, `sub`, `mul`, `neg` -- see
//! `air/symbolic.zig`.

const QM31 = @import("stwo_core").fields.qm31.QM31;

pub fn Families(comptime S: type) type {
    return struct {
        pub const common = @import("common.zig").Ops(S);
        pub const control_common = @import("control_common.zig").Ops(S);
        pub const shift_common = @import("shift_common.zig").Semantics(S);
        pub const base_alu_reg = @import("base_alu_reg.zig").Semantics(S);
        pub const base_alu_imm = @import("base_alu_imm.zig").Semantics(S);
        pub const shifts_reg = @import("shifts_reg.zig").Semantics(S);
        pub const shifts_imm = @import("shifts_imm.zig").Semantics(S);
        pub const lt_reg = @import("lt_reg.zig").Semantics(S);
        pub const lt_imm = @import("lt_imm.zig").Semantics(S);
        pub const branch_eq = @import("branch_eq.zig").Semantics(S);
        pub const branch_lt = @import("branch_lt.zig").Semantics(S);
        pub const lui = @import("lui.zig").Semantics(S);
        pub const auipc = @import("auipc.zig").Semantics(S);
        pub const jalr = @import("jalr.zig").Semantics(S);
        pub const jal = @import("jal.zig").Semantics(S);
        pub const load_store = @import("load_store.zig").Semantics(S);
        pub const mul = @import("mul.zig").Semantics(S);
        pub const mulh = @import("mulh.zig").Semantics(S);
        pub const div = @import("div.zig").Semantics(S);
        pub const fence = @import("fence.zig").Semantics(S);
    };
}

const shipped = Families(QM31);

pub const common = shipped.common;
pub const control_common = shipped.control_common;
pub const shift_common = shipped.shift_common;
pub const base_alu_reg = shipped.base_alu_reg;
pub const base_alu_imm = shipped.base_alu_imm;
pub const shifts_reg = shipped.shifts_reg;
pub const shifts_imm = shipped.shifts_imm;
pub const lt_reg = shipped.lt_reg;
pub const lt_imm = shipped.lt_imm;
pub const branch_eq = shipped.branch_eq;
pub const branch_lt = shipped.branch_lt;
pub const lui = shipped.lui;
pub const auipc = shipped.auipc;
pub const jalr = shipped.jalr;
pub const jal = shipped.jal;
pub const load_store = shipped.load_store;
pub const mul = shipped.mul;
pub const mulh = shipped.mulh;
pub const div = shipped.div;
pub const fence = shipped.fence;

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
