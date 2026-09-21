//! Focused production trace admission and typed authority retirement checks.
test {
    _ = @import("runner/trace_test.zig");
    _ = @import("air/lang/typed_opcode_production_authority_test.zig");
    _ = @import("air/lang/typed_base_alu_imm_authority_test.zig");
    _ = @import("air/lang/typed_base_alu_reg_authority_test.zig");
}
