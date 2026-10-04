//! Focused production trace admission and typed authority retirement checks.
test {
    _ = @import("runner/tests/trace_test.zig");
    _ = @import("air/lang/tests/typed_opcode_production_authority_test.zig");
    _ = @import("air/lang/tests/typed_base_alu_imm_authority_test.zig");
    _ = @import("air/lang/tests/typed_base_alu_reg_authority_test.zig");
}
