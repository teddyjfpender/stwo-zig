//! Focused production trace admission and typed authority retirement checks.
test {
    _ = @import("stwo_riscv_rv32").modules.runner_tests_trace_test;
    _ = @import("stwo_riscv_air_lang").modules.tests_typed_opcode_production_authority_test;
    _ = @import("air/lang/tests/typed_base_alu_imm_authority_test.zig");
    _ = @import("air/lang/tests/typed_base_alu_reg_authority_test.zig");
}
