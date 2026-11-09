//! Focused private gate for the RV32 `DIV` fixed-authority cutover.

const authority = @import("stwo_riscv_rv32").modules.air_lang_typed_div_authority;

test {
    _ = authority;
    _ = @import("air/lang/tests/typed_div_authority_test.zig");
    _ = @import("stwo_riscv_rv32").modules.runner_div_retirement;
    _ = @import("stwo_riscv_rv32").modules.runner_tests_div_retirement_test;
}
