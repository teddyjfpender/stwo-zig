//! Focused private gate for the RV32 `MULH` fixed-authority cutover.

const authority = @import("stwo_riscv_rv32").modules.air_lang_typed_mulh_authority;

test {
    _ = authority;
    _ = @import("air/lang/tests/typed_mulh_authority_test.zig");
    _ = @import("stwo_riscv_rv32").modules.runner_mulh_retirement;
    _ = @import("stwo_riscv_rv32").modules.runner_tests_mulh_retirement_test;
}
