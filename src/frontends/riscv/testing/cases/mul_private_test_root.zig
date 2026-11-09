//! Focused private gate for the RV32 `MUL` fixed-authority cutover.

const authority = @import("stwo_riscv_rv32").modules.air_lang_typed_mul_authority;

test {
    _ = authority;
    _ = @import("air/lang/tests/typed_mul_authority_test.zig");
    _ = @import("stwo_riscv_rv32").modules.runner_mul_retirement;
    _ = @import("stwo_riscv_rv32").modules.runner_tests_mul_retirement_test;
}
