//! Focused private gate for the RV32 `MUL` fixed-authority cutover.

const authority = @import("stwo_riscv_rv32").air.lang.typed_mul_authority;

test {
    _ = authority;
    _ = @import("air/lang/tests/typed_mul_authority_test.zig");
    _ = @import("stwo_riscv_rv32");
    _ = @import("stwo_riscv_rv32");
}
