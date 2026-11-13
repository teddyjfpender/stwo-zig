//! Focused private gate for the RV32 `MULH` fixed-authority cutover.

const authority = @import("stwo_riscv_rv32").air.lang.typed_mulh_authority;

test {
    _ = authority;
    _ = @import("air/lang/tests/typed_mulh_authority_test.zig");
    _ = @import("stwo_riscv_rv32");
    _ = @import("stwo_riscv_rv32");
}
