//! Focused private gate for the RV32 `DIV` fixed-authority cutover.

const authority = @import("stwo_riscv_rv32").air_lang_typed_div_authority;

test {
    _ = authority;
    _ = @import("air/lang/tests/typed_div_authority_test.zig");
    _ = @import("stwo_riscv_rv32");
    _ = @import("stwo_riscv_rv32");
}
