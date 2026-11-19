//! Focused CPU RISC-V composition test roots.

test {
    _ = @import("riscv_composition_arithmetic_test.zig");
    _ = @import("riscv_authenticated_composition_test.zig");
}
