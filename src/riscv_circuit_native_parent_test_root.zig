//! Deferred opt-in full wrapper qualification; do not run during full block.
test {
    _ = @import("integrations/circuit_cpu/riscv_recursion/qualification_v1.zig");
    _ = @import("integrations/circuit_cpu/riscv_recursion/fold_qualification_v1.zig");
}
