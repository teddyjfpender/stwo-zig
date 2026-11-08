//! RISC-V CPU product test root (formerly the `riscv_only` branch of
//! `src/tests.zig`). It sits at `products/riscv/cpu/` so the tests can embed
//! the trace dumper source in `trace/` under Zig 0.15's module-root rule.

const std = @import("std");
const test_options = @import("test_options");

test {
    if (test_options.riscv_exhaustive) {
        _ = @import("tests/trace_test.zig");
    } else {
        _ = @import("tests/product_test.zig");
    }
    std.testing.refAllDecls(@This());
}
