//! Package-root facade for the bounded RISC-V function-value observer.

pub fn main() !void {
    return @import("tools/riscv/function_value/main.zig").main();
}
