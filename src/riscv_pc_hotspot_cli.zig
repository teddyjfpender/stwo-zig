//! Package-root facade for the bounded RISC-V PC-hotspot diagnostic.

pub fn main() !void {
    return @import("tools/riscv/pc_hotspot/main.zig").main();
}
