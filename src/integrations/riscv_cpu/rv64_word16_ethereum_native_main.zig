//! CPU-only native STARK production/reception, without recursion dependencies.
pub fn main() !void {
    try @import("word16_global_execution/ethereum/gkr_main.zig").mainNativeOnly();
}
