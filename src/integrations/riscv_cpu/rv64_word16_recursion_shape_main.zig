//! Bounded diagnostic only; no recursive receiver or circuit is constructed.
pub fn main() !void {
    return @import("word16_recursion/main.zig").main();
}
