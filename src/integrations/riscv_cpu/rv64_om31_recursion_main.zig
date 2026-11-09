//! Current OM31 recursion product; shares the native receiver authority/loader.
pub fn main() !void {
    return @import("../../products/ethereum/statement/cpu/word16_global_execution/ethereum/gkr_main.zig").mainWithRecursion();
}
