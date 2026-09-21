//! Standalone entry with only the admitted parent-verifier command module.
pub fn main() !void {
    return @import("stwo_parent_verifier").main();
}
