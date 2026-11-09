//! Standalone consumer: fixed-key pin, expected public wire, claims and proof.
pub fn main() !void {
    return @import("stwo_leaf_verifier").main();
}
