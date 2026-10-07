//! Build entry for bitcoin/tests/bitcoin_fused_chain_verifier_test.zig.
const selected = @import("src/bitcoin/tests/bitcoin_fused_chain_verifier_test.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
