//! Build entry for bitcoin/tests/bitcoin_chain_anchor_proof_test.zig.
const selected = @import("src/bitcoin/tests/bitcoin_chain_anchor_proof_test.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
