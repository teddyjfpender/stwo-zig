//! Build entry for bitcoin/verification/bitcoin_chain_retarget_verifier.zig.
const selected = @import("src/bitcoin/verification/bitcoin_chain_retarget_verifier.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
