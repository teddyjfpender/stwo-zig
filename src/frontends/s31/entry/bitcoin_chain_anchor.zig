//! Build entry for bitcoin/fold/bitcoin_chain_anchor.zig.
const selected = @import("src/bitcoin/fold/bitcoin_chain_anchor.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
