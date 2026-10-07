//! Build entry for bitcoin/fold/bitcoin_chain_fold.zig.
const selected = @import("src/bitcoin/fold/bitcoin_chain_fold.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
