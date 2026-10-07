//! Build entry for bitcoin/cli/bitcoin_chain_cli.zig.
const selected = @import("src/bitcoin/cli/bitcoin_chain_cli.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
