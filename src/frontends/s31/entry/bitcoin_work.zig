//! Build entry for bitcoin/consensus/bitcoin_work.zig.
const selected = @import("src/bitcoin/consensus/bitcoin_work.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
