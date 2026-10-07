//! Build entry for bitcoin/fold/bitcoin_fold_step.zig.
const selected = @import("src/bitcoin/fold/bitcoin_fold_step.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
