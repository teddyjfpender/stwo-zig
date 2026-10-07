//! Build entry for tools/inspect/inspect_bitcoin_fold_step.zig.
const selected = @import("src/tools/inspect/inspect_bitcoin_fold_step.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
