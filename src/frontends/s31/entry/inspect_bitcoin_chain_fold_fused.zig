//! Build entry for tools/inspect/inspect_bitcoin_chain_fold_fused.zig.
const selected = @import("src/tools/inspect/inspect_bitcoin_chain_fold_fused.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
