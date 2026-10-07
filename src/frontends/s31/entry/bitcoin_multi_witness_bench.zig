//! Build entry for bitcoin/tests/bitcoin_multi_witness_bench.zig.
const selected = @import("src/bitcoin/tests/bitcoin_multi_witness_bench.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
