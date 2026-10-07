//! Build entry for bitcoin/tests/bitcoin_generic_vs_sha_shift_bench_test.zig.
const selected = @import("src/bitcoin/tests/bitcoin_generic_vs_sha_shift_bench_test.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
