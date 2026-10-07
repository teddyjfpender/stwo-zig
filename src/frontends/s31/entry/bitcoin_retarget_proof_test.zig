//! Build entry for bitcoin/tests/bitcoin_retarget_proof_test.zig.
const selected = @import("src/bitcoin/tests/bitcoin_retarget_proof_test.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
