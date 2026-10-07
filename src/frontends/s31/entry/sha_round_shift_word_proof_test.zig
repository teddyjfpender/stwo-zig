//! Build entry for sha/tests/sha_round_shift_word_proof_test.zig.
const selected = @import("src/sha/tests/sha_round_shift_word_proof_test.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
