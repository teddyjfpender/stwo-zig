//! Build entry for sha/air/sha_round_direct_word_logup.zig.
const selected = @import("src/sha/air/sha_round_direct_word_logup.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
