//! Build entry for sha/tests/sha_caller_stream_proof_test.zig.
const selected = @import("src/sha/tests/sha_caller_stream_proof_test.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
