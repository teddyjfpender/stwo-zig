//! Build entry for sha/tests/sha_fused_fold_matched_bench_test.zig.
const selected = @import("src/sha/tests/sha_fused_fold_matched_bench_test.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
