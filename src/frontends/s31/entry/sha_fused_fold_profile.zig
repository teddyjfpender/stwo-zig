//! Build entry for sha/config/sha_fused_fold_profile.zig.
const selected = @import("src/sha/config/sha_fused_fold_profile.zig");

pub fn main() !void {
    try selected.main();
}

test {
    _ = selected;
}
