//! Test discovery and compatibility exports for the independently owned case groups.
const Support = @import("fri_fold_commit_support.zig");

test {
    _ = @import("fri_fold_commit_resident_openings.zig");
    _ = @import("fri_fold_commit_fold_commit.zig");
}
