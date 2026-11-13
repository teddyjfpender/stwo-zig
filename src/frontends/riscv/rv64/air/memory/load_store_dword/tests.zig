//! Test discovery and compatibility exports for the independently owned case groups.
const Support = @import("tests_support.zig");

test {
    _ = @import("tests_classic.zig");
    _ = @import("tests_fused_pair.zig");
}
