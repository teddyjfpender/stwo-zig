//! Canonical detached boundary arithmetic without integration proof harnesses.
test "detached boundary arithmetic and malformed witness rejection" {
    try @import("recursion/detached_boundary_preparation_v1.zig").testExpectedBoundary();
}
