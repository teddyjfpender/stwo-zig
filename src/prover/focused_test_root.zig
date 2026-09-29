//! Explicit test discovery inside the generic prover's package boundary.
const std = @import("std");

comptime {
    std.testing.refAllDeclsRecursive(@import("pcs/columns/preparation.zig"));
    std.testing.refAllDeclsRecursive(@import("pcs/columns/preparation_cache_test.zig"));
    std.testing.refAllDeclsRecursive(@import("pcs/sampled_coefficient_plans.zig"));
    std.testing.refAllDeclsRecursive(@import("pcs/sampled_coefficient_ownership_test.zig"));
    std.testing.refAllDeclsRecursive(@import("poly/circle/mod.zig"));
    std.testing.refAllDeclsRecursive(@import("vcs_lifted/mod.zig"));
}
