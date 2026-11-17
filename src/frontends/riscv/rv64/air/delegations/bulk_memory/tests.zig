//! Test discovery and compatibility exports for the independently owned case groups.
const Support = @import("tests_support.zig");
pub const World = Support.World;
pub const Verdict = Support.Verdict;
pub const imageCode = Support.imageCode;
pub const JWitness = Support.JWitness;
pub const honestJ = Support.honestJ;
pub const verdictJ = Support.verdictJ;
pub const JFixture = Support.JFixture;

test {
    _ = @import("tests_fraction_authority.zig");
    _ = @import("tests_copy_set.zig");
    _ = @import("tests_unaligned_compare.zig");
    _ = @import("tests_jumpdest.zig");
    _ = @import("tests_edge_rejections.zig");
}
