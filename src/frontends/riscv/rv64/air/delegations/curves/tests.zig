//! Test discovery and compatibility exports for the independently owned case groups.
const Support = @import("tests_support.zig");
pub const q = Support.q;
pub const qi = Support.qi;
pub const Harness = Support.Harness;
pub const KEYS = Support.KEYS;
pub const challenges = Support.challenges;

test {
    _ = @import("tests_geometry_known_answers.zig");
    _ = @import("tests_adversarial.zig");
    _ = @import("tests_interaction.zig");
    _ = @import("tests_edge_cases.zig");
}
