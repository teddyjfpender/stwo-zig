//! Shared structural machinery for Native CUDA AIR integrations.

pub const commit_tree = @import("commit_tree.zig");
pub const driver = @import("driver.zig");
pub const proof_bundle = @import("proof_bundle.zig");
pub const resident_views = @import("resident_views.zig");
pub const scheduled_executor = @import("scheduled_executor.zig");
pub const transcript_schedule = @import("transcript_schedule.zig");
pub const uniform_layout = @import("uniform_layout.zig");
pub const uniform_topology = @import("uniform_topology.zig");

test {
    _ = commit_tree;
    _ = driver;
    _ = proof_bundle;
    _ = resident_views;
    _ = scheduled_executor;
    _ = transcript_schedule;
    _ = uniform_layout;
    _ = uniform_topology;
}
