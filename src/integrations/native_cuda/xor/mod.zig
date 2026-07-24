//! Native XOR CUDA frontend adapter.
//!
//! CPU materialization is retained only as a correctness oracle. Production
//! geometry, proof-program emission, topology, and trace construction are
//! independent of CPU trace allocation.

pub const geometry = @import("geometry.zig");
pub const identities = @import("identities.zig");
pub const layout = @import("layout.zig");
pub const program = @import("program.zig");
pub const topology = @import("topology.zig");
pub const trace = @import("trace.zig");
pub const transcript_schedule = @import("transcript_schedule.zig");

test {
    _ = geometry;
    _ = identities;
    _ = layout;
    _ = program;
    _ = topology;
    _ = trace;
    _ = transcript_schedule;
}
