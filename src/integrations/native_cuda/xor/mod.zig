//! Native XOR CUDA frontend adapter.
//!
//! CPU materialization is retained only as a correctness oracle. Production
//! geometry, proof-program emission, topology, and trace construction are
//! independent of CPU trace allocation.

pub const canonical_input = @import("canonical_input.zig");
pub const constraint = @import("constraint.zig");
pub const device_trace = @import("device_trace.zig");
pub const geometry = @import("geometry.zig");
pub const identities = @import("identities.zig");
pub const layout = @import("layout.zig");
pub const parity_targets = @import("parity_targets.zig");
pub const proof_bundle = @import("proof_bundle.zig");
pub const program = @import("program.zig");
pub const topology = @import("topology.zig");
pub const trace = @import("trace.zig");
pub const transcript_schedule = @import("transcript_schedule.zig");

test {
    _ = canonical_input;
    _ = constraint;
    _ = device_trace;
    _ = geometry;
    _ = identities;
    _ = layout;
    _ = parity_targets;
    _ = proof_bundle;
    _ = program;
    _ = topology;
    _ = trace;
    _ = transcript_schedule;
}
