//! Native CUDA Blake integrations.
//!
//! `exact` is the only product-admissible proof structure. The direct exports
//! below belong to the fail-closed legacy experiment and remain temporarily
//! available only so its host contracts can be retired without a flag day.

pub const exact = @import("exact/mod.zig");
pub const geometry = @import("geometry.zig");
pub const canonical_ingress = @import("canonical_ingress.zig");
pub const commit_tree = @import("commit_tree.zig");
pub const driver = @import("driver.zig");
pub const executor = @import("executor/mod.zig");
pub const constraint = @import("constraint.zig");
pub const identities = @import("identities.zig");
pub const layout = @import("layout.zig");
pub const parity_targets = @import("parity_targets.zig");
pub const plan = @import("plan.zig");
pub const program = @import("program.zig");
pub const proof_bundle = @import("proof_bundle.zig");
pub const proof_decode = @import("proof_decode.zig");
pub const protocol = @import("protocol.zig");
pub const requirements = @import("requirements.zig");
pub const resident_bindings = @import("resident_bindings/mod.zig");
pub const slots = @import("slots.zig");
pub const terminal_bundle = @import("terminal_bundle.zig");
pub const topology = @import("topology.zig");
pub const trace = @import("trace.zig");
pub const transcript_schedule = @import("transcript_schedule.zig");

pub const NativeDriver = driver.DriverFor(
    driver.NativeTransaction,
    executor.pipeline,
);
pub const NativeRuntime = driver.NativeRuntime;

test {
    _ = exact;
    _ = geometry;
    _ = canonical_ingress;
    _ = commit_tree;
    _ = driver;
    _ = executor;
    _ = constraint;
    _ = identities;
    _ = layout;
    _ = parity_targets;
    _ = plan;
    _ = program;
    _ = proof_bundle;
    _ = proof_decode;
    _ = protocol;
    _ = requirements;
    _ = resident_bindings;
    _ = slots;
    _ = terminal_bundle;
    _ = topology;
    _ = trace;
    _ = transcript_schedule;
}
