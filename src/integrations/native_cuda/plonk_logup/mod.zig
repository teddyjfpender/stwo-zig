//! Activation-disabled exact Plonk/LogUp Native CUDA integration.

pub const geometry = @import("geometry.zig");
pub const canonical_ingress = @import("canonical_ingress.zig");
pub const canonical_input = @import("canonical_input.zig");
pub const constraint = @import("constraint.zig");
pub const device_trace = @import("device_trace.zig");
pub const driver = @import("driver.zig");
pub const executor = @import("executor/mod.zig");
pub const identities = @import("identities.zig");
pub const layout = @import("layout.zig");
pub const oods = @import("oods.zig");
pub const parity_targets = @import("parity_targets.zig");
pub const plan = @import("plan.zig");
pub const program = @import("program.zig");
pub const proof_bundle = @import("proof_bundle.zig");
pub const proof_decode = @import("proof_decode.zig");
pub const relation = @import("relation.zig");
pub const requirements = @import("requirements.zig");
pub const resident_bindings = @import("resident_bindings.zig");
pub const slots = @import("slots.zig");
pub const terminal_bundle = @import("terminal_bundle.zig");
pub const topology = @import("topology.zig");
pub const trace = @import("trace.zig");
pub const transcript_schedule = @import("transcript_schedule.zig");

/// Release activation remains false until the resident proof matches the CPU
/// canonical bytes, passes the pinned Rust verifier, and reports no fallback.
pub const release_enabled = false;

test {
    _ = canonical_ingress;
    _ = canonical_input;
    _ = constraint;
    _ = device_trace;
    _ = driver;
    _ = executor;
    _ = geometry;
    _ = identities;
    _ = layout;
    _ = oods;
    _ = parity_targets;
    _ = plan;
    _ = program;
    _ = proof_bundle;
    _ = proof_decode;
    _ = relation;
    _ = requirements;
    _ = resident_bindings;
    _ = slots;
    _ = terminal_bundle;
    _ = topology;
    _ = trace;
    _ = transcript_schedule;
}
