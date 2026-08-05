//! Native XOR CUDA frontend adapter.
//!
//! CPU materialization is retained only as a correctness oracle. Production
//! geometry, proof-program emission, topology, and trace construction are
//! independent of CPU trace allocation.

pub const canonical_input = @import("canonical_input.zig");
pub const canonical_ingress = @import("canonical_ingress.zig");
pub const constraint = @import("constraint.zig");
pub const device_trace = @import("device_trace.zig");
pub const driver = @import("driver.zig");
pub const executor = @import("executor/mod.zig");
pub const geometry = @import("geometry.zig");
pub const identities = @import("identities.zig");
pub const layout = @import("layout.zig");
pub const oods = @import("oods.zig");
pub const parity_targets = @import("parity_targets.zig");
pub const plan = @import("plan.zig");
pub const proof_bundle = @import("proof_bundle.zig");
pub const proof_decode = @import("proof_decode.zig");
pub const program = @import("program.zig");
pub const relation = @import("relation.zig");
pub const requirements = @import("requirements.zig");
pub const resident_bindings = @import("resident_bindings.zig");
pub const slots = @import("slots.zig");
pub const topology = @import("topology.zig");
pub const terminal_bundle = @import("terminal_bundle.zig");
pub const terminal_output = @import("terminal_output.zig");
pub const trace = @import("trace.zig");
pub const transcript_schedule = @import("transcript_schedule.zig");

pub const NativeDriver = driver.DriverFor(
    driver.NativeTransaction,
    executor.pipeline,
);
pub const NativeRuntime = driver.NativeRuntime;
pub const CuMetalDriver = driver.DriverFor(
    driver.CuMetalTransaction,
    executor.pipeline,
);
pub const CuMetalRuntime = driver.CuMetalRuntime;

test {
    _ = canonical_input;
    _ = canonical_ingress;
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
    _ = proof_bundle;
    _ = proof_decode;
    _ = program;
    _ = relation;
    _ = requirements;
    _ = resident_bindings;
    _ = slots;
    _ = topology;
    _ = terminal_bundle;
    _ = terminal_output;
    _ = trace;
    _ = transcript_schedule;
}
