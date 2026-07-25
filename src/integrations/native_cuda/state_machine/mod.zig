//! Legacy resident CUDA adapter for the simplified State Machine v1 AIR.
//!
//! Native CPU and pinned Rust now use the exact v2 interaction protocol. This
//! module remains compiled as compatibility code, but no product, benchmark,
//! or parity gate may present it as an exact State Machine backend.

const exact_state_machine = @import("../../../examples/state_machine.zig");

pub const legacy_protocol_name = "raw-stwo-state-machine-v1";
pub const exact_protocol_name = exact_state_machine.protocol_name;
pub const exact_protocol_available = false;

pub fn requireExactProtocol() !void {
    if (!exact_protocol_available)
        return error.StateMachineExactProtocolUnavailable;
}

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
    _ = terminal_bundle;
    _ = topology;
    _ = trace;
    _ = transcript_schedule;
}

test "legacy CUDA State Machine cannot satisfy the exact CPU protocol" {
    try @import("std").testing.expect(!exact_protocol_available);
    try @import("std").testing.expect(!@import("std").mem.eql(
        u8,
        legacy_protocol_name,
        exact_protocol_name,
    ));
    try @import("std").testing.expectError(
        error.StateMachineExactProtocolUnavailable,
        requireExactProtocol(),
    );
}
