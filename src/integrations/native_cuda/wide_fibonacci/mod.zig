//! Native CUDA wide-Fibonacci proof integration.

pub const canonical_ingress = @import("canonical_ingress.zig");
pub const driver = @import("driver.zig");
pub const executor = @import("executor/mod.zig");
pub const commit_tree = @import("commit_tree.zig");
pub const layout = @import("layout.zig");
pub const plan = @import("plan.zig");
pub const program = @import("program.zig");
pub const proof_bundle = @import("proof_bundle.zig");
pub const proof_decode = @import("proof_decode.zig");
pub const protocol = @import("protocol.zig");
pub const request = @import("request.zig");
pub const resident_bindings = @import("resident_bindings/mod.zig");
pub const requirements = @import("requirements.zig");
pub const slots = @import("slots.zig");
pub const topology = @import("topology.zig");
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
    _ = canonical_ingress;
    _ = driver;
    _ = executor;
    _ = commit_tree;
    _ = layout;
    _ = plan;
    _ = program;
    _ = proof_bundle;
    _ = proof_decode;
    _ = protocol;
    _ = request;
    _ = resident_bindings;
    _ = requirements;
    _ = slots;
    _ = topology;
    _ = transcript_schedule;
}
