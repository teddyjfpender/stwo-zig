//! Capability facade for the aggregate CPU + Metal CLI.

const cpu = @import("stwo_aggregate_cpu.zig");

pub const core = cpu.core;
pub const backend = cpu.backend;
pub const prover = cpu.prover;
pub const examples = cpu.examples;
pub const frontends = cpu.frontends;
pub const integrations = cpu.integrations;
pub const interop = cpu.interop;

pub const backends = struct {
    pub const cpu = @import("stwo_cpu_backend");
    pub const metal = @import("stwo_metal_backend");
};
