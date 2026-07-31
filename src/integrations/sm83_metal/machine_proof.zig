//! Metal adapter and proof gate for complete SM83 machine steps.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const frontend = @import("stwo_sm83_frontend");
const MetalProverEngine = @import("stwo_metal_backend").MetalProverEngine;

pub const ProveOutput = frontend.prover.ProveOutput;

pub fn proveExecution(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: frontend.Rom,
    initial_memory: frontend.MemoryImage,
    final_memory: frontend.MemoryImage,
    steps: []const frontend.MachineStepResult,
) !ProveOutput {
    return frontend.prover.proveMachineExecutionWithEngine(
        MetalProverEngine,
        allocator,
        pcs_config,
        rom,
        initial_memory,
        final_memory,
        steps,
    );
}
