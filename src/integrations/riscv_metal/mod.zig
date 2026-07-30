//! Metal integration for the backend-neutral RV32IM frontend.
//!
//! Witness generation and AIR ownership remain in the frontend. This module
//! selects the fail-closed Metal commitment engine; it never substitutes the
//! CPU commitment backend when Metal initialization or execution fails.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const MetalProverEngineImpl = @import("stwo_metal_backend").MetalProverEngine;
const riscv = @import("stwo_riscv_frontend");
const prover_mod = riscv.prover_mod;
const public_data_mod = riscv.air.public_data;
const trace_mod = riscv.runner.trace;
const state_chain = riscv.runner.state_chain;
const memory_state = riscv.runner.memory_state;
const stage_profile = @import("stwo_prover_api").stage_profile;

pub const MetalProverEngine = MetalProverEngineImpl;

comptime {
    prover_mod.assertProverEngine(MetalProverEngine);
}

pub fn proveRiscV(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
) !prover_mod.ProveOutput {
    return proveRiscVWithRecorder(
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        opt_memory,
        null,
    );
}

pub fn proveRiscVWithRecorder(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
) !prover_mod.ProveOutput {
    return prover_mod.proveRiscVTraceOnlyNoPublicIo(
        MetalProverEngine,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        opt_memory,
        recorder,
    );
}

pub fn proveRiscVWithPublicData(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_mod.PublicData,
) !prover_mod.ProveOutput {
    return prover_mod.proveRiscVWithEngineAndPublicData(
        MetalProverEngine,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
    );
}

pub fn verifyRiscV(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: prover_mod.RiscVStatement,
    proof: prover_mod.Proof,
    claim: *const prover_mod.RiscVInteractionClaim,
) !void {
    return prover_mod.verifyRiscVWithEngine(
        MetalProverEngine,
        allocator,
        pcs_config,
        statement,
        proof,
        claim,
    );
}

pub fn proveAndVerifyElf(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    max_steps: usize,
    pcs_config: pcs_core.PcsConfig,
) !prover_mod.OwnedRiscVStatement {
    return prover_mod.proveAndVerifyElfWithEngine(
        MetalProverEngine,
        allocator,
        elf_bytes,
        max_steps,
        pcs_config,
    );
}

test "RISC-V Metal engine satisfies the shared prover transaction contract" {
    comptime prover_mod.assertProverEngine(MetalProverEngine);
    std.testing.refAllDecls(MetalProverEngine);
}

test "api invariant: RISC-V Metal integration cannot select the CPU backend" {
    try std.testing.expect(
        MetalProverEngine.Backend == @import("stwo_metal_backend").MetalCommitBackend,
    );
}
