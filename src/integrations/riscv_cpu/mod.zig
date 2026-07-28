//! CPU/SIMD integration for the backend-neutral Sail RISC-V frontend.

const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const pcs_core = @import("stwo_core").pcs;
const prover_mod = @import("stwo_riscv_frontend").prover_mod;
const public_data_mod = @import("stwo_riscv_frontend").air.public_data;
const trace_mod = @import("stwo_riscv_frontend").runner.trace;
const state_chain = @import("stwo_riscv_frontend").runner.state_chain;
const memory_state = @import("stwo_riscv_frontend").runner.memory_state;
const prove_block = @import("stwo_riscv_frontend").host.prove_block;
const BlockInput = @import("stwo_riscv_frontend").host.block_input.BlockInput;
const stage_profile = @import("stwo_prover_api").stage_profile;

pub const CpuProverEngine = prover_mod.ProverEngineForBackend(CpuBackend);

comptime {
    prover_mod.assertProverEngine(CpuProverEngine);
}

test "api signature: RISC-V CPU engine satisfies the stable transaction contract" {
    comptime @import("stwo_prover_api").assertProverEngine(CpuProverEngine);
}

test "api invariant: RISC-V CPU integration selects only the CPU backend" {
    try std.testing.expect(CpuProverEngine.Backend == CpuBackend);
}

pub fn proveRiscV(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
) !prover_mod.ProveOutput {
    return proveRiscVWithRecorder(allocator, pcs_config, exec_trace, opt_chain, opt_memory, null);
}

pub fn proveRiscVWithRecorder(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
) !prover_mod.ProveOutput {
    return prover_mod.proveRiscVWithEngine(
        CpuProverEngine,
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
        CpuProverEngine,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
    );
}

pub fn diagnoseRiscVRelations(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    public_data: public_data_mod.PublicData,
) !prover_mod.RelationDiagnostic {
    return prover_mod.diagnoseRiscVRelationsWithEngineAndPublicData(
        CpuProverEngine,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        opt_memory,
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
        CpuProverEngine,
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
        CpuProverEngine,
        allocator,
        elf_bytes,
        max_steps,
        pcs_config,
    );
}

pub fn proveEthereumBlock(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    block_input: *const BlockInput,
    pcs_config: pcs_core.PcsConfig,
    max_steps: usize,
) !prove_block.ProveBlockResult {
    return prove_block.proveEthereumBlockWithEngine(
        CpuProverEngine,
        allocator,
        elf_bytes,
        block_input,
        pcs_config,
        max_steps,
    );
}

test {
    std.testing.refAllDecls(@This());
}
