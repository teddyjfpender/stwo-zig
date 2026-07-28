//! Stable public facade for RISC-V STARK proving and verification.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const stage_profile = @import("stwo_prover_api").stage_profile;
const opcode_memory = @import("air/opcode_memory.zig");
const trace_mod = @import("runner/trace.zig");
const state_chain = @import("runner/state_chain.zig");
const memory_state = @import("runner/memory_state.zig");
const orchestration = @import("prover/orchestration.zig");
const types = @import("prover/types.zig");

pub const PublicData = types.PublicData;
pub const Hasher = types.Hasher;
pub const FamilyComponentDesc = types.FamilyComponentDesc;
pub const InfraKind = types.InfraKind;
pub const InfraComponentDesc = types.InfraComponentDesc;
pub const RiscVStatement = types.RiscVStatement;
pub const RiscVInteractionClaim = types.RiscVInteractionClaim;
pub const MAX_COMPONENTS = types.MAX_COMPONENTS;
pub const MAX_INFRA_COMPONENTS = types.MAX_INFRA_COMPONENTS;
pub const Proof = types.Proof;
pub const ExtendedProof = types.ExtendedProof;
pub const OwnedRiscVStatement = types.OwnedRiscVStatement;
pub const RelationDiagnostic = types.RelationDiagnostic;
pub const ProveOutput = types.ProveOutput;
pub const ProverError = types.ProverError;
pub const assertProverEngine = types.assertProverEngine;
pub const ProverEngineForBackend = types.ProverEngineForBackend;

/// Proves through the transaction-level engine selected by the caller.
pub fn proveRiscVWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
) !ProveOutput {
    var channel = Engine.Channel{};
    return proveRiscVWithEngineUsingChannel(
        Engine,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        opt_memory,
        recorder,
        &channel,
    );
}

/// Proves through the normal frontend path while exposing its live channel to
/// conformance instrumentation. The default entrypoint remains branch-free.
pub fn proveRiscVWithEngineUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    channel: *Engine.Channel,
) !ProveOutput {
    const register_boundary = try opcode_memory.deriveRegisterBoundary(exec_trace.rows.items);
    if (opt_chain) |chain| {
        if (!std.mem.eql(u32, &register_boundary.last_clock, &chain.reg_last_clk))
            return ProverError.InvalidStatement;
    }
    return proveRiscVWithEngineAndPublicDataUsingChannel(
        Engine,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        opt_memory,
        recorder,
        .{
            .initial_pc = exec_trace.initial_pc,
            .final_pc = exec_trace.final_pc,
            .clock = @intCast(exec_trace.step_count),
            .initial_regs = register_boundary.initial,
            .final_regs = register_boundary.final,
            .reg_last_clock = register_boundary.last_clock,
            .program_root = null,
            .initial_rw_root = null,
            .final_rw_root = null,
            .io_entries = .{
                .input_start = 0,
                .input_len = 0,
                .input_words = &.{},
                .output_len = 0,
                .output_len_addr = 0,
                .output_data_addr = 0,
                .output_words = &.{},
            },
        },
        channel,
    );
}

pub fn proveRiscVWithEngineAndPublicData(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: PublicData,
) !ProveOutput {
    var channel = Engine.Channel{};
    return proveRiscVWithEngineAndPublicDataUsingChannel(
        Engine,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
        &channel,
    );
}

pub fn proveRiscVWithEngineAndPublicDataUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: PublicData,
    channel: *Engine.Channel,
) !ProveOutput {
    return orchestration.runRiscVWithEngineAndPublicDataUsingChannel(
        Engine,
        .prove,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
        channel,
        null,
        null,
    );
}

/// Generates CP-11 evidence through the production witness and interaction path.
pub fn diagnoseRiscVRelationsWithEngineAndPublicData(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    public_data: PublicData,
) !RelationDiagnostic {
    return orchestration.runRiscVWithEngineAndPublicData(
        Engine,
        .relation_diagnostic,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        opt_memory,
        null,
        public_data,
    );
}

const verifier = @import("prover/verifier.zig");
pub const verifyRiscVWithEngine = verifier.verifyRiscVWithEngine;
pub const verifyRiscVWithEngineUsingChannel = verifier.verifyRiscVWithEngineUsingChannel;
pub const proveAndVerifyElfWithEngine = @import("prover/elf.zig").proveAndVerifyElfWithEngine;
