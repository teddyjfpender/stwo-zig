//! CPU/SIMD integration for the backend-neutral Sail RISC-V frontend.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const pcs_core = @import("stwo_core").pcs;
const prover_mod = frontend.prover_mod;
const public_data_mod = frontend.air.public_data;
const public_data_v2 = frontend.air.public_data_v2;
const guest_statement = frontend.air.guest_precompile.statement;
const artifact_identity = frontend.air.guest_precompile.artifact_identity;
const guest_call_buffer = frontend.runner.guest_precompile.call_buffer;
const guest_runner = frontend.runner.guest_precompile.poseidon2_v1;
const trace_mod = frontend.runner.trace;
const state_chain = frontend.runner.state_chain;
const memory_state = frontend.runner.memory_state;
const runner_result = frontend.runner.result_mod;
const prove_block = frontend.host.prove_block;
const BlockInput = frontend.host.block_input.BlockInput;
const stage_profile = @import("stwo_prover_api").stage_profile;

pub const CpuProverEngine = prover_mod.ProverEngineForBackend(CpuBackend);
pub const Poseidon2ProveOutput = prover_mod.Poseidon2ProveOutput;
pub const Poseidon2InteractionClaim = prover_mod.Poseidon2InteractionClaim;
pub const poseidon2_proof_artifact = prover_mod.guest_precompile.proof_artifact;
pub const recursive_binary_composition_authority = @import("recursive_binary_composition_authority.zig");
pub const recursive_binary_outer = @import("recursive_binary_outer.zig");
pub const recursive_binary_outer_cohort = @import("recursive_binary_outer_cohort.zig");
pub const recursive_binary_verified_publication = @import("recursive_binary_verified_publication.zig");
pub const recursive_fri_outer = @import("recursive_fri_outer.zig");
pub const recursive_segment_v2_leaf_outer = @import("recursive_segment_v2_leaf_outer.zig");
pub const recursive_segment_v2_noncore_owner = @import("recursive_segment_v2_noncore_owner.zig");
pub const recursive_segment_v2_outer_cohort = @import("recursive_segment_v2_outer_cohort.zig");
pub const recursive_segment_v2_outer_admission_v2 = @import("recursive_segment_v2_outer_admission_v2.zig");
pub const recursive_segment_v2_outer_engine = @import("recursive_segment_v2_outer_engine.zig");
pub const recursive_segment_v2_tuple_closure_diagnostic = @import("recursive_segment_v2_tuple_closure_diagnostic.zig");
pub const recursive_segment_v2_verified_artifact = @import("recursive_segment_v2_verified_artifact.zig");
pub const recursive_segment_v2_verified_publication = @import("recursive_segment_v2_verified_publication.zig");
pub const recursive_segment_v2_temporal_child_authority = @import("recursive_segment_v2_temporal_child_authority.zig");
pub const recursive_temporal_pair_authority_v2 = @import("recursive_temporal_pair_authority_v2.zig");
pub const recursive_temporal_nonfri_source_v2 = @import("recursive_temporal_nonfri_source_v2.zig");
pub const recursive_temporal_parent_prefix_runtime = @import("recursive_temporal_parent_prefix_runtime.zig");
pub const recursive_temporal_parent_row35_owner_v1 = @import("recursive_temporal_parent_row35_owner_v1.zig");
pub const recursive_temporal_parent_manifest_v3 = @import("recursive_temporal_parent_manifest_v3.zig");
pub const recursive_temporal_parent_row18_source_v3 = @import("recursive_temporal_parent_row18_source_v3.zig");
pub const recursive_temporal_parent_suffix_v3 = @import("recursive_temporal_parent_suffix_v3.zig");
pub const recursive_temporal_parent_verifier_input_publication_v3 = @import("recursive_temporal_parent_verifier_input_publication_v3.zig");
pub const recursive_temporal_parent_cohort_v3 = @import("recursive_temporal_parent_cohort_v3.zig");
pub const recursive_parent_statement_source = @import("recursive_parent_statement_source.zig");
pub const recursive_parent_statement_air_source = @import("recursive_parent_statement_air_source.zig");
pub const recursive_temporal_child_authority = @import("recursive_temporal_child_authority.zig");

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
    return prover_mod.proveRiscVTraceOnlyNoPublicIo(
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

pub fn proveRiscVWithPublicDataAndExecution(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_mod.PublicData,
    execution: prover_mod.ExecutionOptions,
) !prover_mod.ProveOutput {
    return prover_mod.proveRiscVWithEngineAndPublicDataWithExecution(
        CpuProverEngine,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
        execution,
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

/// Explicit native V2 lane for one resumable execution segment.  Ordinary V1
/// proof and benchmark entrypoints above remain byte-for-byte separate.
pub fn proveRiscVSegmentV2(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    result: *const runner_result.SegmentResult,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
) !prover_mod.ProveOutputV2 {
    return prover_mod.proveRiscVSegmentV2WithEngine(
        CpuProverEngine,
        allocator,
        pcs_config,
        result,
        recorder,
        public_data,
    );
}

pub fn verifyRiscVSegmentV2(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: prover_mod.RiscVStatementV2,
    proof: prover_mod.Proof,
    claim: *const prover_mod.RiscVInteractionClaim,
) !void {
    return prover_mod.verifyRiscVSegmentV2WithEngine(
        CpuProverEngine,
        allocator,
        pcs_config,
        statement,
        proof,
        claim,
    );
}

/// Proves one extension-profile execution with its caller and provider
/// components in the same CPU-backed STARK.
pub fn provePoseidon2WithPublicData(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    calls: *const guest_call_buffer.Frozen,
    execution_rows: *const guest_runner.FrozenExecutionRows,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_mod.PublicData,
) !Poseidon2ProveOutput {
    return prover_mod.provePoseidon2WithEngineAndPublicData(
        CpuProverEngine,
        allocator,
        pcs_config,
        exec_trace,
        calls,
        execution_rows,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
    );
}

/// Independently reconstructs and verifies the extension-profile transcript.
/// The proof is consumed on every return path.
pub fn verifyPoseidon2(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: prover_mod.RiscVStatement,
    extension: guest_statement.ExtensionStatement,
    artifact: artifact_identity.Identity,
    proof: prover_mod.Proof,
    claim: *const Poseidon2InteractionClaim,
) !void {
    return prover_mod.verifyPoseidon2WithEngine(
        CpuProverEngine,
        allocator,
        pcs_config,
        statement,
        extension,
        artifact,
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
    _ = @import("guest_precompile_proof_test.zig");
    _ = @import("split_pcs_prepare_test.zig");
}
