//! CPU/SIMD integration for the backend-neutral Sail RISC-V frontend.

pub const rv64_poseidon2_outer = @import("poseidon2_outer/mod.zig");
pub const rv64_outer_mle_point = @import("logup_gkr/mle_point.zig");
pub const rv64_outer_hybrid_device = @import("outer_gkr/hybrid_device.zig");
pub const rv64_outer_hybrid_air = @import("outer_gkr/hybrid_air.zig");
pub const rv64_outer_hybrid_receiver = @import("outer_gkr/hybrid_receiver.zig");
pub const rv64_outer_hybrid_wire = @import("outer_gkr/hybrid_wire.zig");
pub const rv64_outer_hybrid_child = @import("outer_gkr/child_verifier.zig");
pub const rv64_outer_gkr_profile = @import("outer_gkr/profile.zig");
pub const rv64_outer_gkr_section = @import("outer_gkr/section.zig");
pub const rv64_outer_gkr_binding = @import("outer_gkr/binding.zig");
pub const rv64_services_roster = @import("word16_global_execution/services/roster.zig");
pub const rv64_services_types = @import("word16_global_execution/services/types.zig");
pub const rv64_services_pipeline = @import("word16_global_execution/services/pipeline.zig");
pub const rv64_device_core_headers = @import("word16_execution/device_headers.zig");
pub const rv64_provider_tails = @import("word16_execution/provider_tails.zig");
pub const rv64_memory_input = @import("word16_execution/memory_input.zig");
pub const rv64_family_input = @import("word16_execution/family_input.zig");
pub const rv64_device_main = @import("word16_global_execution/services/device_main.zig");
pub const rv64_device_source_stage = @import("word16_global_execution/services/pipeline.zig").DeviceSourceStage;
const std = @import("std");
pub const rv64_gkr_truth_products = @import("word16_global_execution/services/gkr_local/truth_classic.zig").products;
pub const rv64_gkr_truth_device_source = @import("word16_global_execution/services/gkr_local/truth_device_source.zig");
pub const rv64_gkr_truth_device_composition = @import("word16_global_execution/services/gkr_local/truth_device_composition.zig");
pub const rv64_device_pcs = @import("stwo_prover_api").device_pcs;
pub const rv64_cpu_source = @import("word16_execution/cpu_source.zig");
pub const rv64_gkr_child = @import("word16_global_execution/services/gkr_local/child.zig");
pub const rv64_gkr_cpu_replay = @import("word16_global_execution/services/gkr_local/cpu_replay.zig");
pub const rv64_gkr_native_provider = @import("word16_global_execution/services/gkr_local/native_provider.zig");
pub const rv64_ethereum_gkr_main = @import("word16_global_execution/ethereum/gkr_main.zig");
pub const rv64_gkr_truth_v3_role = @import("word16_global_execution/services/gkr_local/truth_v3_role.zig");
pub const rv64_gkr_truth_v3_catalog = @import("word16_global_execution/services/gkr_local/truth_v3_catalog.zig");
pub const rv64_gkr_truth_role = @import("word16_global_execution/services/gkr_local/truth_role.zig");
pub const rv64_native_gkr_truth = @import("word16_global_execution/services/native_gkr/truth_authority.zig");
pub const rv64_native_gkr_roster = @import("word16_global_execution/services/native_gkr/native_roster.zig");
pub const rv64_native_gkr_cpu = @import("word16_global_execution/services/native_gkr/cpu_component.zig");
pub const rv64_native_gkr_section = @import("word16_global_execution/services/native_gkr/section.zig");
pub const rv64_native_gkr_v2 = @import("word16_global_execution/services/native_gkr/v2.zig");
pub const rv64_gkr_constraints = @import("word16_global_execution/services/gkr_local/constraint_authority.zig");
pub const rv64_gkr_source = @import("word16_global_execution/services/gkr_local/source_authority.zig");
pub const rv64_gkr_cpu_components = @import("word16_global_execution/services/gkr_local/cpu_components.zig");
pub const rv64_gkr_cpu_worker = @import("word16_global_execution/services/gkr_local/cpu_worker.zig");
pub const rv64_gkr_manifest = @import("word16_global_execution/services/gkr_local/manifest.zig");
pub const rv64_gkr_manifest_wire = @import("word16_global_execution/services/gkr_local/manifest_wire.zig");
pub const rv64_gkr_receipt = @import("word16_global_execution/services/gkr_local/receipt.zig");
pub const rv64_gkr_wire = @import("word16_global_execution/services/gkr_local/wire.zig");
/// Native chain policy / version identity (M8 GPU-native device seal: the
/// chi chain IV is chainIv(versionIdentity(version)), a host constant).
pub const rv64_gkr_chain = @import("word16_global_execution/services/gkr_local/chain.zig");
/// Global RAM/KIO/Wire claim layout per origin (claimCount / claimsFromVector):
/// the authority of the Stage2 claims buffer layout (M8 jobs/native_claims.zig).
pub const rv64_gkr_global_cpu = @import("word16_global_execution/services/gkr_local/global_cpu.zig");
pub const rv64_gkr_worker_protocol = @import("word16_global_execution/services/gkr_local/worker_protocol.zig");
/// M8 GPU-native request driver (riscv_cuda rv64/jobs/driver_ge.zig): the
/// direct capture with a per-segment readiness hook, run outside the legacy
/// gkr_main pipeline. Exports only; no behaviour change.
pub const rv64_ethereum_request = @import("rv64_ethereum_request.zig");
pub const rv64_expected_image = @import("word16_execution/expected_image.zig");
pub const rv64_program = @import("word16_execution/program.zig");
pub const rv64_program_metadata = @import("word16_execution/program_metadata.zig");
pub const rv64_ethereum_direct = @import("word16_global_execution/ethereum/direct.zig");
pub const rv64_ethereum_capture = @import("word16_global_execution/ethereum/capture.zig");
pub const rv64_ethereum_receiver = @import("word16_global_execution/ethereum/receiver.zig");
pub const rv64_services_collector = @import("word16_global_execution/services/collector.zig");
pub const rv64_replay_capture = @import("word16_execution/replay_capture.zig");
pub const rv64_ethereum_capture_options = @import("word16_global_execution/ethereum/capture_options.zig");
pub const rv64_ethereum_plan = @import("word16_global_execution/ethereum/plan.zig");
/// M8 GPU-native install-time class builder (riscv_cuda rv64/jobs/
/// native_class_build.zig, stream gn-shape): the warm capture's setup, FIXED
/// authority and per-segment request views, built exactly as gkr_main's
/// inventory does. Exports only; no behaviour change.
pub const rv64_ethereum_keys = @import("word16_global_execution/ethereum/keys.zig");
pub const rv64_ethereum_canon_rungs = @import("word16_global_execution/ethereum/canon_native_rungs.zig");
pub const rv64_gkr_coordinator = @import("word16_global_execution/services/gkr_local/coordinator.zig");
pub const rv64_gkr_bundle_wire = @import("word16_global_execution/services/gkr_local/bundle_wire.zig");
pub const rv64_gkr_source_bounds = @import("word16_global_execution/services/gkr_local/source_bounds.zig");
pub const rv64_ethereum_terminal = @import("word16_global_execution/ethereum/terminal.zig");
pub const rv64_gkr_execution = @import("word16_global_execution/services/gkr_local/execution.zig");
pub const rv64_gkr_fixed_authority = @import("word16_global_execution/services/gkr_local/fixed_authority.zig");
pub const rv64_gkr_fixed_authority_set = @import("word16_global_execution/services/gkr_local/fixed_authority_set.zig");
pub const rv64_gkr_local_roster = @import("word16_global_execution/services/gkr_local/roster.zig");
pub const rv64_services_protocol = @import("word16_global_execution/services/protocol.zig");
pub const rv64_native_policy = @import("word16_execution/native_policy.zig");
pub const rv64_pcs_suite = @import("word16_execution/pcs_suite.zig");
pub const rv64_om31_security_candidate = @import("word16_execution/om31_security_candidate.zig");
pub const rv64 = @import("rv64.zig");
pub const rv64_full = @import("rv64_full.zig");
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
const stage_profile = @import("stwo_prover_api").stage_profile;

pub const Blake3Execution = prover_mod.blake3_execution.ForBackend(CpuBackend);
pub const CpuProverEngine = prover_mod.ProverEngineForBackend(CpuBackend);
pub const Poseidon2ProveOutput = prover_mod.Poseidon2ProveOutput;
pub const Poseidon2InteractionClaim = prover_mod.Poseidon2InteractionClaim;
pub const poseidon2_proof_artifact = prover_mod.guest_precompile.proof_artifact;
pub const ethereum_proof_artifact = prover_mod.guest_precompile.ethereum_proof_artifact;
pub const resource_usage = @import("stwo_prover_engine").measurement.resource_report;
/// The qualified CSP recursion producer shares this generic outer verifier.
pub const recursive_fri_outer = @import("recursive_fri_outer.zig");

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

test {
    std.testing.refAllDecls(@This());
    // Internal detached modules remain in the test inventory without widening the API.
    _ = @import("recursive_segment_v2_detached_boundary.zig");
    _ = @import("recursive_segment_v2_detached_child_transcript.zig");
    _ = @import("recursive_segment_v2_detached_composition.zig");
    _ = @import("recursive_segment_v2_detached_parent_statement.zig");
    _ = @import("recursive_segment_v2_detached_pcs_rows.zig");
    _ = @import("recursive_segment_v2_detached_prefix.zig");
    _ = @import("recursive_segment_v2_detached_transcript.zig");
    _ = @import("recursive_segment_v2_public_inputs.zig");
    _ = @import("recursive_segment_v2_verifier_components.zig");

    _ = @import("guest_precompile_proof_test.zig");
    _ = @import("split_pcs_prepare_test.zig");
}

pub const rv64_om31_outer = @import("rv64_recursion/om31_outer.zig");
pub const rv64_om31_outer_wrap = @import("rv64_recursion/om31_native/outer_wrap.zig");
pub const rv64_om31_cpu_leaf = @import("rv64_recursion/om31_native/cpu_leaf.zig");
pub const rv64_om31_services_root = @import("rv64_recursion/om31_native/services_root.zig");
pub const rv64_om31_ready_dag = @import("rv64_recursion/om31_native/ready_dag.zig");
pub const rv64_om31_typed_fold = @import("rv64_recursion/om31_native/typed_fold.zig");
pub const rv64_om31_typed_summary = @import("rv64_recursion/om31_native/node_summary_v3.zig");
pub const rv64_vk_table = @import("rv64_recursion/vk_table.zig");

pub const rv64_om31_execution_wrap = @import("rv64_recursion/om31_native/execution_wrap.zig");
pub const rv64_root_verify = @import("rv64_recursion/root_verify.zig");
pub const rv64_root_verify_main = @import("rv64_recursion/root_verify_main.zig");

/// Exact production allocator adapter, also used by ready-lane budget admission.
pub const rv64_large_block_recycler = @import("rv64_large_block_recycler.zig");
pub const rv64_recursion_budget = @import("rv64_recursion_budget.zig");
