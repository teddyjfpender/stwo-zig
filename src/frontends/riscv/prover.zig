//! Stable public facade for RISC-V STARK proving and verification.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const stage_profile = @import("stwo_prover_api").stage_profile;
const opcode_memory = @import("air/opcode_memory.zig");
const trace_mod = @import("runner/trace.zig");
const state_chain = @import("runner/state_chain.zig");
const memory_state = @import("runner/memory_state.zig");
const run_result_mod = @import("runner/result.zig");
const orchestration = @import("prover/orchestration.zig");
const types = @import("prover/types.zig");

pub const proof_phase_meter = @import("prover/proof_phase_meter.zig");
pub const guest_precompile = @import("prover/guest_precompile/mod.zig");
pub const main_trace_plan_execution = @import("prover/main_trace_plan_execution.zig");
pub const main_trace_plan_execution_production =
    @import("prover/main_trace_plan_execution_production.zig");
pub const PublicData = types.PublicData;
pub const PublicDataV2 = @import("air/public_data_v2.zig").PublicDataV2;
pub const Hasher = types.Hasher;
pub const FamilyComponentDesc = types.FamilyComponentDesc;
pub const InfraKind = types.InfraKind;
pub const InfraComponentDesc = types.InfraComponentDesc;
pub const RiscVStatement = types.RiscVStatement;
pub const RiscVStatementV2 = types.RiscVStatementV2;
pub const RiscVInteractionClaim = types.RiscVInteractionClaim;
pub const MAX_COMPONENTS = types.MAX_COMPONENTS;
pub const MAX_INFRA_COMPONENTS = types.MAX_INFRA_COMPONENTS;
pub const Proof = types.Proof;
pub const ExtendedProof = types.ExtendedProof;
pub const OwnedRiscVStatement = types.OwnedRiscVStatement;
pub const RelationDiagnostic = types.RelationDiagnostic;
pub const ProveOutput = types.ProveOutput;
pub const ProveOutputV2 = types.ProveOutputV2;
pub const ProverError = types.ProverError;
pub const ExecutionOptions = orchestration.ExecutionOptions;
pub const StatementAdmission = orchestration.StatementAdmission;
pub const StatementAdmissionV2 = orchestration.StatementAdmissionV2;
pub const ExecutionOptionsV2 = orchestration.ExecutionOptionsV2;
pub const assertProverEngine = types.assertProverEngine;
pub const ProverEngineForBackend = types.ProverEngineForBackend;
pub const Poseidon2InteractionClaim = guest_precompile.InteractionClaim;
pub const Poseidon2ProveOutput = guest_precompile.ProveOutput;
pub const provePoseidon2WithEngineAndPublicData =
    guest_precompile.provePoseidon2WithEngineAndPublicData;
pub const provePoseidon2WithEngineAndPublicDataUsingChannel =
    guest_precompile.provePoseidon2WithEngineAndPublicDataUsingChannel;
pub const verifyPoseidon2WithEngine = guest_precompile.verifyPoseidon2WithEngine;
pub const verifyPoseidon2WithEngineUsingChannel =
    guest_precompile.verifyPoseidon2WithEngineUsingChannel;
pub const proveRiscVSegmentV2WithEngine =
    orchestration.runRiscVSegmentV2WithEngine;
pub const proveRiscVSegmentV2WithEngineUsingChannel =
    orchestration.runRiscVSegmentV2WithEngineUsingChannel;
pub const proveRiscVSegmentV2WithEngineUsingChannelAndExecution =
    orchestration.runRiscVSegmentV2WithEngineUsingChannelAndExecution;
/// Explicit protocol-changing entry point for the authenticated, degree-aware
/// physical lookup layout. Ordinary V1 and segment-V2 calls remain on their
/// compatibility transcript and Tree-2 geometry.
pub const proveRiscVSegmentLookupV2WithEngine =
    orchestration.runRiscVSegmentLookupV2WithEngine;
pub const proveRiscVSegmentLookupV2WithEngineUsingChannel =
    orchestration.runRiscVSegmentLookupV2WithEngineUsingChannel;
pub const inspectRiscVSegmentLookupV2FullCohort =
    orchestration.inspectRiscVSegmentLookupV2FullCohort;

/// The one secure PCS profile this repository publishes, and the single source
/// of truth every "secure" selector resolves to: the staged adapter's `.secure`
/// protocol (`src/integrations/riscv_cpu/proof_adapter.zig`) and the benchmark
/// runner's `--secure` flag (`src/tools/riscv/bench/runner.zig`) both return
/// exactly this value rather than restating its numbers.
///
/// Cross-language mirror: `scripts/riscv_csp_benchmark_lib/contract.py` parses
/// *this literal* and refuses to validate a workload manifest when its own
/// `SECURE_PCS_CONFIG` disagrees, so two profiles can no longer both connote
/// "the secure one" while differing (issue #152 item 7). The parser is
/// deliberately dumb: keep one `.field = value,` per line.
pub const SECURE_PCS_CONFIG: pcs_core.PcsConfig = .{
    .pow_bits = 26,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 70,
        .fold_step = 1,
    },
    .lifting_log_size = null,
};

/// Why a completed run must not be handed to the prover.
///
/// One definition, reached from every caller that proves a *run* rather than a
/// hand-built trace: the production ELF adapter
/// (`src/integrations/riscv_cpu/proof_adapter.zig`) and the benchmark runner
/// (`src/tools/riscv/bench/runner.zig`). A fail-closed check present on one path
/// and absent from its sibling is worse than one absent from both, because the
/// passing path lends the other unearned confidence (issue #152 item 5).
pub const RunAdmissionError = error{
    /// The run ended for a reason no statement can bind. Only a halt-flag store
    /// or the canonical `jal x0, 0` sentinel carries a proof-bearing completion;
    /// an ECALL, EBREAK, host halt, step-limit cutoff or undecodable word does
    /// not, and reaches the prover only to fail far downstream.
    UnprovableCompletion,
    /// The committed memory image carries public-I/O words the caller's
    /// `PublicData` will not publish, so the public-I/O LogUp bus cannot cancel
    /// and proving fails much later with `LogupSumNonZero`.
    UnpublishedPublicIo,
};

/// The public I/O a caller's `PublicData` will actually publish.
///
/// Named rather than positional because the two fields are not interchangeable:
/// the input side is a length the statement republishes word by word, the output
/// side is a whole-region yes/no.
pub const PublishedIo = struct {
    /// Bytes of public input the statement publishes.
    input_len: usize,
    /// Whether the statement publishes the guest's output and completion words.
    output: bool,

    /// What the trace-only entrypoint publishes: nothing at all.
    pub const none: PublishedIo = .{ .input_len = 0, .output = false };
};

/// A run the prover must refuse, carrying the evidence that names the cause.
pub const RunAdmissionRejection = union(enum) {
    /// The completion reason the run actually ended with.
    unprovable_completion: run_result_mod.CompletionReason,
    /// Address of the first committed public-I/O word that would go unpublished.
    unpublished_public_io: u32,

    pub fn toError(self: RunAdmissionRejection) RunAdmissionError {
        return switch (self) {
            .unprovable_completion => RunAdmissionError.UnprovableCompletion,
            .unpublished_public_io => RunAdmissionError.UnpublishedPublicIo,
        };
    }
};

/// Rejects every completion reason that carries no proof-bearing completion.
pub fn classifyCompletion(
    reason: run_result_mod.CompletionReason,
) ?RunAdmissionRejection {
    return switch (reason) {
        .halt_flag, .self_loop => null,
        else => .{ .unprovable_completion = reason },
    };
}

/// Rejects a committed memory image whose public-I/O words the statement would
/// not publish.
///
/// Read from the run's own committed words rather than from the declared region:
/// a guest is free to leave its declared input region untouched, and an untouched
/// word emits no consume to leave dangling.
pub fn classifyPublicIo(
    opt_memory: ?*const memory_state.Snapshot,
    published: PublishedIo,
) ?RunAdmissionRejection {
    const memory = opt_memory orelse return null;
    for (memory.words) |word| {
        if (word.final_clock == 0) continue;
        const unpublished_input = word.role.is_public_input and published.input_len == 0;
        const unpublished_output = !published.output and
            (word.role.is_public_output or word.role.is_public_completion);
        if (unpublished_input or unpublished_output)
            return .{ .unpublished_public_io = word.addr };
    }
    return null;
}

/// The shared admission verdict for a completed run whose statement publishes
/// the run's own public I/O.
pub fn classifyRunAdmission(
    run: *const run_result_mod.RunResult,
) ?RunAdmissionRejection {
    if (classifyCompletion(run.completion_reason)) |rejection| return rejection;
    return classifyPublicIo(
        &run.rw_memory,
        .{ .input_len = run.input.len, .output = true },
    );
}

/// Fail closed on any run the prover cannot bind. Every production caller that
/// hands a `RunResult` to the prover calls exactly this.
pub fn admitRunForProving(run: *const run_result_mod.RunResult) RunAdmissionError!void {
    if (classifyRunAdmission(run)) |rejection| return rejection.toError();
}

/// Proves a trace under a statement that publishes **no** public I/O.
///
/// The name states the limitation because the limitation is not recoverable at
/// the call site: this path synthesizes public data with an empty I/O region, so
/// any guest that reads input or writes output cannot balance the public-I/O
/// LogUp bus. It exists for hand-built traces and I/O-free guests only; every
/// other caller wants `proveRiscVWithEngineAndPublicData`, whose public data is
/// a required argument (issue #152 item 1).
pub fn proveRiscVTraceOnlyNoPublicIo(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
) !types.ProveOutputForEngine(Engine) {
    var channel = Engine.Channel{};
    return proveRiscVTraceOnlyNoPublicIoUsingChannel(
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

/// The trace-only path with its live channel exposed to conformance
/// instrumentation. The default entrypoint remains branch-free.
///
/// Ordering note: the public-I/O gate is the very first statement, so a run this
/// path cannot represent is refused before any work is done rather than ~1.2 s
/// later inside the prover. `deriveRegisterBoundary` follows, and it is the
/// first thing that inspects the trace; it runs *ahead* of the opcode admission
/// filter in `prover/statement_geometry.build` (`Trace.groupByOpcodeFamily`) and
/// is therefore the entrypoint's own fail-closed gate for execution-only
/// opcodes, rejecting such a trace with `UnsupportedForProof` rather than
/// letting it reach geometry. Anything inserted before that call which
/// classifies opcodes must be fallible for the same reason.
pub fn proveRiscVTraceOnlyNoPublicIoUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    channel: *Engine.Channel,
) !types.ProveOutputForEngine(Engine) {
    if (classifyPublicIo(opt_memory, PublishedIo.none)) |rejection| return rejection.toError();
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
) !types.ProveOutputForEngine(Engine) {
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

pub fn proveRiscVWithEngineAndPublicDataWithExecution(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: PublicData,
    execution: ExecutionOptions,
) !types.ProveOutputForEngine(Engine) {
    return orchestration.runRiscVWithEngineAndPublicDataWithExecution(
        Engine,
        .prove,
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
) !types.ProveOutputForEngine(Engine) {
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

/// Opt-in exact witness/proving partition for profiled product attempts. The
/// ordinary entrypoint above remains the unmetered production path, and this
/// wrapper does not select a parallel execution policy.
pub fn proveRiscVWithEngineAndPublicDataUsingChannelAndPhaseMeter(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: PublicData,
    channel: *Engine.Channel,
    phase_meter: *proof_phase_meter.Meter,
) !types.ProveOutputForEngine(Engine) {
    return orchestration.runRiscVWithEngineAndPublicDataUsingChannelAndPhaseMeter(
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
        phase_meter,
    );
}

pub fn proveRiscVWithEngineAndPublicDataUsingChannelAndExecution(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: PublicData,
    channel: *Engine.Channel,
    execution: ExecutionOptions,
) !types.ProveOutputForEngine(Engine) {
    return orchestration.runRiscVWithEngineAndPublicDataUsingChannelAndExecution(
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
        execution,
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
pub const verifier_diagnostic_wiring_source = verifier.diagnostic_wiring_source;
pub const QueryCapture = verifier.QueryCapture;
pub const ProofCaptureForEngine = verifier.ProofCaptureForEngine;
pub const RecursiveLeafCaptureForEngine = verifier.RecursiveLeafCaptureForEngine;
pub const VerifiedSegmentV2CaptureForEngine =
    verifier.VerifiedSegmentV2CaptureForEngine;
pub const verifyRiscVWithEngine = verifier.verifyRiscVWithEngine;
pub const verifyRiscVWithEngineUsingChannel = verifier.verifyRiscVWithEngineUsingChannel;
pub const verifyRiscVWithEngineUsingChannelAndQueryCapture =
    verifier.verifyRiscVWithEngineUsingChannelAndQueryCapture;
pub const verifyRiscVWithEngineUsingChannelAndProofCapture =
    verifier.verifyRiscVWithEngineUsingChannelAndProofCapture;
pub const verifyRiscVWithEngineUsingChannelAndRecursiveLeafCapture =
    verifier.verifyRiscVWithEngineUsingChannelAndRecursiveLeafCapture;
pub const verifyRiscVSegmentV2WithEngine =
    verifier.verifyRiscVSegmentV2WithEngine;
pub const verifyRiscVSegmentV2WithEngineUsingChannel =
    verifier.verifyRiscVSegmentV2WithEngineUsingChannel;
pub const verifyRiscVSegmentV2WithEngineUsingChannelAndCapture =
    verifier.verifyRiscVSegmentV2WithEngineUsingChannelAndCapture;
pub const verifyRiscVSegmentLookupV2WithEngine =
    verifier.verifyRiscVSegmentLookupV2WithEngine;
pub const verifyRiscVSegmentLookupV2WithEngineUsingChannel =
    verifier.verifyRiscVSegmentLookupV2WithEngineUsingChannel;
pub const proveAndVerifyElfWithEngine = @import("prover/elf.zig").proveAndVerifyElfWithEngine;
