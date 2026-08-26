//! RISC-V STARK proving orchestration.
//!
//! Proves execution of a RISC-V RV32IM program by:
//! 1. Running the program (ELF) to produce an execution trace
//! 2. Splitting the trace by opcode family
//! 3. Creating per-family components, each at its own log_size
//! 4. Committing and proving via the stwo STARK backend
//! 5. Verification of the produced proof
//!
//! ## Architecture
//!
//! Instead of one monolithic component with all trace rows, the trace is split
//! by opcode family. Each active family gets its own component with its own
//! `log_size = ceil(log2(count))`. This gives smaller FFTs per-component and
//! better cache behavior.
//!
//! ## Stages
//!
//! `proveStages` owns nothing but sequencing. Each stage lives in the module
//! named after the artefact it owns, and the order below is protocol order --
//! a transcript is a total order over these calls, so moving one is a different
//! proof even when every witness value is identical:
//!
//! | stage | module |
//! |-------|--------|
//! | commitment witness (memory, program, Merkle, Poseidon2) | `commitment_witness.zig` |
//! | statement and shard geometry | `statement_geometry.zig` |
//! | tree 0: preprocessed columns | `preprocessed.zig` |
//! | tree 1: main trace | `main_trace.zig` |
//! | claim phase and tree 2: interactions | `interaction_trace.zig` |
//! | components and proof assembly | `proof_finalize.zig` |
//!
//! ## Storage
//!
//! Every protocol-capacity-sized value -- statement, opcode column buffers,
//! interaction scratch, prover components borrowed by `core` -- lives in one
//! heap `ProofWorkspace` per proof (see `proof_workspace.zig`). `proveStages`
//! returns `!void` and publishes through an out-pointer so the large proof
//! output costs one frame slot at the boundary instead of one per
//! error-propagation site inside the stages.
//!
//! ## Usage
//! ```zig
//! const result = try proveRiscVWithEngineAndPublicData(
//!     Engine, allocator, config, &exec_trace, &state_chain, &rw_memory, null, public_data,
//! );
//! try verifyRiscVWithEngine(Engine, allocator, config, result.statement, result.proof, result.interaction_claim);
//! ```

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const prover_engine = @import("stwo_prover_engine").engine;
const work_pool = @import("stwo_prover_engine").work_pool;
const prover_api = @import("stwo_prover_api");
const stage_profile = @import("stwo_prover_api").stage_profile;
const lookup_physical_v2 = @import("../air/lang/lookup_physical_manifest_v2.zig");
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const public_data_v2 = @import("../air/public_data_v2.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const trace_mod = @import("../runner/trace.zig");
const memory_state = @import("../runner/memory_state.zig");
const runner_result = @import("../runner/result.zig");
const state_chain = @import("../runner/state_chain.zig");
const commitment_witness = @import("commitment_witness.zig");
const interaction_trace = @import("interaction_trace.zig");
const main_trace = @import("main_trace.zig");
const preprocessed_trace = @import("preprocessed.zig");
const proof_finalize = @import("proof_finalize.zig");
const proof_phase_meter = @import("proof_phase_meter.zig");
const poseidon_witness_work = @import("poseidon_witness_work.zig");
const proof_workspace = @import("proof_workspace.zig");
const relation_diagnostic = @import("relation_diagnostic.zig");
const statement_geometry = @import("statement_geometry.zig");
const statement_validation = @import("statement_validation.zig");
const test_trace_dump = @import("test_trace_dump.zig");
const test_witness_hook = @import("test_witness_hook.zig");
const types = @import("types.zig");

const CommitmentWitness = commitment_witness.CommitmentWitness;
const Geometry = statement_geometry.Geometry;
const ProofWorkspace = proof_workspace.ProofWorkspace;
const PublicData = types.PublicData;
const ProverError = types.ProverError;
const RiscVInteractionClaim = types.RiscVInteractionClaim;
const RiscVStatement = types.RiscVStatement;
const RunMode = types.RunMode;
const RunOutputForEngine = types.RunOutputForEngine;
const ProveOutputV2ForEngine = types.ProveOutputV2ForEngine;

pub const TestWitnessMutation = test_witness_hook.Mutation;
pub const TestTraceDump = test_trace_dump.Capture;

/// Proof-local, fail-closed statement admission invoked after the production
/// statement has been derived but before transcript binding or any trace-tree
/// construction. The opaque context lets product boundaries compare a
/// statement with sealed request metadata without rebuilding its commitment
/// witness solely for preflight.
pub const StatementAdmission = struct {
    context: *anyopaque,
    admit_fn: *const fn (*anyopaque, *const RiscVStatement) anyerror!void,

    pub fn admit(self: StatementAdmission, statement: *const RiscVStatement) !void {
        try self.admit_fn(self.context, statement);
    }
};

pub const StatementAdmissionV2 = struct {
    context: *anyopaque,
    admit_fn: *const fn (*anyopaque, *const statement_v2.RiscVStatementV2) anyerror!void,

    pub fn admit(
        self: StatementAdmissionV2,
        statement: *const statement_v2.RiscVStatementV2,
    ) !void {
        try self.admit_fn(self.context, statement);
    }
};

/// One value-only CPU resource request shared by every migrated proving stage.
/// A null request keeps the predecessor scheduling path. An explicit request
/// owns one proof-scoped pool shared by Tree 1, Tree 2, quotient composition,
/// and commitment openings, so nested executors cannot invent independent
/// worker budgets.
pub const ExecutionOptions = struct {
    cpu: ?prover_api.CpuCompositionExecutionRequest = null,
    /// Optional product policy over the exact derived statement. Rejection
    /// occurs before Fiat-Shamir state or trace commitments are mutated.
    statement_admission: ?StatementAdmission = null,
};

pub const ExecutionOptionsV2 = struct {
    cpu: ?prover_api.CpuCompositionExecutionRequest = null,
    statement_admission: ?StatementAdmissionV2 = null,
};

pub const LookupLayoutV2 = enum {
    compatibility,
    authenticated_physical_v2,
};

/// Stable-address owner for the one CPU worker pool shared by a proving
/// transaction. The CPU request remains value-only; the scoped binding lets
/// later prover stages resolve this exact pool without threading an executor
/// implementation pointer through the public engine API.
pub const ProofExecutionPool = struct {
    pool: work_pool.WorkPool = undefined,
    binding: work_pool.ScopedPoolBinding = undefined,
    pool_initialized: bool = false,
    binding_initialized: bool = false,

    /// Initializes in final storage because `WorkPool` workers retain its
    /// address. Returning an initialized owner by value would be a use-after-
    /// move bug, hence the explicit in-place contract.
    pub fn initInPlace(
        self: *ProofExecutionPool,
        allocator: std.mem.Allocator,
        request: ?prover_api.CpuCompositionExecutionRequest,
    ) !void {
        self.* = .{};
        const explicit = request orelse return;
        _ = try work_pool.WorkerBudget.init(explicit.worker_count);
        if (explicit.worker_count == 1) return;

        try self.pool.initInPlaceWithOptions(.{
            .worker_count = explicit.worker_count,
            .stack_size = work_pool.WORKER_STACK_SIZE,
            .backing_allocator = allocator,
        });
        self.pool_initialized = true;
        errdefer {
            self.pool.deinit();
            self.pool_initialized = false;
        }

        self.binding = try work_pool.ScopedPoolBinding.init(&self.pool);
        self.binding_initialized = true;
    }

    pub fn deinit(self: *ProofExecutionPool) void {
        if (self.binding_initialized) {
            self.binding.deinit();
            self.binding_initialized = false;
        }
        if (self.pool_initialized) {
            self.pool.deinit();
            self.pool_initialized = false;
        }
    }

    pub fn get(self: *ProofExecutionPool) ?*work_pool.WorkPool {
        return if (self.pool_initialized) &self.pool else null;
    }
};

pub fn runRiscVWithEngineAndPublicData(
    comptime Engine: type,
    comptime mode: RunMode,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: PublicData,
) !RunOutputForEngine(Engine, mode) {
    var channel = Engine.Channel{};
    return runRiscVWithEngineAndPublicDataUsingChannel(
        Engine,
        mode,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
        &channel,
        null,
        null,
    );
}

pub fn runRiscVWithEngineAndPublicDataWithExecution(
    comptime Engine: type,
    comptime mode: RunMode,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: PublicData,
    execution: ExecutionOptions,
) !RunOutputForEngine(Engine, mode) {
    var channel = Engine.Channel{};
    return runRiscVWithEngineAndPublicDataUsingChannelAndExecution(
        Engine,
        mode,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
        &channel,
        null,
        null,
        execution,
    );
}

/// Runs the production proving transaction against a caller-owned channel.
///
/// The ordinary entrypoint above instantiates `Engine.Channel` directly. This
/// substitution point lets conformance tests observe the exact production
/// transcript without replaying statement or commitment events.
///
/// Owns the per-proof workspace: one allocation, released on every exit path.
/// The returned output copies workspace-resident results so it outlives
/// `destroy`; the boxed interaction claim is **transferred** to the caller.
pub fn runRiscVWithEngineAndPublicDataUsingChannel(
    comptime Engine: type,
    comptime mode: RunMode,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: PublicData,
    channel: *Engine.Channel,
    test_mutation: ?TestWitnessMutation,
    test_dump: ?*TestTraceDump,
) !RunOutputForEngine(Engine, mode) {
    return runRiscVWithEngineAndPublicDataUsingChannelAndExecution(
        Engine,
        mode,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
        channel,
        test_mutation,
        test_dump,
        .{},
    );
}

pub fn runRiscVWithEngineAndPublicDataUsingChannelAndExecution(
    comptime Engine: type,
    comptime mode: RunMode,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: PublicData,
    channel: *Engine.Channel,
    test_mutation: ?TestWitnessMutation,
    test_dump: ?*TestTraceDump,
    execution: ExecutionOptions,
) !RunOutputForEngine(Engine, mode) {
    return runRiscVWithEngineAndPublicDataUsingChannelWithControls(
        Engine,
        mode,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
        channel,
        test_mutation,
        test_dump,
        execution,
        null,
    );
}

/// Opt-in measurement boundary for a production proof. Scheduling remains the
/// ordinary predecessor policy; the borrowed meter observes only the five
/// non-overlapping witness-materialization regions and owns no proof state.
pub fn runRiscVWithEngineAndPublicDataUsingChannelAndPhaseMeter(
    comptime Engine: type,
    comptime mode: RunMode,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: PublicData,
    channel: *Engine.Channel,
    phase_meter: *proof_phase_meter.Meter,
) !RunOutputForEngine(Engine, mode) {
    return runRiscVWithEngineAndPublicDataUsingChannelWithControls(
        Engine,
        mode,
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
        .{},
        phase_meter,
    );
}

fn runRiscVWithEngineAndPublicDataUsingChannelWithControls(
    comptime Engine: type,
    comptime mode: RunMode,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    opt_memory: ?*const memory_state.Snapshot,
    recorder: ?*stage_profile.Recorder,
    public_data: PublicData,
    channel: *Engine.Channel,
    test_mutation: ?TestWitnessMutation,
    test_dump: ?*TestTraceDump,
    execution: ExecutionOptions,
    phase_meter: ?*proof_phase_meter.Meter,
) !RunOutputForEngine(Engine, mode) {
    comptime @import("stwo_prover_api").assertProverEngine(Engine);
    const workspace = try ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);

    var output: RunOutputForEngine(Engine, mode) = undefined;
    try proveStages(
        Engine,
        mode,
        workspace,
        &output,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        opt_memory,
        recorder,
        public_data,
        channel,
        test_mutation,
        test_dump,
        execution,
        phase_meter,
    );
    return output;
}

/// Proves one authenticated resumable runner segment under the V2 transcript.
/// This entrypoint is deliberately separate from every V1 wrapper: selecting
/// V2 is a compile-time call-site decision and adds no branch to legacy proof
/// or benchmark transactions.
pub fn runRiscVSegmentV2WithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    result: *const runner_result.SegmentResult,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
) !ProveOutputV2ForEngine(Engine) {
    var transcript_channel = Engine.Channel{};
    return runRiscVSegmentV2WithEngineUsingChannelAndExecution(
        Engine,
        allocator,
        pcs_config,
        result,
        recorder,
        public_data,
        &transcript_channel,
        .{},
    );
}

pub fn runRiscVSegmentV2WithEngineUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    result: *const runner_result.SegmentResult,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
    transcript_channel: *Engine.Channel,
) !ProveOutputV2ForEngine(Engine) {
    return runRiscVSegmentV2WithEngineUsingChannelAndExecution(
        Engine,
        allocator,
        pcs_config,
        result,
        recorder,
        public_data,
        transcript_channel,
        .{},
    );
}

pub fn runRiscVSegmentV2WithEngineUsingChannelAndExecution(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    result: *const runner_result.SegmentResult,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
    transcript_channel: *Engine.Channel,
    execution: ExecutionOptionsV2,
) !ProveOutputV2ForEngine(Engine) {
    return runRiscVSegmentV2WithEngineUsingChannelAndExecutionLayout(
        Engine,
        .authenticated_physical_v2,
        allocator,
        pcs_config,
        result,
        recorder,
        public_data,
        transcript_channel,
        execution,
    );
}

/// Retained V1 lookup-layout compatibility route. New SegmentV2 proofs use the
/// authenticated selected layout by default; callers replaying old artifacts
/// must choose this symbol explicitly.
pub fn runRiscVSegmentLookupV1CompatibilityWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    result: *const runner_result.SegmentResult,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
) !ProveOutputV2ForEngine(Engine) {
    var transcript_channel = Engine.Channel{};
    return runRiscVSegmentLookupV1CompatibilityWithEngineUsingChannel(
        Engine,
        allocator,
        pcs_config,
        result,
        recorder,
        public_data,
        &transcript_channel,
    );
}

pub fn runRiscVSegmentLookupV1CompatibilityWithEngineUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    result: *const runner_result.SegmentResult,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
    transcript_channel: *Engine.Channel,
) !ProveOutputV2ForEngine(Engine) {
    return runRiscVSegmentV2WithEngineUsingChannelAndExecutionLayout(
        Engine,
        .compatibility,
        allocator,
        pcs_config,
        result,
        recorder,
        public_data,
        transcript_channel,
        .{},
    );
}

/// Explicit spelling of the default selected-lookup protocol.
pub fn runRiscVSegmentLookupV2WithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    result: *const runner_result.SegmentResult,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
) !ProveOutputV2ForEngine(Engine) {
    var transcript_channel = Engine.Channel{};
    return runRiscVSegmentLookupV2WithEngineUsingChannel(
        Engine,
        allocator,
        pcs_config,
        result,
        recorder,
        public_data,
        &transcript_channel,
    );
}

pub fn runRiscVSegmentLookupV2WithEngineUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    result: *const runner_result.SegmentResult,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
    transcript_channel: *Engine.Channel,
) !ProveOutputV2ForEngine(Engine) {
    return runRiscVSegmentV2WithEngineUsingChannelAndExecutionLayout(
        Engine,
        .authenticated_physical_v2,
        allocator,
        pcs_config,
        result,
        recorder,
        public_data,
        transcript_channel,
        .{},
    );
}

/// Proof-independent admission for the statement-wide selected lookup cohort.
/// It executes the production witness/geometry derivation, requires the exact
/// seventeen-family manifest permutation, and returns the transcript token
/// that proving will reconstruct. No commitment or Fiat-Shamir state is made.
pub const LookupV2FullCohortInspection = struct {
    activation: lookup_physical_v2.AuthenticatedStatement,
    infrastructure_count: u32,
    compatibility_opcode_interaction_columns: u32,
    infrastructure_interaction_columns: u32,
    compatibility_interaction_columns: u32,
    selected_interaction_columns: usize,
};

pub fn inspectRiscVSegmentLookupV2FullCohort(
    allocator: std.mem.Allocator,
    result: *const runner_result.SegmentResult,
    public_data: public_data_v2.PublicDataV2,
) !LookupV2FullCohortInspection {
    const workspace = try ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    var derived = try deriveV2(allocator, workspace, result, null, public_data);
    defer derived.witness.deinit(allocator);

    var manifest = lookup_physical_v2.Manifest.native();
    if (workspace.statement.n_components != lookup_physical_v2.FAMILY_COUNT)
        return error.InvalidStatementGeometry;
    for (workspace.statement.component_descs[0..workspace.statement.n_components], 0..) |
        descriptor,
        index,
    | {
        if (descriptor.family != manifest.entries[index].family)
            return error.InvalidFamilyOrder;
    }
    const activation = try lookup_physical_v2.AuthenticatedStatement.init(
        &workspace.statement,
        &manifest,
    );
    var compatibility_opcode_columns: u32 = 0;
    for (workspace.statement.component_descs[0..workspace.statement.n_components]) |
        descriptor,
    | {
        compatibility_opcode_columns = std.math.add(
            u32,
            compatibility_opcode_columns,
            @intCast(opcode_interaction.nColumns(descriptor.family)),
        ) catch return error.InvalidStatementGeometry;
    }
    const compatibility_total = workspace.statement.nInteractionColumns();
    const infrastructure_columns = std.math.sub(
        u32,
        compatibility_total,
        compatibility_opcode_columns,
    ) catch return error.InvalidStatementGeometry;
    return .{
        .activation = activation,
        .infrastructure_count = workspace.statement.n_infra,
        .compatibility_opcode_interaction_columns = compatibility_opcode_columns,
        .infrastructure_interaction_columns = infrastructure_columns,
        .compatibility_interaction_columns = compatibility_total,
        .selected_interaction_columns = try activation.totalInteractionColumns(
            &workspace.statement,
            &manifest,
        ),
    };
}

fn runRiscVSegmentV2WithEngineUsingChannelAndExecutionLayout(
    comptime Engine: type,
    comptime lookup_layout: LookupLayoutV2,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    result: *const runner_result.SegmentResult,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
    transcript_channel: *Engine.Channel,
    execution: ExecutionOptionsV2,
) !ProveOutputV2ForEngine(Engine) {
    comptime @import("stwo_prover_api").assertProverEngine(Engine);
    const workspace = try ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);

    var output: ProveOutputV2ForEngine(Engine) = undefined;
    try proveStagesV2(
        Engine,
        lookup_layout,
        workspace,
        &output,
        allocator,
        pcs_config,
        result,
        recorder,
        public_data,
        transcript_channel,
        execution,
    );
    return output;
}

const stages = @import("orchestration_stages.zig").Ops(@This());
const proveStagesV2 = stages.proveStagesV2;
const proveStages = stages.proveStages;
const deriveV2 = stages.deriveV2;
