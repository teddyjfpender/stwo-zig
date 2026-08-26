//! Tree 1: the main trace, in pinned column order, and its commitment.
//!
//! Column order is the whole contract of this module. Opcode-family columns
//! occupy `[0, nOpcodeMainColumns)` in statement order; infrastructure columns
//! follow in registry order (program, RW-memory shards, Merkle, Poseidon2,
//! clock update, lookup-table multiplicities). Every component built later in
//! `proof_finalize` addresses its columns by an offset walked in exactly that
//! order, so a column written to the wrong index is not a layout bug, it is a
//! different AIR.
//!
//! ## Overlap
//!
//! Opcode columns are generated on a helper thread while infrastructure columns
//! are generated on this one. They write disjoint storage: opcode rows land in
//! `workspace.opcode_columns`, infrastructure columns land in freshly allocated
//! buffers, and nothing reads the opcode buffers until `OpcodeGeneration.finish`
//! has joined.
//!
//! ## Ownership
//!
//! The `ColumnEvaluation` array is **transferred** to the commitment scheme at
//! the commit point and released here on every path that does not reach it. The
//! three buffers in `Retained` are the exception: Tree 2 must derive its
//! interactions from byte-identical base values, so they survive this stage and
//! are **transferred** to the caller, which releases them after Tree 2.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const work_pool = @import("stwo_prover_engine").work_pool;
const prover_api = @import("stwo_prover_api");
const stage_profile = @import("stwo_prover_api").stage_profile;
const clock_update_interaction = @import("../air/clock_update_interaction.zig");
const component_order = @import("../air/component_order.zig");
const lookup_table_schema = @import("../air/lookups/tables/schema.zig");
const guest_lookup_registration = @import("../air/guest_precompile/lookup_registration.zig");
const guest_main_trace = @import("../air/guest_precompile/main_trace.zig");
const guest_statement = @import("../air/guest_precompile/statement.zig");
const memory_trace = @import("../air/memory_commitment/trace.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_commitment = @import("../air/program/commitment.zig");
const infra = @import("../infra_trace.zig");
const state_chain = @import("../runner/state_chain.zig");
const guest_call_buffer = @import("../runner/guest_precompile/call_buffer.zig");
const guest_runner = @import("../runner/guest_precompile/poseidon2_v1.zig");
const trace_mod = @import("../runner/trace.zig");
const commitment_witness = @import("commitment_witness.zig");
const lookup_sources = @import("lookup_sources.zig");
const main_witness_work = @import("main_witness_work.zig");
const poseidon_witness_work = @import("poseidon_witness_work.zig");
const production = @import("main_trace_plan_execution_production.zig");
const main_trace_plan = @import("main_trace_plan.zig");
const proof_workspace = @import("proof_workspace.zig");
const opcode_witness_test_authority = @import("opcode_witness_test_authority.zig");
const proof_phase_meter = @import("proof_phase_meter.zig");
const relation_diagnostic = @import("relation_diagnostic.zig");
const statement_geometry = @import("statement_geometry.zig");
const statement_validation = @import("statement_validation.zig");
const test_trace_dump = @import("test_trace_dump.zig");
const test_witness_hook = @import("test_witness_hook.zig");
const trace_arena = @import("trace_arena.zig");
const tree2_main_source = @import("tree2_main_source.zig");
const types = @import("types.zig");

const M31 = m31.M31;
const CommitmentWitness = commitment_witness.CommitmentWitness;
const Geometry = statement_geometry.Geometry;
const ProofWorkspace = proof_workspace.ProofWorkspace;
const ProverError = types.ProverError;
const RunMode = types.RunMode;
const computeLogSize = statement_validation.computeLogSize;

/// Main-trace buffers that outlive their own commitment.
///
/// Tree 2 regenerates its interactions from these exact values, so releasing
/// them at the end of Tree 1 would force a second, possibly divergent,
/// generation pass. **Transferred** to the caller of `generateAndCommit`;
/// release with `deinit` once the interaction trace is committed.
pub const Retained = union(enum) {
    legacy: struct {
        lookup_source: lookup_sources.Result,
    },
    planned: production.Prepared,

    /// Borrows the exact Tree-1 authorities retained for Tree 2. The returned
    /// view owns nothing and may not outlive this union.
    pub fn tree2Source(
        self: *const Retained,
        workspace: *const ProofWorkspace,
    ) tree2_main_source.Source {
        return switch (self.*) {
            .legacy => |*owned| tree2_main_source.Source.fromLegacy(
                workspace,
                &owned.lookup_source,
            ),
            .planned => |*prepared| tree2_main_source.Source.fromPlanned(prepared),
        };
    }

    pub fn deinit(
        self: *Retained,
        allocator: std.mem.Allocator,
        workspace: *ProofWorkspace,
    ) void {
        switch (self.*) {
            .legacy => |*owned| {
                owned.lookup_source.deinit(allocator);
                workspace.releaseOpcodeColumns(allocator);
                workspace.releaseClockMain(allocator);
            },
            .planned => |*prepared| prepared.deinit(),
        }
        self.* = undefined;
    }
};

pub const Poseidon2Retained = struct {
    lookup_source: lookup_sources.Result,
    guest_relation_source: guest_main_trace.RelationSource,

    pub fn deinit(
        self: *Poseidon2Retained,
        allocator: std.mem.Allocator,
        workspace: *ProofWorkspace,
    ) void {
        self.guest_relation_source.deinit();
        self.lookup_source.deinit(allocator);
        workspace.releaseOpcodeColumns(allocator);
        workspace.releaseClockMain(allocator);
    }
};

/// Generates every Tree-1 column and commits it.
pub fn generateAndCommit(
    comptime Engine: type,
    comptime mode: RunMode,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    exec_trace: *const trace_mod.Trace,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    opt_chain: ?*const state_chain.StateChainTracker,
    test_mutation: ?test_witness_hook.Mutation,
    test_dump: ?*test_trace_dump.Capture,
    retained_tree: *?relation_diagnostic.RetainedTree,
    phase_meter: ?*proof_phase_meter.Meter,
) !Retained {
    const capture_main_witness_work = if (test_mutation == null)
        try planMainWitnessFieldWork(recorder)
    else blk: {
        try planIncompleteMainWitnessFieldWork(recorder);
        break :blk false;
    };
    var poseidon_capture = try PoseidonWorkCapture.init(witness);
    var materialization_region: ?proof_phase_meter.WitnessRegion =
        if (phase_meter) |meter| try meter.begin() else null;
    errdefer if (materialization_region) |*region| region.abort();

    const statement = &workspace.statement;
    const n_opcode_main = statement.nOpcodeMainColumns();
    const n_main = n_opcode_main + statement.nInfraColumns();
    const arena_capable = comptime @hasDecl(Engine, "Backend") and
        @hasDecl(Engine.Backend, "adopts_source_trace_arena") and
        Engine.Backend.adopts_source_trace_arena;

    var columns = try Columns.init(
        allocator,
        n_main,
        n_opcode_main,
        if (arena_capable) statement else null,
        null,
    );
    defer columns.deinit(allocator);

    var opcode = try OpcodeGeneration.begin(workspace, allocator, exec_trace, recorder);
    errdefer opcode.abandon(workspace, allocator);
    // Workspace-owned clock columns; freeing an unwritten set is a no-op, so
    // this covers every failure from here to the transfer in `Retained`.
    errdefer workspace.releaseClockMain(allocator);

    if (poseidon_capture) |*capture| {
        const receipt = try generateInfrastructureWithPoseidonWorkReceipt(
            allocator,
            workspace,
            &columns,
            witness,
            geometry,
            opt_chain,
            recorder,
            &capture.authority,
        );
        try capture.completed.observe(&capture.authority, receipt);
    } else {
        try generateInfrastructure(
            allocator,
            workspace,
            &columns,
            witness,
            geometry,
            opt_chain,
            recorder,
        );
    }

    try opcode.finish(workspace);
    errdefer workspace.releaseOpcodeColumns(allocator);

    // A row override lands here, on the generated witness itself, because every
    // artefact below is derived from these buffers. A later forgery would
    // be a witness the prover disagrees with itself about, and the row's
    // rejection would say nothing about the AIR.
    const forged = if (test_mutation) |mutation| try opcode_witness_test_authority.apply(
        allocator,
        statement.*,
        &workspace.opcode_columns,
        exec_trace,
        mutation,
    ) else false;

    // Table multiplicities are derived from the exact family buffers that are
    // committed below. Keeping the lookup source and its commitment on one
    // witness path is what makes a pre-commit mutation hook visible to both.
    var lookup_source = blk: {
        var stage = try stage_profile.StageScope.begin(
            recorder,
            "riscv_lookup_source_ingest",
            "RISC-V lookup-source ingestion",
        );
        defer stage.end();
        break :blk try lookup_sources.ingest(
            allocator,
            statement.*,
            &workspace.opcode_columns,
            .{ .unrepresentable = if (forged) .drop else .reject },
        );
    };
    errdefer lookup_source.deinit(allocator);
    try registerLookupSources(&lookup_source, witness, workspace);
    try appendLookupColumns(allocator, &columns, &lookup_source);
    try copyOpcodeColumns(allocator, workspace, &columns);

    if (poseidon_capture) |*capture| {
        try capture.sealAndPublish(
            recorder,
            witness.poseidonCalls().len,
            0,
        );
    }

    if (capture_main_witness_work) {
        const receipt = try main_witness_work.issueLegacyReceipt(
            statement,
            exec_trace.rows.items,
            .{
                .counter_set_merges = workspace.opcode_columns.counter_set_merges,
                .direct_semantic_audit_performed = workspace.opcode_columns.direct_semantic_audit_performed,
            },
        );
        try publishMainWitnessWorkReceipt(recorder, receipt);
    }

    std.debug.assert(columns.offset == n_main);

    if (test_mutation) |mutation|
        try test_witness_hook.applyMain(allocator, statement.*, columns.values, mutation);
    if (test_dump) |dump| try dump.recordMain(statement, columns.values);
    if (comptime mode == .relation_diagnostic) {
        retained_tree.* = try relation_diagnostic.RetainedTree.capture(allocator, columns.values);
    }

    if (materialization_region) |*region| try region.finish();

    {
        var stage = try stage_profile.StageScope.begin(recorder, "riscv_main_trace_commit", "RISC-V main trace commit");
        defer stage.end();
        columns.moved = true;
        if (comptime @hasDecl(Engine, "commitWithBacking")) {
            if (columns.backing_buffers) |backing_buffers| {
                try Engine.commitWithBacking(
                    scheme,
                    allocator,
                    columns.values,
                    backing_buffers,
                    recorder,
                    channel,
                );
            } else {
                try Engine.commit(scheme, allocator, columns.values, recorder, channel);
            }
        } else {
            try Engine.commit(scheme, allocator, columns.values, recorder, channel);
        }
    }
    return .{ .legacy = .{ .lookup_source = lookup_source } };
}

/// Selects the predecessor or the explicitly requested bounded Tree-1 epoch.
/// A null request preserves the existing production path byte-for-byte.  The
/// requested path borrows the one proof-scoped pool owned by orchestration, so
/// Tree 1 and every later proving stage consume one finite worker budget.
pub fn generateAndCommitWithExecution(
    comptime Engine: type,
    comptime mode: RunMode,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    exec_trace: *const trace_mod.Trace,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    opt_chain: ?*const state_chain.StateChainTracker,
    test_mutation: ?test_witness_hook.Mutation,
    test_dump: ?*test_trace_dump.Capture,
    retained_tree: *?relation_diagnostic.RetainedTree,
    execution_request: ?prover_api.CpuCompositionExecutionRequest,
    execution_pool: ?*work_pool.WorkPool,
    phase_meter: ?*proof_phase_meter.Meter,
) !Retained {
    const request = execution_request orelse return generateAndCommit(
        Engine,
        mode,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        exec_trace,
        witness,
        geometry,
        opt_chain,
        test_mutation,
        test_dump,
        retained_tree,
        phase_meter,
    );
    return generateAndCommitPlanned(
        Engine,
        mode,
        allocator,
        workspace,
        scheme,
        channel,
        recorder,
        exec_trace,
        witness,
        geometry,
        opt_chain,
        test_mutation,
        test_dump,
        retained_tree,
        request,
        execution_pool,
        phase_meter,
    );
}

fn generateAndCommitPlanned(
    comptime Engine: type,
    comptime mode: RunMode,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    exec_trace: *const trace_mod.Trace,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    opt_chain: ?*const state_chain.StateChainTracker,
    test_mutation: ?test_witness_hook.Mutation,
    test_dump: ?*test_trace_dump.Capture,
    retained_tree: *?relation_diagnostic.RetainedTree,
    execution_request: prover_api.CpuCompositionExecutionRequest,
    execution_pool: ?*work_pool.WorkPool,
    phase_meter: ?*proof_phase_meter.Meter,
) !Retained {
    const capture_main_witness_work = try planMainWitnessFieldWork(recorder);
    var materialization_region: ?proof_phase_meter.WitnessRegion =
        if (phase_meter) |meter| try meter.begin() else null;
    errdefer if (materialization_region) |*region| region.abort();

    // Tree-0/Tree-1 witness mutations deliberately remain on the independent
    // predecessor: mutating already-reduced planned columns would detach Tree 1
    // from the retained Tree-2 counters. A Tree-2-only mutation is safe here
    // because it is applied later, after the honest interaction epoch publishes.
    if (test_mutation) |mutation| {
        if (!test_witness_hook.isInteraction(mutation)) {
            return error.UnsupportedPlannedTree1Mutation;
        }
    }
    if (execution_request.worker_count > 1 and execution_pool == null) {
        return error.WorkPoolRequired;
    }
    try work_pool.observeProofPoolStageForTest(.tree1, execution_pool);

    const statement = &workspace.statement;
    const pool_capacity = if (execution_pool) |pool| pool.workerCount() else 1;
    const worker_stack_bytes = if (execution_pool) |pool|
        pool.stackSize()
    else
        work_pool.WORKER_STACK_SIZE;
    const plan = try main_trace_plan.build(statement, .{
        .execution = execution_request,
        .pool_capacity = pool_capacity,
        .worker_stack_bytes = worker_stack_bytes,
        .enable_opcode_audit = false,
    });

    var prepared = try production.Prepared.prepareForEngine(
        Engine,
        allocator,
        &plan,
        statement,
        .{
            .execution_trace = exec_trace,
            .witness = witness,
            .geometry = geometry,
            .state_chain = opt_chain,
            .capture_main_witness_work = capture_main_witness_work,
        },
    );
    errdefer prepared.deinit();
    {
        var stage = try stage_profile.StageScope.begin(
            recorder,
            "riscv_main_trace_tree1_epoch",
            "RISC-V bounded Tree-1 generation epoch",
        );
        defer stage.end();
        _ = try prepared.execute(execution_pool);
    }
    if (capture_main_witness_work) {
        const receipt = try prepared.mainWitnessWorkReceipt();
        const active = recorder orelse unreachable;
        const work = active.workCaptureRecorder() orelse unreachable;
        try work.recordCompletedDelta(receipt.delta());
    }
    if (witness.poseidonWorkShard() != null) {
        try publishPoseidonWorkReceipt(
            recorder,
            try prepared.poseidonWitnessWorkReceipt(),
        );
    }

    const published_columns = try prepared.mainColumns();
    if (test_dump) |dump| try dump.recordMain(statement, published_columns);
    if (comptime mode == .relation_diagnostic) {
        retained_tree.* = try relation_diagnostic.RetainedTree.capture(
            allocator,
            published_columns,
        );
    }

    var commitment = try prepared.takeMainCommitment();
    errdefer commitment.deinit(allocator);
    try commitment.validatePolicy();
    if (materialization_region) |*region| try region.finish();
    const columns = commitment.columns;
    const backing_buffers = commitment.backingBuffers();
    // `Engine.commit*` consumes both descriptors and their payload on success
    // and failure. Disarm the local owner immediately before that call.
    commitment.columns = &.{};
    commitment.backing = null;
    {
        var stage = try stage_profile.StageScope.begin(
            recorder,
            "riscv_main_trace_commit",
            "RISC-V main trace commit",
        );
        defer stage.end();
        if (comptime @hasDecl(Engine, "commitWithBacking")) {
            if (backing_buffers) |backing| {
                try Engine.commitWithBacking(
                    scheme,
                    allocator,
                    columns,
                    backing,
                    recorder,
                    channel,
                );
            } else {
                try Engine.commit(scheme, allocator, columns, recorder, channel);
            }
        } else {
            if (backing_buffers != null)
                return error.InvalidProductionDestinationPolicy;
            try Engine.commit(scheme, allocator, columns, recorder, channel);
        }
    }
    return .{ .planned = prepared };
}

/// Generates the profile Tree 1 in exact base-then-caller-then-provider order.
/// Guest rows are written directly into final commitment storage. Only the 191
/// columns required after the challenge draw are retained.
pub fn generateAndCommitPoseidon2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    extension: *const guest_statement.ExtensionStatement,
    calls: *const guest_call_buffer.Frozen,
    execution_rows: *const guest_runner.FrozenExecutionRows,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    exec_trace: *const trace_mod.Trace,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    opt_chain: ?*const state_chain.StateChainTracker,
) !Poseidon2Retained {
    return generateAndCommitPoseidon2WithPhaseMeter(
        Engine,
        allocator,
        workspace,
        extension,
        calls,
        execution_rows,
        scheme,
        channel,
        recorder,
        exec_trace,
        witness,
        geometry,
        opt_chain,
        null,
    );
}

/// Profile Tree 1 with the same materialization boundary used by the base
/// prover. Commitment work is deliberately outside the witness region.
pub fn generateAndCommitPoseidon2WithPhaseMeter(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    extension: *const guest_statement.ExtensionStatement,
    calls: *const guest_call_buffer.Frozen,
    execution_rows: *const guest_runner.FrozenExecutionRows,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    exec_trace: *const trace_mod.Trace,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    opt_chain: ?*const state_chain.StateChainTracker,
    phase_meter: ?*proof_phase_meter.Meter,
) !Poseidon2Retained {
    const capture_main_witness_work = try planMainWitnessFieldWork(recorder);
    var poseidon_capture = try PoseidonWorkCapture.init(witness);
    const statement = &workspace.statement;
    try extension.validate(statement);
    const n_opcode_main = statement.nOpcodeMainColumns();
    const n_base_main = n_opcode_main + statement.nInfraColumns();
    const n_main = std.math.add(
        usize,
        n_base_main,
        guest_main_trace.main_column_count,
    ) catch return error.InvalidTraceShape;
    const arena_capable = comptime @hasDecl(Engine, "Backend") and
        @hasDecl(Engine.Backend, "adopts_source_trace_arena") and
        Engine.Backend.adopts_source_trace_arena;

    var materialization_region: ?proof_phase_meter.WitnessRegion =
        if (phase_meter) |meter| try meter.begin() else null;
    errdefer if (materialization_region) |*region| region.abort();
    var columns = try Columns.init(
        allocator,
        n_main,
        n_opcode_main,
        if (arena_capable) statement else null,
        if (arena_capable) extension else null,
    );
    defer columns.deinit(allocator);

    var opcode = try OpcodeGeneration.begin(workspace, allocator, exec_trace, recorder);
    errdefer opcode.abandon(workspace, allocator);
    errdefer workspace.releaseClockMain(allocator);
    if (poseidon_capture) |*capture| {
        const receipt = try generateInfrastructureWithPoseidonWorkReceipt(
            allocator,
            workspace,
            &columns,
            witness,
            geometry,
            opt_chain,
            recorder,
            &capture.authority,
        );
        try capture.completed.observe(&capture.authority, receipt);
    } else {
        try generateInfrastructure(
            allocator,
            workspace,
            &columns,
            witness,
            geometry,
            opt_chain,
            recorder,
        );
    }

    var guest_destinations = try columns.reserveGuestAt(
        allocator,
        n_base_main,
        extension.components[0].log_size,
    );
    if (poseidon_capture) |*capture| {
        const receipts = try guest_main_trace.generateMainIntoWithWorkReceipt(
            statement,
            extension,
            calls,
            execution_rows,
            &guest_destinations,
            &capture.authority,
        );
        try receipts.publishInto(&capture.authority, &capture.completed);
    } else {
        try guest_main_trace.generateMainInto(
            statement,
            extension,
            calls,
            execution_rows,
            &guest_destinations,
        );
    }

    try opcode.finish(workspace);
    errdefer workspace.releaseOpcodeColumns(allocator);

    var lookup_source = blk: {
        var stage = try stage_profile.StageScope.begin(
            recorder,
            "riscv_guest_lookup_source_ingest",
            "RISC-V guest lookup-source ingestion",
        );
        defer stage.end();
        break :blk try lookup_sources.ingest(
            allocator,
            statement.*,
            &workspace.opcode_columns,
            .{ .unrepresentable = .reject },
        );
    };
    errdefer lookup_source.deinit(allocator);
    try registerLookupSources(&lookup_source, witness, workspace);
    _ = try guest_lookup_registration.registerGenerated(
        statement,
        extension,
        &guest_destinations,
        &lookup_source.counters,
    );
    try appendLookupColumns(allocator, &columns, &lookup_source);
    try copyOpcodeColumns(allocator, workspace, &columns);
    if (columns.offset != n_base_main or !columns.allInitialized())
        return error.InvalidTraceShape;

    var relation_source = try guest_main_trace.RelationSource.capture(
        allocator,
        &guest_destinations,
        extension.components[0].log_size,
        extension.counts.n_guest,
    );
    errdefer relation_source.deinit();

    if (poseidon_capture) |*capture| {
        try capture.sealAndPublish(
            recorder,
            witness.poseidonCalls().len,
            extension.counts.n_guest,
        );
    }

    if (capture_main_witness_work) {
        const receipt = try main_witness_work.issueLegacyPoseidon2Receipt(
            statement,
            exec_trace.rows.items,
            .{
                .counter_set_merges = workspace.opcode_columns.counter_set_merges,
                .direct_semantic_audit_performed = workspace.opcode_columns.direct_semantic_audit_performed,
            },
            extension.counts.n_guest,
        );
        try publishMainWitnessWorkReceipt(recorder, receipt);
    }

    if (materialization_region) |*region| try region.finish();
    {
        var stage = try stage_profile.StageScope.begin(
            recorder,
            "riscv_guest_main_trace_commit",
            "RISC-V guest main trace commit",
        );
        defer stage.end();
        columns.moved = true;
        if (comptime @hasDecl(Engine, "commitWithBacking")) {
            if (columns.backing_buffers) |backing_buffers| {
                try Engine.commitWithBacking(
                    scheme,
                    allocator,
                    columns.values,
                    backing_buffers,
                    recorder,
                    channel,
                );
            } else {
                try Engine.commit(scheme, allocator, columns.values, recorder, channel);
            }
        } else {
            try Engine.commit(scheme, allocator, columns.values, recorder, channel);
        }
    }
    return .{
        .lookup_source = lookup_source,
        .guest_relation_source = relation_source,
    };
}

/// Explicit fail-closed hook for non-production mutation/fallback paths whose
/// work is intentionally outside the exact producer authorities.
pub fn planIncompleteMainWitnessFieldWork(
    recorder: ?*stage_profile.Recorder,
) !void {
    const active = recorder orelse return;
    const work = active.workCaptureRecorder() orelse return;
    try work.expectProducer(.main_witness_field);
    work.markIncomplete();
}

/// Selects exact producer capture for the prepared Tree-1 epoch. Planning is
/// independent of completion; the producer-issued receipt is recorded only
/// after the epoch reaches its published seal.
pub fn planMainWitnessFieldWork(
    recorder: ?*stage_profile.Recorder,
) !bool {
    const active = recorder orelse return false;
    const work = active.workCaptureRecorder() orelse return false;
    try work.expectProducer(.main_witness_field);
    return true;
}

const support = @import("main_trace_support.zig");
const publishMainWitnessWorkReceipt = support.publishMainWitnessWorkReceipt;
const PoseidonWorkCapture = support.PoseidonWorkCapture;
const publishPoseidonWorkReceipt = support.publishPoseidonWorkReceipt;
pub const generateInfrastructure = support.generateInfrastructure;
const generateInfrastructureWithPoseidonWorkReceipt = support.generateInfrastructureWithPoseidonWorkReceipt;
const copyOpcodeColumns = support.copyOpcodeColumns;
const registerLookupSources = support.registerLookupSources;
const appendLookupColumns = support.appendLookupColumns;
pub const Columns = support.Columns;
pub const OpcodeGeneration = support.OpcodeGeneration;
