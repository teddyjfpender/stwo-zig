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
const prover_pcs = @import("stwo_prover_impl").pcs;
const stage_profile = @import("stwo_prover_impl").stage_profile;
const clock_update_interaction = @import("../air/clock_update_interaction.zig");
const component_order = @import("../air/component_order.zig");
const lookup_table_schema = @import("../air/lookups/tables/schema.zig");
const source_ingest = @import("../air/lookups/tables/source_ingest.zig");
const memory_trace = @import("../air/memory_commitment/trace.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_commitment = @import("../air/program/commitment.zig");
const infra = @import("../infra_trace.zig");
const state_chain = @import("../runner/state_chain.zig");
const trace_mod = @import("../runner/trace.zig");
const commitment_witness = @import("commitment_witness.zig");
const lookup_sources = @import("lookup_sources.zig");
const proof_workspace = @import("proof_workspace.zig");
const relation_diagnostic = @import("relation_diagnostic.zig");
const statement_geometry = @import("statement_geometry.zig");
const statement_validation = @import("statement_validation.zig");
const test_trace_dump = @import("test_trace_dump.zig");
const test_witness_hook = @import("test_witness_hook.zig");
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
pub const Retained = struct {
    lookup_source: source_ingest.Result,

    pub fn deinit(
        self: *Retained,
        allocator: std.mem.Allocator,
        workspace: *ProofWorkspace,
    ) void {
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
) !Retained {
    const statement = &workspace.statement;
    const n_opcode_main = statement.nOpcodeMainColumns();
    const n_main = n_opcode_main + statement.nInfraColumns();

    var columns = try Columns.init(allocator, n_main, n_opcode_main);
    defer columns.deinit(allocator);

    var opcode = try OpcodeGeneration.begin(workspace, allocator, exec_trace, recorder);
    errdefer opcode.abandon(workspace, allocator);
    // Workspace-owned clock columns; freeing an unwritten set is a no-op, so
    // this covers every failure from here to the transfer in `Retained`.
    errdefer workspace.releaseClockMain(allocator);

    try generateInfrastructure(allocator, workspace, &columns, witness, geometry, opt_chain, recorder);

    try opcode.finish(workspace);
    errdefer workspace.releaseOpcodeColumns(allocator);

    // A row override lands here, on the generated witness itself, because every
    // artefact below is derived from these buffers: the multiplicity counters,
    // the committed copy, and Tree 2. A forgery applied after any of them would
    // be a witness the prover disagrees with itself about, and the row's
    // rejection would say nothing about the AIR.
    const forged = if (test_mutation) |mutation| try test_witness_hook.applyOpcodeWitness(
        allocator,
        statement.*,
        &workspace.opcode_columns.components,
        mutation,
    ) else false;

    // Table multiplicities are derived from the exact family buffers that are
    // committed below. Keeping the lookup source and its commitment on one
    // witness path is what makes a pre-commit mutation hook visible to both.
    var lookup_source = try lookup_sources.ingest(
        allocator,
        statement.*,
        &workspace.opcode_columns,
        .{ .unrepresentable = if (forged) .drop else .reject },
    );
    errdefer lookup_source.deinit(allocator);
    try registerLookupSources(&lookup_source, witness, workspace);
    try appendLookupColumns(allocator, &columns, &lookup_source);
    try copyOpcodeColumns(allocator, workspace, &columns);

    std.debug.assert(columns.offset == n_main);

    if (test_mutation) |mutation|
        try test_witness_hook.applyMain(allocator, statement.*, columns.values, mutation);
    if (test_dump) |dump| try dump.recordMain(statement, columns.values);
    if (comptime mode == .relation_diagnostic) {
        retained_tree.* = try relation_diagnostic.RetainedTree.capture(allocator, columns.values);
    }

    {
        var stage = try stage_profile.StageScope.begin(recorder, "riscv_main_trace_commit", "RISC-V main trace commit");
        defer stage.end();
        columns.moved = true;
        try Engine.commit(scheme, allocator, columns.values, recorder, channel);
    }
    return .{ .lookup_source = lookup_source };
}

/// The infrastructure half of Tree 1, in registry order.
fn generateInfrastructure(
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    columns: *Columns,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    opt_chain: ?*const state_chain.StateChainTracker,
    recorder: ?*stage_profile.Recorder,
) !void {
    var stage = try stage_profile.StageScope.begin(recorder, "riscv_infrastructure_trace_generation", "RISC-V infrastructure trace generation");
    try appendProgramColumns(allocator, columns, witness, geometry);
    try appendMemoryColumns(allocator, workspace, columns, witness);
    try appendMerkleColumns(allocator, columns, witness, geometry);
    try appendPoseidonColumns(allocator, columns, witness, geometry);
    try appendClockColumns(allocator, workspace, columns, geometry, opt_chain);
    stage.end();
}

/// Exact sparse decoded-program commitment.
fn appendProgramColumns(
    allocator: std.mem.Allocator,
    columns: *Columns,
    witness: *const CommitmentWitness,
    geometry: Geometry,
) !void {
    const generated = try program_commitment.generateMain(
        allocator,
        witness.program.rows,
        geometry.program_log_size,
    );
    for (0..program_commitment.N_MAIN_COLUMNS) |c| {
        columns.append(.{
            .log_size = geometry.program_log_size,
            .values = generated.values[c],
        });
    }
}

/// Exact ordinary RW-memory boundary table, over the shard partition the
/// statement already declared.
fn appendMemoryColumns(
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    columns: *Columns,
    witness: *const CommitmentWitness,
) !void {
    const claims = witness.boundary orelse return;
    var row_start: usize = 0;
    for (workspace.memory_shard_lengths[0..workspace.memory_shard_count]) |shard_len| {
        const log_size = @max(computeLogSize(shard_len), 4);
        const generated = try memory_trace.generate(
            allocator,
            claims.rows[row_start..][0..shard_len],
            log_size,
        );
        for (generated.values) |values| {
            columns.append(.{ .log_size = log_size, .values = values });
        }
        row_start += shard_len;
    }
}

/// Exact sparse Merkle rows: initial RW, final RW, then program.
fn appendMerkleColumns(
    allocator: std.mem.Allocator,
    columns: *Columns,
    witness: *const CommitmentWitness,
    geometry: Geometry,
) !void {
    const generated = try merkle_node.generateMain(
        allocator,
        witness.merkleRows(),
        geometry.merkle_log_size,
    );
    for (0..merkle_node.N_MAIN_COLUMNS) |c| {
        columns.append(.{
            .log_size = geometry.merkle_log_size,
            .values = generated.values[c],
        });
    }
}

/// Exact narrow Poseidon2 permutation calls, one per sparse Merkle node.
fn appendPoseidonColumns(
    allocator: std.mem.Allocator,
    columns: *Columns,
    witness: *const CommitmentWitness,
    geometry: Geometry,
) !void {
    const generated = try poseidon2_air.generateMain(
        allocator,
        witness.poseidonCalls(),
        geometry.poseidon_log_size,
    );
    for (0..poseidon2_air.N_MAIN_COLUMNS) |c| {
        columns.append(.{
            .log_size = geometry.poseidon_log_size,
            .values = generated.values[c],
        });
    }
}

/// Unified register + memory clock update (10 cols).
///
/// The generated set is kept in the workspace and *copied* into the committed
/// array: Tree 2 reads the workspace copy, which must stay byte-identical to
/// what Tree 1 committed even after the committed array is transferred away.
fn appendClockColumns(
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    columns: *Columns,
    geometry: Geometry,
    opt_chain: ?*const state_chain.StateChainTracker,
) !void {
    var empty_chain = state_chain.StateChainTracker.init(allocator);
    defer empty_chain.deinit();

    const generated = try infra.genClockUpdateColumns(
        allocator,
        opt_chain orelse &empty_chain,
        geometry.clock_update_log,
    );
    workspace.clock_main = generated.columns;
    for (0..infra.CLOCK_UPDATE_COLS) |c| {
        columns.append(.{
            .log_size = geometry.clock_update_log,
            .values = try allocator.dupe(M31, workspace.clock_main[c]),
        });
    }
}

/// Adds the non-opcode multiplicity requests to the counters ingested from the
/// opcode buffers, so one counter set covers every committed lookup.
fn registerLookupSources(
    lookup_source: *source_ingest.Result,
    witness: *const CommitmentWitness,
    workspace: *const ProofWorkspace,
) !void {
    try lookup_sources.registerProgram(&lookup_source.counters, witness.program.rows);
    if (witness.boundary) |claims| {
        try lookup_sources.registerMemoryBoundary(&lookup_source.counters, claims.rows);
    }
    var clock_views: [clock_update_interaction.N_MAIN_COLUMNS][]const M31 = undefined;
    for (&clock_views, workspace.clock_main) |*view, column| view.* = column;
    try clock_update_interaction.registerRangeCheckCounters(
        &lookup_source.counters,
        &clock_views,
    );
}

fn appendLookupColumns(
    allocator: std.mem.Allocator,
    columns: *Columns,
    lookup_source: *source_ingest.Result,
) !void {
    for (component_order.lookupTables()) |kind| {
        const counter = &lookup_source.counters.counters[@intFromEnum(kind)];
        columns.append(.{
            .log_size = lookup_table_schema.logSize(kind),
            .values = try counter.committedColumn(allocator),
        });
    }
}

/// Copies the generated opcode buffers into the committed prefix.
///
/// The copy is not redundant: the committed array is transferred to the scheme,
/// while the workspace originals must survive for Tree 2.
fn copyOpcodeColumns(
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    columns: *Columns,
) !void {
    const statement = &workspace.statement;
    var opcode_col_offset: usize = 0;
    for (0..statement.n_components) |comp_idx| {
        const desc = statement.component_descs[comp_idx];
        const generated = &workspace.opcode_columns.components[comp_idx];
        if (generated.n_columns != desc.n_columns) return ProverError.InvalidStatement;
        for (generated.columns[0..generated.n_columns], 0..) |values, column| {
            columns.put(opcode_col_offset + column, .{
                .log_size = desc.log_size,
                .values = try allocator.dupe(M31, values),
            });
        }
        opcode_col_offset += desc.n_columns;
    }
    std.debug.assert(opcode_col_offset == statement.nOpcodeMainColumns());
}

/// The committed column array plus the per-slot initialization flags that make
/// a partially built array releasable.
const Columns = struct {
    values: []prover_pcs.ColumnEvaluation,
    initialized: []bool,
    /// Next infrastructure slot. Opcode slots are addressed absolutely.
    offset: usize,
    moved: bool,

    fn init(
        allocator: std.mem.Allocator,
        n_main: usize,
        infra_offset: usize,
    ) !Columns {
        const values = try allocator.alloc(prover_pcs.ColumnEvaluation, n_main);
        const initialized = allocator.alloc(bool, n_main) catch |err| {
            allocator.free(values);
            return err;
        };
        @memset(initialized, false);
        return .{
            .values = values,
            .initialized = initialized,
            .offset = infra_offset,
            .moved = false,
        };
    }

    fn put(self: *Columns, index: usize, column: prover_pcs.ColumnEvaluation) void {
        self.values[index] = column;
        self.initialized[index] = true;
    }

    fn append(self: *Columns, column: prover_pcs.ColumnEvaluation) void {
        self.put(self.offset, column);
        self.offset += 1;
    }

    /// Releases the flags always, and the column buffers only while this array
    /// still owns them: after `moved` the commitment scheme does.
    fn deinit(self: *Columns, allocator: std.mem.Allocator) void {
        if (!self.moved) {
            for (self.values, self.initialized) |column, initialized| {
                if (initialized) allocator.free(@constCast(column.values));
            }
            allocator.free(self.values);
        }
        allocator.free(self.initialized);
    }
};

/// The overlapped opcode-column generation.
///
/// `finish` is the only path that hands the generated buffers to the caller;
/// every other exit goes through `abandon`, which still joins the helper thread
/// before touching anything the thread writes.
const OpcodeGeneration = struct {
    thread: ?std.Thread,
    scope: stage_profile.StageScope,
    joined: bool,
    finished: bool,

    fn begin(
        workspace: *ProofWorkspace,
        allocator: std.mem.Allocator,
        exec_trace: *const trace_mod.Trace,
        recorder: ?*stage_profile.Recorder,
    ) !OpcodeGeneration {
        const scope = try stage_profile.StageScope.begin(recorder, "riscv_opcode_trace_generation", "RISC-V opcode trace generation (overlapped)");
        const thread = std.Thread.spawn(
            .{},
            ProofWorkspace.generateOpcodeColumns,
            .{ workspace, allocator, exec_trace },
        ) catch null;
        // A machine that cannot spawn still has to produce the columns; it just
        // loses the overlap with infrastructure generation.
        if (thread == null) workspace.generateOpcodeColumns(allocator, exec_trace);
        return .{ .thread = thread, .scope = scope, .joined = false, .finished = false };
    }

    fn join(self: *OpcodeGeneration) void {
        if (self.joined) return;
        if (self.thread) |thread| thread.join();
        self.joined = true;
    }

    /// Joins, closes the profile scope, and surfaces the generator's error.
    /// On success the caller owns `workspace.opcode_columns`.
    fn finish(self: *OpcodeGeneration, workspace: *ProofWorkspace) !void {
        self.join();
        self.scope.end();
        if (workspace.opcode_error) |err| return err;
        self.finished = true;
    }

    /// Failure path. Releases the generated columns only when generation
    /// succeeded and ownership never reached the caller; a failed generator
    /// already unwound its own partial state.
    fn abandon(
        self: *OpcodeGeneration,
        workspace: *ProofWorkspace,
        allocator: std.mem.Allocator,
    ) void {
        self.join();
        if (self.finished) return;
        if (workspace.opcode_error == null) workspace.releaseOpcodeColumns(allocator);
    }
};
