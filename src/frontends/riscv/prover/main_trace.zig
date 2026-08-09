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
const stage_profile = @import("stwo_prover_api").stage_profile;
const clock_update_interaction = @import("../air/clock_update_interaction.zig");
const component_order = @import("../air/component_order.zig");
const lookup_table_schema = @import("../air/lookups/tables/schema.zig");
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
const trace_arena = @import("trace_arena.zig");
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
    lookup_source: lookup_sources.Result,

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
    const arena_capable = comptime @hasDecl(Engine, "Backend") and
        @hasDecl(Engine.Backend, "adopts_source_trace_arena") and
        Engine.Backend.adopts_source_trace_arena;

    var columns = try Columns.init(
        allocator,
        n_main,
        n_opcode_main,
        if (arena_capable) statement else null,
    );
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
    defer stage.end();
    try appendProgramColumns(allocator, columns, witness, geometry);
    try appendMemoryColumns(allocator, workspace, columns, witness);
    try appendMerkleColumns(allocator, columns, witness, geometry);
    try appendPoseidonColumns(allocator, columns, witness, geometry);
    try appendClockColumns(allocator, workspace, columns, geometry, opt_chain);
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
        try columns.appendOwned(allocator, .{
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
            try columns.appendOwned(allocator, .{ .log_size = log_size, .values = values });
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
        try columns.appendOwned(allocator, .{
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
    if (columns.isArenaBacked()) {
        var destinations = try columns.reserve(
            poseidon2_air.N_MAIN_COLUMNS,
            geometry.poseidon_log_size,
        );
        return poseidon2_air.generateMainInto(
            allocator,
            &destinations,
            witness.poseidonCalls(),
            geometry.poseidon_log_size,
        );
    }
    const generated = try poseidon2_air.generateMain(
        allocator,
        witness.poseidonCalls(),
        geometry.poseidon_log_size,
    );
    for (0..poseidon2_air.N_MAIN_COLUMNS) |c| {
        try columns.appendOwned(allocator, .{
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
        try columns.appendCopy(allocator, .{
            .log_size = geometry.clock_update_log,
            .values = workspace.clock_main[c],
        });
    }
}

/// Adds the non-opcode multiplicity requests to the counters ingested from the
/// opcode buffers, so one counter set covers every committed lookup.
fn registerLookupSources(
    lookup_source: *lookup_sources.Result,
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
    lookup_source: *lookup_sources.Result,
) !void {
    for (component_order.lookupTables()) |kind| {
        const counter = &lookup_source.counters.counters[@intFromEnum(kind)];
        try columns.appendOwned(allocator, .{
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
            try columns.putCopy(allocator, opcode_col_offset + column, .{
                .log_size = desc.log_size,
                .values = values,
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
    /// Present when generation writes into one backend-shaped arena from the
    /// outset. Transferred alongside `values`.
    backing_buffers: ?[][]M31,
    /// Next infrastructure slot. Opcode slots are addressed absolutely.
    offset: usize,
    moved: bool,

    fn init(
        allocator: std.mem.Allocator,
        n_main: usize,
        infra_offset: usize,
        arena_statement: ?*const types.RiscVStatement,
    ) !Columns {
        var backing_buffers: ?[][]M31 = null;
        const values = if (arena_statement) |statement| blk: {
            const log_sizes = try allocator.alloc(u32, n_main);
            defer allocator.free(log_sizes);
            var index: usize = 0;
            for (statement.component_descs[0..statement.n_components]) |desc| {
                for (0..desc.n_columns) |_| {
                    log_sizes[index] = desc.log_size;
                    index += 1;
                }
            }
            for (statement.infra_descs[0..statement.n_infra]) |desc| {
                for (0..desc.n_columns) |_| {
                    log_sizes[index] = desc.log_size;
                    index += 1;
                }
            }
            if (index != n_main) return error.InvalidTraceShape;
            const prepared = trace_arena.prepare(allocator, log_sizes) catch |err| switch (err) {
                error.UnsupportedArenaAlignment => break :blk try allocator.alloc(
                    prover_pcs.ColumnEvaluation,
                    n_main,
                ),
                else => return err,
            };
            backing_buffers = prepared.backing_buffers;
            break :blk prepared.columns;
        } else try allocator.alloc(prover_pcs.ColumnEvaluation, n_main);
        const initialized = allocator.alloc(bool, n_main) catch |err| {
            if (backing_buffers) |buffers| {
                allocator.free(values);
                for (buffers) |buffer| allocator.free(buffer);
                allocator.free(buffers);
            } else {
                allocator.free(values);
            }
            return err;
        };
        @memset(initialized, false);
        return .{
            .values = values,
            .initialized = initialized,
            .backing_buffers = backing_buffers,
            .offset = infra_offset,
            .moved = false,
        };
    }

    fn putOwned(
        self: *Columns,
        allocator: std.mem.Allocator,
        index: usize,
        column: prover_pcs.ColumnEvaluation,
    ) !void {
        if (self.backing_buffers != null) {
            const destination = self.values[index];
            if (destination.log_size != column.log_size or
                destination.values.len != column.values.len)
                return error.InvalidTraceShape;
            @memcpy(@constCast(destination.values), column.values);
            allocator.free(@constCast(column.values));
        } else {
            self.values[index] = column;
        }
        self.initialized[index] = true;
    }

    fn appendOwned(
        self: *Columns,
        allocator: std.mem.Allocator,
        column: prover_pcs.ColumnEvaluation,
    ) !void {
        try self.putOwned(allocator, self.offset, column);
        self.offset += 1;
    }

    fn putCopy(
        self: *Columns,
        allocator: std.mem.Allocator,
        index: usize,
        column: prover_pcs.ColumnEvaluation,
    ) !void {
        if (self.backing_buffers != null) {
            const destination = self.values[index];
            if (destination.log_size != column.log_size or
                destination.values.len != column.values.len)
                return error.InvalidTraceShape;
            @memcpy(@constCast(destination.values), column.values);
        } else {
            self.values[index] = .{
                .log_size = column.log_size,
                .values = try allocator.dupe(M31, column.values),
            };
        }
        self.initialized[index] = true;
    }

    fn appendCopy(
        self: *Columns,
        allocator: std.mem.Allocator,
        column: prover_pcs.ColumnEvaluation,
    ) !void {
        try self.putCopy(allocator, self.offset, column);
        self.offset += 1;
    }

    fn isArenaBacked(self: *const Columns) bool {
        return self.backing_buffers != null;
    }

    fn reserve(
        self: *Columns,
        comptime count: usize,
        log_size: u32,
    ) ![count][]M31 {
        if (!self.isArenaBacked() or self.offset + count > self.values.len)
            return error.InvalidTraceShape;
        var result: [count][]M31 = undefined;
        for (0..count) |index| {
            const destination = self.values[self.offset + index];
            if (destination.log_size != log_size)
                return error.InvalidTraceShape;
            result[index] = @constCast(destination.values);
            self.initialized[self.offset + index] = true;
        }
        self.offset += count;
        return result;
    }

    /// Releases the flags always, and the column buffers only while this array
    /// still owns them: after `moved` the commitment scheme does.
    fn deinit(self: *Columns, allocator: std.mem.Allocator) void {
        if (!self.moved) {
            if (self.backing_buffers) |backing_buffers| {
                allocator.free(self.values);
                for (backing_buffers) |buffer| allocator.free(buffer);
                allocator.free(backing_buffers);
            } else {
                for (self.values, self.initialized) |column, initialized| {
                    if (initialized) allocator.free(@constCast(column.values));
                }
                allocator.free(self.values);
            }
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

    /// A scope measures the whole generation lifetime, including the join. Both
    /// finish and abandonment use this idempotent close so their overlapping
    /// error paths cannot leave the recorder stack open or pop it twice.
    fn joinAndEndScope(self: *OpcodeGeneration) void {
        self.join();
        self.scope.end();
    }

    /// Joins, closes the profile scope, and surfaces the generator's error.
    /// On success the caller owns `workspace.opcode_columns`.
    fn finish(self: *OpcodeGeneration, workspace: *ProofWorkspace) !void {
        self.joinAndEndScope();
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
        self.joinAndEndScope();
        if (self.finished) return;
        if (workspace.opcode_error == null) workspace.releaseOpcodeColumns(allocator);
    }
};

fn expectScopeClosedAsRoot(
    recorder: *stage_profile.Recorder,
    closed_scope_id: []const u8,
) !void {
    var probe = try stage_profile.StageScope.begin(
        recorder,
        "riscv_scope_lifecycle_probe",
        "RISC-V scope lifecycle probe",
    );
    probe.end();

    var profile = try recorder.snapshot(std.testing.allocator);
    defer profile.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), profile.stages.len);
    try std.testing.expectEqualStrings(closed_scope_id, profile.stages[0].id);
    try std.testing.expect(profile.stages[0].children == null);
    try std.testing.expectEqualStrings(
        "riscv_scope_lifecycle_probe",
        profile.stages[1].id,
    );
    try std.testing.expect(profile.stages[1].children == null);
}

test "main trace profiling: infrastructure failure closes its scope" {
    const allocator = std.testing.allocator;
    var recorder = stage_profile.Recorder.init(allocator, "zig", "riscv");
    defer recorder.deinit();

    const workspace = try ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    var columns = try Columns.init(
        allocator,
        program_commitment.N_MAIN_COLUMNS,
        0,
        null,
    );
    defer columns.deinit(allocator);

    var program = try program_commitment.build(
        allocator,
        &.{.{ .pc = 0, .word = 0x00000013 }},
        &.{},
    );
    defer program.deinit(allocator);
    const witness: CommitmentWitness = .{
        .boundary = null,
        .program = program,
        .poseidon_calls = .empty,
        .merkle_rows = .empty,
    };
    const geometry: Geometry = .{
        .program_log_size = 4,
        .merkle_log_size = 4,
        .poseidon_log_size = 4,
        .clock_update_log = 4,
        .merkle_infra_index = 0,
        .poseidon_infra_index = 0,
        .clock_infra_index = 0,
    };
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );

    try std.testing.expectError(
        error.OutOfMemory,
        generateInfrastructure(
            failing.allocator(),
            workspace,
            &columns,
            &witness,
            geometry,
            null,
            &recorder,
        ),
    );
    try expectScopeClosedAsRoot(
        &recorder,
        "riscv_infrastructure_trace_generation",
    );
}

test "main trace profiling: abandoned opcode generation closes its scope" {
    const allocator = std.testing.allocator;
    var recorder = stage_profile.Recorder.init(allocator, "zig", "riscv");
    defer recorder.deinit();
    const workspace = try ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    workspace.opcode_error = error.InjectedOpcodeGenerationFailure;

    var generation: OpcodeGeneration = .{
        .thread = null,
        .scope = try stage_profile.StageScope.begin(
            &recorder,
            "riscv_opcode_trace_generation",
            "RISC-V opcode trace generation (overlapped)",
        ),
        .joined = false,
        .finished = false,
    };
    generation.abandon(workspace, allocator);
    // Cleanup paths can overlap after `finish` reports an opcode error. Closing
    // twice must remain a no-op after the first balanced pop.
    generation.abandon(workspace, allocator);

    try std.testing.expect(generation.joined);
    try std.testing.expect(generation.scope.ended);
    try expectScopeClosedAsRoot(
        &recorder,
        "riscv_opcode_trace_generation",
    );
}
