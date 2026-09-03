//! Infrastructure generation, column ownership, and overlapped opcode support.

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
const native_provider_omit = @import("memory_provider_shards/native_provider_omit_v1.zig");

const M31 = m31.M31;
const CommitmentWitness = commitment_witness.CommitmentWitness;
const Geometry = statement_geometry.Geometry;
const ProofWorkspace = proof_workspace.ProofWorkspace;
const ProverError = types.ProverError;
const RunMode = types.RunMode;
const computeLogSize = statement_validation.computeLogSize;

/// Main-trace buffers that outlive their own commitment.
///
pub fn publishMainWitnessWorkReceipt(
    recorder: ?*stage_profile.Recorder,
    receipt: main_witness_work.Receipt,
) !void {
    const active = recorder orelse unreachable;
    const work = active.workCaptureRecorder() orelse unreachable;
    try work.recordCompletedDelta(receipt.delta());
}

pub const PoseidonWorkCapture = struct {
    authority: poseidon_witness_work.Authority,
    completed: poseidon_witness_work.Shard,

    pub fn init(witness: *const CommitmentWitness) !?PoseidonWorkCapture {
        const completed = witness.poseidonWorkShard() orelse return null;
        const authority = poseidon_witness_work.Authority.init();
        try completed.validate(&authority);
        if (completed.counts.base_air_rows != 0 or
            completed.counts.guest_provider_preflight_rows != 0 or
            completed.counts.guest_provider_materialization_rows != 0 or
            completed.counts.legacy_common_traces != 0)
        {
            return error.InvalidPoseidonWorkReceipt;
        }
        return .{ .authority = authority, .completed = completed };
    }

    pub fn sealAndPublish(
        self: *PoseidonWorkCapture,
        recorder: ?*stage_profile.Recorder,
        expected_base_rows: usize,
        expected_guest_rows: usize,
    ) !void {
        const expected_base: u64 = @intCast(expected_base_rows);
        const expected_guest: u64 = @intCast(expected_guest_rows);
        if (self.completed.counts.base_air_rows != expected_base or
            self.completed.counts.guest_provider_preflight_rows != expected_guest or
            self.completed.counts.guest_provider_materialization_rows != expected_guest or
            self.completed.counts.legacy_common_traces != 0)
        {
            return error.InvalidPoseidonWorkReceipt;
        }
        try publishPoseidonWorkReceipt(
            recorder,
            try poseidon_witness_work.seal(&self.authority, self.completed),
        );
    }
};

pub fn publishPoseidonWorkReceipt(
    recorder: ?*stage_profile.Recorder,
    receipt: poseidon_witness_work.Receipt,
) !void {
    poseidon_witness_work.publish(recorder, receipt) catch |err| return switch (err) {
        error.PoseidonWorkRecorderMissing => error.PoseidonWorkCaptureRecorderMissing,
        else => err,
    };
}

/// The infrastructure half of Tree 1, in registry order.
pub fn generateInfrastructure(
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

/// Provider-externalized infrastructure generation. The typed geometry has no
/// Poseidon member, so this path cannot accidentally allocate or materialize
/// the native 445-column provider. Ordinary generation above is unchanged.
pub fn generateInfrastructureWithoutNativePoseidon(
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    columns: *Columns,
    witness: *const CommitmentWitness,
    geometry: native_provider_omit.ProjectedGeometryV1,
    opt_chain: ?*const state_chain.StateChainTracker,
    recorder: ?*stage_profile.Recorder,
) !void {
    var stage = try stage_profile.StageScope.begin(
        recorder,
        "riscv_infrastructure_trace_generation_without_native_poseidon",
        "RISC-V infrastructure trace generation with external Poseidon provider",
    );
    defer stage.end();
    const projected = projectedLegacyGeometry(geometry);
    try appendProgramColumns(allocator, columns, witness, projected);
    try appendMemoryColumns(allocator, workspace, columns, witness);
    try appendMerkleColumns(allocator, columns, witness, projected);
    try appendClockColumns(allocator, workspace, columns, projected, opt_chain);
}

/// Exact-work sibling of `generateInfrastructure`. The ordinary route remains
/// unchanged; receipt construction is selected once per profiled proof and
/// occurs only after every infrastructure column completed successfully.
pub fn generateInfrastructureWithPoseidonWorkReceipt(
    allocator: std.mem.Allocator,
    workspace: *ProofWorkspace,
    columns: *Columns,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    opt_chain: ?*const state_chain.StateChainTracker,
    recorder: ?*stage_profile.Recorder,
    authority: *const poseidon_witness_work.Authority,
) !poseidon_witness_work.ProducerReceipt {
    var stage = try stage_profile.StageScope.begin(
        recorder,
        "riscv_infrastructure_trace_generation",
        "RISC-V infrastructure trace generation",
    );
    defer stage.end();
    try appendProgramColumns(allocator, columns, witness, geometry);
    try appendMemoryColumns(allocator, workspace, columns, witness);
    try appendMerkleColumns(allocator, columns, witness, geometry);
    const receipt = try appendPoseidonColumnsWithWorkReceipt(
        allocator,
        columns,
        witness,
        geometry,
        authority,
    );
    try appendClockColumns(allocator, workspace, columns, geometry, opt_chain);
    return receipt;
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
    const rows = witness.memoryBoundaryRows();
    if (rows.len == 0) return;
    var row_start: usize = 0;
    for (workspace.memory_shard_lengths[0..workspace.memory_shard_count]) |shard_len| {
        const log_size = @max(computeLogSize(shard_len), 4);
        const generated = try memory_trace.generate(
            allocator,
            rows[row_start..][0..shard_len],
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

fn appendPoseidonColumnsWithWorkReceipt(
    allocator: std.mem.Allocator,
    columns: *Columns,
    witness: *const CommitmentWitness,
    geometry: Geometry,
    authority: *const poseidon_witness_work.Authority,
) !poseidon_witness_work.ProducerReceipt {
    if (columns.isArenaBacked()) {
        var destinations = try columns.reserve(
            poseidon2_air.N_MAIN_COLUMNS,
            geometry.poseidon_log_size,
        );
        return poseidon2_air.generateMainIntoWithWorkReceipt(
            allocator,
            &destinations,
            witness.poseidonCalls(),
            geometry.poseidon_log_size,
            authority,
        );
    }
    const generated = try poseidon2_air.generateMainWithWorkReceipt(
        allocator,
        witness.poseidonCalls(),
        geometry.poseidon_log_size,
        authority,
    );
    for (0..poseidon2_air.N_MAIN_COLUMNS) |column| {
        try columns.appendOwned(allocator, .{
            .log_size = geometry.poseidon_log_size,
            .values = generated.columns.values[column],
        });
    }
    return generated.receipt;
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

/// Adapter kept private to the omission-aware generator. The impossible
/// Poseidon slot is never observed because that generator does not call
/// `appendPoseidonColumns`.
fn projectedLegacyGeometry(
    geometry: native_provider_omit.ProjectedGeometryV1,
) Geometry {
    return .{
        .program_log_size = geometry.program_log_size,
        .merkle_log_size = geometry.merkle_log_size,
        .poseidon_log_size = 0,
        .clock_update_log = geometry.clock_update_log,
        .merkle_infra_index = geometry.merkle_infra_index,
        .poseidon_infra_index = std.math.maxInt(usize),
        .clock_infra_index = geometry.clock_infra_index,
    };
}

/// Adds the non-opcode multiplicity requests to the counters ingested from the
/// opcode buffers, so one counter set covers every committed lookup.
pub fn registerLookupSources(
    lookup_source: *lookup_sources.Result,
    witness: *const CommitmentWitness,
    workspace: *const ProofWorkspace,
) !void {
    try lookup_sources.registerProgram(&lookup_source.counters, witness.program.rows);
    const boundary_rows = witness.memoryBoundaryRows();
    if (boundary_rows.len != 0)
        try lookup_sources.registerMemoryBoundary(
            &lookup_source.counters,
            boundary_rows,
        );
    var clock_views: [clock_update_interaction.N_MAIN_COLUMNS][]const M31 = undefined;
    for (&clock_views, workspace.clock_main) |*view, column| view.* = column;
    try clock_update_interaction.registerRangeCheckCounters(
        &lookup_source.counters,
        &clock_views,
    );
}

pub fn appendLookupColumns(
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
pub fn copyOpcodeColumns(
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
pub const Columns = struct {
    values: []prover_pcs.ColumnEvaluation,
    initialized: []bool,
    /// Present when generation writes into one backend-shaped arena from the
    /// outset. Transferred alongside `values`.
    backing_buffers: ?[][]M31,
    /// Next infrastructure slot. Opcode slots are addressed absolutely.
    offset: usize,
    moved: bool,

    pub fn init(
        allocator: std.mem.Allocator,
        n_main: usize,
        infra_offset: usize,
        arena_statement: ?*const types.RiscVStatement,
        arena_extension: ?*const guest_statement.ExtensionStatement,
    ) !Columns {
        if (arena_extension != null and arena_statement == null)
            return error.InvalidTraceShape;
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
            if (arena_extension) |extension| {
                for (extension.components) |desc| {
                    for (0..desc.main_columns) |_| {
                        if (index == log_sizes.len)
                            return error.InvalidTraceShape;
                        log_sizes[index] = desc.log_size;
                        index += 1;
                    }
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

    pub fn putOwned(
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

    pub fn appendOwned(
        self: *Columns,
        allocator: std.mem.Allocator,
        column: prover_pcs.ColumnEvaluation,
    ) !void {
        try self.putOwned(allocator, self.offset, column);
        self.offset += 1;
    }

    pub fn putCopy(
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

    pub fn appendCopy(
        self: *Columns,
        allocator: std.mem.Allocator,
        column: prover_pcs.ColumnEvaluation,
    ) !void {
        try self.putCopy(allocator, self.offset, column);
        self.offset += 1;
    }

    pub fn isArenaBacked(self: *const Columns) bool {
        return self.backing_buffers != null;
    }

    pub fn reserve(
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

    pub fn reserveGuestAt(
        self: *Columns,
        allocator: std.mem.Allocator,
        start: usize,
        log_size: u32,
    ) !guest_main_trace.MainDestinations {
        const count = guest_main_trace.main_column_count;
        if (start > self.values.len or count > self.values.len - start or
            log_size >= @bitSizeOf(usize))
        {
            return error.InvalidTraceShape;
        }
        for (self.initialized[start .. start + count]) |initialized| {
            if (initialized) return error.InvalidTraceShape;
        }

        const domain_size = @as(usize, 1) << @intCast(log_size);
        var initialized_count: usize = 0;
        errdefer if (!self.isArenaBacked()) {
            for (start..start + initialized_count) |index| {
                allocator.free(@constCast(self.values[index].values));
                self.initialized[index] = false;
            }
        };
        for (start..start + count) |index| {
            if (self.isArenaBacked()) {
                const destination = self.values[index];
                if (destination.log_size != log_size or
                    destination.values.len != domain_size)
                {
                    return error.InvalidTraceShape;
                }
            } else {
                self.values[index] = .{
                    .log_size = log_size,
                    .values = try allocator.alloc(M31, domain_size),
                };
                initialized_count += 1;
            }
            self.initialized[index] = true;
        }

        var result: guest_main_trace.MainDestinations = undefined;
        for (&result.caller, 0..) |*destination, index| {
            destination.* = @constCast(self.values[start + index].values);
        }
        const provider_start = start + guest_main_trace.caller_main_column_count;
        for (&result.provider, 0..) |*destination, index| {
            destination.* = @constCast(self.values[provider_start + index].values);
        }
        return result;
    }

    pub fn allInitialized(self: *const Columns) bool {
        for (self.initialized) |initialized| if (!initialized) return false;
        return true;
    }

    /// Releases the flags always, and the column buffers only while this array
    /// still owns them: after `moved` the commitment scheme does.
    pub fn deinit(self: *Columns, allocator: std.mem.Allocator) void {
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
pub const OpcodeGeneration = struct {
    thread: ?std.Thread,
    scope: stage_profile.StageScope,
    joined: bool,
    finished: bool,

    pub fn begin(
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
    pub fn finish(self: *OpcodeGeneration, workspace: *ProofWorkspace) !void {
        self.joinAndEndScope();
        if (workspace.opcode_error) |err| return err;
        self.finished = true;
    }

    /// Failure path. Releases the generated columns only when generation
    /// succeeded and ownership never reached the caller; a failed generator
    /// already unwound its own partial state.
    pub fn abandon(
        self: *OpcodeGeneration,
        workspace: *ProofWorkspace,
        allocator: std.mem.Allocator,
    ) void {
        self.joinAndEndScope();
        if (self.finished) return;
        if (workspace.opcode_error == null) workspace.releaseOpcodeColumns(allocator);
    }
};
