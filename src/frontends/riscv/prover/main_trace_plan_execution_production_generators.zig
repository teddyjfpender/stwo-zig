//! Allocation-free adapters for the production Tree-1 row generators.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const task_graph = @import("stwo_prover_engine").task_graph;
const clock_update_interaction = @import("../air/clock_update_interaction.zig");
const lookup_counter = @import("../air/lookups/tables/counter.zig");
const source_ingest = @import("../air/lookups/tables/source_ingest.zig");
const memory_boundary = @import("../air/memory_commitment/boundary.zig");
const memory_interaction = @import("../air/memory_commitment/interaction.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_commitment = @import("../air/program/commitment.zig");
const program_interaction = @import("../air/program/interaction.zig");
const semantic_eval = @import("../air/semantic_eval.zig");
const statement_mod = @import("../air/statement.zig");
const profile = @import("../isa/profile.zig");
const state_chain = @import("../runner/state_chain.zig");
const trace_mod = @import("../runner/trace.zig");
const infra = @import("../infra_trace.zig");
const main_witness_work = @import("main_witness_work.zig");
const poseidon_witness_work = @import("poseidon_witness_work.zig");
const plan_mod = @import("main_trace_plan.zig");

const CANCEL_POLL_MASK: usize = 4095;

pub fn fillOpcodeChunk(
    component_columns: *[statement_mod.MAX_COMPONENTS][trace_mod.MAX_FAMILY_COLUMNS][]M31,
    component_placements: *const [statement_mod.MAX_COMPONENTS]infra.BitReversalTable,
    first_component: *const [trace_mod.N_FAMILIES]usize,
    family_component_counts: *const [trace_mod.N_FAMILIES]usize,
    family_offsets: [trace_mod.N_FAMILIES]usize,
    rows: []const trace_mod.TraceRow,
    proof_opcodes: []const trace_mod.ProofOpcode,
    counters: *lookup_counter.Set,
    context: *task_graph.TaskContext,
) !bool {
    if (rows.len != proof_opcodes.len) return error.InvalidProductionInput;
    var offsets = family_offsets;
    for (rows, proof_opcodes, 0..) |row, proof_opcode, index| {
        if ((index & CANCEL_POLL_MASK) == 0 and context.isCancelled()) {
            return false;
        }
        const family = trace_mod.opcodeFamily(proof_opcode);
        const family_index = @intFromEnum(family);
        const family_row = offsets[family_index];
        offsets[family_index] += 1;
        const shard_index = family_row / plan_mod.OPCODE_ROWS_PER_CHUNK;
        if (shard_index >= family_component_counts[family_index]) {
            return error.InvalidProductionInput;
        }
        const component_index = first_component[family_index] + shard_index;
        const logical_row = family_row -
            shard_index * plan_mod.OPCODE_ROWS_PER_CHUNK;
        const committed_row = component_placements[component_index].map(
            logical_row,
        );
        trace_mod.validateFamilyRow(row, family) catch
            return error.InvalidSemanticWitness;
        trace_mod.fillFamilyColumns(
            &component_columns[component_index],
            committed_row,
            row,
            family,
        );
        try source_ingest.registerGeneratedCommittedRow(
            family,
            &component_columns[component_index],
            committed_row,
            counters,
        );
    }
    return true;
}

/// Profiled sibling of the branch-free ordinary row loop. Work is derived only
/// after the producer completed, so a cancelled/failed shard cannot escape.
pub fn fillOpcodeChunkProfiled(
    component_columns: *[statement_mod.MAX_COMPONENTS][trace_mod.MAX_FAMILY_COLUMNS][]M31,
    component_placements: *const [statement_mod.MAX_COMPONENTS]infra.BitReversalTable,
    first_component: *const [trace_mod.N_FAMILIES]usize,
    family_component_counts: *const [trace_mod.N_FAMILIES]usize,
    family_offsets: [trace_mod.N_FAMILIES]usize,
    rows: []const trace_mod.TraceRow,
    proof_opcodes: []const trace_mod.ProofOpcode,
    counters: *lookup_counter.Set,
    work_authority: *const main_witness_work.Authority,
    work: *main_witness_work.Shard,
    context: *task_graph.TaskContext,
) !bool {
    const completed = try fillOpcodeChunk(
        component_columns,
        component_placements,
        first_component,
        family_component_counts,
        family_offsets,
        rows,
        proof_opcodes,
        counters,
        context,
    );
    if (!completed) return false;
    for (rows, proof_opcodes) |row, proof_opcode| {
        try work.observeOpcodeRow(
            work_authority,
            trace_mod.opcodeFamily(proof_opcode),
            row,
        );
    }
    return true;
}

pub fn fillProgram(
    columns: *[program_commitment.N_MAIN_COLUMNS][]M31,
    rows: []const program_commitment.Row,
    placement: infra.BitReversalTable,
    work: ?*main_witness_work.Shard,
    context: *task_graph.TaskContext,
) !bool {
    if (rows.len > columns[0].len) return error.InvalidProductionInput;
    for (rows, 0..) |row, logical_row| {
        if ((logical_row & CANCEL_POLL_MASK) == 0 and context.isCancelled()) {
            return false;
        }
        try profile.requireProgramWordAddress(row.addr);
        const dst = placement.map(logical_row);
        columns[0][dst] = M31.one();
        columns[1][dst] = M31.fromU64(row.addr);
        for (row.values, 0..) |value, limb| {
            columns[2 + limb][dst] = M31.fromU64(value);
        }
        columns[6][dst] = M31.fromU64(row.multiplicity);
        columns[7][dst] = M31.fromU64(row.root);
        const word_address = row.addr >> 2;
        columns[8][dst] = M31.fromU64(word_address & ((@as(u32, 1) << 20) - 1));
        columns[9][dst] = M31.fromU64(word_address >> 20);
    }
    if (work) |shard| try shard.observeInfrastructure(.program, rows.len);
    return true;
}

pub fn fillMemory(
    columns: *[8][]M31,
    rows: []const memory_boundary.Row,
    placement: infra.BitReversalTable,
    work: ?*main_witness_work.Shard,
    context: *task_graph.TaskContext,
) !bool {
    if (rows.len > columns[0].len) return error.InvalidProductionInput;
    for (rows, 0..) |row, logical_row| {
        if ((logical_row & CANCEL_POLL_MASK) == 0 and context.isCancelled()) {
            return false;
        }
        const dst = placement.map(logical_row);
        columns[0][dst] = M31.fromU64(row.addr);
        columns[1][dst] = M31.fromU64(row.clock);
        for (row.value, 0..) |value, limb| {
            columns[2 + limb][dst] = M31.fromU64(value);
        }
        columns[6][dst] = row.multiplicity;
        columns[7][dst] = M31.fromU64(row.root);
    }
    if (work) |shard| try shard.observeInfrastructure(.memory, rows.len);
    return true;
}

pub fn fillMerkle(
    columns: *[merkle_node.N_MAIN_COLUMNS][]M31,
    rows: []const merkle_node.NodeRow,
    placement: infra.BitReversalTable,
    work: ?*main_witness_work.Shard,
    context: *task_graph.TaskContext,
) !bool {
    if (rows.len > columns[0].len) return error.InvalidProductionInput;
    for (rows, 0..) |row, logical_row| {
        if ((logical_row & CANCEL_POLL_MASK) == 0 and context.isCancelled()) {
            return false;
        }
        const dst = placement.map(logical_row);
        const values = [_]M31{
            M31.one(),
            M31.fromU64(row.index),
            M31.fromU64(row.depth),
            M31.fromU64(row.lhs),
            M31.fromU64(row.rhs),
            M31.fromU64(row.cur),
            M31.fromU64(row.lhs_mult),
            M31.fromU64(row.rhs_mult),
            M31.fromU64(row.cur_mult),
            M31.fromU64(row.root),
        };
        for (values, columns) |value, column| column[dst] = value;
    }
    if (work) |shard| try shard.observeInfrastructure(.merkle, rows.len);
    return true;
}

/// `rows` owns committed destination rows, not logical call rows. This keeps
/// workers on disjoint cache-line runs while preserving canonical placement.
pub fn fillPoseidonRange(
    columns: *[poseidon2_air.N_MAIN_COLUMNS][]M31,
    calls: []const poseidon2_air.Call,
    inverse_placement: []const usize,
    rows: plan_mod.RowRange,
    context: *task_graph.TaskContext,
) !bool {
    const start: usize = @intCast(rows.start);
    const end: usize = @intCast(try rows.end());
    if (end > inverse_placement.len or columns[0].len != inverse_placement.len) {
        return error.InvalidProductionInput;
    }
    for (start..end) |committed_row| {
        if (((committed_row - start) & CANCEL_POLL_MASK) == 0 and
            context.isCancelled())
        {
            return false;
        }
        const logical_row = inverse_placement[committed_row];
        if (logical_row >= calls.len) continue;
        const values = poseidon2_air.fill(calls[logical_row]);
        for (values, columns) |value, column| {
            column[committed_row] = value;
        }
    }
    return true;
}

pub const PoseidonRangeWorkResult = struct {
    completed: bool,
    receipt: ?poseidon_witness_work.ProducerReceipt,
};

/// Profiled sibling of `fillPoseidonRange`.  It keeps the active-call tally in
/// the already-required committed-row walk; cancellation returns no receipt,
/// and the coordinator cannot aggregate partial worker progress.
pub fn fillPoseidonRangeWithWorkReceipt(
    columns: *[poseidon2_air.N_MAIN_COLUMNS][]M31,
    calls: []const poseidon2_air.Call,
    inverse_placement: []const usize,
    rows: plan_mod.RowRange,
    authority: *const poseidon_witness_work.Authority,
    context: *task_graph.TaskContext,
) !PoseidonRangeWorkResult {
    try authority.validate();
    const start: usize = @intCast(rows.start);
    const end: usize = @intCast(try rows.end());
    if (end > inverse_placement.len or columns[0].len != inverse_placement.len) {
        return error.InvalidProductionInput;
    }
    var completed_rows: u64 = 0;
    for (start..end) |committed_row| {
        if (((committed_row - start) & CANCEL_POLL_MASK) == 0 and
            context.isCancelled())
        {
            return .{ .completed = false, .receipt = null };
        }
        const logical_row = inverse_placement[committed_row];
        if (logical_row >= calls.len) continue;
        const values = poseidon2_air.fill(calls[logical_row]);
        for (values, columns) |value, column| {
            column[committed_row] = value;
        }
        completed_rows = std.math.add(u64, completed_rows, 1) catch
            return error.PoseidonWorkOverflow;
    }
    return .{
        .completed = true,
        .receipt = try poseidon_witness_work.complete(
            authority,
            .base_air_row_materialization,
            completed_rows,
        ),
    };
}

pub fn fillClock(
    columns: *[infra.CLOCK_UPDATE_COLS][]M31,
    retained: *[infra.CLOCK_UPDATE_COLS][]M31,
    chain: ?*const state_chain.StateChainTracker,
    placement: infra.BitReversalTable,
    expected_rows: usize,
    work: ?*main_witness_work.Shard,
    context: *task_graph.TaskContext,
) !bool {
    const reg_updates = if (chain) |tracker| tracker.clock_updates_reg.items else &.{};
    const mem_updates = if (chain) |tracker| tracker.clock_updates_mem.items else &.{};
    if (reg_updates.len + mem_updates.len != expected_rows or
        expected_rows > columns[0].len)
    {
        return error.InvalidProductionInput;
    }
    var logical_row: usize = 0;
    for (reg_updates) |update| {
        if ((logical_row & CANCEL_POLL_MASK) == 0 and context.isCancelled()) {
            return false;
        }
        placeClockRow(columns, retained, placement.map(logical_row), 0, update);
        logical_row += 1;
    }
    for (mem_updates) |update| {
        if ((logical_row & CANCEL_POLL_MASK) == 0 and context.isCancelled()) {
            return false;
        }
        placeClockRow(columns, retained, placement.map(logical_row), 1, update);
        logical_row += 1;
    }
    if (work) |shard| try shard.observeInfrastructure(
        .clock_update,
        expected_rows,
    );
    return true;
}

pub fn auditOpcode(
    columns: *const [trace_mod.MAX_FAMILY_COLUMNS][]M31,
    family: trace_mod.OpcodeFamily,
    n_columns: usize,
    n_real_rows: usize,
    placement: infra.BitReversalTable,
    work_authority: ?*const main_witness_work.Authority,
    work: ?*main_witness_work.Shard,
    context: *task_graph.TaskContext,
) !bool {
    var sampled: [trace_mod.MAX_FAMILY_COLUMNS]semantic_eval.BaseScalar =
        undefined;
    for (0..placement.mapping.len) |logical_row| {
        if ((logical_row & CANCEL_POLL_MASK) == 0 and context.isCancelled()) {
            return false;
        }
        const committed_row = placement.map(logical_row);
        for (sampled[0..n_columns], columns[0..n_columns]) |*value, column| {
            value.* = .fromBase(column[committed_row]);
        }
        const evaluation = try semantic_eval.BaseEval.evaluate(
            family,
            sampled[0..n_columns],
            if (logical_row < n_real_rows)
                semantic_eval.BaseScalar.one()
            else
                semantic_eval.BaseScalar.zero(),
        );
        if (!evaluation.allZero()) return error.InvalidSemanticWitness;
    }
    if (work) |shard| try shard.observeAudit(
        work_authority orelse return error.InvalidMainWitnessWorkAuthority,
        family,
        placement.mapping.len,
    );
    return true;
}

pub fn seedLookups(
    counters: *lookup_counter.Set,
    program_rows: []const program_commitment.Row,
    memory_rows: []const memory_boundary.Row,
    clock_columns: *const [infra.CLOCK_UPDATE_COLS][]M31,
    clock_active_rows: usize,
    work_authority: ?*const main_witness_work.Authority,
    work: ?*main_witness_work.Shard,
    context: *task_graph.TaskContext,
) !bool {
    for (program_rows, 0..) |row, index| {
        if ((index & CANCEL_POLL_MASK) == 0 and context.isCancelled()) {
            return false;
        }
        const entries = program_interaction.entriesFromRow(row);
        try counters.registerList(entries);
    }
    for (memory_rows, 0..) |row, index| {
        if ((index & CANCEL_POLL_MASK) == 0 and context.isCancelled()) {
            return false;
        }
        const entries = memory_interaction.entriesFromRow(row);
        try counters.registerList(entries);
    }
    var sampled: [infra.CLOCK_UPDATE_COLS]QM31 = undefined;
    for (0..clock_columns[0].len) |committed_row| {
        if ((committed_row & CANCEL_POLL_MASK) == 0 and context.isCancelled()) {
            return false;
        }
        for (clock_columns, &sampled) |column, *value| {
            value.* = QM31.fromBase(column[committed_row]);
        }
        const row = try clock_update_interaction.Row.fromMain(&sampled);
        const entries = clock_update_interaction.orderedEntries(row);
        try counters.registerList(entries);
    }
    if (work) |shard| try shard.observeSeed(
        work_authority orelse return error.InvalidMainWitnessWorkAuthority,
        program_rows.len,
        memory_rows.len,
        clock_columns[0].len,
        clock_active_rows,
    );
    return true;
}

pub fn fillLookup(
    destination: []M31,
    counter: *const lookup_counter.Counter,
    placement: infra.BitReversalTable,
    context: *task_graph.TaskContext,
) !bool {
    if (destination.len != counter.values.len or
        placement.mapping.len != destination.len)
    {
        return error.InvalidProductionInput;
    }
    for (counter.values, 0..) |value, logical_row| {
        if ((logical_row & CANCEL_POLL_MASK) == 0 and context.isCancelled()) {
            return false;
        }
        destination[placement.map(logical_row)] = value;
    }
    return true;
}

fn placeClockRow(
    columns: *[infra.CLOCK_UPDATE_COLS][]M31,
    retained: *[infra.CLOCK_UPDATE_COLS][]M31,
    dst: usize,
    address_space: u32,
    update: state_chain.ClockUpdate,
) void {
    const low_mask = (@as(u32, 1) << state_chain.CLOCK_PREV_LOW_BITS) - 1;
    const limbs = update.valueLimbs();
    const values = [_]M31{
        M31.one(),
        M31.fromU64(address_space),
        M31.fromU64(update.addr & 0x7fff_ffff),
        M31.fromU64(update.clk_prev),
        limbs[0],
        limbs[1],
        limbs[2],
        limbs[3],
        M31.fromU64(update.clk_prev & low_mask),
        M31.fromU64(update.clk_prev >> state_chain.CLOCK_PREV_LOW_BITS),
    };
    for (values, columns, retained) |value, main, copy| {
        main[dst] = value;
        copy[dst] = value;
    }
}
