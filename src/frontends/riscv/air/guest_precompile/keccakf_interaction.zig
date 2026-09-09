//! Parallel, pairs-batched interaction generation for a Keccak-f shard.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_work_pool = @import("stwo_prover_engine").work_pool;
const logup = @import("../logup.zig");
const plan = @import("keccakf_interaction_plan.zig");
const relations_mod = @import("keccakf_relations.zig");
const trace_mod = @import("keccakf_trace.zig");
const witness = @import("keccakf_witness.zig");

pub const column_count: usize = plan.interaction_column_count;
pub const batch_count: usize = plan.batch_count;

pub const Result = struct {
    columns: [column_count][]M31,
    claims: [batch_count]QM31,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        for (self.columns) |column| allocator.free(column);
        self.* = undefined;
    }

    pub fn total(self: *const Result) QM31 {
        var result = QM31.zero();
        for (self.claims) |claim| result = result.add(claim);
        return result;
    }
};

pub fn generate(
    allocator: std.mem.Allocator,
    trace: *const trace_mod.Shard,
    relations: *const relations_mod.Relations,
    pool: *prover_work_pool.WorkPool,
) !Result {
    const generated = try logup.generateParallelColumns(
        batch_count,
        allocator,
        Context{ .trace = trace, .relations = relations },
        trace.log_size,
        pool,
    );
    return .{ .columns = generated.columns, .claims = generated.claims };
}

const Context = struct {
    trace: *const trace_mod.Shard,
    relations: *const relations_mod.Relations,

    pub fn rowPairsAt(self: Context, logical_row: usize) [batch_count]logup.RowPair {
        const main = readMain(self.trace, logical_row);
        const next = readState(
            self.trace,
            (logical_row + 1) % self.trace.domainSize(),
        );
        const caller_output = readState(
            self.trace,
            (logical_row + 27) % self.trace.domainSize(),
        );
        const selectors = readSelectors(self.trace, logical_row);
        return plan.rowPairsBase(
            &main,
            &next,
            &caller_output,
            &selectors,
            self.relations,
        ) catch unreachable;
    }
};

pub fn readMain(
    trace: *const trace_mod.Shard,
    logical_row: usize,
) [trace_mod.Layout.main_columns]M31 {
    var result: [trace_mod.Layout.main_columns]M31 = undefined;
    for (&result, 0..) |*value, column| value.* =
        trace.mainAt(column, logical_row);
    return result;
}

pub fn readState(
    trace: *const trace_mod.Shard,
    logical_row: usize,
) [witness.state_cell_count]M31 {
    var result: [witness.state_cell_count]M31 = undefined;
    for (&result, 0..) |*value, cell| value.* =
        trace.mainAt(trace_mod.Layout.state + cell, logical_row);
    return result;
}

pub fn readSelectors(
    trace: *const trace_mod.Shard,
    logical_row: usize,
) [witness.row_count]M31 {
    var result: [witness.row_count]M31 = undefined;
    const committed = trace_mod.committedRow(logical_row, trace.log_size);
    for (&result, 0..) |*value, group| value.* = trace.preprocessedColumn(
        trace_mod.Layout.row_group + group,
    )[committed];
    return result;
}
