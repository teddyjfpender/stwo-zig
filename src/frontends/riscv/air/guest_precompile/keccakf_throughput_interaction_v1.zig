//! Interaction-column materializer for the throughput Keccak candidate.
//!
//! This consumes the existing byte-identical paired trace and the distinct
//! throughput verifier-program plan.  It is intentionally not wired into the
//! production Ethereum component roster.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_work_pool = @import("stwo_prover_engine").work_pool;
const logup = @import("../logup.zig");
const compact_interaction = @import("keccakf_interaction.zig");
const plan = @import("keccakf_throughput_interaction_plan_v1.zig");
const relations_mod = @import("keccakf_relations.zig");
const trace_mod = @import("keccakf_trace.zig");

pub const production_active = false;
pub const column_count: usize = plan.interaction_column_count;
pub const batch_count: usize = plan.batch_count;

pub const Result = struct {
    columns: [column_count][]M31,
    claims: [batch_count]QM31,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        for (self.columns) |column| allocator.free(column);
        self.* = undefined;
    }

    pub fn permutationTotal(self: *const Result) QM31 {
        var result = QM31.zero();
        for (self.claims[0..plan.permutation_batch_count]) |claim|
            result = result.add(claim);
        return result;
    }

    pub fn callerTotal(self: *const Result) QM31 {
        var result = QM31.zero();
        for (self.claims[plan.permutation_batch_count..]) |claim|
            result = result.add(claim);
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
        const main = compact_interaction.readMain(self.trace, logical_row);
        const next = compact_interaction.readState(
            self.trace,
            (logical_row + 1) % self.trace.domainSize(),
        );
        const caller_output = compact_interaction.readState(
            self.trace,
            (logical_row + 27) % self.trace.domainSize(),
        );
        const selectors = compact_interaction.readSelectors(
            self.trace,
            logical_row,
        );
        return plan.rowPairsBase(
            &main,
            &next,
            &caller_output,
            &selectors,
            self.relations,
        ) catch unreachable;
    }
};

comptime {
    if (column_count != 1_180 or batch_count != 295 or production_active)
        @compileError("Keccak throughput interaction materializer drifted");
}
