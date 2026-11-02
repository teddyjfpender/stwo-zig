//! Bounded row waves over borrowed n-point coset buffers; one joined pool lease.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const C = @import("component.zig");
const L = @import("layout.zig");
const E = @import("equations.zig");
const gather = @import("gather.zig");
const packed_rows = @import("packed_rows.zig");
const Eval = @import("../../full/coset_evaluation.zig").Evaluation;
const sinks = @import("../../evaluation.zig");
const work = engine.work_pool;
const Column = engine.air.accumulation.ColumnAccumulator;
const points = @import("../../../../air/component_point_support.zig");
pub const MIN_STACK = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;
pub fn evaluatePart(component: *const C.Component, evaluation: *const Eval, part: usize, output: *Column, inverse: M, pool: ?*work.WorkPool) !void {
    const parameters_value = component.proverParameters();
    return evaluateParameters(&parameters_value, evaluation, part, output, inverse, pool);
}
pub fn evaluateParameters(component: *const C.Parameters, evaluation: *const Eval, part: usize, output: *Column, inverse: M, pool: ?*work.WorkPool) !void {
    const tiled = if (comptime @import("builtin").is_test) testing.tiled else true;
    const simd = if (comptime @import("builtin").is_test) testing.simd else true;
    return evaluateImpl(component, evaluation, part, output, inverse, pool, tiled, simd);
}
fn evaluateImpl(component: *const C.Parameters, evaluation: *const Eval, part: usize, output: *Column, inverse: M, pool: ?*work.WorkPool, tiled: bool, simd: bool) !void {
    if (part >= 4 or evaluation.trace_log != component.log_size or output.random_coeff_powers.len != component.nConstraints() or output.col.len() != 4 * evaluation.size) return error.InvalidKeccakCosetShape;
    const total = component.fixedCount() + component.mainCount() + component.interactionCount();
    if (evaluation.current_values.len != total or evaluation.previous_values.len != total) return error.InvalidKeccakCosetShape;
    for (evaluation.current_values) |column| if (column.len != evaluation.size) return error.InvalidKeccakCosetShape;
    if (component.kind == .permutation) {
        for (evaluation.previous_values, 0..) |column, c| {
            const main = c >= L.FIXED and c < L.FIXED + L.MAIN;
            const shifted = (main and (c - L.FIXED < L.STATE or c - L.FIXED >= L.ACTIVE_A)) or c >= total - 4;
            if (shifted and column.len != evaluation.size) return error.InvalidKeccakCosetShape;
        }
    } else {
        for (evaluation.previous_values[total - 4 ..]) |column| if (column.len != evaluation.size) return error.InvalidKeccakCosetShape;
    }
    const workers = if (pool) |active| @min(active.workerCount(), @max(1, evaluation.size / 64)) else 1;
    if (pool) |active| if (active.stackSize() < MIN_STACK) return error.InvalidKeccakWorkerStack;
    const scratch = try evaluation.allocator.alloc(WorkerScratch, if (component.kind == .permutation) workers else 0);
    defer evaluation.allocator.free(scratch);
    for (scratch) |*value| value.* = if (simd) .{ .simd = undefined } else .{ .scalar = undefined };
    var jobs: [work.MAX_WORKERS]Job = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .component = component, .evaluation = evaluation, .part = part, .output = output.*, .inverse = inverse, .scratch = if (component.kind == .permutation) &scratch[i] else null, .tiled = tiled, .simd = simd, .start = evaluation.size * i / workers, .end = evaluation.size * (i + 1) / workers };
    if (workers == 1) {
        jobs[0].run();
        output.* = jobs[0].output;
        return;
    }
    var lease = try pool.?.acquire(try work.WorkerBudget.init(workers));
    defer lease.deinit();
    var group = std.Thread.WaitGroup{};
    defer {
        group.wait();
        lease.completeWave();
    }
    output.next_fresh_index = null;
    for (jobs[0..workers]) |*job| job.output.next_fresh_index = null;
    for (jobs[1..workers]) |*job| try lease.spawnWg(&group, Job.run, .{job});
    jobs[0].run();
}
const Job = struct {
    component: *const C.Parameters,
    evaluation: *const Eval,
    part: usize,
    output: Column,
    inverse: M,
    scratch: ?*WorkerScratch,
    tiled: bool,
    simd: bool,
    start: usize,
    end: usize,
    fn run(self: *Job) void {
        const component = self.component;
        const evaluation = self.evaluation;
        const values = evaluation.current_values;
        const fm = component.fixedCount() + component.mainCount();
        if (self.simd) {
            packed_rows.evaluate(component, evaluation, self.part, self.start, self.end, &self.output, self.inverse, if (self.scratch) |scratch| &scratch.simd else null);
            return;
        }
        if (self.tiled and component.kind == .permutation and component.legacy_gather) {
            var start = self.start;
            while (start < self.end) {
                const count = @min(gather.ROWS, self.end - start);
                const rows = self.scratch.?.scalar.rows[0..count];
                gather.fill(evaluation, self.part, start, rows);
                for (rows, 0..) |*row, i| {
                    const prior = row.promote(&self.scratch.?.scalar.arithmetic);
                    self.emitPermutation(&self.scratch.?.scalar.arithmetic, prior, evaluation.globalRow(self.part, start + i));
                }
                start += count;
            }
            return;
        }
        // Retained untiled gather is the exact pre-tile qualification oracle.
        for (self.start..self.end) |r| {
            const global = evaluation.globalRow(self.part, r);
            const prior = evaluation.previousRow(self.part, r);
            var weighted = sinks.WeightedAccumulator{ .powers = self.output.random_coeff_powers };
            var sink = sinks.Sink{ .values = null, .weighted_accumulator = &weighted };
            if (component.kind != .permutation) {
                var tuple: [6]Q = undefined;
                for (&tuple, values[0..6]) |*v, col| v.* = Q.fromBase(col[r]);
                sink.emit(C.tableResidualFor(Q, component, &tuple, Q.fromBase(values[6][r]), Q.fromBase(values[7][r]), points.secureAt(values[8..12], r), points.secureAt(evaluation.previous_values[8..12], prior)));
            } else {
                const scratch = &self.scratch.?.scalar.arithmetic;
                for (&scratch.fixed, values[0..L.FIXED]) |*v, col| v.* = Q.fromBase(col[r]);
                for (&scratch.main, values[L.FIXED..fm]) |*v, col| v.* = Q.fromBase(col[r]);
                for (L.MASK_OFFSETS[1..], 0..) |offset, j| {
                    const shifted = core.utils.offsetBitReversedCircleDomainIndex(global, component.log_size, component.log_size + 2, offset);
                    const target_part = shifted / evaluation.size;
                    std.debug.assert(target_part == self.part or target_part == self.part ^ 1);
                    const sources = if (target_part == self.part) values else evaluation.previous_values;
                    for (&scratch.shifted[j], sources[L.FIXED..][0..L.STATE]) |*v, col| v.* = Q.fromBase(col[shifted % evaluation.size]);
                }
                for (&scratch.previous_header, evaluation.previous_values[L.FIXED + L.ACTIVE_A ..][0..3]) |*v, col| v.* = Q.fromBase(col[prior]);
                for (scratch.interaction[0..component.batches], 0..) |*v, b| v.* = points.secureAt(values[fm + 4 * b ..], r);
                self.emitPermutation(scratch, points.secureAt(evaluation.previous_values[fm + component.interactionCount() - 4 ..], prior), global);
                continue;
            }
            std.debug.assert(sink.count == component.nConstraints());
            self.output.accumulate(global, weighted.accumulation.mulM31(self.inverse));
        }
    }
    fn emitPermutation(self: *Job, scratch: *const C.Scratch, previous: Q, global: usize) void {
        var weighted = sinks.WeightedAccumulator{ .powers = self.output.random_coeff_powers };
        var sink = sinks.Sink{ .values = null, .weighted_accumulator = &weighted };
        self.component.emit_q(scratch.row(), scratch.interaction[0..self.component.batches], previous, self.component.claim, self.component.challenges, .{ .calls = self.component.calls, .first_id = self.component.first_call_id }, &sink);
        std.debug.assert(sink.count == self.component.nConstraints());
        self.output.accumulate(global, weighted.accumulation.mulM31(self.inverse));
    }
};

const WorkerScratch = union { scalar: ScalarScratch, simd: packed_rows.Scratch };
const ScalarScratch = struct {
    arithmetic: C.Scratch align(64),
    rows: [gather.ROWS]gather.Row,
};
pub const WORKER_SCRATCH_BYTES = @sizeOf(WorkerScratch);
pub const NATIVE_TILE_BYTES = @sizeOf([gather.ROWS]gather.Row);
pub const testing = if (@import("builtin").is_test) struct {
    pub const Gather = gather;
    pub const Evaluation = Eval;
    threadlocal var tiled: bool = true;
    threadlocal var simd: bool = true;
    pub const SimdBinding = struct {
        previous: bool,
        pub fn init(enabled: bool) SimdBinding {
            const old = simd;
            simd = enabled;
            return .{ .previous = old };
        }
        pub fn deinit(self: *SimdBinding) void {
            simd = self.previous;
        }
    };
    pub const Binding = struct {
        previous: bool,
        previous_simd: bool,
        pub fn init(enabled: bool) Binding {
            const previous = tiled;
            const previous_simd = simd;
            tiled = enabled;
            if (!enabled) simd = false;
            return .{ .previous = previous, .previous_simd = previous_simd };
        }
        pub fn deinit(self: *Binding) void {
            tiled = self.previous;
            simd = self.previous_simd;
        }
    };
    pub fn evaluateUntiled(component: *const C.Component, evaluation: *const Eval, part: usize, output: *Column, inverse: M, pool: ?*work.WorkPool) !void {
        const parameters_value = component.proverParameters();
        return evaluateImpl(&parameters_value, evaluation, part, output, inverse, pool, false, false);
    }
} else struct {};
