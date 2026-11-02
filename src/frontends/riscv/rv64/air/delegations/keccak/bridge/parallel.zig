//! Private per-worker narrow row scratch, drained before coset reuse.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const C = @import("component.zig");
const L = @import("layout.zig");
const E = @import("equations.zig");
const Eval = @import("../../../full/coset_evaluation.zig").Evaluation;
const sinks = @import("../../../evaluation.zig");
const work = engine.work_pool;
const Column = engine.air.accumulation.ColumnAccumulator;
const packed_rows = @import("packed_rows.zig");
const points = @import("../../../../../air/component_point_support.zig");
pub fn evaluatePart(component: *const C.Component, evaluation: *const Eval, part: usize, output: *Column, inverse: M, pool: ?*work.WorkPool) !void {
    const simd = if (comptime @import("builtin").is_test) testing.simd else true;
    return evaluateImpl(component, evaluation, part, output, inverse, pool, simd);
}
fn evaluateImpl(component: *const C.Component, evaluation: *const Eval, part: usize, output: *Column, inverse: M, pool: ?*work.WorkPool, simd: bool) !void {
    if (part >= 4 or evaluation.trace_log != component.log_size or output.random_coeff_powers.len != L.CONSTRAINTS or output.col.len() != 4 * evaluation.size) return error.InvalidKeccakBridgeCosetShape;
    const total = L.FIXED + L.MAIN + L.INTERACTION;
    if (evaluation.current_values.len != total or evaluation.previous_values.len != total) return error.InvalidKeccakBridgeCosetShape;
    for (evaluation.current_values) |column| if (column.len != evaluation.size) return error.InvalidKeccakBridgeCosetShape;
    for (evaluation.previous_values, 0..) |column, c| {
        const previous_main = c >= L.FIXED and c < L.FIXED + L.PREVIOUS_MAIN;
        const header = c >= L.FIXED + L.ACTIVE and c < L.FIXED + L.MAIN;
        if ((previous_main or header or c >= total - 4) and column.len != evaluation.size) return error.InvalidKeccakBridgeCosetShape;
    }
    if (pool) |active| if (active.stackSize() < @import("../parallel.zig").MIN_STACK) return error.InvalidKeccakWorkerStack;
    const workers = if (pool) |active| @min(active.workerCount(), @max(1, evaluation.size / 64)) else 1;
    const scratch = try evaluation.allocator.alloc(WorkerScratch, workers);
    defer evaluation.allocator.free(scratch);
    for (scratch) |*value| value.* = if (simd) .{ .simd = undefined } else .{ .scalar = undefined };
    var jobs: [work.MAX_WORKERS]Job = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .component = component, .evaluation = evaluation, .part = part, .output = output.*, .inverse = inverse, .scratch = &scratch[i], .simd = simd, .start = evaluation.size * i / workers, .end = evaluation.size * (i + 1) / workers };
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
    component: *const C.Component,
    evaluation: *const Eval,
    part: usize,
    output: Column,
    inverse: M,
    scratch: *WorkerScratch,
    simd: bool,
    start: usize,
    end: usize,
    fn run(self: *Job) void {
        const component = self.component;
        const evaluation = self.evaluation;
        const values = evaluation.current_values;
        if (self.simd) {
            packed_rows.evaluate(component, evaluation, self.part, self.start, self.end, &self.output, self.inverse, &self.scratch.simd);
            return;
        }
        const scratch = &self.scratch.scalar;
        const fm = L.FIXED + L.MAIN;
        for (self.start..self.end) |r| {
            const prior = evaluation.previousRow(self.part, r);
            for (&scratch.fixed, values[0..L.FIXED]) |*v, col| v.* = Q.fromBase(col[r]);
            for (&scratch.main, values[L.FIXED..fm]) |*v, col| v.* = Q.fromBase(col[r]);
            for (&scratch.previous, evaluation.previous_values[L.FIXED..][0..L.PREVIOUS_MAIN]) |*v, col| v.* = Q.fromBase(col[prior]);
            for (&scratch.previous_header, evaluation.previous_values[L.FIXED + L.ACTIVE ..][0..2]) |*v, col| v.* = Q.fromBase(col[prior]);
            for (&scratch.interaction, 0..) |*v, b| v.* = points.secureAt(values[fm + 4 * b ..], r);
            var weighted = sinks.WeightedAccumulator{ .powers = self.output.random_coeff_powers };
            var sink = sinks.Sink{ .values = null, .weighted_accumulator = &weighted };
            E.emit(scratch.row(), &scratch.interaction, points.secureAt(evaluation.previous_values[fm + L.INTERACTION - 4 ..], prior), component.claim, component.challenges, .{ .calls = component.calls, .first_id = component.first_call_id }, &sink);
            std.debug.assert(sink.count == L.CONSTRAINTS);
            self.output.accumulate(evaluation.globalRow(self.part, r), weighted.accumulation.mulM31(self.inverse));
        }
    }
};

const WorkerScratch = union { scalar: C.Scratch, simd: C.ScratchFor(sinks.PackedBase) };
pub const WORKER_SCRATCH_BYTES = @sizeOf(WorkerScratch);
pub const testing = if (@import("builtin").is_test) struct {
    threadlocal var simd = true;
    pub const Binding = struct {
        previous: bool,
        pub fn init(enabled: bool) Binding {
            const previous = simd;
            simd = enabled;
            return .{ .previous = previous };
        }
        pub fn deinit(self: *Binding) void {
            simd = self.previous;
        }
    };
    pub fn evaluateScalar(component: *const C.Component, evaluation: *const Eval, part: usize, output: *Column, inverse: M, pool: ?*work.WorkPool) !void {
        return evaluateImpl(component, evaluation, part, output, inverse, pool, false);
    }
} else struct {};
