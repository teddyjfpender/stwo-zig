//! Bounded row work on the prover's existing pool. Each joined wave borrows one
//! evaluated coset; no worker survives scratch reuse. Arithmetic remains in
//! Component.emit, exactly as at OODS points and in serial proving.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const work = engine.work_pool;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const E = @import("../evaluation.zig");
const L = E.L;
const frame = @import("frame.zig");
const component_mod = @import("component.zig");
const Component = component_mod.Component;
const Evaluation = @import("coset_evaluation.zig").Evaluation;
const Column = engine.air.accumulation.ColumnAccumulator;
// Debug's unoptimized extension-field temporaries need a larger frame; the
// production optimized path is qualified with a 256 KiB worker guard.
pub const MIN_STACK_BYTES = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;
pub const MIN_ROWS_PER_WORKER = 64;
pub const WORKER_SCRATCH_BYTES = @sizeOf(Scratch);

/// All fallible shape validation precedes submission. The only subsequent
/// errors are structured lease/submission errors; every submitted helper is
/// drained before returning an error or releasing its contexts.
pub fn evaluatePart(component: *const Component, evaluation: *const Evaluation, part: usize, output: *Column, inverse: M, pool: ?*work.WorkPool) !void {
    try validate(component, evaluation, part, output);
    if (pool) |active| if (active.stackSize() < MIN_STACK_BYTES) return error.InvalidRv64ParallelStack;
    var previous_main: [9]PreviousSource = undefined;
    var previous_interaction: [20]PreviousSource = undefined;
    var n_previous_main: usize = 0;
    var n_previous_interaction: usize = 0;
    for (0..component.mainCount()) |i| if (component.needsPreviousMain(i)) {
        if (n_previous_main == previous_main.len) return error.InvalidRv64ParallelShape;
        previous_main[n_previous_main] = .{ .destination = i, .values = evaluation.previous_values[frame.FIXED + i] };
        n_previous_main += 1;
    };
    const inter_start = frame.FIXED + component.mainCount();
    for (0..component.interactionCount()) |i| if (component.needsPreviousInteraction(i)) {
        if (n_previous_interaction == previous_interaction.len) return error.InvalidRv64ParallelShape;
        previous_interaction[n_previous_interaction] = .{ .destination = i, .values = evaluation.previous_values[inter_start + i] };
        n_previous_interaction += 1;
    };
    const workers = if (pool) |active| @min(active.workerCount(), @max(1, evaluation.size / MIN_ROWS_PER_WORKER)) else 1;
    // Keep row-gather arrays off worker stacks. This one bounded allocation is
    // made by the coordinator; each task owns a disjoint scratch element.
    const scratch = try evaluation.allocator.alloc(Scratch, workers);
    defer evaluation.allocator.free(scratch);
    var jobs: [work.MAX_WORKERS]Job = undefined;
    if (workers == 1) {
        jobs[0] = .{ .component = component, .evaluation = evaluation, .scratch = &scratch[0], .part = part, .output = output.*, .previous_main = previous_main[0..n_previous_main], .previous_interaction = previous_interaction[0..n_previous_interaction], .inverse = inverse, .start = 0, .end = evaluation.size };
        jobs[0].run();
        output.* = jobs[0].output;
        return;
    }
    const active = pool.?;
    var lease = try active.acquire(try work.WorkerBudget.init(workers));
    defer lease.deinit();
    var wait_group = std.Thread.WaitGroup{};
    defer {
        wait_group.wait();
        lease.completeWave();
    }
    // Buckets are zero-initialized by columns(). Per-job additive copies avoid
    // sharing the sequential fresh-index cursor while retaining prior terms.
    output.next_fresh_index = null;
    for (jobs[0..workers], 0..) |*job, i| {
        job.* = .{ .component = component, .evaluation = evaluation, .scratch = &scratch[i], .part = part, .output = output.*, .previous_main = previous_main[0..n_previous_main], .previous_interaction = previous_interaction[0..n_previous_interaction], .inverse = inverse, .start = evaluation.size * i / workers, .end = evaluation.size * (i + 1) / workers };
    }
    for (jobs[1..workers]) |*job| try lease.spawnWg(&wait_group, Job.run, .{job});
    jobs[0].run();
}

const PreviousSource = struct { destination: usize, values: []const M };

const Job = struct {
    component: *const Component,
    evaluation: *const Evaluation,
    scratch: *Scratch,
    part: usize,
    output: Column,
    previous_main: []const PreviousSource,
    previous_interaction: []const PreviousSource,
    inverse: M,
    start: usize,
    end: usize,
    fn run(self: *Job) void {
        const component = self.component;
        const evaluation = self.evaluation;
        const values = evaluation.current_values;
        const main = self.scratch.main[0..component.mainCount()];
        const prior_main = self.scratch.prior_main[0..component.mainCount()];
        const current = self.scratch.current[0..component.interactionCount()];
        const prior = self.scratch.prior[0..component.interactionCount()];
        // Every unshifted prior lane is permanently zero for this worker wave.
        @memset(prior_main[component.plan.main_count..], Q.zero());
        @memset(prior, Q.zero());
        @memset(&self.scratch.logical, Q.zero());
        const main_sources = values[frame.FIXED..][0..component.mainCount()];
        const interaction_sources = values[frame.FIXED + component.mainCount() ..];
        for (self.start..self.end) |row| {
            const prior_row = evaluation.previousRow(self.part, row);
            var fixed: frame.Geometry = undefined;
            for (&fixed, values[0..frame.FIXED]) |*value, source| value.* = Q.fromBase(source[row]);
            for (main, main_sources) |*value, source| value.* = Q.fromBase(source[row]);
            for (self.previous_main) |source| prior_main[source.destination] = Q.fromBase(source.values[prior_row]);
            for (current, interaction_sources) |*value, source| value.* = Q.fromBase(source[row]);
            for (self.previous_interaction) |source| prior[source.destination] = Q.fromBase(source.values[prior_row]);
            var accumulator = E.WeightedAccumulator{ .powers = self.output.random_coeff_powers };
            var sink = E.Sink{ .values = null, .weighted_accumulator = &accumulator };
            component.inflation.apply(main[0..component.plan.main_count], &self.scratch.logical);
            component.emitWithLogical(fixed, main, prior_main, current, prior, &self.scratch.logical, &sink);
            std.debug.assert(sink.count == component.constraint_count);
            self.output.accumulate(evaluation.globalRow(self.part, row), accumulator.accumulation.mulM31(self.inverse));
        }
    }
};

const Scratch = struct {
    logical: E.Main,
    main: [L.MAIN + frame.WIDTH]Q,
    prior_main: [L.MAIN + frame.WIDTH]Q,
    current: [component_mod.MAX_INTERACTION]Q,
    prior: [component_mod.MAX_INTERACTION]Q,
};

fn validate(component: *const Component, evaluation: *const Evaluation, part: usize, output: *const Column) !void {
    const total = frame.FIXED + component.mainCount() + component.interactionCount();
    if (part >= 4 or component.log_size != evaluation.trace_log or evaluation.current_values.len != total or evaluation.previous_values.len != total or evaluation.previous_columns.len != total or output.col.len() != 4 * evaluation.size or output.random_coeff_powers.len != component.constraint_count) return error.InvalidRv64ParallelShape;
    for (evaluation.current_values, evaluation.previous_values, evaluation.previous_columns, 0..) |current, previous, actual, i| {
        const expected = if (i < frame.FIXED) false else if (i < frame.FIXED + component.mainCount()) component.needsPreviousMain(i - frame.FIXED) else component.needsPreviousInteraction(i - frame.FIXED - component.mainCount());
        if (current.len != evaluation.size or actual != expected or (expected and previous.len != evaluation.size)) return error.InvalidRv64ParallelShape;
    }
}
