//! Private per-worker narrow row scratch, drained before coset reuse.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const C = @import("component.zig");
const Eval = @import("../../full/coset_evaluation.zig").Evaluation;
const work = engine.work_pool;
const Column = engine.air.accumulation.ColumnAccumulator;
pub const MIN_STACK: usize = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;
pub fn evaluatePart(component: *const C.Component, evaluation: *const Eval, part: usize, output: *Column, inverse: M, pool: ?*work.WorkPool) !void {
    if (part >= 4 or evaluation.trace_log != component.log_size or output.random_coeff_powers.len != component.nConstraints()) return error.InvalidSecpCosetShape;
    if (pool) |active| if (active.stackSize() < MIN_STACK) return error.InvalidSecpWorkerStack;
    const workers = if (pool) |active| @min(active.workerCount(), @max(1, evaluation.size / 64)) else 1;
    const scratch = try evaluation.allocator.alloc(C.Scratch, workers);
    defer evaluation.allocator.free(scratch);
    var jobs: [work.MAX_WORKERS]Job = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .component = component, .evaluation = evaluation, .part = part, .output = output.*, .inverse = inverse, .scratch = &scratch[i], .start = evaluation.size * i / workers, .end = evaluation.size * (i + 1) / workers };
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
    scratch: *C.Scratch,
    start: usize,
    end: usize,
    fn run(self: *Job) void {
        var row = self.start;
        while (row < self.end) : (row += 16) self.component.evaluateRows(self.evaluation, self.part, row, @min(16, self.end - row), &self.output, self.inverse, self.scratch);
    }
};
