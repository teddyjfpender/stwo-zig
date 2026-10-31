//! Private per-worker narrow row scratch, drained before coset reuse.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const C = @import("component.zig");
const L = @import("layout.zig");
const E = @import("equations.zig");
const Eval = @import("../../../full/coset_evaluation.zig").Evaluation;
const sinks = @import("../../../evaluation.zig");
const work = engine.work_pool;
const Column = engine.air.accumulation.ColumnAccumulator;
pub fn evaluatePart(component: *const C.Component, evaluation: *const Eval, part: usize, output: *Column, inverse: M, pool: ?*work.WorkPool) !void {
    if (part >= 4 or evaluation.trace_log != component.log_size or output.random_coeff_powers.len != L.CONSTRAINTS) return error.InvalidSecpBridgeCosetShape;
    if (pool) |active| if (active.stackSize() < @import("../parallel.zig").MIN_STACK) return error.InvalidSecpWorkerStack;
    const workers = if (pool) |active| @min(active.workerCount(), @max(1, evaluation.size / 64)) else 1;
    const scratch = try evaluation.allocator.alloc(C.PackedScratch, workers);
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
    scratch: *C.PackedScratch,
    start: usize,
    end: usize,
    fn run(self: *Job) void {
        const component = self.component;
        const evaluation = self.evaluation;
        const values = evaluation.current_values;
        const scratch = self.scratch;
        const fm = L.FIXED + L.MAIN;
        const D = @import("../packed_domain.zig");
        var r = self.start;
        while (r < self.end) : (r += D.LANES) {
            const count = @min(D.LANES, self.end - r);
            var prior: [D.LANES]usize = undefined;
            for (prior[0..count], 0..) |*value, i| value.* = evaluation.previousRow(self.part, r + i);
            for (&scratch.fixed, values[0..L.FIXED]) |*v, col| v.* = D.load(col, r, count);
            for (&scratch.main, values[L.FIXED..fm]) |*v, col| v.* = D.load(col, r, count);
            for (&scratch.previous, evaluation.previous_values[L.FIXED..][0..L.PREVIOUS_MAIN]) |*v, col| v.* = D.gather(col, prior[0..count]);
            for (&scratch.previous_header, evaluation.previous_values[L.FIXED + L.ACTIVE ..][0..2]) |*v, col| v.* = D.gather(col, prior[0..count]);
            for (&scratch.interaction, 0..) |*v, b| v.* = D.secure(values[fm + 4 * b ..], r, count);
            var weighted = sinks.PackedWeightedAccumulator{ .powers = self.output.random_coeff_powers };
            var sink = sinks.PackedSink{ .weighted_accumulator = &weighted };
            E.emitGeneric(D.F, component.program, scratch.row(component.packet_format), &scratch.interaction, D.previousSecure(evaluation.previous_values[fm + L.INTERACTION - 4 ..], prior[0..count]), component.claim, component.challenges, .{ .calls = component.calls, .first_id = component.first_call_id }, &sink);
            std.debug.assert(sink.count == L.CONSTRAINTS);
            D.accumulate(&self.output, evaluation.globalRow(self.part, r), count, weighted.accumulation.mulBase(D.F.splat(self.inverse)));
        }
    }
};
