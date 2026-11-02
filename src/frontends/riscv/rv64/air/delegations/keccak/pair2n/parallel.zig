//! Bounded joined row wave; all residuals use the one scalar/packed authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const V = @import("../../../evaluation.zig");
const F = V.PackedBase;
const S = V.PackedSecure;
const C = @import("component.zig");
const L = @import("layout.zig");
const K = @import("../layout.zig");
const E = @import("equations.zig");
const Base = @import("../component.zig");
const gather = @import("../packed_rows.zig");
const Eval = @import("../../../full/coset_evaluation.zig").Evaluation;
const Column = engine.air.accumulation.ColumnAccumulator;
const work = engine.work_pool;
pub const MIN_STACK = if (@import("builtin").mode == .Debug) 1 << 20 else 256 << 10;
pub fn evaluate(component: *const C.Component, evaluation: *const Eval, part: usize, output: *Column, inverse: M, pool: ?*work.WorkPool) !void {
    if (part >= 2 or evaluation.log_expansion != 1 or evaluation.trace_log != component.log_size or output.col.len() != 2 * evaluation.size or output.random_coeff_powers.len != component.nConstraints()) return error.InvalidKeccakPair2nShape;
    if (pool) |p| if (p.stackSize() < MIN_STACK) return error.InvalidKeccakWorkerStack;
    const total = component.fixedCount() + component.mainCount() + component.interactionCount();
    if (evaluation.current_values.len != total or evaluation.previous_values.len != total) return error.InvalidKeccakPair2nShape;
    for (evaluation.current_values) |column| if (column.len != evaluation.size) return error.InvalidKeccakPair2nShape;
    if (component.kind == .permutation) {
        for (evaluation.previous_values, 0..) |column, c| if ((c >= L.FIXED and c < L.FIXED + K.STATE) or (c >= L.FIXED + K.ACTIVE_A and c < L.FIXED + K.MAIN) or c >= total - 4) {
            if (column.len != evaluation.size) return error.InvalidKeccakPair2nShape;
        };
    } else {
        for (evaluation.previous_values[total - 4 ..]) |column| {
            if (column.len != evaluation.size) return error.InvalidKeccakPair2nShape;
        }
    }
    const workers = if (pool) |p| @min(p.workerCount(), @max(@as(usize, 1), evaluation.size / 64)) else 1;
    const scratch = try evaluation.allocator.alloc(C.ScratchFor(F), if (component.kind == .permutation) workers else 0);
    defer evaluation.allocator.free(scratch);
    var jobs: [work.MAX_WORKERS]Job = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .component = component, .evaluation = evaluation, .part = part, .output = output.*, .inverse = inverse, .scratch = if (component.kind == .permutation) &scratch[i] else null, .start = evaluation.size * i / workers, .end = evaluation.size * (i + 1) / workers };
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
    scratch: ?*C.ScratchFor(F),
    start: usize,
    end: usize,
    fn run(self: *Job) void {
        const c = self.component;
        const e = self.evaluation;
        const values = e.current_values;
        var begin = self.start;
        while (begin < self.end) : (begin += V.LANES) {
            const count: usize = @min(V.LANES, self.end - begin);
            var previous: [V.LANES]usize = undefined;
            for (0..count) |i| previous[i] = e.previousRow(self.part, begin + i);
            var accumulator = V.PackedWeightedAccumulator{ .powers = self.output.random_coeff_powers };
            var sink = V.PackedSink{ .weighted_accumulator = &accumulator };
            if (c.kind == .permutation) {
                const row = self.scratch.?;
                const fm = L.FIXED + L.MAIN;
                for (&row.fixed, values[0..L.FIXED]) |*v, column| v.* = gather.load(column, begin, count);
                for (&row.main, values[L.FIXED..fm]) |*v, column| v.* = gather.load(column, begin, count);
                for (K.MASK_OFFSETS[1..], 0..) |offset, j| {
                    var indices: [V.LANES]usize = undefined;
                    var partner: [V.LANES]bool = undefined;
                    for (0..count) |i| {
                        const global = core.utils.offsetBitReversedCircleDomainIndex(e.globalRow(self.part, begin + i), e.trace_log, e.trace_log + 1, offset);
                        indices[i] = global % e.size;
                        partner[i] = global / e.size != self.part;
                    }
                    for (&row.shifted[j], 0..) |*v, column| {
                        var lanes: [V.LANES]M = @splat(M.zero());
                        for (0..count) |i| lanes[i] = (if (partner[i]) e.previous_values[L.FIXED + column] else values[L.FIXED + column])[indices[i]];
                        v.* = F.fromLanes(lanes);
                    }
                }
                for (&row.previous_header, e.previous_values[L.FIXED + K.ACTIVE_A ..][0..3]) |*v, column| v.* = gather.gather(column, previous[0..count]);
                for (&row.interaction, 0..) |*v, pair| v.* = gather.loadSecure(values[fm + 4 * pair ..][0..4], begin, count);
                E.emitFor(F, row.row(), &row.interaction, gather.gatherSecure(e.previous_values[fm + L.PREFIX ..][0..4], previous[0..count]), c.claim, c.challenges, .{ .calls = c.calls, .first_id = c.first_call_id }, &sink);
            } else {
                var tuple: [6]F = undefined;
                for (&tuple, values[0..6]) |*v, column| v.* = gather.load(column, begin, count);
                sink.emit(Base.tableResidualFor(F, c, &tuple, gather.load(values[6], begin, count), gather.load(values[7], begin, count), gather.loadSecure(values[8..12], begin, count), gather.gatherSecure(e.previous_values[8..12], previous[0..count])));
            }
            std.debug.assert(sink.count == c.nConstraints());
            gather.accumulate(&self.output, e.globalRow(self.part, begin), count, accumulator.accumulation.mulBase(F.splat(self.inverse)));
        }
    }
};
