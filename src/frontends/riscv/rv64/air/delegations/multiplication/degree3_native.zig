//! Native16-row PackedM31 arithmetic with secure lookup/random accumulation.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../../evaluation.zig");
const L = @import("degree3_layout.zig");
const P = @import("degree3_provider.zig");
const C = @import("degree3_component.zig").Component;
const Partition = @import("../../full/coset_evaluation.zig").Evaluation;
const cp = engine.air.component_prover;
const M = core.fields.m31.M31;
const F = E.PackedBase;
const TOTAL = L.FIXED + L.MAIN + L.INTERACTION;
pub const MIN_STACK_BYTES = 256 * 1024;
const Scratch = struct { fixed: [L.FIXED]F, main: [L.MAIN]F, current: [L.INTERACTION]F, previous: [4]F };
pub fn evaluate(self: *const C, trace: *const cp.Trace, accumulator: *engine.air.accumulation.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
    return evaluateImpl(false, self, trace, accumulator, pool);
}
fn evaluateImpl(comptime scalar_reference: bool, self: *const C, trace: *const cp.Trace, accumulator: *engine.air.accumulation.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
    if (pool) |active| if (active.stackSize() < MIN_STACK_BYTES) return error.InvalidRv64MultiplicationWorkerStack;
    if (self.log_size < 5 or self.log_size > 22 or self.count > (@as(usize, 1) << @intCast(self.log_size)) or trace.polys.items.len != 3 or trace.polys.items[0].len < self.fixed_offset + L.FIXED or trace.polys.items[1].len < self.main_offset + L.MAIN or trace.polys.items[2].len < self.interaction_offset + L.INTERACTION) return error.InvalidRv64MultiplicationShape;
    const a = accumulator.allocator;
    var polys: [TOTAL]cp.Poly = undefined;
    @memcpy(polys[0..L.FIXED], trace.polys.items[0][self.fixed_offset..][0..L.FIXED]);
    @memcpy(polys[L.FIXED..][0..L.MAIN], trace.polys.items[1][self.main_offset..][0..L.MAIN]);
    @memcpy(polys[L.FIXED + L.MAIN ..], trace.polys.items[2][self.interaction_offset..][0..L.INTERACTION]);
    var previous: [TOTAL]bool = @splat(false);
    previous[L.FIXED + L.COUNT] = true;
    @memset(previous[L.FIXED + L.MAIN + L.PREFIX ..], true);
    var evaluation = try Partition.initDegreeThree(a, &polys, self.log_size, &previous);
    defer evaluation.deinit();
    const scratch: ?*Scratch = if (comptime scalar_reference) null else try a.create(Scratch);
    defer if (scratch) |value| a.destroy(value);
    const columns = try accumulator.columns(a, &.{.{ .log_size = self.log_size + 1, .n_cols = L.CONSTRAINTS }});
    defer a.free(columns);
    var output = columns[0];
    for (0..2) |part| {
        try evaluation.evaluatePartWithPool(part, pool);
        const denominator = try evaluation.denominatorInverse(part);
        if (comptime scalar_reference) {
            scalarRows(self, &evaluation, part, denominator, &output);
        } else {
            var row: usize = 0;
            while (row < evaluation.size) : (row += E.LANES) {
                var prior: [E.LANES]usize = undefined;
                for (&prior, 0..) |*v, lane| v.* = evaluation.previousRow(part, row + lane);
                for (&scratch.?.fixed, 0..) |*v, c| v.* = F.load(evaluation.current_values[c].ptr + row);
                for (&scratch.?.main, 0..) |*v, c| v.* = F.load(evaluation.current_values[L.FIXED + c].ptr + row);
                for (&scratch.?.current, 0..) |*v, c| v.* = F.load(evaluation.current_values[L.FIXED + L.MAIN + c].ptr + row);
                for (&scratch.?.previous, 0..) |*v, c| v.* = gather(evaluation.previous_values[L.FIXED + L.MAIN + L.PREFIX + c], prior);
                const count = gather(evaluation.previous_values[L.FIXED + L.COUNT], prior);
                var weighted = E.WeightedAccumulatorFor(F){ .powers = output.random_coeff_powers };
                var sink = E.SinkFor(F){ .weighted_accumulator = &weighted };
                P.evaluateFor(F, scratch.?.fixed, &scratch.?.main, &scratch.?.current, E.secureFromCoordinatesFor(F, scratch.?.previous), count, E.qFor(F, self.count), self.challenges, self.byte_alpha, self.claim, &sink);
                std.debug.assert(sink.count == L.CONSTRAINTS);
                const values = weighted.accumulation.mulBase(F.fromBase(denominator)).coordinates();
                const start = evaluation.globalRow(part, row);
                const fresh = if (output.next_fresh_index) |next| next == start else false;
                output.next_fresh_index = if (fresh) start + E.LANES else null;
                for (output.col.columns, values) |column, value| {
                    if (fresh) value.store(column.ptr + start) else F.load(column.ptr + start).add(value).store(column.ptr + start);
                }
            }
        }
    }
}
fn gather(values: []const M, indices: [E.LANES]usize) F {
    var result: [E.LANES]M = undefined;
    for (&result, indices) |*v, i| v.* = values[i];
    return F.fromLanes(result);
}

// Compiled only by tests; production has no scalar-domain fallback.
fn scalarRows(self: *const C, evaluation: *const Partition, part: usize, inverse: M, output: *engine.air.accumulation.ColumnAccumulator) void {
    for (0..evaluation.size) |row| {
        const prior = evaluation.previousRow(part, row);
        var fixed: [L.FIXED]E.Q = undefined;
        var main: [L.MAIN]E.Q = undefined;
        var current: [L.INTERACTION]E.Q = undefined;
        var previous: [4]E.Q = undefined;
        for (&fixed, 0..) |*v, c| v.* = E.Q.fromBase(evaluation.current_values[c][row]);
        for (&main, 0..) |*v, c| v.* = E.Q.fromBase(evaluation.current_values[L.FIXED + c][row]);
        for (&current, 0..) |*v, c| v.* = E.Q.fromBase(evaluation.current_values[L.FIXED + L.MAIN + c][row]);
        for (&previous, 0..) |*v, c| v.* = E.Q.fromBase(evaluation.previous_values[L.FIXED + L.MAIN + L.PREFIX + c][prior]);
        const count = E.Q.fromBase(evaluation.previous_values[L.FIXED + L.COUNT][prior]);
        var weighted = E.WeightedAccumulator{ .powers = output.random_coeff_powers };
        var sink = E.Sink{ .values = null, .weighted_accumulator = &weighted };
        P.evaluateFor(E.Q, fixed, &main, &current, E.Q.fromPartialEvals(previous), count, E.q(self.count), self.challenges, self.byte_alpha, self.claim, &sink);
        std.debug.assert(sink.count == L.CONSTRAINTS);
        output.accumulate(evaluation.globalRow(part, row), weighted.accumulation.mulM31(inverse));
    }
}
pub const testing = if (@import("builtin").is_test) struct {
    pub fn scalar(self: *const C, trace: *const cp.Trace, accumulator: *engine.air.accumulation.DomainEvaluationAccumulator) !void {
        return evaluateImpl(true, self, trace, accumulator, null);
    }
} else struct {};
