//! Bounded four-coset classic truth kernel, packed M31 arithmetic / OM31 weights.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const F = E.PackedFields.BaseForField(O);
const P = engine.air.component_prover.ForField(O);
const D = engine.air.accumulation.ForField(O);
const Evaluation = A.full.coset_evaluation.Evaluation;
const Component = @import("truth_role.zig").Component;
const Samples = struct {
    owner: *const Component,
    evaluation: *const Evaluation,
    part: usize,
    row: usize,
    pub fn last(s: @This()) !F {
        return F.load(s.evaluation.current_values[s.evaluation.sources.len - 1].ptr + s.row);
    }
    pub fn get(s: @This(), tree: usize, column: usize, shift: i32) !F {
        const widths = s.owner.widths();
        const index = column + (if (tree == 0) @as(usize, 0) else if (tree == 1) widths[0] else widths[0] + widths[1]);
        if (shift == 0) return F.load(s.evaluation.current_values[index].ptr + s.row);
        var values: [E.LANES]M = undefined;
        for (&values, 0..) |*v, lane| {
            const target = core.utils.offsetBitReversedCircleDomainIndex(s.evaluation.globalRow(s.part, s.row + lane), s.owner.log_size, s.owner.log_size + s.owner.compositionLogSplit(), shift);
            const part = target / s.evaluation.size;
            const row = target % s.evaluation.size;
            v.* = if (part == s.part) s.evaluation.current_values[index][row] else if (part == s.part ^ 1 and s.evaluation.previous_values[index].len != 0) s.evaluation.previous_values[index][row] else return error.InvalidWideTruthShift;
        }
        return F.fromLanes(values);
    }
};
pub fn evaluate(self: *const Component, trace: *const P.Trace, acc: *D.DomainEvaluationAccumulator) !void {
    try self.validate();
    const a = acc.allocator;
    const widths = self.widths();
    const native_total = widths[0] + widths[1] + widths[2];
    const total = native_total + 1;
    const columns = try a.alloc(P.Poly, total);
    defer a.free(columns);
    const previous = try a.alloc(bool, total);
    defer a.free(previous);
    if (trace.polys.items.len != 3) return error.InvalidWideTruthTrace;
    var at: usize = 0;
    for (widths, 0..) |width, t| {
        if (trace.polys.items[t].len < self.offsets[t] + width) return error.InvalidWideTruthTrace;
        @memcpy(columns[at..][0..width], trace.polys.items[t][self.offsets[t]..][0..width]);
        for (0..width) |c| previous[at + c] = self.shifts(t, c).len > 1;
        at += width;
    }
    const rows = @as(usize, 1) << @intCast(self.log_size);
    const values = try a.alloc(M, rows);
    defer a.free(values);
    @memset(values, M.zero());
    values[A.witness.physical(rows - 1, self.log_size)] = M.one();
    var last = try engine.poly.circle.poly.interpolateFromEvaluation(a, try engine.poly.circle.evaluation.CircleEvaluation.init(core.poly.circle.canonic.CanonicCoset.new(self.log_size).circleDomain(), values));
    defer last.deinit(a);
    columns[native_total] = .{ .log_size = self.log_size, .values = &.{}, .coefficients = last };
    previous[native_total] = false;
    var evaluation = if (self.compositionLogSplit() == 1) try Evaluation.initDegreeThree(a, columns, self.log_size, previous) else try Evaluation.init(a, columns, self.log_size, previous);
    defer evaluation.deinit();
    const outputs = try acc.columns(a, &.{.{ .log_size = self.log_size + self.compositionLogSplit(), .n_cols = self.nConstraints() }});
    defer a.free(outputs);
    var output = outputs[0];
    for (0..@as(usize, 1) << @intCast(self.compositionLogSplit())) |part| {
        try evaluation.evaluatePartWithPool(part, engine.work_pool.currentScopedPool());
        const inverse = F.fromBase(try evaluation.denominatorInverse(part));
        var row: usize = 0;
        while (row < evaluation.size) : (row += E.LANES) {
            var weighted = E.WeightedAccumulatorFor(F){ .powers = output.random_coeff_powers };
            var sink = E.SinkFor(F){ .weighted_accumulator = &weighted };
            try self.emitFor(F, Samples{ .owner = self, .evaluation = &evaluation, .part = part, .row = row }, &sink);
            if (sink.count != self.nConstraints()) return error.WideTruthConstraintCount;
            const result = weighted.accumulation.mulBase(inverse).coordinates();
            const start = evaluation.globalRow(part, row);
            const fresh = if (output.next_fresh_index) |next| next == start else false;
            output.next_fresh_index = if (fresh) start + E.LANES else null;
            for (output.col.columns, result) |column, v| {
                if (fresh) v.store(column.ptr + start) else F.load(column.ptr + start).add(v).store(column.ptr + start);
            }
        }
    }
}
