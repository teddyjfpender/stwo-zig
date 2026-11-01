//! Joined2n domain evaluation: one bounded expansion of original MAIN and actual
//!16 binding columns; packed M31 original constraints and packed OM residuals.
//! Succinct Eq auxiliaries are derived from the checked GKR point, never PCS
//! witness columns, and owned only for this component's evaluation lifetime.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const F = E.PackedFields.BaseForField(O);
const S = E.PackedFields.SecureForField(O);
const P = engine.air.component_prover.ForField(O);
const D = engine.air.accumulation.ForField(O);
const B = @import("binding.zig");
const Partition = A.full.coset_evaluation.Evaluation;
fn packedSecure(values: [][]const M, start: usize, row: usize) S {
    var coords: [8]F = undefined;
    for (&coords, 0..) |*v, c| v.* = F.load(values[start + c].ptr + row);
    return E.secureFromCoordinatesForField(O, F, coords);
}
pub fn evaluate(self: anytype, trace: *const P.Trace, acc: *D.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
    try self.validate();
    const Component = @typeInfo(@TypeOf(self)).pointer.child;
    const Scratch = struct { fixed: [Component.MAX_FIXED]F, main: [Component.MAX_MAIN]F, previous: [Component.MAX_MAIN]F, weights: [128]S };
    const shape = self.mainShape();
    if (shape.fixed > Component.MAX_FIXED or shape.main > Component.MAX_MAIN) return error.InvalidLocalGkrTrace;
    const log = self.data.instance.row_log;
    const offsets = self.columnOffsets();
    if (trace.polys.items.len < 3 or trace.polys.items[0].len < offsets[0] + shape.fixed or trace.polys.items[1].len < offsets[1] + shape.main or trace.polys.items[2].len < self.inter_offset + 16) return error.InvalidLocalGkrTrace;
    const a = acc.allocator;
    const rows = try self.data.instance.rows();
    var aux: [10]engine.poly.circle.CircleCoefficients = undefined;
    var done: usize = 0;
    defer for (aux[0..done]) |*v| v.deinit(a);
    const native_domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
    for (&aux, 0..) |*coefficient, column| {
        const values = try a.alloc(M, rows);
        defer a.free(values);
        @memset(values, M.zero());
        if (column < 8) {
            for (0..rows) |logical| {
                const t: usize = @ctz(~(logical / 2));
                const q = if (logical % 2 == 0) self.data.point.hc0[t] else self.data.point.hc1[t];
                values[A.witness.physical(logical, log)] = q.toM31Array()[column];
            }
        } else values[A.witness.physical(column - 8, log)] = M.one();
        coefficient.* = try engine.poly.circle.poly.interpolateFromEvaluation(a, try engine.poly.circle.evaluation.CircleEvaluation.init(native_domain, values));
        done += 1;
    }
    const main_at = shape.fixed;
    const inter_at = main_at + shape.main;
    const aux_at = inter_at + 16;
    const total = aux_at + 10;
    var columns: [Component.MAX_FIXED + Component.MAX_MAIN + 26]P.Poly = undefined;
    @memcpy(columns[0..shape.fixed], trace.polys.items[0][offsets[0]..][0..shape.fixed]);
    @memcpy(columns[main_at..inter_at], trace.polys.items[1][offsets[1]..][0..shape.main]);
    @memcpy(columns[inter_at..aux_at], trace.polys.items[2][self.inter_offset..][0..16]);
    for (aux, 0..) |coefficient, c| columns[aux_at + c] = .{ .log_size = log, .values = &.{}, .coefficients = coefficient };
    var previous: [Component.MAX_FIXED + Component.MAX_MAIN + 26]bool = @splat(false);
    for (0..shape.main) |c| previous[main_at + c] = self.previousMain(c);
    @memset(previous[inter_at + 8 .. inter_at + 16], true);
    var evaluation = try Partition.initDegreeThree(a, columns[0..total], log, previous[0..total]);
    defer evaluation.deinit();
    const scratch = try a.create(Scratch);
    defer a.destroy(scratch);
    scratch.previous = @splat(F.zero());
    for (scratch.weights[0..self.data.lane_count], self.data.lane_weights[0..self.data.lane_count]) |*v, x| v.* = S.splat(x);
    const outputs = try acc.columns(a, &.{.{ .log_size = log + 1, .n_cols = self.nConstraints() }});
    defer a.free(outputs);
    var output = outputs[0];
    for (0..2) |part| {
        try evaluation.evaluatePartWithPool(part, pool);
        const inverse = F.fromBase(try evaluation.denominatorInverse(part));
        var row: usize = 0;
        while (row < rows) : (row += E.LANES) {
            for (scratch.fixed[0..shape.fixed], 0..) |*v, c| v.* = F.load(evaluation.current_values[c].ptr + row);
            for (scratch.main[0..shape.main], 0..) |*v, c| {
                v.* = F.load(evaluation.current_values[main_at + c].ptr + row);
                if (self.previousMain(c)) {
                    var prior: [E.LANES]M = undefined;
                    for (&prior, 0..) |*x, lane| x.* = evaluation.previous_values[main_at + c][evaluation.previousRow(part, row + lane)];
                    scratch.previous[c] = F.fromLanes(prior);
                }
            }
            var weighted = E.WeightedAccumulatorFor(F){ .powers = output.random_coeff_powers };
            var sink = E.SinkFor(F){ .weighted_accumulator = &weighted };
            try self.emitMainFor(F, scratch.fixed[0..shape.fixed], scratch.main[0..shape.main], scratch.previous[0..shape.main], &sink);
            var projection = B.ProjectionFor(F){ .challenges = &self.data.challenges, .lane_weights = scratch.weights[0..self.data.lane_count], .terms = self.data.instance.terms };
            self.emitLocalFor(F, scratch.fixed[0..shape.fixed], scratch.main[0..shape.main], &projection);
            try projection.finish();
            var next_coords: [8]F = undefined;
            var prior_coords: [8]F = undefined;
            for (0..8) |c| {
                var next: [E.LANES]M = undefined;
                var prior: [E.LANES]M = undefined;
                for (&next, &prior, 0..) |*n, *p, lane| {
                    const global = evaluation.globalRow(part, row + lane);
                    const shifted = core.utils.offsetBitReversedCircleDomainIndex(global, log, log + 1, 2);
                    if (shifted / rows != part) return error.InvalidLocalGkrNextMask;
                    n.* = evaluation.current_values[inter_at + c][shifted % rows];
                    p.* = evaluation.previous_values[inter_at + 8 + c][evaluation.previousRow(part, row + lane)];
                }
                next_coords[c] = F.fromLanes(next);
                prior_coords[c] = F.fromLanes(prior);
            }
            B.emitFor(F, .{ .eq = packedSecure(evaluation.current_values, inter_at, row), .eq_next2 = E.secureFromCoordinatesForField(O, F, next_coords), .prefix = packedSecure(evaluation.current_values, inter_at + 8, row), .prefix_previous = E.secureFromCoordinatesForField(O, F, prior_coords) }, .{ .first = S.fromBase(F.load(evaluation.current_values[aux_at + 8].ptr + row)), .second = S.fromBase(F.load(evaluation.current_values[aux_at + 9].ptr + row)), .carry = packedSecure(evaluation.current_values, aux_at, row), .eq0 = S.splat(self.data.point.eq0), .eq1 = S.splat(self.data.point.eq1) }, projection.combine(S.splat(self.data.eta)), S.splat(self.data.target_per_row), &sink);
            if (sink.count != self.nConstraints()) return error.LocalGkrProjectionShape;
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
