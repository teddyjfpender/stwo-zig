//! Bounded2n MAIN-only domain path: reuse the existing column/coset authority,
//! evaluate direct equations over packed M31, accumulate with eight coordinates.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../evaluation.zig");
const A = @import("authority.zig");
const Component = @import("component.zig").Component;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const F = E.PackedFields.BaseForField(O);
const P = engine.air.component_prover.ForField(O);
const D = engine.air.accumulation.ForField(O);
const Partition = @import("../full/coset_evaluation.zig").Evaluation;
const Scratch = struct { fixed: [3]F, main: [128]F, previous: [128]F };
pub fn evaluate(self: *const Component, trace: *const P.Trace, accumulator: *D.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
    try self.validate();
    const shape = A.shape(self.role());
    if (trace.polys.items.len < 2 or trace.polys.items[0].len < self.offsets[0] + shape.fixed or trace.polys.items[1].len < self.offsets[1] + shape.main) return error.InvalidMainOnlyTrace;
    const total = shape.fixed + shape.main;
    var columns: [131]P.Poly = undefined;
    @memcpy(columns[0..shape.fixed], trace.polys.items[0][self.offsets[0]..][0..shape.fixed]);
    @memcpy(columns[shape.fixed..total], trace.polys.items[1][self.offsets[1]..][0..shape.main]);
    var previous_columns: [131]bool = @splat(false);
    for (0..shape.main) |c| previous_columns[shape.fixed + c] = A.previousMain(self.role(), c);
    const allocator = accumulator.allocator;
    var evaluation = try Partition.initDegreeThree(allocator, columns[0..total], self.log_size, previous_columns[0..total]);
    defer evaluation.deinit();
    const scratch = try allocator.create(Scratch);
    defer allocator.destroy(scratch);
    scratch.previous = @splat(F.zero());
    const outputs = try accumulator.columns(allocator, &.{.{ .log_size = self.log_size + 1, .n_cols = shape.constraints }});
    defer allocator.free(outputs);
    var output = outputs[0];
    for (0..2) |part| {
        try evaluation.evaluatePartWithPool(part, pool);
        const inverse = F.fromBase(try evaluation.denominatorInverse(part));
        var row: usize = 0;
        while (row < evaluation.size) : (row += E.LANES) {
            for (scratch.fixed[0..shape.fixed], 0..) |*v, c| v.* = F.load(evaluation.current_values[c].ptr + row);
            for (scratch.main[0..shape.main], 0..) |*v, c| {
                v.* = F.load(evaluation.current_values[shape.fixed + c].ptr + row);
                if (A.previousMain(self.role(), c)) {
                    var prior: [E.LANES]M = undefined;
                    for (&prior, 0..) |*p, lane| p.* = evaluation.previous_values[shape.fixed + c][evaluation.previousRow(part, row + lane)];
                    scratch.previous[c] = F.fromLanes(prior);
                }
            }
            var weighted = E.WeightedAccumulatorFor(F){ .powers = output.random_coeff_powers };
            var sink = E.SinkFor(F){ .weighted_accumulator = &weighted };
            try A.emitFor(F, self.public, scratch.fixed[0..shape.fixed], scratch.main[0..shape.main], scratch.previous[0..shape.main], &sink);
            if (sink.count != shape.constraints) return error.InvalidMainOnlyConstraintCount;
            const result = weighted.accumulation.mulBase(inverse).coordinates();
            const start = evaluation.globalRow(part, row);
            const fresh = if (output.next_fresh_index) |next| next == start else false;
            output.next_fresh_index = if (fresh) start + E.LANES else null;
            // Exactly8 coordinate columns, never a four-column reinterpretation.
            for (output.col.columns, result) |column, v| {
                if (fresh) v.store(column.ptr + start) else F.load(column.ptr + start).add(v).store(column.ptr + start);
            }
        }
    }
}
