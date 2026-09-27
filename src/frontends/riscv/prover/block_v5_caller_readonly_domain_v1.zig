//! Exact quotient samples for the same source mask as OODS. Every selected
//! polynomial receives full-LDE recovery and high-degree rejection.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Support = @import("../recursion/air/universal_typed_component_contract.zig");
const Air = @import("block_v5_caller_readonly_component_v1.zig");
pub fn evaluate(self: *const Air.Component, source: *const engine.air.component_prover.Trace, accumulator: *engine.air.accumulation.DomainEvaluationAccumulator) !void {
    if (source.polys.items.len != 4) return error.InvalidCallerReadonlyTrees;
    const a = accumulator.allocator;
    const eval_log = self.source.log_size + 2;
    const domain = core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain();
    const point = core.circle.CirclePointQM31{ .x = Q.one(), .y = Q.zero() };
    var shape = try self.sourceMaskPoints(a, point, eval_log);
    defer shape.deinitDeep(a);
    const values = try a.alloc([][]const M, 4);
    var n: usize = 0;
    defer {
        for (values[0..n]) |tree| a.free(tree);
        a.free(values);
    }
    const sampled = try a.alloc([][]Q, 4);
    var ns: usize = 0;
    defer {
        for (sampled[0..ns]) |tree| {
            for (tree) |column| a.free(column);
            a.free(tree);
        }
        a.free(sampled);
    }
    var selected: usize = 0;
    for (shape.items) |tree| for (tree) |column| {
        selected += @intFromBool(column.len != 0);
    };
    const buffers = try a.alloc([]M, selected);
    var initialized: usize = 0;
    defer {
        for (buffers[0..initialized]) |column| a.free(column);
        a.free(buffers);
    }
    var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
    defer engine.poly.twiddles.deinitM31(a, &twiddles);
    const transform = engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles);
    for (shape.items, 0..) |tree, t| {
        if (source.polys.items[t].len < tree.len) return error.InvalidCallerReadonlyTrees;
        values[t] = try a.alloc([]const M, tree.len);
        n += 1;
        sampled[t] = try a.alloc([]Q, tree.len);
        var cols: usize = 0;
        errdefer {
            for (sampled[t][0..cols]) |column| a.free(column);
            a.free(sampled[t]);
        }
        for (tree, 0..) |samples, c| {
            sampled[t][c] = try a.alloc(Q, samples.len);
            cols += 1;
            values[t][c] = &.{};
            if (samples.len == 0) continue;
            _ = try Support.sourceNeedsExtension(source.polys.items[t][c], self.source.log_size, eval_log);
            values[t][c] = try Support.evaluationValues(a, source.polys.items[t][c], self.source.log_size, eval_log, domain.size(), transform, buffers, &initialized);
        }
        ns += 1;
    }
    if (initialized != 0) try engine.poly.circle.poly.evaluateBuffersWithTwiddles(buffers[0..initialized], domain, transform);
    const output = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = Air.COUNT }});
    defer a.free(output);
    var out = output[0];
    var inverses: [4]M = undefined;
    for (&inverses, 0..) |*inverse, i| inverse.* = try core.constraints.cosetVanishing(M, core.poly.circle.canonic.CanonicCoset.new(self.source.log_size).coset(), domain.at(core.utils.bitReverseIndex(i, 2))).inv();
    for (0..domain.size()) |row| {
        const previous = core.utils.previousBitReversedCircleDomainIndex(row, self.source.log_size, eval_log);
        const shifted = core.utils.offsetBitReversedCircleDomainIndex(row, self.source.log_size, eval_log, 27);
        for (shape.items, 0..) |tree, t| for (tree, 0..) |samples, c| {
            for (0..samples.len) |s| {
                // Only interaction uses -1; only Keccak state uses +27.
                const r = if (s == 0) row else if (t == 3) previous else if (t == 1) shifted else return error.InvalidCallerReadonlySamples;
                sampled[t][c][s] = Q.fromBase(values[t][c][r]);
            }
        };
        const mask = core.air.components.MaskValues{ .items = sampled };
        const equations = try self.evaluateMask(&mask);
        var folded = Q.zero();
        for (equations, 0..) |equation, i| folded = folded.add(out.random_coeff_powers[Air.COUNT - 1 - i].mul(equation));
        out.accumulate(row, folded.mulM31(inverses[row >> @intCast(self.source.log_size)]));
    }
}
