//! Typed secure sampling over the shared M31 commitment owner. The wide
//! correctness fallback borrows retained coefficients or interpolates one
//! column at a time; it does not create a lifted column matrix.
const std = @import("std");
const core = @import("stwo_core");
const tree_mod = @import("commitment_tree.zig");
const poly = @import("../poly/circle/poly.zig");
const eval_mod = @import("../poly/circle/evaluation.zig");
const TreeVec = core.pcs.TreeVec;
pub fn ForField(comptime S: type) type {
    return struct {
        const Point = core.circle.CirclePoint(S);
        pub fn evaluateAndReleaseWithWorkRecorder(comptime B: type, comptime H: type, a: std.mem.Allocator, trees: []tree_mod.CommitmentTreeProverForBackend(B, H), points: TreeVec([][]Point), log: u32, recorder: ?*@import("stwo_prover_api").work_profile.Recorder(true)) !TreeVec([][]S) {
            if (recorder != null) return error.UnsupportedWideSamplingWorkProfile;
            if (trees.len != points.items.len) return error.ShapeMismatch;
            const out = try a.alloc([][]S, trees.len);
            errdefer a.free(out);
            var ntrees: usize = 0;
            errdefer for (out[0..ntrees]) |t| {
                for (t) |c| a.free(c);
                a.free(t);
            };
            for (trees, points.items, 0..) |*tree, tree_points, ti| {
                if (tree.columns.len != tree_points.len) return error.ShapeMismatch;
                if (tree.coefficients) |coefficients| if (coefficients.len != tree.columns.len) return error.ShapeMismatch;
                const result = try a.alloc([]S, tree.columns.len);
                var ncols: usize = 0;
                errdefer {
                    for (result[0..ncols]) |c| a.free(c);
                    a.free(result);
                }
                for (tree.columns, tree_points, 0..) |column, ps, ci| {
                    try column.validateRetained();
                    if (ps.len != 0 and column.log_size > log) return error.ShapeMismatch;
                    const values = try a.alloc(S, ps.len);
                    result[ci] = values;
                    ncols += 1;
                    if (ps.len == 0) continue;
                    var temporary: ?poly.CircleCoefficients = null;
                    defer if (temporary) |*p| p.deinit(a);
                    const coefficients = if (tree.coefficients) |coefficients| coefficients[ci] else blk: {
                        if (column.coefficient_values) |retained| break :blk try poly.CircleCoefficients.initBorrowed(retained);
                        const domain = core.poly.circle.canonic.CanonicCoset.new(column.log_size).circleDomain();
                        temporary = try poly.interpolateFromEvaluation(a, try eval_mod.CircleEvaluation.init(domain, column.values));
                        break :blk temporary.?;
                    };
                    const fold_count = log - column.log_size;
                    for (ps, 0..) |point, i| values[i] = coefficients.evalAtPointFor(S, point.repeatedDouble(fold_count));
                }
                out[ti] = result;
                ntrees += 1;
            }
            for (trees) |*tree| tree.releaseCoefficients(a);
            return TreeVec([][]S).initOwned(out);
        }
    };
}
